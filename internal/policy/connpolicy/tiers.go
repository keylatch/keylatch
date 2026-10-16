package connpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
)

// Delivery tiers, from the strongest containment (D1: no child) to none (D6).
const (
	D1 = "D1"
	D2 = "D2"
	D3 = "D3"
	D4 = "D4"
	D5 = "D5"
	D6 = "D6"
)

// AllTiers lists the tiers in order.
var AllTiers = []string{D1, D2, D3, D4, D5, D6}

// Approval modes a document may name.
const (
	ApprovalAuto            = "auto"
	ApprovalAsk             = "ask"
	ApprovalAutoIfContained = "auto_if_contained"
	ApprovalPresenceForD6   = "presence_for_D6"
	ApprovalPresence        = "presence"
)

var approvalModes = []string{ApprovalAuto, ApprovalAsk, ApprovalAutoIfContained, ApprovalPresenceForD6, ApprovalPresence}

// DefaultTiers are the tiers a caller kind gets when its entry lists none: an
// agent or host never gets a raw value (D5 is contained but needs the document
// to say so, D6 is never), a service gets D5 only when enrolled, and a human
// gets all of them.
func DefaultTiers(k callerkind.Kind) []string {
	switch k {
	case callerkind.Human:
		return AllTiers
	case callerkind.Service:
		return AllTiers[:5]
	default:
		return AllTiers[:4]
	}
}

// DefaultApproval is the approval mode a caller kind gets when its entry names
// none.
func DefaultApproval(k callerkind.Kind) string {
	switch k {
	case callerkind.Human:
		return ApprovalPresenceForD6
	case callerkind.Service:
		return ApprovalAuto
	default:
		return ApprovalAutoIfContained
	}
}

// ResolveApproval turns an approval mode and a tier into what must happen
// before the request runs: "auto", "ask" or "presence". D6 always needs
// presence. Containment is the approval for D1 to D4; D5 holds the real value,
// so it needs an approval unless the exact command is pinned.
func ResolveApproval(mode, tier string, pinned bool) string {
	if tier == D6 {
		return ApprovalPresence
	}
	switch mode {
	case ApprovalAsk, ApprovalPresence:
		return mode
	case ApprovalAuto:
		return ApprovalAuto
	case ApprovalPresenceForD6:
		return ApprovalAuto
	}
	// auto_if_contained
	if tier == D5 && !pinned {
		return ApprovalAsk
	}
	return ApprovalAuto
}

// CommandRule pins an argv pattern. Match[0] is the executable: an absolute
// path pattern, compared with the executable the command resolves to, never
// with the name as typed. The remaining entries match one argument each; "*"
// matches any one argument and a trailing "**" any rest. Tiers narrows the
// tiers the matched command may use. ExeSHA256 pins the executable's content;
// only a pinned command, in a location the user cannot write, runs at D5
// without an approval.
type CommandRule struct {
	Match     []string `json:"match"`
	Tiers     []string `json:"tiers,omitempty"`
	Approval  string   `json:"approval,omitempty"`
	ExeSHA256 string   `json:"exe_sha256,omitempty"`
}

// MatchArgv reports whether argv, whose first word has been resolved to the
// executable at exe, matches the pattern. It never panics; a malformed pattern
// matches nothing.
func MatchArgv(pattern, argv []string, exe string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if len(pattern) == 0 || len(argv) == 0 || exe == "" {
		return false
	}
	if !filepath.IsAbs(pattern[0]) || !pathGlob(pattern[0], exe) {
		return false
	}
	rest, args := pattern[1:], argv[1:]
	for i, p := range rest {
		if p == "**" {
			return i == len(rest)-1
		}
		if i >= len(args) {
			return false
		}
		if p != "*" && !globOne(p, args[i]) {
			return false
		}
	}
	return len(args) == len(rest)
}

// pathGlob matches a path against a pattern whose "*" never crosses a "/" and
// whose "**" matches any number of whole path elements.
func pathGlob(pattern, path string) bool {
	return globSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

// globSegments matches path elements against pattern elements, where "**"
// matches any number of whole elements. It fills a table, so the work is
// bounded by the product of the lengths however many wildcards a pattern has.
func globSegments(p, s []string) bool {
	next := make([]bool, len(s)+1) // row i+1: does p[i+1:] match s[j:]
	cur := make([]bool, len(s)+1)
	next[len(s)] = true
	for i := len(p) - 1; i >= 0; i-- {
		for j := len(s); j >= 0; j-- {
			if p[i] == "**" {
				cur[j] = next[j] || (j < len(s) && cur[j+1])
			} else {
				cur[j] = j < len(s) && globOne(p[i], s[j]) && next[j+1]
			}
		}
		next, cur = cur, next
		clear(cur)
	}
	return next[0]
}

// globOne matches one argument or path element: "*" and "?" are the only
// wildcards, so a pattern cannot grow into a regular expression. It keeps one
// backtrack point, which makes it linear in the product of the lengths at worst.
func globOne(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]):
			px++
			sx++
		case star >= 0:
			mark++
			px, sx = star+1, mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// ResolveExecutable returns the real path of the executable argv0 names: a
// word with a slash is taken relative to dir, a bare word is looked up in
// pathEnv. Symlinks are resolved, so a pattern is compared with what would run.
func ResolveExecutable(argv0, dir, pathEnv string) (string, error) {
	if argv0 == "" {
		return "", errors.New("empty command")
	}
	var candidates []string
	if strings.Contains(argv0, "/") {
		if filepath.IsAbs(argv0) {
			candidates = []string{argv0}
		} else {
			candidates = []string{filepath.Join(dir, argv0)}
		}
	} else {
		for _, d := range filepath.SplitList(pathEnv) {
			if d == "" || !filepath.IsAbs(d) {
				continue
			}
			candidates = append(candidates, filepath.Join(d, argv0))
		}
	}
	for _, c := range candidates {
		real, err := filepath.EvalSymlinks(c)
		if err != nil {
			continue
		}
		if info, err := os.Stat(real); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return real, nil
		}
	}
	return "", fmt.Errorf("%s: executable not found", argv0)
}

// VerifyPinned checks that the executable at path is the one a rule pinned: its
// content hashes to want, and neither it nor any directory above it can be
// written by a user other than root, so the file cannot change after the check.
func VerifyPinned(path, want string) error {
	want = strings.ToLower(strings.TrimSpace(want))
	if len(want) != 64 {
		return errors.New("exe_sha256 must be 64 hex digits")
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if err := rootOwnedAndClosed(p, info); err != nil {
			return err
		}
		if p == "/" || p == filepath.Dir(p) {
			break
		}
	}
	f, err := os.Open(path) //nolint:gosec // G304: the pinned executable is the file being verified
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%s does not match its pinned hash", path)
	}
	return nil
}

// ttl parses a duration field, zero when unset.
func ttl(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q must be a positive duration such as 15m", s)
	}
	return d, nil
}

func validTiers(kind callerkind.Kind, tiers []string) error {
	for _, t := range tiers {
		if !slices.Contains(AllTiers, t) {
			return fmt.Errorf("%q is not a tier (D1 to D6)", t)
		}
		if t == D6 && kind != callerkind.Human {
			return fmt.Errorf("D6 hands out an uncontained value and is for human callers only")
		}
	}
	return nil
}
