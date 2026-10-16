package hook

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/paths"
)

// homeProtected lists the home-relative credential locations an agent must not
// read directly, in addition to the Keylatch state directories derived from
// internal/paths. Commands that only use such a file without printing it (ls,
// ssh -i, kubectl --kubeconfig) are exempt for these.
var homeProtected = []string{
	".keylatch", ".ssh", ".aws", ".gnupg", ".kube", ".config/gcloud",
	".docker/config.json", ".netrc", ".config/gh/hosts.yml", ".git-credentials", ".npmrc", ".pypirc",
	".azure", ".terraform.d/credentials.tfrc.json", ".config/keylatch",
}

// homeSecret lists the locations no command may name at all: shell history,
// the history database and key or remote configs of secret tooling.
var homeSecret = []string{
	".local/share/atuin", ".local/share/fish/fish_history", ".config/sops/age", ".config/rclone", ".mc/config.json",
}

// historyRe matches the per-tool history files in a home directory
// (.bash_history, .zsh_history, .psql_history, ...).
const historyRe = `\.[A-Za-z0-9_-]+_history`

// Env carries what the guard needs from the host: the user's home directory,
// the environment lookup that internal/paths resolves Keylatch state from, and
// the Keylatch binary path whose replacement the guard refuses.
type Env struct {
	Home   string
	Lookup func(string) string
	Binary string
}

// DefaultEnv reads the running process.
func DefaultEnv() Env {
	home, _ := os.UserHomeDir()
	bin, _ := os.Executable()
	return Env{Home: home, Lookup: os.Getenv, Binary: bin}
}

type policy struct {
	home       string
	roots      []string
	rootText   *regexp.Regexp
	secretText *regexp.Regexp
	binary     string
}

var envFileRe = regexp.MustCompile(`(?i)^(\.env(\..+)?|.+\.env)$`)

func isEnvFileName(name string) bool {
	if !envFileRe.MatchString(name) {
		return false
	}
	lower := strings.ToLower(name)
	for _, ok := range []string{".example", ".sample", ".template"} {
		if strings.HasSuffix(lower, ok) {
			return false
		}
	}
	return true
}

func newPolicy(env Env) *policy {
	if env.Lookup == nil {
		env.Lookup = func(string) string { return "" }
	}
	p := &policy{home: slash(env.Home), binary: slash(env.Binary)}
	homes := homeSpellings(p.home)

	var roots []string
	for _, h := range homes {
		for _, rel := range append(append([]string{}, homeProtected...), homeSecret...) {
			roots = append(roots, path.Join(h, rel))
		}
	}
	state := stateDirs(env, homes)
	p.roots = dedupe(append(roots, state...))

	homeAlt := []string{`~[A-Za-z0-9._-]*`, `\$HOME`, `\$\{HOME\}`, `\$USERPROFILE`, `\$\{USERPROFILE\}`, `\$env:USERPROFILE`, `%USERPROFILE%`}
	for _, h := range homes {
		homeAlt = append(homeAlt, regexp.QuoteMeta(h))
	}
	alt := strings.Join(homeAlt, "|")
	secret := make([]string, 0, len(homeSecret)+1)
	for _, rel := range homeSecret {
		secret = append(secret, regexp.QuoteMeta(rel))
	}
	secret = append(secret, historyRe)
	weak := make([]string, 0, len(homeProtected))
	for _, rel := range homeProtected {
		weak = append(weak, regexp.QuoteMeta(rel))
	}
	homeRe := func(names []string) string {
		return `(^|[^A-Za-z0-9_./-])(` + alt + `)/+(` + strings.Join(names, "|") + `)([^A-Za-z0-9_.-]|$)`
	}
	parts := []string{homeRe(append(weak, secret...))}
	for _, r := range state {
		if strings.HasPrefix(r, "/") || isDrivePath(r) {
			parts = append(parts, `(^|[^A-Za-z0-9_./-])`+regexp.QuoteMeta(r)+`([/]|[^A-Za-z0-9_.-]|$)`)
		}
	}
	p.rootText = regexp.MustCompile(`(?i)` + strings.Join(parts, "|"))
	p.secretText = regexp.MustCompile(`(?i)` + homeRe(secret))
	return p
}

func isDrivePath(s string) bool {
	return len(s) > 2 && s[1] == ':' && s[2] == '/'
}

// homeSpellings returns the home directory as given and with symlinks resolved.
func homeSpellings(home string) []string {
	if home == "" {
		return nil
	}
	out := []string{home}
	if resolved, err := filepath.EvalSymlinks(home); err == nil && slash(resolved) != home {
		out = append(out, slash(resolved))
	}
	return out
}

// stateDirs lists the Keylatch config, vault, audit, policy, grant, session
// and gateway locations for the current OS, honouring the same overrides the
// CLI honours.
func stateDirs(env Env, homes []string) []string {
	l := paths.Lookup(env.Lookup)
	dirs := []string{
		paths.ConfigDir(l), filepath.Dir(paths.Config(l)), paths.Vault(l), filepath.Dir(paths.Audit(l)),
		filepath.Dir(paths.Policy(l)), paths.PolicyDir(l), filepath.Dir(paths.Grants(l)), paths.GrantsDir(l),
		paths.Sessions(l), paths.ApprovalsDir(l), paths.KeyringDir(l), paths.GatewayDir(l), paths.Projects(l),
		paths.Actors(l), filepath.Dir(paths.Receipts(l)), filepath.Dir(paths.ControlSocket(l)),
	}
	for _, h := range homes {
		dirs = append(dirs, path.Join(h, ".keylatch"), path.Join(h, ".config", "keylatch"))
	}
	// Only Linux reads XDG_CONFIG_HOME, but a config placed there elsewhere is
	// still Keylatch state worth denying.
	if xdg := env.Lookup("XDG_CONFIG_HOME"); xdg != "" {
		dirs = append(dirs, filepath.Join(xdg, "keylatch"))
	}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d = slash(d); d != "" && d != "." && d != "/" {
			out = append(out, path.Clean(d))
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if k := strings.ToLower(s); !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

func slash(s string) string {
	if runtime.GOOS == "windows" {
		s = strings.ReplaceAll(s, `\`, "/")
	}
	return s
}

var (
	multiSlash = regexp.MustCompile(`/{2,}`)
	dotSegment = regexp.MustCompile(`/\./`)
	dotDot     = regexp.MustCompile(`/[^/\s.][^/\s]*/\.\./|/\.[^/\s.][^/\s]*/\.\./`)
)

// normalizeText folds the spellings of a path that name the same file: repeated
// slashes, "/./" and "seg/.." pairs.
func normalizeText(s string) string {
	s = multiSlash.ReplaceAllString(slash(s), "/")
	for range 64 {
		next := dotDot.ReplaceAllString(dotSegment.ReplaceAllString(s, "/"), "/")
		if next == s {
			break
		}
		s = next
	}
	return s
}

// mentions reports whether text names a protected location, however it is
// spelled (tilde, $HOME, the literal home path, quoted segments, //, /./, ..).
func (p *policy) mentions(text string) bool {
	return p.rootText.MatchString(normalizeText(text))
}

// mentionsSecret is mentions for the locations that no command may name.
func (p *policy) mentionsSecret(text string) bool {
	return p.secretText.MatchString(normalizeText(text))
}

// expandHome turns a leading ~, $HOME, ${HOME} or $USERPROFILE into the home
// directory.
func (p *policy) expandHome(s string) string {
	if p.home == "" {
		return s
	}
	for _, prefix := range []string{"${HOME}", "$HOME", "${USERPROFILE}", "$USERPROFILE", "~"} {
		if s == prefix || strings.HasPrefix(s, prefix+"/") {
			return p.home + s[len(prefix):]
		}
	}
	return s
}

// resolve returns the absolute, cleaned spellings of a path: lexical and with
// symlinks resolved through the longest existing prefix, so a link into a
// credential directory is caught.
func (p *policy) resolve(raw, cwd string) []string {
	s := p.expandHome(slash(raw))
	if !path.IsAbs(s) && !isDrivePath(s) {
		if cwd == "" {
			return nil
		}
		s = path.Join(cwd, s)
	}
	out := []string{path.Clean(s)}
	if real := evalExisting(s); real != "" && real != out[0] {
		out = append(out, real)
	}
	return out
}

func evalExisting(s string) string {
	cur := filepath.FromSlash(path.Clean(s))
	var tail []string
	for range 64 {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return path.Join(append([]string{slash(real)}, tail...)...)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
	return ""
}

func under(p, root string) bool {
	p, root = strings.ToLower(p), strings.ToLower(root)
	return p == root || strings.HasPrefix(p, strings.TrimRight(root, "/")+"/")
}

// pathDenied reports whether the path is, is inside, or (for recursive reads)
// contains a protected location.
func (p *policy) pathDenied(raw, cwd string, recursive bool) bool {
	for _, abs := range p.resolve(raw, cwd) {
		for _, root := range p.roots {
			if under(abs, root) || (recursive && under(root, abs)) {
				return true
			}
		}
		if p.historyFile(abs) {
			return true
		}
	}
	return false
}

func (p *policy) historyFile(abs string) bool {
	if p.home == "" || !under(abs, p.home) {
		return false
	}
	rel := strings.TrimPrefix(abs[len(p.home):], "/")
	first, _, _ := strings.Cut(rel, "/")
	return historyName.MatchString(first)
}

var historyName = regexp.MustCompile(`(?i)^` + historyRe + `$`)

// globDenied reports whether a glob pattern can match a protected location or
// something inside one.
func (p *policy) globDenied(raw, cwd string) bool {
	s := p.expandHome(slash(raw))
	if !path.IsAbs(s) && !isDrivePath(s) {
		if cwd == "" {
			return false
		}
		s = path.Join(cwd, s)
	}
	pat := strings.Split(path.Clean(s), "/")
	for _, root := range p.roots {
		if globCovers(pat, strings.Split(root, "/")) {
			return true
		}
	}
	return false
}

func globCovers(pat, root []string) bool {
	for i, rc := range root {
		if i >= len(pat) {
			return false
		}
		if strings.Contains(pat[i], "**") {
			return true
		}
		if ok, err := path.Match(strings.ToLower(pat[i]), strings.ToLower(rc)); err != nil || !ok {
			return false
		}
	}
	return true
}

func hasGlobMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

var settingsRe = settingsPattern()

// settingsPattern matches every file the harness registry lists as holding
// hooks or MCP servers, at any depth.
func settingsPattern() *regexp.Regexp {
	var alts []string
	for _, f := range harness.ProtectedFiles() {
		if dir, isDir := strings.CutSuffix(f, "/"); isDir {
			alts = append(alts, regexp.QuoteMeta(dir)+`(/|$)`)
		} else {
			alts = append(alts, regexp.QuoteMeta(f)+`$`)
		}
	}
	return regexp.MustCompile(`(?i)(^|/)(` + strings.Join(alts, "|") + `)`)
}

// settingsFile reports whether the text names a harness settings or hook
// file, whose edit could remove the guard.
func settingsFile(text string) bool { return settingsRe.MatchString(normalizeText(text)) }

// binaryNamed reports whether text names the Keylatch binary path.
func (p *policy) binaryNamed(text string) bool {
	return p.binary != "" && strings.Contains(strings.ToLower(normalizeText(text)), strings.ToLower(p.binary))
}
