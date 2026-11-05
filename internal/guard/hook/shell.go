package hook

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	// dynMark stands in for a value computed at run time; procMark for a
	// process substitution.
	dynMark  = "\x01"
	procMark = "\x02"
	// pipedIn marks stdin fed by a pipeline the guard cannot read.
	pipedIn = "\x00piped"

	maxDepth = 8
	maxHops  = 16
)

type analyzer struct {
	p      *policy
	cwd    string
	reason string
	stdin  map[*syntax.CallExpr]string
}

func analyzeShell(p *policy, cmd, cwd string) Decision {
	a := &analyzer{p: p, cwd: path.Clean(slash(cwd)), stdin: map[*syntax.CallExpr]string{}}
	if cwd == "" {
		a.cwd = ""
	}
	if a.program(cmd, true, 0) {
		return deny("%s", a.reason)
	}
	return Decision{}
}

func (a *analyzer) fail(format string, args ...any) bool {
	if a.reason == "" {
		a.reason = fmt.Sprintf(format, args...)
	}
	return true
}

// program analyzes shell source and reports whether it is denied. whole is
// true when the source is the entire command the agent submitted.
func (a *analyzer) program(src string, whole bool, depth int) bool {
	if depth > maxDepth {
		return a.fail("commands are nested more than %d levels deep", maxDepth)
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		return a.fail("the command could not be parsed (%v); the guard denies what it cannot parse", err)
	}
	var wholeCall *syntax.CallExpr
	if whole && len(file.Stmts) == 1 {
		st := file.Stmts[0]
		if c, ok := st.Cmd.(*syntax.CallExpr); ok && !st.Background && !st.Coprocess && !st.Negated && !hasSubstitution(c) {
			wholeCall = c
		}
	}
	denied := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if denied {
			return false
		}
		switch n := n.(type) {
		case *syntax.Stmt:
			denied = a.stmt(n)
		case *syntax.BinaryCmd:
			a.pipe(n)
		case *syntax.CallExpr:
			denied = a.call(n, n == wholeCall, depth)
		case *syntax.DeclClause:
			denied = a.decl(n)
		}
		return !denied
	})
	return denied
}

func hasSubstitution(c *syntax.CallExpr) bool {
	found := false
	for _, w := range c.Args {
		syntax.Walk(w, func(n syntax.Node) bool {
			switch n.(type) {
			case *syntax.CmdSubst, *syntax.ProcSubst:
				found = true
			}
			return !found
		})
	}
	return found
}

// word evaluates a shell word to the text the shell would pass, with run-time
// values replaced by markers.
func (a *analyzer) word(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		a.part(&sb, part, false)
	}
	return sb.String()
}

func (a *analyzer) part(sb *strings.Builder, part syntax.WordPart, quoted bool) {
	switch p := part.(type) {
	case *syntax.Lit:
		sb.WriteString(unescape(p.Value, quoted))
	case *syntax.SglQuoted:
		if p.Dollar {
			sb.WriteString(decodeANSIC(p.Value))
		} else {
			sb.WriteString(p.Value)
		}
	case *syntax.DblQuoted:
		for _, inner := range p.Parts {
			a.part(sb, inner, true)
		}
	case *syntax.ParamExp:
		sb.WriteString(a.param(p))
	case *syntax.ProcSubst:
		sb.WriteString(procMark)
	default:
		sb.WriteString(dynMark)
	}
}

func (a *analyzer) param(p *syntax.ParamExp) string {
	if p.Param == nil || p.Excl || p.Length || p.Width || p.Index != nil || p.Slice != nil || p.Repl != nil {
		return dynMark
	}
	if p.Exp == nil {
		switch p.Param.Value {
		case "HOME", "USERPROFILE":
			if a.p.home != "" {
				return a.p.home
			}
		}
		return dynMark
	}
	if (p.Exp.Op == syntax.DefaultUnset || p.Exp.Op == syntax.DefaultUnsetOrNull) && p.Exp.Word != nil {
		return a.word(p.Exp.Word)
	}
	return dynMark
}

func unescape(v string, quoted bool) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\\' && i+1 < len(v) {
			n := v[i+1]
			if n == '\n' {
				i++
				continue
			}
			if !quoted || strings.IndexByte("$`\"\\", n) >= 0 {
				sb.WriteByte(n)
				i++
				continue
			}
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// decodeANSIC decodes the escapes of a $'...' string, which is a pure text
// transform and so can hide a command name without any execution.
func decodeANSIC(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			continue
		}
		i++
		switch c := s[i]; c {
		case 'a':
			sb.WriteByte(7)
		case 'b':
			sb.WriteByte(8)
		case 'e', 'E':
			sb.WriteByte(27)
		case 'f':
			sb.WriteByte(12)
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 't':
			sb.WriteByte('\t')
		case 'v':
			sb.WriteByte(11)
		case 'x', 'u', 'U':
			limit := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
			j := i + 1
			for j < len(s) && j-i-1 < limit && isHex(s[j]) {
				j++
			}
			n, _ := strconv.ParseUint(s[i+1:j], 16, 32)
			if j == i+1 {
				sb.WriteByte(c)
			} else if c == 'x' {
				sb.WriteByte(byte(n & 0xff))
			} else {
				sb.WriteRune(rune(n & 0x1fffff))
			}
			i = j - 1
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i
			for j < len(s) && j-i < 3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			n, _ := strconv.ParseUint(s[i:j], 8, 16)
			sb.WriteByte(byte(n & 0xff))
			i = j - 1
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

var procEnvironRe = regexp.MustCompile(`/proc/[^/\s]*/environ`)

func (a *analyzer) stmt(s *syntax.Stmt) bool {
	call, _ := s.Cmd.(*syntax.CallExpr)
	for _, r := range s.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			if call != nil {
				a.stdin[call] = a.word(r.Hdoc)
			}
			continue
		case syntax.WordHdoc:
			if call != nil {
				a.stdin[call] = a.word(r.Word)
			}
			continue
		case syntax.DplIn, syntax.DplOut:
			continue
		}
		target := a.word(r.Word)
		if procEnvironRe.MatchString(target) {
			return a.fail("reading /proc/*/environ is denied: it dumps the environment")
		}
		if a.names(target, false) {
			return a.fail("a redirection names a Keylatch or credential location (%s)", target)
		}
		input := r.Op == syntax.RdrIn || r.Op == syntax.RdrInOut
		if input && isEnvFileName(lastElem(target)) {
			return a.fail("reading %s is denied: .env files hold secrets", target)
		}
		if !input && (settingsFile(target) || a.p.binaryNamed(target)) {
			return a.fail("writes to harness settings and the Keylatch binary are denied (%s)", target)
		}
	}
	return false
}

// pipe records what a pipeline feeds the command on its right.
func (a *analyzer) pipe(b *syntax.BinaryCmd) {
	if b.Op != syntax.Pipe && b.Op != syntax.PipeAll {
		return
	}
	right, ok := b.Y.Cmd.(*syntax.CallExpr)
	if !ok {
		return
	}
	a.stdin[right] = pipedIn
	left, ok := b.X.Cmd.(*syntax.CallExpr)
	if !ok || len(left.Args) == 0 {
		return
	}
	if name := cmdName(a.word(left.Args[0])); name == "echo" || name == "printf" {
		var parts []string
		for _, w := range left.Args[1:] {
			if t := a.word(w); !strings.HasPrefix(t, "-") {
				parts = append(parts, t)
			}
		}
		a.stdin[right] = strings.Join(parts, " ")
	}
}

func isKubeconfig(name string) bool { return name == "KUBECONFIG" }

func (a *analyzer) call(c *syntax.CallExpr, whole bool, depth int) bool {
	for _, as := range c.Assigns {
		if as.Value == nil || as.Name == nil || isKubeconfig(as.Name.Value) {
			continue
		}
		if v := a.word(as.Value); a.names(v, false) {
			return a.fail("an assignment names a Keylatch or credential location (%s)", v)
		}
	}
	if len(c.Args) == 0 {
		return false
	}
	argv := make([]string, len(c.Args))
	for i, w := range c.Args {
		argv[i] = a.word(w)
	}
	a.track(argv)
	if a.checkArgs(argv, whole) {
		return true
	}
	return a.resolve(argv, depth, 0, a.stdin[c], whole)
}

func (a *analyzer) decl(d *syntax.DeclClause) bool {
	variant := d.Variant.Value
	flags, names := "", 0
	for _, as := range d.Args {
		if as.Name == nil {
			w := a.word(as.Value)
			if strings.HasPrefix(w, "-") {
				flags += w[1:]
				continue
			}
			names++
			continue
		}
		names++
		if as.Value == nil || isKubeconfig(as.Name.Value) {
			continue
		}
		if v := a.word(as.Value); a.names(v, false) {
			return a.fail("an assignment names a Keylatch or credential location (%s)", v)
		}
	}
	if variant != "local" && (names == 0 || strings.Contains(flags, "p")) {
		return a.fail("%s without a variable to set prints the environment, which is denied", variant)
	}
	return false
}

// track follows cd so a relative path is judged from the directory it runs in.
func (a *analyzer) track(argv []string) {
	if name := cmdName(argv[0]); name != "cd" && name != "pushd" {
		return
	}
	rest := skipOpts(argv[1:], nil, false)
	switch {
	case len(rest) == 0:
		a.cwd = a.p.home
	case strings.ContainsAny(rest[0], dynMark+procMark) || rest[0] == "-":
		a.cwd = ""
	default:
		target := a.p.expandHome(slash(rest[0]))
		switch {
		case isAbs(target):
			a.cwd = path.Clean(target)
		case a.cwd != "":
			a.cwd = path.Join(a.cwd, target)
		}
	}
}

// names reports whether text names a protected location, directly or relative
// to the tracked working directory.
func (a *analyzer) names(text string, echoLike bool) bool {
	return a.classify(text, echoLike) != named{}
}

type named struct{ weak, secret bool }

// classify says whether text names a protected location, and whether it is
// one no command may name.
func (a *analyzer) classify(text string, echoLike bool) named {
	n := named{weak: a.p.mentions(text), secret: a.p.mentionsSecret(text)}
	if hasGlobMeta(text) && !strings.HasPrefix(text, "-") && a.p.globDenied(text, a.cwd) {
		n.weak = true
	}
	if echoLike || a.cwd == "" || text == "" || strings.HasPrefix(text, "-") || strings.ContainsAny(text, "~$"+dynMark) || isAbs(slash(text)) {
		return n
	}
	joined := path.Join(a.cwd, slash(text))
	n.weak = n.weak || a.p.mentions(joined)
	n.secret = n.secret || a.p.mentionsSecret(joined)
	return n
}

var safeWhole = map[string]bool{"ls": true, "stat": true, "ssh-add": true, "ssh-keygen": true, "chmod": true, "chown": true, "mkdir": true, "touch": true}

func (a *analyzer) checkArgs(argv []string, whole bool) bool {
	name := cmdName(argv[0])
	echoLike := name == "echo" || name == "printf"
	hit := false
	for _, t := range argv {
		if procEnvironRe.MatchString(t) {
			return a.fail("reading /proc/*/environ is denied: it dumps the environment")
		}
		n := a.classify(t, echoLike)
		if n.secret {
			return a.fail("%s names shell history or secret-tool configuration (%s), which no command may read", name, t)
		}
		hit = hit || n.weak
	}
	if !hit || a.exempt(name, argv[1:], whole) {
		return false
	}
	return a.fail("%s names a Keylatch or credential location; direct reads of credential files are denied", name)
}

// exempt says whether a command that names a protected path only uses the file
// without printing it: cluster CLIs given their kubeconfig, and the commands in
// safeWhole, ssh and git transport when they are the whole command.
func (a *analyzer) exempt(name string, args []string, whole bool) bool {
	switch name {
	case "kubectl", "helm", "gh":
		for _, x := range args {
			if x == "--raw" || x == "--flatten" {
				return false
			}
		}
		return a.onlyValuesOf(args, "--kubeconfig", "--config")
	}
	if !whole {
		return false
	}
	switch {
	case safeWhole[name]:
		return true
	case name == "ssh" || name == "scp":
		return a.onlyValuesOf(args, "-i", "-F", "-oIdentityFile")
	case name == "git":
		return gitTransport(args)
	}
	return false
}

// onlyValuesOf reports whether the arguments name no protected location apart
// from the values of the given flags.
func (a *analyzer) onlyValuesOf(args []string, flags ...string) bool {
	for i := 0; i < len(args); i++ {
		if n := flagValueLen(args, i, flags); n > 0 {
			i += n - 1
			continue
		}
		if a.names(args[i], false) {
			return false
		}
	}
	return true
}

// flagValueLen returns how many arguments at i form a flag with its value.
func flagValueLen(args []string, i int, flags []string) int {
	x := args[i]
	for _, f := range flags {
		switch {
		case f == "-oIdentityFile":
			if strings.HasPrefix(strings.ToLower(x), "-oidentityfile") {
				return 1
			}
			if x == "-o" && i+1 < len(args) && strings.HasPrefix(strings.ToLower(args[i+1]), "identityfile") {
				return 2
			}
		case x == f:
			return 2
		case strings.HasPrefix(x, f+"="):
			return 1
		}
	}
	return 0
}

var gitTransportCmds = map[string]bool{"clone": true, "fetch": true, "pull": true, "push": true, "ls-remote": true, "init": true, "remote": true, "submodule": true, "lfs": true}

func gitTransport(args []string) bool {
	sub, _ := gitSub(args)
	return gitTransportCmds[sub]
}

// gitSub returns the git subcommand and its arguments, skipping global options.
func gitSub(args []string) (string, []string) {
	rest := skipOpts(args, map[string]bool{"-c": true, "-C": true, "--git-dir": true, "--work-tree": true, "--namespace": true}, false)
	if len(rest) == 0 {
		return "", nil
	}
	return rest[0], rest[1:]
}

func cmdName(word string) string {
	word = strings.ToLower(word[strings.LastIndexAny(word, `/\`)+1:])
	return strings.TrimSuffix(word, ".exe")
}

// skipOpts drops leading options (and the values of those in withArg) and,
// when assigns is set, leading NAME=value words.
func skipOpts(args []string, withArg map[string]bool, assigns bool) []string {
	i := 0
	for i < len(args) {
		x := args[i]
		switch {
		case x == "--":
			return args[min(i+1, len(args)):]
		case withArg[x]:
			i += 2
		case strings.HasPrefix(x, "-") && x != "-":
			i++
		case assigns && assignRe.MatchString(x):
			i++
		default:
			return args[i:]
		}
	}
	return nil
}

var assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func positional(args []string) []string {
	var out []string
	for _, x := range args {
		if !strings.HasPrefix(x, "-") {
			out = append(out, x)
		}
	}
	return out
}

func hasFlag(args []string, flags ...string) bool {
	for _, x := range args {
		for _, f := range flags {
			if x == f || strings.HasPrefix(x, f+"=") {
				return true
			}
		}
	}
	return false
}

// hasCluster reports whether any short-option cluster (-abc) contains letter.
func hasCluster(args []string, letters string) bool {
	for _, x := range args {
		if len(x) > 1 && x[0] == '-' && x[1] != '-' && strings.ContainsAny(x[1:], letters) {
			return true
		}
	}
	return false
}

// seq reports whether words occur in order among the positional arguments.
func seq(args []string, words ...string) bool {
	i := 0
	for _, x := range positional(args) {
		if i < len(words) && x == words[i] {
			i++
		}
	}
	return i == len(words)
}

func braceVariants(s string) []string {
	open := strings.IndexByte(s, '{')
	if open < 0 {
		return []string{s}
	}
	depth, comma := 0, false
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case ',':
			if depth == 1 {
				comma = true
			}
		case '}':
			depth--
			if depth == 0 {
				if !comma {
					return []string{s}
				}
				var out []string
				for _, alt := range splitTop(s[open+1 : i]) {
					for _, tail := range braceVariants(s[i+1:]) {
						out = append(out, braceVariants(s[:open]+alt+tail)...)
						if len(out) > 64 {
							return out
						}
					}
				}
				return out
			}
		}
	}
	return []string{s}
}

func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}
