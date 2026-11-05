package hook

import (
	"regexp"
	"strings"
)

type step struct {
	inner   [][]string
	program string
	reason  string
}

// resolve analyzes one command: the deny rules for its name, then whatever it
// runs (wrappers, nested shells, eval).
func (a *analyzer) resolve(argv []string, depth, hops int, stdin string, whole bool) bool {
	if len(argv) == 0 {
		return false
	}
	if hops > maxHops {
		return a.fail("wrapper commands are nested more than %d levels deep", maxHops)
	}
	if variants := braceVariants(argv[0]); len(variants) > 1 {
		for _, v := range variants {
			if a.resolve(append([]string{v}, argv[1:]...), depth, hops+1, stdin, whole) {
				return true
			}
		}
		return false
	}
	if strings.ContainsAny(argv[0], dynMark+procMark) {
		if depth > 0 {
			return a.fail("a command computed at run time inside a nested shell cannot be analysed")
		}
		return false
	}
	name, args := cmdName(argv[0]), argv[1:]
	if r := a.rules(name, args, stdin); r != "" {
		return a.fail("%s", r)
	}
	st := a.wrapper(name, args, stdin)
	switch {
	case st.reason != "":
		return a.fail("%s", st.reason)
	case st.program != "":
		return a.program(st.program, whole, depth+1)
	}
	for _, inner := range st.inner {
		if a.resolve(inner, depth, hops+1, "", false) {
			return true
		}
	}
	return false
}

var (
	interpreterRe = regexp.MustCompile(`^(python[0-9.]*|pypy[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|lua|luajit|awk|gawk|mawk|nawk)$`)
	jqRe          = regexp.MustCompile(`^(jq|gojq|yq)$`)
	envDumpRe     = regexp.MustCompile(`environ\b|os\.getenv|process\.env|Deno\.env|Bun\.env|%ENV|\bENV\b|ENVIRON|getenv`)
	jqEnvRe       = regexp.MustCompile(`(^|[^A-Za-z0-9_.])(\$ENV|env)([^A-Za-z0-9_]|$)`)
)

var envReaders = map[string]bool{
	"cat": true, "tac": true, "head": true, "tail": true, "less": true, "more": true, "most": true, "bat": true, "batcat": true,
	"nl": true, "pr": true, "cp": true, "mv": true, "rsync": true, "scp": true, "grep": true, "egrep": true, "fgrep": true,
	"zgrep": true, "rg": true, "ag": true, "ack": true, "sed": true, "cut": true, "sort": true, "uniq": true, "tr": true,
	"od": true, "xxd": true, "hexdump": true, "strings": true, "base64": true, "base32": true, "gzip": true, "zcat": true,
	"tar": true, "zip": true, "dd": true, "diff": true, "cmp": true, "comm": true, "paste": true, "column": true, "fold": true,
	"source": true, ".": true, "tee": true, "curl": true, "wget": true, "nc": true, "ncat": true, "openssl": true,
}

var settingsWriters = map[string]bool{
	"tee": true, "cp": true, "mv": true, "ln": true, "install": true, "rm": true, "truncate": true, "dd": true,
	"chmod": true, "chattr": true, "rsync": true, "sed": true, "perl": true,
}

// rules holds the per-command deny rules.
func (a *analyzer) rules(name string, args []string, stdin string) string {
	pos := positional(args)
	has := func(words ...string) bool {
		for _, p := range pos {
			for _, w := range words {
				if p == w {
					return true
				}
			}
		}
		return false
	}
	first := ""
	if len(pos) > 0 {
		first = pos[0]
	}
	switch name {
	case "printenv":
		return "printenv dumps the environment"
	case "set":
		if len(args) == 0 {
			return "set without arguments prints every shell variable, including the environment"
		}
	case "compgen":
		if hasCluster(args, "ve") || (hasFlag(args, "-A") && has("variable", "export")) {
			return "compgen -v/-e lists environment variable names"
		}
	case "history", "fc":
		return name + " reads shell history"
	case "tmux":
		if has("show-environment", "show-env", "showenv") {
			return "tmux show-environment dumps the session environment"
		}
	case "direnv":
		if first == "export" || first == "dump" {
			return "direnv " + first + " prints the loaded environment"
		}
	case "mise", "rtx":
		switch {
		case first == "env" || first == "e" || first == "hook-env":
			return "mise " + first + " prints the managed environment"
		case first == "set" && !anyContains(pos[1:], "="):
			return "mise set without an assignment prints the managed environment"
		case first == "config" && has("get"):
			return "mise config get reads the managed environment"
		}
	case "atuin":
		if has("search", "history", "stats", "dotfiles", "kv", "store") {
			return "atuin exposes shell history and stored variables"
		}
	case "sops":
		if hasFlag(args, "-d", "--decrypt") || hasCluster(args, "d") || has("decrypt", "exec-env", "exec-file") {
			return "sops decryption prints secrets"
		}
	case "age", "rage":
		if hasFlag(args, "--decrypt") || hasCluster(args, "d") {
			return "age decryption prints secrets"
		}
	case "secret-tool":
		if has("lookup", "search") {
			return "secret-tool lookup reads a keyring secret"
		}
	case "hf", "huggingface-cli":
		if seq(args, "auth", "token") {
			return "hf auth token prints an access token"
		}
	case "gh":
		if seq(args, "auth", "token") || (seq(args, "auth", "status") && hasFlag(args, "-t", "--show-token")) {
			return "gh auth token prints a GitHub token"
		}
	case "git":
		if sub, _ := gitSub(args); sub == "credential" || strings.HasPrefix(sub, "credential-") {
			return "git credential reads stored credentials"
		}
	case "gcloud":
		if seq(args, "auth", "print-access-token") || seq(args, "auth", "print-identity-token") || seq(args, "secrets", "versions", "access") || seq(args, "config", "config-helper") {
			return "gcloud prints a token or secret value"
		}
	case "az":
		if seq(args, "account", "get-access-token") || seq(args, "keyvault", "secret", "show") || seq(args, "keyvault", "secret", "download") || seq(args, "ad", "sp", "create-for-rbac") {
			return "az prints a token or secret value"
		}
	case "aws":
		if seq(args, "secretsmanager", "get-secret-value") || seq(args, "configure", "export-credentials") ||
			(has("get-parameter", "get-parameters", "get-parameters-by-path") && hasFlag(args, "--with-decryption")) {
			return "aws prints a secret or credential"
		}
	case "vault":
		if has("read") || seq(args, "kv", "get") || seq(args, "kv", "export") {
			return "vault prints a secret"
		}
	case "op":
		if has("read", "inject", "run") || seq(args, "item", "get") || seq(args, "document", "get") {
			return "the 1Password CLI prints a secret"
		}
	case "bw":
		if has("get", "export", "list", "serve", "unlock", "login") {
			return "the Bitwarden CLI prints a secret or a session key"
		}
	case "bws":
		return "the Bitwarden Secrets Manager CLI prints secrets"
	case "doppler":
		if has("secrets") {
			return "doppler secrets prints secrets"
		}
	case "infisical":
		if has("secrets", "export") {
			return "infisical prints secrets"
		}
	case "systemd-creds":
		if has("decrypt", "cat") {
			return "systemd-creds decrypt prints a credential"
		}
	case "security":
		if has("find-generic-password", "find-internet-password", "find-key", "dump-keychain", "export") {
			return "security reads the macOS keychain"
		}
	case "keylatch":
		switch {
		case first == "get" && !hasFlag(args, "--masked"):
			return "keylatch get prints a raw secret; use --masked or keylatch run"
		case first == "export" || first == "backup":
			return "keylatch " + first + " writes secret values out"
		}
	case "kubectl":
		if seq(args, "config", "view") && hasFlag(args, "--raw", "--flatten") {
			return "kubectl config view --raw prints cluster credentials"
		}
	}
	if strings.HasPrefix(name, "docker-credential-") {
		return name + " reads stored registry credentials"
	}
	text := strings.Join(args, "\n")
	if stdin != pipedIn {
		text += "\n" + stdin
	}
	switch {
	case interpreterRe.MatchString(name) && envDumpRe.MatchString(text):
		return name + " reads the process environment"
	case jqRe.MatchString(name) && jqEnvRe.MatchString(text):
		return name + " reads the process environment"
	case interpreterRe.MatchString(name) && stdin != "" && stdin != pipedIn && a.p.mentions(stdin):
		return name + " reads a Keylatch or credential location"
	}
	if envReaders[name] {
		for _, x := range args {
			if !strings.HasPrefix(x, "-") && isEnvFileName(lastElem(x)) {
				return name + " reads " + x + ": .env files hold secrets"
			}
		}
	}
	if settingsWriters[name] && (name != "sed" || hasCluster(args, "i") || hasFlag(args, "--in-place")) {
		for _, x := range args {
			if settingsFile(x) || a.p.binaryNamed(x) {
				return name + " would change a harness settings file or the Keylatch binary: " + x
			}
		}
	}
	return ""
}

func anyContains(in []string, sub string) bool {
	for _, s := range in {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

var shells = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "fish": true, "csh": true, "tcsh": true}

var simpleWrappers = map[string]map[string]bool{
	"sudo":       {"-u": true, "-g": true, "-h": true, "-p": true, "-r": true, "-t": true, "-C": true, "-D": true, "-T": true, "-U": true},
	"doas":       {"-u": true, "-C": true},
	"nice":       {"-n": true},
	"ionice":     {"-c": true, "-n": true, "-p": true, "-P": true, "-u": true},
	"nohup":      {},
	"setsid":     {},
	"time":       {"-f": true, "-o": true},
	"stdbuf":     {"-i": true, "-o": true, "-e": true},
	"command":    {},
	"builtin":    {},
	"exec":       {"-a": true},
	"xargs":      {"-a": true, "-d": true, "-E": true, "-I": true, "-L": true, "-n": true, "-P": true, "-s": true, "-l": true},
	"unbuffer":   {},
	"caffeinate": {"-t": true, "-w": true},
	"rtk":        {},
}

func afterDashDash(args []string) []string {
	for i, x := range args {
		if x == "--" {
			return args[i+1:]
		}
	}
	return nil
}

func one(argv []string) step {
	if len(argv) == 0 {
		return step{}
	}
	return step{inner: [][]string{argv}}
}

// wrapper unwraps the commands that run another command.
func (a *analyzer) wrapper(name string, args []string, stdin string) step {
	pos := positional(args)
	switch {
	case shells[name]:
		return shellStep(args, stdin)
	case name == "eval":
		return step{program: strings.Join(args, " ")}
	case name == "env":
		return envStep(args)
	case name == "command" && hasFlag(args, "-v", "-V"):
		return step{}
	case simpleWrappers[name] != nil:
		return one(skipOpts(args, simpleWrappers[name], true))
	}
	switch name {
	case "timeout":
		rest := skipOpts(args, map[string]bool{"-s": true, "-k": true, "--signal": true, "--kill-after": true}, false)
		if len(rest) > 1 {
			return one(rest[1:])
		}
	case "taskset", "flock":
		rest := skipOpts(args, map[string]bool{"-c": true, "-w": true, "-E": true}, false)
		if len(rest) > 1 {
			return one(rest[1:])
		}
	case "watch":
		if rest := skipOpts(args, map[string]bool{"-n": true, "--interval": true}, false); len(rest) > 0 {
			return step{program: strings.Join(rest, " ")}
		}
	case "su":
		for i, x := range args {
			if (x == "--command" || (len(x) > 1 && x[0] == '-' && x[1] != '-' && strings.HasSuffix(x, "c"))) && i+1 < len(args) {
				return step{program: args[i+1]}
			}
		}
	case "tmux":
		for i, x := range args {
			if (x == "run-shell" || x == "run") && i+1 < len(args) {
				if rest := skipOpts(args[i+1:], map[string]bool{"-t": true, "-d": true}, false); len(rest) > 0 {
					return step{program: strings.Join(rest, " ")}
				}
			}
		}
	case "find":
		return findStep(args)
	case "direnv":
		for i, x := range args {
			if x == "exec" {
				if rest := skipOpts(args[i+1:], nil, false); len(rest) > 1 {
					return one(rest[1:])
				}
				return step{}
			}
		}
	case "mise", "rtx":
		if len(pos) > 0 && (pos[0] == "exec" || pos[0] == "x") {
			rest := args
			for i, x := range args {
				if x == pos[0] {
					rest = args[i+1:]
					break
				}
			}
			if after := afterDashDash(rest); after != nil {
				return one(after)
			}
			for i, x := range rest {
				if !strings.HasPrefix(x, "-") && !strings.Contains(x, "@") {
					return one(rest[i:])
				}
			}
		}
	case "keylatch":
		if len(pos) > 0 && pos[0] == "run" {
			return one(afterDashDash(args))
		}
	case "doppler", "infisical":
		if len(pos) > 0 && pos[0] == "run" {
			return one(afterDashDash(args))
		}
	case "watchexec":
		if after := afterDashDash(args); after != nil {
			return one(after)
		}
		return one(skipOpts(args, map[string]bool{"-w": true, "-e": true, "-i": true, "-f": true, "-d": true, "-E": true, "--watch": true, "--exts": true, "--ignore": true, "--filter": true, "--debounce": true, "--env": true}, false))
	}
	return step{}
}

var execFlags = map[string]bool{"-exec": true, "-execdir": true, "-ok": true, "-okdir": true}

func findStep(args []string) step {
	var st step
	for i := 0; i < len(args); i++ {
		if !execFlags[args[i]] {
			continue
		}
		var cmd []string
		for i++; i < len(args) && args[i] != ";" && args[i] != "+"; i++ {
			cmd = append(cmd, args[i])
		}
		if len(cmd) > 0 {
			st.inner = append(st.inner, cmd)
		}
	}
	return st
}

var envAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func literalAbs(dir string) bool {
	return !strings.ContainsAny(dir, dynMark+procMark) && (strings.HasPrefix(slash(dir), "/") || isDrivePath(slash(dir)))
}

// envStep unwraps `env [-C dir] [-i] [-u NAME] [NAME=value ...] command`.
// env alone prints the environment, and any option the guard does not model
// is denied rather than guessed at.
func envStep(args []string) step {
	i := 0
loop:
	for i < len(args) {
		x := args[i]
		switch {
		case x == "--":
			i++
			break loop
		case x == "-C" || x == "--chdir":
			if i+1 >= len(args) || !literalAbs(args[i+1]) {
				return step{reason: "env -C needs a literal absolute directory"}
			}
			i += 2
		case strings.HasPrefix(x, "--chdir="):
			if !literalAbs(strings.TrimPrefix(x, "--chdir=")) {
				return step{reason: "env --chdir needs a literal absolute directory"}
			}
			i++
		case x == "-u" || x == "--unset":
			i += 2
		case strings.HasPrefix(x, "--unset="), x == "-i", x == "--ignore-environment", x == "-", envAssign.MatchString(x):
			i++
		case strings.HasPrefix(x, "-"):
			return step{reason: "env option " + x + " is not allowed"}
		default:
			break loop
		}
	}
	if i >= len(args) {
		return step{reason: "env without a command prints the environment"}
	}
	return one(args[i:])
}

// shellStep unwraps a nested shell: its -c payload, a script read from stdin
// (heredoc, here-string or a pipe of echo/printf), or neither.
func shellStep(args []string, stdin string) step {
	i := 0
	cFlag := false
scan:
	for i < len(args) {
		x := args[i]
		switch {
		case x == "--":
			i++
			break scan
		case x == "-o" || x == "+o" || x == "-O" || x == "+O" || x == "--rcfile" || x == "--init-file":
			i += 2
		case strings.HasPrefix(x, "--"):
			i++
		case strings.HasPrefix(x, "-") || strings.HasPrefix(x, "+"):
			if strings.Contains(x[1:], "c") {
				cFlag = true
			}
			i++
		default:
			break scan
		}
	}
	rest := args[min(i, len(args)):]
	if cFlag {
		for _, x := range rest {
			if !strings.HasPrefix(x, "-") {
				return step{program: x}
			}
		}
		return step{}
	}
	if len(rest) > 0 {
		if strings.Contains(rest[0], procMark) {
			return step{reason: "a shell runs a process substitution, which cannot be analysed"}
		}
		return step{}
	}
	switch stdin {
	case "":
		return step{}
	case pipedIn:
		return step{reason: "a shell reads commands from a pipe that cannot be analysed"}
	}
	return step{program: stdin}
}
