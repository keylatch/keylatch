// Package hook decides whether an agent tool call may run. It parses shell
// commands into a syntax tree, so it matches commands rather than substrings,
// and it fails closed: input it cannot parse or an internal error is a deny.
package hook

import (
	"fmt"
	"io"
	"strings"
)

// Decision is the guard's verdict for one tool call.
type Decision struct {
	Deny   bool
	Reason string
}

func deny(format string, a ...any) Decision {
	return Decision{Deny: true, Reason: fmt.Sprintf(format, a...)}
}

type toolCall struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	Cwd       string         `json:"cwd"`
}

var (
	readTools  = map[string]bool{"Read": true, "Grep": true, "Glob": true, "NotebookRead": true}
	writeTools = map[string]bool{"Edit": true, "Write": true, "MultiEdit": true, "NotebookEdit": true}
	pathKeys   = []string{"file_path", "path", "notebook_path", "dir_path", "absolute_path", "filePath", "AbsolutePath", "TargetFile", "DirectoryPath"}
)

const maxPayload = 8 << 20

// Decide evaluates one PreToolUse payload. A panic inside the guard is
// recovered and reported as a deny.
func Decide(payload []byte, env Env) (d Decision) {
	defer func() {
		if r := recover(); r != nil {
			d = deny("the guard failed unexpectedly (%v) and denies by default", r)
		}
	}()
	return decide(payload, env)
}

func decide(payload []byte, env Env) Decision {
	call, err := parseNative(payload)
	if err != nil {
		return deny("%v", err)
	}
	return decideCall(call, env)
}

func decideCall(call toolCall, env Env) Decision {
	if call.ToolName == "" {
		return deny("the tool call names no tool")
	}
	p := newPolicy(env)
	if call.ToolName == "Bash" {
		cmd, ok := call.ToolInput["command"].(string)
		if !ok {
			return deny("the Bash tool call carries no command")
		}
		return analyzeShell(p, cmd, call.Cwd)
	}
	return checkFileTool(p, call)
}

func checkFileTool(p *policy, call toolCall) Decision {
	name := call.ToolName
	read, write := readTools[name], writeTools[name]
	for _, key := range pathKeys {
		v, ok := call.ToolInput[key].(string)
		if !ok || v == "" {
			continue
		}
		if d := checkToolPath(p, name, v, call.Cwd, read && name != "Glob"); d.Deny {
			return d
		}
		if write {
			if d := checkWrite(p, v); d.Deny {
				return d
			}
		}
	}
	if name == "Glob" {
		if pat, ok := call.ToolInput["pattern"].(string); ok {
			if d := checkGlob(p, pat, call.ToolInput["path"], call.Cwd); d.Deny {
				return d
			}
		}
	}
	if g, ok := call.ToolInput["glob"].(string); ok && g != "" {
		if d := checkGlob(p, g, call.ToolInput["path"], call.Cwd); d.Deny {
			return d
		}
	}
	if paths, ok := call.ToolInput["paths"].([]any); ok {
		for _, e := range paths {
			if s, ok := e.(string); ok {
				if d := checkToolPath(p, name, s, call.Cwd, true); d.Deny {
					return d
				}
			}
		}
	}
	return Decision{}
}

func checkToolPath(p *policy, tool, v, cwd string, read bool) Decision {
	if (hasGlobMeta(v) && p.globDenied(v, cwd)) || p.pathDenied(v, cwd, read) || p.mentions(v) {
		return deny("%s of %s is denied: it names a Keylatch or credential location", tool, v)
	}
	if read && isEnvFileName(lastElem(v)) {
		return deny("%s of %s is denied: .env files hold secrets", tool, v)
	}
	return Decision{}
}

func checkGlob(p *policy, pattern string, base any, cwd string) Decision {
	dir, _ := base.(string)
	candidates := []string{pattern}
	if dir != "" && !strings.HasPrefix(p.expandHome(pattern), "/") {
		candidates = append(candidates, strings.TrimRight(dir, "/")+"/"+pattern)
	}
	for _, c := range candidates {
		if p.globDenied(c, cwd) || p.mentions(c) {
			return deny("the glob %s names a Keylatch or credential location", c)
		}
	}
	return Decision{}
}

func checkWrite(p *policy, v string) Decision {
	if settingsFile(v) {
		return deny("writes to harness settings and hook files are denied: %s", v)
	}
	if p.binaryNamed(v) {
		return deny("writes to the Keylatch binary are denied: %s", v)
	}
	return Decision{}
}

func lastElem(s string) string {
	s = strings.TrimRight(slash(s), "/")
	return s[strings.LastIndex(s, "/")+1:]
}

// Run reads one payload from stdin and writes the Claude Code decision: a deny
// is exit status 2, the reason on stderr and the deny JSON on stdout; an allow
// writes nothing and returns 0. Any read failure is a deny.
func Run(stdin io.Reader, stdout, stderr io.Writer, env Env) int {
	return RunFor("claude-code", stdin, stdout, stderr, env)
}
