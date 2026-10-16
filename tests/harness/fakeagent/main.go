//go:build harness

// Command fakeagent behaves like an agent harness for one tool call. It sets
// the environment the real harness sets, offers the call to every installed
// pre-tool hook the way the harness does, and runs the call under the given
// home directory only when no hook refuses it. It prints one JSON result.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/harness"
)

//go:embed profiles.json
var profilesJSON []byte

type profile struct {
	ObservedIn string            `json:"observed_in"`
	Env        map[string]string `json:"env"`
	HookConfig string            `json:"hook_config"`
	// HookFile is the hook file's name inside the harness's configuration
	// directory, as the harness registry names it; HookConfig must end in it.
	HookFile   string `json:"hook_file"`
	HookFormat string `json:"hook_format"`
	// HookEvent is the event the guard registers under, for matcher-group
	// formats.
	HookEvent string `json:"hook_event"`
	// Payload names the shape of the call handed to a hook: "native" (the
	// default), "gemini", "cursor" or "opencode".
	Payload string `json:"payload"`
}

// Result is the single JSON document the program prints.
type Result struct {
	Blocked  bool   `json:"blocked"`
	Reason   string `json:"reason,omitempty"`
	ExitCode int    `json:"exit_code"`
	// Output is raw bytes so binary key material survives the JSON encoding.
	Stdout []byte `json:"stdout"`
	Stderr []byte `json:"stderr"`
}

func main() {
	var (
		profileName = flag.String("profile", "claude-code", "harness profile")
		home        = flag.String("home", "", "home directory the agent runs under")
		workdir     = flag.String("workdir", "", "working directory (default: home)")
		tool        = flag.String("tool", "Bash", "tool name")
		input       = flag.String("input", "{}", "tool_input as JSON")
		extraEnv    = flag.String("env", "", "extra KEY=VALUE pairs, newline separated")
		hooksOnly   = flag.Bool("hooks-only", false, "report whether a hook refuses the call without running it")
	)
	flag.Parse()
	if *home == "" {
		fatal(errors.New("--home is required"))
	}
	if *workdir == "" {
		*workdir = *home
	}

	var profiles map[string]profile
	if err := json.Unmarshal(profilesJSON, &profiles); err != nil {
		fatal(err)
	}
	p, ok := profiles[*profileName]
	if !ok {
		fatal(fmt.Errorf("unknown profile %q", *profileName))
	}
	if !strings.HasSuffix(p.HookConfig, p.HookFile) {
		fatal(fmt.Errorf("profile %q: hook_config %q does not end in hook_file %q", *profileName, p.HookConfig, p.HookFile))
	}

	var toolInput map[string]any
	if err := json.Unmarshal([]byte(*input), &toolInput); err != nil {
		fatal(fmt.Errorf("--input: %w", err))
	}

	env := agentEnv(*home, p, *extraEnv)

	if reason, blocked := runHooks(*home, p, *tool, toolInput, env, *workdir); blocked {
		emit(Result{Blocked: true, Reason: reason, ExitCode: 2})
		return
	}
	if *hooksOnly {
		emit(Result{})
		return
	}
	emit(runTool(*tool, toolInput, env, *workdir))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fakeagent:", err)
	os.Exit(70)
}

func emit(r Result) {
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		fatal(err)
	}
}

// agentEnv is the host environment minus anything that already marks an
// agent, plus the profile's variables and HOME.
func agentEnv(home string, p profile, extra string) []string {
	marks := map[string]bool{}
	for _, s := range harness.Signals() {
		marks[s.Name] = true
	}
	var env []string
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		if marks[name] || strings.HasPrefix(name, "KEYLATCH_") || name == "HOME" || strings.HasPrefix(name, "CLAUDE") || strings.HasPrefix(name, "CODEX") ||
			strings.HasPrefix(name, "CURSOR") || strings.HasPrefix(name, "GEMINI") || name == "XDG_CONFIG_HOME" {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "HOME="+home)
	for k, v := range p.Env {
		env = append(env, k+"="+v)
	}
	for _, line := range strings.Split(extra, "\n") {
		if line != "" {
			env = append(env, line)
		}
	}
	return env
}

type hookEntry struct {
	matcher string
	command string
	// event is the hook event the entry is under, for harnesses that run one
	// hook list per kind of call.
	event string
	// anyFailure marks a hook whose non-zero exit blocks the call, as an
	// OpenCode plugin does by throwing.
	anyFailure bool
}

var pluginPathRe = regexp.MustCompile(`const KEYLATCH = ("(?:[^"\\]|\\.)*");`)

func loadHooks(home string, p profile) []hookEntry {
	data, err := readCapped(filepath.Join(home, p.HookConfig))
	if err != nil {
		return nil
	}
	if p.HookFormat == "opencode-plugin" {
		m := pluginPathRe.FindSubmatch(data)
		var path string
		if m == nil || json.Unmarshal(m[1], &path) != nil {
			return nil
		}
		return []hookEntry{{command: `"` + path + `" guard hook --harness opencode`, anyFailure: true}}
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []hookEntry
	collect := func(group map[string]any) {
		matcher, _ := group["matcher"].(string)
		hooks, _ := group["hooks"].([]any)
		for _, h := range hooks {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); cmd != "" {
				out = append(out, hookEntry{matcher: matcher, command: cmd})
			}
		}
	}
	hooks, _ := doc["hooks"].(map[string]any)
	switch p.HookFormat {
	case "claude-code", "gemini":
		groups, _ := hooks[p.HookEvent].([]any)
		for _, g := range groups {
			if gm, ok := g.(map[string]any); ok {
				collect(gm)
			}
		}
	case "cursor":
		for event, list := range hooks {
			entries, _ := list.([]any)
			for _, e := range entries {
				if em, ok := e.(map[string]any); ok {
					if cmd, _ := em["command"].(string); cmd != "" {
						out = append(out, hookEntry{command: cmd, event: event})
					}
				}
			}
		}
	case "event-array":
		groups, _ := doc["hooks"].([]any)
		for _, g := range groups {
			if gm, ok := g.(map[string]any); ok && gm["event"] == "PreToolUse" {
				collect(gm)
			}
		}
	}
	return out
}

// cursorEvent is the hook list Cursor offers a call to.
func cursorEvent(tool string) string {
	switch tool {
	case "Bash":
		return "beforeShellExecution"
	case "Read":
		return "beforeReadFile"
	}
	return "beforeMCPExecution"
}

// hookPayload is the call as the harness hands it to a hook.
func hookPayload(p profile, tool string, in map[string]any, workdir string) []byte {
	var v any
	switch p.Payload {
	case "gemini":
		v = map[string]any{"tool_name": nativeTool(p, tool), "tool_input": in, "cwd": workdir}
	case "cursor":
		switch tool {
		case "Bash":
			v = map[string]any{"command": in["command"], "cwd": workdir}
		case "Read":
			v = map[string]any{"file_path": in["file_path"], "attachments": []any{}}
		default:
			raw, _ := json.Marshal(in)
			v = map[string]any{"tool_name": tool, "tool_input": string(raw)}
		}
	case "opencode":
		args := map[string]any{}
		for k, val := range in {
			if k == "file_path" {
				k = "filePath"
			}
			args[k] = val
		}
		v = map[string]any{"tool_name": nativeTool(p, tool), "tool_input": args, "cwd": workdir}
	default:
		v = map[string]any{"tool_name": tool, "tool_input": in, "cwd": workdir}
	}
	b, _ := json.Marshal(v)
	return b
}

var nativeNames = map[string]map[string]string{
	"gemini":   {"Bash": "run_shell_command", "Read": "read_file", "Glob": "glob", "Grep": "search_file_content"},
	"opencode": {"Bash": "bash", "Read": "read", "Glob": "glob", "Grep": "grep"},
}

// nativeTool is the name the harness gives a tool; hook matchers are written
// against it.
func nativeTool(p profile, tool string) string {
	if n, ok := nativeNames[p.Payload][tool]; ok {
		return n
	}
	return tool
}

func matches(matcher, tool string) bool {
	if matcher == "" || matcher == "*" {
		return true
	}
	re, err := regexp.Compile("^(?:" + matcher + ")$")
	return err == nil && re.MatchString(tool)
}

// runHooks offers the call to each hook. A hook refuses it by exiting 2, by
// printing a permissionDecision of "deny" (alone or under hookSpecificOutput),
// or by printing the deny verdict of its own harness.
func runHooks(home string, p profile, tool string, toolInput map[string]any, env []string, workdir string) (string, bool) {
	payload := hookPayload(p, tool, toolInput, workdir)
	for _, h := range loadHooks(home, p) {
		if !matches(h.matcher, nativeTool(p, tool)) {
			continue
		}
		if p.HookFormat == "cursor" && h.event != cursorEvent(tool) {
			continue
		}
		cmd, cancel := bashCommand(h.command)
		defer cancel()
		cmd.Env = env
		cmd.Dir = workdir
		cmd.Stdin = strings.NewReader(string(payload))
		var stdout, stderr cappedBuffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) && (ee.ExitCode() == 2 || h.anyFailure) {
			return strings.TrimSpace(stderr.String()), true
		}
		if err != nil && h.anyFailure {
			return err.Error(), true
		}
		var verdict struct {
			Hook struct {
				Decision string `json:"permissionDecision"`
				Reason   string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
			Decision  string `json:"permissionDecision"`
			Reason    string `json:"permissionDecisionReason"`
			Gemini    string `json:"decision"`
			GeminiWhy string `json:"reason"`
			Cursor    string `json:"permission"`
			CursorWhy string `json:"user_message"`
		}
		if json.Unmarshal([]byte(stdout.String()), &verdict) != nil {
			continue
		}
		switch {
		case verdict.Hook.Decision == "deny":
			return verdict.Hook.Reason, true
		case verdict.Decision == "deny":
			return verdict.Reason, true
		case verdict.Gemini == "deny":
			return verdict.GeminiWhy, true
		case verdict.Cursor == "deny":
			return verdict.CursorWhy, true
		}
	}
	return "", false
}

// toolTimeout ends a tool call that waits on a prompt nobody can answer; the
// harness counts it as a call that did not obtain anything.
const toolTimeout = 2 * time.Minute

// outputLimit caps what one call may capture; a let-through command that
// prints forever otherwise grows the fake agent and the test until the host
// runs out of memory.
const outputLimit = 1 << 20

var errOutputLimit = errors.New("output limit reached")

// cappedBuffer keeps the first outputLimit bytes and then fails the write, so
// the child gets SIGPIPE instead of filling memory.
type cappedBuffer struct{ b strings.Builder }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := outputLimit - c.b.Len()
	if len(p) > room {
		c.b.Write(p[:max(room, 0)])
		return max(room, 0), errOutputLimit
	}
	return c.b.Write(p)
}

func (c *cappedBuffer) String() string { return c.b.String() }

// readCapped reads at most outputLimit bytes of a regular file. Devices,
// FIFOs, sockets and /proc files that report no size would otherwise block or
// read without end.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the tool call under test
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(f, outputLimit))
}

// bashCommand runs script in its own process group; the returned cancel also
// kills whatever the script left running in the background.
func bashCommand(script string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.WaitDelay = 5 * time.Second
	ownGroup(cmd)
	return cmd, func() {
		_ = killGroup(cmd)
		cancel()
	}
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func runTool(tool string, in map[string]any, env []string, workdir string) Result {
	switch tool {
	case "Bash":
		cmd, cancel := bashCommand(str(in, "command"))
		defer cancel()
		cmd.Env = env
		cmd.Dir = workdir
		var stdout, stderr cappedBuffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		res := Result{}
		if err := cmd.Run(); err != nil {
			res.ExitCode = 1
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				res.ExitCode = ee.ExitCode()
			} else {
				stderr.b.WriteString(err.Error())
			}
		}
		res.Stdout, res.Stderr = []byte(stdout.String()), []byte(stderr.String())
		return res
	case "Read":
		data, err := readCapped(str(in, "file_path"))
		if err != nil {
			return Result{ExitCode: 1, Stderr: []byte(err.Error())}
		}
		return Result{Stdout: data}
	case "Glob":
		root := str(in, "path")
		var names cappedBuffer
		deadline := time.Now().Add(toolTimeout)
		pattern := str(in, "pattern")
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if time.Now().After(deadline) {
				return fs.SkipAll
			}
			if ok, _ := filepath.Match(pattern, d.Name()); ok {
				if _, werr := names.Write([]byte(path + "\n")); werr != nil {
					return fs.SkipAll
				}
			}
			return nil
		})
		return Result{Stdout: []byte(strings.TrimSuffix(names.String(), "\n"))}
	case "Grep":
		re, err := regexp.Compile(str(in, "pattern"))
		if err != nil {
			return Result{ExitCode: 1, Stderr: []byte(err.Error())}
		}
		var hits cappedBuffer
		deadline := time.Now().Add(toolTimeout)
		_ = filepath.WalkDir(str(in, "path"), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if time.Now().After(deadline) {
				return fs.SkipAll
			}
			data, rerr := readCapped(path)
			if rerr != nil {
				return nil
			}
			for _, line := range strings.Split(string(data), "\n") {
				if !re.MatchString(line) {
					continue
				}
				if _, werr := hits.Write([]byte(path + ":" + line + "\n")); werr != nil {
					return fs.SkipAll
				}
			}
			return nil
		})
		return Result{Stdout: []byte(strings.TrimSuffix(hits.String(), "\n"))}
	}
	return Result{ExitCode: 1, Stderr: []byte("unknown tool " + tool)}
}
