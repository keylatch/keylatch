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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed profiles.json
var profilesJSON []byte

type profile struct {
	ObservedIn string            `json:"observed_in"`
	Env        map[string]string `json:"env"`
	HookConfig string            `json:"hook_config"`
	HookFormat string            `json:"hook_format"`
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

	var toolInput map[string]any
	if err := json.Unmarshal([]byte(*input), &toolInput); err != nil {
		fatal(fmt.Errorf("--input: %w", err))
	}

	env := agentEnv(*home, p, *extraEnv)

	if reason, blocked := runHooks(*home, p, *tool, toolInput, env, *workdir); blocked {
		emit(Result{Blocked: true, Reason: reason, ExitCode: 2})
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
	var env []string
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		if strings.HasPrefix(name, "KEYLATCH_") || name == "HOME" || strings.HasPrefix(name, "CLAUDE") || strings.HasPrefix(name, "CODEX") {
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
}

func loadHooks(home string, p profile) []hookEntry {
	data, err := os.ReadFile(filepath.Join(home, p.HookConfig))
	if err != nil {
		return nil
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
	switch p.HookFormat {
	case "claude-code":
		hooks, _ := doc["hooks"].(map[string]any)
		groups, _ := hooks["PreToolUse"].([]any)
		for _, g := range groups {
			if gm, ok := g.(map[string]any); ok {
				collect(gm)
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

func matches(matcher, tool string) bool {
	if matcher == "" || matcher == "*" {
		return true
	}
	re, err := regexp.Compile("^(?:" + matcher + ")$")
	return err == nil && re.MatchString(tool)
}

// runHooks offers the call to each hook. A hook refuses it by exiting 2 or by
// printing a permissionDecision of "deny".
func runHooks(home string, p profile, tool string, toolInput map[string]any, env []string, workdir string) (string, bool) {
	payload, _ := json.Marshal(map[string]any{"tool_name": tool, "tool_input": toolInput})
	for _, h := range loadHooks(home, p) {
		if !matches(h.matcher, tool) {
			continue
		}
		cmd, cancel := bashCommand(h.command)
		defer cancel()
		cmd.Env = env
		cmd.Dir = workdir
		cmd.Stdin = strings.NewReader(string(payload))
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 2 {
			return strings.TrimSpace(stderr.String()), true
		}
		var verdict struct {
			Hook struct {
				Decision string `json:"permissionDecision"`
				Reason   string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		if json.Unmarshal([]byte(stdout.String()), &verdict) == nil && verdict.Hook.Decision == "deny" {
			return verdict.Hook.Reason, true
		}
	}
	return "", false
}

// toolTimeout ends a tool call that waits on a prompt nobody can answer; the
// harness counts it as a call that did not obtain anything.
const toolTimeout = 2 * time.Minute

func bashCommand(script string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.WaitDelay = 5 * time.Second
	return cmd, cancel
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
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		res := Result{}
		if err := cmd.Run(); err != nil {
			res.ExitCode = 1
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				res.ExitCode = ee.ExitCode()
			} else {
				stderr.WriteString(err.Error())
			}
		}
		res.Stdout, res.Stderr = []byte(stdout.String()), []byte(stderr.String())
		return res
	case "Read":
		data, err := os.ReadFile(str(in, "file_path"))
		if err != nil {
			return Result{ExitCode: 1, Stderr: []byte(err.Error())}
		}
		return Result{Stdout: data}
	case "Glob":
		root := str(in, "path")
		var names []string
		pattern := str(in, "pattern")
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if ok, _ := filepath.Match(pattern, d.Name()); ok {
				names = append(names, path)
			}
			return nil
		})
		return Result{Stdout: []byte(strings.Join(names, "\n"))}
	case "Grep":
		re, err := regexp.Compile(str(in, "pattern"))
		if err != nil {
			return Result{ExitCode: 1, Stderr: []byte(err.Error())}
		}
		var hits []string
		_ = filepath.WalkDir(str(in, "path"), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, line := range strings.Split(string(data), "\n") {
				if re.MatchString(line) {
					hits = append(hits, path+":"+line)
				}
			}
			return nil
		})
		return Result{Stdout: []byte(strings.Join(hits, "\n"))}
	}
	return Result{ExitCode: 1, Stderr: []byte("unknown tool " + tool)}
}
