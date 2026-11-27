package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// An adapter turns one harness's stdin payload into the tool call the guard
// decides on and says how that harness wants a denial reported.
type adapter struct {
	parse func(payload []byte) (toolCall, error)
	// deny writes the harness's deny JSON (empty for none) and names the exit
	// status. Most harnesses block on exit 2; Antigravity documents decisions
	// as stdout JSON only.
	denyJSON func(reason string) string
	exit     int
	// allowJSON is printed for an allowed call by harnesses that expect an answer.
	allowJSON string
}

func marshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var adapters = map[string]adapter{
	"claude-code": {parse: parseNative, exit: 2, denyJSON: hookSpecificDeny},
	"codex":       {parse: parseNative, exit: 2, denyJSON: hookSpecificDeny},
	"gemini-cli": {
		parse: parseGemini, exit: 2, allowJSON: `{"decision":"allow"}`,
		denyJSON: func(r string) string { return marshal(map[string]string{"decision": "deny", "reason": r}) },
	},
	"antigravity": {
		parse: parseAntigravity, exit: 0, allowJSON: `{"decision":"allow"}`,
		denyJSON: func(r string) string { return marshal(map[string]string{"decision": "deny", "reason": r}) },
	},
	"cursor": {
		parse: parseCursor, exit: 2, allowJSON: `{"permission":"allow"}`,
		denyJSON: func(r string) string {
			return marshal(map[string]string{"permission": "deny", "user_message": r, "agent_message": r})
		},
	},
	"copilot-cli": {
		parse: parseCopilot, exit: 2,
		denyJSON: func(r string) string {
			return marshal(map[string]string{"permissionDecision": "deny", "permissionDecisionReason": r})
		},
	},
	"windsurf": {parse: parseWindsurf, exit: 2},
	"opencode": {parse: parseOpenCode, exit: 2},
}

func hookSpecificDeny(reason string) string {
	return marshal(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": reason,
	}})
}

// Harnesses lists the harness IDs the guard understands.
func Harnesses() []string {
	out := make([]string, 0, len(adapters))
	for id := range adapters {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// DecideFor evaluates one payload in the named harness's format.
func DecideFor(harnessID string, payload []byte, env Env) (d Decision) {
	defer func() {
		if r := recover(); r != nil {
			d = deny("the guard failed unexpectedly (%v) and denies by default", r)
		}
	}()
	a, ok := adapters[harnessID]
	if !ok {
		return deny("unsupported harness %q (supported: %s)", harnessID, strings.Join(Harnesses(), ", "))
	}
	call, err := a.parse(payload)
	if err != nil {
		return deny("%v", err)
	}
	return decideCall(call, env)
}

// RunFor reads one payload from stdin and reports the decision the way the
// harness expects: a denial is the harness's deny JSON on stdout, the reason on
// stderr and its documented exit status; an allow prints what the harness
// expects (often nothing) and returns 0. A payload that cannot be read, is too
// large or is not understood is a denial.
func RunFor(harnessID string, stdin io.Reader, stdout, stderr io.Writer, env Env) int {
	a, known := adapters[harnessID]
	if !known {
		fmt.Fprintf(stderr, "[hook/keylatch] Blocked: unsupported harness %q (supported: %s)\n", harnessID, strings.Join(Harnesses(), ", "))
		return 2
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxPayload+1))
	var d Decision
	switch {
	case err != nil:
		d = deny("the tool call payload could not be read: %v", err)
	case len(data) > maxPayload:
		d = deny("the tool call payload is larger than %d bytes", maxPayload)
	default:
		d = DecideFor(harnessID, data, env)
	}
	if !d.Deny {
		if a.allowJSON != "" {
			fmt.Fprintln(stdout, a.allowJSON)
		}
		return 0
	}
	reason := "[hook/keylatch] Blocked: " + d.Reason
	fmt.Fprintln(stderr, reason)
	if a.denyJSON != nil {
		fmt.Fprintln(stdout, a.denyJSON(reason))
	}
	return a.exit
}

func parseNative(payload []byte) (toolCall, error) {
	var call toolCall
	if err := json.Unmarshal(payload, &call); err != nil {
		return toolCall{}, fmt.Errorf("the tool call payload is not valid JSON: %v", err)
	}
	return call, nil
}

// rename maps a harness's tool names onto the names the guard's file-tool rules
// know.
func rename(call toolCall, names map[string]string) toolCall {
	if to, ok := names[call.ToolName]; ok {
		call.ToolName = to
	}
	return call
}

func parseGemini(payload []byte) (toolCall, error) {
	call, err := parseNative(payload)
	if err != nil {
		return call, err
	}
	return rename(call, map[string]string{
		"run_shell_command": "Bash", "read_file": "Read", "read_many_files": "Read", "list_directory": "Read",
		"glob": "Glob", "search_file_content": "Grep", "grep_search": "Grep", "write_file": "Write", "replace": "Edit",
	}), nil
}

func parseOpenCode(payload []byte) (toolCall, error) {
	call, err := parseNative(payload)
	if err != nil {
		return call, err
	}
	return rename(call, map[string]string{
		"bash": "Bash", "read": "Read", "list": "Read", "glob": "Glob", "grep": "Grep",
		"write": "Write", "edit": "Edit", "patch": "Edit", "multiedit": "MultiEdit",
	}), nil
}

// parseCursor reads the three payloads Cursor sends: beforeShellExecution
// ({"command"}), beforeReadFile ({"file_path", "attachments"}) and
// beforeMCPExecution ({"tool_name", "tool_input"}, the input being a JSON
// string), plus the tool-call form some Cursor builds use for the shell.
func parseCursor(payload []byte) (toolCall, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return toolCall{}, fmt.Errorf("the tool call payload is not valid JSON: %v", err)
	}
	str := func(key string) string {
		var s string
		_ = json.Unmarshal(raw[key], &s)
		return s
	}
	cwd := str("cwd")
	if name := str("tool_name"); name != "" {
		input := map[string]any{}
		if len(raw["tool_input"]) > 0 {
			var s string
			if json.Unmarshal(raw["tool_input"], &s) == nil {
				_ = json.Unmarshal([]byte(s), &input)
			} else {
				_ = json.Unmarshal(raw["tool_input"], &input)
			}
		}
		if name == "Shell" || name == "run_terminal_cmd" {
			name = "Bash"
		}
		return toolCall{ToolName: name, ToolInput: input, Cwd: cwd}, nil
	}
	if cmd, ok := raw["command"]; ok {
		var c string
		if json.Unmarshal(cmd, &c) != nil {
			return toolCall{}, fmt.Errorf("the Cursor shell payload carries no command string")
		}
		return toolCall{ToolName: "Bash", ToolInput: map[string]any{"command": c}, Cwd: cwd}, nil
	}
	if _, ok := raw["file_path"]; ok {
		paths := []any{}
		if p := str("file_path"); p != "" {
			paths = append(paths, p)
		}
		var attachments []struct {
			FilePath string `json:"file_path"`
		}
		_ = json.Unmarshal(raw["attachments"], &attachments)
		for _, a := range attachments {
			if a.FilePath != "" {
				paths = append(paths, a.FilePath)
			}
		}
		return toolCall{ToolName: "Read", ToolInput: map[string]any{"paths": paths}, Cwd: cwd}, nil
	}
	return toolCall{}, fmt.Errorf("the Cursor payload is not a shell, read or MCP call")
}

// parseCopilot reads Copilot's two shapes: the Claude-style tool_name and
// tool_input, and toolName with toolArgs as a JSON string.
func parseCopilot(payload []byte) (toolCall, error) {
	var raw struct {
		ToolName string          `json:"toolName"`
		ToolArgs json.RawMessage `json:"toolArgs"`
		Cwd      string          `json:"cwd"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return toolCall{}, fmt.Errorf("the tool call payload is not valid JSON: %v", err)
	}
	if raw.ToolName == "" {
		return parseNative(payload)
	}
	input := map[string]any{}
	var s string
	if json.Unmarshal(raw.ToolArgs, &s) == nil {
		_ = json.Unmarshal([]byte(s), &input)
	} else {
		_ = json.Unmarshal(raw.ToolArgs, &input)
	}
	call := toolCall{ToolName: raw.ToolName, ToolInput: input, Cwd: raw.Cwd}
	return rename(call, map[string]string{
		"bash": "Bash", "powershell": "Bash", "view": "Read", "edit": "Edit", "create": "Write",
		"glob": "Glob", "grep": "Grep",
	}), nil
}

// parseAntigravity reads {"toolCall":{"name","args"}}.
func parseAntigravity(payload []byte) (toolCall, error) {
	var raw struct {
		ToolCall struct {
			Name string         `json:"name"`
			Args map[string]any `json:"args"`
		} `json:"toolCall"`
		Cwd string `json:"cwd"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return toolCall{}, fmt.Errorf("the tool call payload is not valid JSON: %v", err)
	}
	if raw.ToolCall.Name == "" {
		return parseNative(payload)
	}
	input := raw.ToolCall.Args
	if input == nil {
		input = map[string]any{}
	}
	call := toolCall{ToolName: raw.ToolCall.Name, ToolInput: input, Cwd: raw.Cwd}
	if call.ToolName == "run_command" {
		call.ToolName = "Bash"
		input["command"] = input["CommandLine"]
	}
	if call.ToolName == "view_file" {
		call.ToolName = "Read"
	}
	return call, nil
}

// parseWindsurf reads {"agent_action_name", "tool_info"}.
func parseWindsurf(payload []byte) (toolCall, error) {
	var raw struct {
		Action   string         `json:"agent_action_name"`
		ToolInfo map[string]any `json:"tool_info"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return toolCall{}, fmt.Errorf("the tool call payload is not valid JSON: %v", err)
	}
	info := raw.ToolInfo
	if info == nil {
		info = map[string]any{}
	}
	cwd, _ := info["cwd"].(string)
	switch raw.Action {
	case "pre_run_command":
		return toolCall{ToolName: "Bash", ToolInput: map[string]any{"command": info["command_line"]}, Cwd: cwd}, nil
	case "pre_read_code":
		return toolCall{ToolName: "Read", ToolInput: info, Cwd: cwd}, nil
	case "pre_write_code":
		return toolCall{ToolName: "Write", ToolInput: info, Cwd: cwd}, nil
	case "pre_mcp_tool_use":
		args, _ := info["mcp_tool_arguments"].(map[string]any)
		if args == nil {
			args = map[string]any{}
		}
		return toolCall{ToolName: "mcp__" + fmt.Sprint(info["mcp_server_name"]) + "__" + fmt.Sprint(info["mcp_tool_name"]), ToolInput: args}, nil
	}
	return toolCall{}, fmt.Errorf("unknown Windsurf action %q", raw.Action)
}
