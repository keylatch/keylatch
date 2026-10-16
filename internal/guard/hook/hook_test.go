package hook

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHome   = "/home/tester"
	testBinary = "/usr/local/bin/keylatch"
)

func testEnv(t *testing.T) Env {
	t.Helper()
	t.Setenv("HOME", testHome)
	t.Setenv("USERPROFILE", testHome)
	return Env{Home: testHome, Lookup: func(string) string { return "" }, Binary: testBinary}
}

func bashPayload(cmd string) []byte {
	b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": cmd}})
	return b
}

func toolPayload(tool string, input map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"tool_name": tool, "tool_input": input})
	return b
}

func corpus(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	require.NoError(t, err)
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, strings.ReplaceAll(line, `\n`, "\n"))
	}
	require.NoError(t, sc.Err())
	return lines
}

func TestDenyCorpus(t *testing.T) {
	env := testEnv(t)
	lines := corpus(t, "deny_corpus.txt")
	require.Greater(t, len(lines), 200)
	for _, cmd := range lines {
		d := Decide(bashPayload(cmd), env)
		assert.True(t, d.Deny, "must deny: %q", cmd)
		assert.NotEmpty(t, d.Reason, "deny needs a reason: %q", cmd)
	}
}

func TestAllowCorpus(t *testing.T) {
	env := testEnv(t)
	lines := corpus(t, "allow_corpus.txt")
	require.Greater(t, len(lines), 100)
	for _, cmd := range lines {
		d := Decide(bashPayload(cmd), env)
		assert.False(t, d.Deny, "must allow: %q (denied: %s)", cmd, d.Reason)
	}
}

func TestFailClosedOnParseError(t *testing.T) {
	env := testEnv(t)
	for _, cmd := range []string{"echo 'unterminated", "if then", "echo $(", "cat <<EOF", "((", "echo ${", "x=(", "case x in", "echo =(env)", "ls ; ; env"} {
		d := Decide(bashPayload(cmd), env)
		assert.True(t, d.Deny, "unparsable command must be denied: %q", cmd)
	}
	for name, payload := range map[string][]byte{
		"not json":         []byte("{"),
		"empty":            nil,
		"no tool":          []byte(`{"tool_input":{"command":"ls"}}`),
		"bash no command":  toolPayload("Bash", map[string]any{}),
		"bash bad command": toolPayload("Bash", map[string]any{"command": 5}),
	} {
		assert.True(t, Decide(payload, env).Deny, name)
	}
}

func TestFailClosedOnInternalPanic(t *testing.T) {
	t.Setenv("HOME", testHome)
	env := Env{Home: testHome, Lookup: func(string) string { panic("boom") }}
	d := Decide(bashPayload("ls"), env)
	assert.True(t, d.Deny)
	assert.Contains(t, d.Reason, "denies by default")
}

func TestNestingLimit(t *testing.T) {
	env := testEnv(t)
	cmd := "ls"
	for range maxDepth + 2 {
		cmd = "bash -c " + shellQuote(cmd)
	}
	d := Decide(bashPayload(cmd), env)
	assert.True(t, d.Deny)
	assert.Contains(t, d.Reason, "nested")

	hop := "env"
	cmd = "ls"
	for range maxHops + 2 {
		cmd = hop + " -i " + cmd
	}
	assert.True(t, Decide(bashPayload(cmd), env).Deny)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func TestAllFileTools(t *testing.T) {
	env := testEnv(t)
	protected := testHome + "/.ssh/id_rsa"
	cases := []struct {
		tool  string
		input map[string]any
		deny  bool
	}{
		{"Read", map[string]any{"file_path": protected}, true},
		{"Read", map[string]any{"file_path": "~/.aws/credentials"}, true},
		{"Read", map[string]any{"file_path": testHome}, true},
		{"Read", map[string]any{"file_path": testHome + "/.keylatch/config.json"}, true},
		{"Read", map[string]any{"file_path": testHome + "/.bash_history"}, true},
		{"Read", map[string]any{"file_path": testHome + "/proj/../.ssh/id_rsa"}, true},
		{"Read", map[string]any{"file_path": "/work/app/.env"}, true},
		{"Read", map[string]any{"file_path": "/work/app/.env.example"}, false},
		{"Read", map[string]any{"file_path": "/work/app/main.go"}, false},
		{"Grep", map[string]any{"pattern": ".", "path": testHome + "/.ssh"}, true},
		{"Grep", map[string]any{"pattern": "BEGIN", "path": "~/.ssh"}, true},
		{"Grep", map[string]any{"pattern": "k", "glob": testHome + "/.aws/*"}, true},
		{"Grep", map[string]any{"pattern": "k", "path": testHome}, true},
		{"Grep", map[string]any{"pattern": "TODO", "path": "/work/src"}, false},
		{"Grep", map[string]any{"pattern": "/\\*", "path": "/work/src"}, false},
		{"Grep", map[string]any{"pattern": "//.*TODO"}, false},
		{"Grep", map[string]any{"pattern": "TODO"}, false},
		{"Glob", map[string]any{"pattern": testHome + "/.ssh/**"}, true},
		{"Glob", map[string]any{"pattern": ".ss*/*", "path": testHome}, true},
		{"Glob", map[string]any{"pattern": testHome + "/.ss*/id_*"}, true},
		{"Grep", map[string]any{"pattern": "bw-session", "path": testHome + "/.config/keylatch"}, true},
		{"Glob", map[string]any{"pattern": "*", "path": testHome + "/.config/keylatch"}, true},
		{"Glob", map[string]any{"pattern": "**/*.go", "path": "/work"}, false},
		{"Glob", map[string]any{"pattern": "/work/src/**/*.go"}, false},
		{"Glob", map[string]any{"pattern": "*.md", "path": testHome}, false},
		{"NotebookRead", map[string]any{"notebook_path": testHome + "/.ssh/nb.ipynb"}, true},
		{"NotebookRead", map[string]any{"notebook_path": "/work/nb.ipynb"}, false},
		{"Edit", map[string]any{"file_path": testHome + "/.npmrc"}, true},
		{"Edit", map[string]any{"file_path": testHome + "/.claude/settings.json"}, true},
		{"Edit", map[string]any{"file_path": "/work/.claude/settings.local.json"}, true},
		{"Edit", map[string]any{"file_path": testBinary}, true},
		{"Edit", map[string]any{"file_path": "/work/main.go"}, false},
		{"Edit", map[string]any{"file_path": "/work/.env"}, false},
		{"Write", map[string]any{"file_path": testHome + "/.ssh/authorized_keys"}, true},
		{"Write", map[string]any{"file_path": testHome + "/.claude/hooks/x.sh"}, true},
		{"Write", map[string]any{"file_path": "/work/notes.md"}, false},
		{"MultiEdit", map[string]any{"file_path": testHome + "/.aws/config"}, true},
		{"MultiEdit", map[string]any{"file_path": testHome + "/.claude.json"}, true},
		{"MultiEdit", map[string]any{"file_path": "/work/a.go"}, false},
		{"NotebookEdit", map[string]any{"notebook_path": testHome + "/.gnupg/nb.ipynb"}, true},
		{"NotebookEdit", map[string]any{"notebook_path": "/etc/claude-code/managed-settings.json"}, true},
		{"NotebookEdit", map[string]any{"notebook_path": "/work/nb.ipynb"}, false},
		{"WebFetch", map[string]any{"url": "https://example.com"}, false},
		{"Task", map[string]any{"prompt": "read ~/.ssh/id_rsa"}, false},
		{"LS", map[string]any{"path": testHome + "/.ssh"}, true},
		{"mcp__thing__read", map[string]any{"path": testHome + "/.kube/config"}, true},
		{"read_many_files", map[string]any{"paths": []any{"/work/a.go", testHome + "/.ssh/id_rsa"}}, true},
		{"read_many_files", map[string]any{"paths": []any{"/work/a.go"}}, false},
	}
	for _, c := range cases {
		d := Decide(toolPayload(c.tool, c.input), env)
		assert.Equal(t, c.deny, d.Deny, "%s %v (reason: %s)", c.tool, c.input, d.Reason)
	}
}

func TestRelativeToolPathUsesCwd(t *testing.T) {
	env := testEnv(t)
	b, _ := json.Marshal(map[string]any{"tool_name": "Read", "cwd": testHome, "tool_input": map[string]any{"file_path": ".ssh/id_rsa"}})
	assert.True(t, Decide(b, env).Deny)
	b, _ = json.Marshal(map[string]any{"tool_name": "Read", "cwd": "/work", "tool_input": map[string]any{"file_path": ".ssh/id_rsa"}})
	assert.False(t, Decide(b, env).Deny)
	b, _ = json.Marshal(map[string]any{"tool_name": "Bash", "cwd": testHome, "tool_input": map[string]any{"command": "cat .ssh/id_rsa"}})
	assert.True(t, Decide(b, env).Deny)
	b, _ = json.Marshal(map[string]any{"tool_name": "Bash", "cwd": testHome + "/.ssh", "tool_input": map[string]any{"command": "cat id_rsa"}})
	assert.True(t, Decide(b, env).Deny)
	b, _ = json.Marshal(map[string]any{"tool_name": "Bash", "cwd": "/work", "tool_input": map[string]any{"command": "cat .ssh/id_rsa && cd .. && echo ok"}})
	assert.False(t, Decide(b, env).Deny)
}

func TestGuardedDirsPerOS(t *testing.T) {
	t.Setenv("HOME", testHome)
	t.Setenv("USERPROFILE", testHome)
	lookup := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		name string
		env  map[string]string
		path string
	}{
		{"default dot dir", nil, testHome + "/.keylatch/vault/x"},
		{"default config dir", nil, testHome + "/.config/keylatch/config.json"},
		{"config dir override", map[string]string{"KEYLATCH_CONFIG_DIR": "/srv/kl"}, "/srv/kl/vault/identity"},
		{"xdg config", map[string]string{"XDG_CONFIG_HOME": "/xdg"}, "/xdg/keylatch/config.json"},
		{"vault override", map[string]string{"KEYLATCH_VAULT_PATH": "/data/vault"}, "/data/vault/keys"},
		{"audit override", map[string]string{"KEYLATCH_AUDIT_PATH": "/var/log/kl/audit.log"}, "/var/log/kl/audit.log"},
		{"socket dir", map[string]string{"KEYLATCH_SOCKET": "/run/kl/keylatchd.sock"}, "/run/kl/keylatchd.sock"},
	}
	for _, c := range cases {
		env := Env{Home: testHome, Lookup: lookup(c.env), Binary: testBinary}
		assert.True(t, Decide(bashPayload("cat "+c.path), env).Deny, c.name+" (shell)")
		assert.True(t, Decide(toolPayload("Read", map[string]any{"file_path": c.path}), env).Deny, c.name+" (Read)")
		assert.True(t, Decide(toolPayload("Glob", map[string]any{"pattern": filepath.ToSlash(filepath.Dir(c.path)) + "/*"}), env).Deny, c.name+" (Glob)")
	}
	env := Env{Home: testHome, Lookup: lookup(nil), Binary: testBinary}
	assert.False(t, Decide(bashPayload("cat /srv/other/file"), env).Deny)
}

func TestSymlinkIntoProtectedDirIsDenied(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), []byte("k"), 0o600))
	work := t.TempDir()
	require.NoError(t, os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(work, "link")))
	env := Env{Home: home, Lookup: func(string) string { return "" }, Binary: testBinary}

	assert.True(t, Decide(toolPayload("Read", map[string]any{"file_path": filepath.Join(work, "link", "id_rsa")}), env).Deny)
	assert.True(t, Decide(toolPayload("Read", map[string]any{"file_path": filepath.Join(work, "link", "missing")}), env).Deny)
	assert.False(t, Decide(toolPayload("Read", map[string]any{"file_path": filepath.Join(work, "plain.txt")}), env).Deny)
}

func TestHomeSymlinkSpellings(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "homelink")
	require.NoError(t, os.Symlink(real, link))
	t.Setenv("HOME", link)
	env := Env{Home: link, Lookup: func(string) string { return "" }}
	resolved, err := filepath.EvalSymlinks(real)
	require.NoError(t, err)
	assert.True(t, Decide(bashPayload("cat "+filepath.ToSlash(resolved)+"/.ssh/id_rsa"), env).Deny)
	assert.True(t, Decide(bashPayload("cat "+filepath.ToSlash(link)+"/.ssh/id_rsa"), env).Deny)
}

func TestRunProtocol(t *testing.T) {
	env := testEnv(t)
	var out, errOut bytes.Buffer

	code := Run(strings.NewReader(string(bashPayload("cat ~/.ssh/id_rsa"))), &out, &errOut, env)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut.String(), "[hook/keylatch] Blocked:")
	var resp struct {
		Out struct {
			Event    string `json:"hookEventName"`
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &resp))
	assert.Equal(t, "PreToolUse", resp.Out.Event)
	assert.Equal(t, "deny", resp.Out.Decision)
	assert.NotEmpty(t, resp.Out.Reason)

	out.Reset()
	errOut.Reset()
	assert.Equal(t, 0, Run(strings.NewReader(string(bashPayload("go test ./..."))), &out, &errOut, env))
	assert.Empty(t, out.String())
	assert.Empty(t, errOut.String())

	assert.Equal(t, 2, Run(errReader{}, &out, &errOut, env))
	assert.Equal(t, 2, Run(strings.NewReader(strings.Repeat("x", maxPayload+10)), &out, &errOut, env))
	assert.Equal(t, 2, Run(strings.NewReader(""), &out, &errOut, env))
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestDefaultEnv(t *testing.T) {
	env := DefaultEnv()
	assert.NotNil(t, env.Lookup)
	assert.NotEmpty(t, env.Home)
	assert.False(t, Decide(bashPayload("echo hi"), env).Deny)
}

func TestNewPolicyWithoutHomeOrLookup(t *testing.T) {
	p := newPolicy(Env{})
	assert.NotNil(t, p)
	assert.False(t, p.pathDenied("/work/a.go", "", false))
	assert.False(t, p.historyFile("/anything"))
}

func TestDecodeANSIC(t *testing.T) {
	cases := map[string]string{
		`\x65nv`: "env", `\145nv`: "env", `e\u006ev`: "env", `\U0000006Env`: "nnv", `a\tb\nc`: "a\tb\nc",
		`\a\b\e\E\f\r\v`: "\a\b\x1b\x1b\f\r\v", `\\ \' \"`: `\ ' "`, `\xZ`: "xZ", `\q`: "q", `end\`: `end\`,
	}
	for in, want := range cases {
		assert.Equal(t, want, decodeANSIC(in), in)
	}
}

func TestBraceVariants(t *testing.T) {
	assert.Equal(t, []string{"env", ""}, braceVariants("{env,}"))
	assert.Equal(t, []string{"a", "b", "c"}, braceVariants("{a,b,c}"))
	assert.Equal(t, []string{"xay", "xby"}, braceVariants("x{a,b}y"))
	assert.Equal(t, []string{"ac", "ad", "bc", "bd"}, braceVariants("{a,b}{c,d}"))
	assert.ElementsMatch(t, []string{"a", "b", "c"}, braceVariants("{a,{b,c}}"))
	assert.Equal(t, []string{"{a}"}, braceVariants("{a}"))
	assert.Equal(t, []string{"{a,b"}, braceVariants("{a,b"))
	assert.Equal(t, []string{"plain"}, braceVariants("plain"))
	assert.LessOrEqual(t, len(braceVariants("{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}")), 70)
}

func TestUnescapeAndNames(t *testing.T) {
	assert.Equal(t, "a$b", unescape(`a\$b`, true))
	assert.Equal(t, `a\nb`, unescape(`a\nb`, true))
	assert.Equal(t, "anb", unescape(`a\nb`, false))
	assert.Equal(t, "ab", unescape("a\\\nb", false))
	assert.Equal(t, "end\\", unescape(`end\`, false))
	assert.Equal(t, "env", cmdName("/usr/bin/ENV.exe"))
	assert.Equal(t, "cat", cmdName(`C:\tools\cat.exe`))
	assert.Equal(t, "", cmdName(""))
}

func TestEnvFileNames(t *testing.T) {
	for name, want := range map[string]bool{
		".env": true, ".env.local": true, ".env.production": true, "prod.env": true, ".ENV": true,
		".env.example": false, ".env.sample": false, ".env.template": false, ".env.EXAMPLE": false,
		"environment.ts": false, "env": false, ".envrc": false, "main.go": false,
	} {
		assert.Equal(t, want, isEnvFileName(name), name)
	}
}

func TestSkipOptsAndHelpers(t *testing.T) {
	assert.Equal(t, []string{"cmd", "x"}, skipOpts([]string{"-a", "-b", "cmd", "x"}, nil, false))
	assert.Equal(t, []string{"cmd"}, skipOpts([]string{"-u", "root", "cmd"}, map[string]bool{"-u": true}, false))
	assert.Equal(t, []string{"cmd"}, skipOpts([]string{"A=1", "cmd"}, nil, true))
	assert.Equal(t, []string{"-x"}, skipOpts([]string{"--", "-x"}, nil, false))
	assert.Nil(t, skipOpts([]string{"-a"}, nil, false))
	assert.Nil(t, skipOpts([]string{"-u"}, map[string]bool{"-u": true}, false))
	assert.True(t, seq([]string{"--x", "auth", "-y", "token"}, "auth", "token"))
	assert.False(t, seq([]string{"token", "auth"}, "auth", "token"))
	assert.True(t, hasCluster([]string{"-lc"}, "c"))
	assert.False(t, hasCluster([]string{"--color"}, "c"))
	assert.True(t, hasFlag([]string{"--with-decryption=true"}, "--with-decryption"))
	assert.Equal(t, []string{"b"}, afterDashDash([]string{"a", "--", "b"}))
	assert.Nil(t, afterDashDash([]string{"a"}))
	assert.True(t, anyContains([]string{"A=1"}, "="))
}

func TestGlobCoverage(t *testing.T) {
	env := testEnv(t)
	p := newPolicy(env)
	for pattern, want := range map[string]bool{
		testHome + "/.ssh/**":    true,
		testHome + "/**":         true,
		testHome + "/.s?h/*":     true,
		testHome + "/.ssh":       true,
		testHome + "/code/*":     false,
		testHome + "/.ssh2/*":    false,
		"~/.aws/*":               true,
		"/work/*":                false,
		testHome + "/.[a-z]sh/x": true,
		testHome + "/[":          false,
	} {
		assert.Equal(t, want, p.globDenied(pattern, ""), pattern)
	}
	assert.False(t, p.globDenied("relative/*", ""))
	assert.True(t, p.globDenied(".ss*/*", testHome))
}

func TestPolicyTextForms(t *testing.T) {
	p := newPolicy(testEnv(t))
	for text, want := range map[string]bool{
		"~/.ssh/id_rsa":                 true,
		"$HOME/.ssh":                    true,
		"${HOME}/.aws/credentials":      true,
		"%USERPROFILE%/.ssh/id_rsa":     true,
		"$env:USERPROFILE/.ssh/id_rsa":  true,
		testHome + "/.ssh/id_rsa":       true,
		"-v ~/.ssh:/k":                  true,
		"host:~/.ssh/id_rsa":            true,
		"--from-file=$HOME/.ssh/id_rsa": true,
		"~/.ssh_config":                 false,
		"~/.sshfoo":                     false,
		"~/code/.ssh/x":                 false,
		"/tmp/home/tester/.ssh/x":       false,
		"~/.ssh2":                       false,
		"~/.keylatch-notes":             false,
		"README.md":                     false,
	} {
		assert.Equal(t, want, p.mentions(text), text)
	}
	assert.True(t, p.mentionsSecret("~/.bash_history"))
	assert.False(t, p.mentionsSecret("~/.ssh/id_rsa"))
	assert.True(t, settingsFile("~/.claude/settings.json"))
	assert.False(t, settingsFile("~/.claude/projects/x.json"))
	assert.True(t, p.binaryNamed("/usr/local/bin//keylatch"))
	assert.False(t, newPolicy(Env{Home: testHome}).binaryNamed("/anything"))
}

func TestPathDeniedForms(t *testing.T) {
	p := newPolicy(testEnv(t))
	assert.True(t, p.pathDenied("~/.ssh", "", false))
	assert.True(t, p.pathDenied(testHome, "", true))
	assert.False(t, p.pathDenied(testHome, "", false))
	assert.True(t, p.pathDenied("/", "", true))
	assert.True(t, p.pathDenied(".ssh/x", testHome, false))
	assert.False(t, p.pathDenied(".ssh/x", "", false))
	assert.True(t, p.pathDenied(testHome+"/.psql_history", "", false))
	assert.False(t, p.pathDenied(testHome+"/notes_history.txt", "", false))
	assert.False(t, p.pathDenied("/work/x", "", true))
}
