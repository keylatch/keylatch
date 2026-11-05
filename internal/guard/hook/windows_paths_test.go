package hook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	winShortHome = `C:\Users\RUNNER~1\AppData\Local\Temp\TestGuard\001`
	winLongHome  = `C:\Users\runneradmin\AppData\Local\Temp\TestGuard\001`
)

// windowsEnv makes the policy see Windows paths on any OS: backslashes
// separate segments and the volume knows 8.3 short names.
func windowsEnv(t *testing.T) Env {
	t.Helper()
	oldWin, oldShort := windowsPaths, expandShortNames
	windowsPaths = true
	expandShortNames = func(p string) string {
		return strings.ReplaceAll(p, "RUNNER~1", "runneradmin")
	}
	t.Cleanup(func() { windowsPaths, expandShortNames = oldWin, oldShort })
	return Env{Home: winShortHome, Lookup: func(string) string { return "" }, Binary: `C:\Program Files\Keylatch\keylatch.exe`}
}

func bashPayloadIn(cmd, cwd string) []byte {
	b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": cmd}, "cwd": cwd})
	return b
}

func TestWindowsHomeSpellingsAreDenied(t *testing.T) {
	env := windowsEnv(t)
	short := strings.ReplaceAll(winShortHome, `\`, "/")
	long := strings.ReplaceAll(winLongHome, `\`, "/")
	for _, cmd := range []string{
		`cat ` + short + `/.ssh/id_rsa`,
		`cat ` + long + `/.ssh/id_rsa`,
		`cat ` + strings.ToLower(short) + `/.SSH/ID_RSA`,
		`cat ` + strings.ToUpper(long) + `/.zsh_history`,
		`less ` + short + `/.config/gh/hosts.yml`,
		`python3 -c 'print(open("` + short + `/.ssh/id_rsa").read())'`,
		`cat "` + winShortHome + `\.ssh\id_rsa"`,
		`type '` + winLongHome + `\.aws\credentials'`,
	} {
		d := Decide(bashPayloadIn(cmd, short), env)
		assert.True(t, d.Deny, "must deny: %q", cmd)
	}
}

func TestWindowsDriveLetterCdIsFollowed(t *testing.T) {
	env := windowsEnv(t)
	cwd := "C:/work/project"
	for _, cmd := range []string{
		`cd ~ && cat .ssh/id_rsa`,
		`cd $HOME; cat .aws/credentials`,
		`cd ~/code && cat ../.ssh/id_rsa`,
		`cd ~ && echo x >> .npmrc`,
		`cd C:/Users/runneradmin/AppData/Local/Temp/TestGuard/001 && cat .ssh/id_rsa`,
		`cd ` + strings.ReplaceAll(winShortHome, `\`, "/") + ` && cat .ssh/id_rsa`,
	} {
		d := Decide(bashPayloadIn(cmd, cwd), env)
		assert.True(t, d.Deny, "must deny: %q", cmd)
	}
}

func TestWindowsPathsOutsideTheHomeCredentialsAreAllowed(t *testing.T) {
	env := windowsEnv(t)
	short := strings.ReplaceAll(winShortHome, `\`, "/")
	for _, cmd := range []string{
		`cat ` + short + `/project/readme.md`,
		`cd ~ && cat project/readme.md`,
		`cd C:/work/project && cat src/main.go`,
		`cat C:/work/.ssh-notes.md`,
	} {
		d := Decide(bashPayloadIn(cmd, "C:/work"), env)
		assert.False(t, d.Deny, "must allow: %q (denied: %s)", cmd, d.Reason)
	}
}

func TestWindowsHomeSpellingsCoverShortAndLongNames(t *testing.T) {
	env := windowsEnv(t)
	p := newPolicy(env)
	got := strings.Join(p.homes, "|")
	assert.Contains(t, got, "C:/Users/RUNNER~1/")
	assert.Contains(t, got, "C:/Users/runneradmin/")
	require.True(t, p.historyFile("c:/users/runneradmin/appdata/local/temp/testguard/001/.zsh_history"))
	assert.False(t, p.historyFile("c:/users/runneradmin/appdata/local/temp/testguard/001/project/.zsh_history"))
}

func TestIsAbsAcceptsDriveLetters(t *testing.T) {
	for s, want := range map[string]bool{"/usr": true, "C:/Users": true, "c:/": true, "C:": false, "rel/dir": false, "": false} {
		assert.Equal(t, want, isAbs(s), s)
	}
}
