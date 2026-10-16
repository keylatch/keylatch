//go:build !windows

package control

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/runner"
)

func TestParseKeyArgs(t *testing.T) {
	ka, err := parseKeyArgs(strings.Fields("sign app-key --field=signing --alg HS256 --in msg.bin --out=sig.hex --aad ctx --kid k1 --encoding hex"))
	require.NoError(t, err)
	assert.Equal(t, KeyRequest{Action: string(keyops.OpSign), Connection: "app-key", Field: "signing", Alg: "HS256", KeyID: "k1", AAD: []byte("ctx")}, ka.req)
	assert.Equal(t, "msg.bin", ka.in)
	assert.Equal(t, "sig.hex", ka.out)
	assert.Equal(t, "hex", ka.encoding)

	ka, err = parseKeyArgs(strings.Fields("verify --sig s.bin app-key"))
	require.NoError(t, err)
	assert.Equal(t, "-", ka.in, "input defaults to stdin")
	assert.Equal(t, "raw", ka.encoding)
	assert.Equal(t, "s.bin", ka.sig)

	for name, args := range map[string]string{
		"no operation":          "",
		"unknown operation":     "export app-key",
		"no connection":         "sign",
		"two connections":       "sign a b",
		"unknown option":        "sign a --bogus x",
		"option without value":  "sign a --alg",
		"unknown encoding":      "sign a --encoding rot13",
		"verify without --sig":  "verify a",
		"inline unknown option": "sign a --bogus=x",
	} {
		_, err := parseKeyArgs(strings.Fields(args))
		assert.Error(t, err, name)
	}
}

func TestParseKeyPolicyArgs(t *testing.T) {
	kp, err := parseKeyPolicyArgs(strings.Fields("allow app-key --field signing --secret=vault/path --op sign,jwt-sign --op=verify --alg HS256,,ES256 --host-key SHA256:abc --agent-decrypt --ssh-agent"))
	require.NoError(t, err)
	assert.Equal(t, KeyPolicyRequest{
		Action: "allow", Connection: "app-key", Field: "signing", Secret: "vault/path",
		Operations: []string{"sign", "jwt_sign", "verify"}, Algorithms: []string{"HS256", "ES256"},
		HostKeys: []string{"SHA256:abc"}, AgentDecrypt: true, SSHAgent: true,
	}, kp)

	kp, err = parseKeyPolicyArgs(strings.Fields("list"))
	require.NoError(t, err)
	assert.Equal(t, "list", kp.Action)
	assert.Empty(t, kp.Connection, "list takes no connection")

	for name, args := range map[string]string{
		"revoke without connection": "revoke",
		"two connections":           "allow a b",
		"unknown option":            "allow a --bogus",
		"option without value":      "allow a --field",
	} {
		_, err := parseKeyPolicyArgs(strings.Fields(args))
		assert.Error(t, err, name)
	}
}

func TestKeyCommandRejectsBadArgumentsBeforeTalkingToTheDaemon(t *testing.T) {
	for _, args := range [][]string{{"sign"}, {"allow"}, {"revoke", "a", "--bogus"}, {"verify", "a"}} {
		var out, errOut bytes.Buffer
		code := runKey(nil, args, IO{In: strings.NewReader(""), Out: &out, ErrOut: &errOut})
		assert.Equal(t, exitcode.UserError, code, args)
		assert.Contains(t, errOut.String(), "keylatch key:")
		assert.Empty(t, out.String())
	}
}

func TestKeyInputAndTextEncodings(t *testing.T) {
	assert.Equal(t, []byte{0xde, 0xad}, mustDecode(t, []byte(" dead\n"), "hex"))
	assert.Equal(t, []byte("hi"), mustDecode(t, []byte("aGk=\n"), "base64"))
	assert.Equal(t, []byte(" raw \n"), mustDecode(t, []byte(" raw \n"), "raw"), "raw input is untouched")
	_, err := decodeText([]byte("zz"), "hex")
	assert.Error(t, err)
	_, err = decodeText([]byte("!!"), "base64")
	assert.Error(t, err)

	assert.Equal(t, []byte("dead\n"), encodeText([]byte{0xde, 0xad}, "hex"))
	assert.Equal(t, []byte("aGk=\n"), encodeText([]byte("hi"), "base64"))
	assert.Equal(t, []byte("hi"), encodeText([]byte("hi"), "raw"))

	file := filepath.Join(t.TempDir(), "in")
	require.NoError(t, os.WriteFile(file, []byte("from file"), 0o600))
	got, err := readLimited(file, strings.NewReader("ignored"))
	require.NoError(t, err)
	assert.Equal(t, "from file", string(got))
	got, err = readLimited("-", strings.NewReader("from stdin"))
	require.NoError(t, err)
	assert.Equal(t, "from stdin", string(got))
	_, err = readLimited(filepath.Join(t.TempDir(), "absent"), nil)
	assert.Error(t, err)
	_, err = readLimited("-", bytes.NewReader(make([]byte, keyops.MaxInput+1)))
	assert.ErrorContains(t, err, "larger than")
	got, err = readLimited("-", bytes.NewReader(make([]byte, keyops.MaxInput)))
	require.NoError(t, err)
	assert.Len(t, got, keyops.MaxInput)
}

func mustDecode(t *testing.T, b []byte, enc string) []byte {
	t.Helper()
	out, err := decodeText(b, enc)
	require.NoError(t, err)
	return out
}

func TestReportWritesTheDaemonReplyAndPicksTheExitCode(t *testing.T) {
	var out, errOut bytes.Buffer
	streams := IO{Out: &out, ErrOut: &errOut}
	assert.Equal(t, 0, report(Response{OK: true, Stdout: []byte("o"), Stderr: []byte("e")}, streams))
	assert.Equal(t, "o", out.String())
	assert.Equal(t, "e", errOut.String())

	errOut.Reset()
	assert.Equal(t, exitcode.PolicyDeny, report(Response{Error: "denied", ExitCode: exitcode.PolicyDeny}, streams))
	assert.Equal(t, "keylatch: denied\n", errOut.String())
	assert.Equal(t, exitcode.OperationFailed, report(Response{}, streams), "a failed reply never exits 0")
}

func TestCallerProxyPrefersHTTPSOverTheGenericProxy(t *testing.T) {
	assert.Equal(t, "http://a", callerProxy(lookupOf(map[string]string{"HTTPS_PROXY": "http://a", "ALL_PROXY": "http://z"})))
	assert.Equal(t, "http://b", callerProxy(lookupOf(map[string]string{"https_proxy": "http://b", "all_proxy": "http://z"})))
	assert.Equal(t, "http://z", callerProxy(lookupOf(map[string]string{"all_proxy": "http://z"})))
	assert.Empty(t, callerProxy(lookupOf(nil)))
}

func TestShellQuoteSurvivesAQuoteInThePath(t *testing.T) {
	assert.Equal(t, `'/bin/keylatch'`, shellQuote("/bin/keylatch"))
	assert.Equal(t, `'/it'\''s/keylatch'`, shellQuote("/it's/keylatch"))
	assert.NotEmpty(t, self())
}

func TestRunArgsRefuseWhatTheDaemonPathCannotHonour(t *testing.T) {
	ra, err := parseRunArgs([]string{"--tier=d4", "--repo", "o/r", "--permission", "contents=read", "--extra", "A, B,", "--clean-env", "--no-daemon-start", "stripe", "--", "make", "test"})
	require.NoError(t, err)
	assert.Equal(t, TierAdapter, ra.tier)
	assert.Equal(t, "o/r", ra.repository)
	assert.Equal(t, []string{"contents=read"}, ra.perms)
	assert.Equal(t, []string{"A", "B"}, ra.extra)
	assert.True(t, ra.clean)
	assert.Equal(t, []string{"make", "test"}, ra.command)

	for name, args := range map[string][]string{
		"forwarding Keylatch settings": {"--extra", "KEYLATCH_SOCKET", "stripe", "--", "x"},
		"unsupported flag":             {"--verbose", "stripe", "--", "x"},
		"flag without value":           {"--runtime"},
		"second connection":            {"a", "b", "--", "x"},
		"no command":                   {"a", "--"},
		"no separator":                 {"a"},
	} {
		_, err := parseRunArgs(args)
		assert.Error(t, err, name)
	}
}

func TestGitCredentialHelperStaysSilentWithoutASessionOrDaemon(t *testing.T) {
	request := "protocol=https\nhost=github.com\n\nignored=after-blank\n"
	for name, tc := range map[string]struct {
		args   []string
		lookup map[string]string
	}{
		"store is not served":    {[]string{"store"}, nil},
		"no argument":            {nil, nil},
		"no session":             {[]string{"get"}, nil},
		"session without daemon": {[]string{"get"}, map[string]string{runner.ProxySessionVar: "sess", "KEYLATCH_SOCKET": filepath.Join(t.TempDir(), "none.sock")}},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := runGitCredential(lookupOf(tc.lookup), tc.args, IO{In: strings.NewReader(request), Out: &out, ErrOut: &errOut})
			assert.Zero(t, code, "git falls through to its next helper")
			assert.Empty(t, out.String())
		})
	}

	var out bytes.Buffer
	code := runGitCredential(lookupOf(map[string]string{runner.ProxySessionVar: "sess"}), []string{"get"}, IO{In: strings.NewReader("protocol=https\n\n"), Out: &out})
	assert.Zero(t, code)
	assert.Empty(t, out.String(), "a request without a host gets nothing")
}

func TestDockerCredentialHelperAnswersNothingItCannotBackUp(t *testing.T) {
	run := func(lookup map[string]string, args []string, in string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := RunDockerCredential(lookupOf(lookup), args, IO{In: strings.NewReader(in), Out: &out, ErrOut: &errOut})
		return code, out.String(), errOut.String()
	}
	code, _, errOut := run(nil, nil, "")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "usage")

	code, _, errOut = run(nil, []string{"bogus"}, "")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "unknown command")

	code, out, _ := run(nil, []string{"list"}, "")
	assert.Zero(t, code)
	assert.Equal(t, "{}\n", out)

	code, out, _ = run(nil, []string{"store"}, `{"ServerURL":"ghcr.io","Secret":"x"}`)
	assert.Zero(t, code)
	assert.Empty(t, out, "nothing is stored: Keylatch is the only place credentials live")

	for name, lookup := range map[string]map[string]string{
		"no session":             nil,
		"session without daemon": {runner.ProxySessionVar: "sess", "KEYLATCH_SOCKET": filepath.Join(t.TempDir(), "none.sock")},
	} {
		code, out, _ = run(lookup, []string{"get"}, "ghcr.io\n")
		assert.Equal(t, 1, code, name)
		assert.Equal(t, notFound+"\n", out, name)
	}
}

func TestTemporaryFilesFailCleanlyWhenTheTempDirectoryIsGone(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))

	_, _, cleanup, err := prepareDockerConfig("/bin/keylatch")
	assert.ErrorContains(t, err, "docker config")
	assert.Nil(t, cleanup)

	session := &runner.SessionEnv{Set: []runner.EnvAssign{{Name: "DOCKER_CONFIG", Value: runner.DockerConfigPlaceholder}}}
	_, _, err = withDockerConfig(session, "/bin/keylatch")
	assert.Error(t, err)
	assert.Equal(t, runner.DockerConfigPlaceholder, session.Set[0].Value, "a failed setup leaves the placeholder alone")

	_, _, _, err = writeCABundle(lookupOf(nil), "pem")
	assert.ErrorContains(t, err, "CA bundle directory")
}

func TestWireFramesRefuseWhatTheyCannotCarry(t *testing.T) {
	var buf bytes.Buffer
	assert.Error(t, writeFrame(&buf, make(chan int)))
	assert.Empty(t, buf.String())

	require.NoError(t, writeFrame(&buf, Response{Code: "x"}))
	var resp Response
	require.NoError(t, readFrame(bufio.NewReader(&buf), &resp, maxFrame))
	assert.Equal(t, "x", resp.Code)

	big, err := json.Marshal(Response{Error: strings.Repeat("a", 5000)})
	require.NoError(t, err)
	assert.ErrorIs(t, readFrame(bufio.NewReaderSize(bytes.NewReader(append(big, '\n')), 16), &resp, 1024), errFrameTooLarge)
	assert.ErrorContains(t, readFrame(bufio.NewReader(strings.NewReader("not json\n")), &resp, maxFrame), "malformed frame")
}
