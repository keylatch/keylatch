package control

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/contained"
	"github.com/keylatch/keylatch/internal/exitcode"
)

func TestMain(m *testing.M) {
	if contained.MaybeRun() {
		return
	}
	os.Exit(m.Run())
}

// nativeWorld is a containedWorld whose launcher is the real sandbox, so the
// daemon's whole D5 path runs: policy, values, namespaces, relay, redaction
// and the post-run scan. Only the egress socket is replaced, because a forwarder
// in the sandbox needs a Unix socket.
func nativeWorld(t *testing.T) *containedWorld {
	t.Helper()
	probe := contained.Probe()
	if missing := probe.Missing(); len(missing) > 0 {
		t.Skipf("the sandbox is unavailable here: %s", strings.Join(missing, "; "))
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	w := newContainedWorld(t)
	w.srv.cfg.Contained.Launcher = &contained.Native{Binary: exe, Cgroups: true}
	// Each run directory must sit where the unprivileged user namespace can
	// bind it.
	return w
}

func TestNativeContainedRunHidesTheValueFromItsOwnOutput(t *testing.T) {
	w := nativeWorld(t)
	script := `printf 'plain=%s\n' "$STRIPE_SECRET_KEY"
printf 'b64=%s\n' "$(printf %s "$STRIPE_SECRET_KEY" | base64 | tr -d '\n')"
printf 'hex=%s\n' "$(printf %s "$STRIPE_SECRET_KEY" | od -An -tx1 | tr -d ' \n')"
printf 'err=%s\n' "$STRIPE_SECRET_KEY" >&2
test "${#STRIPE_SECRET_KEY}" -gt 20 && echo holds-the-value`
	res := w.runRaw(w.request("sh", "-c", script), nil)
	require.True(t, res.first.OK, res.first.Error)
	assert.Equal(t, 0, res.final.ExitCode, res.stderr)
	assert.Contains(t, res.stdout, "holds-the-value", "the sandbox holds the real value")
	for _, form := range []string{containedSecret, base64.StdEncoding.EncodeToString([]byte(containedSecret)), hex.EncodeToString([]byte(containedSecret)), url.QueryEscape(containedSecret)} {
		assert.NotContains(t, res.stdout, form)
		assert.NotContains(t, res.stderr, form)
	}
	assert.Contains(t, res.stdout, "plain=")
	for _, e := range w.audit.events {
		assert.NotContains(t, fmt.Sprint(e), containedSecret)
	}
}

func TestNativeContainedRunReportsFilesThatHoldTheValue(t *testing.T) {
	w := nativeWorld(t)
	script := `printf %s "$STRIPE_SECRET_KEY" | base64 > dump.b64; echo harmless > clean.txt`
	res := w.runRaw(w.request("sh", "-c", script), nil)
	assert.Equal(t, exitcode.PolicyDeny, res.final.ExitCode)
	assert.Contains(t, res.final.Error, "dump.b64")
	require.Len(t, w.events(audit.ActionContainedLeakSuspected), 1)
	b, err := os.ReadFile(filepath.Join(w.project, "dump.b64"))
	require.NoError(t, err)
	assert.NotEmpty(t, b, "the file is reported, not deleted")
}

func TestNativeContainedRunIsContained(t *testing.T) {
	w := nativeWorld(t)
	state := filepath.Join(filepath.Dir(w.project), "state", "gateway")
	require.NoError(t, os.MkdirAll(state, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(state, "tokens.json"), []byte("secret-token-store"), 0o600))
	script := `cat ` + state + `/tokens.json 2>&1 | head -c 80
echo "net: $(cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' ' | tr '\n' ,)"
echo "home: $HOME"
sleep 600 &
setsid sleep 601 &
echo done`
	res := w.runRaw(w.request("sh", "-c", script), nil)
	require.True(t, res.final.OK, res.final.Error+res.stderr)
	assert.NotContains(t, res.stdout, "secret-token-store")
	assert.Contains(t, res.stdout, "net: lo,")
	assert.Contains(t, res.stdout, "home: "+contained.DefaultHome)
	// The run returned although two sleeping children were left behind: the
	// namespace ended with the command and took them along.
}

func TestNativeContainedRunPassesInputThroughAndSetsTheExitStatus(t *testing.T) {
	w := nativeWorld(t)
	res := w.runRaw(w.request("sh", "-c", `read -r line; echo "got:$line"; exit 6`), func(conn *net.UnixConn, _ Response) {
		require.NoError(t, writeFrame(conn, Chunk{Data: []byte("hello\n")}))
		require.NoError(t, writeFrame(conn, Chunk{EOF: true}))
	})
	assert.Equal(t, 6, res.final.ExitCode)
	assert.Contains(t, res.stdout, "got:hello")
}
