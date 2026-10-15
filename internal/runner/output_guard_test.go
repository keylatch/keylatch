package runner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/redactor"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const guardToken = "tok-Zq8x+Yw3Rt5Uv7Bn9Cm1Dk2Fh4Gj6Lp0"

func runGuarded(t *testing.T, script, dir string, scan redactor.ScanPolicy) (string, string, runner.RuntimeReceipt) {
	t.Helper()
	vault := newClassicMockBackend()
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte("root"), backend.Meta{Path: path, Backend: "stub", Version: 1}))
	b := &stubBroker{result: broker.NewExchangeResult("myapi", "inject", 3600*1e9, broker.FreshExchange, []byte(guardToken))}

	var out, errOut strings.Builder
	receipt, err := runner.NewBrokeredDriver(vault, b, nil).Run(context.Background(), runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", script},
		WorkingDir:     dir,
		FileScan:       scan,
		Stdout:         &out,
		Stderr:         &errOut,
	}, brokeredTmpl("myapi"))
	require.NoError(t, err)
	return out.String(), errOut.String(), receipt
}

func TestOutputGuardCatchesEncodedLeaks(t *testing.T) {
	scripts := map[string]string{
		"raw":         `printf '%s\n' "$TEST_API_KEY"`,
		"base64":      `printf '%s' "$TEST_API_KEY" | base64`,
		"base64-pad":  `printf 'user:%s!' "$TEST_API_KEY" | base64`,
		"hex":         `printf '%s' "$TEST_API_KEY" | od -An -v -tx1 | tr -d ' \n'`,
		"hex-upper":   `printf '%s' "$TEST_API_KEY" | od -An -v -tx1 | tr -d ' \n' | tr a-f A-F`,
		"url":         `printf '%s' "$TEST_API_KEY" | od -An -v -tx1 | tr -d '\n' | sed 's/ /%/g'`,
		"stderr":      `printf '%s' "$TEST_API_KEY" >&2`,
		"split-write": `printf '%s' "${TEST_API_KEY%"${TEST_API_KEY#??????}"}"; sleep 0.05; printf '%s' "${TEST_API_KEY#??????}"`,
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			out, errOut, _ := runGuarded(t, script, t.TempDir(), redactor.ScanReport)
			assert.Contains(t, out+errOut, redactor.Marker)
			for _, v := range []string{guardToken, "Zq8x", "Zq8x+Yw3"} {
				assert.NotContains(t, out+errOut, v)
			}
		})
	}
}

func TestOutputGuardLeavesOrdinaryOutput(t *testing.T) {
	out, _, receipt := runGuarded(t, `echo hello world`, t.TempDir(), redactor.ScanReport)
	assert.Equal(t, "hello world\n", out)
	assert.Zero(t, receipt.LeakedFiles)
}

func TestOutputGuardReportsFilesWrittenByChild(t *testing.T) {
	dir := t.TempDir()
	_, errOut, receipt := runGuarded(t, `printf '%s' "$TEST_API_KEY" | base64 > leak.b64; echo fine > ok.txt`, dir, redactor.ScanReport)
	assert.Equal(t, 1, receipt.LeakedFiles)
	assert.Contains(t, errOut, "leak.b64")
	assert.NotContains(t, errOut, guardToken)
	b, err := os.ReadFile(filepath.Join(dir, "ok.txt"))
	require.NoError(t, err)
	assert.Equal(t, "fine\n", string(b))
}

func TestOutputGuardRedactsFilesWhenAsked(t *testing.T) {
	dir := t.TempDir()
	_, _, receipt := runGuarded(t, `printf 'key=%s\n' "$TEST_API_KEY" > .env.leak`, dir, redactor.ScanRedact)
	assert.Equal(t, 1, receipt.LeakedFiles)
	b, err := os.ReadFile(filepath.Join(dir, ".env.leak"))
	require.NoError(t, err)
	assert.Equal(t, "key="+redactor.Marker+"\n", string(b))
}
