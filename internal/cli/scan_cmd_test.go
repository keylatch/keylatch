package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/exitcode"
)

const (
	// Split so push-time secret scanners do not mistake the fixture for a key.
	scanKey    = "sk_" + "live_" + "0123456789abcdefghijklmnop"
	scanCanary = "klc-canary-stripe-0123456789abcdef"
)

func runScan(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newScanCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestScanFlagsCredentialsAndCanariesWithoutPrintingThem(t *testing.T) {
	text := "hello\nAuthorization: Bearer " + scanKey + "\nnote " + scanCanary + "\nfine\n"
	_, stderr, err := runScan(t, text)
	require.Error(t, err)
	var cliErr *CLIError
	require.ErrorAs(t, err, &cliErr)
	assert.Equal(t, exitcode.SecurityBlock, cliErr.Code)
	assert.Contains(t, stderr, "<stdin>:2: credential")
	assert.Contains(t, stderr, "<stdin>:3: canary")
	assert.NotContains(t, stderr+cliErr.Message, scanKey)
	assert.NotContains(t, stderr+cliErr.Message, scanCanary)
}

func TestScanPassesCleanTextAndFiles(t *testing.T) {
	_, stderr, err := runScan(t, "nothing to see\n")
	assert.NoError(t, err)
	assert.Empty(t, stderr)

	dir := t.TempDir()
	clean, dirty := filepath.Join(dir, "clean.txt"), filepath.Join(dir, "dirty.txt")
	require.NoError(t, os.WriteFile(clean, []byte("ok\n"), 0o600))
	require.NoError(t, os.WriteFile(dirty, []byte("x\nBearer "+scanKey+"\n"), 0o600))
	_, _, err = runScan(t, "", clean)
	assert.NoError(t, err)
	_, stderr, err = runScan(t, "", clean, dirty)
	assert.Error(t, err)
	assert.Contains(t, stderr, dirty+":2: credential")
	_, _, err = runScan(t, "", filepath.Join(dir, "missing"))
	assert.Error(t, err)
}

func TestScanRedactWritesTheFilteredTextAndSucceeds(t *testing.T) {
	stdout, stderr, err := runScan(t, "a\nBearer "+scanKey+"\nb "+scanCanary+"\n", "--redact")
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.NotContains(t, stdout, scanKey)
	assert.NotContains(t, stdout, scanCanary)
	assert.Contains(t, stdout, "a\n")
	assert.Contains(t, stdout, "[REDACTED]")
}

func TestScanLinesReportsReadErrors(t *testing.T) {
	_, _, err := scanLines("x", errReader{})
	assert.Error(t, err)
	_, _, err = runScanWith(errReader{})
	assert.Error(t, err)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, os.ErrClosed }

func runScanWith(r errReader) (string, string, error) {
	cmd := newScanCmd()
	cmd.SetIn(r)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	return "", "", cmd.Execute()
}
