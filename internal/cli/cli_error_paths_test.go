package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type caFailingWriter struct{}

func (caFailingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

type caFailingReader struct{}

func (caFailingReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestReadFieldFromStdin(t *testing.T) {
	_, err := readFieldFromStdin(caFailingReader{})
	assert.ErrorContains(t, err, "reading stdin: broken pipe")
}

func TestStdinIsTTYFalseForFile(t *testing.T) {
	caSwapStdin(t, "x")
	assert.False(t, stdinIsTTY())
}

func TestNewInsecureArgv(t *testing.T) {
	e := NewInsecureArgv("value for %s passed on argv", "api_key")
	assert.Equal(t, "InsecureArgv", e.Class)
	assert.Equal(t, exitcode.InsecureArgv, e.Code)
	assert.Equal(t, "value for api_key passed on argv", e.Message)
}

func TestCheckExpiryJSONWriteFailure(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	f.rotate(t, caPath, []byte(caSecret("x")))
	root := NewRootCommand()
	root.SetOut(caFailingWriter{})
	root.SetErr(caFailingWriter{})
	root.SetArgs([]string{"check-expiry", "--json"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
	var stderr bytes.Buffer
	assert.Equal(t, exitcode.OperationFailed, ReportError(root, []string{"check-expiry", "--json"}, err, &stderr))
}

func TestFetchSigFromReleasesNetworkFailures(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	_, _, err := fetchSigFromGitHubReleasesURL(closedURL+"/%s", "1.0.0")
	assert.ErrorContains(t, err, "fetch release API")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1.0.0", r.URL.Path)
		_ = json.NewEncoder(w).Encode(gitHubRelease{Assets: []gitHubReleaseAsset{
			{Name: "keylatch.tar.gz", BrowserDownloadURL: closedURL + "/archive"},
			{Name: "keylatch.sig", BrowserDownloadURL: closedURL + "/sig"},
		}})
	}))
	defer api.Close()
	path, cleanup, err := fetchSigFromGitHubReleasesURL(api.URL+"/%s", "1.0.0")
	assert.ErrorContains(t, err, "download sig")
	assert.Empty(t, path)
	assert.Nil(t, cleanup)
}

func TestGuardLLMSessionReportsUnknownCommandWithoutArgs(t *testing.T) {
	orig := SecurityBlockHook
	t.Cleanup(func() { SecurityBlockHook = orig })
	var got []SecurityBlockEvent
	SecurityBlockHook = func(_ context.Context, e SecurityBlockEvent) { got = append(got, e) }

	innerCalled := false
	h := GuardLLMSession(func(context.Context, HandlerArgs) (Result, error) {
		innerCalled = true
		return Result{}, nil
	})
	var stdout, stderr bytes.Buffer
	lookup := func(k string) string {
		if k == "CLAUDECODE" {
			return "1"
		}
		return ""
	}
	res, err := h(context.Background(), HandlerArgs{Env: lookup, Stdout: &stdout, Stderr: &stderr})
	require.NoError(t, err)
	assert.Equal(t, exitcode.SecurityBlock, res.ExitCode)
	assert.False(t, innerCalled)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "Detected via: CLAUDECODE")
	require.Len(t, got, 1)
	assert.Equal(t, "unknown", got[0].Command)
}

func TestFetchSigFromReleasesTruncatedDownload(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sig" {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("short"))
			return
		}
		_ = json.NewEncoder(w).Encode(gitHubRelease{Assets: []gitHubReleaseAsset{
			{Name: "keylatch.sig", BrowserDownloadURL: srv.URL + "/sig"},
		}})
	}))
	defer srv.Close()
	path, _, err := fetchSigFromGitHubReleasesURL(srv.URL+"/%s", "v2.0.0")
	assert.ErrorContains(t, err, "write sig")
	assert.Empty(t, path)
}

func TestCryptoCalibratePrintsParameters(t *testing.T) {
	if testing.Short() {
		t.Skip("calibration targets two seconds of hashing")
	}
	caNewEnv(t)
	out, _, err := caRun(t, nil, "crypto", "calibrate")
	require.NoError(t, err)
	var p map[string]float64
	require.NoError(t, json.Unmarshal([]byte(out), &p))
	for _, k := range []string{"time", "memory", "threads", "salt_len", "key_len"} {
		assert.Positive(t, p[k], k)
	}
}
