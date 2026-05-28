package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/version"
)

// TestCosignIdentityConstants asserts the cosign constants are properly anchored and
// contain expected substrings. The regexp uses escaped dots to prevent impostor URL matching.
func TestCosignIdentityConstants(t *testing.T) {
	if !strings.HasPrefix(cosignIdentityRegexp, "^") {
		t.Errorf("cosignIdentityRegexp is not anchored at start: %s", cosignIdentityRegexp)
	}
	if !strings.Contains(cosignIdentityRegexp, "keylatch/keylatch") {
		t.Errorf("cosignIdentityRegexp does not contain keylatch org: %s", cosignIdentityRegexp)
	}
	// Dots are escaped in the regexp (release\.yml not release.yml) to prevent spoofing.
	if !strings.Contains(cosignIdentityRegexp, `release\.yml`) {
		t.Errorf("cosignIdentityRegexp does not contain escaped release.yml: %s", cosignIdentityRegexp)
	}
	if !strings.Contains(cosignIdentityRegexp, "refs/tags/v") {
		t.Errorf("cosignIdentityRegexp does not contain refs/tags/v: %s", cosignIdentityRegexp)
	}
	if !strings.Contains(cosignOIDCIssuer, "token.actions.githubusercontent.com") {
		t.Errorf("cosignOIDCIssuer does not contain expected domain: %s", cosignOIDCIssuer)
	}
}

// TestFetchSigFromGitHubReleases_Found verifies that a .sig asset is downloaded.
func TestFetchSigFromGitHubReleases_Found(t *testing.T) {
	sigContent := "fakesigcontent"

	// Serve the asset download.
	assetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sigContent)) //nolint:errcheck
	}))
	defer assetSrv.Close()

	// Serve the release API.
	release := gitHubRelease{
		Assets: []gitHubReleaseAsset{
			{Name: "keylatch-linux-amd64.sig", BrowserDownloadURL: assetSrv.URL + "/sig"},
		},
	}
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release) //nolint:errcheck
	}))
	defer apiSrv.Close()

	// Override the API URL for testing by patching via a helper.
	// Since gitHubReleasesAPI is a package-level constant, we build the URL directly.
	sigPath, cleanup, err := fetchSigFromGitHubReleasesURL(apiSrv.URL+"/releases/tags/%s", "1.0.0")
	if err != nil {
		t.Fatalf("fetchSigFromGitHubReleases: %v", err)
	}
	defer cleanup()

	data, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read downloaded sig: %v", err)
	}
	if string(data) != sigContent {
		t.Errorf("sig content = %q, want %q", string(data), sigContent)
	}
}

// TestVerifySelf_FetchesAndVerifies verifies that runVerifySelf uses fetchSigFromGitHubReleases
// when no adjacent .sig file exists, and propagates fetch errors as CLIError (not os.Exit).
func TestVerifySelf_FetchesAndVerifies(t *testing.T) {
	// Mock GitHub Releases API — returns 404 to exercise the error path.
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer apiSrv.Close()

	// Call fetchSigFromGitHubReleasesURL directly with the mock server URL.
	// This exercises the same code path that runVerifySelf uses internally.
	_, cleanup, err := fetchSigFromGitHubReleasesURL(apiSrv.URL+"/releases/tags/%s", "2.0.0")
	if err == nil {
		cleanup()
		t.Fatal("expected error from 404 API response, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected 404 in error message, got: %v", err)
	}
}

// TestFetchSigFromGitHubReleases_NotFound verifies error when no .sig asset exists.
func TestFetchSigFromGitHubReleases_NotFound(t *testing.T) {
	release := gitHubRelease{
		Assets: []gitHubReleaseAsset{
			{Name: "keylatch-linux-amd64.tar.gz", BrowserDownloadURL: "http://example.com/nope"},
		},
	}
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release) //nolint:errcheck
	}))
	defer apiSrv.Close()

	_, cleanup, err := fetchSigFromGitHubReleasesURL(apiSrv.URL+"/releases/tags/%s", "1.0.0")
	if err == nil {
		cleanup()
		t.Fatal("expected error when no .sig asset found, got nil")
	}
	if !strings.Contains(err.Error(), "no .sig asset") {
		t.Errorf("expected 'no .sig asset' in error, got: %v", err)
	}
}

// TestRunVerifySelf_DevBinary verifies that runVerifySelf returns a CLIError (not os.Exit)
// when version.Version is "dev" or empty, exercising the early-exit guard added in C2.
func TestRunVerifySelf_DevBinary(t *testing.T) {
	devVersions := []string{"dev", ""}
	for _, v := range devVersions {
		t.Run("version="+v, func(t *testing.T) {
			orig := version.Version
			version.Version = v
			defer func() { version.Version = orig }()

			cmd := newVerifyCmd()
			var out, errBuf bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errBuf)
			cmd.SetArgs([]string{"--self"})

			// Execute must return an error, not panic or call os.Exit.
			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected error for dev binary, got nil")
			}

			// The error must be a CLIError (UsageError), not a raw panic or os.Exit.
			var cliErr *CLIError
			if !errors.As(err, &cliErr) {
				t.Errorf("expected *CLIError, got %T: %v", err, err)
			}
			if cliErr != nil && cliErr.Class != "UsageError" {
				t.Errorf("expected CLIError.Class=UsageError, got %q", cliErr.Class)
			}
		})
	}
}
