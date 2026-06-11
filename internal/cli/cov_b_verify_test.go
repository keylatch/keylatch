package cli

// cov_b_verify_test.go — Agent B coverage for verify_cmd.go.
// Tests for fetchSigFromGitHubReleasesURL and command registration.
// Network calls are intercepted via httptest servers.
// Hermetic: no real GitHub API calls, no OS keychain.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestFetchSigFromGitHubReleasesURL_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	template := srv.URL + "/repos/keylatch/keylatch/releases/tags/%s"
	_, _, err := fetchSigFromGitHubReleasesURL(template, "1.0.0")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected 404 in error, got: %v", err)
	}
}

func TestFetchSigFromGitHubReleasesURL_NoSigAsset(t *testing.T) {
	release := gitHubRelease{
		Assets: []gitHubReleaseAsset{
			{Name: "keylatch_1.0.0_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/bin.tar.gz"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release) //nolint:errcheck
	}))
	defer srv.Close()

	template := srv.URL + "/repos/keylatch/keylatch/releases/tags/%s"
	_, _, err := fetchSigFromGitHubReleasesURL(template, "1.0.0")
	if err == nil {
		t.Fatal("expected error when no .sig asset exists")
	}
	if !strings.Contains(err.Error(), ".sig") {
		t.Errorf("expected '.sig' mention in error, got: %v", err)
	}
}

func TestFetchSigFromGitHubReleasesURL_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{bad json")
	}))
	defer srv.Close()

	template := srv.URL + "/repos/keylatch/keylatch/releases/tags/%s"
	_, _, err := fetchSigFromGitHubReleasesURL(template, "1.0.0")
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
	if !strings.Contains(err.Error(), "parse release API response") {
		t.Errorf("expected 'parse release API response' in error, got: %v", err)
	}
}

func TestFetchSigFromGitHubReleasesURL_VersionPrefixV(t *testing.T) {
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		http.NotFound(w, r)
	}))
	defer srv.Close()

	template := srv.URL + "/%s"
	// Pass version without "v" prefix — should be prepended.
	_, _, err := fetchSigFromGitHubReleasesURL(template, "1.2.3")
	// Error is expected (404); we just want to check the path.
	_ = err
	if !strings.Contains(receivedPath, "v1.2.3") {
		t.Errorf("expected 'v1.2.3' in request path, got: %s", receivedPath)
	}
}

func TestFetchSigFromGitHubReleasesURL_VersionAlreadyHasV(t *testing.T) {
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		http.NotFound(w, r)
	}))
	defer srv.Close()

	template := srv.URL + "/%s"
	// Pass version already with "v" prefix — should not double-prefix.
	_, _, err := fetchSigFromGitHubReleasesURL(template, "v1.2.3")
	_ = err
	if !strings.Contains(receivedPath, "v1.2.3") {
		t.Errorf("expected 'v1.2.3' in request path, got: %s", receivedPath)
	}
	if strings.Contains(receivedPath, "vv1.2.3") {
		t.Errorf("double 'v' prefix in request path: %s", receivedPath)
	}
}

func TestFetchSigFromGitHubReleasesURL_DownloadsSigFile(t *testing.T) {
	sigContent := "SIGNATURE_DATA_HERE"

	// Serve the sig file from a second server.
	sigSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sigContent)
	}))
	defer sigSrv.Close()

	release := gitHubRelease{
		Assets: []gitHubReleaseAsset{
			{Name: "keylatch_1.0.0_checksums.txt.sig", BrowserDownloadURL: sigSrv.URL + "/sig"},
		},
	}

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release) //nolint:errcheck
	}))
	defer apiSrv.Close()

	template := apiSrv.URL + "/%s"
	sigPath, cleanup, err := fetchSigFromGitHubReleasesURL(template, "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	if sigPath == "" {
		t.Fatal("expected non-empty sigPath")
	}

	// Verify temp file contents.
	data, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read sig file: %v", err)
	}
	if string(data) != sigContent {
		t.Errorf("expected sig content %q, got: %q", sigContent, string(data))
	}

	// Verify cleanup removes the file.
	cleanup()
	if _, err := os.Stat(sigPath); !os.IsNotExist(err) {
		t.Error("expected temp sig file to be removed by cleanup")
	}
}

// TestVerifyCmd_Registered checks `verify` is in the command tree and has --self flag.
func TestVerifyCmd_Registered(t *testing.T) {
	root := NewRootCommand()
	verifyCmd, _, err := root.Find([]string{"verify"})
	if err != nil || verifyCmd == nil {
		t.Fatal("expected 'verify' command to be registered in root")
	}
	selfFlag := verifyCmd.Flags().Lookup("self")
	if selfFlag == nil {
		t.Error("expected --self flag on verify command")
	}
}
