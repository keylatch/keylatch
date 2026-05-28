package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/version"
	"github.com/spf13/cobra"
)

// cosignIdentityRegexp matches the OIDC identity used by the keylatch release workflow.
// The pattern is fully anchored and dots are escaped to prevent URL prefix/suffix spoofing.
// Update this regexp when the release workflow path or tag prefix changes.
const cosignIdentityRegexp = `^https://github\.com/keylatch/keylatch/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]`

// cosignOIDCIssuer is the OIDC issuer for GitHub Actions.
const cosignOIDCIssuer = "https://token.actions.githubusercontent.com"

// gitHubReleasesAPI is the GitHub Releases API endpoint template.
const gitHubReleasesAPI = "https://api.github.com/repos/keylatch/keylatch/releases/tags/%s"

// newVerifyCmd returns the `keylatch verify` subcommand.
func newVerifyCmd() *cobra.Command {
	var self bool
	cmd := &cobra.Command{
		Use:   "verify [binary]",
		Short: "Verify the keylatch binary using cosign",
		Long: `Verify the keylatch binary's Sigstore/cosign signature.

With --self, verifies the currently running binary automatically.
The signature is fetched from the adjacent .sig file or, if absent,
downloaded from GitHub Releases.`,
		RunE: func(c *cobra.Command, args []string) error {
			if self {
				return runVerifySelf(c)
			}
			if len(args) == 0 {
				return fmt.Errorf("specify a binary path or use --self")
			}
			return runVerify(c, args[0], "")
		},
	}
	cmd.Flags().BoolVar(&self, "self", false, "verify the currently running keylatch binary")
	return cmd
}

// runVerifySelf verifies the currently installed keylatch binary.
func runVerifySelf(c *cobra.Command) error {
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		return fmt.Errorf("could not resolve symlink: %w", err)
	}

	// Reject dev builds early — cosign verification is only meaningful for release tags.
	ver := version.Version
	if ver == "" || ver == "dev" {
		return NewUsageError(
			"this binary was not built from a release tag; cosign verification is only available for released versions",
		)
	}

	// Check for adjacent .sig file.
	sigPath := binPath + ".sig"
	if _, err := os.Stat(sigPath); os.IsNotExist(err) {
		// Fetch from GitHub Releases.
		fetched, cleanup, fetchErr := fetchSigFromGitHubReleases(ver)
		if fetchErr != nil {
			return NewRuntimeNotAvailable(
				"could not fetch signature for v%s from GitHub Releases (%v). "+
					"Verify manually: cosign verify-blob --certificate-identity-regexp %q --certificate-oidc-issuer %q --signature <sig-file> %s",
				ver, fetchErr, cosignIdentityRegexp, cosignOIDCIssuer, binPath,
			)
		}
		defer cleanup()
		sigPath = fetched
	}

	return runVerify(c, binPath, sigPath)
}

// runVerify runs cosign verify-blob for binPath using sigPath.
func runVerify(c *cobra.Command, binPath, sigPath string) error {
	args := []string{
		"verify-blob",
		"--certificate-identity-regexp", cosignIdentityRegexp,
		"--certificate-oidc-issuer", cosignOIDCIssuer,
	}
	if sigPath != "" {
		args = append(args, "--signature", sigPath)
	}
	args = append(args, binPath)

	//nolint:gosec // G204: cosign args are constructed from constants, not user input
	cmd := exec.Command("cosign", args...)
	cmd.Stdout = c.OutOrStdout()
	cmd.Stderr = c.ErrOrStderr()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign verify-blob failed: %w", err)
	}
	fmt.Fprintln(c.OutOrStdout(), "Verification OK")
	return nil
}

// gitHubReleaseAsset describes a single GitHub Release asset.
type gitHubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// gitHubRelease describes a GitHub Release JSON response.
type gitHubRelease struct {
	Assets []gitHubReleaseAsset `json:"assets"`
}

// fetchSigFromGitHubReleases downloads the .sig asset for version from the
// GitHub Releases API. Returns the path to a temp file and a cleanup func.
// The caller must call cleanup() when done with the file.
func fetchSigFromGitHubReleases(ver string) (sigPath string, cleanup func(), err error) {
	return fetchSigFromGitHubReleasesURL(gitHubReleasesAPI, ver)
}

// fetchSigFromGitHubReleasesURL is the injectable version of fetchSigFromGitHubReleases
// for testing — it accepts an overridable API URL template.
func fetchSigFromGitHubReleasesURL(apiURLTemplate, ver string) (sigPath string, cleanup func(), err error) {
	// Ensure version starts with "v".
	tag := ver
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}

	url := fmt.Sprintf(apiURLTemplate, tag)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url) //nolint:noctx // standalone fetch
	if err != nil {
		return "", nil, fmt.Errorf("fetch release API: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("GitHub Releases API returned %d for tag %s", resp.StatusCode, tag)
	}

	var release gitHubRelease
	if decErr := json.NewDecoder(resp.Body).Decode(&release); decErr != nil {
		return "", nil, fmt.Errorf("parse release API response: %w", decErr)
	}

	// Find the .sig asset.
	var sigURL string
	for _, asset := range release.Assets {
		if strings.HasSuffix(asset.Name, ".sig") {
			sigURL = asset.BrowserDownloadURL
			break
		}
	}
	if sigURL == "" {
		return "", nil, fmt.Errorf("no .sig asset found in release %s", tag)
	}

	// Download to temp file.
	tmp, err := os.CreateTemp("", "keylatch-*.sig")
	if err != nil {
		return "", nil, fmt.Errorf("create temp sig file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanupFn := func() { os.Remove(tmpPath) } //nolint:errcheck

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", nil, fmt.Errorf("secure temp file: %w", err)
	}

	sigResp, err := client.Get(sigURL) //nolint:noctx
	if err != nil {
		_ = tmp.Close()
		cleanupFn()
		return "", nil, fmt.Errorf("download sig: %w", err)
	}
	defer sigResp.Body.Close() //nolint:errcheck

	if _, err := io.Copy(tmp, sigResp.Body); err != nil {
		_ = tmp.Close()
		cleanupFn()
		return "", nil, fmt.Errorf("write sig: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanupFn()
		return "", nil, fmt.Errorf("close temp sig: %w", err)
	}

	return tmpPath, cleanupFn, nil
}
