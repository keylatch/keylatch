// generate.go — Keylatch release manifest generator.
//
// Assembles the release manifest JSON from platform artifact paths and
// checksums, optionally signs the manifest with cosign, and writes it
// to stdout or a file.
//
// Usage:
//
//	go run ./packaging/release-manifest/ \
//	  --version 1.2.3 \
//	  --channel stable \
//	  --notes-file RELEASE_NOTES.md \
//	  --artifact darwin-arm64:Keylatch.dmg:$(sha256sum Keylatch.dmg | awk '{print $1}') \
//	  --artifact linux-amd64:keylatch-app.AppImage:$(sha256sum ... | awk '{print $1}') \
//	  [--output manifest.json] \
//	  [--sign] [--key cosign.key]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Manifest is the release manifest structure (spec §3.5).
type Manifest struct {
	Version      string              `json:"version"`
	Channel      string              `json:"channel"`
	PublishedAt  string              `json:"published_at"`
	Notes        string              `json:"notes"`
	Artifacts    map[string]Artifact `json:"artifacts"`
	SignatureURL string              `json:"signature_url"`
	ManifestURL  string              `json:"manifest_url"`
}

// Artifact describes a single platform artifact.
type Artifact struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
}

// artifactFlag is a repeatable --artifact flag.
type artifactFlag []string

func (a *artifactFlag) String() string { return strings.Join(*a, ", ") }
func (a *artifactFlag) Set(v string) error {
	*a = append(*a, v)
	return nil
}

func main() {
	var (
		version     = flag.String("version", "", "Release version (required)")
		channel     = flag.String("channel", "stable", "Release channel (stable|beta|nightly)")
		notesFile   = flag.String("notes-file", "", "Path to Markdown release notes file")
		outputFile  = flag.String("output", "", "Output file (default: stdout)")
		sign        = flag.Bool("sign", false, "Sign manifest with cosign")
		cosignKey   = flag.String("key", "", "cosign private key path (for local signing; omit for OIDC keyless)")
		manifestURL = flag.String("manifest-url", "", "Canonical URL of the manifest (self-referential)")
		sigURL      = flag.String("sig-url", "", "URL where the cosign signature will be published")
		baseURL     = flag.String("base-url", "https://releases.keylatch.app", "Base URL for artifact download links")
	)
	var artifacts artifactFlag
	flag.Var(&artifacts, "artifact", "platform-arch:path:sha256 (repeatable)")
	flag.Parse()

	if *version == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --version is required")
		os.Exit(1)
	}

	// Read release notes.
	var notes string
	if *notesFile != "" {
		data, err := os.ReadFile(*notesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: reading --notes-file: %v\n", err)
			os.Exit(1)
		}
		notes = string(data)
	}

	// Parse artifact specs.
	parsedArtifacts := make(map[string]Artifact, len(artifacts))
	for _, spec := range artifacts {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) != 3 {
			fmt.Fprintf(os.Stderr, "ERROR: artifact %q must be platform-arch:path:sha256\n", spec)
			os.Exit(1)
		}
		key, path, sha := parts[0], parts[1], parts[2]

		// Verify SHA256 matches actual file.
		computed, err := hashFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: hashing %s: %v\n", path, err)
			os.Exit(1)
		}
		if !strings.EqualFold(computed, sha) {
			fmt.Fprintf(os.Stderr, "ERROR: SHA256 mismatch for %s: got %s, expected %s\n", path, computed, sha)
			os.Exit(1)
		}

		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: stat %s: %v\n", path, err)
			os.Exit(1)
		}

		platformArch := strings.SplitN(key, "-", 2)
		platform, arch := "", ""
		if len(platformArch) == 2 {
			platform, arch = platformArch[0], platformArch[1]
		}

		parsedArtifacts[key] = Artifact{
			URL:      fmt.Sprintf("%s/artifacts/%s/%s/%s", *baseURL, *version, key, info.Name()),
			SHA256:   strings.ToLower(sha),
			Size:     info.Size(),
			Platform: platform,
			Arch:     arch,
		}
	}

	manifest := Manifest{
		Version:     *version,
		Channel:     *channel,
		PublishedAt: time.Now().UTC().Format(time.RFC3339),
		Notes:       notes,
		Artifacts:   parsedArtifacts,
		SignatureURL: func() string {
			if *sigURL != "" {
				return *sigURL
			}
			return fmt.Sprintf("%s/manifest/%s.json.sig", *baseURL, *version)
		}(),
		ManifestURL: func() string {
			if *manifestURL != "" {
				return *manifestURL
			}
			return fmt.Sprintf("%s/manifest/%s.json", *baseURL, *version)
		}(),
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: marshalling manifest: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	// Write output.
	var out io.Writer = os.Stdout
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close() //nolint:errcheck // defer close of output file; write error already caught above
		out = f
	}
	if _, err := out.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: writing manifest: %v\n", err)
		os.Exit(1)
	}

	// Sign with cosign if requested.
	if *sign && *outputFile != "" {
		args := []string{"sign-blob", "--output-signature=" + *outputFile + ".sig"}
		if *cosignKey != "" {
			args = append(args, "--key="+*cosignKey)
		} else {
			// Keyless OIDC signing (for CI).
			args = append(args, "--oidc-issuer=https://token.actions.githubusercontent.com")
		}
		args = append(args, *outputFile)
		cmd := exec.Command("cosign", args...) //nolint:gosec // G204: "cosign" is the sigstore signing binary; fixed string
		cmd.Stdout = os.Stderr                 // cosign writes info to stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: cosign sign-blob failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Signed manifest: %s.sig\n", *outputFile)
	}
}

// hashFile computes the SHA-256 hex digest of the file at path.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // defer close in read-only hash path
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
