// Package docker generates Docker Compose configurations for the keylatch gateway.
//
// S9-10: rootless, localhost bind, no --network host, env-var paths.
// Uses ${HOME}/.keylatch references, never absolute user-specific paths.
package docker

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

// ComposeOptions configures the Docker Compose output.
type ComposeOptions struct {
	Port        int    // default 7878
	KeylatchDir string // "~/.keylatch" (env-var referenced, not expanded)
	Version     string // binary version label
}

// composeTemplate is the Docker Compose YAML template.
// S9-10: rootless, localhost bind, no --network host, env-var paths.
const composeTemplate = `version: "3.9"
services:
  keylatch-gateway:
    image: ghcr.io/keylatch/keylatch:{{.Version}}
    command: ["gateway", "up", "--port", "{{.Port}}"]
    ports:
      - "127.0.0.1:{{.Port}}:{{.Port}}"
    volumes:
      - "${HOME}/.keylatch:/root/.keylatch:ro"
    user: "nonroot:nonroot"
    read_only: true
    security_opt:
      - "no-new-privileges:true"
    restart: unless-stopped
`

// GenerateCompose returns a Docker Compose YAML for the gateway.
// S9-10: rootless, localhost bind, no --network host, env-var paths.
// Uses ${HOME}/.keylatch references, never absolute user-specific paths.
func GenerateCompose(opts ComposeOptions) ([]byte, error) {
	if opts.Port == 0 {
		opts.Port = 7878
	}
	if opts.Version == "" {
		opts.Version = "latest"
	}

	tmpl, err := template.New("compose").Parse(composeTemplate)
	if err != nil {
		return nil, fmt.Errorf("docker: parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, opts); err != nil {
		return nil, fmt.Errorf("docker: execute template: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteAt writes the compose file to path with mode 0o600.
func WriteAt(path string, opts ComposeOptions) error {
	data, err := GenerateCompose(opts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("docker: mkdir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("docker: write %q: %w", path, err)
	}
	_ = os.Chmod(path, 0o600)
	return nil
}
