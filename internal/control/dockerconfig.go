//go:build !windows

package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/runner"
)

// dockerHelperName is the program name Docker derives from "credsStore".
const dockerHelperName = "docker-credential-keylatch"

// prepareDockerConfig creates the Docker client configuration a credential
// store session needs: a config directory that names the Keylatch store, and a
// directory holding the helper program Docker will look for on PATH. It
// returns both and a function that removes them.
func prepareDockerConfig(keylatchBin string) (configDir, binDir string, cleanup func(), err error) {
	root, err := os.MkdirTemp("", "keylatch-docker-")
	if err != nil {
		return "", "", nil, fmt.Errorf("docker config: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(root) }
	fail := func(err error) (string, string, func(), error) {
		cleanup()
		return "", "", nil, fmt.Errorf("docker config: %w", err)
	}
	configDir, binDir = filepath.Join(root, "config"), filepath.Join(root, "bin")
	for _, d := range []string{configDir, binDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return fail(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"credsStore":"keylatch"}`+"\n"), 0o600); err != nil {
		return fail(err)
	}
	script := "#!/bin/sh\nexec " + shellQuote(keylatchBin) + " " + dockerCredentialVerb + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(binDir, dockerHelperName), []byte(script), 0o700); err != nil { //nolint:gosec // G306: the helper must be executable
		return fail(err)
	}
	return configDir, binDir, cleanup, nil
}

// withDockerConfig fills the Docker configuration placeholder in the session
// environment. It returns the directory to put first on PATH, or "" when the
// session has no Docker credential store.
func withDockerConfig(session *runner.SessionEnv, keylatchBin string) (binDir string, cleanup func(), err error) {
	idx := -1
	for i := range session.Set {
		if session.Set[i].Value == runner.DockerConfigPlaceholder {
			idx = i
		}
	}
	if idx < 0 {
		return "", func() {}, nil
	}
	if keylatchBin == "" {
		return "", nil, errors.New("docker config: the keylatch executable is not known")
	}
	configDir, binDir, cleanup, err := prepareDockerConfig(keylatchBin)
	if err != nil {
		return "", nil, err
	}
	session.Set[idx].Value = configDir
	return binDir, cleanup, nil
}

// prependPath puts dir first on the PATH of env.
func prependPath(env []string, dir string) []string {
	for i, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			env[i] = "PATH=" + dir + string(os.PathListSeparator) + v
			return env
		}
	}
	return append(env, "PATH="+dir)
}
