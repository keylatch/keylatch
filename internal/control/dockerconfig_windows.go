//go:build windows

package control

import (
	"errors"

	"github.com/keylatch/keylatch/internal/runner"
)

// withDockerConfig refuses a Docker credential store session: the helper
// wrapper is a shell script and the placeholder tier is not served on Windows.
func withDockerConfig(session *runner.SessionEnv, _ string) (string, func(), error) {
	for _, e := range session.Set {
		if e.Value == runner.DockerConfigPlaceholder {
			return "", nil, errors.New("docker credential store sessions are not supported on Windows")
		}
	}
	return "", func() {}, nil
}

func prependPath(env []string, _ string) []string { return env }
