package main

import (
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/contained"
	"github.com/keylatch/keylatch/internal/control"
)

// toolchainCaches are package-manager caches, relative to the daemon user's
// home, that contained runs may read. Only those that exist are mounted, and
// always read-only.
var toolchainCaches = []string{".cache/pnpm", ".npm", "go/pkg/mod", ".cargo/registry", ".cache/pip", ".gradle/caches"}

// newContained wires tier D5: the daemon's own keylatch binary is the sandbox
// helper, secret values come from the configured backend, and each run's
// private directories live next to the control socket.
func newContained(socket, keylatchBin string, res vaultResolver) *control.ContainedConfig {
	cc := &control.ContainedConfig{
		Launcher: &contained.Native{Binary: keylatchBin, Cgroups: true},
		Values:   res.value,
		StateDir: filepath.Join(filepath.Dir(socket), "runs"),
		Report:   contained.Probe,
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, c := range toolchainCaches {
			cc.ReadOnly = append(cc.ReadOnly, filepath.Join(home, c))
		}
	}
	return cc
}
