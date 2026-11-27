package release_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// symbolsOf builds ./cmd/keylatch with the given tags and returns the symbol
// table of the resulting binary.
func symbolsOf(t *testing.T, tags string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)

	bin := filepath.Join(t.TempDir(), "keylatch")
	build := exec.Command("go", "build", "-tags", tags, "-o", bin, "./cmd/keylatch")
	build.Dir = root
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "go build -tags %s: %s", tags, out)

	nm := exec.Command("go", "tool", "nm", bin)
	nm.Dir = root
	syms, err := nm.Output()
	require.NoError(t, err)
	return string(syms)
}

func TestReleaseBinaryHasNoExperimentalSymbols(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two binaries")
	}

	experimental := []string{"keylatch/internal/team", "keylatch/internal/trust/"}

	// The control build proves the search can see these packages when present.
	withTag := symbolsOf(t, "experimental")
	for _, pkg := range experimental {
		require.True(t, strings.Contains(withTag, pkg), "experimental build should contain %s symbols", pkg)
	}

	release := symbolsOf(t, "production,release")
	for _, pkg := range experimental {
		assert.False(t, strings.Contains(release, pkg), "release binary must not contain %s symbols", pkg)
	}
}
