package llmcontext_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestLeafPackageDeps verifies that internal/llmcontext must not
// import any other internal/* package from this module.
func TestLeafPackageDeps(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/keylatch/keylatch/internal/llmcontext").Output()
	if err != nil {
		t.Fatalf("go list -deps failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "github.com/keylatch/keylatch/internal/") &&
			line != "github.com/keylatch/keylatch/internal/llmcontext" {
			t.Errorf("llmcontext imports disallowed internal package: %s", line)
		}
	}
}
