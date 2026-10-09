package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckRelay(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, relayBinary)
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	found := func(string) (string, error) { return bin, nil }
	missing := func(string) (string, error) { return "", errors.New("not found") }

	if st := checkRelay(missing)(context.Background()); !st.OK || st.Warn {
		t.Errorf("missing relay is optional: %+v", st)
	}
	if st := checkRelay(found)(context.Background()); !st.OK || !st.Warn || st.Fix == "" {
		t.Errorf("a user-writable relay must warn with a fix: %+v", st)
	}
	if err := os.Chmod(bin, 0o555); err != nil {
		t.Fatal(err)
	}
	if st := checkRelay(found)(context.Background()); !st.OK || st.Warn {
		t.Errorf("a read-only relay is fine: %+v", st)
	}
	gone := func(string) (string, error) { return filepath.Join(dir, "gone"), nil }
	if st := checkRelay(gone)(context.Background()); !st.Warn {
		t.Errorf("an uninspectable relay must warn: %+v", st)
	}
}
