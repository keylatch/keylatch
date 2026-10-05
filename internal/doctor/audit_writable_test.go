package doctor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckAuditWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not restrict the owner on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file modes")
	}
	dir := filepath.Join(t.TempDir(), "cfg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.log")
	lookup := func(k string) string {
		if k == "KEYLATCH_AUDIT_PATH" {
			return logPath
		}
		return ""
	}
	check := checkAuditWritable(lookup)
	ctx := context.Background()

	if st := check(ctx); !st.OK || st.Warn {
		t.Fatalf("missing log: %+v", st)
	}

	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if st := check(ctx); !st.OK || st.Warn {
		t.Fatalf("writable log: %+v", st)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if st := check(ctx); !st.OK || !st.Warn {
		t.Fatalf("read-only directory should warn: %+v", st)
	}

	if err := os.Chmod(logPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if st := check(ctx); st.OK || st.Fix == "" {
		t.Fatalf("read-only log should fail with a fix: %+v", st)
	}
}
