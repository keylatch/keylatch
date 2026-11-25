package backendtest_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/memory"
	"github.com/keylatch/keylatch/internal/backendtest"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

const bkModeEnv = "KEYLATCH_BKBT_MODE"

// bkFaulty wraps the memory backend and breaks one contract per mode so the
// harness's failure reporting can be observed.
type bkFaulty struct {
	*memory.Backend
	mode string
}

var errBkInjected = errors.New("injected failure")

func (f *bkFaulty) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	switch f.mode {
	case "get-always-ok":
		return []byte("x"), backend.Meta{}, nil
	case "get-wrong-value":
		v, m, err := f.Backend.Get(ctx, path)
		if err == nil {
			v = append(v, '!')
		}
		return v, m, err
	case "get-broken":
		return nil, backend.Meta{}, errBkInjected
	}
	return f.Backend.Get(ctx, path)
}

func (f *bkFaulty) Set(ctx context.Context, path string, value []byte, m backend.Meta) error {
	if f.mode == "set-broken" {
		return errBkInjected
	}
	return f.Backend.Set(ctx, path, value, m)
}

func (f *bkFaulty) Delete(ctx context.Context, path string) error {
	if f.mode == "delete-broken" {
		return errBkInjected
	}
	return f.Backend.Delete(ctx, path)
}

func (f *bkFaulty) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	switch f.mode {
	case "list-broken":
		return nil, errBkInjected
	case "list-incomplete":
		return []backend.Entry{{Meta: backend.Meta{Path: "default/test/list/a"}, Exists: false}}, nil
	}
	return f.Backend.List(ctx, prefix)
}

func (f *bkFaulty) GetMeta(ctx context.Context, path string) (vmeta.Meta, error) {
	switch f.mode {
	case "meta-ok":
		return vmeta.Meta{Path: path}, nil
	case "meta-wrong-path":
		return vmeta.Meta{Path: "other/path"}, nil
	case "meta-unimplemented":
		return vmeta.Meta{}, errBkInjected
	}
	return f.Backend.GetMeta(ctx, path)
}

func (f *bkFaulty) Close() error {
	if f.mode == "close-broken" {
		return errBkInjected
	}
	return f.Backend.Close()
}

func bkFactory(mode string) func() backend.Backend {
	return func() backend.Backend { return &bkFaulty{Backend: memory.New(), mode: mode} }
}

func TestCompliance_MemoryPasses(t *testing.T) {
	backendtest.RunBackendComplianceTests(t, func() backend.Backend { return memory.New() })
}

func TestCompliance_MetaSupportedPasses(t *testing.T) {
	backendtest.RunBackendComplianceTests(t, bkFactory("meta-ok"))
}

func TestCompliance_MetaErrorSkips(t *testing.T) {
	backendtest.RunBackendComplianceTests(t, bkFactory("meta-unimplemented"))
}

// TestBkHarnessChild is the subprocess body: it runs the harness against a
// deliberately broken backend and is expected to fail.
func TestBkHarnessChild(t *testing.T) {
	mode := os.Getenv(bkModeEnv)
	if mode == "" {
		t.Skip("subprocess helper")
	}
	backendtest.RunBackendComplianceTests(t, bkFactory(mode))
}

func bkRunChild(t *testing.T, mode string) string {
	t.Helper()
	args := []string{"-test.run=^TestBkHarnessChild$", "-test.v"}
	// Share the coverage directory so statements executed in the child count.
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), bkModeEnv+"="+mode)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("mode %s: child should fail, got err=%v\n%s", mode, err, out.String())
	}
	return out.String()
}

func TestCompliance_ReportsViolations(t *testing.T) {
	cases := []struct {
		mode string
		want []string
	}{
		{"get-always-ok", []string{"Get on missing path", "want ErrNotFound", "Get after Delete"}},
		{"get-wrong-value", []string{`Get: got "super-secret-value!"`}},
		{"get-broken", []string{"Get: injected failure"}},
		{"set-broken", []string{"Set: injected failure", "Set before Delete", `Set "default/test/list/a"`}},
		{"delete-broken", []string{"Delete: injected failure"}},
		{"list-broken", []string{"List: injected failure"}},
		{"list-incomplete", []string{`entry "default/test/list/a": Exists should be true`, `List: missing entry "default/test/list/b"`}},
		{"meta-wrong-path", []string{`GetMeta.Path: got "other/path", want "default/test/getmeta"`}},
		{"close-broken", []string{"Close (first): injected failure", "Close (second): injected failure"}},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			out := bkRunChild(t, tc.mode)
			if !strings.Contains(out, "--- FAIL") {
				t.Fatalf("no FAIL marker in output:\n%s", out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
		})
	}
}
