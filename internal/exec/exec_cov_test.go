package exec

import (
	"context"
	"testing"
)

func TestMockRunner_Helpers(t *testing.T) {
	t.Parallel()
	m := &MockRunner{}
	ctx := context.Background()

	if got := m.LastCallName(); got != "" {
		t.Errorf("LastCallName on empty = %q", got)
	}
	if got := m.LastCallArgs(); got != nil {
		t.Errorf("LastCallArgs on empty = %v", got)
	}

	_, _, _, _ = m.Run(ctx, "op", []string{"item", "get", "tok"}, nil)
	_, _, _, _ = m.Run(ctx, "bw", []string{"list", "items"}, nil)

	if got := m.LastCallName(); got != "bw" {
		t.Errorf("LastCallName = %q, want bw", got)
	}
	if got := m.LastCallArgs(); len(got) != 2 || got[0] != "list" {
		t.Errorf("LastCallArgs = %v", got)
	}
	if got := m.CountCallsWithArg("item"); got != 2 {
		t.Errorf("CountCallsWithArg(item) = %d, want 2", got)
	}
	if got := m.CountCallsWithArg("absent"); got != 0 {
		t.Errorf("CountCallsWithArg(absent) = %d, want 0", got)
	}
	if got := len(m.CallsCopy()); got != 2 {
		t.Errorf("CallsCopy len = %d, want 2", got)
	}

	m.Reset()
	if got := len(m.CallsCopy()); got != 0 {
		t.Errorf("after Reset: %d calls", got)
	}
}

func TestRealProbe_FindAndVersion(t *testing.T) {
	t.Parallel()
	p := RealProbe{}
	ctx := context.Background()

	// "go" is guaranteed in PATH wherever the tests run.
	path, found, err := p.Find(ctx, "go")
	if err != nil || !found || path == "" {
		t.Fatalf("Find(go) = %q, %v, %v", path, found, err)
	}

	// Nonexistent binary: not found, no error.
	_, found, err = p.Find(ctx, "keylatch-definitely-not-a-binary-xyz")
	if err != nil {
		t.Fatalf("Find(nonexistent) error: %v", err)
	}
	if found {
		t.Error("Find(nonexistent) reported found")
	}

	// Version ignores the exit code and returns the first output line.
	line, err := p.Version(ctx, path)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	_ = line // content varies; exercising the path is the goal
}

func TestIsNotFound(t *testing.T) {
	t.Parallel()
	if isNotFound(nil) {
		t.Error("isNotFound(nil) = true")
	}
}

func TestArgSignature(t *testing.T) {
	t.Parallel()
	if got := argSignature("op", []string{"a", "b"}); got != "op|a|b" {
		t.Errorf("argSignature = %q", got)
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()
	if p := Resolve("go"); p == "" {
		t.Error("Resolve(go) returned empty")
	}
	if p := Resolve("keylatch-definitely-not-a-binary-xyz"); p != "" {
		t.Errorf("Resolve(nonexistent) = %q, want empty", p)
	}
}

func TestMustResolve(t *testing.T) {
	t.Parallel()
	if p := MustResolve("go"); p == "" {
		t.Error("MustResolve(go) returned empty")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustResolve(nonexistent) did not panic")
		}
	}()
	_ = MustResolve("keylatch-definitely-not-a-binary-xyz")
}

// TestDefaultRunner_RejectsRelativePath covers the S1-8 guard, which is the
// only Run branch reachable on every platform.
func TestDefaultRunner_RejectsRelativePath(t *testing.T) {
	t.Parallel()
	_, _, _, err := DefaultRunner.Run(context.Background(), "relative-name", nil, nil)
	if err == nil {
		t.Fatal("expected rejection of relative path")
	}
}
