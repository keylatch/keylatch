package backend_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// noopFactory is a trivial Factory used as a test fixture.
func noopFactory(_ context.Context, _ backend.BackendConfig) (backend.Backend, error) {
	return nil, nil
}

// TestRegistry_ErrAlreadyRegistered verifies that registering the same name
// twice returns ErrAlreadyRegistered.
func TestRegistry_ErrAlreadyRegistered(t *testing.T) {
	r := backend.NewRegistry()

	if err := r.Register("dup", noopFactory); err != nil {
		t.Fatalf("first Register: unexpected error: %v", err)
	}

	err := r.Register("dup", noopFactory)
	if err == nil {
		t.Fatal("second Register: expected ErrAlreadyRegistered, got nil")
	}

	var alreadyReg backend.ErrAlreadyRegistered
	if !errors.As(err, &alreadyReg) {
		t.Fatalf("expected ErrAlreadyRegistered, got %T: %v", err, err)
	}
	if alreadyReg.Name != "dup" {
		t.Errorf("ErrAlreadyRegistered.Name = %q, want %q", alreadyReg.Name, "dup")
	}
}

// TestRegistry_Get_Absent verifies that Get returns (nil, false) for an
// unregistered name.
func TestRegistry_Get_Absent(t *testing.T) {
	r := backend.NewRegistry()

	f, ok := r.Get("nonexistent")
	if ok {
		t.Error("Get(unregistered): ok == true, want false")
	}
	if f != nil {
		t.Error("Get(unregistered): factory is non-nil, want nil")
	}
}

// TestRegistry_List_Sorted verifies that List returns registered names in
// sorted order regardless of registration order.
func TestRegistry_List_Sorted(t *testing.T) {
	r := backend.NewRegistry()

	for _, name := range []string{"zebra", "alpha", "mango"} {
		if err := r.Register(name, noopFactory); err != nil {
			t.Fatalf("Register(%q): %v", name, err)
		}
	}

	got := r.List()
	want := []string{"alpha", "mango", "zebra"}
	if len(got) != len(want) {
		t.Fatalf("List() len = %d, want %d; got %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRegistry_ConcurrentRegisterGet exercises Register and Get under
// concurrent access to verify no data race is triggered.
func TestRegistry_ConcurrentRegisterGet(t *testing.T) {
	r := backend.NewRegistry()

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers * 2)

	// Half the goroutines register unique names; the other half call Get.
	for i := 0; i < workers; i++ {
		name := "backend-" + string(rune('a'+i))
		go func(n string) {
			defer wg.Done()
			_ = r.Register(n, noopFactory)
		}(name)

		go func(n string) {
			defer wg.Done()
			_, _ = r.Get(n)
		}(name)
	}

	wg.Wait()
}
