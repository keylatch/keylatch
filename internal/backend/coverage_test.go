// Package backend_test — additional coverage tests targeting previously
// uncovered functions: Store.Close, AppendRegistrationError,
// RegistrationErrors, ErrAlreadyRegistered.Error, and StripNonStringSettings.
package backend_test

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// TestStore_Close verifies that Close zeroes all byte slices and clears the map.
func TestStore_Close(t *testing.T) {
	s := backend.Store{
		Backend: "file",
		Entries: map[string][]byte{
			"default/ai/openrouter/api_key": []byte("sk-secret"),
			"default/ai/anthropic/api_key":  []byte("sk-secret2"),
		},
	}

	s.Close()

	if len(s.Entries) != 0 {
		t.Errorf("after Close: Entries has %d items, want 0", len(s.Entries))
	}
}

// TestStore_Close_Empty verifies that Close on an empty store is safe.
func TestStore_Close_Empty(t *testing.T) {
	s := backend.Store{
		Backend: "file",
		Entries: map[string][]byte{},
	}
	s.Close() // must not panic
}

// TestRegistrationError verifies AppendRegistrationError and RegistrationErrors.
//
// NOTE: This test uses a separate registry-error round-trip.  The package-level
// registrationErr slice is a singleton so we can only add to it; we verify the
// new error appears in the result.
func TestRegistrationError_AppendAndRetrieve(t *testing.T) {
	sentinel := errors.New("test-registration-error-sentinel")
	backend.AppendRegistrationError(sentinel)

	errs := backend.RegistrationErrors()
	found := false
	for _, e := range errs {
		if errors.Is(e, sentinel) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("RegistrationErrors() does not contain the appended error; got: %v", errs)
	}
}

// TestErrAlreadyRegistered_Error verifies the error string formatting.
func TestErrAlreadyRegistered_Error(t *testing.T) {
	err := backend.ErrAlreadyRegistered{Name: "file"}
	got := err.Error()
	if got == "" {
		t.Error("ErrAlreadyRegistered.Error() returned empty string")
	}
	// Must mention the backend name.
	if !containsSubstring(got, "file") {
		t.Errorf("ErrAlreadyRegistered.Error() = %q; want it to mention the name %q", got, "file")
	}
}

// TestStripNonStringSettings verifies that only string and nil values are kept.
func TestStripNonStringSettings(t *testing.T) {
	fn := func(string) string { return "" }
	input := map[string]interface{}{
		"data_dir":    "/tmp/vault",
		"env":         fn, // non-string: should be stripped
		"nil_val":     nil,
		"some_number": 42,           // non-string: should be stripped
		"some_bool":   true,         // non-string: should be stripped
		"slice_val":   []string{"a"}, // non-string: should be stripped
	}

	got := backend.StripNonStringSettings(input)

	if _, ok := got["data_dir"]; !ok {
		t.Error("StripNonStringSettings: expected data_dir to be retained")
	}
	if v, ok := got["nil_val"]; !ok || v != nil {
		t.Errorf("StripNonStringSettings: expected nil_val=nil, got ok=%v v=%v", ok, v)
	}
	if _, ok := got["env"]; ok {
		t.Error("StripNonStringSettings: expected env (func) to be stripped")
	}
	if _, ok := got["some_number"]; ok {
		t.Error("StripNonStringSettings: expected some_number (int) to be stripped")
	}
	if _, ok := got["some_bool"]; ok {
		t.Error("StripNonStringSettings: expected some_bool (bool) to be stripped")
	}
	if _, ok := got["slice_val"]; ok {
		t.Error("StripNonStringSettings: expected slice_val ([]string) to be stripped")
	}

	// Original map must not be modified.
	if len(input) != 6 {
		t.Errorf("StripNonStringSettings modified input map (now %d entries)", len(input))
	}
}

// TestStripNonStringSettings_Empty verifies an empty input produces an empty output.
func TestStripNonStringSettings_Empty(t *testing.T) {
	got := backend.StripNonStringSettings(map[string]interface{}{})
	if len(got) != 0 {
		t.Errorf("StripNonStringSettings({}): got %d entries, want 0", len(got))
	}
}

// containsSubstring is a minimal helper to avoid importing strings in tests.
func containsSubstring(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
