package meta_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/aad"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// FuzzAADSerializer verifies that aad.Marshal never panics and is
// deterministic: calling it twice on the same binding produces identical bytes.
func FuzzAADSerializer(f *testing.F) {
	// Seed corpus: various byte lengths that map to fuzzed field strings.
	seeds := [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0x00}, 32),
		bytes.Repeat([]byte{0xFF}, 32),
		[]byte("default/ai/openrouter/api_key"),
		[]byte(`{"schema_version":1}`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Build an AADBinding using the fuzzed data as string fields.
		// Truncate long inputs to avoid pathological allocations.
		str := string(data)
		if len(str) > 256 {
			str = str[:256]
		}

		binding := meta.AADBinding{
			SchemaVersion: 1,
			Namespace:     str,
			Path:          str,
			Version:       1,
			KeyTerm:       0,
			BackendID:     str,
			CreatedAt:     baseTime,
			Algorithm:     "xchacha20-poly1305",
		}

		// Must not panic.
		out1, err1 := aad.Marshal(binding)
		if err1 != nil {
			// Errors are acceptable; panics are not.
			return
		}

		// Must be deterministic: marshal again and compare.
		out2, err2 := aad.Marshal(binding)
		if err2 != nil {
			t.Errorf("second Marshal returned error when first succeeded: %v", err2)
			return
		}

		if !bytes.Equal(out1, out2) {
			t.Errorf("aad.Marshal is not deterministic for binding with data=%q: %q != %q", data, out1, out2)
		}
	})
}
