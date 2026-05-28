package meta_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/vault/meta"
)

func validMeta() meta.Meta {
	now := time.Now().UTC().Truncate(time.Second)
	return meta.Meta{
		SchemaVersion:  meta.CurrentSchemaVersion,
		Path:           "default/ai/openrouter/api_key",
		Accessor:       meta.NewAccessor(),
		CurrentVersion: 1,
		MaxVersions:    meta.DefaultMaxVersions,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// -----------------------------------------------------------------------
// Validate table tests
// -----------------------------------------------------------------------

func TestValidate(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Second)
	future := now.Add(time.Hour)

	cases := []struct {
		name    string
		mutate  func(*meta.Meta)
		wantErr error
	}{
		{"happy path", func(_ *meta.Meta) {}, nil},
		{"missing path", func(m *meta.Meta) { m.Path = "" }, meta.ErrMissingPath},
		{"missing accessor", func(m *meta.Meta) { m.Accessor = "" }, meta.ErrMissingAccessor},
		{"unsupported schema version", func(m *meta.Meta) { m.SchemaVersion = 99 }, meta.ErrUnsupportedSchemaVersion},
		{"version zero", func(m *meta.Meta) { m.CurrentVersion = 0 }, meta.ErrInvalidVersion},
		{"version negative", func(m *meta.Meta) { m.CurrentVersion = -1 }, meta.ErrInvalidVersion},
		{"max versions negative", func(m *meta.Meta) { m.MaxVersions = -1 }, meta.ErrInvalidMaxVersions},
		{"expires before issued", func(m *meta.Meta) {
			m.IssuedAt = &future
			m.ExpiresAt = &past
		}, meta.ErrExpiresBeforeIssued},
		{"expires exactly 1s before issued", func(m *meta.Meta) {
			issued := now
			exp := now.Add(-time.Second)
			m.IssuedAt = &issued
			m.ExpiresAt = &exp
		}, meta.ErrExpiresBeforeIssued},
		{"invalid version entry", func(m *meta.Meta) {
			m.Versions = []meta.VersionMeta{{Version: 0, CreatedAt: now}}
		}, meta.ErrInvalidVersionEntry},
		{"custom contains secret", func(m *meta.Meta) {
			m.Custom = map[string]string{
				"note": "sk-or-v1-ABCDEF1234567890ABCDEF1234567890", // >20 chars, upper+digit
			}
		}, meta.ErrCustomContainsSecret},
		{"custom safe short value", func(m *meta.Meta) {
			m.Custom = map[string]string{"env": "production"}
		}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validMeta()
			tc.mutate(&m)
			err := m.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
			} else {
				if err != tc.wantErr {
					t.Errorf("want %v, got %v", tc.wantErr, err)
				}
			}
		})
	}
}

// -----------------------------------------------------------------------
// JSON round-trip
// -----------------------------------------------------------------------

func TestJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(24 * time.Hour)
	issued := now.Add(-time.Hour)

	original := meta.Meta{
		SchemaVersion:     meta.CurrentSchemaVersion,
		Path:              "default/ai/openrouter/api_key",
		Accessor:          meta.NewAccessor(),
		Backend:           "file",
		CurrentVersion:    2,
		OldestVersion:     1,
		MaxVersions:       meta.DefaultMaxVersions,
		DestroyedVersions: []int{},
		CreatedAt:         now,
		UpdatedAt:         now,
		IssuedAt:          &issued,
		ExpiresAt:         &exp,
		RotationHint:      "monthly",
		Owner:             "alice",
		Scope:             "production",
		Purpose:           "openrouter api access",
		SafeFields:        []string{"model"},
		Custom:            map[string]string{"env": "prod"},
		TeamID:            "team-42",
		SharedRecipients:  []string{"bob", "carol"},
		Versions: []meta.VersionMeta{
			{
				Version:   1,
				CreatedAt: now,
				CreatedBy: "alice",
				AAD: meta.AADBinding{
					SchemaVersion: 1,
					Namespace:     "default",
					Path:          "default/ai/openrouter/api_key",
					Version:       1,
					KeyTerm:       0,
					BackendID:     "file:/tmp/vault",
					CreatedAt:     now,
					Algorithm:     "xchacha20-poly1305",
				},
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded meta.Meta
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Check key fields.
	if decoded.Path != original.Path {
		t.Errorf("Path mismatch: %q != %q", decoded.Path, original.Path)
	}
	if decoded.Accessor != original.Accessor {
		t.Errorf("Accessor mismatch")
	}
	if decoded.CurrentVersion != original.CurrentVersion {
		t.Errorf("CurrentVersion mismatch")
	}
	if decoded.IssuedAt == nil || !decoded.IssuedAt.Equal(*original.IssuedAt) {
		t.Errorf("IssuedAt mismatch")
	}
	if decoded.ExpiresAt == nil || !decoded.ExpiresAt.Equal(*original.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch")
	}
	if decoded.TeamID != original.TeamID {
		t.Errorf("TeamID mismatch")
	}
	if len(decoded.SharedRecipients) != len(original.SharedRecipients) {
		t.Errorf("SharedRecipients mismatch")
	}
	if len(decoded.Versions) != 1 {
		t.Errorf("Versions length mismatch")
	}
	if decoded.Versions[0].AAD.Algorithm != "xchacha20-poly1305" {
		t.Errorf("AAD.Algorithm mismatch: %q", decoded.Versions[0].AAD.Algorithm)
	}
}

// -----------------------------------------------------------------------
// NewAccessor uniqueness and length
// -----------------------------------------------------------------------

func TestNewAccessorUniqueness(t *testing.T) {
	const n = 10_000
	seen := make(map[meta.ID]struct{}, n)
	for i := 0; i < n; i++ {
		id := meta.NewAccessor()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate accessor at iteration %d: %s", i, id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != n {
		t.Errorf("expected %d unique accessors, got %d", n, len(seen))
	}
}

func TestNewAccessorLength(t *testing.T) {
	id := meta.NewAccessor()
	if len(string(id)) != 26 {
		t.Errorf("expected length 26, got %d: %s", len(string(id)), id)
	}
}

// -----------------------------------------------------------------------
// AADBinding JSON key names
// -----------------------------------------------------------------------

func TestAADBindingJSONKeys(t *testing.T) {
	now := time.Now().UTC()
	aad := meta.AADBinding{
		SchemaVersion: 1,
		Namespace:     "default",
		Path:          "default/ai/openrouter/api_key",
		Version:       1,
		KeyTerm:       0,
		BackendID:     "file:/tmp",
		CreatedAt:     now,
		Algorithm:     "xchacha20-poly1305",
	}

	data, err := json.Marshal(aad)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	requiredKeys := []string{
		"schema_version", "namespace", "path", "version",
		"key_term", "backend_id", "created_at", "algorithm",
	}
	for _, k := range requiredKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("missing JSON key %q in AADBinding", k)
		}
	}
}

// -----------------------------------------------------------------------
// DeliveryRecord cap test (via AppendDelivery)
// -----------------------------------------------------------------------

func TestDeliveryRecordCap(t *testing.T) {
	vm := &meta.VersionMeta{Version: 1}
	for i := 0; i < 17; i++ {
		meta.AppendDelivery(vm, meta.DeliveryRecord{RuntimeMode: "direct"})
	}
	if len(vm.LastDeliveries) != meta.MaxDeliveryRecords {
		t.Errorf("expected %d, got %d", meta.MaxDeliveryRecords, len(vm.LastDeliveries))
	}
}

func TestDeliveryRecordFIFO(t *testing.T) {
	vm := &meta.VersionMeta{Version: 1}
	// Fill to cap.
	for i := 0; i < meta.MaxDeliveryRecords; i++ {
		meta.AppendDelivery(vm, meta.DeliveryRecord{RuntimeMode: "first"})
	}
	// Add one more — oldest "first" should be evicted.
	meta.AppendDelivery(vm, meta.DeliveryRecord{RuntimeMode: "last"})

	if len(vm.LastDeliveries) != meta.MaxDeliveryRecords {
		t.Errorf("cap not enforced: got %d", len(vm.LastDeliveries))
	}
	// Last entry should be "last".
	last := vm.LastDeliveries[len(vm.LastDeliveries)-1]
	if last.RuntimeMode != "last" {
		t.Errorf("expected last entry to have RuntimeMode 'last', got %q", last.RuntimeMode)
	}
}
