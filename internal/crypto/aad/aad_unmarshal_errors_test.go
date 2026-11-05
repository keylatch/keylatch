package aad_test

import (
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/aad"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

func TestUnmarshal_RejectsMalformedInput(t *testing.T) {
	if _, err := aad.Unmarshal([]byte("{not json")); err == nil || !strings.Contains(err.Error(), "aad: unmarshal") {
		t.Fatalf("malformed json: %v", err)
	}
	if _, err := aad.Unmarshal([]byte(`{"created_at":"yesterday"}`)); err == nil || !strings.Contains(err.Error(), "created_at") {
		t.Fatalf("bad timestamp: %v", err)
	}
}

func TestMarshal_DistinctBindingsProduceDistinctAAD(t *testing.T) {
	base := vmeta.AADBinding{
		SchemaVersion: 1, Namespace: "default", Path: "default/ai/p/k", Version: 1,
		KeyTerm: 1, BackendID: "b", CreatedAt: time.Unix(1700000000, 0), Algorithm: "xchacha20-poly1305",
	}
	ref, err := aad.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*vmeta.AADBinding){
		func(b *vmeta.AADBinding) { b.Version = 2 },
		func(b *vmeta.AADBinding) { b.Path = "default/ai/p/other" },
		func(b *vmeta.AADBinding) { b.KeyTerm = 2 },
		func(b *vmeta.AADBinding) { b.BackendID = "c" },
		func(b *vmeta.AADBinding) { b.Namespace = "team" },
	}
	for i, m := range mutations {
		b := base
		m(&b)
		out, err := aad.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) == string(ref) {
			t.Errorf("mutation %d produced identical AAD", i)
		}
	}
	back, err := aad.Unmarshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	if back.Path != base.Path || back.Version != base.Version || !back.CreatedAt.Equal(base.CreatedAt) {
		t.Fatalf("round trip = %+v", back)
	}
}
