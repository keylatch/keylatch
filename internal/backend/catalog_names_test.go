package backend_test

import (
	"slices"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

func TestKnownCanonicalNames_SortedUniqueAndCanonical(t *testing.T) {
	names := backend.KnownCanonicalNames()
	want := []string{
		"aws-sm", "azure-kv", "bw", "doppler", "file", "gcp-sm", "infisical",
		"keeper", "keychain", "lastpass", "op", "op-connect", "proton-pass", "vault",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("KnownCanonicalNames() = %v, want %v", names, want)
	}
	for _, alias := range []string{"protonpass", "hashivault", "awssm", "azurekv", "opconnect"} {
		if slices.Contains(names, alias) {
			t.Errorf("alias %q must not be listed as a canonical name", alias)
		}
	}
	for _, n := range names {
		got, ok := backend.CanonicalName(n)
		if !ok || got != n {
			t.Errorf("CanonicalName(%q) = %q, %v; canonical names must map to themselves", n, got, ok)
		}
	}
}
