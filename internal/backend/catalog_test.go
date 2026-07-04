package backend_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

func TestCanonicalName_Aliases(t *testing.T) {
	cases := map[string]string{
		"awssm":          "aws-sm",
		"aws-secrets":    "aws-sm",
		"gcpsm":          "gcp-sm",
		"azure-keyvault": "azure-kv",
		"azurekv":        "azure-kv",
		"opconnect":      "op-connect",
		"protonpass":     "proton-pass",
		"hashivault":     "vault",
	}
	for input, want := range cases {
		got, ok := backend.CanonicalName(input)
		if !ok {
			t.Fatalf("CanonicalName(%q) ok=false", input)
		}
		if got != want {
			t.Fatalf("CanonicalName(%q) = %q, want %q", input, got, want)
		}
	}
}
