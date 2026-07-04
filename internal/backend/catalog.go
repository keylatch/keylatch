package backend

import "sort"

// Canonical backend identifiers. Aliases are accepted at CLI/config boundaries
// for user ergonomics, but config.json should persist these canonical names.
var canonicalBackends = map[string]string{
	"file":           "file",
	"keychain":       "keychain",
	"op":             "op",
	"bw":             "bw",
	"proton-pass":    "proton-pass",
	"protonpass":     "proton-pass",
	"keeper":         "keeper",
	"lastpass":       "lastpass",
	"vault":          "vault",
	"hashivault":     "vault",
	"aws-sm":         "aws-sm",
	"awssm":          "aws-sm",
	"aws-secrets":    "aws-sm",
	"gcp-sm":         "gcp-sm",
	"gcpsm":          "gcp-sm",
	"azure-kv":       "azure-kv",
	"azurekv":        "azure-kv",
	"azure-keyvault": "azure-kv",
	"doppler":        "doppler",
	"infisical":      "infisical",
	"op-connect":     "op-connect",
	"opconnect":      "op-connect",
}

// CanonicalName normalizes a backend name and reports whether it is known.
func CanonicalName(name string) (string, bool) {
	canonical, ok := canonicalBackends[name]
	return canonical, ok
}

// KnownCanonicalNames returns the stable, user-selectable backend names.
func KnownCanonicalNames() []string {
	seen := make(map[string]bool, len(canonicalBackends))
	for _, canonical := range canonicalBackends {
		seen[canonical] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
