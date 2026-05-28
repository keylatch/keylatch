package registry

import _ "embed"

// provider_schema.json is the canonical copy of the provider template JSON schema.
// templates/providers/schema.json is a duplicate kept for documentation purposes.
// They must be kept in sync. To verify sync:
//
//go:generate diff -q provider_schema.json ../../../templates/providers/schema.json

//go:embed provider_schema.json
var providerSchemaJSON []byte
