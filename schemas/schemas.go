// Package schemas embeds the JSON Schemas Keylatch publishes.
package schemas

import _ "embed"

// ConnectionPolicy is the JSON Schema of a per-connection policy document.
//
//go:embed connection-policy.schema.json
var ConnectionPolicy []byte
