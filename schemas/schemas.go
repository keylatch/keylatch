// Package schemas embeds the JSON Schemas Keylatch publishes.
package schemas

import _ "embed"

// ConnectionPolicy is the JSON Schema of a per-connection policy document.
//
//go:embed connection-policy.schema.json
var ConnectionPolicy []byte

// MigrateMap is the JSON Schema of the map 'keylatch migrate inventory' reads.
//
//go:embed migrate-map.schema.json
var MigrateMap []byte

// MigratePlan is the JSON Schema of the plan 'keylatch migrate inventory'
// prints and 'keylatch migrate import' reads.
//
//go:embed migrate-plan.schema.json
var MigratePlan []byte
