package explain

import _ "embed"

//go:embed schema_v1.json
var schemaV1 []byte

// Schema returns the JSON Schema for the documents of SchemaVersion.
func Schema() []byte { return schemaV1 }
