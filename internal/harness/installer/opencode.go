package installer

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// opencodePlugin is the TypeScript plugin OpenCode loads from its plugin
// directory. It hands every tool call to `keylatch guard hook` and throws when
// the guard denies or does not run.
//
//go:embed opencode_plugin.ts
var opencodePlugin string

// opencodePluginSource fills the plugin template with the absolute Keylatch
// path. The path is a JSON string, which is also a valid TypeScript string.
func opencodePluginSource(keylatchPath string) []byte {
	quoted, _ := json.Marshal(keylatchPath)
	return []byte(strings.ReplaceAll(opencodePlugin, "__KEYLATCH_PATH__", string(quoted)))
}
