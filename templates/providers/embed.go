// Package providers embeds the built-in provider template YAML files.
package providers

import "embed"

//go:embed core/*.yaml saas/*/*.yaml community/*.yaml experimental/*.yaml
var EmbeddedFS embed.FS
