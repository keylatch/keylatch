// Package examples embeds the example files shipped under examples/.
package examples

import "embed"

// PolicyD holds the example connection policy documents, in policy.d/.
//
//go:embed policy.d/*.json
var PolicyD embed.FS
