// Package installer writes a harness's hook, MCP and rules files by structured
// merge. Where each harness keeps them comes from internal/harness; the merge
// itself from internal/harness/merge. It is separate from the registry because
// the registry is a leaf that process detection depends on.
package installer

import "github.com/keylatch/keylatch/internal/harness"

// The installer speaks in the registry's terms.
type (
	Descriptor = harness.Descriptor
	Env        = harness.Env
	Layout     = harness.Layout
)

// Support levels and file formats, as the registry defines them.
const (
	SupportGuard    = harness.SupportGuard
	FormatJSON      = harness.FormatJSON
	FormatTOML      = harness.FormatTOML
	FormatPluginDir = harness.FormatPluginDir
)
