// Package agent implements the agent profile installer. It provides a Preset
// interface with per-agent implementations (Claude Code, Codex, Cursor, and
// others) and the keylatch agent setup/snippet command handlers.
//
// Security invariants:
// - --dry-run produces no file writes
// - profile files contain placeholder values only
// - presets declare write paths up front; writing to undeclared path is rejected
// - no KEYLATCH_MCP_TOKEN in any written config file
package agent

import (
	"context"
	"errors"

	"github.com/keylatch/keylatch/internal/agentsnippet"
	"github.com/keylatch/keylatch/internal/connections"
)

// Preset is the interface that all agent profile implementations must satisfy.
type Preset interface {
	// Name returns the agent identifier (e.g. "claude-code").
	Name() string

	// Setup installs the agent profile. Writes config files if DryRun=false.
	Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error)

	// HealthCheck verifies that the installed profile is functioning.
	HealthCheck(ctx context.Context) Status

	// Uninstall removes the keylatch integration from the agent config.
	Uninstall(ctx context.Context) error

	// Diff returns the proposed changes without applying them.
	Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error)
}

// SetupOptions configures agent profile installation.
type SetupOptions struct {
	Mode      agentsnippet.ProfileMode
	DryRun    bool // if true, no files are written
	Force     bool // if true, overwrite existing files (blocked inside LLM sessions)
	Namespace string
}

// Receipt is returned on successful Setup.
type Receipt struct {
	Agent        string
	Mode         agentsnippet.ProfileMode
	FilesWritten []string
	Instructions string
}

// Status is returned by HealthCheck.
type Status struct {
	Healthy bool
	Detail  string
}

// Diff describes the proposed changes from a Setup call (without applying them).
type Diff struct {
	Added    []string
	Modified []string
	Removed  []string
	Content  string // human-readable diff
}

// ErrUnknownPreset is returned when Get is called with an unrecognised agent name.
var ErrUnknownPreset = errors.New("agent: unknown preset")

// presetRegistry maps agent name → Preset implementation.
var presetRegistry = map[string]Preset{}

// Register adds a preset to the registry.
// Called from each preset's init() or from the init() in this file.
func Register(p Preset) {
	presetRegistry[p.Name()] = p
}

// Get returns the Preset for the given name, or ErrUnknownPreset.
func Get(name string) (Preset, error) {
	p, ok := presetRegistry[name]
	if !ok {
		return nil, ErrUnknownPreset
	}
	return p, nil
}

// init registers all built-in presets.
// Implementations are in preset_claudecode.go, preset_codex.go, and preset_others.go.
func init() {
	// Registrations happen via each preset file's own init() call.
	// This comment serves as documentation of the registration pattern.
}
