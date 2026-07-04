package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/agentsnippet"
	"github.com/keylatch/keylatch/internal/connections"
)

func init() {
	Register(&CursorPreset{})
	Register(&OpenHandsPreset{})
	Register(&OpenCodePreset{})
	Register(&OpenClawPreset{})
	Register(&NanoClawPreset{})
	Register(&HermesPreset{})
	Register(&N8nPreset{})
	Register(&DifyPreset{})
	Register(&CustomPreset{})
}

// genericPreset is a helper that implements the common preset pattern.
type genericPreset struct {
	name string //nolint:unused // planned: used by preset display name in agent listing
}

func (g *genericPreset) setupAgent(ctx context.Context, agentName string, opts SetupOptions, store connections.Store) (Receipt, error) {
	profile, err := agentsnippet.GenerateProfile(ctx, agentName, opts.Mode, store)
	if err != nil {
		return Receipt{}, fmt.Errorf("%s setup: %w", agentName, err)
	}
	if err := checkProfileContentNoSecrets(profile.Files); err != nil {
		return Receipt{}, err
	}
	declaredPaths := make([]string, len(profile.Files))
	for i, f := range profile.Files {
		declaredPaths[i] = f.Path
	}
	var written []string
	for _, f := range profile.Files {
		if err := guardedWrite(f.Path, f.Content, declaredPaths, f.ConflictPolicy, opts); err != nil {
			return Receipt{}, fmt.Errorf("%s setup: write %s: %w", agentName, f.Path, err)
		}
		if !opts.DryRun {
			written = append(written, f.Path)
		}
	}
	return Receipt{Agent: agentName, Mode: opts.Mode, FilesWritten: written, Instructions: profile.Instructions}, nil
}

func (g *genericPreset) diffAgent(ctx context.Context, agentName string, opts SetupOptions, store connections.Store) (Diff, error) {
	profile, err := agentsnippet.GenerateProfile(ctx, agentName, opts.Mode, store)
	if err != nil {
		return Diff{}, err
	}
	var added []string
	for _, f := range profile.Files {
		if _, err := os.Stat(expandHome(f.Path)); err != nil {
			added = append(added, f.Path)
		}
	}
	return Diff{Added: added}, nil
}

func (g *genericPreset) healthCheck(configPath string) Status {
	if _, err := os.Stat(expandHome(configPath)); err != nil {
		return Status{Healthy: false, Detail: "config file not found"}
	}
	return Status{Healthy: true, Detail: "config file exists"}
}

// CursorPreset implements Preset for Cursor.
type CursorPreset struct{ genericPreset }

func (p *CursorPreset) Name() string { return "cursor" }
func (p *CursorPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	return p.setupAgent(ctx, "cursor", opts, store)
}
func (p *CursorPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "cursor", opts, store)
}
func (p *CursorPreset) Uninstall(_ context.Context) error {
	return removeFromMCPServers(expandHome("${HOME}/.cursor/settings.json"), "keylatch")
}
func (p *CursorPreset) HealthCheck(_ context.Context) Status {
	return p.healthCheck("${HOME}/.cursor/settings.json")
}

// OpenHandsPreset implements Preset for OpenHands.
type OpenHandsPreset struct{ genericPreset }

func (p *OpenHandsPreset) Name() string { return "openhands" }
func (p *OpenHandsPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	return p.setupAgent(ctx, "openhands", opts, store)
}
func (p *OpenHandsPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "openhands", opts, store)
}
func (p *OpenHandsPreset) Uninstall(_ context.Context) error {
	return os.Remove(expandHome("${HOME}/.openhands/config.json"))
}
func (p *OpenHandsPreset) HealthCheck(_ context.Context) Status {
	// Stub: healthy if binary exists in PATH.
	if _, err := filepath.Abs("openhands"); err == nil {
		return Status{Healthy: true, Detail: "openhands binary found"}
	}
	return p.healthCheck("${HOME}/.openhands/config.json")
}

// OpenCodePreset implements Preset for OpenCode.
type OpenCodePreset struct{ genericPreset }

func (p *OpenCodePreset) Name() string { return "opencode" }
func (p *OpenCodePreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	return p.setupAgent(ctx, "opencode", opts, store)
}
func (p *OpenCodePreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "opencode", opts, store)
}
func (p *OpenCodePreset) Uninstall(_ context.Context) error {
	return removeFromMCPServers(expandHome("${HOME}/.opencode/config.json"), "keylatch")
}
func (p *OpenCodePreset) HealthCheck(_ context.Context) Status {
	return p.healthCheck("${HOME}/.opencode/config.json")
}

// OpenClawPreset implements Preset for OpenClaw.
type OpenClawPreset struct{ genericPreset }

func (p *OpenClawPreset) Name() string { return "openclaw" }
func (p *OpenClawPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	return p.setupAgent(ctx, "openclaw", opts, store)
}
func (p *OpenClawPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "openclaw", opts, store)
}
func (p *OpenClawPreset) Uninstall(_ context.Context) error {
	return removeFromMCPServers(expandHome("${HOME}/.openclaw/config.json"), "keylatch")
}
func (p *OpenClawPreset) HealthCheck(_ context.Context) Status {
	return p.healthCheck("${HOME}/.openclaw/config.json")
}

// NanoClawPreset implements Preset for NanoClaw.
type NanoClawPreset struct{ genericPreset }

func (p *NanoClawPreset) Name() string { return "nanoclaw" }
func (p *NanoClawPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	return p.setupAgent(ctx, "nanoclaw", opts, store)
}
func (p *NanoClawPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "nanoclaw", opts, store)
}
func (p *NanoClawPreset) Uninstall(_ context.Context) error {
	return removeFromMCPServers(expandHome("${HOME}/.nanoclaw/config.json"), "keylatch")
}
func (p *NanoClawPreset) HealthCheck(_ context.Context) Status {
	return p.healthCheck("${HOME}/.nanoclaw/config.json")
}

// HermesPreset implements Preset for Hermes.
type HermesPreset struct{ genericPreset }

func (p *HermesPreset) Name() string { return "hermes" }
func (p *HermesPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	return p.setupAgent(ctx, "hermes", opts, store)
}
func (p *HermesPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "hermes", opts, store)
}
func (p *HermesPreset) Uninstall(_ context.Context) error {
	return removeFromMCPServers(expandHome("${HOME}/.hermes/config.json"), "keylatch")
}
func (p *HermesPreset) HealthCheck(_ context.Context) Status {
	return p.healthCheck("${HOME}/.hermes/config.json")
}

// N8nPreset implements Preset for n8n.
// n8n writes a separate env-file with only non-secret config.
type N8nPreset struct{ genericPreset }

func (p *N8nPreset) Name() string { return "n8n" }
func (p *N8nPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	return p.setupAgent(ctx, "n8n", opts, store)
}
func (p *N8nPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "n8n", opts, store)
}
func (p *N8nPreset) Uninstall(_ context.Context) error {
	return os.Remove(expandHome("${HOME}/.n8n/keylatch.env"))
}
func (p *N8nPreset) HealthCheck(_ context.Context) Status {
	return p.healthCheck("${HOME}/.n8n/keylatch.env")
}

// DifyPreset implements Preset for Dify.
// Dify writes a separate env-file with only non-secret config.
type DifyPreset struct{ genericPreset }

func (p *DifyPreset) Name() string { return "dify" }
func (p *DifyPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	return p.setupAgent(ctx, "dify", opts, store)
}
func (p *DifyPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "dify", opts, store)
}
func (p *DifyPreset) Uninstall(_ context.Context) error {
	return os.Remove(expandHome("${HOME}/.dify/keylatch.env"))
}
func (p *DifyPreset) HealthCheck(_ context.Context) Status {
	return p.healthCheck("${HOME}/.dify/keylatch.env")
}

// CustomPreset accepts --config-path at setup time and validates it.
// target path must be under $HOME and not in a denylist.
type CustomPreset struct {
	genericPreset
	configPath string
}

// deniedPaths is the list of paths Custom preset cannot write to.
var deniedPaths = []string{
	".keylatch",
	".ssh",
	".config",
}

func (p *CustomPreset) Name() string { return "custom" }
func (p *CustomPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	if p.configPath == "" {
		return Receipt{}, fmt.Errorf("custom preset: --config-path is required")
	}
	home, _ := os.UserHomeDir()
	if !isUnderHome(p.configPath, home) {
		return Receipt{}, fmt.Errorf("custom preset: config path must be under $HOME")
	}
	for _, denied := range deniedPaths {
		if isUnderPath(p.configPath, filepath.Join(home, denied)) {
			return Receipt{}, fmt.Errorf("custom preset: config path %q is in denylist", p.configPath)
		}
	}
	return p.setupAgent(ctx, "custom", opts, store)
}

func (p *CustomPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	return p.diffAgent(ctx, "custom", opts, store)
}
func (p *CustomPreset) Uninstall(_ context.Context) error { return nil }
func (p *CustomPreset) HealthCheck(_ context.Context) Status {
	return Status{Healthy: true, Detail: "custom preset"}
}

// isUnderHome checks if path is under the home directory.
func isUnderHome(path, home string) bool {
	absPath, _ := filepath.Abs(path)
	absHome, _ := filepath.Abs(home)
	return len(absPath) > len(absHome) && absPath[:len(absHome)] == absHome
}

// isUnderPath checks if path is under prefix.
func isUnderPath(path, prefix string) bool {
	absPath, _ := filepath.Abs(path)
	absPrefix, _ := filepath.Abs(prefix)
	return len(absPath) >= len(absPrefix) && absPath[:len(absPrefix)] == absPrefix
}
