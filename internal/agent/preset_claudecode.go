package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/agentsnippet"
	"github.com/keylatch/keylatch/internal/connections"
)

func init() {
	Register(&ClaudeCodePreset{})
	Register(&CodexPreset{})
}

// ClaudeCodePreset implements Preset for Claude Code.
type ClaudeCodePreset struct{}

func (p *ClaudeCodePreset) Name() string { return "claude-code" }

// Setup installs the Claude Code MCP server configuration.
// Merges keylatch into ~/.claude/settings.json without overwriting other keys.
func (p *ClaudeCodePreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	profile, err := agentsnippet.GenerateProfile(ctx, "claude-code", opts.Mode, store)
	if err != nil {
		return Receipt{}, fmt.Errorf("claude-code setup: generate profile: %w", err)
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
			return Receipt{}, fmt.Errorf("claude-code setup: write %s: %w", f.Path, err)
		}
		if !opts.DryRun {
			written = append(written, f.Path)
		}
	}

	return Receipt{
		Agent:        "claude-code",
		Mode:         opts.Mode,
		FilesWritten: written,
		Instructions: profile.Instructions,
	}, nil
}

// Diff computes the line diff between the current config and what Setup would write.
func (p *ClaudeCodePreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	profile, err := agentsnippet.GenerateProfile(ctx, "claude-code", opts.Mode, store)
	if err != nil {
		return Diff{}, err
	}

	var diffLines strings.Builder
	var modified, added []string

	for _, f := range profile.Files {
		expandedPath := expandHome(f.Path)
		existing, err := os.ReadFile(expandedPath)
		if err != nil {
			added = append(added, f.Path)
			fmt.Fprintf(&diffLines, "+ [NEW] %s\n%s\n", f.Path, f.Content)
		} else if string(existing) != f.Content {
			modified = append(modified, f.Path)
			fmt.Fprintf(&diffLines, "~ [MOD] %s\nold: %s\nnew: %s\n",
				f.Path, strings.TrimSpace(string(existing)), strings.TrimSpace(f.Content))
		}
	}

	return Diff{
		Added:    added,
		Modified: modified,
		Content:  diffLines.String(),
	}, nil
}

// Uninstall removes the keylatch key from ~/.claude/settings.json.
func (p *ClaudeCodePreset) Uninstall(_ context.Context) error {
	settingsPath := filepath.Join(expandHome("${HOME}"), ".claude", "settings.json")
	return removeFromMCPServers(settingsPath, "keylatch")
}

// HealthCheck runs keylatch status to verify the integration is working.
func (p *ClaudeCodePreset) HealthCheck(_ context.Context) Status {
	settingsPath := filepath.Join(expandHome("${HOME}"), ".claude", "settings.json")
	if _, err := os.Stat(settingsPath); err != nil {
		return Status{Healthy: false, Detail: "settings.json not found"}
	}
	return Status{Healthy: true, Detail: "settings.json exists"}
}

// CodexPreset implements Preset for OpenAI Codex.
type CodexPreset struct{}

func (p *CodexPreset) Name() string { return "codex" }

func (p *CodexPreset) Setup(ctx context.Context, opts SetupOptions, store connections.Store) (Receipt, error) {
	profile, err := agentsnippet.GenerateProfile(ctx, "codex", opts.Mode, store)
	if err != nil {
		return Receipt{}, fmt.Errorf("codex setup: %w", err)
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
			return Receipt{}, fmt.Errorf("codex setup: write %s: %w", f.Path, err)
		}
		if !opts.DryRun {
			written = append(written, f.Path)
		}
	}
	return Receipt{Agent: "codex", Mode: opts.Mode, FilesWritten: written, Instructions: profile.Instructions}, nil
}

func (p *CodexPreset) Diff(ctx context.Context, opts SetupOptions, store connections.Store) (Diff, error) {
	profile, err := agentsnippet.GenerateProfile(ctx, "codex", opts.Mode, store)
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

func (p *CodexPreset) Uninstall(_ context.Context) error {
	configPath := filepath.Join(expandHome("${HOME}"), ".codex", "config.json")
	return removeFromMCPServers(configPath, "keylatch")
}

func (p *CodexPreset) HealthCheck(_ context.Context) Status {
	configPath := filepath.Join(expandHome("${HOME}"), ".codex", "config.json")
	if _, err := os.Stat(configPath); err != nil {
		return Status{Healthy: false, Detail: "config.json not found"}
	}
	return Status{Healthy: true, Detail: "config.json exists"}
}

// removeFromMCPServers removes the given key from the mcpServers JSON object in configPath.
func removeFromMCPServers(configPath, key string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil // nothing to do
	}
	var m map[string]interface{}
	if err := jsonUnmarshal(data, &m); err != nil {
		return nil
	}
	if mcp, ok := m["mcpServers"].(map[string]interface{}); ok {
		delete(mcp, key)
		m["mcpServers"] = mcp
	}
	out, err := jsonMarshalIndent(m)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, out, 0o600)
}
