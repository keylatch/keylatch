package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/agent"
	"github.com/keylatch/keylatch/internal/agentsnippet"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
)

// canaryPhase3 is the sentinel value used to verify no credential leak
// through the golden path.
const canaryPhase3 = "KEYLATCH_CANARY_PHASE3_GOLDEN_0xCAFEBABE"

// goldenMockStore is an in-memory Store for golden path tests.
type goldenMockStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newGoldenMockStore() *goldenMockStore {
	return &goldenMockStore{data: map[string][]byte{}}
}

func (m *goldenMockStore) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return v, backend.Meta{Path: path, Backend: "golden_mock", Version: 1, UpdatedAt: time.Now()}, nil
}

func (m *goldenMockStore) Set(_ context.Context, path string, value []byte, _ backend.Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[path] = cp
	return nil
}

func (m *goldenMockStore) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var entries []backend.Entry
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			entries = append(entries, backend.Entry{
				Meta:   backend.Meta{Path: k, Backend: "golden_mock"},
				Exists: true,
			})
		}
	}
	return entries, nil
}

func (m *goldenMockStore) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[path]; !ok {
		return backend.ErrNotFound
	}
	delete(m.data, path)
	return nil
}

// filesIn returns all regular files under dir recursively.
func filesIn(t *testing.T, dir string) []string {
	t.Helper()
	var paths []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	return paths
}

// TestGoldenPath_FullUserJourney verifies the complete user journey:
// 1. Bootstrap fresh HOME / XDG_RUNTIME_DIR.
// 2. Connect openrouter with a canary api_key via in-memory MockBackend.
// 3. Run `agent setup claude-code --mode mcp --dry-run` → assert no file writes.
// 4. Assert GenerateMCPConfig is well-formed JSON with command:"keylatch".
// 5. Assert no canary byte, no KEYLATCH_MCP_TOKEN, no absolute paths leak.
func TestGoldenPath_FullUserJourney(t *testing.T) {
	ctx := context.Background()

	// --- Step 1: Bootstrap fresh HOME and XDG_RUNTIME_DIR ---
	homeDir := t.TempDir()
	xdgDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_RUNTIME_DIR", xdgDir)
	// Unset any LLM session signals so we are in a normal user session.
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	// Unset KEYLATCH_MCP_TOKEN for safety.
	t.Setenv("KEYLATCH_MCP_TOKEN", "")

	store := newGoldenMockStore()

	// --- Step 2: Connect openrouter with canary api_key ---
	canaryBytes := []byte(canaryPhase3)
	conn, err := connections.Connect(ctx, "openrouter", connections.ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields: map[string][]byte{
			"api_key": canaryBytes,
		},
	}, store)
	if err != nil {
		t.Fatalf("Connect openrouter: %v", err)
	}
	if conn.Provider != "openrouter" {
		t.Errorf("conn.Provider = %q, want %q", conn.Provider, "openrouter")
	}
	if conn.Status != "untested" {
		t.Errorf("conn.Status = %q, want %q", conn.Status, "untested")
	}

	// Record files before dry-run so we can detect new writes.
	filesBefore := filesIn(t, homeDir)

	// --- Step 3: Run agent setup claude-code --mode mcp --dry-run ---
	preset, err := agent.Get("claude-code")
	if err != nil {
		t.Fatalf("agent.Get(claude-code): %v", err)
	}

	receipt, err := preset.Setup(ctx, agent.SetupOptions{
		Mode:      agentsnippet.ProfileModeMCP,
		DryRun:    true,
		Namespace: "default",
	}, store)
	if err != nil {
		t.Fatalf("preset.Setup dry-run: %v", err)
	}

	// DryRun must produce no file writes.
	if len(receipt.FilesWritten) > 0 {
		t.Errorf("dry-run wrote files: %v", receipt.FilesWritten)
	}
	filesAfter := filesIn(t, homeDir)
	if len(filesAfter) != len(filesBefore) {
		t.Errorf("dry-run changed file count: before %d, after %d",
			len(filesBefore), len(filesAfter))
	}

	// --- Step 4: Assert GenerateMCPConfig is well-formed JSON with command:"keylatch" ---
	mcpCfg, err := agentsnippet.GenerateMCPConfig(ctx)
	if err != nil {
		t.Fatalf("GenerateMCPConfig: %v", err)
	}

	// Must be serialisable to valid JSON.
	mcpBytes, err := json.Marshal(mcpCfg)
	if err != nil {
		t.Fatalf("GenerateMCPConfig json.Marshal: %v", err)
	}

	// Verify it round-trips.
	var roundTrip agentsnippet.MCPConfig
	if err := json.Unmarshal(mcpBytes, &roundTrip); err != nil {
		t.Fatalf("GenerateMCPConfig round-trip: %v", err)
	}

	keylatchSpec, ok := roundTrip.MCPServers["keylatch"]
	if !ok {
		t.Fatal("MCPConfig missing 'keylatch' server entry")
	}
	if keylatchSpec.Command != "keylatch" {
		t.Errorf("MCPConfig.command = %q, want %q", keylatchSpec.Command, "keylatch")
	}

	// --- Step 5: Assert no canary, no KEYLATCH_MCP_TOKEN, no absolute paths ---

	// Prose snippet — must not leak canary or absolute paths.
	snippet, err := agentsnippet.GenerateInstruction(ctx, agentsnippet.InstructionOpts{
		IncludeMCP: true,
		Namespace:  "default",
	}, store)
	if err != nil {
		t.Fatalf("GenerateInstruction: %v", err)
	}

	snippetBytes := []byte(snippet)
	mcpOutput := mcpBytes

	// 5a: canary must not appear in any generated output.
	canary := []byte(canaryPhase3)
	if bytes.Contains(snippetBytes, canary) {
		t.Errorf("canary leaked into prose snippet")
	}
	if bytes.Contains(mcpOutput, canary) {
		t.Errorf("canary leaked into MCP config JSON")
	}

	// 5b: KEYLATCH_MCP_TOKEN must not appear.
	tokenMark := []byte("KEYLATCH_MCP_TOKEN")
	if bytes.Contains(snippetBytes, tokenMark) {
		t.Errorf("KEYLATCH_MCP_TOKEN leaked into prose snippet")
	}
	if bytes.Contains(mcpOutput, tokenMark) {
		t.Errorf("KEYLATCH_MCP_TOKEN leaked into MCP config JSON")
	}

	// 5c: absolute $HOME or /Users/ paths must not appear in generated output.
	homeMark := []byte(homeDir)
	usersPrefix := []byte("/Users/")
	homePrefixLinux := []byte("/home/")

	if bytes.Contains(snippetBytes, homeMark) {
		t.Errorf("absolute HOME path leaked into prose snippet")
	}
	if bytes.Contains(snippetBytes, usersPrefix) {
		t.Errorf("/Users/ path leaked into prose snippet")
	}
	if bytes.Contains(snippetBytes, homePrefixLinux) {
		t.Errorf("/home/ path leaked into prose snippet")
	}
	if bytes.Contains(mcpOutput, homeMark) {
		t.Errorf("absolute HOME path leaked into MCP config JSON")
	}
	if bytes.Contains(mcpOutput, usersPrefix) {
		t.Errorf("/Users/ path leaked into MCP config JSON")
	}

	// 5d: canary must not appear in any file written to homeDir.
	for _, f := range filesAfter {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bytes.Contains(data, canary) {
			t.Errorf("canary leaked to file %s", f)
		}
	}
}

// TestGoldenPath_MCPConfigShape verifies the MCP config JSON shape in isolation.
func TestGoldenPath_MCPConfigShape(t *testing.T) {
	ctx := context.Background()

	// Unset KEYLATCH_MCP_TOKEN to ensure clean state.
	t.Setenv("KEYLATCH_MCP_TOKEN", "")

	mcpCfg, err := agentsnippet.GenerateMCPConfig(ctx)
	if err != nil {
		t.Fatalf("GenerateMCPConfig: %v", err)
	}

	// Must be valid JSON.
	b, err := json.Marshal(mcpCfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !json.Valid(b) {
		t.Errorf("GenerateMCPConfig output is not valid JSON")
	}

	// command must be "keylatch".
	spec, ok := mcpCfg.MCPServers["keylatch"]
	if !ok {
		t.Fatal("missing 'keylatch' entry in mcpServers")
	}
	if spec.Command != "keylatch" {
		t.Errorf("command = %q, want %q", spec.Command, "keylatch")
	}
	// args must include "--stdio".
	hasStdio := false
	for _, a := range spec.Args {
		if a == "--stdio" {
			hasStdio = true
			break
		}
	}
	if !hasStdio {
		t.Errorf("args %v do not include --stdio", spec.Args)
	}

	// KEYLATCH_MCP_TOKEN must be absent from Env.
	if _, ok := spec.Env["KEYLATCH_MCP_TOKEN"]; ok {
		t.Errorf("Env contains KEYLATCH_MCP_TOKEN")
	}
}

// TestGoldenPath_DryRunNoWrites verifies for the golden path preset.
func TestGoldenPath_DryRunNoWrites(t *testing.T) {
	ctx := context.Background()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("CLAUDE_CODE", "")

	store := newGoldenMockStore()

	presets := []string{"claude-code", "codex", "cursor", "openhands"}
	for _, name := range presets {
		name := name
		t.Run(name, func(t *testing.T) {
			p, err := agent.Get(name)
			if err != nil {
				t.Fatalf("agent.Get(%q): %v", name, err)
			}

			filesBefore := filesIn(t, homeDir)

			receipt, err := p.Setup(ctx, agent.SetupOptions{
				Mode:   agentsnippet.ProfileModeMCP,
				DryRun: true,
			}, store)
			if err != nil {
				t.Fatalf("%s Setup dry-run: %v", name, err)
			}
			if len(receipt.FilesWritten) > 0 {
				t.Errorf("%s dry-run reported FilesWritten: %v", name, receipt.FilesWritten)
			}

			filesAfter := filesIn(t, homeDir)
			if len(filesAfter) != len(filesBefore) {
				t.Errorf("%s dry-run changed file count: before %d, after %d",
					name, len(filesBefore), len(filesAfter))
			}
		})
	}
}
