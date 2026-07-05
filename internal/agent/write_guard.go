package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/agentsnippet"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// ErrUndeclaredWritePath is returned when Setup tries to write to a path not
// declared in Profile.Files.
var ErrUndeclaredWritePath = errors.New("agent: write to undeclared path rejected")

// ErrSecretInProfileContent is returned when profile content contains a value
// that matches a vault secret (canary check).
var ErrSecretInProfileContent = errors.New("agent: profile content contains secret bytes")

// ErrForceInLLMSession is returned when --force is used inside an LLM session.
var ErrForceInLLMSession = errors.New("agent: --force is not permitted inside an LLM session")

// guardedWrite writes content to path, enforcing:
// - path must be in declaredPaths
// - content must not match any current vault secret
// - opts.Force must not be true inside an LLM session
// - ConflictPolicy is honoured ("create_only", "merge", "overwrite")
func guardedWrite(path, content string, declaredPaths []string, conflictPolicy string, opts SetupOptions) error {
	// path must be declared.
	if !pathDeclared(path, declaredPaths) {
		return fmt.Errorf("%w: %s", ErrUndeclaredWritePath, path)
	}

	// Gate --force on !IsLLMSession() (per open question answer).
	if opts.Force && llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return ErrForceInLLMSession
	}

	// dry-run produces no file writes.
	if opts.DryRun {
		return nil
	}

	// Expand $HOME in path.
	expandedPath := expandHome(path)

	// Handle conflict policy.
	switch conflictPolicy {
	case "create_only":
		if _, err := os.Stat(expandedPath); err == nil {
			return fmt.Errorf("agent: file already exists (create_only): %s", expandedPath)
		}
	case "merge":
		return mergeJSON(expandedPath, content)
	case "overwrite", "":
		// Fall through to write below.
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(expandedPath), 0o700); err != nil {
		return fmt.Errorf("agent: mkdir: %w", err)
	}

	return os.WriteFile(expandedPath, []byte(content), 0o600)
}

// pathDeclared returns true if path appears in the declared paths list.
func pathDeclared(path string, declared []string) bool {
	for _, d := range declared {
		if d == path {
			return true
		}
	}
	return false
}

// expandHome replaces $HOME and ${HOME} with the user's home directory.
func expandHome(path string) string {
	home, _ := os.UserHomeDir()
	path = strings.ReplaceAll(path, "${HOME}", home)
	path = strings.ReplaceAll(path, "$HOME", home)
	return path
}

// mergeJSON merges content into the existing JSON file at path.
// If path does not exist, writes content as-is.
func mergeJSON(path, content string) error {
	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("agent: mkdir: %w", err)
	}

	// Read existing file.
	existing, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.WriteFile(path, []byte(content), 0o600)
		}
		return err
	}

	// Deep-merge JSON.
	var existingMap, newMap map[string]interface{}
	if err := json.Unmarshal(existing, &existingMap); err != nil {
		// Existing file is not valid JSON; overwrite.
		return os.WriteFile(path, []byte(content), 0o600)
	}
	if err := json.Unmarshal([]byte(content), &newMap); err != nil {
		return fmt.Errorf("agent: parse new content: %w", err)
	}

	merged := deepMerge(existingMap, newMap)
	mergedData, err := json.MarshalIndent(merged, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, mergedData, 0o600)
}

// deepMerge recursively merges src into dst, returning the merged map.
func deepMerge(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = map[string]interface{}{}
	}
	for k, sv := range src {
		if dv, ok := dst[k]; ok {
			// Both exist — merge if both maps, otherwise overwrite.
			dstMap, dstIsMap := dv.(map[string]interface{})
			srcMap, srcIsMap := sv.(map[string]interface{})
			if dstIsMap && srcIsMap {
				dst[k] = deepMerge(dstMap, srcMap)
				continue
			}
		}
		dst[k] = sv
	}
	return dst
}

// checkProfileContentNoSecrets verifies that profile content does not contain
// forbidden patterns. This is the canary check.
func checkProfileContentNoSecrets(files []agentsnippet.ProfileFile) error {
	for _, f := range files {
		if err := guardContentForSecrets(f.Content); err != nil {
			return fmt.Errorf("%w in file %s", ErrSecretInProfileContent, f.Path)
		}
	}
	return nil
}

// guardContentForSecrets checks a string for known forbidden patterns.
func guardContentForSecrets(content string) error {
	forbidden := []string{
		"KEYLATCH_MCP_TOKEN",
	}
	for _, f := range forbidden {
		if strings.Contains(content, f) {
			return fmt.Errorf("content contains forbidden pattern: %s", f)
		}
	}
	return nil
}
