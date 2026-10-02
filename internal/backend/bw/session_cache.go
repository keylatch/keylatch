package bw

// session_cache.go implements the H5 session-cache seam: `keylatch bw
// unlock` stores a BW_SESSION token here so subsequent keylatch invocations
// (including ones with no controlling terminal) can inject it via the M3
// RunEnv seam instead of requiring BW_SESSION to be exported by hand every
// time.
//
// Security invariants:
//   - Token file mode 0600, cache dir mode 0700 (matches paths.AssertSafeModes).
//   - The token is NEVER written to, or derivable from, the sidecar metadata
//     file — StatSession only ever reads the sidecar, never the token file,
//     so doctor/`bw status` can report presence+expiry without risking a
//     token read.
//   - ClearSession best-effort zeroes the token file before unlinking it.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// DefaultSessionTTL is the default lifetime for a session cached via
// `keylatch bw unlock` when --ttl is not provided.
const DefaultSessionTTL = 8 * time.Hour

const (
	sessionFileName     = "bw.session"
	sessionMetaFileName = "bw.session.meta.json"
)

// sessionMeta is the sidecar file written alongside the cached session
// token. It NEVER contains the token itself.
type sessionMeta struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// sessionCacheDir returns the directory holding the cached bw session and
// its sidecar metadata. Override: KEYLATCH_BW_SESSION_DIR.
func sessionCacheDir(env llmcontext.Lookup) string {
	if env != nil {
		if v := env("KEYLATCH_BW_SESSION_DIR"); v != "" {
			return v
		}
	}
	return filepath.Join(paths.ConfigDir(env), "sessions")
}

// SessionCachePath returns the path to the cached BW_SESSION token file
// (mode 0600). Exported for doctor/tests; the token itself is never logged.
func SessionCachePath(env llmcontext.Lookup) string {
	return filepath.Join(sessionCacheDir(env), sessionFileName)
}

// SessionMetaPath returns the path to the sidecar metadata file (expiry
// only — never the token).
func SessionMetaPath(env llmcontext.Lookup) string {
	return filepath.Join(sessionCacheDir(env), sessionMetaFileName)
}

// SaveSession atomically writes token (mode 0600) and a TTL sidecar (mode
// 0600) to the session cache directory (mode 0700, created if absent). The
// token is never logged or embedded in a returned error.
func SaveSession(env llmcontext.Lookup, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("bw: SaveSession: empty token")
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}

	dir := sessionCacheDir(env)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("bw: create session cache dir: %w", err)
	}

	if err := writeFileAtomic(SessionCachePath(env), []byte(token), 0o600); err != nil {
		return fmt.Errorf("bw: write session cache: %w", err)
	}

	meta := sessionMeta{ExpiresAt: time.Now().Add(ttl)}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("bw: marshal session meta: %w", err)
	}
	metaBytes = append(metaBytes, '\n')
	if err := writeFileAtomic(SessionMetaPath(env), metaBytes, 0o600); err != nil {
		return fmt.Errorf("bw: write session meta: %w", err)
	}
	return nil
}

// LoadSession returns the cached token if present and unexpired. Returns
// ("", false, nil) — NOT an error — when the cache is absent, corrupt, or
// expired; callers should fall back to the "run keylatch bw unlock" hint.
func LoadSession(env llmcontext.Lookup) (token string, ok bool, err error) {
	status, statErr := StatSession(env)
	if statErr != nil {
		return "", false, statErr
	}
	if !status.Present || status.Expired {
		return "", false, nil
	}
	data, readErr := os.ReadFile(SessionCachePath(env))
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("bw: read session cache: %w", readErr)
	}
	return string(data), true, nil
}

// ClearSession removes the cached token and sidecar. Best-effort: absent
// files are not an error. The token file is zeroed before unlink.
func ClearSession(env llmcontext.Lookup) error {
	tokenPath := SessionCachePath(env)
	metaPath := SessionMetaPath(env)

	if data, err := os.ReadFile(tokenPath); err == nil {
		zeroed := make([]byte, len(data))
		_ = os.WriteFile(tokenPath, zeroed, 0o600) //nolint:errcheck // best-effort wipe before unlink
	}

	var firstErr error
	if err := os.Remove(tokenPath); err != nil && !os.IsNotExist(err) {
		firstErr = err
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// SessionStatus reports cached-session presence and expiry WITHOUT ever
// returning or exposing the token itself.
type SessionStatus struct {
	Present   bool
	ExpiresAt time.Time
	Expired   bool
}

// StatSession reads ONLY the sidecar metadata file — never the token file —
// so callers (doctor, `keylatch bw status`) can report presence/expiry
// without any code path that could leak the token.
func StatSession(env llmcontext.Lookup) (SessionStatus, error) {
	metaBytes, err := os.ReadFile(SessionMetaPath(env))
	if err != nil {
		if os.IsNotExist(err) {
			return SessionStatus{}, nil
		}
		return SessionStatus{}, fmt.Errorf("bw: read session meta: %w", err)
	}
	var meta sessionMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return SessionStatus{}, fmt.Errorf("bw: decode session meta: %w", err)
	}
	// A sidecar without a token file is a corrupt/partial cache — treat as absent.
	if _, statErr := os.Stat(SessionCachePath(env)); statErr != nil {
		return SessionStatus{}, nil
	}
	return SessionStatus{
		Present:   true,
		ExpiresAt: meta.ExpiresAt,
		Expired:   time.Now().After(meta.ExpiresAt),
	}, nil
}

// writeFileAtomic writes data to path atomically (temp-file + rename) with
// the given mode. Mirrors internal/config.Save's pattern.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".session-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close() //nolint:errcheck // best-effort cleanup in error path
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() //nolint:errcheck // best-effort cleanup in error path
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	success = true
	return nil
}
