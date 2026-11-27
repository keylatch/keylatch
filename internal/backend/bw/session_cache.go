package bw

// session_cache.go implements the session cache: `keylatch bw unlock` seals a
// BW_SESSION token under the vault KEK so later keylatch invocations (including
// ones with no controlling terminal) can inject it via the RunEnv seam instead
// of requiring BW_SESSION to be exported by hand.
//
// Security invariants:
//   - The token is stored only wrapped by the KEK; no file under the config
//     directory holds it in the clear. A plaintext session file left by an
//     earlier version is zeroed and removed by the next save or by `bw lock`.
//   - A session lives at most MaxSessionTTL and, by default, DefaultSessionTTL.
//   - Token file mode 0600, cache dir mode 0700 (matches paths.AssertSafeModes).
//   - StatSession only ever reads the sidecar metadata, never the token file,
//     so doctor/`bw status` can report presence and expiry without risking a
//     token read.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

const (
	// DefaultSessionTTL is the lifetime of a session cached via
	// `keylatch bw unlock` when no TTL is given.
	DefaultSessionTTL = time.Hour
	// MaxSessionTTL is the longest lifetime a cached session may have.
	MaxSessionTTL = 8 * time.Hour
)

const (
	sessionFileName     = "bw.session.enc"
	sessionMetaFileName = "bw.session.meta.json"
	// legacySessionFileName is the plaintext token file earlier versions wrote.
	legacySessionFileName = "bw.session"
)

// ErrSessionTTLTooLong is returned for a session lifetime above MaxSessionTTL.
var ErrSessionTTLTooLong = fmt.Errorf("bw: session lifetime is above the maximum of %s", MaxSessionTTL)

// sessionMeta is the sidecar file written alongside the sealed session token.
// It NEVER contains the token itself.
type sessionMeta struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// sessionCacheDir returns the directory holding the sealed bw session and its
// sidecar metadata. Override: KEYLATCH_BW_SESSION_DIR.
func sessionCacheDir(env llmcontext.Lookup) string {
	if env != nil {
		if v := env("KEYLATCH_BW_SESSION_DIR"); v != "" {
			return v
		}
	}
	return filepath.Join(paths.ConfigDir(env), "sessions")
}

// SessionCachePath returns the path to the sealed session file (mode 0600).
func SessionCachePath(env llmcontext.Lookup) string {
	return filepath.Join(sessionCacheDir(env), sessionFileName)
}

// SessionMetaPath returns the path to the sidecar metadata file (expiry
// only — never the token).
func SessionMetaPath(env llmcontext.Lookup) string {
	return filepath.Join(sessionCacheDir(env), sessionMetaFileName)
}

// LegacySessionPath returns where earlier versions kept the session token in
// plaintext. Nothing writes it any more.
func LegacySessionPath(env llmcontext.Lookup) string {
	return filepath.Join(sessionCacheDir(env), legacySessionFileName)
}

// DefaultKEK returns the vault KEK the sealed session is wrapped by.
func DefaultKEK(env llmcontext.Lookup) (kek.KEK, error) {
	return file.LoadKeyringKEK(paths.ResolveKeyringPath(env))
}

// SaveSession seals token under k and writes it (mode 0600) with a TTL sidecar
// (mode 0600) to the session cache directory (mode 0700, created if absent).
// A ttl of zero or less means DefaultSessionTTL; one above MaxSessionTTL is an
// error. The token is never logged or embedded in a returned error.
func SaveSession(env llmcontext.Lookup, k kek.KEK, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("bw: SaveSession: empty token")
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if ttl > MaxSessionTTL {
		return ErrSessionTTLTooLong
	}
	sealed, err := k.Wrap([]byte(token))
	if err != nil {
		return fmt.Errorf("bw: seal session: %w", err)
	}

	dir := sessionCacheDir(env)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("bw: create session cache dir: %w", err)
	}
	if err := writeFileAtomic(SessionCachePath(env), sealed, 0o600); err != nil {
		return fmt.Errorf("bw: write session cache: %w", err)
	}
	metaBytes, err := json.MarshalIndent(sessionMeta{ExpiresAt: time.Now().Add(ttl)}, "", "  ")
	if err != nil {
		return fmt.Errorf("bw: marshal session meta: %w", err)
	}
	if err := writeFileAtomic(SessionMetaPath(env), append(metaBytes, '\n'), 0o600); err != nil {
		return fmt.Errorf("bw: write session meta: %w", err)
	}
	return removeLegacySession(env)
}

// LoadSession returns the cached token if present and unexpired. Returns
// ("", false, nil) — NOT an error — when the cache is absent, corrupt, or
// expired; callers should fall back to the "run keylatch bw unlock" hint. A
// sealed token that k cannot open is an error.
func LoadSession(env llmcontext.Lookup, k kek.KEK) (token string, ok bool, err error) {
	status, statErr := StatSession(env)
	if statErr != nil {
		return "", false, statErr
	}
	if !status.Present || status.Expired {
		return "", false, nil
	}
	sealed, readErr := os.ReadFile(SessionCachePath(env))
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("bw: read session cache: %w", readErr)
	}
	plain, err := k.Unwrap(sealed)
	if err != nil {
		return "", false, fmt.Errorf("bw: open session cache: %w", err)
	}
	defer clear(plain)
	return string(plain), true, nil
}

// ClearSession removes the sealed token, the sidecar and any plaintext token
// file an earlier version left. Best-effort: absent files are not an error.
func ClearSession(env llmcontext.Lookup) error {
	firstErr := removeLegacySession(env)
	for _, p := range []string{SessionCachePath(env), SessionMetaPath(env)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// removeLegacySession overwrites and deletes the plaintext token file.
func removeLegacySession(env llmcontext.Lookup) error {
	path := LegacySessionPath(env)
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: the session cache path
		_ = os.WriteFile(path, make([]byte, len(data)), 0o600) //nolint:errcheck // best-effort wipe before unlink
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bw: remove legacy session file: %w", err)
	}
	return nil
}

// SessionStatus reports cached-session presence and expiry WITHOUT ever
// returning or exposing the token itself.
type SessionStatus struct {
	Present   bool
	ExpiresAt time.Time
	Expired   bool
	// LegacyPlaintext is true when an earlier version's plaintext token file is
	// still on disk.
	LegacyPlaintext bool
}

// StatSession reads ONLY the sidecar metadata file — never a token file — so
// callers (doctor, `keylatch bw status`) can report presence/expiry without
// any code path that could leak the token.
func StatSession(env llmcontext.Lookup) (SessionStatus, error) {
	var status SessionStatus
	if _, err := os.Stat(LegacySessionPath(env)); err == nil {
		status.LegacyPlaintext = true
	}
	metaBytes, err := os.ReadFile(SessionMetaPath(env))
	if err != nil {
		if os.IsNotExist(err) {
			return status, nil
		}
		return status, fmt.Errorf("bw: read session meta: %w", err)
	}
	var meta sessionMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return status, fmt.Errorf("bw: decode session meta: %w", err)
	}
	// A sidecar without a sealed token is a corrupt/partial cache — treat as absent.
	if _, statErr := os.Stat(SessionCachePath(env)); statErr != nil {
		return status, nil
	}
	status.Present = true
	status.ExpiresAt = meta.ExpiresAt
	status.Expired = time.Now().After(meta.ExpiresAt)
	return status, nil
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
