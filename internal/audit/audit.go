// Package audit implements the append-only, AEAD-encrypted, HMAC-chained
// audit logger for keylatch.
//
// Security invariants:
//   - S5-12: audit entries contain no value bytes, no DEKs, no wrapped keys.
//   - S5-13: audit --raw is blocked in LLM sessions (enforced at CLI layer).
//   - FIND-006: each event is AEAD-sealed individually under the AuditDEK.
//   - FIND3-008: chain headers are unencrypted so VerifyChain works without the DEK.
package audit

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// DeriveChainMACKey derives the 32-byte HMAC chain key from the audit salt.
// This key is salt-dependent but not DEK-dependent so VerifyChain works
// in header-only mode (FIND3-008) without the AuditDEK.
func DeriveChainMACKey(salt []byte) []byte {
	// ikm is the audit salt; info provides domain separation.
	ikm := salt
	r := hkdf.New(sha256.New, ikm, nil, []byte("keylatch/audit/mac-key/v1"))
	key := make([]byte, 32)
	_, _ = io.ReadFull(r, key)
	return key
}

// Action identifies what operation was performed.
type Action string

// Outcome describes the result of an action.
type Outcome string

const (
	// Outcome constants.
	OutcomeOK     Outcome = "ok"
	OutcomeDenied Outcome = "denied"
	OutcomeError  Outcome = "error"
	OutcomeWarn   Outcome = "warn"
)

// Action constants — all Phase 5 actions plus forward-compat Phase 11/12 stubs.
const (
	// Phase 5 — vault operations.
	ActionWrite   Action = "write"
	ActionRead    Action = "read"
	ActionDelete  Action = "delete"
	ActionList    Action = "list"
	ActionDecrypt Action = "decrypt"
	ActionEncrypt Action = "encrypt"
	ActionRevoke  Action = "revoke"
	ActionRotate  Action = "rotate"

	// Phase 5 — keyring operations.
	ActionKeyringInit Action = "keyring_init"
	ActionKEKRotate   Action = "kek_rotate"
	ActionTermDestroy Action = "term_destroy"

	// Phase 5 — audit operations.
	ActionAuditRotate Action = "audit_rotate"
	ActionAuditVerify Action = "audit_verify"
	ActionAuditRead   Action = "audit_read"

	// Phase 11 forward-compat stubs.
	ActionPolicyCheck Action = "policy_check"
	ActionTokenIssue  Action = "token_issue"
	ActionTokenRevoke Action = "token_revoke"

	// Phase 11: trust operations.
	ActionTrustUnwrap    Action = "trust_unwrap"
	ActionTrustEnroll    Action = "trust_enroll"
	ActionTrustRevoke    Action = "trust_revoke"
	ActionTrustChallenge Action = "trust_challenge"
	ActionTrustApprove   Action = "trust_approve"

	// Phase 12 forward-compat stubs.
	ActionShare    Action = "share"
	ActionUnshare  Action = "unshare"
	ActionDelegate Action = "delegate"

	// Phase 9 gateway actions.
	ActionGatewayCall         Action = "gateway_call"
	ActionGatewayTokenMint    Action = "gateway_token_mint"
	ActionGatewayTokenRevoke  Action = "gateway_token_revoke"
	ActionSubstitutionBlocked Action = "substitution_blocked"

	// Phase 13 broker actions.
	ActionBrokerExchange            Action = "broker.exchange"
	ActionBrokerCacheHit            Action = "broker.cache_hit"
	ActionDirectRunCredentialAccess Action = "broker.direct_run_credential_access"
	ActionDirectRunBlocked          Action = "broker.direct_run_blocked"

	// EPIC-09 child-env hygiene actions.
	// ActionChildEnvFilter records that KEYLATCH_* vars were stripped from the
	// child process environment. Extra.stripped_vars lists the names (not values)
	// of the removed variables.
	ActionChildEnvFilter Action = "child_env.filter"
	// ActionCleanEnv records that --clean-env was applied, reducing the child
	// process environment to a minimal allowlist. Extra.preserved_vars lists
	// the names retained; Extra.stripped_count is the number removed.
	ActionCleanEnv Action = "child_env.clean"

	// EPIC-17 operating-mode actions.
	// ActionCanaryInjected records that a canary token was injected into the child
	// environment. Extra.provider holds the provider slug; Extra.session_id holds
	// the actor identity. The canary token value is never logged.
	ActionCanaryInjected Action = "canary.injected"

	// EPIC-24 sandbox actions.
	// ActionSandboxLaunched records a successful sandbox launch via
	// direct_classic_sandboxed mode. Extra.executable_sha256 holds the verified
	// hash; Extra.executable holds the path (not the value).
	ActionSandboxLaunched Action = "sandbox.launched"
	// ActionSandboxLaunchRefused records a refused sandbox launch due to a hash
	// mismatch, missing feature flag, or bwrap absence. Extra.reason describes
	// the refusal; expected/actual hold hashes when relevant.
	ActionSandboxLaunchRefused Action = "sandbox.launch_refused"
	// ActionSandboxDenyApplied records that the deny-list was applied for a
	// sandbox run. Extra.denied_paths lists the paths (no values).
	ActionSandboxDenyApplied Action = "sandbox.deny_applied"
)

// Emitter is a minimal interface for components that need to emit audit events
// without holding a full *Logger reference. *Logger satisfies this interface.
type Emitter interface {
	Emit(ctx context.Context, e Event) error
}

// loggerEmitter wraps *Logger to satisfy Emitter.
type loggerEmitter struct {
	l *Logger
}

// AsEmitter wraps l as an Emitter. Returns nil if l is nil.
func AsEmitter(l *Logger) Emitter {
	if l == nil {
		return nil
	}
	return &loggerEmitter{l: l}
}

func (le *loggerEmitter) Emit(ctx context.Context, e Event) error {
	return le.l.Log(ctx, e)
}

// Event is an audit log entry. All fields are value-free per S5-12.
type Event struct {
	// Timestamp is the RFC3339Nano time of the event.
	Timestamp time.Time `json:"ts"`

	// Action is what operation was performed.
	Action Action `json:"action"`

	// Outcome is the result.
	Outcome Outcome `json:"outcome"`

	// Path is the canonical secret path (value-free — path only, not value).
	Path string `json:"path,omitempty"`

	// Accessor is the HMAC'd accessor identifier.
	Accessor string `json:"accessor,omitempty"`

	// Actor is the HMAC'd user/process identity.
	Actor string `json:"actor,omitempty"`

	// RuntimeMode is the execution context ("cli", "launchd", "mcp", etc.).
	RuntimeMode string `json:"runtime_mode,omitempty"`

	// Backend identifies which backend was used ("file", "keychain", etc.).
	Backend string `json:"backend,omitempty"`

	// BackendID is the stable backend instance ID (from backend.ID()).
	BackendID string `json:"backend_id,omitempty"`

	// KeyTerm is the key term used for this operation (Phase 5).
	KeyTerm int `json:"key_term,omitempty"`

	// ReceiptID is an opaque receipt identifier for cross-referencing.
	ReceiptID string `json:"receipt_id,omitempty"`

	// Extra holds additional safe fields filtered by SafeLogFields.
	Extra map[string]any `json:"extra,omitempty"`

	// ServiceName identifies the service that triggered this event.
	ServiceName string `json:"service,omitempty"`
}

// Exporter is a forward-compat interface for Phase 12 SIEM exporters.
// Registered via RegisterExporter; nil-safe hook in Logger.
type Exporter interface {
	// Export receives a sealed audit line (ciphertext, not plaintext).
	// It must not block for more than a few milliseconds.
	Export(sealedLine []byte)
}

var (
	activeExporter     Exporter
	activeExporterOnce sync.Mutex
)

// RegisterExporter sets the active exporter. nil disables export.
func RegisterExporter(e Exporter) {
	activeExporterOnce.Lock()
	activeExporter = e
	activeExporterOnce.Unlock()
}

// Sentinel errors.
var (
	ErrSaltUnavailable  = errors.New("audit: salt unavailable")
	ErrLogCorrupt       = errors.New("audit: log corrupt")
	ErrAuditFsyncFailed = errors.New("audit: fsync failed")
)

// maxLogSize is the default size cap for auto-rotation (5 MiB).
const maxLogSize = 5 * 1024 * 1024

// Logger is an append-only audit log writer.
type Logger struct {
	mu sync.Mutex

	path        string
	file        *os.File
	salt        []byte
	auditDEK    []byte
	chainMACKey []byte

	// Chain state (protected by mu).
	seq      int64
	prevHMAC string

	maxSize int64

	// fsyncFailHook is used for fault-injection tests.
	fsyncFailHook func() error
}

// Open opens or creates the audit log at path.
//
// salt is the 32-byte HMAC salt (from audit/salt.LoadOrCreate).
// auditDEK is the 32-byte key used to AEAD-seal each event.
//
// The parent directory must exist with mode 0o700.
// The log file is created with mode 0o600.
func Open(path string, salt []byte, auditDEK []byte) (*Logger, error) {
	// Validate parent directory mode.
	if err := validateParentDir(path); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}

	// Derive the chain MAC key from salt only (no DEK).
	// This allows VerifyChain to work in header-only mode without the AuditDEK
	// (FIND3-008): the chain MAC key depends only on the salt, not the DEK.
	chainMACKey := DeriveChainMACKey(salt)

	l := &Logger{
		path:        path,
		file:        f,
		salt:        salt,
		auditDEK:    auditDEK,
		chainMACKey: chainMACKey,
		maxSize:     maxLogSize,
	}

	// Seed chain state from the last line of an existing log.
	if err := l.seedChainState(); err != nil {
		_ = f.Close()
		return nil, err
	}

	return l, nil
}

// Path returns the file path of the audit log.
func (l *Logger) Path() string {
	return l.path
}

// Close flushes and closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// Log appends an audit event to the log.
// It seals the event under the AuditDEK (FIND-006), updates the HMAC chain,
// and fsyncs before returning.
func (l *Logger) Log(_ context.Context, e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.appendEvent(e)
}

// SummaryOpts controls which events are included in a Summary.
type SummaryOpts struct {
	Since     time.Time
	Service   string
	Path      string
	Action    Action
	Namespace string
}

// Summary contains aggregated (value-free) audit statistics.
type Summary struct {
	TotalEvents   int
	ByAction      map[Action]int
	ByOutcome     map[Outcome]int
	OldestEvent   time.Time
	NewestEvent   time.Time
	AccessorHMACs []string
}

// Summarize aggregates matching audit events from the log.
// Raw event bodies are never returned — only aggregate metadata.
func (l *Logger) Summarize(opts SummaryOpts) (Summary, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.summarize(opts)
}

// Rotate renames the current log file to .1 and opens a new empty log.
func (l *Logger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rotate()
}

// validateParentDir checks that the parent directory of path has mode 0o700.
// Returns nil if the directory does not exist yet (caller will create it).
func validateParentDir(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		// Directory doesn't exist yet; caller (Open) will create it.
		return nil
	}
	if runtime.GOOS != "windows" {
		// Windows NTFS ignores Unix permission bits — os.MkdirAll(path, 0o700)
		// reports 0777 on Windows so the check is meaningless there.
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return fmt.Errorf("audit: parent directory %s has unsafe permissions %04o (want 0700)", dir, mode)
		}
	}
	return nil
}
