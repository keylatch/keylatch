// Package brokerapi is the request and response vocabulary of the broker
// operations that ride the control socket's JSON framing: presence proofs,
// policy, secrets, audit, key rotation, migration and agent session
// registration. Decode is the only way a daemon turns bytes from a client into
// a Request, and it is strict: unknown fields, oversized values and malformed
// shapes are refused before any handler runs.
package brokerapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Op names a broker operation. Every name contains a dot, so none collides
// with a control protocol operation.
type Op string

// Broker operations.
const (
	OpStatus          Op = "broker.status"
	OpPresenceBegin   Op = "presence.begin"
	OpPolicyAccept    Op = "policy.accept"
	OpPolicyImport    Op = "policy.import"
	OpPolicyExport    Op = "policy.export"
	OpPolicyCheck     Op = "policy.check"
	OpSecretSet       Op = "secret.set"
	OpSecretDelete    Op = "secret.delete"
	OpSecretList      Op = "secret.list"
	OpAuditHead       Op = "audit.head"
	OpMigrateImport   Op = "migrate.import"
	OpMigrateExport   Op = "migrate.export"
	OpRotateKeys      Op = "keys.rotate"
	OpSessionRegister Op = "session.register"
	OpSessionEnd      Op = "session.end"
	OpSessionVerify   Op = "session.verify"
)

var allOps = []Op{
	OpStatus, OpPresenceBegin, OpPolicyAccept, OpPolicyImport, OpPolicyExport, OpPolicyCheck,
	OpSecretSet, OpSecretDelete, OpSecretList, OpAuditHead, OpMigrateImport, OpMigrateExport,
	OpRotateKeys, OpSessionRegister, OpSessionEnd, OpSessionVerify,
}

// Response codes.
const (
	CodeBadRequest       = "bad_request"
	CodeRefused          = "refused"
	CodeNotFound         = "not_found"
	CodeUnavailable      = "unavailable"
	CodePresenceRequired = "presence_required"
)

// Bounds on what a client may send.
const (
	MaxValue    = 1 << 20
	MaxItems    = 10000
	MaxPathLen  = 512
	MaxFiles    = 256
	MaxFileSize = 1 << 20
	ProofLen    = 32
)

// Privileged reports whether op changes policy, secrets or keys, and so needs a
// presence proof bound to the request.
func Privileged(op Op) bool {
	switch op {
	case OpPolicyAccept, OpPolicyImport, OpSecretSet, OpSecretDelete, OpMigrateImport, OpMigrateExport, OpRotateKeys:
		return true
	}
	return false
}

// Request is one client message.
type Request struct {
	Op Op `json:"op"`
	// Signals and Ticket are the agent signals and session ticket from the
	// client's environment. They can only make the daemon stricter, and the
	// digest ignores them.
	Signals []string `json:"signals,omitempty"`
	Ticket  string   `json:"ticket,omitempty"`
	// Proof is a presence proof issued for exactly this request.
	Proof string `json:"proof,omitempty"`
	// Target is the privileged request OpPresenceBegin asks the human to approve.
	Target *Request `json:"target,omitempty"`

	Path  string `json:"path,omitempty"`
	Value []byte `json:"value,omitempty"`
	// Files is the policy a policy.accept or a bundle carries: relative name to
	// file content.
	Files map[string][]byte `json:"files,omitempty"`
	// Bundle is the signed policy a policy.import carries.
	Bundle *Bundle `json:"bundle,omitempty"`
	// Items and Nonce carry a migration; the daemon answers with a keyed hash
	// of each value stored.
	Items        []Item `json:"items,omitempty"`
	Nonce        []byte `json:"nonce,omitempty"`
	OldAuditHead string `json:"old_audit_head,omitempty"`
	// Session registers or ends an agent session.
	Session *SessionRequest `json:"session,omitempty"`
}

// Item is one secret in a migration.
type Item struct {
	Path  string `json:"path"`
	Value []byte `json:"value"`
}

// Bundle is a signed policy: the files, who signed them and the signature.
type Bundle struct {
	Files          map[string][]byte `json:"files"`
	KeyID          string            `json:"key_id"`
	PresenceDigest string            `json:"presence_digest,omitempty"`
	Signature      []byte            `json:"signature"`
}

// SessionRequest registers an agent scope with the daemon.
type SessionRequest struct {
	ID     string `json:"id"`
	Cgroup string `json:"cgroup,omitempty"`
}

// Response is one daemon message.
type Response struct {
	OK       bool   `json:"ok"`
	Code     string `json:"code,omitempty"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`

	Proof   *Proof            `json:"proof,omitempty"`
	Status  *Status           `json:"status,omitempty"`
	Policy  *PolicyState      `json:"policy,omitempty"`
	Bundle  *Bundle           `json:"bundle,omitempty"`
	Entries []Entry           `json:"entries,omitempty"`
	Items   []Item            `json:"items,omitempty"`
	MACs    map[string]string `json:"macs,omitempty"`
	Head    *AuditHead        `json:"head,omitempty"`
	Session *SessionInfo      `json:"session,omitempty"`
}

// Proof is what the daemon hands back once the human approved a request.
type Proof struct {
	ID        string `json:"id"`
	Digest    string `json:"digest"`
	Method    string `json:"method"`
	ExpiresAt int64  `json:"expires_at"`
}

// Status describes the daemon and the caller's partition.
type Status struct {
	Version         string `json:"version"`
	Mode            string `json:"mode"`
	UID             uint32 `json:"uid"`
	KeyID           string `json:"key_id"`
	KeysLocked      bool   `json:"keys_locked"`
	RotationPending bool   `json:"rotation_pending"`
	Policy          string `json:"policy"`
	Secrets         int    `json:"secrets"`
	Presence        string `json:"presence"`
}

// PolicyState is the verification state of the partition's stored policy.
type PolicyState struct {
	State        string `json:"state"`
	Detail       string `json:"detail,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	PresenceHash string `json:"presence_digest,omitempty"`
}

// Entry is the metadata of one secret.
type Entry struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
}

// AuditHead is the head of the daemon's audit chain.
type AuditHead struct {
	Hash   string `json:"hash"`
	Events int64  `json:"events"`
}

// SessionInfo answers a session registration or a ticket check. PID and Start
// name the launcher process the ticket is bound to.
type SessionInfo struct {
	ID     string `json:"id,omitempty"`
	Ticket string `json:"ticket,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Start  uint64 `json:"start,omitempty"`
}

var (
	// ErrBadRequest wraps every decoding refusal.
	ErrBadRequest = errors.New("brokerapi: bad request")

	policyFileName = regexp.MustCompile(`^(policy\.json|policy\.d/[A-Za-z0-9._-]{1,128}\.json)$`)
	sessionID      = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)
)

// OpOf reads the operation of a frame without decoding the rest, and reports
// false for anything that is not a broker operation.
func OpOf(raw []byte) (Op, bool) {
	var head struct {
		Op Op `json:"op"`
	}
	if json.Unmarshal(raw, &head) != nil || !slices.Contains(allOps, head.Op) {
		return "", false
	}
	return head.Op, true
}

// Decode parses and validates one request frame.
func Decode(frame []byte) (Request, error) {
	var req Request
	dec := json.NewDecoder(bytes.NewReader(frame))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if dec.More() {
		return Request{}, fmt.Errorf("%w: trailing data", ErrBadRequest)
	}
	if err := req.Validate(); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	return req, nil
}

// Validate checks that the request has the shape its operation needs.
func (r Request) Validate() error {
	if !slices.Contains(allOps, r.Op) {
		return fmt.Errorf("unknown operation %q", r.Op)
	}
	if len(r.Proof) > 0 && (len(r.Proof) != ProofLen*2 || !isHex(r.Proof)) {
		return errors.New("malformed proof")
	}
	if len(r.Signals) > 64 || len(r.Ticket) > 512 {
		return errors.New("too many signals or an oversized ticket")
	}
	for _, s := range r.Signals {
		if len(s) > 128 {
			return errors.New("oversized signal")
		}
	}
	if r.Target != nil {
		if r.Op != OpPresenceBegin {
			return errors.New("only presence.begin takes a target")
		}
		if r.Target.Target != nil || !Privileged(r.Target.Op) || r.Target.Proof != "" {
			return errors.New("the target must be a privileged request without a proof or a target")
		}
		if err := r.Target.Validate(); err != nil {
			return fmt.Errorf("target: %w", err)
		}
	}
	switch r.Op {
	case OpPresenceBegin:
		if r.Target == nil {
			return errors.New("presence.begin needs a target")
		}
	case OpSecretSet:
		if err := validPath(r.Path); err != nil {
			return err
		}
		if len(r.Value) > MaxValue {
			return errors.New("value too large")
		}
	case OpSecretDelete:
		return validPath(r.Path)
	case OpPolicyAccept:
		return validFiles(r.Files)
	case OpPolicyImport:
		if r.Bundle == nil {
			return errors.New("policy.import needs a bundle")
		}
		if err := validFiles(r.Bundle.Files); err != nil {
			return err
		}
		if len(r.Bundle.Signature) > 128 || len(r.Bundle.KeyID) > 64 {
			return errors.New("malformed bundle signature")
		}
	case OpMigrateImport:
		return r.validMigration()
	case OpSessionVerify:
		if r.Ticket == "" {
			return errors.New("session.verify needs a ticket")
		}
	case OpSessionRegister, OpSessionEnd:
		if r.Session == nil || !sessionID.MatchString(r.Session.ID) {
			return errors.New("a session id of 8 to 64 letters, digits and dashes is required")
		}
		if len(r.Session.Cgroup) > 1024 || strings.ContainsRune(r.Session.Cgroup, 0) {
			return errors.New("malformed cgroup")
		}
	}
	return nil
}

func (r Request) validMigration() error {
	if len(r.Items) > MaxItems {
		return errors.New("too many items")
	}
	if len(r.Nonce) < 16 || len(r.Nonce) > 64 {
		return errors.New("a migration needs a 16 to 64 byte nonce")
	}
	seen := map[string]bool{}
	for _, it := range r.Items {
		if err := validPath(it.Path); err != nil {
			return err
		}
		if len(it.Value) > MaxValue || seen[it.Path] {
			return errors.New("oversized or duplicate item")
		}
		seen[it.Path] = true
	}
	if len(r.OldAuditHead) > 128 || !isHex(r.OldAuditHead) {
		return errors.New("malformed audit head")
	}
	return nil
}

func validPath(p string) error {
	if p == "" || len(p) > MaxPathLen || strings.ContainsRune(p, 0) {
		return errors.New("a path of 1 to 512 bytes without NUL is required")
	}
	return nil
}

func validFiles(files map[string][]byte) error {
	if len(files) == 0 || len(files) > MaxFiles {
		return errors.New("a policy needs 1 to 256 files")
	}
	if _, ok := files["policy.json"]; !ok {
		return errors.New("the policy needs a policy.json")
	}
	for name, body := range files {
		if !policyFileName.MatchString(name) {
			return fmt.Errorf("%q is not a policy file name", name)
		}
		if len(body) > MaxFileSize {
			return fmt.Errorf("%s is too large", name)
		}
	}
	return nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// Digest is the hex SHA-256 over everything the request would change. A
// presence proof is issued for a digest, and the daemon recomputes it from the
// request it receives, so a proof cannot be moved to another request.
func (r Request) Digest() string {
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field([]byte("keylatch/request/v1"))
	field([]byte(r.Op))
	field([]byte(r.Path))
	sum := sha256.Sum256(r.Value)
	field(sum[:])
	digestFiles(field, r.Files)
	if r.Bundle != nil {
		digestFiles(field, r.Bundle.Files)
	}
	items := slices.Clone(r.Items)
	slices.SortFunc(items, func(a, b Item) int { return strings.Compare(a.Path, b.Path) })
	for _, it := range items {
		field([]byte(it.Path))
		s := sha256.Sum256(it.Value)
		field(s[:])
	}
	field(r.Nonce)
	field([]byte(r.OldAuditHead))
	return hex.EncodeToString(h.Sum(nil))
}

func digestFiles(field func([]byte), files map[string][]byte) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		field([]byte(n))
		s := sha256.Sum256(files[n])
		field(s[:])
	}
}

// Describe returns the action name and the sentence the human reads when
// approving the request. The daemon builds it from the request itself, never
// from text the client supplies.
func (r Request) Describe() (action, summary string) {
	short := r.Digest()[:12]
	switch r.Op {
	case OpSecretSet:
		return "secret.set", fmt.Sprintf("Store a %d-byte secret at %q (request %s)", len(r.Value), r.Path, short)
	case OpSecretDelete:
		return "secret.delete", fmt.Sprintf("Delete the secret at %q (request %s)", r.Path, short)
	case OpPolicyAccept:
		return "policy.change", fmt.Sprintf("Accept a policy of %d file(s) (request %s)", len(r.Files), short)
	case OpPolicyImport:
		n := 0
		if r.Bundle != nil {
			n = len(r.Bundle.Files)
		}
		return "policy.change", fmt.Sprintf("Import a policy bundle of %d file(s) from another host (request %s)", n, short)
	case OpMigrateImport:
		return "broker.adopt", fmt.Sprintf("Move %d secret(s) from your account into the broker (request %s)", len(r.Items), short)
	case OpMigrateExport:
		return "broker.export", fmt.Sprintf("Copy every broker secret back into your account (request %s)", short)
	case OpRotateKeys:
		return "keys.rotate", fmt.Sprintf("Rotate the broker master key (request %s)", short)
	}
	return string(r.Op), fmt.Sprintf("Perform %s (request %s)", r.Op, short)
}
