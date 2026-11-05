package keyops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// Failure classes a caller can match with errors.Is.
var (
	ErrDenied      = errors.New("not permitted")
	ErrNotFound    = errors.New("not found")
	ErrInvalid     = errors.New("invalid request")
	ErrUnavailable = errors.New("unavailable")
)

// MaxInput bounds the bytes a single input accepts.
const MaxInput = 256 << 10

// Caller describes who asks. Constrained callers (agent and host) never
// receive plaintext unless the field allows it.
type Caller struct {
	Kind        string
	Constrained bool
}

// Request is one key operation.
type Request struct {
	Operation  Operation
	Connection string
	Field      string
	Alg        string
	Input      []byte
	Signature  []byte
	AAD        []byte
	KeyID      string
}

// Result is the outcome of an operation. Output is empty for verify.
type Result struct {
	Output []byte
	Valid  bool
}

// KeyStore reads key material. The caller clears the returned bytes.
type KeyStore interface {
	Fetch(ctx context.Context, secret string) ([]byte, error)
}

// BackendKeys reads keys from the configured credential backend.
type BackendKeys struct {
	cfg config.Config
	env llmcontext.Lookup
}

// NewBackendKeys returns a KeyStore over the backend selected by cfg.
func NewBackendKeys(cfg config.Config, env llmcontext.Lookup) *BackendKeys {
	return &BackendKeys{cfg: cfg, env: env}
}

// Fetch implements KeyStore.
func (b *BackendKeys) Fetch(ctx context.Context, secret string) ([]byte, error) {
	be, err := dispatch.Select(ctx, b.cfg, b.env)
	if err != nil {
		return nil, fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
	}
	v, _, err := be.Get(ctx, secret)
	if err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return nil, fmt.Errorf("%w: the key is not in the backend", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: read key", ErrUnavailable)
	}
	return v, nil
}

// Service runs key operations under the allowlist and records each one.
type Service struct {
	policy PolicySource
	keys   KeyStore
	audit  audit.Emitter
}

// New returns a Service. An audit emitter is required: an operation that
// cannot be recorded is not returned to the caller.
func New(policy PolicySource, keys KeyStore, emitter audit.Emitter) (*Service, error) {
	if policy == nil || keys == nil || emitter == nil {
		return nil, errors.New("keyops: policy, key store and audit emitter are required")
	}
	return &Service{policy: policy, keys: keys, audit: emitter}, nil
}

func (s *Service) record(ctx context.Context, c Caller, op Operation, ref KeyRef, alg string, input []byte, outcome audit.Outcome, reason string) error {
	sum := sha256.Sum256(input)
	extra := map[string]any{
		"operation":    string(op),
		"alg":          alg,
		"connection":   ref.Connection,
		"field":        ref.Field,
		"caller_kind":  c.Kind,
		"input_sha256": hex.EncodeToString(sum[:]),
	}
	if reason != "" {
		extra["reason"] = reason
	}
	return s.audit.Emit(ctx, audit.Event{Action: audit.ActionKeyOperation, Outcome: outcome, Extra: extra})
}

func deny(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(format, args...))
}

// authorize resolves the key and checks operation, algorithm and caller kind.
func (s *Service) authorize(c Caller, req Request) (KeyRef, string, error) {
	if !slices.Contains(userOperations, req.Operation) {
		return KeyRef{}, "", fmt.Errorf("%w: unknown operation %q", ErrInvalid, req.Operation)
	}
	if req.Connection == "" {
		return KeyRef{}, "", fmt.Errorf("%w: a connection is required", ErrInvalid)
	}
	ref, err := s.policy.Lookup(req.Connection, req.Field)
	if err != nil {
		return KeyRef{}, "", err
	}
	fp := ref.Policy
	if !slices.Contains(fp.Operations, string(req.Operation)) {
		return ref, "", deny("%s is not on the allowlist for %s/%s", req.Operation, ref.Connection, ref.Field)
	}
	alg := ""
	if req.Alg != "" {
		n, ok := NormalizeAlgorithm(req.Alg)
		if !ok {
			return ref, "", deny("algorithm %q is not on the allowlist for %s on %s/%s", req.Alg, req.Operation, ref.Connection, ref.Field)
		}
		alg = n
	} else {
		var fitting []string
		for _, a := range fp.Algorithms {
			if algorithmFits(req.Operation, a) {
				fitting = append(fitting, a)
			}
		}
		if len(fitting) != 1 {
			return ref, "", fmt.Errorf("%w: pass --alg", ErrInvalid)
		}
		alg = fitting[0]
	}
	if !slices.Contains(fp.Algorithms, alg) || !algorithmFits(req.Operation, alg) {
		return ref, alg, deny("algorithm %s is not on the allowlist for %s on %s/%s", alg, req.Operation, ref.Connection, ref.Field)
	}
	if req.Operation == OpDecrypt && c.Constrained && !fp.AgentDecrypt {
		return ref, alg, deny("decrypt returns plaintext and is not available to %s callers on %s/%s", c.Kind, ref.Connection, ref.Field)
	}
	if len(req.Input) > MaxInput || len(req.Signature) > MaxInput || len(req.AAD) > MaxInput {
		return ref, alg, fmt.Errorf("%w: input is larger than %d bytes", ErrInvalid, MaxInput)
	}
	return ref, alg, nil
}

// Do performs one operation for c.
func (s *Service) Do(ctx context.Context, c Caller, req Request) (Result, error) {
	ref, alg, err := s.authorize(c, req)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrNotFound) {
			if ref.Connection == "" {
				ref = KeyRef{Connection: req.Connection, Field: req.Field}
			}
			_ = s.record(ctx, c, req.Operation, ref, alg, req.Input, audit.OutcomeDenied, err.Error())
		}
		return Result{}, err
	}

	res, err := s.perform(ctx, ref, alg, req)
	outcome, reason := audit.OutcomeOK, ""
	if err != nil {
		outcome, reason = audit.OutcomeError, err.Error()
	}
	if aerr := s.record(ctx, c, req.Operation, ref, alg, req.Input, outcome, reason); aerr != nil {
		clear(res.Output)
		return Result{}, fmt.Errorf("%w: audit log is not writable", ErrUnavailable)
	}
	return res, err
}

func (s *Service) perform(ctx context.Context, ref KeyRef, alg string, req Request) (Result, error) {
	key, err := s.keys.Fetch(ctx, ref.Policy.Secret)
	if err != nil {
		return Result{}, err
	}
	defer clear(key)

	switch req.Operation {
	case OpSign:
		sig, err := Sign(alg, key, req.Input, false)
		return Result{Output: sig}, opError(err)
	case OpVerify:
		ok, err := Verify(alg, key, req.Input, req.Signature, false)
		return Result{Valid: ok}, opError(err)
	case OpEncrypt:
		ct, err := Encrypt(key, req.Input, req.AAD)
		return Result{Output: ct}, opError(err)
	case OpDecrypt:
		pt, err := Decrypt(key, req.Input, req.AAD)
		return Result{Output: pt}, opError(err)
	case OpJWTSign:
		tok, err := SignJWT(alg, key, req.Input, req.KeyID)
		return Result{Output: tok}, opError(err)
	}
	return Result{}, fmt.Errorf("%w: unknown operation %q", ErrInvalid, req.Operation)
}

func opError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrInvalid, err)
}
