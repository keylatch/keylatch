package keyops

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"golang.org/x/crypto/hkdf"
)

const policyVersion = 1

// ErrTampered means the allowlist does not carry a valid MAC from this
// installation, so it was edited outside Keylatch or damaged.
var ErrTampered = errors.New("key operation allowlist failed its integrity check")

// FieldPolicy is the allowlist for one connection field that is used through
// operations instead of being delivered as a value.
type FieldPolicy struct {
	// Secret is the backend path of the key.
	Secret     string   `json:"secret"`
	Operations []string `json:"operations"`
	Algorithms []string `json:"algorithms"`
	// AgentDecrypt lets agent and host callers decrypt, which returns plaintext.
	AgentDecrypt bool `json:"agent_decrypt,omitempty"`
	// SSHAgent exposes the key through the ssh-agent endpoint.
	SSHAgent *SSHPolicy `json:"ssh_agent,omitempty"`
}

// SSHPolicy configures the ssh-agent endpoint for a key.
type SSHPolicy struct {
	// HostKeys limits signing to sessions bound to one of these server host
	// key fingerprints (SHA256:...). Empty allows any host.
	HostKeys []string `json:"host_keys,omitempty"`
}

// KeyRef identifies a configured key.
type KeyRef struct {
	Connection string
	Field      string
	Policy     FieldPolicy
}

// PolicySource answers which operations a connection field allows.
type PolicySource interface {
	Lookup(connection, field string) (KeyRef, error)
	SSHKeys() ([]KeyRef, error)
}

// Document maps connection to field to policy.
type Document map[string]map[string]FieldPolicy

type policyFile struct {
	Version     int      `json:"version"`
	Connections Document `json:"connections"`
}

type envelope struct {
	MAC    string          `json:"mac"`
	Policy json.RawMessage `json:"policy"`
}

// MACKey derives the allowlist MAC key from the installation's audit salt, a
// secret the daemon already holds in Keylatch state.
func MACKey(auditSalt []byte) []byte {
	key := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, auditSalt, nil, []byte("keylatch/key-operations/mac/v1")), key)
	return key
}

// Store keeps the allowlist in Keylatch state, sealed with a MAC so a file
// edited by hand is refused rather than trusted. A missing file allows nothing.
type Store struct {
	mu   sync.Mutex
	path string
	key  []byte
}

// NewStore returns a Store at path sealed with key.
func NewStore(path string, key []byte) *Store { return &Store{path: path, key: key} }

// OpenStore returns the Store for the installation env describes, creating the
// audit salt its MAC key comes from when the installation has none yet.
func OpenStore(env llmcontext.Lookup) (*Store, error) {
	salt, err := readOrCreateSalt(paths.AuditSalt(env))
	if err != nil {
		return nil, err
	}
	defer clear(salt)
	return NewStore(paths.KeyOperations(env), MACKey(salt)), nil
}

// Inspect reports how many keys the installation's allowlist names, without
// creating anything. present is false when no allowlist has been written.
func Inspect(env llmcontext.Lookup) (keys int, present bool, err error) {
	path := paths.KeyOperations(env)
	if _, serr := os.Stat(path); errors.Is(serr, os.ErrNotExist) {
		return 0, false, nil
	}
	salt, err := os.ReadFile(paths.AuditSalt(env))
	if err != nil || len(salt) != 32 {
		return 0, true, fmt.Errorf("%w: the installation's MAC key is unavailable", ErrTampered)
	}
	defer clear(salt)
	doc, err := NewStore(path, MACKey(salt)).Load()
	if err != nil {
		return 0, true, err
	}
	for _, fields := range doc {
		keys += len(fields)
	}
	return keys, true, nil
}

func readOrCreateSalt(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("audit salt %q is not 32 bytes", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return readOrCreateSalt(path)
		}
		return nil, err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return nil, err
	}
	return b, f.Close()
}

func (s *Store) mac(policy []byte) string {
	m := hmac.New(sha256.New, s.key)
	m.Write(policy)
	return hex.EncodeToString(m.Sum(nil))
}

// Load reads and verifies the allowlist.
func (s *Store) Load() (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) load() (Document, error) {
	if err := paths.AssertSafeModes(s.path); err != nil {
		var missing *paths.PathNotFound
		if errors.As(err, &missing) {
			return nil, nil
		}
		return nil, fmt.Errorf("key operation allowlist: %w", err)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("key operation allowlist: %w", err)
	}
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil || len(env.Policy) == 0 {
		return nil, fmt.Errorf("%w: unreadable file; restore it, or delete it and re-add entries with 'keylatch key allow'", ErrTampered)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, env.Policy); err != nil {
		return nil, fmt.Errorf("%w: unreadable file; restore it, or delete it and re-add entries with 'keylatch key allow'", ErrTampered)
	}
	want, err := hex.DecodeString(env.MAC)
	got, _ := hex.DecodeString(s.mac(compact.Bytes()))
	if err != nil || !hmac.Equal(want, got) {
		return nil, fmt.Errorf("%w: the file was changed outside Keylatch; restore it, or delete it and re-add entries with 'keylatch key allow'", ErrTampered)
	}
	return ParsePolicy(compact.Bytes())
}

func (s *Store) write(doc Document) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	policy, err := json.Marshal(policyFile{Version: policyVersion, Connections: doc})
	if err != nil {
		return err
	}
	out, err := json.Marshal(envelope{MAC: s.mac(policy), Policy: policy})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".key-operations-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// update publishes an edit only after its authorization and audit succeed under the lock.
func (s *Store) update(fn func(Document) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return err
	}
	if doc == nil {
		doc = Document{}
	}
	if err := fn(doc); err != nil {
		return err
	}
	for conn, fields := range doc {
		if len(fields) == 0 {
			delete(doc, conn)
		}
	}
	return s.write(doc)
}

// ParsePolicy decodes and validates an allowlist document.
func ParsePolicy(data []byte) (Document, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f policyFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("key operation allowlist: %w", err)
	}
	if f.Version != policyVersion {
		return nil, fmt.Errorf("key operation allowlist: unsupported version %d", f.Version)
	}
	for conn, fields := range f.Connections {
		for name, fp := range fields {
			norm, err := validateField(fp)
			if err != nil {
				return nil, fmt.Errorf("key operation allowlist: %s/%s: %w", conn, name, err)
			}
			fields[name] = norm
		}
	}
	return f.Connections, nil
}

func validateField(fp FieldPolicy) (FieldPolicy, error) {
	if fp.Secret == "" {
		return fp, errors.New("secret is required")
	}
	for _, o := range fp.Operations {
		if !slices.Contains(userOperations, Operation(o)) {
			return fp, fmt.Errorf("unknown operation %q", o)
		}
	}
	algs := make([]string, 0, len(fp.Algorithms))
	for _, a := range fp.Algorithms {
		n, ok := NormalizeAlgorithm(a)
		if !ok {
			return fp, fmt.Errorf("unknown algorithm %q", a)
		}
		algs = append(algs, n)
	}
	fp.Algorithms = algs
	if fp.SSHAgent != nil {
		for _, h := range fp.SSHAgent.HostKeys {
			if !strings.HasPrefix(h, "SHA256:") {
				return fp, fmt.Errorf("host key %q is not a SHA256 fingerprint", h)
			}
		}
	}
	return fp, nil
}

// Lookup resolves connection and field. An empty field selects the only one.
func (s *Store) Lookup(connection, field string) (KeyRef, error) {
	conns, err := s.Load()
	if err != nil {
		return KeyRef{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	fields, ok := conns[connection]
	if !ok {
		return KeyRef{}, fmt.Errorf("%w: no key operations are configured for connection %q", ErrNotFound, connection)
	}
	if field == "" {
		if len(fields) != 1 {
			return KeyRef{}, fmt.Errorf("%w: connection %q has several key fields; pass --field", ErrInvalid, connection)
		}
		for name := range fields {
			field = name
		}
	}
	fp, ok := fields[field]
	if !ok {
		return KeyRef{}, fmt.Errorf("%w: no key operations are configured for %q field %q", ErrNotFound, connection, field)
	}
	return KeyRef{Connection: connection, Field: field, Policy: fp}, nil
}

// SSHKeys lists the keys exposed through the ssh-agent endpoint.
func (s *Store) SSHKeys() ([]KeyRef, error) {
	conns, err := s.Load()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var out []KeyRef
	for conn, fields := range conns {
		for name, fp := range fields {
			if fp.SSHAgent != nil {
				out = append(out, KeyRef{Connection: conn, Field: name, Policy: fp})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Connection+"\x00"+out[i].Field < out[j].Connection+"\x00"+out[j].Field
	})
	return out, nil
}
