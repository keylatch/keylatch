package brokerd

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
)

const (
	policyFile = "policy.json"
	policyDir  = "policy.d"
	sigFile    = "policy.sig"
)

// Policy states reported by Verify.
const (
	PolicyAbsent   = "absent"
	PolicySigned   = "signed"
	PolicyUnsigned = "unsigned"
	PolicyTampered = "tampered"
)

// PolicyStore keeps a partition's accepted policy together with the daemon's
// Ed25519 signature over it and the digest of the presence proof that accepted
// it. A policy file that is unsigned or does not match its signature is
// ignored: the daemon denies and records a security.block event.
type PolicyStore struct {
	Dir   string
	Keys  *keys.Hierarchy
	Audit audit.Emitter
	Now   func() time.Time

	mu       sync.Mutex
	reported string
}

type policySig struct {
	V              int               `json:"v"`
	KeyID          string            `json:"key_id"`
	PresenceDigest string            `json:"presence_digest"`
	SignedAt       time.Time         `json:"signed_at"`
	Files          map[string]string `json:"files"`
	Signature      []byte            `json:"signature"`
}

func (p *PolicyStore) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// payload is what the signature covers: the file hashes and the presence digest.
func payload(files map[string]string, presenceDigest string) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("keylatch/policy/v1\n")
	for _, n := range names {
		b.WriteString(n + " " + files[n] + "\n")
	}
	b.WriteString("presence " + presenceDigest + "\n")
	return []byte(b.String())
}

func hashFiles(files map[string][]byte) map[string]string {
	out := make(map[string]string, len(files))
	for n, body := range files {
		sum := sha256.Sum256(body)
		out[n] = hex.EncodeToString(sum[:])
	}
	return out
}

func keyIDOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Accept stores files as the partition's policy and signs them. presenceDigest
// is the digest of the proof that approved the change.
func (p *PolicyStore) Accept(files map[string][]byte, presenceDigest string) error {
	if err := brokerValidate(files); err != nil {
		return err
	}
	signer, err := p.Keys.Signer(keys.PolicySigning)
	if err != nil {
		return fmt.Errorf("brokerd: policy signing key: %w", err)
	}
	defer clear(signer)

	p.mu.Lock()
	defer p.mu.Unlock()
	if err := os.RemoveAll(filepath.Join(p.Dir, policyDir)); err != nil {
		return fmt.Errorf("brokerd: %w", err)
	}
	if err := os.Remove(filepath.Join(p.Dir, sigFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("brokerd: %w", err)
	}
	for name, body := range files {
		dst := filepath.Join(p.Dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return fmt.Errorf("brokerd: %w", err)
		}
		if err := os.WriteFile(dst, body, 0o600); err != nil {
			return fmt.Errorf("brokerd: %w", err)
		}
	}
	hashes := hashFiles(files)
	sig := policySig{
		V: 1, KeyID: keyIDOf(signer.Public().(ed25519.PublicKey)), PresenceDigest: presenceDigest,
		SignedAt: p.now().UTC(), Files: hashes, Signature: ed25519.Sign(signer, payload(hashes, presenceDigest)),
	}
	b, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	tmp := filepath.Join(p.Dir, sigFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("brokerd: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(p.Dir, sigFile)); err != nil {
		return fmt.Errorf("brokerd: %w", err)
	}
	p.reported = ""
	return nil
}

// brokerValidate parses what the daemon is about to sign, so a policy the
// enforcer cannot load is refused up front rather than denying everything later.
func brokerValidate(files map[string][]byte) error {
	dir, err := os.MkdirTemp("", "keylatch-policy-check-")
	if err != nil {
		return fmt.Errorf("brokerd: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, policyFile), files[policyFile], 0o600); err != nil {
		return fmt.Errorf("brokerd: %w", err)
	}
	if _, err := policy.Load(filepath.Join(dir, policyFile)); err != nil {
		return fmt.Errorf("brokerd: the policy does not load: %w", err)
	}
	for name, body := range files {
		if !json.Valid(body) {
			return fmt.Errorf("brokerd: %s is not valid JSON", name)
		}
		if strings.HasPrefix(name, policyDir+"/") {
			if _, err := connpolicy.Parse(body); err != nil {
				return fmt.Errorf("brokerd: %s is not a connection policy: %w", name, err)
			}
		}
	}
	return nil
}

// onDisk lists the policy files that exist, by relative name.
func (p *PolicyStore) onDisk() (map[string][]byte, error) {
	out := map[string][]byte{}
	read := func(rel string) error {
		b, err := os.ReadFile(filepath.Join(p.Dir, filepath.FromSlash(rel))) //nolint:gosec // G304: inside the partition
		if err != nil {
			return err
		}
		out[rel] = b
		return nil
	}
	if err := read(policyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(p.Dir, policyDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("unexpected directory %s", e.Name())
		}
		if err := read(policyDir + "/" + e.Name()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Verify reports the state of the stored policy.
func (p *PolicyStore) Verify() brokerapi.PolicyState {
	files, err := p.onDisk()
	if err != nil {
		return brokerapi.PolicyState{State: PolicyTampered, Detail: err.Error()}
	}
	raw, sigErr := os.ReadFile(filepath.Join(p.Dir, sigFile)) //nolint:gosec // G304: inside the partition
	switch {
	case errors.Is(sigErr, os.ErrNotExist) && len(files) == 0:
		return brokerapi.PolicyState{State: PolicyAbsent}
	case errors.Is(sigErr, os.ErrNotExist):
		return brokerapi.PolicyState{State: PolicyUnsigned, Detail: "policy files exist without a daemon signature"}
	case sigErr != nil:
		return brokerapi.PolicyState{State: PolicyTampered, Detail: sigErr.Error()}
	}
	var sig policySig
	if err := json.Unmarshal(raw, &sig); err != nil || sig.V != 1 {
		return brokerapi.PolicyState{State: PolicyTampered, Detail: "the signature file is malformed"}
	}
	pub, err := p.Keys.Public(keys.PolicySigning)
	if err != nil {
		return brokerapi.PolicyState{State: PolicyTampered, Detail: "the policy signing key is unavailable"}
	}
	st := brokerapi.PolicyState{KeyID: sig.KeyID, PresenceHash: sig.PresenceDigest}
	if sig.KeyID != keyIDOf(pub) || !ed25519.Verify(pub, payload(sig.Files, sig.PresenceDigest), sig.Signature) {
		st.State, st.Detail = PolicyTampered, "the signature does not verify under the policy signing key"
		return st
	}
	if got := hashFiles(files); !equalMaps(got, sig.Files) {
		st.State, st.Detail = PolicyTampered, "the policy files changed after they were signed"
		return st
	}
	st.State = PolicySigned
	return st
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Gate refuses a request while the stored policy is unsigned or tampered with.
// The daemon then behaves as if no policy existed, which denies. The refusal is
// recorded once per distinct failure so a tampered file cannot flood the log.
func (p *PolicyStore) Gate(ctx context.Context, res callerkind.Result) error {
	st := p.Verify()
	if st.State != PolicyUnsigned && st.State != PolicyTampered {
		return nil
	}
	p.mu.Lock()
	first := p.reported != st.State+st.Detail
	p.reported = st.State + st.Detail
	p.mu.Unlock()
	if first && p.Audit != nil {
		_ = p.Audit.Emit(ctx, audit.Event{Action: audit.ActionSecurityBlock, Outcome: audit.OutcomeDenied, Extra: map[string]any{
			"command": "policy.verify", "signals": []string{st.State}, "caller_kind": string(res.Kind),
		}})
	}
	return fmt.Errorf("the stored policy is %s (%s); the daemon ignores it and denies until a policy is accepted with presence", st.State, st.Detail)
}

// Export returns the signed policy as a bundle. It refuses a policy that does
// not verify.
func (p *PolicyStore) Export() (brokerapi.Bundle, error) {
	st := p.Verify()
	if st.State != PolicySigned {
		return brokerapi.Bundle{}, fmt.Errorf("brokerd: the stored policy is %s, so there is nothing trustworthy to export", st.State)
	}
	files, err := p.onDisk()
	if err != nil {
		return brokerapi.Bundle{}, err
	}
	raw, err := os.ReadFile(filepath.Join(p.Dir, sigFile)) //nolint:gosec // G304: inside the partition
	if err != nil {
		return brokerapi.Bundle{}, err
	}
	var sig policySig
	if err := json.Unmarshal(raw, &sig); err != nil {
		return brokerapi.Bundle{}, err
	}
	return brokerapi.Bundle{Files: files, KeyID: sig.KeyID, PresenceDigest: sig.PresenceDigest, Signature: sig.Signature}, nil
}

// Import accepts the files of a bundle from another host. That host's
// signature cannot vouch for anything here, so the files are signed again under
// this daemon's key with the digest of the presence proof that approved the
// import.
func (p *PolicyStore) Import(b brokerapi.Bundle, presenceDigest string) error {
	return p.Accept(b.Files, presenceDigest)
}

// Names returns the sorted policy file names on disk, for status output.
func (p *PolicyStore) Names() []string {
	files, _ := p.onDisk()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
