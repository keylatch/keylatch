package brokerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/machinecert"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

// machineRecord is what the broker knows about a machine certificate it issued.
type machineRecord struct {
	Name     string    `json:"name"`
	Owner    uint32    `json:"owner"`
	Domain   string    `json:"domain"`
	Caps     []string  `json:"caps"`
	Serial   string    `json:"serial"`
	Issued   time.Time `json:"issued"`
	NotAfter time.Time `json:"not_after"`
	Revoked  bool      `json:"revoked"`
}

// machineStore persists issued certificates under the daemon's state root.
type machineStore struct {
	path string

	mu     sync.Mutex
	loaded bool
	m      map[string]machineRecord // by serial
}

func newMachineStore(root string) *machineStore {
	return &machineStore{path: filepath.Join(root, "machines.json")}
}

func (s *machineStore) load() error {
	if s.loaded {
		return nil
	}
	s.m = map[string]machineRecord{}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(b, &s.m); err != nil {
			return fmt.Errorf("machine registry: %w", err)
		}
	}
	s.loaded = true
	return nil
}

func (s *machineStore) save() error {
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *machineStore) bySerial(serial string) (machineRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return machineRecord{}, false
	}
	r, ok := s.m[serial]
	return r, ok
}

func (r machineRecord) active(now time.Time) bool { return !r.Revoked && now.Before(r.NotAfter) }

// activeByName returns the owner's live record for name.
func (s *machineStore) activeByName(owner uint32, name string, now time.Time) (machineRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return machineRecord{}, false
	}
	for _, r := range s.m {
		if r.Owner == owner && r.Name == name && r.active(now) {
			return r, true
		}
	}
	return machineRecord{}, false
}

func (s *machineStore) put(r machineRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	s.m[r.Serial] = r
	return s.save()
}

func (s *machineStore) ownedBy(owner uint32) []machineRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return nil
	}
	var out []machineRecord
	for _, r := range s.m {
		if r.Owner == owner {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b machineRecord) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return a.Issued.Compare(b.Issued)
	})
	return out
}

func (s *Server) machineStore() *machineStore {
	s.machOnce.Do(func() { s.mach = newMachineStore(s.cfg.StateRoot) })
	return s.mach
}

func (s *Server) machineCA() (*x509.Certificate, ed25519.PrivateKey, []byte, error) {
	key, err := s.cfg.Keys.Signer(keys.MachineCA)
	if err != nil {
		return nil, nil, nil, err
	}
	ca, der, err := machinecert.CA(key)
	return ca, key, der, err
}

func (a *admin) issueMachine(ctx context.Context, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	mr := req.Machine
	now := a.s.cfg.Now().UTC()
	store := a.s.machineStore()
	if _, taken := store.activeByName(a.p.uid, mr.Name, now); taken {
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, fmt.Errorf("a credential named %q is already active; revoke it first", mr.Name))
	}
	ca, caKey, caDER, err := a.s.machineCA()
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	defer clear(caKey)
	notAfter := now.Add(time.Duration(mr.TTLSeconds) * time.Second)
	der, serial, err := machinecert.IssueClient(ca, caKey, ed25519.PublicKey(mr.PublicKey), machinecert.Claims{Name: mr.Name, Domain: mr.Domain, Caps: mr.Caps, NotAfter: notAfter}, now)
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	rec := machineRecord{Name: mr.Name, Owner: a.p.uid, Domain: mr.Domain, Caps: mr.Caps, Serial: serial.String(), Issued: now, NotAfter: notAfter}
	if err := store.put(rec); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if err := a.emit(ctx, audit.ActionMachineIssue, audit.OutcomeOK, res, map[string]any{
		"name": rec.Name, "domain": rec.Domain, "caps": strings.Join(rec.Caps, ","), "serial": rec.Serial,
		"not_after": rec.NotAfter.Format(time.RFC3339), "presence": req.Digest()[:16], "outcome": "ok",
	}); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	return brokerapi.Response{OK: true, Machine: &brokerapi.MachineResult{Certificate: machinecert.PEM(der), CA: machinecert.PEM(caDER)}}
}

func (a *admin) revokeMachine(ctx context.Context, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	store := a.s.machineStore()
	now := a.s.cfg.Now().UTC()
	rec, ok := store.activeByName(a.p.uid, req.Machine.Name, now)
	if !ok {
		return fail(brokerapi.CodeNotFound, exitcode.Missing, fmt.Errorf("no active credential named %q", req.Machine.Name))
	}
	rec.Revoked = true
	if err := store.put(rec); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if err := a.emit(ctx, audit.ActionMachineRevoke, audit.OutcomeOK, res, map[string]any{
		"name": rec.Name, "serial": rec.Serial, "presence": req.Digest()[:16], "outcome": "ok",
	}); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	return brokerapi.Response{OK: true}
}

func (a *admin) listMachines() brokerapi.Response {
	out := []brokerapi.MachineInfo{}
	for _, r := range a.s.machineStore().ownedBy(a.p.uid) {
		out = append(out, brokerapi.MachineInfo{Name: r.Name, Domain: r.Domain, Caps: r.Caps, Serial: r.Serial, NotAfter: r.NotAfter.Format(time.RFC3339), Revoked: r.Revoked})
	}
	return brokerapi.Response{OK: true, Machine: &brokerapi.MachineResult{Machines: out}}
}

// listenFile holds the address of the machine listener.
func (s *Server) listenFile() string { return filepath.Join(s.cfg.StateRoot, "machine-listen") }

func (a *admin) setMachineListen(ctx context.Context, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	mr := req.Machine
	if err := gateway.ValidateMachineAddr(mr.Listen, mr.AllowWildcard); err != nil {
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
	}
	if err := os.MkdirAll(a.s.cfg.StateRoot, 0o700); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if err := os.WriteFile(a.s.listenFile(), []byte(mr.Listen+"\n"), 0o600); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if err := a.s.RestartMachineListener(mr.AllowWildcard); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if err := a.emit(ctx, audit.ActionPolicyChange, audit.OutcomeOK, res, map[string]any{"change": "machine.listen", "digest": req.Digest(), "after": mr.Listen}); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	return brokerapi.Response{OK: true}
}

// machineBackend lets the machine listener use the broker's registry, stores
// and audit log.
type machineBackend struct{ s *Server }

var errMachineAuth = errors.New("the certificate is not accepted")

func (b machineBackend) Authenticate(cert *x509.Certificate) (gateway.MachinePrincipal, error) {
	claims, err := machinecert.ClaimsOf(cert)
	if err != nil {
		return gateway.MachinePrincipal{}, err
	}
	rec, ok := b.s.machineStore().bySerial(cert.SerialNumber.String())
	switch {
	case !ok:
		return gateway.MachinePrincipal{}, errMachineAuth
	case !rec.active(b.s.cfg.Now()):
		return gateway.MachinePrincipal{}, gateway.ErrMachineRevoked
	case rec.Name != claims.Name || rec.Domain != claims.Domain || !slices.Equal(rec.Caps, claims.Caps):
		return gateway.MachinePrincipal{}, errMachineAuth
	}
	return gateway.MachinePrincipal{Name: rec.Name, Domain: rec.Domain, Caps: rec.Caps, Serial: rec.Serial}, nil
}

func (b machineBackend) Refused(ctx context.Context, p *gateway.MachinePrincipal, reason string) {
	who := "unauthenticated"
	if p != nil {
		who = p.Name
	}
	_ = b.s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionSecurityBlock, Outcome: audit.OutcomeDenied, Extra: map[string]any{
		"command": "machine.call " + who, "signals": []string{reason}, "caller_kind": string(callerkind.Machine),
	}})
}

func baseURLOf(tmpl registry.ConnectionTemplate) (string, error) {
	i := strings.Index(tmpl.TestStrategy.Endpoint, "://")
	if i < 0 {
		return "", errors.New("the provider has no endpoint")
	}
	rest := tmpl.TestStrategy.Endpoint[i+3:]
	host, _, _ := strings.Cut(rest, "/")
	if host == "" {
		return "", errors.New("the provider endpoint has no host")
	}
	return tmpl.TestStrategy.Endpoint[:i+3] + host, nil
}

func (b machineBackend) Call(ctx context.Context, p gateway.MachinePrincipal, c gateway.MachineCall) (gateway.MachineCallResult, error) {
	rec, ok := b.s.machineStore().bySerial(p.Serial)
	if !ok || !rec.active(b.s.cfg.Now()) {
		return gateway.MachineCallResult{}, gateway.ErrMachineRevoked
	}
	tmpl, err := registry.Get(c.Connection)
	if err != nil {
		return gateway.MachineCallResult{}, gateway.ErrMachineNotFound
	}
	act, ok := tmpl.Actions[c.Action]
	if !ok || tmpl.DeniesRoute(act.Method, act.Path) || len(tmpl.SecretFields) == 0 {
		return gateway.MachineCallResult{}, gateway.ErrMachineNotFound
	}
	part, err := b.s.partition(ctx, rec.Owner)
	if err != nil {
		return gateway.MachineCallResult{}, err
	}
	if err := part.policy.Gate(ctx, callerkind.Result{Kind: callerkind.Machine}); err != nil {
		return gateway.MachineCallResult{}, err
	}
	var src secretStore = part.store
	if part.syncStore != nil {
		src = part.syncStore
	}
	// The domain is the certificate's, never the request's.
	path := connections.SecretFieldPath(rec.Domain, tmpl.Category, c.Connection, tmpl.SecretFields[0].Name)
	cred, _, err := src.Get(ctx, path)
	if err != nil {
		return gateway.MachineCallResult{}, gateway.ErrMachineNotFound
	}
	defer clear(cred)
	base, err := baseURLOf(tmpl)
	if err != nil {
		return gateway.MachineCallResult{}, err
	}
	do := b.s.cfg.CallAction
	if do == nil {
		do = runner.ExecuteAction
	}
	result, callErr := do(ctx, base, c.Connection, c.Action, c.Params, string(cred))
	extra := map[string]any{"connection": c.Connection, "action": c.Action, "caller_kind": string(callerkind.Machine)}
	outcome := audit.OutcomeOK
	if callErr != nil {
		outcome, extra["reason"] = audit.OutcomeError, "dispatch failed"
	} else {
		extra["status"] = result.StatusCode
	}
	if err := b.s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionCall, Outcome: outcome, Extra: extra}); err != nil {
		return gateway.MachineCallResult{}, err
	}
	if callErr != nil {
		return gateway.MachineCallResult{}, callErr
	}
	return gateway.MachineCallResult{Status: result.StatusCode, DurationMs: result.DurationMs, Body: runner.Redact(redactValue(result.Body, cred))}, nil
}

func redactValue(body, value []byte) []byte {
	if len(value) == 0 {
		return body
	}
	return bytes.ReplaceAll(body, value, []byte("[REDACTED]"))
}

// machineManager owns the running listener.
type machineManager struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	ctx    context.Context
}

// StartMachineListener starts the listener when an address is configured.
// Serve calls it; an error is logged, not fatal, since the daemon serves its
// socket without it.
func (s *Server) StartMachineListener(ctx context.Context) {
	s.machines.mu.Lock()
	s.machines.ctx = ctx
	s.machines.mu.Unlock()
	if err := s.RestartMachineListener(false); err != nil {
		slog.Warn("machine listener not started", "error", err)
	}
}

// RestartMachineListener stops the listener and starts it on the configured
// address, if any.
func (s *Server) RestartMachineListener(allowWildcard bool) error {
	m := &s.machines
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel, m.done = nil, nil
	}
	raw, err := os.ReadFile(s.listenFile())
	if errors.Is(err, os.ErrNotExist) || m.ctx == nil {
		return nil
	}
	if err != nil {
		return err
	}
	addr := strings.TrimSpace(string(raw))
	if addr == "" {
		return nil
	}
	l, err := s.newMachineListener(addr, allowWildcard || wildcardAllowedBefore(addr))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel, m.done = cancel, make(chan struct{})
	done := m.done
	go func() {
		defer close(done)
		if err := l.Serve(ctx); err != nil {
			slog.Error("machine listener stopped", "error", err)
		}
	}()
	return nil
}

// wildcardAllowedBefore reports that the stored address was accepted with
// --allow-wildcard; a restart must not reject what a human already approved.
func wildcardAllowedBefore(addr string) bool {
	return gateway.ValidateMachineAddr(addr, false) != nil && gateway.ValidateMachineAddr(addr, true) == nil
}

func (s *Server) newMachineListener(addr string, allowWildcard bool) (*gateway.MachineListener, error) {
	ca, caKey, _, err := s.machineCA()
	if err != nil {
		return nil, err
	}
	defer clear(caKey)
	host, _, _ := net.SplitHostPort(addr)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	der, err := machinecert.IssueServer(ca, caKey, pub, []string{host, "localhost"}, now, now.Add(365*24*time.Hour))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return gateway.NewMachineListener(gateway.MachineListenerConfig{
		Addr: addr, AllowWildcard: allowWildcard, ClientCAs: pool,
		ServerCert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		Backend:    machineBackend{s},
		Listen:     s.cfg.MachineListen,
	})
}
