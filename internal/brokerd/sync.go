package brokerd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/registry"
	keysync "github.com/keylatch/keylatch/internal/sync"
	"github.com/keylatch/keylatch/internal/sync/targets"
)

// SyncConfig tunes the sync operations. The zero value talks to the real
// APIs.
type SyncConfig struct {
	// HTTP sends the target API requests. Nil uses a client with a timeout.
	HTTP *http.Client
	// Target replaces the client for a target; ok=false uses the real one.
	Target func(name string, t keysync.Target, token targets.Token) (keysync.TargetClient, bool)
	// Probe replaces the HTTPS verification request of a rotation.
	Probe func(ctx context.Context, url string, value []byte) error
}

type connCtxKey struct{}

// secretStore is what the sync operations need of a partition's store.
type secretStore interface {
	Get(ctx context.Context, p string) ([]byte, backend.Meta, error)
	Put(ctx context.Context, p string, value []byte) (int, error)
	List(ctx context.Context, prefix string) ([]backend.Entry, error)
}

// storeSecrets reads the sources of a sync from a partition's store. A
// connection and field name resolve to a path by the first rule that matches:
// the exact path, connection/field, or the one stored path that ends in
// /connection/field.
type storeSecrets struct{ st secretStore }

func (s storeSecrets) find(ctx context.Context, connection string, fields []string) (string, error) {
	entries, err := s.st.List(ctx, "")
	if err != nil {
		return "", err
	}
	have := make([]string, len(entries))
	for i, e := range entries {
		have[i] = e.Path
	}
	return keysync.FindPath(have, connection, fields)
}

func (s storeSecrets) Value(ctx context.Context, connection, field string) ([]byte, error) {
	fields := []string{field}
	if field == "" {
		fields = []string{"", "value"}
	}
	p, err := s.find(ctx, connection, fields)
	if err != nil {
		return nil, err
	}
	v, _, err := s.st.Get(ctx, p)
	return v, err
}

func (s storeSecrets) credential(ctx context.Context, connection string) (string, error) {
	p, err := s.find(ctx, connection, keysync.CredentialFields)
	if err != nil {
		return "", err
	}
	v, _, err := s.st.Get(ctx, p)
	if err != nil {
		return "", err
	}
	defer clear(v)
	return strings.TrimSpace(string(v)), nil
}

// credentialKinds says, per target, what kind of credential its connection
// holds: "github-app" when the connection stores an app private key (so the
// daemon could mint a short-lived token), "token" for a long-lived token.
func (s storeSecrets) credentialKinds(ctx context.Context, m keysync.Manifest) map[string]string {
	entries, err := s.st.List(ctx, "")
	if err != nil {
		return nil
	}
	have := make([]string, len(entries))
	for i, e := range entries {
		have[i] = e.Path
	}
	out := map[string]string{}
	for name, t := range m.Targets {
		if t.Credential == "" {
			continue
		}
		if _, err := keysync.FindPath(have, t.Credential, []string{"private_key"}); err == nil {
			out[name] = "github-app"
		} else if _, err := keysync.FindPath(have, t.Credential, keysync.CredentialFields); err == nil {
			out[name] = "token"
		}
	}
	return out
}

func previousPath(connection, field string) string {
	if field == "" {
		field = "_"
	}
	return path.Join(".sync", "previous", connection, field)
}

func (s storeSecrets) Previous(ctx context.Context, connection, field string) ([]byte, error) {
	v, _, err := s.st.Get(ctx, previousPath(connection, field))
	if errors.Is(err, backend.ErrNotFound) {
		return nil, keysync.ErrNoPrevious
	}
	return v, err
}

func (s storeSecrets) Remember(ctx context.Context, connection, field string, value []byte) error {
	_, err := s.st.Put(ctx, previousPath(connection, field), value)
	return err
}

// syncAudit reports the engine's events to the audit log with the caller kind
// and the digest of the request the human approved.
type syncAudit struct {
	a        *admin
	res      callerkind.Result
	presence string
}

func (s syncAudit) Event(ctx context.Context, action string, f map[string]any) error {
	extra := map[string]any{"caller_kind": string(s.res.Kind), "presence": s.presence}
	for k, v := range f {
		extra[k] = v
	}
	out := audit.OutcomeOK
	if f["outcome"] == "failed" {
		out = audit.OutcomeError
	}
	return s.a.s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.Action(action), Outcome: out, Extra: extra})
}

func (a *admin) syncKey() func() ([]byte, error) {
	return func() ([]byte, error) { return a.s.cfg.Keys.SyncKeyFor(uidString(a.p.uid)) }
}

func (a *admin) syncState() *syncState {
	a.p.syncOnce.Do(func() { a.p.sync = newSyncState(a.p.configDir(), a.syncKey()) })
	return a.p.sync
}

func (a *admin) syncOp(ctx context.Context, peer control.Peer, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	if err := a.p.policy.Gate(ctx, res); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	sr := req.Sync
	m, err := keysync.Parse(sr.Manifest, nil)
	if err != nil {
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
	}
	allowed, err := verifyAllowlist(m)
	if err != nil {
		return fail(brokerapi.CodeRefused, exitcode.PolicyDeny, err)
	}
	var src secretStore = a.p.store
	if a.p.syncStore != nil {
		src = a.p.syncStore
	}
	store := storeSecrets{src}
	files, cleanup, ferr := a.receiveEnvFiles(ctx, sr)
	if ferr != nil {
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, ferr)
	}
	defer cleanup()
	clients, err := a.syncTargets(m, sr, store, files)
	if err != nil {
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
	}
	presence := ""
	if brokerapi.Privileged(req.Op) {
		presence = req.Digest()[:16]
	}
	eng := &keysync.Engine{
		Manifest: m, Targets: clients, Secrets: store, State: a.syncState(),
		Audit: syncAudit{a, res, presence}, Probe: guardProbe(allowed, a.probe()),
	}
	out := &brokerapi.SyncResult{Credentials: store.credentialKinds(ctx, m)}
	switch req.Op {
	case brokerapi.OpSyncDiff, brokerapi.OpSyncDrift:
		out.Changes, err = eng.Diff(ctx, req.Op == brokerapi.OpSyncDiff)
		out.Drift = keysync.Drifted(out.Changes)
	case brokerapi.OpSyncApply:
		out.Entries, err = eng.Apply(ctx, sr.Prune)
	case brokerapi.OpSyncRotate:
		out.Entries, err = eng.Rotate(ctx, sr.Name, keysync.RotateOptions{
			Target: sr.Target, KeepOld: time.Duration(sr.KeepOldSeconds) * time.Second, NoRollback: sr.NoRollback,
		})
	}
	if err != nil {
		resp := fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
		resp.Sync = out
		return resp
	}
	return brokerapi.Response{OK: true, Sync: out}
}

func (a *admin) syncTargets(m keysync.Manifest, sr *brokerapi.SyncRequest, store storeSecrets, files map[string]*envFile) (map[string]keysync.TargetClient, error) {
	io := map[string]targets.EnvFileIO{}
	for name, f := range files {
		io[name] = targets.EnvFileIO{Existing: f.existing, Flush: f.flush}
	}
	return targets.Build(m, targets.BuildOptions{
		Credential: store.credential, HTTP: a.s.cfg.Sync.HTTP,
		Links: sr.Links, LinkTeams: sr.LinkTeams, Root: sr.Root, EnvKeys: sr.EnvKeys, EnvFiles: io,
		Override: a.s.cfg.Sync.Target,
	})
}

// verifyAllowlist maps each verification URL of the manifest to the hosts it
// may reach: the hosts of the template of the connection the variable's value
// comes from. A value is only ever sent as a bearer token to a host that
// connection's provider already uses.
func verifyAllowlist(m keysync.Manifest) (map[string][]string, error) {
	out := map[string][]string{}
	for _, v := range m.Vars {
		if v.Verify == nil {
			continue
		}
		tmpl, err := registry.Get(v.From.Connection)
		if err != nil {
			return nil, fmt.Errorf("%s: verify.url cannot be checked: %q is not a provider connection with known hosts", v.Name, v.From.Connection)
		}
		if err := checkVerifyHost(v.Verify.URL, tmpl.Hosts); err != nil {
			return nil, fmt.Errorf("%s: %w", v.Name, err)
		}
		out[v.Verify.URL] = append(out[v.Verify.URL], tmpl.Hosts...)
	}
	return out, nil
}

func checkVerifyHost(raw string, hosts []string) error {
	u, err := neturl.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("the verification URL must be a plain https URL")
	}
	if p := u.Port(); p != "" && p != "443" {
		return fmt.Errorf("the verification URL may not use port %s", p)
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range hosts {
		h = strings.ToLower(h)
		if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
			return nil
		}
	}
	return fmt.Errorf("the verification host %s is not one of the source connection's hosts", host)
}

// guardProbe refuses to send a value to a URL the manifest check did not
// allow, whatever calls the probe.
func guardProbe(allowed map[string][]string, probe func(context.Context, string, []byte) error) func(context.Context, string, []byte) error {
	return func(ctx context.Context, url string, value []byte) error {
		hosts, ok := allowed[url]
		if !ok {
			return errors.New("the verification URL is not allowlisted")
		}
		if err := checkVerifyHost(url, hosts); err != nil {
			return err
		}
		return probe(ctx, url, value)
	}
}

func (a *admin) probe() func(ctx context.Context, url string, value []byte) error {
	if a.s.cfg.Sync.Probe != nil {
		return a.s.cfg.Sync.Probe
	}
	return httpsProbe
}

// httpsProbe sends GET url with value as a bearer token and wants a 2xx. It
// follows no redirect and dials only addresses outside the private, link-local
// and metadata ranges, checked on the address actually connected to.
func httpsProbe(ctx context.Context, url string, value []byte) error {
	if !strings.HasPrefix(url, "https://") {
		return errors.New("the verification URL must be https")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		for _, n := range registry.SSRFDenyRanges {
			if ip == nil || n.Contains(ip) {
				return errors.New("the verification URL resolves to a forbidden address")
			}
		}
		return nil
	}}
	client := &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(value))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the verification request answered %d", resp.StatusCode)
	}
	return nil
}

// envFile is one env-file target handed over as descriptors.
type envFile struct {
	existing []byte
	temp     *os.File
}

func (f *envFile) flush(content []byte) error {
	if err := f.temp.Truncate(0); err != nil {
		return err
	}
	if _, err := f.temp.WriteAt(content, 0); err != nil {
		return err
	}
	return f.temp.Sync()
}
