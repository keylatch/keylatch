package brokerd

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/exitcode"
)

// UnitInfo is what the service manager reports about a unit, plus a digest of
// its files.
type UnitInfo struct {
	Transient    bool
	FragmentPath string
	DropIns      []string
	ExecStart    string
	// SHA256 is the digest over the unit file and its drop-ins, path and
	// content of each, in the order systemd applies them.
	SHA256 string
}

// UnitInspector reads a unit's state from the service manager of its scope.
type UnitInspector interface {
	// Inspect describes unit in scope ("system", or "user" for owner's manager).
	Inspect(ctx context.Context, scope string, owner uint32, unit string) (UnitInfo, error)
}

// systemctlInspector asks systemctl, which talks to the service manager over
// D-Bus, for the properties of a unit and reads its files.
type systemctlInspector struct {
	run      func(ctx context.Context, args ...string) ([]byte, error)
	readFile func(string) ([]byte, error)
}

var systemctlPaths = []string{"/usr/bin/systemctl", "/bin/systemctl"}

func execSystemctl(ctx context.Context, args ...string) ([]byte, error) {
	for _, p := range systemctlPaths {
		if _, err := os.Stat(p); err == nil {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, p, args...).Output() //nolint:gosec // fixed binary; the unit name was validated by brokerapi
		}
	}
	return nil, errors.New("systemctl was not found")
}

func (s systemctlInspector) Inspect(ctx context.Context, scope string, owner uint32, unit string) (UnitInfo, error) {
	run, read := s.run, s.readFile
	if run == nil {
		run = execSystemctl
	}
	if read == nil {
		read = os.ReadFile
	}
	args := []string{"show", "--no-pager", "-p", "Transient,FragmentPath,DropInPaths,ExecStart", "--", unit}
	if scope == "user" {
		args = append([]string{"--user", fmt.Sprintf("--machine=%d@.host", owner)}, args...)
	}
	out, err := run(ctx, args...)
	if err != nil {
		return UnitInfo{}, fmt.Errorf("the service manager did not describe %s: %w", unit, err)
	}
	var info UnitInfo
	seen := false
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "Transient":
			info.Transient, seen = v == "yes", true
		case "FragmentPath":
			info.FragmentPath = v
		case "DropInPaths":
			info.DropIns = strings.Fields(v)
		case "ExecStart":
			info.ExecStart = v
		}
	}
	if !seen {
		return UnitInfo{}, fmt.Errorf("the service manager reported no Transient property for %s", unit)
	}
	h := sha256.New()
	for _, p := range append([]string{info.FragmentPath}, info.DropIns...) {
		if p == "" {
			continue
		}
		body, err := read(p)
		if err != nil {
			return UnitInfo{}, fmt.Errorf("read %s: %w", p, err)
		}
		fmt.Fprintf(h, "%d:%s%d:", len(p), p, len(body))
		h.Write(body)
	}
	info.SHA256 = hex.EncodeToString(h.Sum(nil))
	return info, nil
}

// unitRecord is what was true of one unit when it was enrolled.
type unitRecord struct {
	Unit      string `json:"unit"`
	SHA256    string `json:"sha256"`
	ExecStart string `json:"exec_start"`
}

// Enrollment lets a set of units receive one connection. CapHash is the keyed
// hash of the capability sealed into the units' credential file; the capability
// itself is never stored.
type Enrollment struct {
	Connection     string       `json:"connection"`
	Scope          string       `json:"scope"`
	Owner          uint32       `json:"owner"`
	AllowTransient bool         `json:"allow_transient"`
	CapHash        string       `json:"cap_hash"`
	Units          []unitRecord `json:"units"`
	Enrolled       time.Time    `json:"enrolled"`
}

// serviceStore persists enrollments under the daemon's state root.
type serviceStore struct {
	path string
	key  func() ([]byte, error)

	mu     sync.Mutex
	loaded bool
	m      map[string]Enrollment
}

func newServiceStore(root string, key func() ([]byte, error)) *serviceStore {
	return &serviceStore{path: filepath.Join(root, "services.json"), key: key}
}

func (s *serviceStore) load() error {
	if s.loaded {
		return nil
	}
	s.m = map[string]Enrollment{}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(b, &s.m); err != nil {
			return fmt.Errorf("service enrollments: %w", err)
		}
		// Records written when enrollments were keyed by connection alone.
		for k, e := range s.m {
			if want := enrollmentKey(e.Owner, e.Connection); k != want {
				delete(s.m, k)
				s.m[want] = e
			}
		}
	}
	s.loaded = true
	return nil
}

func (s *serviceStore) save() error {
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

func (s *serviceStore) capHash(capability []byte) (string, error) {
	k, err := s.key()
	if err != nil {
		return "", err
	}
	defer clear(k)
	m := hmac.New(sha256.New, k)
	m.Write(capability)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// enrollmentKey keys an enrollment by its owner as well as its connection, so
// one user's enrollment of a name never replaces or reads another's.
func enrollmentKey(owner uint32, connection string) string {
	return fmt.Sprintf("%d/%s", owner, connection)
}

func (s *serviceStore) get(owner uint32, connection string) (Enrollment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return Enrollment{}, false
	}
	e, ok := s.m[enrollmentKey(owner, connection)]
	return e, ok
}

func (s *serviceStore) put(e Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	s.m[enrollmentKey(e.Owner, e.Connection)] = e
	return s.save()
}

func (s *serviceStore) remove(owner uint32, connection, unit string) (removed []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	key := enrollmentKey(owner, connection)
	e, ok := s.m[key]
	if !ok {
		return nil, nil
	}
	keep := e.Units[:0:0]
	for _, u := range e.Units {
		if unit == "" || u.Unit == unit {
			removed = append(removed, u.Unit)
			continue
		}
		keep = append(keep, u)
	}
	if len(keep) == 0 {
		delete(s.m, key)
	} else {
		e.Units = keep
		s.m[key] = e
	}
	return removed, s.save()
}

// named returns every enrollment of a connection name, whoever owns it.
func (s *serviceStore) named(connection string) []Enrollment {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return nil
	}
	var out []Enrollment
	for _, e := range s.m {
		if e.Connection == connection {
			out = append(out, e)
		}
	}
	return out
}

func (s *serviceStore) ownedBy(uid uint32) []Enrollment {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return nil
	}
	var out []Enrollment
	for _, e := range s.m {
		if e.Owner == uid {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b Enrollment) int { return strings.Compare(a.Connection, b.Connection) })
	return out
}

func (s *Server) units() UnitInspector {
	if s.cfg.Units != nil {
		return s.cfg.Units
	}
	return systemctlInspector{}
}

func (s *Server) services() *serviceStore {
	s.svcOnce.Do(func() {
		s.svc = newServiceStore(s.cfg.StateRoot, func() ([]byte, error) { return s.cfg.Keys.ServiceKeyFor("") })
	})
	return s.svc
}

// enrollService records the units that may receive a connection and returns
// the capability to seal into their credential file. The capability is not a
// secret value: it proves nothing outside the enrolled units.
func (a *admin) enrollService(ctx context.Context, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	sr := req.Service
	if sr.Scope == "user" && a.p.uid == 0 {
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, errors.New("a user scope needs a user account"))
	}
	if !a.connectionExists(ctx, sr.Connection) {
		return fail(brokerapi.CodeNotFound, exitcode.Missing, fmt.Errorf("the connection %q has no stored value", sr.Connection))
	}
	records := make([]unitRecord, 0, len(sr.Units))
	for _, u := range sr.Units {
		info, err := a.s.units().Inspect(ctx, sr.Scope, a.p.uid, u)
		if err != nil {
			return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
		}
		if info.Transient && !sr.AllowTransient {
			return fail(brokerapi.CodeBadRequest, exitcode.UserError, fmt.Errorf("%s is a transient unit; enroll it with --allow-transient or use a unit file", u))
		}
		if !info.Transient && info.FragmentPath == "" {
			return fail(brokerapi.CodeBadRequest, exitcode.UserError, fmt.Errorf("%s has no unit file", u))
		}
		records = append(records, unitRecord{Unit: u, SHA256: info.SHA256, ExecStart: info.ExecStart})
	}
	capability := make([]byte, 32)
	if _, err := rand.Read(capability); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	svc := a.s.services()
	hash, err := svc.capHash(capability)
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	now := a.s.cfg.Now().UTC()
	if err := svc.put(Enrollment{Connection: sr.Connection, Scope: sr.Scope, Owner: a.p.uid, AllowTransient: sr.AllowTransient, CapHash: hash, Units: records, Enrolled: now}); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	for _, r := range records {
		if err := a.emit(ctx, audit.ActionServiceEnroll, audit.OutcomeOK, res, map[string]any{
			"connection": sr.Connection, "unit": r.Unit, "scope": sr.Scope, "allow_transient": sr.AllowTransient,
			"presence": req.Digest()[:16], "outcome": "ok",
		}); err != nil {
			return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
		}
	}
	return brokerapi.Response{OK: true, Service: &brokerapi.ServiceResult{Capability: capability, Services: infosOf(svc.mustGet(a.p.uid, sr.Connection), nil)}}
}

func (s *serviceStore) mustGet(owner uint32, connection string) Enrollment {
	e, _ := s.get(owner, connection)
	return e
}

func (a *admin) connectionExists(ctx context.Context, connection string) bool {
	_, err := storeSecrets{a.secretSource()}.credentialPaths(ctx, connection)
	return err == nil
}

func (a *admin) secretSource() secretStore {
	if a.p.syncStore != nil {
		return a.p.syncStore
	}
	return a.p.store
}

func infosOf(e Enrollment, changed map[string]string) []brokerapi.ServiceInfo {
	out := make([]brokerapi.ServiceInfo, 0, len(e.Units))
	for _, u := range e.Units {
		info := brokerapi.ServiceInfo{
			Connection: e.Connection, Unit: u.Unit, Scope: e.Scope, AllowTransient: e.AllowTransient,
			ExecStart: u.ExecStart, UnitSHA256: u.SHA256, Enrolled: e.Enrolled.Format(time.RFC3339),
		}
		if why, bad := changed[u.Unit]; bad {
			info.Changed, info.Detail = true, why
		}
		out = append(out, info)
	}
	return out
}

func (a *admin) revokeService(ctx context.Context, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	sr := req.Service
	_, ok := a.s.services().get(a.p.uid, sr.Connection)
	if !ok {
		return fail(brokerapi.CodeNotFound, exitcode.Missing, fmt.Errorf("no unit is enrolled for %q", sr.Connection))
	}
	removed, err := a.s.services().remove(a.p.uid, sr.Connection, sr.Unit)
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if len(removed) == 0 {
		return fail(brokerapi.CodeNotFound, exitcode.Missing, fmt.Errorf("%s is not enrolled for %q", sr.Unit, sr.Connection))
	}
	for _, u := range removed {
		if err := a.emit(ctx, audit.ActionServiceRevoke, audit.OutcomeOK, res, map[string]any{
			"connection": sr.Connection, "unit": u, "presence": req.Digest()[:16], "outcome": "ok",
		}); err != nil {
			return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
		}
	}
	return brokerapi.Response{OK: true}
}

// listServices reports the caller's enrollments and whether each unit still
// matches what was enrolled. It returns no capability and no value.
func (a *admin) listServices(ctx context.Context) brokerapi.Response {
	var all []brokerapi.ServiceInfo
	for _, e := range a.s.services().ownedBy(a.p.uid) {
		changed := map[string]string{}
		for _, u := range e.Units {
			if why := a.unitDrift(ctx, e, u); why != "" {
				changed[u.Unit] = why
			}
		}
		all = append(all, infosOf(e, changed)...)
	}
	return brokerapi.Response{OK: true, Service: &brokerapi.ServiceResult{Services: all}}
}

// unitDrift says what differs between a unit now and at enrollment, or "".
func (a *admin) unitDrift(ctx context.Context, e Enrollment, u unitRecord) string {
	info, err := a.s.units().Inspect(ctx, e.Scope, e.Owner, u.Unit)
	switch {
	case err != nil:
		return "the unit cannot be inspected: " + err.Error()
	case info.Transient && !e.AllowTransient:
		return "the unit is transient"
	case info.SHA256 != u.SHA256:
		return "the unit file or a drop-in changed"
	case info.ExecStart != u.ExecStart:
		return "ExecStart changed"
	}
	return ""
}
