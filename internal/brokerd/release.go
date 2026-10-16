package brokerd

import (
	"bufio"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/registry"
	keysync "github.com/keylatch/keylatch/internal/sync"
)

// unitOfCgroup names the service unit a control group path belongs to: the
// innermost .service element, other than the user manager itself. user reports
// a unit of a user manager.
func unitOfCgroup(path string) (unit string, user, ok bool) {
	elems := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(elems) - 1; i >= 0; i-- {
		e := elems[i]
		if !strings.HasSuffix(e, ".service") || strings.HasPrefix(e, "user@") {
			continue
		}
		for _, outer := range elems[:i] {
			if strings.HasPrefix(outer, "user@") {
				user = true
			}
		}
		return e, user, true
	}
	return "", false, false
}

// serviceEnv maps a connection to the environment variables its runtime
// contract names: the injection rules of its provider template, or, for a
// connection with no template, one variable named after the connection.
func (s storeSecrets) serviceEnv(ctx context.Context, connection string) ([]brokerapi.ServiceEnv, error) {
	if tmpl, err := registry.Get(connection); err == nil && len(tmpl.InjectionRules) > 0 {
		out := make([]brokerapi.ServiceEnv, 0, len(tmpl.InjectionRules))
		for _, r := range tmpl.InjectionRules {
			v, _, err := s.st.Get(ctx, connections.SecretFieldPath("default", tmpl.Category, connection, r.Source))
			if err != nil {
				wipe(out)
				return nil, fmt.Errorf("field %q of %q: %w", r.Source, connection, err)
			}
			out = append(out, brokerapi.ServiceEnv{Name: r.EnvVar, Value: v})
		}
		return out, nil
	}
	p, err := s.find(ctx, connection, []string{"", "value", "token", "api_key"})
	if err != nil {
		return nil, err
	}
	v, _, err := s.st.Get(ctx, p)
	if err != nil {
		return nil, err
	}
	return []brokerapi.ServiceEnv{{Name: envName(connection), Value: v}}, nil
}

func wipe(env []brokerapi.ServiceEnv) {
	for i := range env {
		clear(env[i].Value)
	}
}

func envName(connection string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(connection) {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// credentialPaths reports whether a connection has anything stored.
func (s storeSecrets) credentialPaths(ctx context.Context, connection string) ([]brokerapi.ServiceEnv, error) {
	env, err := s.serviceEnv(ctx, connection)
	wipe(env)
	return env, err
}

// denyService records why a release was refused and answers without saying.
// The reason goes to the audit log; the caller may be an agent probing.
func (s *Server) denyService(ctx context.Context, res callerkind.Result, connection, reason string) brokerapi.Response {
	_ = s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionSecurityBlock, Outcome: audit.OutcomeDenied, Extra: map[string]any{
		"command": "service.release " + connection, "signals": []string{reason}, "caller_kind": string(res.Kind),
	}})
	return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, errors.New("the credential cannot be released to this process"))
}

// releaseService hands a connection to a systemd unit that proves it is the
// enrolled unit: the peer's control group names the unit, the capability from
// its credential file matches, and the unit is still what was enrolled. Any
// mismatch is refused and audited as a security block.
func (s *Server) releaseService(ctx context.Context, uid uint32, cgroup string, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	sr := req.Service
	if res.Kind == callerkind.Agent {
		return s.denyService(ctx, res, sr.Connection, "agent caller")
	}
	unit, user, ok := unitOfCgroup(cgroup)
	if !ok {
		return s.denyService(ctx, res, sr.Connection, "the caller is not in a systemd service unit (service credentials need systemd, so macOS and Windows brokers always refuse)")
	}
	e, ok := s.services().get(sr.Connection)
	if !ok {
		return s.denyService(ctx, res, sr.Connection, "no unit is enrolled for the connection")
	}
	hash, err := s.services().capHash(sr.Capability)
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if !hmac.Equal([]byte(hash), []byte(e.CapHash)) {
		return s.denyService(ctx, res, sr.Connection, "the capability does not match")
	}
	var rec *unitRecord
	for i := range e.Units {
		if e.Units[i].Unit == unit {
			rec = &e.Units[i]
		}
	}
	switch {
	case rec == nil:
		return s.denyService(ctx, res, sr.Connection, "the unit "+unit+" is not enrolled")
	case user != (e.Scope == "user") || (user && uid != e.Owner):
		return s.denyService(ctx, res, sr.Connection, "the unit runs in another scope than it was enrolled in")
	}
	a := &admin{s: s}
	if why := a.unitDrift(ctx, e, *rec); why != "" {
		return s.denyService(ctx, res, sr.Connection, unit+": "+why)
	}
	p, err := s.partition(ctx, e.Owner)
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if err := p.policy.Gate(ctx, res); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	src := secretStore(p.store)
	if p.syncStore != nil {
		src = p.syncStore
	}
	env, err := storeSecrets{src}.serviceEnv(ctx, sr.Connection)
	if err != nil {
		if errors.Is(err, backend.ErrNotFound) || errors.Is(err, keysync.ErrNoSecret) {
			return fail(brokerapi.CodeNotFound, exitcode.Missing, errors.New("the connection has no stored value"))
		}
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if err := s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionRelease, Outcome: audit.OutcomeOK, Extra: map[string]any{
		"connection": sr.Connection, "unit": unit, "caller_kind": string(callerkind.Service),
	}}); err != nil {
		wipe(env)
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	return brokerapi.Response{OK: true, Service: &brokerapi.ServiceResult{Env: env}}
}

// serveServiceOnly answers a peer whose account may not use the broker in
// general, as system services' accounts may not. It serves one thing: the
// release of a credential to an enrolled unit.
func (s *Server) serveServiceOnly(ctx context.Context, conn control.Conn, id *Identity) {
	deny := func() {
		refuse(conn, control.CodeRefused, exitcode.SecurityBlock, fmt.Sprintf("user %d may not use the broker", id.UID))
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, 1<<20)).ReadBytes('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		deny()
		return
	}
	req, err := brokerapi.Decode(line)
	if err != nil || req.Op != brokerapi.OpServiceRelease {
		deny()
		return
	}
	if err := id.Verify(); err != nil {
		refuse(conn, control.CodeRefused, exitcode.SecurityBlock, err.Error())
		return
	}
	resp := s.releaseService(ctx, id.UID, id.Cgroup, callerkind.Result{Kind: callerkind.Host}, req)
	b, _ := json.Marshal(resp)
	_, _ = conn.Write(append(b, '\n'))
}
