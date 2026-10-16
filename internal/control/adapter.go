package control

import (
	"context"
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/adapter"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/runner"
)

// adapterRuntime is the runtime name reported for tier D4.
const adapterRuntime = "adapter"

// adapterSession opens a protocol adapter session: the child gets a loopback
// address and a session token, and the daemon authenticates to the database.
func (s *Server) adapterSession(ctx context.Context, kind Kind, rr *RunRequest) Response {
	resp := Response{Kind: kind, Code: CodeBadRequest, ExitCode: exitcode.UserError}
	if s.cfg.Adapters == nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.RuntimeNotAvailable
		resp.Error = "tier D4 is not available: the daemon has no credential store or audit log for protocol adapters"
		return resp
	}
	if rr.Runtime != "" && rr.Runtime != adapterRuntime {
		resp.Error = fmt.Sprintf("tier D4 does not take the %s runtime", rr.Runtime)
		return resp
	}
	tmpl, err := s.template(ctx, rr.Connection)
	if err != nil {
		resp.Code, resp.ExitCode = CodeNotFound, exitcode.Missing
		resp.Error = fmt.Sprintf("unknown connection %q", rr.Connection)
		return resp
	}
	sess, err := s.cfg.Adapters.Open(adapter.OpenRequest{Template: tmpl, Target: rr.Target, User: rr.DBUser, Database: rr.Database})
	switch {
	case errors.Is(err, adapter.ErrNotAdapter):
		resp.Error = fmt.Sprintf("connection %q declares no protocol adapter, so tier D4 cannot serve it", rr.Connection)
		return resp
	case errors.Is(err, adapter.ErrTarget):
		resp.Code, resp.ExitCode = CodeRefused, exitcode.PolicyDeny
		resp.Error = fmt.Sprintf("connection %q: %v; name the database with --target host:port", rr.Connection, err)
		return resp
	case err != nil:
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
		resp.Error = fmt.Sprintf("could not open an adapter session: %v", err)
		return resp
	}
	return Response{OK: true, Kind: kind, Session: &Session{
		Tier:    TierAdapter,
		Runtime: adapterRuntime,
		Env:     runner.PostgresAdapterEnv(tmpl, sess.User(), rr.Database, sess.Token()),
		ProxyID: sess.ID(),
	}}
}
