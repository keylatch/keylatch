package control

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/presence"
	"golang.org/x/crypto/ssh/agent"
)

func callerOf(kind Kind) keyops.Caller {
	return keyops.Caller{Kind: string(kind), Constrained: kind.Constrained()}
}

func keyErrorResponse(resp Response, err error) Response {
	switch {
	case errors.Is(err, keyops.ErrDenied):
		resp.Code, resp.ExitCode = CodeRefused, exitcode.SecurityBlock
	case errors.Is(err, keyops.ErrNotFound):
		resp.Code, resp.ExitCode = CodeNotFound, exitcode.Missing
	case errors.Is(err, keyops.ErrUnavailable):
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.BackendUnavailable
	}
	resp.Error = err.Error()
	return resp
}

// keyPolicy lists or edits the allowlist. Only a human may add or widen.
func (s *Server) keyPolicyPeer(ctx context.Context, kind Kind, kp *KeyPolicyRequest, peer Peer) Response {
	resp := Response{Kind: kind, Code: CodeBadRequest, ExitCode: exitcode.UserError}
	if kp == nil {
		resp.Error = "a key policy request is required"
		return resp
	}
	if s.cfg.KeyAdmin == nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.BackendUnavailable
		resp.Error = "key operations are not enabled on this daemon"
		return resp
	}
	ch := keyops.Change{
		Connection: kp.Connection, Field: kp.Field, Secret: kp.Secret,
		Operations: kp.Operations, Algorithms: kp.Algorithms, HostKeys: kp.HostKeys,
		AgentDecrypt: kp.AgentDecrypt, SSHAgent: kp.SSHAgent, PresenceDigest: kp.PresenceDigest,
	}
	var err error
	caller := callerOf(kind)
	switch kp.Action {
	case "allow":
		// Broker hosts become authorized only if the peer-specific OS check succeeds.
		if kind == KindHost && s.cfg.KeyPeerPresence != nil {
			caller.Constrained = false
		}
		err = s.cfg.KeyAdmin.AllowVerified(ctx, caller, ch, func(ctx context.Context, summary string) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			var err error
			switch {
			case s.cfg.KeyPeerPresence != nil:
				err = s.cfg.KeyPeerPresence(ctx, peer, presence.ActionKeyAllow, summary)
			case s.cfg.KeyPresence != nil:
				err = s.cfg.KeyPresence.Confirm(ctx, presence.ActionKeyAllow, summary)
			default:
				err = presence.ErrUnavailable
			}
			if err != nil {
				return "", err
			}
			if peer.Verify != nil {
				if err := peer.Verify(); err != nil {
					return "", err
				}
			}
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return presence.Digest(presence.ActionKeyAllow, summary), nil
		})
	case "revoke":
		err = s.cfg.KeyAdmin.Revoke(ctx, caller, ch)
	case "list":
		var out []byte
		if out, err = s.cfg.KeyAdmin.List(caller, kp.Connection); err == nil {
			return Response{OK: true, Kind: kind, Stdout: append(out, '\n')}
		}
	default:
		resp.Error = "unknown key policy action"
		return resp
	}
	if err != nil {
		return keyErrorResponse(resp, err)
	}
	return Response{OK: true, Kind: kind}
}

// key answers a key operation. The reply carries the result only; errors say
// what was refused, never anything about the key.
func (s *Server) key(ctx context.Context, kind Kind, kr *KeyRequest) Response {
	resp := Response{Kind: kind, Code: CodeBadRequest, ExitCode: exitcode.UserError}
	if kr == nil {
		resp.Error = "a key request is required"
		return resp
	}
	if s.cfg.Keys == nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.BackendUnavailable
		resp.Error = "key operations are not enabled on this daemon"
		return resp
	}
	res, err := s.cfg.Keys.Do(ctx, callerOf(kind), keyops.Request{
		Operation:  keyops.Operation(kr.Action),
		Connection: kr.Connection,
		Field:      kr.Field,
		Alg:        kr.Alg,
		Input:      kr.Input,
		Signature:  kr.Signature,
		AAD:        kr.AAD,
		KeyID:      kr.KeyID,
	})
	switch {
	case err != nil:
		return keyErrorResponse(resp, err)
	case kr.Action == string(keyops.OpVerify) && !res.Valid:
		resp.Code, resp.ExitCode, resp.Error = CodeInvalidSignature, exitcode.UserError, "signature does not match"
	default:
		resp = Response{OK: true, Kind: kind, Stdout: res.Output}
	}
	return resp
}

// ServeSSHAgent answers the ssh-agent protocol on ln until ctx is done. The
// endpoint lists public keys and signs; the daemon's user is the only peer
// accepted.
func (s *Server) ServeSSHAgent(ctx context.Context, ln *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveAgentConn(ctx, conn)
		}()
	}
}

func (s *Server) serveAgentConn(ctx context.Context, conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	peer, err := peerOf(conn)
	if err != nil || peer.UID != s.uid || s.cfg.Keys == nil {
		return
	}
	_ = agent.ServeAgent(s.cfg.Keys.NewSSHAgent(callerOf(s.classify(peer, Request{}).Kind)), conn)
}
