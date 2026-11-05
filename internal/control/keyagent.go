package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/exitcode"
	"golang.org/x/crypto/ssh/agent"
)

type keyAgentConn struct {
	Conn
	reader *bufio.Reader
	stop   func() bool
}

func (c *keyAgentConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *keyAgentConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.Conn.Close()
}

func validKeyAgent(protocol string) bool { return protocol == "ssh" || protocol == "gpg" }

func (s *Server) keyAgent(ctx context.Context, conn Conn, reader *bufio.Reader, res callerkind.Result, peer Peer, protocol string) {
	kind := res.Kind
	if !validKeyAgent(protocol) || s.cfg.Keys == nil {
		_ = writeFrame(conn, Response{Kind: kind, Code: CodeUnavailable, ExitCode: exitcode.BackendUnavailable, Error: "key agent protocol is unavailable"})
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := writeFrame(conn, Response{OK: true, Kind: kind}); err != nil {
		return
	}
	stream := &keyAgentConn{Conn: conn, reader: reader}
	caller := callerOf(kind)
	// A relay can never turn its downstream clients into unconstrained callers.
	caller.Constrained = true
	service := s.cfg.Keys.WithPolicyCheck(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if peer.Verify != nil {
			if err := peer.Verify(); err != nil {
				return err
			}
		}
		if s.cfg.Gate != nil {
			return s.cfg.Gate(ctx, res)
		}
		return nil
	})
	if protocol == "gpg" {
		_ = service.ServeGPGAgent(ctx, stream, caller)
	} else {
		_ = agent.ServeAgent(service.NewSSHAgent(caller), stream)
	}
}

// KeyAgent opens a protocol stream without transferring key material to the client.
func (c *Client) KeyAgent(ctx context.Context, protocol string) (Conn, error) {
	if !validKeyAgent(protocol) {
		return nil, errors.New("key agent protocol must be ssh or gpg")
	}
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	stream := &keyAgentConn{Conn: conn, reader: bufio.NewReader(conn)}
	stream.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	ok := false
	defer func() {
		if !ok {
			_ = stream.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	if err := writeFrame(conn, c.stamp(Request{Op: OpKeyAgent, KeyAgent: protocol})); err != nil {
		return nil, err
	}
	var response Response
	if err := readFrame(stream.reader, &response, maxResponse); err != nil {
		return nil, err
	}
	if !response.OK {
		return nil, fmt.Errorf("key agent refused: %s", response.Error)
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return stream, nil
}
