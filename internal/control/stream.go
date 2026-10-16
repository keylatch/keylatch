package control

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/harness"
)

// frameWriter sends everything written to it as intermediate frames. A slow
// reader blocks the write, which blocks the child, so nothing buffers
// without bound.
type frameWriter struct {
	conn   io.Writer
	mu     *sync.Mutex
	stderr bool
	n      *atomic.Int64
	cancel context.CancelFunc
}

func (w *frameWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), chunkSize)]
		resp := Response{More: true}
		if w.stderr {
			resp.Stderr = chunk
		} else {
			resp.Stdout = chunk
		}
		w.mu.Lock()
		err := writeFrame(w.conn, resp)
		w.mu.Unlock()
		if err != nil {
			w.cancel()
			return written, err
		}
		written += len(chunk)
		w.n.Add(int64(len(chunk)))
		p = p[len(chunk):]
	}
	return written, nil
}

// exec runs a served verb and streams its output. Refusals and the final
// status come back as one closing frame.
func (s *Server) exec(ctx context.Context, conn *net.UnixConn, r *bufio.Reader, res callerkind.Result, req Request) {
	kind := res.Kind
	d := decision{
		op: string(OpExec), verb: req.Verb, res: res, child: childInDaemon,
		argv: slices.Concat(req.Global, []string{req.Verb}, req.Args),
	}
	finish := func(resp Response, outcome audit.Outcome) {
		resp.Kind = kind
		if err := s.record(ctx, d, outcome); err != nil {
			resp = auditRefusal(resp, err)
		}
		_ = writeFrame(conn, resp)
	}
	refuse := func(resp Response) {
		d.reason = resp.Error
		finish(resp, audit.OutcomeDenied)
	}

	switch {
	case slices.Contains(valueVerbs, req.Verb):
		if kind.Constrained() {
			refuse(Response{
				Code: CodeRefused, ExitCode: exitcode.SecurityBlock,
				Error: fmt.Sprintf("%q returns secret values and is not available to %s callers", req.Verb, kind),
			})
			return
		}
		d.child = childInCaller
		finish(Response{Code: CodeRunLocally}, audit.OutcomeOK)
		return
	case !slices.Contains(servedVerbs, req.Verb):
		refuse(Response{Code: CodeBadRequest, ExitCode: exitcode.UserError, Error: fmt.Sprintf("%q is not served by the daemon", req.Verb)})
		return
	case req.Verb == "run" && !slices.Contains(req.Args, "--dry-run"):
		refuse(Response{Code: CodeBadRequest, ExitCode: exitcode.UserError, Error: "run is served as a session request; only --dry-run is executed by the daemon"})
		return
	}
	for _, a := range d.argv {
		if strings.ContainsRune(a, 0) {
			refuse(Response{Code: CodeBadRequest, ExitCode: exitcode.UserError, Error: "argument contains a NUL byte"})
			return
		}
	}

	d.runID = newRunID()
	if err := s.record(ctx, d, audit.OutcomeOK); err != nil {
		_ = writeFrame(conn, auditRefusal(Response{Kind: kind}, err))
		return
	}
	started := time.Now()

	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	var (
		mu    sync.Mutex
		bytes atomic.Int64
	)
	cmd := exec.CommandContext(ctx, s.cfg.Binary, slices.Concat(req.Global, []string{req.Verb}, req.Args)...) //nolint:gosec // G204: the binary is fixed by the daemon and the verb is allowlisted
	cmd.Env = s.childEnv(kind)
	cmd.Stdout = &frameWriter{conn: conn, mu: &mu, n: &bytes, cancel: cancel}
	cmd.Stderr = &frameWriter{conn: conn, mu: &mu, stderr: true, n: &bytes, cancel: cancel}
	stdin, err := cmd.StdinPipe()
	if err == nil {
		err = cmd.Start()
	}

	resp := Response{Kind: kind}
	if err != nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
		resp.Error = fmt.Sprintf("run %s: %v", req.Verb, err)
	} else {
		go forwardStdin(r, stdin)
		err = cmd.Wait()
		resp.OK = err == nil
		var exitErr *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &exitErr):
			resp.ExitCode = exitErr.ExitCode()
		default:
			resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
			resp.Error = fmt.Sprintf("run %s: %v", req.Verb, err)
		}
	}
	mu.Lock()
	_ = writeFrame(conn, resp)
	mu.Unlock()
	s.recordExit(ctx, d.op, req.Verb, d.runID, resp.ExitCode, started, bytes.Load(), "")
}

// forwardStdin copies the client's stdin frames into the child until the
// client ends them or the child's stdin closes.
func forwardStdin(r *bufio.Reader, w io.WriteCloser) {
	defer func() { _ = w.Close() }()
	for {
		var c Chunk
		if err := readFrame(r, &c, maxFrame); err != nil || c.EOF {
			return
		}
		if _, err := w.Write(c.Data); err != nil {
			return
		}
	}
}

// childEnv is the daemon's own environment, never the caller's. A constrained
// caller's verbs run as an agent session so every existing guard applies.
func (s *Server) childEnv(kind Kind) []string {
	env := os.Environ()
	env = append(env, s.cfg.ChildEnv...)
	env = append(env, LocalEnv+"=1")
	if kind.Constrained() {
		env = append(env, harness.ManualLabel+"=1")
	}
	return env
}

// ExecStream asks the daemon to run a served verb, copying its output to
// streams as it arrives and sending streams.In as stdin. The returned
// response is the closing frame: exit status and any refusal.
func (c *Client) ExecStream(global []string, verb string, args []string, streams IO) (Response, error) {
	conn, err := c.dial()
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := writeFrame(conn, c.stamp(Request{Op: OpExec, Global: global, Verb: verb, Args: args})); err != nil {
		return Response{}, err
	}
	go sendStdin(conn, streams.In)

	r := bufio.NewReader(conn)
	for {
		var resp Response
		if err := readFrame(r, &resp, maxFrame); err != nil {
			return Response{}, err
		}
		if !resp.More {
			return resp, nil
		}
		if streams.Out != nil {
			_, _ = streams.Out.Write(resp.Stdout)
		}
		if streams.ErrOut != nil {
			_, _ = streams.ErrOut.Write(resp.Stderr)
		}
	}
}

// Exec runs a served verb with no stdin and returns its collected output.
func (c *Client) Exec(global []string, verb string, args []string) (Response, error) {
	var out, errOut bytes.Buffer
	resp, err := c.ExecStream(global, verb, args, IO{Out: &out, ErrOut: &errOut})
	if err != nil {
		return Response{}, err
	}
	resp.Stdout, resp.Stderr = out.Bytes(), errOut.Bytes()
	return resp, nil
}

// sendStdin forwards in to the daemon in bounded frames and then ends the
// stream. A nil in ends it at once.
func sendStdin(conn net.Conn, in io.Reader) {
	if in != nil {
		buf := make([]byte, chunkSize)
		for {
			n, err := in.Read(buf)
			if n > 0 && writeFrame(conn, Chunk{Data: buf[:n]}) != nil {
				return
			}
			if err != nil {
				break
			}
		}
	}
	_ = writeFrame(conn, Chunk{EOF: true})
}
