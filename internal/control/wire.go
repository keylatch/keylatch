// Package control is the transport between the keylatch thin client and the
// keylatchd control socket. The client holds no key material: it sends a
// request and the daemon, which owns the vault, signing keys and policy,
// decides what the caller may have.
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/keylatch/keylatch/internal/runner"
)

// Kind classifies the process on the other end of the socket.
type Kind string

const (
	// KindHuman is a same-user process in the daemon's own namespaces that
	// shows no agent signal.
	KindHuman Kind = "human"
	// KindAgent is a caller that presented an agent signal.
	KindAgent Kind = "agent"
	// KindHost is a same-user caller outside the daemon's namespaces, such as
	// a process inside a harness sandbox, that presented no agent signal.
	KindHost Kind = "host"
)

// Constrained reports whether the kind may not receive secret values.
func (k Kind) Constrained() bool { return k != KindHuman }

// Op names a socket operation.
type Op string

const (
	// OpExec runs a daemon-served verb and returns its output.
	OpExec Op = "exec"
	// OpRunSession issues a scoped session for a child the client starts.
	OpRunSession Op = "run_session"
	// OpGateway turns the connection into a byte stream to the gateway.
	OpGateway Op = "gateway"
	// OpProxy turns the connection into a client connection of a placeholder
	// session's proxy.
	OpProxy Op = "proxy"
	// OpEndSession revokes a placeholder session.
	OpEndSession Op = "end_session"
)

// Tier names a delivery tier.
type Tier string

const (
	TierAction      Tier = "D1"
	TierGateway     Tier = "D2"
	TierPlaceholder Tier = "D3"
	TierAdapter     Tier = "D4"
	TierContained   Tier = "D5"
	TierRaw         Tier = "D6"
)

// Request is one client message.
type Request struct {
	Op Op `json:"op"`
	// Global holds the flags that precede the verb.
	Global []string `json:"global,omitempty"`
	Verb   string   `json:"verb,omitempty"`
	Args   []string `json:"args,omitempty"`
	// Signals are the agent signals the client saw in its own environment.
	// They can only make the daemon stricter.
	Signals []string `json:"signals,omitempty"`
	// Ticket is the raw session ticket from the client's environment.
	Ticket string `json:"ticket,omitempty"`
	// Proxy names the placeholder session an OpProxy or OpEndSession request
	// addresses.
	Proxy string      `json:"proxy,omitempty"`
	Run   *RunRequest `json:"run,omitempty"`
}

// RunRequest describes a command to run under a connection.
type RunRequest struct {
	Connection string   `json:"connection"`
	Runtime    string   `json:"runtime,omitempty"`
	Tier       Tier     `json:"tier,omitempty"`
	Command    []string `json:"command"`
	CWD        string   `json:"cwd,omitempty"`
	// UpstreamProxy is the proxy the caller's own environment names. A
	// placeholder session sends its upstream traffic through it.
	UpstreamProxy string `json:"upstream_proxy,omitempty"`
}

// Session is what the daemon returns for an accepted run request.
type Session struct {
	Tier       Tier              `json:"tier"`
	Runtime    string            `json:"runtime"`
	Env        runner.SessionEnv `json:"env"`
	TTLSeconds int               `json:"ttl_seconds"`
	// ProxyID, CAPEM and CAVars are set for placeholder sessions: the proxy
	// session to relay to, the session CA certificate, and the variables that
	// must point at a bundle containing it.
	ProxyID string   `json:"proxy_id,omitempty"`
	CAPEM   string   `json:"ca_pem,omitempty"`
	CAVars  []string `json:"ca_vars,omitempty"`
}

// Response is one daemon message.
type Response struct {
	OK       bool     `json:"ok"`
	Kind     Kind     `json:"kind,omitempty"`
	ExitCode int      `json:"exit_code,omitempty"`
	Stdout   []byte   `json:"stdout,omitempty"`
	Stderr   []byte   `json:"stderr,omitempty"`
	Code     string   `json:"code,omitempty"`
	Error    string   `json:"error,omitempty"`
	Session  *Session `json:"session,omitempty"`
}

const maxFrame = 1 << 20

var errFrameTooLarge = errors.New("control: frame too large")

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func readFrame(r *bufio.Reader, v any, limit int) error {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return err
		}
		line = append(line, chunk...)
		if len(line) > limit {
			return errFrameTooLarge
		}
		if !isPrefix {
			break
		}
	}
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("control: malformed frame: %w", err)
	}
	return nil
}
