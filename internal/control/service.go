package control

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runner"
)

// brokerCaller sends one broker request; *Client is one.
type brokerCaller interface {
	Call(brokerapi.Request) (brokerapi.Response, error)
}

// clientReleaser presents a unit's capability to the broker.
type clientReleaser struct{ c brokerCaller }

func (r clientReleaser) Release(_ context.Context, connection string, capability []byte) ([]runner.ServiceEnv, error) {
	resp, err := r.c.Call(brokerapi.Request{Op: brokerapi.OpServiceRelease, Service: &brokerapi.ServiceRequest{Connection: connection, Capability: capability}})
	if err != nil {
		return nil, err
	}
	if !resp.OK || resp.Service == nil {
		if resp.Code == brokerapi.CodeRefused || resp.ExitCode == exitcode.SecurityBlock {
			return nil, fmt.Errorf("%w: %s", runner.ErrReleaseRefused, resp.Error)
		}
		return nil, fmt.Errorf("service: %s", resp.Error)
	}
	out := make([]runner.ServiceEnv, len(resp.Service.Env))
	for i, e := range resp.Service.Env {
		out[i] = runner.ServiceEnv{Name: e.Name, Value: e.Value}
	}
	return out, nil
}

// runService runs a command inside an enrolled systemd unit with the
// connection the broker releases to it.
func runService(ctx context.Context, c *Client, lookup llmcontext.Lookup, ra runArgs, streams IO) int {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code, err := runner.RunService(ctx, runner.ServiceRun{
		Connection: ra.connection, Command: ra.command,
		CredentialsDir: lookup("CREDENTIALS_DIRECTORY"),
		Releaser:       clientReleaser{c},
		Env:            os.Environ(),
		Stdin:          streams.In, Stdout: streams.Out, Stderr: streams.ErrOut,
	})
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch run: %v\n", err)
	}
	return code
}
