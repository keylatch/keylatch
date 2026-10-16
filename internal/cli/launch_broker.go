package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// systemdRunPaths are fixed: PATH belongs to the caller, and a planted
// systemd-run would start the harness outside the scope the daemon watches.
var systemdRunPaths = []string{"/usr/bin/systemd-run", "/bin/systemd-run"}

// agentScopePath is where the user's systemd manager places the transient scope
// keylatch-agent-<id>.scope. Tests replace it.
var agentScopePath = func(uid int, id string) string {
	return fmt.Sprintf("/user.slice/user-%d.slice/user@%d.service/app.slice/keylatch-agent-%s.scope", uid, uid, id)
}

// launchThroughBroker registers a new agent session with the daemon, then
// starts the harness in a transient scope of the user's systemd manager. The
// daemon classifies every process in that scope as an agent from its control
// group alone, so clearing the environment does not hide it. The ticket the
// daemon signs rides in the environment as a second signal.
func launchThroughBroker(c *cobra.Command, env llmcontext.Lookup, args []string) error {
	run := ""
	for _, p := range systemdRunPaths {
		if _, err := os.Stat(p); err == nil {
			run = p
			break
		}
	}
	if run == "" {
		return NewUsageError("launch: systemd-run is required to start the harness in a registered scope")
	}
	bc, err := brokerClient(env)
	if err != nil {
		return err
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return NewInternalError("launch: %v", err)
	}
	id := hex.EncodeToString(raw[:])
	scope := agentScopePath(os.Getuid(), id)
	resp, err := bc.Call(brokerapi.Request{Op: brokerapi.OpSessionRegister, Session: &brokerapi.SessionRequest{ID: id, Cgroup: scope}})
	if err != nil {
		return withExitCodeOperation("launch", err)
	}
	if !resp.OK {
		return brokerFailure("launch", resp)
	}
	defer func() {
		_, _ = bc.Call(brokerapi.Request{Op: brokerapi.OpSessionEnd, Session: &brokerapi.SessionRequest{ID: id}})
	}()

	ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	argv := append([]string{"--user", "--scope", "--quiet", "--collect", "--slice=app.slice", "--unit=keylatch-agent-" + id, "--"}, args...)
	child := exec.CommandContext(ctx, run, argv...) //nolint:gosec // G204: fixed binary; the harness is the command the user asked to launch
	child.Env = launchEnvironment(os.Environ(), resp.Session.Ticket)
	child.Stdin = c.InOrStdin()
	child.Stdout = c.OutOrStdout()
	child.Stderr = c.ErrOrStderr()
	return launchCommandError(superviseLaunch(child, func(p *exec.Cmd) error { return confirmScope(p.Process.Pid, scope) }))
}

// confirmScope checks that the started harness sits in the scope that was
// registered. systemd-run --scope replaces itself with the harness once the
// scope exists, so a mismatch means the registration does not cover it.
func confirmScope(pid int, want string) error {
	var got string
	for range 50 {
		dump, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			return fmt.Errorf("launch: read the harness's control group: %w", err)
		}
		if got = brokerd.ParseCgroup(string(dump)); got == want {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("launch: the harness runs in %q, not in its registered scope %q; stopping it", got, want)
}

// verifyBrokerTicket asks the daemon whether raw is a ticket it issued to this
// user, and reports the launcher process the ticket is bound to.
func verifyBrokerTicket(env llmcontext.Lookup, raw string) (llmcontext.Ticket, error) {
	bc, err := brokerClient(env)
	if err != nil {
		return llmcontext.Ticket{}, err
	}
	resp, err := bc.Call(brokerapi.Request{Op: brokerapi.OpSessionVerify, Ticket: raw})
	if err != nil {
		return llmcontext.Ticket{}, err
	}
	if !resp.OK || resp.Session == nil {
		return llmcontext.Ticket{}, errors.Join(llmcontext.ErrTicketInvalid, errors.New(resp.Error))
	}
	return llmcontext.Ticket{PID: resp.Session.PID, ProcessStart: resp.Session.Start}, nil
}
