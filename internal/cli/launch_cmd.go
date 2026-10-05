package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

const ticketKeySize = 32

func init() {
	llmcontext.SetTicketVerifier(verifySessionTicket)
}

func newLaunchCmd() *cobra.Command {
	var harnessID string
	cmd := &cobra.Command{
		Use:   "launch [--harness <name>] -- <command> [args...]",
		Short: "Start an agent harness with a session ticket that marks it as an agent",
		Long: `Start an agent harness from your own terminal. The harness and every
process it starts carry a signed session ticket, so Keylatch treats them as
an agent session even when their environment is cleared. The ticket is
bound to this launcher process and is valid for 12 hours.

launch refuses to run inside an agent session or without an interactive
terminal.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup
			if cl := llmcontext.Classify(env); cl.Detected() {
				return NewSecurityBlock("launch: refusing to run inside an agent session (signals: %s)", strings.Join(cl.Signals, ", "))
			}
			if err := requireInteractiveTerminal("launch", "KL-4120"); err != nil {
				return err
			}
			id, err := resolveLaunchHarness(harnessID, args[0])
			if err != nil {
				return err
			}
			raw, err := issueLaunchTicket(env, id)
			if err != nil {
				return NewInternalError("launch: %v", err)
			}

			ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			child := exec.CommandContext(ctx, args[0], args[1:]...)
			child.Env = launchEnvironment(os.Environ(), raw)
			child.Stdin = c.InOrStdin()
			child.Stdout = c.OutOrStdout()
			child.Stderr = c.ErrOrStderr()
			return launchCommandError(superviseLaunch(child))
		},
	}
	cmd.Flags().StringVar(&harnessID, "harness", "", "harness ID (claude-code, codex, cursor, gemini-cli, opencode, aider, copilot-cli); inferred from the command name when omitted")
	return cmd
}

func resolveLaunchHarness(flag, command string) (string, error) {
	if flag != "" {
		d, ok := harness.Lookup(flag)
		if !ok {
			return "", NewUsageError("launch: unknown harness %q", flag)
		}
		return d.ID, nil
	}
	d, ok := harness.ByExecutable(command)
	if !ok {
		return "", NewUsageError("launch: cannot tell which harness %q is; pass --harness", filepath.Base(command))
	}
	return d.ID, nil
}

func issueLaunchTicket(env llmcontext.Lookup, harnessID string) (string, error) {
	key, err := loadOrCreateTicketKey(paths.SessionTicketKey(env))
	if err != nil {
		return "", err
	}
	defer clear(key)
	self, err := llmcontext.CurrentProcess()
	if err != nil {
		return "", fmt.Errorf("identify launcher process: %w", err)
	}
	sid := make([]byte, 16)
	if _, err := rand.Read(sid); err != nil {
		return "", err
	}
	return llmcontext.IssueTicket(llmcontext.Ticket{
		SessionID:    hex.EncodeToString(sid),
		Harness:      harnessID,
		PID:          self.PID,
		ProcessStart: self.Start,
	}, key)
}

// launchEnvironment passes the caller's environment through, replacing any
// inherited ticket with the new one.
func launchEnvironment(base []string, ticket string) []string {
	out := make([]string, 0, len(base)+1)
	for _, entry := range base {
		if name, _, _ := strings.Cut(entry, "="); name == llmcontext.TicketEnv {
			continue
		}
		out = append(out, entry)
	}
	return append(out, llmcontext.TicketEnv+"="+ticket)
}

// loadOrCreateTicketKey reads the ticket signing key, creating it with
// owner-only permissions on first use.
func loadOrCreateTicketKey(path string) ([]byte, error) {
	key, err := readTicketKey(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key = make([]byte, ticketKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return readTicketKey(path)
	}
	if err != nil {
		return nil, err
	}
	_, writeErr := f.Write(key)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("write session ticket key: %w", writeErr)
	}
	return key, nil
}

func readTicketKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != ticketKeySize {
		return nil, errors.New("session ticket key is corrupt")
	}
	return key, nil
}

func verifySessionTicket(env llmcontext.Lookup, raw string) (llmcontext.Ticket, error) {
	key, err := readTicketKey(paths.SessionTicketKey(env))
	if err != nil {
		return llmcontext.Ticket{}, fmt.Errorf("read session ticket key: %w", err)
	}
	defer clear(key)
	return llmcontext.VerifyTicket(raw, key)
}

// superviseLaunch runs the harness with the terminal in the foreground, and
// on exit stops every process it left running and takes the terminal back.
func superviseLaunch(child *exec.Cmd) (result error) {
	stop, err := startLaunchProcess(child)
	if err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	defer func() {
		if err := stop(); err != nil {
			result = errors.Join(result, fmt.Errorf("stop agent processes: %w", err))
		}
		if err := restoreLaunchTerminal(child); err != nil {
			result = errors.Join(result, fmt.Errorf("restore terminal: %w", err))
		}
	}()
	return child.Wait()
}

// launchCommandError passes the harness's exit status through; main prints
// nothing for it unless supervision itself also failed.
func launchCommandError(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		_, joined := err.(interface{ Unwrap() []error })
		return &CLIError{Class: "AgentExit", Code: launchExitCode(exitErr), Message: err.Error(), Quiet: !joined}
	}
	return NewInternalError("launch: %v", err)
}
