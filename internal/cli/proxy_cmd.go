// Package cli — proxy lifecycle subcommands.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// proxyPIDPath returns the proxy PID file path.
func proxyPIDPath(env llmcontext.Lookup) string {
	return proxyPIDPathFromDir(paths.ConfigDir(env))
}

func proxyPIDPathFromDir(dir string) string {
	return dir + "/proxy.pid"
}

// proxyStatePath returns the proxy state file path (stores port alongside PID).
func proxyStatePath(env llmcontext.Lookup) string {
	return proxyStatePathFromDir(paths.ConfigDir(env))
}

func proxyStatePathFromDir(dir string) string {
	return dir + "/proxy.state"
}

// proxyState is the sidecar state written alongside proxy.pid.
// It stores the port so that `proxy status` and `gateway up --with-proxy`
// can determine whether the running proxy is on the expected port.
type proxyState struct {
	PID  int `json:"pid"`
	Port int `json:"port"`
}

// writeProxyState writes the proxy state file atomically.
func writeProxyState(statePath string, st proxyState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("proxy: marshal state: %w", err)
	}
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("proxy: write state tmp: %w", err)
	}
	if err := os.Rename(tmp, statePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("proxy: rename state file: %w", err)
	}
	return nil
}

// readProxyState reads the proxy state file. Returns zero-value and nil if the file
// does not exist.
func readProxyState(statePath string) (proxyState, error) {
	data, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return proxyState{}, nil
		}
		return proxyState{}, fmt.Errorf("proxy: read state %q: %w", statePath, err)
	}
	var st proxyState
	if err := json.Unmarshal(data, &st); err != nil {
		return proxyState{}, fmt.Errorf("proxy: parse state %q: %w", statePath, err)
	}
	return st, nil
}

// removeProxyState removes the proxy state file, ignoring not-found errors.
func removeProxyState(statePath string) error {
	err := os.Remove(statePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("proxy: remove state %q: %w", statePath, err)
	}
	return nil
}

// proxyLiveness reports whether the proxy daemon is running, based on ~/.keylatch/proxy.pid.
func proxyLiveness(env llmcontext.Lookup) (running bool, pid int, err error) {
	pidPath := proxyPIDPath(env)
	p, running := gateway.IsRunning(pidPath)
	return running, p, nil
}

// newProxyCmdFull returns the fully-implemented `proxy` subcommand.
func newProxyCmdFull() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Manage the keylatch CONNECT proxy",
		Long: `Manage the keylatch HTTP CONNECT interception proxy.

The proxy intercepts HTTPS CONNECT tunnels and injects credentials into
outbound provider API calls. It requires local CA trust installation.

Use 'keylatch proxy up' to start, 'keylatch proxy down' to stop,
and 'keylatch proxy status' to check the proxy state.

Note: 'keylatch gateway down' does NOT auto-stop the proxy; proxy and gateway
have independent lifecycles. Stop the proxy explicitly with 'keylatch proxy down'.`,
	}
	cmd.AddCommand(newProxyUpCmd())
	cmd.AddCommand(newProxyDownCmd())
	cmd.AddCommand(newProxyStatusCmd())
	return cmd
}

// newProxyUpCmd returns the `proxy up` subcommand.
func newProxyUpCmd() *cobra.Command {
	var (
		port   int
		detach bool
	)
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Start the CONNECT proxy listener",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			pidPath := proxyPIDPath(env)
			statePath := proxyStatePath(env)

			// W4: single read-then-decide — avoids double ReadPID and silent error.
			storedPID, err := gateway.ReadPID(pidPath)
			if err != nil {
				return fmt.Errorf("proxy up: read PID: %w", err)
			}
			if storedPID != 0 {
				if _, running := gateway.IsRunning(pidPath); running {
					return NewUsageError("proxy is already running (pid: %d) — use `keylatch proxy down` to stop it", storedPID)
				}
				// Stale PID file — process is dead.
				fmt.Fprintln(c.OutOrStdout(), "proxy: removing stale PID file")
				_ = gateway.RemovePID(pidPath)
				_ = removeProxyState(statePath)
			}

			if detach {
				// Detach: relaunch without --detach.
				childArgs := []string{"proxy", "up", fmt.Sprintf("--port=%d", port)}
				if err := startDetached(childArgs, pidPath); err != nil {
					return err
				}
				// Poll for PID file.
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					if data, err := os.ReadFile(pidPath); err == nil {
						fmt.Fprintf(c.OutOrStdout(), "proxy: started in background (pid: %s)\n", string(data))
						return nil
					}
					time.Sleep(50 * time.Millisecond)
				}
				fmt.Fprintln(c.OutOrStdout(), "proxy: started in background")
				return nil
			}

			// Foreground: start listener.
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("proxy up: listen %s: %w", addr, err)
			}
			defer ln.Close() //nolint:errcheck

			// Write PID file and state file (C3: store port alongside PID).
			if err := gateway.WritePID(pidPath, os.Getpid()); err != nil {
				return fmt.Errorf("proxy up: write PID: %w", err)
			}
			if err := writeProxyState(statePath, proxyState{PID: os.Getpid(), Port: port}); err != nil {
				_ = gateway.RemovePID(pidPath)
				return fmt.Errorf("proxy up: write state: %w", err)
			}
			defer func() {
				_ = gateway.RemovePID(pidPath)
				_ = removeProxyState(statePath)
			}()

			// Emit audit event.
			if em := audit.EmitterFromCtx(c.Context()); em != nil {
				_ = em.Emit(c.Context(), audit.Event{
					Action:  "proxy.started",
					Outcome: audit.OutcomeOK,
					Extra: map[string]any{
						"port": port,
						"pid":  os.Getpid(),
					},
				})
			}

			fmt.Fprintf(c.OutOrStdout(), "proxy: listening on %s\n", addr)
			fmt.Fprintln(c.OutOrStdout(), "proxy: press Ctrl+C to stop")

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer cancel()

			// Accept connections until context cancelled.
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						select {
						case <-ctx.Done():
							return
						default:
							fmt.Fprintf(c.ErrOrStderr(), "proxy: accept error: %v\n", err)
						}
						return
					}
					// Close immediately — full proxy logic is out of scope here.
					conn.Close() //nolint:errcheck
				}
			}()

			<-ctx.Done()
			fmt.Fprintln(c.OutOrStdout(), "proxy: shutting down")
			return nil
		},
	}
	cmd.Flags().IntVar(&port, "port", 8888, "port for the CONNECT proxy listener")
	cmd.Flags().BoolVar(&detach, "detach", false, "run proxy as a background process")
	return cmd
}

// newProxyDownCmd returns the `proxy down` subcommand.
func newProxyDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Stop the running CONNECT proxy",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			pidPath := proxyPIDPath(env)
			statePath := proxyStatePath(env)

			storedPID, err := gateway.ReadPID(pidPath)
			if err != nil {
				return fmt.Errorf("proxy down: read PID: %w", err)
			}
			if storedPID == 0 {
				fmt.Fprintln(c.OutOrStdout(), "Proxy is not running.")
				return nil
			}

			// Check liveness.
			_, running := gateway.IsRunning(pidPath)
			if !running {
				// C1: emit audit event for already-dead stale PID path.
				if em := audit.EmitterFromCtx(c.Context()); em != nil {
					_ = em.Emit(c.Context(), audit.Event{
						Action:  "proxy.stopped",
						Outcome: audit.OutcomeOK,
						Extra: map[string]any{
							"pid":    storedPID,
							"reason": "already-dead",
						},
					})
				}
				fmt.Fprintln(c.OutOrStdout(), "Cleaned up stale PID file.")
				_ = removeProxyState(statePath)
				return gateway.RemovePID(pidPath)
			}

			proc, err := os.FindProcess(storedPID)
			if err != nil {
				_ = gateway.RemovePID(pidPath)
				return nil
			}

			// Send SIGTERM.
			reason := "sigterm"
			if err := proc.Signal(syscall.SIGTERM); err != nil {
				_ = gateway.RemovePID(pidPath)
				return nil
			}

			// Wait up to 5 s for graceful exit.
			done := make(chan struct{})
			go func() {
				proc.Wait() //nolint:errcheck
				close(done)
			}()

			select {
			case <-done:
				// Graceful exit.
			case <-time.After(5 * time.Second):
				// Force kill.
				reason = "sigkill"
				_ = proc.Signal(syscall.SIGKILL)
			}

			_ = gateway.RemovePID(pidPath)
			_ = removeProxyState(statePath)

			// Emit audit event.
			if em := audit.EmitterFromCtx(c.Context()); em != nil {
				_ = em.Emit(c.Context(), audit.Event{
					Action:  "proxy.stopped",
					Outcome: audit.OutcomeOK,
					Extra: map[string]any{
						"pid":    storedPID,
						"reason": reason,
					},
				})
			}

			fmt.Fprintf(c.OutOrStdout(), "proxy: stopped (pid: %d, reason: %s)\n", storedPID, reason)
			return nil
		},
	}
}

// proxyStatusOutput is the JSON shape for `proxy status --json`.
type proxyStatusOutput struct {
	Running       bool   `json:"running"`
	PID           *int   `json:"pid"`
	Address       string `json:"address,omitempty"`
	UptimeSeconds *int64 `json:"uptimeSeconds"`
}

// newProxyStatusCmd returns the `proxy status` subcommand.
func newProxyStatusCmd() *cobra.Command {
	var useJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show proxy running state",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			pidPath := proxyPIDPath(env)
			statePath := proxyStatePath(env)

			pid, running := gateway.IsRunning(pidPath)

			var uptimeSeconds *int64
			if running {
				info, err := os.Stat(pidPath)
				if err == nil {
					secs := int64(time.Since(info.ModTime()).Seconds())
					uptimeSeconds = &secs
				}
			}

			var pidPtr *int
			if running {
				pidPtr = &pid
			}

			// C3: read port from state file; fall back to default 8888.
			port := 8888
			if st, err := readProxyState(statePath); err == nil && st.Port != 0 {
				port = st.Port
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)

			out := proxyStatusOutput{
				Running:       running,
				PID:           pidPtr,
				UptimeSeconds: uptimeSeconds,
			}
			if running {
				out.Address = addr
			}

			if useJSON {
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			state := "stopped"
			if running {
				state = "running"
			}
			pidStr := "n/a"
			if pidPtr != nil {
				pidStr = fmt.Sprintf("%d", *pidPtr)
			}
			fmt.Fprintf(c.OutOrStdout(), "proxy: %s (pid: %s)\n", state, pidStr)
			if running && uptimeSeconds != nil {
				fmt.Fprintf(c.OutOrStdout(), "proxy: address: %s, uptime: %ds\n", addr, *uptimeSeconds)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON")
	return cmd
}

// startProxyWithGateway starts the proxy alongside the gateway.
// Used by `gateway up --with-proxy`.
//
// It returns a done channel that is closed once the cleanup goroutine has
// finished closing the listener and removing the PID file. Callers that need
// to wait for a clean shutdown (e.g. tests) should receive on the done channel
// after cancelling ctx.
func startProxyWithGateway(ctx context.Context, port int, pidPath string) (<-chan struct{}, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proxy (--with-proxy): listen %s: %w", addr, err)
	}

	if err := gateway.WritePID(pidPath, os.Getpid()); err != nil {
		ln.Close() //nolint:errcheck
		return nil, fmt.Errorf("proxy (--with-proxy): write PID: %w", err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Cleanup goroutine: close listener and remove PID file when ctx is done.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		ln.Close()                 //nolint:errcheck
		gateway.RemovePID(pidPath) //nolint:errcheck
	}()

	// Accept goroutine: accept and immediately close connections (stub).
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close() //nolint:errcheck
		}
	}()

	// Signal done once cleanup completes.
	go func() {
		wg.Wait()
		close(done)
	}()

	return done, nil
}
