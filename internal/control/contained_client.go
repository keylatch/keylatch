package control

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/term"

	"github.com/keylatch/keylatch/internal/contained"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// offeredEnv is what the client lets a contained child see of its own
// environment: terminal and locale settings and the names the caller asked for.
func offeredEnv(lookup llmcontext.Lookup, environ, extra []string) []string {
	var out []string
	for _, e := range environ {
		name, _, _ := strings.Cut(e, "=")
		if slices.Contains(passthroughEnv, name) || strings.HasPrefix(name, "LC_") {
			out = append(out, e)
		}
	}
	for _, name := range extra {
		if v := lookup(name); v != "" {
			out = append(out, name+"="+v)
		}
	}
	return out
}

// terminalSize returns the size of f when it is a terminal.
func terminalSize(f *os.File) (*contained.Winsize, bool) {
	if f == nil || !term.IsTerminal(int(f.Fd())) { //nolint:gosec // G115: a descriptor fits in int
		return nil, false
	}
	cols, rows, err := term.GetSize(int(f.Fd())) //nolint:gosec // G115: a descriptor fits in int
	if err != nil || rows <= 0 || cols <= 0 {
		return &contained.Winsize{Rows: 24, Cols: 80}, true
	}
	return &contained.Winsize{Rows: uint16(rows), Cols: uint16(cols)}, true //nolint:gosec // G115: terminal sizes fit in uint16
}

// runContained asks the daemon to run the command in its sandbox and relays
// the run: stdin, resize and signals out, output and the exit status back. The
// client holds no secret; the value goes from the daemon into the sandbox.
func runContained(ctx context.Context, c *Client, lookup llmcontext.Lookup, ra runArgs, streams IO) int {
	cwd, _ := os.Getwd()
	rr := RunRequest{
		Connection: ra.connection, Tier: TierContained, Runtime: containedRuntime, Command: ra.command, CWD: cwd,
		Env: offeredEnv(lookup, os.Environ(), ra.extra),
	}
	stdin, _ := streams.In.(*os.File)
	stdout, _ := streams.Out.(*os.File)
	ws, interactive := terminalSize(stdin)
	if _, outTTY := terminalSize(stdout); interactive && outTTY {
		rr.TTY = ws
	}

	conn, err := c.dial()
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch run: daemon: %v\n", err)
		return exitcode.OperationFailed
	}
	defer func() { _ = conn.Close() }()
	if err := writeFrame(conn, c.stamp(Request{Op: OpContained, Run: &rr})); err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch run: daemon: %v\n", err)
		return exitcode.OperationFailed
	}

	r := bufio.NewReader(conn)
	var wmu sync.Mutex
	send := func(ch Chunk) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = writeFrame(conn, ch)
	}

	var started bool
	for {
		var resp Response
		if err := readFrame(r, &resp, maxFrame); err != nil {
			fmt.Fprintf(streams.ErrOut, "keylatch run: daemon: %v\n", err)
			return exitcode.OperationFailed
		}
		if !started {
			if !resp.More {
				return report(resp, streams)
			}
			if resp.Session == nil {
				// A message before the run starts, such as the approval to wait for.
				_, _ = streams.ErrOut.Write(resp.Stderr)
				continue
			}
			started = true
			restore := func() {}
			if rr.TTY != nil {
				if old, err := term.MakeRaw(int(stdin.Fd())); err == nil { //nolint:gosec // G115: a descriptor fits in int
					restore = func() { _ = term.Restore(int(stdin.Fd()), old) } //nolint:gosec // G115: a descriptor fits in int
				}
			}
			defer restore()
			stop := relayInput(ctx, streams, rr.TTY != nil, stdin, send)
			defer stop()
		}
		if !resp.More {
			_, _ = streams.Out.Write(resp.Stdout)
			_, _ = streams.ErrOut.Write(resp.Stderr)
			if resp.Error != "" {
				fmt.Fprintf(streams.ErrOut, "\r\nkeylatch: %s\r\n", resp.Error)
			}
			if !resp.OK && resp.ExitCode == 0 {
				return exitcode.OperationFailed
			}
			return resp.ExitCode
		}
		_, _ = streams.Out.Write(resp.Stdout)
		_, _ = streams.ErrOut.Write(resp.Stderr)
	}
}

// relayInput forwards stdin, terminal resizes and signals to the daemon until
// the returned function is called.
func relayInput(ctx context.Context, streams IO, tty bool, stdin *os.File, send func(Chunk)) (stop func()) {
	done := make(chan struct{})
	go func() {
		buf := make([]byte, chunkSize)
		for streams.In != nil {
			n, err := streams.In.Read(buf)
			if n > 0 {
				send(Chunk{Data: slices.Clone(buf[:n])})
			}
			if err != nil {
				break
			}
		}
		send(Chunk{EOF: true})
	}()

	sigs := make(chan os.Signal, 4)
	// A terminal in raw mode delivers ^C as input, so only a plain run
	// forwards interrupts as signals.
	notify := []os.Signal{syscall.SIGTERM, syscall.SIGHUP}
	if !tty {
		notify = append(notify, os.Interrupt)
	}
	signal.Notify(sigs, notify...)
	resize := resizeSignals()
	go func() {
		for {
			select {
			case s := <-sigs:
				if sig, ok := s.(syscall.Signal); ok {
					send(Chunk{Signal: int(sig)})
				}
			case <-resize:
				if ws, ok := terminalSize(stdin); ok && tty {
					send(Chunk{Resize: ws})
				}
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() {
		signal.Stop(sigs)
		close(done)
	}
}
