package control

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/keylatch/keylatch/internal/exitcode"
)

func runKeyAgent(ctx context.Context, client *Client, args []string, streams IO) int {
	flags := flag.NewFlagSet("key agent", flag.ContinueOnError)
	flags.SetOutput(streams.ErrOut)
	protocol := flags.String("protocol", "", "ssh or gpg")
	socket := flags.String("socket", "", "owner-only local agent socket path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !validKeyAgent(*protocol) || *socket == "" {
		fmt.Fprintln(streams.ErrOut, "usage: keylatch key agent --protocol ssh|gpg --socket <path>")
		return exitcode.UserError
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintln(streams.ErrOut, "keylatch: local key-agent sockets require Unix")
		return exitcode.OperationFailed
	}
	ln, err := Listen(*socket)
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch: %v\n", err)
		return exitcode.OperationFailed
	}
	defer func() { _ = ln.Close() }()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fmt.Fprintf(streams.ErrOut, "keylatch: %s agent listening on %s\n", *protocol, *socket)
	if err := client.RelayKeyAgent(ctx, ln, *protocol); err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch: %v\n", err)
		return exitcode.OperationFailed
	}
	return 0
}

// RelayKeyAgent connects owner-only local clients to authenticated daemon streams.
func (c *Client) RelayKeyAgent(ctx context.Context, ln *net.UnixListener, protocol string) error {
	if !validKeyAgent(protocol) {
		return fmt.Errorf("key agent protocol must be ssh or gpg")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			cancelled := ctx.Err() != nil
			cancel()
			if cancelled {
				return nil
			}
			return err
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			defer func() { _ = conn.Close() }()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			peer, err := peerOf(conn)
			if err != nil || peer.UID != uint32(os.Getuid()) { //nolint:gosec // Unix-only listener; UID is nonnegative.
				return
			}
			upstream, err := c.KeyAgent(ctx, protocol)
			if err != nil {
				return
			}
			defer func() { _ = upstream.Close() }()
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(upstream, conn)
				_ = upstream.CloseWrite()
				close(done)
			}()
			_, _ = io.Copy(conn, upstream)
			_ = conn.Close()
			_ = upstream.Close()
			<-done
		}()
	}
}
