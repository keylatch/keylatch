//go:build !windows

package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/callerkind"
)

var execStoreCanary = "canary" + "-exec-store-" + "0e9a"

type execSource struct{}

func (execSource) Get(_ context.Context, p string) ([]byte, backend.Meta, error) {
	if p != "default/ai/demo/api_key" {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return []byte(execStoreCanary), backend.Meta{Path: p}, nil
}

func (execSource) List(context.Context, string) ([]backend.Entry, error) { return nil, nil }

// A verb the daemon runs reads the store over the descriptor it inherits and
// learns where it is from the environment, not from the caller.
const storeScript = `#!/bin/sh
echo "fd:$KEYLATCH_BROKER_STORE_FD"
printf '{"op":"get","path":"default/ai/demo/api_key"}\n' >&3
read -r reply <&3
echo "reply:$reply"
`

func socketPair(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c.(*net.UnixConn)
		t.Cleanup(func() { _ = c.Close() })
	}
	return conns[0], conns[1]
}

// runExec sends one exec request through a socket pair, so no listening socket
// is needed, and returns the verb's stdout and the closing frame.
func runExec(t *testing.T, cfg Config, kind Kind, verb string) (string, Response) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keylatch")
	if err := os.WriteFile(bin, []byte(storeScript), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.Binary = bin
	cfg.Env = lookupOf(nil)
	srv, cli := socketPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewServer(cfg).exec(context.Background(), srv, bufio.NewReader(srv), callerkind.Result{Kind: kind}, Request{Op: OpExec, Verb: verb})
	}()
	var out bytes.Buffer
	r := bufio.NewReader(cli)
	for {
		var resp Response
		if err := readFrame(r, &resp, maxFrame); err != nil {
			t.Fatal(err)
		}
		if !resp.More {
			<-done
			return out.String(), resp
		}
		out.Write(resp.Stdout)
	}
}

func TestDaemonVerbReadsTheStoreThroughItsDescriptor(t *testing.T) {
	out, resp := runExec(t, Config{ChildStore: execSource{}}, KindHuman, "call")
	if !resp.OK {
		t.Fatalf("resp = %+v", resp)
	}
	for _, want := range []string{"fd:3", base64.StdEncoding.EncodeToString([]byte(execStoreCanary))} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

func TestMintIsServedWhenTheDaemonHoldsTheStore(t *testing.T) {
	out, resp := runExec(t, Config{ChildStore: execSource{}}, KindHuman, "mint")
	if !resp.OK || !strings.Contains(out, "fd:3") {
		t.Fatalf("human mint: %+v %q", resp, out)
	}
	out, resp = runExec(t, Config{ChildStore: execSource{}}, KindAgent, "mint")
	if resp.OK || resp.ExitCode != 2 || strings.Contains(out, execStoreCanary) {
		t.Fatalf("agent mint: %+v %q", resp, out)
	}
}

func TestMintRunsLocallyWithoutADaemonStore(t *testing.T) {
	out, resp := runExec(t, Config{}, KindHuman, "mint")
	if resp.Code != CodeRunLocally || out != "" {
		t.Fatalf("mint without a store: %+v %q", resp, out)
	}
}
