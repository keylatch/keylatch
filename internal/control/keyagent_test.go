//go:build unix

package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/keyops"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestKeyAgentCLIStartsProtocolSocket(t *testing.T) {
	d := startKeyDaemon(t, nil, memoryKeys{})
	socket := filepath.Join(filepath.Dir(d.socket), "cli-agent.sock")
	ctx, cancel := context.WithCancel(t.Context())
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		code, handled := Handle(ctx, lookupOf(d.env), []string{"key", "agent", "--protocol", "gpg", "--socket", socket}, IO{Out: io.Discard, ErrOut: &stderr})
		if !handled {
			code = -1
		}
		done <- code
	}()
	defer func() {
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Errorf("CLI exit %d: %s", code, stderr.String())
			}
		case <-time.After(5 * time.Second):
			t.Error("CLI relay did not stop")
		}
	}()
	var conn net.Conn
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, err = net.Dial("unix", socket)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.HasPrefix(line, "OK ") {
		t.Fatalf("protocol greeting: %q, %v", line, err)
	}
}

func TestKeyAgentRelaySignsAndClosesIdleClients(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := startKeyDaemon(t, []keyops.Change{{Connection: "signing", Field: "key", Secret: "ed", SSHAgent: true}}, memoryKeys{"ed": pemOf(t, private)})
	client, err := NewClient(lookupOf(d.env))
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"ssh", "gpg"} {
		t.Run(protocol, func(t *testing.T) {
			ln, err := Listen(filepath.Join(filepath.Dir(d.socket), protocol+"-relay.sock"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- client.RelayKeyAgent(ctx, ln, protocol) }()
			conn, err := net.Dial("unix", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if protocol == "ssh" {
				key, err := ssh.NewPublicKey(public)
				if err != nil {
					t.Fatal(err)
				}
				sig, err := agent.NewClient(conn).Sign(key, []byte("through broker-compatible relay"))
				if err != nil {
					t.Fatal(err)
				}
				if err := key.Verify([]byte("through broker-compatible relay"), sig); err != nil {
					t.Fatal(err)
				}
			} else {
				reader := bufio.NewReader(conn)
				if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "OK ") {
					t.Fatalf("greeting: %q, %v", line, err)
				}
				_, _ = fmt.Fprintln(conn, "GETINFO version")
				if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "D ") {
					t.Fatalf("version: %q, %v", line, err)
				}
				if line, err := reader.ReadString('\n'); err != nil || line != "OK\n" {
					t.Fatalf("result: %q, %v", line, err)
				}
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("idle relay blocked shutdown")
			}
			if _, err := os.Stat(ln.Addr().String()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("socket remains after shutdown: %v", err)
			}
		})
	}
	requireAbsent(t, "audit", d.audit.dump(), pemOf(t, private))
}

func TestKeyAgentStreamHonorsPolicyGate(t *testing.T) {
	d := startKeyDaemonWith(t, nil, memoryKeys{}, func(cfg *Config) {
		cfg.Gate = func(context.Context, callerkind.Result) error { return errors.New("policy integrity failed") }
	})
	client, err := NewClient(lookupOf(d.env))
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"gpg", "ssh"} {
		if conn, err := client.KeyAgent(t.Context(), protocol); err == nil {
			_ = conn.Close()
			t.Fatal("key-agent stream bypassed policy gate")
		}
	}
}
