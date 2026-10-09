//go:build !windows

package gpgcard

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

func trgClearLLMEnv(t *testing.T) {
	t.Helper()
	for _, s := range llmcontext.Signals {
		t.Setenv(s.EnvKey, "")
	}
}

type trgScd struct {
	mu       sync.Mutex
	commands []string
}

func (s *trgScd) record(c string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, c)
}

func (s *trgScd) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func trgShortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "trg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// trgServe starts a fake scdaemon; reply maps a command line to the raw lines to send back.
func trgServe(t *testing.T, greeting string, reply func(cmd string) string) (string, *trgScd) {
	t.Helper()
	sock := filepath.Join(trgShortDir(t), "S.scdaemon")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	scd := &trgScd{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = fmt.Fprint(c, greeting)
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.TrimRight(line, "\n")
					scd.record(cmd)
					_, _ = fmt.Fprint(c, reply(cmd))
				}
			}(conn)
		}
	}()
	return sock, scd
}

func trgOKReply(sig string) func(string) string {
	return func(cmd string) string {
		if cmd == "PKSIGN" {
			return "S PROGRESS 1\n# comment\nX unknown\nD " + sig + "\nOK\n"
		}
		return "OK\n"
	}
}

func TestNewProbesSocketAndSignsViaScdaemon(t *testing.T) {
	trgClearLLMEnv(t)
	sock, scd := trgServe(t, "OK ready\n", trgOKReply("ab%25cd%0A"))

	a, err := New(Options{SocketPath: sock, Keygrip: "AABB"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.ID() != "gpgcard:AABB" || a.Type() != trust.RootGPGCard || a.opts.Label != "gpg-card" {
		t.Fatalf("ID=%q Type=%q Label=%q", a.ID(), a.Type(), a.opts.Label)
	}

	digest := []byte{0x01, 0x02, 0xff}
	sig, pub, err := a.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(sig) != "ab%cd\n" || pub != nil {
		t.Fatalf("sig=%q pub=%v", sig, pub)
	}
	want := []string{"SETKEY AABB", "SIGKEY AABB", "SETHASH --hash=sha256 " + hex.EncodeToString(digest), "PKSIGN"}
	if got := scd.seen(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("commands = %q, want %q", got, want)
	}
}

func TestNewDefaultsKeygripAndLabel(t *testing.T) {
	sock, _ := trgServe(t, "OK\n", trgOKReply("00"))
	a, err := New(Options{SocketPath: sock, Label: "work card"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != "gpgcard:default" || a.keygrip != "default" || a.opts.Label != "work card" {
		t.Fatalf("adapter = %+v", a)
	}
}

func TestNewDeviceAbsent(t *testing.T) {
	_, err := New(Options{SocketPath: filepath.Join(trgShortDir(t), "missing")})
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "scdaemon not reachable") {
		t.Fatalf("err = %v", err)
	}
}

func TestDialRejectsBadGreeting(t *testing.T) {
	sock, _ := trgServe(t, "ERR 1 no card\n", trgOKReply(""))
	_, err := New(Options{SocketPath: sock})
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), `unexpected greeting "ERR 1 no card"`) {
		t.Fatalf("err = %v", err)
	}

	silent := filepath.Join(trgShortDir(t), "S.silent")
	ln, err := net.Listen("unix", silent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	if _, err := assuanDial(silent); err == nil || !strings.Contains(err.Error(), "read greeting") {
		t.Fatalf("closed before greeting: err = %v", err)
	}
}

func TestSignErrorsFromEachProtocolStep(t *testing.T) {
	trgClearLLMEnv(t)
	for _, step := range []string{"SETKEY", "SIGKEY", "SETHASH", "PKSIGN"} {
		t.Run(step, func(t *testing.T) {
			sock, _ := trgServe(t, "OK\n", func(cmd string) string {
				if strings.HasPrefix(cmd, step) {
					return "ERR 100663404 Card error\n"
				}
				return "OK\n"
			})
			a, err := New(Options{SocketPath: sock, Keygrip: "K"})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = a.Sign(context.Background(), []byte{1})
			if err == nil || !strings.Contains(err.Error(), "gpgcard: sign: assuan: "+step+": assuan: error response: ERR 100663404 Card error") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestSignBadDLineAndDroppedConnection(t *testing.T) {
	trgClearLLMEnv(t)
	sock, _ := trgServe(t, "OK\n", func(cmd string) string {
		if cmd == "PKSIGN" {
			return "D %zz\nOK\n"
		}
		return "OK\n"
	})
	a, _ := New(Options{SocketPath: sock})
	if _, _, err := a.Sign(context.Background(), []byte{1}); err == nil || !strings.Contains(err.Error(), "decode D-line") {
		t.Fatalf("bad D-line: err = %v", err)
	}

	conn, err := assuanDial(sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.UnixConn).CloseRead()
	if _, err := assuanSend(conn, "SETKEY x"); err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("read after shutdown: err = %v", err)
	}
	_ = conn.Close()
	if _, err := assuanSend(conn, "SETKEY x"); err == nil || !strings.Contains(err.Error(), `send "SETKEY x"`) {
		t.Fatalf("send on closed conn: err = %v", err)
	}
}

func TestSignDeviceRemovedAfterNew(t *testing.T) {
	trgClearLLMEnv(t)
	sock, _ := trgServe(t, "OK\n", trgOKReply("00"))
	a, err := New(Options{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	a.opts.SocketPath = filepath.Join(trgShortDir(t), "gone")
	if _, _, err := a.Sign(context.Background(), []byte{1}); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestLLMSessionBlocksSignAndPresence(t *testing.T) {
	trgClearLLMEnv(t)
	t.Setenv("CLAUDECODE", "1")
	sock, scd := trgServe(t, "OK\n", trgOKReply("00"))
	a, err := New(Options{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Sign(context.Background(), []byte{1}); !errors.Is(err, trust.ErrLLMSessionBlocked) {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := a.RequirePresence(context.Background(), "why"); !errors.Is(err, trust.ErrLLMSessionBlocked) {
		t.Fatalf("RequirePresence: %v", err)
	}
	if n := len(scd.seen()); n != 0 {
		t.Fatalf("scdaemon received %d commands in an LLM session", n)
	}
}

func TestPresenceProofRootID(t *testing.T) {
	trgClearLLMEnv(t)
	a := &Adapter{id: "gpgcard:K", keygrip: "K"}
	p, err := a.RequirePresence(context.Background(), "reveal")
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != "gpg-card-pin" || p.RootID != "gpgcard:K" || p.ConfirmedAt.IsZero() {
		t.Fatalf("proof = %+v", p)
	}
	if err := a.VerifyPresenceProof(context.Background(), p); err != nil {
		t.Fatalf("VerifyPresenceProof: %v", err)
	}
	if err := a.VerifyPresenceProof(context.Background(), trust.PresenceProof{}); err == nil {
		t.Fatal("empty RootID must be rejected")
	}

	a.opts.HMACFunc = func(b []byte) []byte { return append([]byte("h:"), b...) }
	p, err = a.RequirePresence(context.Background(), "reveal")
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.RawURLEncoding.EncodeToString([]byte("h:gpgcard:K")); p.RootID != want {
		t.Fatalf("RootID = %q, want %q", p.RootID, want)
	}
}

func TestCapabilitiesAndUnsupportedOps(t *testing.T) {
	a := &Adapter{id: "gpgcard:K"}
	for c, want := range map[trust.Capability]bool{
		trust.CapSignChallenge: true, trust.CapUserPresence: true,
		trust.CapWrap: false, trust.CapLaunchdSafe: false, trust.CapAttestation: false,
	} {
		if a.Has(c) != want {
			t.Errorf("Has(%d) = %v", c, !want)
		}
	}
	ctx := context.Background()
	dek := []byte{1, 2, 3}
	if _, err := a.Wrap(ctx, dek); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("Wrap: %v", err)
	}
	if dek[0]|dek[1]|dek[2] != 0 {
		t.Error("Wrap must zero the DEK even when unsupported")
	}
	if _, err := a.Unwrap(ctx, nil); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("Unwrap: %v", err)
	}
	if err := a.Verify(ctx, nil, nil, nil); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("Verify: %v", err)
	}
	if _, err := a.Attest(ctx); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("Attest: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func trgFakeGpgconf(t *testing.T, script string) {
	t.Helper()
	dir := trgShortDir(t)
	if err := os.WriteFile(filepath.Join(dir, "gpgconf"), []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestSocketDiscoveryViaGpgconf(t *testing.T) {
	sock, _ := trgServe(t, "OK\n", trgOKReply("00"))
	agentSock := filepath.Join(filepath.Dir(sock), "S.gpg-agent")
	trgFakeGpgconf(t, `[ "$1 $2" = "--list-dirs agent-socket" ] || exit 3
echo "`+agentSock+`"
`)
	got, err := scdaemonSocket()
	if err != nil || got != sock {
		t.Fatalf("scdaemonSocket = %q, %v; want %q", got, err, sock)
	}

	extra := map[string]any{"keygrip": "KG"}
	r, err := trust.New(trust.RootSpec{Type: trust.RootGPGCard, Label: "L", Extra: extra})
	if err != nil {
		t.Fatalf("trust.New: %v", err)
	}
	a := r.(*Adapter)
	if a.ID() != "gpgcard:KG" || a.opts.SocketPath != sock || a.opts.Label != "L" {
		t.Fatalf("adapter = %+v", a.opts)
	}
}

func TestSocketDiscoveryFailure(t *testing.T) {
	trgFakeGpgconf(t, "exit 2\n")
	_, err := New(Options{})
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "gpgconf") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv("PATH", trgShortDir(t))
	if _, err := trust.New(trust.RootSpec{Type: trust.RootGPGCard}); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("gpgconf absent: err = %v", err)
	}
}

func TestAssuanDecodeD(t *testing.T) {
	cases := map[string]string{
		"plain":   "plain",
		"%41%42":  "AB",
		"a%25b":   "a%b",
		"trail%4": "trail%4",
		"%0D%0A":  "\r\n",
		"":        "",
	}
	for in, want := range cases {
		got, err := assuanDecodeD(in)
		if err != nil || string(got) != want {
			t.Errorf("assuanDecodeD(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := assuanDecodeD("%G0"); err == nil || !strings.Contains(err.Error(), "bad percent-escape at 0") {
		t.Errorf("bad escape: err = %v", err)
	}
}
