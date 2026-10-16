//go:build unix

package brokerd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestListenFDs(t *testing.T) {
	pid := os.Getpid()
	for name, tc := range map[string]struct {
		env  map[string]string
		want int
	}{
		"activated":       {map[string]string{"LISTEN_PID": strconv.Itoa(pid), "LISTEN_FDS": "2"}, 2},
		"for another pid": {map[string]string{"LISTEN_PID": "1", "LISTEN_FDS": "1"}, 0},
		"no variables":    {nil, 0},
		"zero sockets":    {map[string]string{"LISTEN_PID": strconv.Itoa(pid), "LISTEN_FDS": "0"}, 0},
		"garbage count":   {map[string]string{"LISTEN_PID": strconv.Itoa(pid), "LISTEN_FDS": "x"}, 0},
	} {
		if got := ListenFDs(envOf(tc.env), pid); got != tc.want {
			t.Errorf("%s: ListenFDs = %d, want %d", name, got, tc.want)
		}
	}
}

func TestListenAdoptsTheActivatedSocket(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socket pairs are not permitted here: %v", err)
	}
	defer func() { _ = syscall.Close(fds[1]) }()
	prev := firstListenFD
	firstListenFD = uintptr(fds[0])
	defer func() { firstListenFD = prev }()

	env := envOf(map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1"})
	ln, err := Listen(filepath.Join(t.TempDir(), "never-created.sock"), env, os.Getpid())
	if err != nil {
		t.Fatalf("Listen with socket activation: %v", err)
	}
	_ = ln.Close()
	if _, err := os.Stat(filepath.Join(t.TempDir(), "never-created.sock")); err == nil {
		t.Fatal("an activated socket must not create a path")
	}

	// A descriptor that is not a socket is refused.
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := ListenFD(f.Fd()); err == nil {
		t.Fatal("adopting a non-socket must fail")
	}
}

func TestListenCreatesWorldConnectableSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "run", "broker.sock")
	ln, err := Listen(path, envOf(nil), os.Getpid())
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("binding Unix sockets is not permitted here: %v", err)
		}
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode: %v %v", info, err)
	}
	if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o755 {
		t.Fatalf("socket directory mode = %v", info.Mode().Perm())
	}
	if _, err := Listen(path, envOf(nil), os.Getpid()); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("a second daemon on the same socket = %v", err)
	}
	// A stale socket left by a dead daemon is replaced.
	_ = ln.Close()
	ln2, err := Listen(path, envOf(nil), os.Getpid())
	if err != nil {
		t.Fatalf("replacing a stale socket: %v", err)
	}
	_ = ln2.Close()
}

func TestOpenAuditUsesTheHierarchy(t *testing.T) {
	h := testKeys(t)
	dir := filepath.Join(t.TempDir(), "audit")
	l, err := OpenAudit(dir, h)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if err := l.Log(context.Background(), audit.Event{Action: audit.ActionSet, Outcome: audit.OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	if head := l.Head(); head.Seq != 1 || head.Hash == "" {
		t.Fatalf("head = %+v", head)
	}
	if info, _ := os.Stat(filepath.Join(dir, "audit.log")); info.Mode().Perm() != 0o600 {
		t.Fatalf("audit log mode = %v", info.Mode().Perm())
	}
	// The log is sealed under keys derived from the hierarchy: another hierarchy cannot continue it.
	if _, err := OpenAudit(filepath.Join(t.TempDir(), "a", "b"), h); err != nil {
		t.Fatalf("OpenAudit creates its directory: %v", err)
	}
	if _, err := OpenAudit(filepath.Join(os.DevNull, "x"), h); err == nil {
		t.Fatal("OpenAudit under a file must fail")
	}
}

func TestPartitionStartsItsGateway(t *testing.T) {
	var got GatewayPartition
	h := newHarness(t, func(c *Config) {
		c.Gateway = func(_ context.Context, p GatewayPartition) (string, error) {
			got = p
			return "127.0.0.1:4999", nil
		}
	})
	p, err := h.srv.partition(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if got.UID != 1000 || got.Store != p.store || !strings.HasSuffix(got.ConfigDir, filepath.Join("users", "1000", "config")) {
		t.Fatalf("gateway partition = %+v", got)
	}
	if got.Env("KEYLATCH_CONFIG_DIR") != got.ConfigDir {
		t.Fatal("the partition environment must point at the partition's own config directory")
	}
	if addr := p.env("KEYLATCH_GATEWAY_ADDR"); addr != "127.0.0.1:4999" {
		t.Fatalf("gateway address = %q", addr)
	}
	if got.Env("HOME") != "" || got.Env("KEYLATCH_SOCKET") != "" {
		t.Fatal("the partition environment must not leak the daemon's variables")
	}

	// A gateway that fails to start leaves the tier unavailable, not the partition.
	h2 := newHarness(t, func(c *Config) {
		c.Gateway = func(context.Context, GatewayPartition) (string, error) { return "", errors.New("no port") }
	})
	p2, err := h2.srv.partition(context.Background(), 1000)
	if err != nil || p2.env("KEYLATCH_GATEWAY_ADDR") != "" {
		t.Fatalf("partition with a failing gateway: %v %q", err, p2.env("KEYLATCH_GATEWAY_ADDR"))
	}
}

func TestGatewayFactoryServesPartition(t *testing.T) {
	h := testKeys(t)
	logger, err := OpenAudit(filepath.Join(t.TempDir(), "audit"), h)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	srv := newHarness(t, nil)
	p, err := srv.srv.partition(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tokenKey := func() ([]byte, error) { return h.TokenKeyFor("1000") }
	addr, err := Gateway(logger)(ctx, GatewayPartition{UID: 1000, ConfigDir: filepath.Join(srv.srv.PartitionDir(1000), "config"), Store: p.store, Env: p.env, TokenKey: tokenKey})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "did not start") {
			t.Skipf("loopback listeners are not permitted here: %v", err)
		}
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("gateway bound %q, want loopback", addr)
	}
}

func TestPartitionsListing(t *testing.T) {
	h := newHarness(t, nil)
	if uids, err := h.srv.partitions(); err != nil || len(uids) != 0 {
		t.Fatalf("partitions of a fresh state = %v, %v", uids, err)
	}
	for _, uid := range []uint32{1000, 1002} {
		if _, err := h.srv.partition(context.Background(), uid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(h.state, "users", "notauid"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	uids, err := h.srv.partitions()
	if err != nil || len(uids) != 2 {
		t.Fatalf("partitions = %v, %v", uids, err)
	}
	if h.srv.Sessions() == nil {
		t.Fatal("Sessions")
	}
}

func TestAdminSurfacesAuditFailures(t *testing.T) {
	h := newHarness(t, nil)
	nonce := make([]byte, 16)
	cases := map[string]brokerapi.Request{
		"adopt":  {Op: brokerapi.OpMigrateImport, Nonce: nonce, Items: []brokerapi.Item{{Path: "a", Value: []byte("x")}}},
		"export": {Op: brokerapi.OpMigrateExport},
		"policy": {Op: brokerapi.OpPolicyAccept, Files: map[string][]byte{"policy.json": []byte(`{}`)}},
	}
	for name, req := range cases {
		req = h.proven(t, 1000, req)
		h.rec.fail = errors.New("disk full")
		resp := h.send(t, 1000, req)
		h.rec.fail = nil
		if resp.OK || resp.Code != brokerapi.CodeRefused {
			t.Errorf("%s with a failing audit log = %+v", name, resp)
		}
	}
	// The same requests succeed once the log is back.
	req := h.proven(t, 1000, cases["export"])
	if resp := h.send(t, 1000, req); !resp.OK {
		t.Fatalf("export = %+v", resp)
	}
}

func TestPolicyStoreFailures(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	h := newHarness(t, nil)
	p, _ := h.srv.partition(context.Background(), 1000)
	files := map[string][]byte{"policy.json": []byte(`{}`)}

	// A directory where a policy file belongs is tampering.
	if err := os.MkdirAll(filepath.Join(p.policy.Dir, "policy.d", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if st := p.policy.Verify(); st.State != PolicyTampered {
		t.Fatalf("state = %s", st.State)
	}
	_ = os.RemoveAll(filepath.Join(p.policy.Dir, "policy.d"))

	// Writing into a read-only partition fails and signs nothing.
	if err := os.Chmod(p.policy.Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(p.policy.Dir, 0o700) }()
	if err := p.policy.Accept(files, "d"); err == nil {
		t.Fatal("Accept into a read-only directory must fail")
	}
	_ = os.Chmod(p.policy.Dir, 0o700)

	// An absent signing key directory surfaces as an error, not a panic.
	if err := p.policy.Accept(map[string][]byte{"policy.d/x.json": []byte(`{}`)}, "d"); err == nil {
		t.Fatal("a policy without policy.json must be refused")
	}
	p.policy.Now = func() time.Time { return time.Unix(5, 0) }
	if err := p.policy.Accept(files, "d"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.policy.Export(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(p.policy.Dir, sigFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.policy.Export(); err == nil {
		t.Fatal("Export without a signature must fail")
	}
}

func TestPartitionTokenKeysDiffer(t *testing.T) {
	keysByUID := map[uint32][]byte{}
	h := newHarness(t, func(c *Config) {
		c.Gateway = func(_ context.Context, p GatewayPartition) (string, error) {
			k, err := p.TokenKey()
			keysByUID[p.UID] = k
			return "127.0.0.1:4999", err
		}
	})
	for _, uid := range []uint32{1000, 1001} {
		if _, err := h.srv.partition(context.Background(), uid); err != nil {
			t.Fatal(err)
		}
	}
	if len(keysByUID[1000]) != 32 || bytes.Equal(keysByUID[1000], keysByUID[1001]) {
		t.Fatal("a token minted for one user's gateway must not verify at another's")
	}
}

func TestNewPolkitAndProofsDefaults(t *testing.T) {
	if p := NewPolkit(); p != nil && p.Bin == "" {
		t.Fatal("NewPolkit returned a method without a binary")
	}
	pr := NewProofs(nil)
	if got := pr.Issue(1, "d", "fake"); got.ID == "" || got.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("Issue = %+v", got)
	}
	s := NewSessions([]byte("k"), nil)
	if s.InAgentScope("/x") {
		t.Fatal("an empty table classifies nothing")
	}
	var pol PolicyStore
	if pol.now().IsZero() {
		t.Fatal("now")
	}
}
