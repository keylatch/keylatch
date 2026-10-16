package contained

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validSpec() Spec {
	return Spec{Argv: []string{"make", "test"}, Env: []string{"A=b"}, Project: "/work/p", EgressDir: "/run/e", RootDir: "/run/r"}
}

func TestValidateFillsDefaults(t *testing.T) {
	s := validSpec()
	require.NoError(t, s.Validate())
	assert.Equal(t, "/work/p", s.Dir)
	assert.Equal(t, DefaultHome, s.Home)
	assert.Equal(t, DefaultProxyPort, s.ProxyPort)

	s = validSpec()
	s.TTY = &Winsize{}
	require.NoError(t, s.Validate())
	assert.Equal(t, Winsize{Rows: 24, Cols: 80}, *s.TTY)
}

func TestValidateRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Spec){
		"no command":          func(s *Spec) { s.Argv = nil },
		"empty command":       func(s *Spec) { s.Argv = []string{""} },
		"NUL in argv":         func(s *Spec) { s.Argv = []string{"a\x00b"} },
		"env without equals":  func(s *Spec) { s.Env = []string{"NOEQUALS"} },
		"env without name":    func(s *Spec) { s.Env = []string{"=v"} },
		"relative project":    func(s *Spec) { s.Project = "work/p" },
		"unclean project":     func(s *Spec) { s.Project = "/work/../p" },
		"relative egress dir": func(s *Spec) { s.EgressDir = "e" },
		"relative root dir":   func(s *Spec) { s.RootDir = "r" },
		"relative read-only":  func(s *Spec) { s.ReadOnly = []string{"x"} },
		"relative read-write": func(s *Spec) { s.ReadWrite = []string{"../x"} },
		"relative dir":        func(s *Spec) { s.Dir = "sub" },
		"honey escapes home":  func(s *Spec) { s.Honey = []HoneyFile{{Path: "../etc/passwd"}} },
		"honey absolute":      func(s *Spec) { s.Honey = []HoneyFile{{Path: "/etc/passwd"}} },
		"honey empty":         func(s *Spec) { s.Honey = []HoneyFile{{}} },
		"port zero":           func(s *Spec) { s.ProxyPort = -1 },
		"port too large":      func(s *Spec) { s.ConnectPorts = []int{70000} },
	} {
		s := validSpec()
		mutate(&s)
		assert.Error(t, s.Validate(), name)
	}
}

func TestReportMissingNamesOnlyRequiredCapabilities(t *testing.T) {
	r := Report{Capabilities: []Capability{
		{Name: "user_namespace", OK: true},
		{Name: "landlock", OK: false, Detail: "no kernel support"},
		{Name: "cgroup_leaf", OK: false, Detail: "read-only"},
	}}
	assert.Equal(t, []string{"landlock: no kernel support"}, r.Missing())
	c, ok := r.Get("cgroup_leaf")
	assert.True(t, ok)
	assert.Equal(t, "read-only", c.Detail)
	_, ok = r.Get("nope")
	assert.False(t, ok)
}

func TestForwardPipesEachConnectionToAFreshUpstream(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	var mu sync.Mutex
	dials := 0
	go Forward(l, func() (net.Conn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		a, b := net.Pipe()
		go func() {
			defer func() { _ = b.Close() }()
			buf := make([]byte, 4)
			_, _ = io.ReadFull(b, buf)
			_, _ = b.Write([]byte(strings.ToUpper(string(buf))))
		}()
		return a, nil
	})

	for _, msg := range []string{"abcd", "wxyz"} {
		c, err := net.Dial("tcp", l.Addr().String())
		require.NoError(t, err)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Write([]byte(msg))
		require.NoError(t, err)
		got, err := io.ReadAll(c)
		require.NoError(t, err)
		assert.Equal(t, strings.ToUpper(msg), string(got))
		_ = c.Close()
	}
	mu.Lock()
	assert.Equal(t, 2, dials)
	mu.Unlock()
}

func TestForwardClosesTheClientWhenTheUpstreamIsUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	go Forward(l, func() (net.Conn, error) { return nil, io.ErrClosedPipe })
	c, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadAll(c)
	assert.NoError(t, err)
	_ = c.Close()
}

func TestForwardStopsWhenTheListenerCloses(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { Forward(l, nil); close(done) }()
	_ = l.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Forward kept running after its listener closed")
	}
}

func TestPipeHalfClosesPlainConnections(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := make(chan struct{})
	go func() { pipe(a2, b1); close(done) }()
	go func() { _, _ = a1.Write([]byte("hi")); _ = a1.Close() }()
	got, _ := io.ReadAll(b2)
	assert.Equal(t, "hi", string(got))
	_ = b2.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not finish")
	}
}
