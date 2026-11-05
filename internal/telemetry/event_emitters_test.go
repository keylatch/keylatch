package telemetry_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmitters_NameAndValueFreeFields(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		emit   func(s telemetry.Sink)
		name   string
		fields map[string]string
	}{
		{func(s telemetry.Sink) { telemetry.SetupCompleted(ctx, s, "file") }, "setup_completed", map[string]string{"backend": "file"}},
		{func(s telemetry.Sink) { telemetry.ConnectSucceeded(ctx, s, "openai", "op") }, "connect_succeeded", map[string]string{"provider": "openai", "backend": "op"}},
		{func(s telemetry.Sink) { telemetry.RunInvoked(ctx, s, "gateway_typed", "success") }, "run_invoked", map[string]string{"runtime_mode": "gateway_typed", "exit_code_class": "success"}},
		{func(s telemetry.Sink) { telemetry.DoctorRun(ctx, s, "warning") }, "doctor_run", map[string]string{"overall_status": "warning"}},
		{func(s telemetry.Sink) { telemetry.DaemonStarted(ctx, s, "auto") }, "daemon_started", map[string]string{"trigger": "auto"}},
		{func(s telemetry.Sink) { telemetry.GuardBlocked(ctx, s, "claude-code", 3) }, "guard_blocked", map[string]string{"agent": "claude-code", "count": "3"}},
		{func(s telemetry.Sink) { telemetry.ErrorOccurred(ctx, s, "KL-1001") }, "error_occurred", map[string]string{"kl_code": "KL-1001"}},
		{func(s telemetry.Sink) { telemetry.GatewayRequestCompleted(ctx, s, "anthropic", "denied", 42) }, "gateway_request_completed", map[string]string{"provider": "anthropic", "outcome": "denied", "duration_ms": "42"}},
		{func(s telemetry.Sink) { telemetry.VaultError(ctx, s, "bw") }, "vault_error", map[string]string{"backend": "bw"}},
		{func(s telemetry.Sink) { telemetry.TokenMinted(ctx, s, "gateway_sdk") }, "token_minted", map[string]string{"runtime": "gateway_sdk"}},
	}
	for _, tc := range cases {
		s := &MockSink{}
		before := time.Now().UTC().Add(-time.Second)
		tc.emit(s)
		events := s.Events()
		require.Len(t, events, 1, tc.name)
		assert.Equal(t, tc.name, events[0].Name)
		assert.Equal(t, tc.fields, events[0].Fields, tc.name)
		assert.True(t, events[0].Timestamp.After(before), tc.name)
		assert.Equal(t, time.UTC, events[0].Timestamp.Location())
	}
}

func TestNew_SelectsSink(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_URL", "")
	assert.IsType(t, telemetry.NoopSink{}, telemetry.New(false, "remote", ""))
	assert.IsType(t, telemetry.NoopSink{}, telemetry.New(true, "carrier-pigeon", ""))
	assert.Equal(t, telemetry.LocalFileSink{Path: "/x"}, telemetry.New(true, "local", "/x"))
	assert.IsType(t, &telemetry.RemoteSink{}, telemetry.New(true, "remote", ""))
}

func TestLocalFileSink_AppendsNDJSONWithPrivateMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.ndjson")
	s := telemetry.LocalFileSink{Path: p}
	telemetry.DoctorRun(context.Background(), s, "healthy")
	telemetry.DaemonStarted(context.Background(), s, "manual")

	f, err := os.Open(p) //nolint:gosec // temp path
	require.NoError(t, err)
	defer f.Close()
	sc := bufio.NewScanner(f)
	var names []string
	for sc.Scan() {
		var ev telemetry.Event
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
		names = append(names, ev.Name)
	}
	assert.Equal(t, []string{"doctor_run", "daemon_started"}, names)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	// Unwritable destinations are swallowed, never surfaced.
	telemetry.LocalFileSink{Path: filepath.Join(t.TempDir(), "missing", "x")}.Emit(context.Background(), telemetry.Event{Name: "e"})
}

func TestRemoteSink_EnrichesWithoutOverridingCallerFields(t *testing.T) {
	bodies := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sink := telemetry.NewRemoteSinkForTest(srv.URL)
	sink.Emit(context.Background(), telemetry.Event{Name: "a", Fields: map[string]string{"os": "caller-os"}})
	sink.Emit(context.Background(), telemetry.Event{Name: "b"})

	got := map[string]map[string]string{}
	for i := 0; i < 2; i++ {
		select {
		case b := <-bodies:
			var ev telemetry.Event
			require.NoError(t, json.Unmarshal(b, &ev))
			got[ev.Name] = ev.Fields
		case <-time.After(5 * time.Second):
			t.Fatal("remote sink did not post")
		}
	}
	assert.Equal(t, "caller-os", got["a"]["os"], "caller-provided fields win")
	assert.Equal(t, runtime.GOOS, got["b"]["os"])
	assert.Equal(t, runtime.GOARCH, got["b"]["arch"])
	assert.Len(t, got["b"]["session_id"], 32)
	assert.Equal(t, got["a"]["session_id"], got["b"]["session_id"], "one session per process")
	assert.NotEmpty(t, got["b"]["keylatch_version"])
	sa, err := strconv.Atoi(got["a"]["sequence_id"])
	require.NoError(t, err)
	sb, err := strconv.Atoi(got["b"]["sequence_id"])
	require.NoError(t, err)
	assert.NotEqual(t, sa, sb, "every event gets its own sequence number")
}

func TestRemoteSink_CancelledContextSendsNothing(t *testing.T) {
	hits := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits <- struct{}{}
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	telemetry.NewRemoteSinkForTest(srv.URL).Emit(ctx, telemetry.Event{Name: "x"})
	select {
	case <-hits:
		t.Fatal("cancelled context must not post")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRemoteSink_InvalidEndpointGivesUp(t *testing.T) {
	// A control character makes request construction fail; Emit must not panic or block.
	telemetry.NewRemoteSinkForTest("http://bad\x7f").Emit(context.Background(), telemetry.Event{Name: "x"})
}

func TestEnsureInstallID_FilesystemErrors(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "install_id"), 0o700))
	_, err := telemetry.EnsureInstallID(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read install_id")

	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	_, err = telemetry.EnsureInstallID(filepath.Join(file, "sub"))
	require.Error(t, err)

	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		ro := t.TempDir()
		require.NoError(t, os.Chmod(ro, 0o500))
		t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
		_, err = telemetry.EnsureInstallID(ro)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create temp install_id")
	}
}
