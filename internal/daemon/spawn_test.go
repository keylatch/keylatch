package daemon_test

import (
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/daemon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Spawn re-executes the current binary as `<self> ui ...`; in tests that is
// this test binary, which must exit straight away instead of running tests.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "ui" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// gdHoldDaemonPort occupies the fixed keylatchd address with a /health
// handler answering status, or skips when the port is already in use.
func gdHoldDaemonPort(t *testing.T, status int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:7890")
	if err != nil {
		t.Skipf("127.0.0.1:7890 unavailable: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ln)
		close(done)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
}

func TestIsRunning_ReflectsHealthStatus(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		gdHoldDaemonPort(t, http.StatusOK)
		assert.True(t, daemon.IsRunning())
	})
	t.Run("unhealthy", func(t *testing.T) {
		gdHoldDaemonPort(t, http.StatusServiceUnavailable)
		assert.False(t, daemon.IsRunning(), "a non-200 health answer is not a running daemon")
	})
}

func TestSpawn_ReturnsOnceHealthy(t *testing.T) {
	gdHoldDaemonPort(t, http.StatusOK)
	require.NoError(t, daemon.Spawn())
}

func TestSpawn_TimesOutWhenNeverHealthy(t *testing.T) {
	gdHoldDaemonPort(t, http.StatusInternalServerError)
	start := time.Now()
	err := daemon.Spawn()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not start in time")
	assert.GreaterOrEqual(t, time.Since(start), 2*time.Second)
}

func TestPingKeylatchd_MalformedAddr(t *testing.T) {
	assert.False(t, daemon.PingKeylatchd("bad host:%zz"))
}

func TestSendFirstLaunchNotification_NoPanic(t *testing.T) {
	assert.NotPanics(t, daemon.SendFirstLaunchNotification)
}
