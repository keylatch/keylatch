package ui_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/require"
)

func TestReadinessAnnouncesBoundListener(t *testing.T) {
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- srv.ServeWithReady(ctx, func(address string) error {
			conn, dialErr := net.DialTimeout("tcp", address, time.Second)
			if dialErr != nil {
				return dialErr
			}
			_ = conn.Close()
			ready <- address
			return nil
		})
	}()
	var address string
	select {
	case address = <-ready:
	case err := <-done:
		t.Fatalf("server stopped before readiness: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("readiness was not announced")
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + address + "/health")
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestReadinessIsNotAnnouncedOnBindFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	opts := defaultOpts(t)
	opts.Bind = listener.Addr().String()
	srv, err := ui.New(opts)
	require.NoError(t, err)
	called := false
	err = srv.ServeWithReady(t.Context(), func(string) error { called = true; return nil })
	require.Error(t, err)
	require.False(t, called)
}

func TestReadinessFailureClosesListener(t *testing.T) {
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)
	want := errors.New("ready output unavailable")
	var address string
	err = srv.ServeWithReady(t.Context(), func(bound string) error { address = bound; return want })
	require.ErrorIs(t, err, want)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err)
}
