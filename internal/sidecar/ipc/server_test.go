package ipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 7)
	}
	return k
}

func TestNewServer_KeyValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewServer("/tmp/x.sock", []byte("short")); err == nil {
		t.Error("short key must be rejected")
	}
	s, err := NewServer("/tmp/x.sock", testKey())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.Registry() == nil {
		t.Error("Registry must not be nil")
	}
}

func TestEventSubscriptionDoesNotBlockBootstrapAndShutdown(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "ipc.sock")
	key := testKey()
	s, err := NewServer(path, key)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	exited := make(chan struct{})
	s.Registry().Register(MethodSubscribeEvents, func(ctx context.Context, _ any, _ *FrameWriter) (any, error) {
		defer close(exited)
		close(entered)
		<-ctx.Done()
		return nil, nil
	})
	s.Registry().Register(MethodMintBootstrapToken, mintBootstrapTokenHandler(&fakeMinter{token: "fresh-token"}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx) }()
	dial := func() net.Conn {
		t.Helper()
		var lastErr error
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			select {
			case err := <-done:
				t.Fatalf("IPC listener stopped: %v", err)
			default:
			}
			conn, err := net.Dial("unix", path)
			if err == nil {
				t.Cleanup(func() { _ = conn.Close() })
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				return conn
			}
			lastErr = err
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("IPC socket %s did not become available: %v", path, lastErr)
		return nil
	}
	idle := dial()
	stream := dial()
	if err := NewFrameWriter(stream, key).Write(Request{Method: MethodSubscribeEvents}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("idle connection blocked event subscription")
	}
	bootstrap := dial()
	if err := NewFrameWriter(bootstrap, key).Write(Request{Method: MethodMintBootstrapToken}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := NewFrameReader(bootstrap, key).Read(&response); err != nil || response.Error != "" {
		t.Fatalf("event subscription blocked bootstrap: %+v %v", response, err)
	}
	_ = stream.Close()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("subscription remained active after client disconnect")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not close accepted connections")
	}
	var b [1]byte
	if _, err := idle.Read(b[:]); err == nil {
		t.Fatal("idle connection remained open after shutdown")
	}
}

// TestServer_ListenRoundTrip starts the server on a real unix socket, sends
// an authenticated Health request, reads the response, then sends a frame
// with a corrupted HMAC and verifies the connection is dropped silently.
func TestServer_ListenRoundTrip(t *testing.T) {
	// Unix domain sockets work on Windows 10 1809+/Server 2019+ via AF_UNIX,
	// so this test runs on all CI platforms.
	t.Parallel()

	sockPath := filepath.Join(shortTempDir(t), "ipc.sock")
	key := testKey()
	s, err := NewServer(sockPath, key)
	if err != nil {
		t.Fatal(err)
	}
	RegisterHandlers(s.Registry(), nil, &fakeMinter{token: "t"}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Listen(ctx) }()

	// Wait for the socket to appear.
	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("could not connect to %s: %v", sockPath, err)
	}

	// Authenticated Health round-trip.
	fw := NewFrameWriter(conn, key)
	fr := NewFrameReader(conn, key)
	if err := fw.Write(Request{Method: MethodHealth}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var resp Response
	if err := fr.Read(&resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("Health over socket: %s", resp.Error)
	}
	conn.Close()

	// Bad-HMAC frame: connection must be dropped without a response.
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	wrongKey := make([]byte, 32) // all zeros — wrong HMAC secret
	badFW := NewFrameWriter(conn2, wrongKey)
	if err := badFW.Write(Request{Method: MethodHealth}); err != nil {
		t.Fatalf("write bad frame: %v", err)
	}
	goodFR := NewFrameReader(conn2, key)
	var dropped Response
	if err := goodFR.Read(&dropped); err == nil {
		t.Error("expected connection drop after HMAC mismatch, got a response")
	}
	conn2.Close()

	// Shutdown cleanly.
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Errorf("Listen returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Listen did not return after cancel")
	}
}

func TestRecordInvalidFrame_WindowCounting(t *testing.T) {
	t.Parallel()
	s, err := NewServer(filepath.Join(shortTempDir(t), "x.sock"), testKey())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		s.recordInvalidFrame()
	}
	s.windowMu.Lock()
	n := s.invalidFrameCount
	s.windowMu.Unlock()
	if n == 0 {
		t.Error("invalid frame counter did not increment")
	}
}

// TestFrameReader_RejectsOversizedAndTruncated covers the codec error
// branches: declared length beyond maxFrameSize, and a truncated body.
func TestFrameReader_RejectsOversizedAndTruncated(t *testing.T) {
	t.Parallel()
	key := testKey()

	// Oversized declared length.
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxFrameSize+1)
	buf.Write(hdr[:])
	fr := NewFrameReader(&buf, key)
	var v any
	if err := fr.Read(&v); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("oversized frame: got %v, want ErrFrameTooLarge", err)
	}

	// Truncated body: declared 100 bytes, deliver 3.
	buf.Reset()
	binary.BigEndian.PutUint32(hdr[:], 100)
	buf.Write(hdr[:])
	buf.Write([]byte{1, 2, 3})
	fr = NewFrameReader(&buf, key)
	if err := fr.Read(&v); err == nil {
		t.Error("truncated frame must error")
	}
}
