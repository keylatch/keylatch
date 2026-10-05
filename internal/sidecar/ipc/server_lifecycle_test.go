package ipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/sidecar/events"
)

func gdSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func gdDial(t *testing.T, path string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", path); err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("could not dial %s", path)
	return nil
}

func TestServer_ListenFailsOnBadPath(t *testing.T) {
	s, err := NewServer(filepath.Join(t.TempDir(), "missing", "s.sock"), testKey())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Listen(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ipc: listen on") {
		t.Fatalf("want listen error, got %v", err)
	}
}

func TestServer_SocketModeKeyCopyAndCleanup(t *testing.T) {
	sock := gdSock(t)
	key := testKey()
	s, err := NewServer(sock, key)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 0xff
	if s.key[0] == key[0] {
		t.Fatal("server must keep its own copy of the HMAC key")
	}
	RegisterHandlers(s.Registry(), events.NewMux(), nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx) }()
	conn := gdDial(t, sock)

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %o, want 600", info.Mode().Perm())
	}

	fw := NewFrameWriter(conn, testKey())
	fr := NewFrameReader(conn, testKey())

	if err := fw.Write(Request{Method: "ReadVault"}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := fr.Read(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "unsupported_method" {
		t.Errorf("disallowed method response = %+v", resp)
	}

	if err := fw.Write(Request{Method: MethodMintBootstrapToken}); err != nil {
		t.Fatal(err)
	}
	resp = Response{}
	if err := fr.Read(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "internal_error" || resp.Result != nil {
		t.Errorf("unconfigured minter must fail without detail, got %+v", resp)
	}

	// Cancel while the connection is idle; the next request is still
	// answered and then the server closes the connection.
	cancel()
	if err := fw.Write(Request{Method: MethodHealth}); err != nil {
		t.Fatal(err)
	}
	resp = Response{}
	if err := fr.Read(&resp); err != nil {
		t.Fatalf("in-flight request after cancel: %v", err)
	}
	var extra Response
	if err := fr.Read(&extra); err == nil {
		t.Error("connection must be closed after shutdown")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Listen returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Listen did not return")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Error("socket file must be removed on shutdown")
	}
	if !bytes.Equal(s.key, make([]byte, 32)) {
		t.Error("HMAC key must be zeroed on shutdown")
	}
}

func TestServer_HMACMismatchCountsInvalidFrame(t *testing.T) {
	sock := gdSock(t)
	s, err := NewServer(sock, testKey())
	if err != nil {
		t.Fatal(err)
	}
	RegisterHandlers(s.Registry(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	conn := gdDial(t, sock)
	if err := NewFrameWriter(conn, make([]byte, 32)).Write(Request{Method: MethodHealth}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := NewFrameReader(conn, testKey()).Read(&resp); err == nil {
		t.Fatal("forged frame must not get a response")
	}
	s.windowMu.Lock()
	n := s.invalidFrameCount
	s.windowMu.Unlock()
	if n != 1 {
		t.Errorf("invalid frame count = %d, want 1", n)
	}

	conn2 := gdDial(t, sock)
	if err := NewFrameWriter(conn2, testKey()).Write(Request{Method: MethodHealth}); err != nil {
		t.Fatal(err)
	}
	if err := NewFrameReader(conn2, testKey()).Read(&resp); err != nil {
		t.Fatalf("server must keep serving after a forged frame: %v", err)
	}
}

func TestRecordInvalidFrame_WindowExpiryAndThreshold(t *testing.T) {
	s, err := NewServer("/unused", testKey())
	if err != nil {
		t.Fatal(err)
	}
	s.invalidFrameCount = 7
	s.windowStart = time.Now().Add(-2 * invalidFrameWindowDuration)
	s.recordInvalidFrame()
	if s.invalidFrameCount != 1 {
		t.Errorf("expired window must restart the count, got %d", s.invalidFrameCount)
	}

	for i := 0; i < invalidFrameAlertThreshold-2; i++ {
		s.recordInvalidFrame()
	}
	if s.invalidFrameCount != invalidFrameAlertThreshold-1 {
		t.Fatalf("count = %d", s.invalidFrameCount)
	}
	s.recordInvalidFrame()
	if s.invalidFrameCount != 0 {
		t.Errorf("reaching the threshold must reset the counter, got %d", s.invalidFrameCount)
	}
}

type gdFailWriter struct{}

func (gdFailWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestSubscribeEvents_ExitsOnWriteFailure(t *testing.T) {
	mux := events.NewMux()
	h := subscribeEventsHandler(mux)
	fw := NewFrameWriter(gdFailWriter{}, testKey())

	done := make(chan struct{})
	go func() {
		res, err := h(context.Background(), nil, fw)
		if res != nil || err != nil {
			t.Errorf("handler = %v, %v", res, err)
		}
		close(done)
	}()

	deadline := time.After(3 * time.Second)
	for {
		mux.Publish(events.Event{Type: events.EventTypeSecurity})
		select {
		case <-done:
			mux.Stop()
			return
		case <-deadline:
			t.Fatal("handler did not exit after write failure")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestFrameWriter_MarshalAndWriteErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := NewFrameWriter(&buf, testKey()).Write(make(chan int)); err == nil {
		t.Error("unencodable value must error")
	}
	if buf.Len() != 0 {
		t.Error("nothing may be written when encoding fails")
	}
	if err := NewFrameWriter(gdFailWriter{}, testKey()).Write("x"); err == nil {
		t.Error("writer error must be returned")
	}
}

func TestFrameReader_MissingTag(t *testing.T) {
	var buf bytes.Buffer
	if err := NewFrameWriter(&buf, testKey()).Write("hello"); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	truncated := frame[:len(frame)-hmacTagSize+3]
	var out string
	err := NewFrameReader(bytes.NewReader(truncated), testKey()).Read(&out)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("want ErrUnexpectedEOF, got %v", err)
	}
	if out != "" {
		t.Error("nothing may be decoded from an unauthenticated frame")
	}

	tampered := append([]byte(nil), frame...)
	tampered[5] ^= 0x01
	err = NewFrameReader(bytes.NewReader(tampered), testKey()).Read(&out)
	if !errors.Is(err, ErrHMACMismatch) {
		t.Errorf("tampered body: want ErrHMACMismatch, got %v", err)
	}

	lenOnly := make([]byte, 4)
	binary.BigEndian.PutUint32(lenOnly, 3)
	err = NewFrameReader(bytes.NewReader(lenOnly), testKey()).Read(&out)
	if !errors.Is(err, io.EOF) {
		t.Errorf("missing body: want EOF, got %v", err)
	}
}
