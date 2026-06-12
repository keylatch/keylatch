package ipc

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/sidecar/events"
)

type fakeMinter struct {
	token string
	err   error
}

func (f *fakeMinter) MintBootstrapToken() (string, time.Time, error) {
	return f.token, time.Now().Add(time.Minute), f.err
}

func newRegisteredRegistry(t *testing.T, minter BootstrapTokenMinter, shutdown ShutdownFunc) *MethodRegistry {
	t.Helper()
	reg := NewMethodRegistry()
	RegisterHandlers(reg, events.NewMux(), minter, shutdown)
	return reg
}

func TestRegisterHandlers_AllFiveDispatchable(t *testing.T) {
	t.Parallel()
	reg := newRegisteredRegistry(t, &fakeMinter{token: "tok"}, func() {})
	ctx := context.Background()

	// Health.
	resp := reg.Dispatch(ctx, Request{Method: MethodHealth}, nil)
	if resp.Error != "" {
		t.Fatalf("Health: %s", resp.Error)
	}
	m, ok := resp.Result.(map[string]any)
	if !ok || m["ok"] != true {
		t.Errorf("Health result = %#v", resp.Result)
	}
	if m["build"] == "" {
		t.Error("Health must report a build version")
	}

	// MintBootstrapToken.
	resp = reg.Dispatch(ctx, Request{Method: MethodMintBootstrapToken}, nil)
	if resp.Error != "" {
		t.Fatalf("MintBootstrapToken: %s", resp.Error)
	}
	m, _ = resp.Result.(map[string]any)
	if m["token"] != "tok" {
		t.Errorf("MintBootstrapToken result = %#v", resp.Result)
	}

	// Shutdown — the func runs on a goroutine; wait for the signal.
	done := make(chan struct{})
	reg2 := newRegisteredRegistry(t, nil, func() { close(done) })
	resp = reg2.Dispatch(ctx, Request{Method: MethodShutdown}, nil)
	if resp.Error != "" {
		t.Fatalf("Shutdown: %s", resp.Error)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("ShutdownFunc was not invoked")
	}
}

func TestDispatch_ErrorPaths(t *testing.T) {
	t.Parallel()
	reg := NewMethodRegistry()
	ctx := context.Background()

	// Disallowed method name.
	resp := reg.Dispatch(ctx, Request{Method: "EvilMethod"}, nil)
	if resp.Error != "unsupported_method" {
		t.Errorf("disallowed: %q", resp.Error)
	}

	// Allowed but unregistered.
	resp = reg.Dispatch(ctx, Request{Method: MethodHealth}, nil)
	if resp.Error != "unsupported_method" {
		t.Errorf("unregistered: %q", resp.Error)
	}

	// Handler error must be masked as internal_error (S14-8).
	reg.Register(MethodHealth, func(_ context.Context, _ any, _ *FrameWriter) (any, error) {
		return nil, errors.New("secret detail")
	})
	resp = reg.Dispatch(ctx, Request{Method: MethodHealth}, nil)
	if resp.Error != "internal_error" {
		t.Errorf("handler error: %q", resp.Error)
	}
}

func TestRegister_DisallowedPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("Register of a disallowed method must panic (S14-8)")
		}
	}()
	NewMethodRegistry().Register("NotAllowed", func(_ context.Context, _ any, _ *FrameWriter) (any, error) {
		return nil, nil
	})
}

func TestMintBootstrapToken_Errors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Nil minter.
	h := mintBootstrapTokenHandler(nil)
	if _, err := h(ctx, nil, nil); err == nil {
		t.Error("nil minter must error")
	}

	// Minter failure propagates.
	h = mintBootstrapTokenHandler(&fakeMinter{err: errors.New("mint failed")})
	if _, err := h(ctx, nil, nil); err == nil {
		t.Error("minter error must propagate")
	}
}

func TestOpenSystemBrowser_Validation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := openSystemBrowserHandler()

	// Missing params.
	if _, err := h(ctx, nil, nil); err == nil {
		t.Error("missing params must error")
	}
	// Missing url key.
	if _, err := h(ctx, map[string]any{"other": "x"}, nil); err == nil {
		t.Error("missing url must error")
	}
	// Rejected schemes (S14-2 / M8) — must fail BEFORE any browser launch.
	for _, bad := range []string{
		"file:///etc/passwd",
		"ftp://host/x",
		"javascript:alert(1)",
		"http://insecure.example",
		"://not-a-url",
	} {
		if _, err := h(ctx, map[string]any{"url": bad}, nil); err == nil {
			t.Errorf("scheme must be rejected: %q", bad)
		} else if !strings.Contains(err.Error(), "rejected URL scheme") && !strings.Contains(err.Error(), "missing url") {
			t.Logf("%q rejected with: %v", bad, err)
		}
	}
}

func TestExtractURLParam(t *testing.T) {
	t.Parallel()
	if _, ok := extractURLParam("not-a-map"); ok {
		t.Error("non-map params must not extract")
	}
	if _, ok := extractURLParam(map[string]any{"url": 42}); ok {
		t.Error("non-string url must not extract")
	}
	u, ok := extractURLParam(map[string]any{"url": "https://x"})
	if !ok || u != "https://x" {
		t.Errorf("extractURLParam = %q, %v", u, ok)
	}
}

func TestSubscribeEvents_StreamsAndStops(t *testing.T) {
	t.Parallel()
	mux := events.NewMux()
	h := subscribeEventsHandler(mux)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h(ctx, nil, nil)
		done <- err
	}()

	// Cancelling the context must end the stream cleanly.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("subscribe handler returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscribe handler did not exit on context cancel")
	}
}

// TestSubscribeEvents_DeliversFrames publishes events through the mux and
// verifies the handler writes them as authenticated frames, then exits when
// the mux closes the subscriber channel.
func TestSubscribeEvents_DeliversFrames(t *testing.T) {
	t.Parallel()
	mux := events.NewMux()
	h := subscribeEventsHandler(mux)

	pr, pw := io.Pipe()
	fw := NewFrameWriter(pw, testKey())
	fr := NewFrameReader(pr, testKey())

	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		_, err := h(ctx, nil, fw)
		done <- err
	}()

	// Give the handler a moment to subscribe before publishing.
	time.Sleep(50 * time.Millisecond)
	mux.Publish(events.Event{Type: events.EventType("test.event")})

	var got events.Event
	if err := fr.Read(&got); err != nil {
		t.Fatalf("read published event frame: %v", err)
	}
	if got.Type != "test.event" {
		t.Errorf("event type = %q", got.Type)
	}

	// Stopping the mux closes subscriber channels; the handler must exit.
	mux.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("handler returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not exit after mux stop")
	}
	pw.Close()
	pr.Close()
}
