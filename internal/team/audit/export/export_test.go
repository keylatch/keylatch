package export_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team/audit/export"
)

func newEvent(action string) export.AuditEvent {
	return export.AuditEvent{
		Action:    action,
		Actor:     "hmac-actor-id",
		Target:    "hmac-target-id",
		Timestamp: time.Now().UTC(),
		Details: map[string]interface{}{
			"raw_email": "alice@example.com",
			"count":     42,
		},
	}
}

func TestExport_NeverBlocks_UnreachableEndpoint(t *testing.T) {
	// S12-14: Export to unreachable endpoint must not block.
	e := export.New(export.AdapterSplunk, "http://192.0.2.1:9999/unreachable", "test-team-id")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e.Start(ctx)

	// Send many events quickly — should not block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			e.Export(newEvent("test"))
		}
	}()

	select {
	case <-done:
		// OK — Export returned without blocking.
	case <-time.After(time.Second):
		t.Error("Export blocked for > 1s — S12-14 violated")
	}
}

func TestExport_BufferFull_DropsWithoutBlock(t *testing.T) {
	// Fill buffer then try to add more — should not block, should increment dropped.
	e := export.New(export.AdapterSplunk, "http://192.0.2.1:9999/unreachable", "test-team-id")

	// Fill the 1000-event buffer.
	for i := 0; i < 1000; i++ {
		e.Export(newEvent("fill"))
	}

	// This should drop and increment dropped counter.
	e.Export(newEvent("overflow"))

	if e.DroppedCount() < 1 {
		t.Errorf("DroppedCount = %d, want >= 1", e.DroppedCount())
	}
}

func TestFlush_DeliversEvents(t *testing.T) {
	received := make([][]byte, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = append(received, body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := export.New(export.AdapterSplunk, srv.URL, "test-team-id")
	e.Export(newEvent("action-1"))
	e.Export(newEvent("action-2"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := e.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if len(received) != 2 {
		t.Errorf("received %d events, want 2", len(received))
	}
}

func TestExport_ValueFree_NoRawEmails(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := export.New(export.AdapterSplunk, srv.URL, "test-team-id")
	e.Export(export.AuditEvent{
		Action:    "read",
		Actor:     "hmac-actor",
		Target:    "hmac-target",
		Timestamp: time.Now().UTC(),
		Details: map[string]interface{}{
			"email": "alice@example.com",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = e.Flush(ctx)

	if strings.Contains(capturedBody, "alice@example.com") {
		t.Error("raw email found in exported event — value-free invariant violated")
	}
}

func TestAdapterFormats(t *testing.T) {
	adapters := []export.SIEMAdapter{
		export.AdapterSplunk,
		export.AdapterDatadog,
		export.AdapterElastic,
		export.AdapterSumoLogic,
		export.AdapterChronicle,
		export.AdapterSentinelOne,
		export.AdapterPanther,
	}

	for _, adapter := range adapters {
		t.Run(string(adapter), func(t *testing.T) {
			var received []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			e := export.New(adapter, srv.URL, "test-team-id")
			e.Export(newEvent("test-" + string(adapter)))

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := e.Flush(ctx); err != nil {
				t.Fatalf("Flush: %v", err)
			}

			if len(received) == 0 {
				t.Errorf("no data received for adapter %s", adapter)
			}
		})
	}
}
