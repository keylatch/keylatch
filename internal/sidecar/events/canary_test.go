package events_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	canarypkg "github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/sidecar/events"
)

func TestCanary_SidecarOutputDoesNotContainSentinels(t *testing.T) {
	mux := events.NewMux()
	ch := mux.Subscribe()
	defer mux.Unsubscribe(ch)

	upstreamCh := make(chan interface{}, 1)
	upstreamCh <- map[string]interface{}{
		"approval_id": canarypkg.Phase14DesktopSentinel,
		"provider":    "github",
		"action":      "read:repo",
		"actor":       "claude-code",
	}
	close(upstreamCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux.Start(ctx, upstreamCh, nil, nil)

	select {
	case ev := <-ch:
		output, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		canarypkg.AssertNoLeak(t, canarypkg.RegisteredSentinels(), canarypkg.JSONResponse(string(output)))
		if len(output) == 0 {
			t.Fatal("expected sidecar event output")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for sidecar canary event")
	}
}
