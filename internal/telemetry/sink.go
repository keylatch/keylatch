package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	klruntime "github.com/keylatch/keylatch/internal/runtime"
	"github.com/keylatch/keylatch/internal/version"
)

var (
	remoteSessionID = newRemoteSessionID()
	remoteSequence  uint32
)

// Event represents a single anonymised telemetry event. All fields must be
// non-sensitive: no secret values, no command arguments, no file paths.
type Event struct {
	Name      string            `json:"event"`
	Timestamp time.Time         `json:"timestamp"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// Sink accepts telemetry events. Implementations must never block the caller
// and must silently swallow all errors.
type Sink interface {
	Emit(ctx context.Context, event Event)
}

// NoopSink discards all events.
type NoopSink struct{}

func (NoopSink) Emit(_ context.Context, _ Event) {}

// LocalFileSink appends NDJSON events to a local file.
type LocalFileSink struct{ Path string }

func (s LocalFileSink) Emit(_ context.Context, event Event) {
	line, err := json.Marshal(event)
	if err != nil {
		return
	}
	f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()              //nolint:errcheck
	fmt.Fprintf(f, "%s\n", line) //nolint:errcheck
}

// RemoteSink POSTs events to the hosted telemetry receiver.
// All errors are swallowed — telemetry failures must never surface to the user.
type RemoteSink struct {
	endpoint string
	client   *http.Client
	// backoffs overrides retryBackoffs for this sink instance. nil = use package var.
	backoffs []time.Duration
}

// newRemoteSink creates a RemoteSink pointing at the production endpoint.
// The endpoint can be overridden by KEYLATCH_TELEMETRY_URL — used by CI canary
// scans to redirect events to a local mock server.
func newRemoteSink() *RemoteSink {
	endpoint := "https://telemetry.keylatch.dev/v1/events"
	if override := os.Getenv("KEYLATCH_TELEMETRY_URL"); override != "" {
		endpoint = override
	}
	return &RemoteSink{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Emit dispatches the event asynchronously in a goroutine. It returns
// immediately so it never blocks the CLI's critical path.
// The goroutine respects ctx cancellation and applies a retry policy:
//
//	Attempt 1: 5 s timeout → on failure wait 5 s
//	Attempt 2: 5 s timeout → on failure wait 30 s
//	Attempt 3: 5 s timeout → on failure, give up silently
//
// Total worst-case wall-clock: ~2 m 35 s. All errors are swallowed.
func (s *RemoteSink) Emit(ctx context.Context, event Event) {
	event = enrichRemoteEvent(event)
	body, err := json.Marshal(event)
	if err != nil {
		return // swallow serialisation error
	}

	// NOTE: Fire-and-forget goroutine. For a short-lived CLI process the OS reclaims it
	// on exit. Do not embed RemoteSink in long-lived server processes without a shutdown mechanism.
	go s.emitWithRetry(ctx, body)
}

// retryBackoffs defines the wait durations between successive attempts.
// index i = wait after attempt i+1 fails (last entry is unused — we give up).
// Exported via retryBackoffs so tests can inject short durations.
var retryBackoffs = []time.Duration{5 * time.Second, 30 * time.Second}

func (s *RemoteSink) emitWithRetry(ctx context.Context, body []byte) {
	const maxAttempts = 3
	const attemptTimeout = 5 * time.Second

	backoffs := retryBackoffs
	if s.backoffs != nil {
		backoffs = s.backoffs
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Honour context cancellation between attempts.
		if ctx.Err() != nil {
			return
		}

		timeout := attemptTimeout
		if s.client.Timeout > 0 && s.client.Timeout < timeout {
			// Test sink uses a shorter per-request timeout.
			timeout = s.client.Timeout
		}

		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, s.endpoint, bytes.NewReader(body))
		if err != nil {
			cancel()
			return // request creation failure is not retriable
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		resp, err := s.client.Do(req)
		cancel()

		if err == nil {
			resp.Body.Close() //nolint:errcheck
			// Treat 2xx and 4xx as terminal (do not retry). Only 5xx is retriable.
			if resp.StatusCode < 500 {
				return
			}
			// 5xx — fall through to retry logic below.
		}

		// Failed — wait before next attempt if one remains.
		if attempt < len(backoffs) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoffs[attempt]):
			}
		}
	}
	// Silently give up after maxAttempts.
}

func enrichRemoteEvent(event Event) Event {
	fields := make(map[string]string, len(event.Fields)+5)
	for key, value := range event.Fields {
		fields[key] = value
	}
	setDefault(fields, "keylatch_version", version.Version)
	setDefault(fields, "os", goruntime.GOOS)
	setDefault(fields, "arch", goruntime.GOARCH)
	setDefault(fields, "session_id", remoteSessionID)
	setDefault(fields, "sequence_id", strconv.FormatUint(uint64(atomic.AddUint32(&remoteSequence, 1)), 10))
	event.Fields = fields
	return event
}

func setDefault(fields map[string]string, key string, value string) {
	if fields[key] == "" {
		fields[key] = value
	}
}

func newRemoteSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

// New returns the appropriate Sink based on config values.
// enabled=false → NoopSink; enabled=true, sink="local" → LocalFileSink;
// enabled=true, sink="remote" → RemoteSink that POSTs to telemetry.keylatch.dev.
func New(enabled bool, sinkType string, filePath string) Sink {
	if !enabled {
		return NoopSink{}
	}
	switch sinkType {
	case "local":
		return LocalFileSink{Path: filePath}
	case "remote":
		return newRemoteSink()
	default:
		return NoopSink{}
	}
}

// ShouldEmit returns true only when telemetry is permitted by the effective
// operating-mode settings AND the kill-switch env var is not set.
//
// Kill-switch: set KEYLATCH_TELEMETRY_DISABLE=1 to suppress all telemetry
// regardless of mode configuration. This is the operator escape hatch.
func ShouldEmit(settings klruntime.EffectiveSettings) bool {
	if v := strings.ToLower(os.Getenv("KEYLATCH_TELEMETRY_DISABLE")); v == "1" || v == "true" {
		return false
	}
	return settings.TelemetryEnabled
}
