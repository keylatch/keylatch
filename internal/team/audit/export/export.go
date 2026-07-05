// Package export implements SIEM audit export.
//
// Security invariants:
// - SIEM export unavailability NEVER blocks local keylatch operations.
// - All exported values are HMACd — no raw emails or names.
// - Async buffered: buffer size 1000; Export never blocks.
package export

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
)

// SIEMAdapter identifies the target SIEM system.
type SIEMAdapter string

const (
	AdapterSplunk      SIEMAdapter = "splunk"
	AdapterDatadog     SIEMAdapter = "datadog"
	AdapterElastic     SIEMAdapter = "elastic"
	AdapterSumoLogic   SIEMAdapter = "sumologic"
	AdapterChronicle   SIEMAdapter = "chronicle"
	AdapterSentinelOne SIEMAdapter = "sentinelone"
	AdapterPanther     SIEMAdapter = "panther"
)

// AuditEvent is a value-free audit event for SIEM export.
// All sensitive values must be HMACd before creating an AuditEvent.
type AuditEvent struct {
	Action    string                 `json:"action"`
	Actor     string                 `json:"actor"`  // HMAC of member ID
	Target    string                 `json:"target"` // HMAC of target
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details"` // all values HMACd
}

// Exporter is an async buffered SIEM exporter.
// SIEM unavailability never blocks local operations.
type Exporter struct {
	adapter  SIEMAdapter
	endpoint string
	hmacKey  []byte // C-10: team-scoped key derived via HKDF
	buf      chan AuditEvent
	dropped  atomic.Int64
	client   *http.Client
}

// New creates an async buffered exporter. Buffer size: 1000.
// C-10: teamID is used to derive a team-scoped HMAC key via HKDF.
func New(adapter SIEMAdapter, endpoint, teamID string) *Exporter {
	// Derive team-scoped HMAC key using HKDF-SHA256.
	h := hkdf.New(sha256.New, []byte(teamID), []byte("keylatch/siem/export/v1"), nil)
	key := make([]byte, 32)
	_, _ = io.ReadFull(h, key)

	return &Exporter{
		adapter:  adapter,
		endpoint: endpoint,
		hmacKey:  key,
		buf:      make(chan AuditEvent, 1000),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Export enqueues an event for async delivery. Never blocks.
// If buffer full, drops event and increments dropped counter.
func (e *Exporter) Export(event AuditEvent) {
	select {
	case e.buf <- event:
	default:
		// Buffer full: drop and count (never block).
		e.dropped.Add(1)
	}
}

// DroppedCount returns the number of events dropped due to buffer overflow.
func (e *Exporter) DroppedCount() int64 {
	return e.dropped.Load()
}

// Flush drains the buffer synchronously (for testing and shutdown).
func (e *Exporter) Flush(ctx context.Context) error {
	for {
		select {
		case event := <-e.buf:
			if err := e.send(ctx, event); err != nil {
				// log but don't block — continue draining.
				continue
			}
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Buffer drained.
			return nil
		}
	}
}

// Start launches the background sender goroutine.
func (e *Exporter) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case event := <-e.buf:
				// send failure is silently swallowed — never blocks local ops.
				_ = e.send(ctx, event)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// send delivers a single event to the SIEM endpoint using the adapter format.
func (e *Exporter) send(ctx context.Context, event AuditEvent) error {
	var body []byte
	var contentType string
	var err error

	switch e.adapter {
	case AdapterSplunk:
		body, contentType, err = formatSplunkHEC(event, e.hmacKey)
	case AdapterDatadog:
		body, contentType, err = formatDatadog(event, e.hmacKey)
	case AdapterElastic:
		body, contentType, err = formatElastic(event, e.hmacKey)
	case AdapterSumoLogic:
		body, contentType, err = formatSumoLogic(event, e.hmacKey)
	case AdapterChronicle:
		body, contentType, err = formatChronicle(event, e.hmacKey)
	case AdapterSentinelOne:
		body, contentType, err = formatSentinelOne(event, e.hmacKey)
	case AdapterPanther:
		body, contentType, err = formatPanther(event, e.hmacKey)
	default:
		return fmt.Errorf("export: unknown adapter %q", e.adapter)
	}
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := e.client.Do(req)
	if err != nil {
		// SIEM unavailability never blocks local ops.
		return nil
	}
	defer resp.Body.Close()
	return nil
}

// hmacValue returns HMAC-SHA256 of value using the team-scoped key.
func hmacValue(value string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// hmacDetails returns a copy of details map with all string values HMACd.
// C-10: recurses into nested maps.
func hmacDetails(details map[string]interface{}, key []byte) map[string]interface{} {
	if details == nil {
		return nil
	}
	out := make(map[string]interface{}, len(details))
	for k, v := range details {
		switch vt := v.(type) {
		case string:
			out[k] = hmacValue(vt, key)
		case map[string]interface{}:
			out[k] = hmacDetails(vt, key)
		default:
			out[k] = v
		}
	}
	return out
}

// formatSplunkHEC formats an event for Splunk HEC ingestion.
func formatSplunkHEC(e AuditEvent, key []byte) ([]byte, string, error) {
	payload := map[string]interface{}{
		"event": map[string]interface{}{
			"action":    e.Action,
			"actor":     e.Actor,
			"target":    e.Target,
			"timestamp": e.Timestamp.UTC().Format(time.RFC3339),
			"details":   hmacDetails(e.Details, key),
		},
		"sourcetype": "keylatch:audit",
		"time":       e.Timestamp.Unix(),
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}

// formatDatadog formats an event for Datadog log ingestion.
func formatDatadog(e AuditEvent, key []byte) ([]byte, string, error) {
	payload := map[string]interface{}{
		"ddsource":  "keylatch",
		"ddtags":    "action:" + e.Action,
		"hostname":  "keylatch-agent",
		"message":   e.Action,
		"actor":     e.Actor,
		"target":    e.Target,
		"timestamp": e.Timestamp.UTC().Format(time.RFC3339),
		"details":   hmacDetails(e.Details, key),
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}

// formatElastic formats an event for Elasticsearch ingestion.
func formatElastic(e AuditEvent, key []byte) ([]byte, string, error) {
	payload := map[string]interface{}{
		"@timestamp": e.Timestamp.UTC().Format(time.RFC3339),
		"action":     e.Action,
		"actor":      e.Actor,
		"target":     e.Target,
		"details":    hmacDetails(e.Details, key),
		"source":     "keylatch",
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}

// formatSumoLogic formats an event for Sumo Logic ingestion.
func formatSumoLogic(e AuditEvent, key []byte) ([]byte, string, error) {
	payload := map[string]interface{}{
		"timestamp": e.Timestamp.UTC().Format(time.RFC3339),
		"action":    e.Action,
		"actor":     e.Actor,
		"target":    e.Target,
		"details":   hmacDetails(e.Details, key),
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}

// formatChronicle formats an event for Google Chronicle ingestion.
func formatChronicle(e AuditEvent, key []byte) ([]byte, string, error) {
	payload := map[string]interface{}{
		"events": []map[string]interface{}{
			{
				"timestamp": e.Timestamp.UTC().Format(time.RFC3339Nano),
				"metadata": map[string]interface{}{
					"event_type": e.Action,
				},
				"actor": map[string]interface{}{
					"user": map[string]interface{}{
						"userid": e.Actor,
					},
				},
				"target": map[string]interface{}{
					"resource": map[string]interface{}{
						"name": e.Target,
					},
				},
				"additional": hmacDetails(e.Details, key),
			},
		},
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}

// formatSentinelOne formats an event for SentinelOne ingestion.
func formatSentinelOne(e AuditEvent, key []byte) ([]byte, string, error) {
	payload := map[string]interface{}{
		"event_type": e.Action,
		"actor_id":   e.Actor,
		"target_id":  e.Target,
		"timestamp":  e.Timestamp.UTC().Format(time.RFC3339),
		"details":    hmacDetails(e.Details, key),
		"source":     "keylatch",
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}

// formatPanther formats an event for Panther ingestion.
func formatPanther(e AuditEvent, key []byte) ([]byte, string, error) {
	payload := map[string]interface{}{
		"p_log_type":   "Keylatch.Audit",
		"p_event_time": e.Timestamp.UTC().Format(time.RFC3339),
		"action":       e.Action,
		"actor":        e.Actor,
		"target":       e.Target,
		"details":      hmacDetails(e.Details, key),
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}
