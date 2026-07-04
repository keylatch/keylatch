package api_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReceipts_GET_Returns200JSON verifies that GET /v1/receipts returns 200 and
// application/json Content-Type for an empty store.
func TestReceipts_GET_Returns200JSON(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(100)
	h := api.NewReceiptsHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	_, ok := resp["receipts"]
	assert.True(t, ok, "response must contain a 'receipts' key")
}

// TestReceipts_GET_LimitParam verifies that ?limit=N caps the result set.
func TestReceipts_GET_LimitParam(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(100)
	// Push 10 receipts.
	for i := 0; i < 10; i++ {
		store.Push(runner.RuntimeReceipt{Provider: "anthropic", Capability: "chat", PolicyDecision: "allowed"})
	}

	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts?limit=5", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Receipts []map[string]interface{} `json:"receipts"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Len(t, body.Receipts, 5, "?limit=5 must return exactly 5 receipts")
}

// TestReceipts_GET_LimitDefault verifies that the default limit is 20.
func TestReceipts_GET_LimitDefault(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(100)
	// Push 25 receipts.
	for i := 0; i < 25; i++ {
		store.Push(runner.RuntimeReceipt{Provider: "openai", Capability: "embed", PolicyDecision: "allowed"})
	}

	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Receipts []map[string]interface{} `json:"receipts"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Len(t, body.Receipts, 20, "default limit must return 20 receipts")
}

// TestReceipts_GET_LimitInvalid verifies that a non-numeric limit returns 400.
func TestReceipts_GET_LimitInvalid(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	h := api.NewReceiptsHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts?limit=abc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestReceipts_GET_LimitCappedAt100 verifies that ?limit=200 is clamped to 100.
func TestReceipts_GET_LimitCappedAt100(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(200)
	// Seed 150 receipts.
	for i := 0; i < 150; i++ {
		store.Push(runner.RuntimeReceipt{Provider: "openai", Capability: "embed", PolicyDecision: "allowed"})
	}

	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts?limit=200", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Receipts []map[string]interface{} `json:"receipts"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Len(t, body.Receipts, 100, "limit=200 must be clamped to 100")
}

// TestPushReceiptsHandler verifies that POST /v1/receipts stores the receipt.
func TestPushReceiptsHandler(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	h := api.NewPushReceiptsHandler(store)

	receipt := runner.RuntimeReceipt{
		Runtime:  "direct_classic",
		ExitCode: 0,
		Provider: "openrouter",
	}
	body, _ := json.Marshal(receipt)
	req := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	got := store.Last(1)
	if len(got) != 1 || got[0].Runtime != "direct_classic" {
		t.Fatalf("receipt not stored: %+v", got)
	}
}

// TestPushReceiptsHandler_MethodNotAllowed verifies that non-POST methods are rejected.
func TestPushReceiptsHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	h := api.NewPushReceiptsHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestPushReceiptsHandler_BadBody verifies that malformed JSON returns 400.
func TestPushReceiptsHandler_BadBody(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	h := api.NewPushReceiptsHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/v1/receipts", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestReceiptsPOST_RejectsForeignUID verifies that POST /v1/receipts is rejected
// with 401 when the X-Keylatch-IPC-Secret header is absent or incorrect
// (peer-cred check). This prevents foreign UIDs or unprivileged
// processes from injecting fake receipts into the UI dashboard.
func TestReceiptsPOST_RejectsForeignUID(t *testing.T) {
	t.Parallel()

	const correctSecret = "correct-ipc-secret-hex-abcdef1234567890"

	store := api.NewReceiptStore(10)
	h := api.NewPushReceiptsHandlerWithSecret(store, correctSecret)

	body := []byte(`{"runtime":"gateway_typed","provider":"openai","capability":"chat","policy_decision":"allowed"}`)

	// Case 1: no secret header — must be rejected.
	t.Run("missing_secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code, "missing IPC secret must return 401")
		assert.Empty(t, store.Last(10), "no receipts must be stored on rejection")
	})

	// Case 2: wrong secret — must be rejected.
	t.Run("wrong_secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Keylatch-IPC-Secret", "wrong-secret-from-foreign-uid")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code, "wrong IPC secret must return 401")
		assert.Empty(t, store.Last(10), "no receipts must be stored on rejection")
	})

	// Case 3: correct secret — must succeed.
	t.Run("correct_secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Keylatch-IPC-Secret", correctSecret)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusNoContent, rr.Code, "correct IPC secret must return 204")
		got := store.Last(1)
		require.Len(t, got, 1, "receipt must be stored after successful push")
		assert.Equal(t, "gateway_typed", got[0].Runtime)
	})
}

// ── canonical test suite ─────────────────────────────────────────────

// TestReceipts_GETJSON verifies basic JSON response shape for GET /v1/receipts.
func TestReceipts_GETJSON(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	store.Push(runner.RuntimeReceipt{
		Runtime:        "gateway_typed",
		Provider:       "anthropic",
		Capability:     "messages",
		PolicyDecision: "allowed",
	})

	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body struct {
		Receipts []struct {
			Runtime        string `json:"runtime"`
			Provider       string `json:"provider"`
			Capability     string `json:"capability"`
			PolicyDecision string `json:"policy_decision"`
		} `json:"receipts"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Len(t, body.Receipts, 1)
	assert.Equal(t, "gateway_typed", body.Receipts[0].Runtime)
	assert.Equal(t, "anthropic", body.Receipts[0].Provider)
	assert.Equal(t, "messages", body.Receipts[0].Capability)
	assert.Equal(t, "allowed", body.Receipts[0].PolicyDecision)
}

// TestReceipts_GETLimit verifies that ?limit=5 returns at most 5 receipts.
func TestReceipts_GETLimit(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(100)
	for i := 0; i < 15; i++ {
		store.Push(runner.RuntimeReceipt{Provider: "openai", Capability: "embed", PolicyDecision: "allowed"})
	}

	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts?limit=5", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Receipts []map[string]interface{} `json:"receipts"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Len(t, body.Receipts, 5, "?limit=5 must return at most 5 receipts")
}

// TestReceipts_SSEEmitsOnPush verifies that pushing a receipt triggers an SSE
// "receipt" event that the client receives within a reasonable timeout.
func TestReceipts_SSEEmitsOnPush(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	h := api.NewReceiptsStreamHandler(store)

	// Use a real HTTP server so we can stream the response incrementally.
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/receipts/stream") //nolint:noctx // test-only
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	// Read events on a goroutine so we can push a receipt concurrently.
	lines := make(chan string, 64)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()

	// Wait for the initial heartbeat to confirm the connection is established.
	deadline := time.After(3 * time.Second)
	heartbeatSeen := false
	for !heartbeatSeen {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatal("SSE stream closed before heartbeat")
			}
			if strings.HasPrefix(line, "event: heartbeat") {
				heartbeatSeen = true
			}
		case <-deadline:
			t.Fatal("timeout waiting for SSE heartbeat")
		}
	}

	// Push a receipt — the SSE stream must emit it.
	want := runner.RuntimeReceipt{
		Runtime:        "gateway_typed",
		Provider:       "anthropic",
		Capability:     "messages",
		PolicyDecision: "allowed",
	}
	store.Push(want)

	// Look for the "event: receipt" line within 3 seconds.
	deadline = time.After(3 * time.Second)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatal("SSE stream closed before receipt event")
			}
			if strings.HasPrefix(line, "event: receipt") {
				// Consume the next "data:" line.
				select {
				case dataLine := <-lines:
					assert.True(t, strings.HasPrefix(dataLine, "data:"), "expected data line, got: %q", dataLine)
					jsonPart := strings.TrimPrefix(dataLine, "data: ")
					var got map[string]interface{}
					require.NoError(t, json.Unmarshal([]byte(jsonPart), &got))
					assert.Equal(t, "anthropic", got["provider"])
					assert.Equal(t, "messages", got["capability"])
				case <-time.After(2 * time.Second):
					t.Fatal("timeout waiting for SSE data line after event")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for SSE receipt event after Push")
		}
	}
}

// TestReceipts_NeverContainsCredentialBytes verifies that the GET /v1/receipts
// response only contains the approved projected fields. The canary is
// injected as the Provider value — a projected field — to confirm the projection
// pipeline is active and actually serving data. It then verifies that no
// unapproved credential-key names appear in the response body.
//
// Design rationale: RuntimeReceipt has no "value" or "secret" field, so the
// meaningful invariant to test is that (a) the response is not vacuously empty
// and (b) no credential-key names exist in any serialised key position.
func TestReceipts_NeverContainsCredentialBytes(t *testing.T) {
	t.Parallel()

	// Canary injected as Provider — a projected field — so the response is
	// non-vacuous: the canary MUST appear in "provider" (it is safe metadata),
	// proving the handler actually serialised the receipt through the view.
	const canary = "sk-test-canary-provider-slug-abcdef123456"

	store := api.NewReceiptStore(10)
	store.Push(runner.RuntimeReceipt{
		Runtime:         "gateway_typed",
		Provider:        canary, // injected into a projected field
		Capability:      "messages",
		PolicyDecision:  "allowed",
		CredentialShape: "bearer",
		ExitCode:        0,
	})

	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Canary MUST appear in the "provider" field — proves projection is live
	// and not returning an empty or stub response.
	assert.True(t, strings.Contains(body, canary),
		"canary injected as provider slug must appear in projected response — handler returned no data")

	// No credential-key names must appear in any serialised key position.
	for _, kw := range []string{`"value":`, `"secret":`, `"password":`, `"api_key":`, `"credential_value":`} {
		assert.False(t, strings.Contains(body, kw),
			"credential field key %q must not appear in receipt JSON", kw)
	}

	// Additionally verify the response only contains the approved projected keys.
	approvedKeys := []string{`"runtime"`, `"provider"`, `"capability"`, `"policy_decision"`, `"credential_shape"`, `"exit_code"`, `"ttl"`, `"receipts"`}
	// Parse into a generic structure to inspect keys.
	var envelope map[string]interface{}
	require.NoError(t, json.NewDecoder(strings.NewReader(body)).Decode(&envelope))
	receiptsRaw, ok := envelope["receipts"].([]interface{})
	require.True(t, ok, "response must have a 'receipts' array")
	require.Len(t, receiptsRaw, 1, "expected exactly one receipt in response")

	receiptMap, ok := receiptsRaw[0].(map[string]interface{})
	require.True(t, ok, "each receipt entry must be a JSON object")

	approvedSet := make(map[string]bool)
	for _, k := range approvedKeys {
		approvedSet[strings.Trim(k, `"`)] = true
	}
	for key := range receiptMap {
		assert.True(t, approvedSet[key],
			"receipt response contains unexpected key %q — only approved projected fields permitted", key)
	}
}

// TestReceipts_NoCredentialValues verifies that no credential field values appear
// in the response body.
func TestReceipts_NoCredentialValues(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(100)
	// Push a receipt with plausible-but-safe field values.
	store.Push(runner.RuntimeReceipt{
		Provider:        "anthropic",
		Capability:      "messages",
		PolicyDecision:  "allowed",
		Runtime:         "gateway_typed",
		CredentialShape: "bearer",
	})

	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	body := rec.Body.String()
	// No actual credential value should appear — credential_shape is metadata,
	// not a value. Verify that no field named "value", "secret", "token", or
	// "password" appears in any response key position.
	credentialKeywords := []string{`"value":`, `"secret":`, `"password":`, `"api_key":`, `"token":`}
	for _, kw := range credentialKeywords {
		assert.False(t, strings.Contains(body, kw),
			"response must not contain credential field %q", kw)
	}
}
