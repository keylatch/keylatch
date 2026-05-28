package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/metrics"
)

func TestNew_NonNil(t *testing.T) {
	m := metrics.New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

func TestServeHTTP_ContentType(t *testing.T) {
	m := metrics.New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type: got %q, want prefix %q", ct, "text/plain")
	}
}

func TestServeHTTP_ContainsAllMetrics(t *testing.T) {
	m := metrics.New()

	// Increment each counter so we get non-zero values in the output.
	m.GatewayRequestsOK.Add(3)
	m.GatewayRequestsDenied.Add(1)
	m.GatewayRequestsError.Add(2)
	m.GatewayLatencyTotalMs.Add(500)
	m.VaultErrorsTotal.Add(1)
	m.TokenMintsTotal.Add(10)
	m.TokenRevokesTotal.Add(4)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.ServeHTTP(rec, req)

	body := rec.Body.String()

	expectedMetrics := []string{
		"keylatch_gateway_requests_total{outcome=\"ok\"} 3",
		"keylatch_gateway_requests_total{outcome=\"denied\"} 1",
		"keylatch_gateway_requests_total{outcome=\"error\"} 2",
		"keylatch_gateway_latency_ms_total 500",
		"keylatch_vault_errors_total 1",
		"keylatch_token_mints_total 10",
		"keylatch_token_revokes_total 4",
		"keylatch_daemon_uptime_seconds",
	}
	for _, want := range expectedMetrics {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\nfull body:\n%s", want, body)
		}
	}
}

func TestServeHTTP_ZeroCounters(t *testing.T) {
	m := metrics.New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "keylatch_gateway_requests_total{outcome=\"ok\"} 0") {
		t.Errorf("expected zero counter in output\nfull body:\n%s", body)
	}
}
