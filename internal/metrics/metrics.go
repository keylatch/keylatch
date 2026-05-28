// Package metrics provides the MetricsCollector type for process-lifetime
// counters shared between the gateway and UI subsystems.
//
// This package has no internal dependencies and can be safely imported by
// both internal/gateway and internal/ui without creating an import cycle.
package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// MetricsCollector holds process-lifetime counters incremented by gateway,
// vault, and token subsystems.
type MetricsCollector struct {
	GatewayRequestsOK     atomic.Int64
	GatewayRequestsDenied atomic.Int64
	GatewayRequestsError  atomic.Int64
	GatewayLatencyTotalMs atomic.Int64
	VaultErrorsTotal      atomic.Int64
	TokenMintsTotal       atomic.Int64
	TokenRevokesTotal     atomic.Int64
	startTime             time.Time
}

// New creates a new MetricsCollector with the start time set to now.
func New() *MetricsCollector {
	return &MetricsCollector{startTime: time.Now()}
}

// ServeHTTP implements http.Handler and writes a Prometheus text exposition.
func (m *MetricsCollector) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	uptime := time.Since(m.startTime).Seconds()
	fmt.Fprintf(w,
		"# HELP keylatch_gateway_requests_total Gateway requests by outcome.\n"+
			"# TYPE keylatch_gateway_requests_total counter\n"+
			"keylatch_gateway_requests_total{outcome=\"ok\"} %d\n"+
			"keylatch_gateway_requests_total{outcome=\"denied\"} %d\n"+
			"keylatch_gateway_requests_total{outcome=\"error\"} %d\n"+
			"# HELP keylatch_gateway_latency_ms_total Cumulative gateway latency in milliseconds.\n"+
			"# TYPE keylatch_gateway_latency_ms_total counter\n"+
			"keylatch_gateway_latency_ms_total %d\n"+
			"# HELP keylatch_vault_errors_total Vault operation errors.\n"+
			"# TYPE keylatch_vault_errors_total counter\n"+
			"keylatch_vault_errors_total %d\n"+
			"# HELP keylatch_token_mints_total Tokens minted.\n"+
			"# TYPE keylatch_token_mints_total counter\n"+
			"keylatch_token_mints_total %d\n"+
			"# HELP keylatch_token_revokes_total Tokens revoked.\n"+
			"# TYPE keylatch_token_revokes_total counter\n"+
			"keylatch_token_revokes_total %d\n"+
			"# HELP keylatch_daemon_uptime_seconds Daemon uptime in seconds.\n"+
			"# TYPE keylatch_daemon_uptime_seconds gauge\n"+
			"keylatch_daemon_uptime_seconds %.2f\n",
		m.GatewayRequestsOK.Load(),
		m.GatewayRequestsDenied.Load(),
		m.GatewayRequestsError.Load(),
		m.GatewayLatencyTotalMs.Load(),
		m.VaultErrorsTotal.Load(),
		m.TokenMintsTotal.Load(),
		m.TokenRevokesTotal.Load(),
		uptime,
	)
}
