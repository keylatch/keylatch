// Package telemetry emits anonymized usage events to local or remote sinks.
package telemetry

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// SetupCompleted emits the setup_completed event. backend is the backend name
// (e.g. "keychain") — never the key value.
func SetupCompleted(ctx context.Context, sink Sink, backend string) {
	sink.Emit(ctx, Event{
		Name:      "setup_completed",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"backend": backend},
	})
}

// ConnectSucceeded emits connect_succeeded.
func ConnectSucceeded(ctx context.Context, sink Sink, provider, backend string) {
	sink.Emit(ctx, Event{
		Name:      "connect_succeeded",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"provider": provider, "backend": backend},
	})
}

// RunInvoked emits run_invoked. exitCodeClass is "success", "failure", or "error".
func RunInvoked(ctx context.Context, sink Sink, runtimeMode, exitCodeClass string) {
	sink.Emit(ctx, Event{
		Name:      "run_invoked",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"runtime_mode": runtimeMode, "exit_code_class": exitCodeClass},
	})
}

// DoctorRun emits doctor_run. overallStatus is "healthy", "warning", or "error".
func DoctorRun(ctx context.Context, sink Sink, overallStatus string) {
	sink.Emit(ctx, Event{
		Name:      "doctor_run",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"overall_status": overallStatus},
	})
}

// DaemonStarted emits daemon_started. trigger is "auto" or "manual".
func DaemonStarted(ctx context.Context, sink Sink, trigger string) {
	sink.Emit(ctx, Event{
		Name:      "daemon_started",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"trigger": trigger},
	})
}

// GuardBlocked emits guard_blocked. agent is anonymised (just the agent name, no path).
func GuardBlocked(ctx context.Context, sink Sink, agent string, count int) {
	sink.Emit(ctx, Event{
		Name:      "guard_blocked",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"agent": agent, "count": fmt.Sprintf("%d", count)},
	})
}

// ErrorOccurred emits error_occurred. klCode is the KL-XXXX error code — no values.
func ErrorOccurred(ctx context.Context, sink Sink, klCode string) {
	sink.Emit(ctx, Event{
		Name:      "error_occurred",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"kl_code": klCode},
	})
}

// GatewayRequestCompleted emits gateway_request_completed.
// outcome: "allowed" | "denied". provider: provider name (no credentials).
func GatewayRequestCompleted(ctx context.Context, sink Sink, provider, outcome string, durationMS int64) {
	sink.Emit(ctx, Event{
		Name:      "gateway_request_completed",
		Timestamp: time.Now().UTC(),
		Fields: map[string]string{
			"provider":    provider,
			"outcome":     outcome,
			"duration_ms": strconv.FormatInt(durationMS, 10),
		},
	})
}

// VaultError emits vault_error. backend: backend name. klCode: KL-XXXX error code if available.
func VaultError(ctx context.Context, sink Sink, backend string) {
	sink.Emit(ctx, Event{
		Name:      "vault_error",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"backend": backend},
	})
}

// TokenMinted emits token_minted.
func TokenMinted(ctx context.Context, sink Sink, runtime string) {
	sink.Emit(ctx, Event{
		Name:      "token_minted",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"runtime": runtime},
	})
}
