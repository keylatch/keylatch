// Package budget implements per-actor spend and action rate limits for Phase 13.
package budget

import (
	"context"
	"errors"
)

// ErrBudgetExceeded is returned when a limit is exceeded.
var ErrBudgetExceeded = errors.New("budget: limit exceeded for this actor/capability")

// BudgetPolicy defines limits for a given actor/capability combination.
type BudgetPolicy struct {
	SpendPerHour         float64
	SpendPerDay          float64
	EmailSendsPerHour    int
	SlackMessagesPerHour int
	DNSMutationsPerDay   int
	AWSActionCount       int
	StripeRefundAmount   float64
	DownloadBytesLimit   int64
}

// BudgetCounter is the interface for checking and recording budget usage.
type BudgetCounter interface {
	// CheckAndRecord atomically checks the budget and records usage in one locked
	// operation, eliminating the TOCTOU race between separate Check + Record calls (C-4).
	CheckAndRecord(ctx context.Context, actor, capability string, amount float64) error
	// Check is a read-only query — use for status display only, not enforcement.
	Check(ctx context.Context, actor, capability string, amount float64) error
	// Record increments the usage counter. Prefer CheckAndRecord for enforcement.
	Record(ctx context.Context, actor, capability string, amount float64) error
}

// BudgetDenialReceipt is the value-free receipt returned on budget denial.
// actor_hmac contains the HMAC'd actor ID — never the raw ID.
type BudgetDenialReceipt struct {
	ActorHMAC    string  `json:"actor_hmac"`
	Capability   string  `json:"capability"`
	LimitType    string  `json:"limit_type"`
	LimitValue   float64 `json:"limit_value,omitempty"`
	CurrentValue float64 `json:"current_value,omitempty"`
}
