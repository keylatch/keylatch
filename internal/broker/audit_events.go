package broker

// Broker audit event action names.
// These are also defined in internal/audit/audit.go — this file provides
// typed constants for use within the broker package itself.
const (
	// ActionBrokerExchange is emitted on a fresh token exchange.
	ActionBrokerExchange = "broker.exchange"

	// ActionBrokerCacheHit is emitted on a cache hit (no exchange performed).
	ActionBrokerCacheHit = "broker.cache_hit"

	// ActionDirectRunCredentialAccess is emitted at credential-delivery in direct_classic_sandboxed mode.
	ActionDirectRunCredentialAccess = "broker.direct_run_credential_access"

	// ActionDirectRunBlocked is emitted when the LLM-session gate blocks a direct run.
	ActionDirectRunBlocked = "broker.direct_run_blocked"
)

// BrokerExchangeEvent describes a fresh exchange audit event.
// All actor and session IDs are HMAC-hashed — no raw values.
type BrokerExchangeEvent struct {
	Provider         string `json:"provider"`
	ExchangeStrategy string `json:"exchange_strategy"`
	ActorHMAC        string `json:"actor_hmac"`
	SessionIDHMAC    string `json:"session_id_hmac"`
	Namespace        string `json:"namespace"`
	Capability       string `json:"capability"`
	TTLSeconds       int64  `json:"ttl_seconds"`
	// ScopesCount is the count only — no raw scope list.
	ScopesCount int `json:"scopes_count"`
}

// BrokerCacheHitEvent describes a cache-hit audit event.
type BrokerCacheHitEvent struct {
	Provider            string `json:"provider"`
	ActorHMAC           string `json:"actor_hmac"`
	SessionIDHMAC       string `json:"session_id_hmac"`
	Capability          string `json:"capability"`
	CacheAgeSeconds     int64  `json:"cache_age_seconds"`
	TTLRemainingSeconds int64  `json:"ttl_remaining_seconds"`
}

// DirectRunCredentialAccessEvent describes a credential-delivery audit event
// for direct_classic_sandboxed mode. Emitted at the credential-delivery point only.
type DirectRunCredentialAccessEvent struct {
	Provider              string `json:"provider"`
	ActorHMAC             string `json:"actor_hmac"`
	Capability            string `json:"capability"`
	SandboxProfile        string `json:"sandbox_profile"`
	MaskingProfileApplied string `json:"masking_profile_applied"`
	BudgetRemaining       string `json:"budget_remaining"`
	TTLSecondsUsed        int64  `json:"ttl_seconds_used"`
	AllowedHostsCount     int    `json:"allowed_hosts_count"`
}

// DirectRunBlockedEvent describes a blocked direct-run audit event.
type DirectRunBlockedEvent struct {
	ActorHMAC        string `json:"actor_hmac"`
	Connection       string `json:"connection"`
	Capability       string `json:"capability"`
	RuntimeRequested string `json:"runtime_requested"`
	LLMSessionSignal bool   `json:"llm_session_signal"`
	BlockedBy        string `json:"blocked_by"`
}
