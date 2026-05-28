package api

// T-13-05: Server-validated approval-ttl endpoint.
// EPIC-27: Extended with operating mode, telemetry kill-switch, experimental
//          opt-in, and approval policy default.
//
// GET  /api/settings → full settings response
// PUT  /api/settings → partial update (any subset of fields)
//
// Security invariant: the client cannot set a TTL above approval_ttl_max_seconds.
// A client submitting 999999 receives back the clamped value (≤ max).

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
)

const (
	// DefaultApprovalTTLSeconds is the initial approval TTL (60 s).
	DefaultApprovalTTLSeconds = 60

	// DefaultApprovalTTLMaxSeconds is the server-enforced upper bound (1 h).
	DefaultApprovalTTLMaxSeconds = 3600
)

// OperatingModeValue enumerates the valid operating modes.
// standard — default production mode
// telemetry — same as standard, plus usage telemetry
// canary — opt-in pre-release features (advanced)
// custom — fully custom configuration (advanced)
type OperatingModeValue string

const (
	OperatingModeStandard  OperatingModeValue = "standard"
	OperatingModeTelemetry OperatingModeValue = "telemetry"
	OperatingModeCanary    OperatingModeValue = "canary"
	OperatingModeCustom    OperatingModeValue = "custom"
)

// validOperatingModes is the set of accepted mode strings.
var validOperatingModes = map[OperatingModeValue]bool{
	OperatingModeStandard:  true,
	OperatingModeTelemetry: true,
	OperatingModeCanary:    true,
	OperatingModeCustom:    true,
}

// ApprovalPolicyValue enumerates the valid approval policy defaults.
// trust     — auto-approve all agent requests
// first-run — approve once per session; deny subsequent requests
// prompt    — always prompt the user (default)
type ApprovalPolicyValue string

const (
	ApprovalPolicyTrust    ApprovalPolicyValue = "trust"
	ApprovalPolicyFirstRun ApprovalPolicyValue = "first-run"
	ApprovalPolicyPrompt   ApprovalPolicyValue = "prompt"
)

// validApprovalPolicies is the set of accepted policy strings.
var validApprovalPolicies = map[ApprovalPolicyValue]bool{
	ApprovalPolicyTrust:    true,
	ApprovalPolicyFirstRun: true,
	ApprovalPolicyPrompt:   true,
}

// SettingsStore holds the mutable settings state.
// It is safe for concurrent use by multiple goroutines.
type SettingsStore struct {
	mu               sync.RWMutex
	ttlSeconds       int
	maxTTLSeconds    int
	advancedMode     bool
	operatingMode    OperatingModeValue
	telemetryDisable bool
	experimental     bool
	approvalPolicy   ApprovalPolicyValue
}

// NewSettingsStore returns a SettingsStore with default values.
func NewSettingsStore() *SettingsStore {
	return &SettingsStore{
		ttlSeconds:       DefaultApprovalTTLSeconds,
		maxTTLSeconds:    DefaultApprovalTTLMaxSeconds,
		advancedMode:     false,
		operatingMode:    OperatingModeStandard,
		telemetryDisable: false,
		experimental:     false,
		approvalPolicy:   ApprovalPolicyPrompt,
	}
}

// GetTTL returns the current approval TTL and max TTL.
func (s *SettingsStore) GetTTL() (ttl, max int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ttlSeconds, s.maxTTLSeconds
}

// SetTTL sets the approval TTL, clamping to [1, max].
// Returns the clamped ttl and the current max under the same lock acquisition,
// eliminating the TOCTOU race that would arise from calling GetTTL() separately.
func (s *SettingsStore) SetTTL(requested int) (ttl, max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if requested < 1 {
		requested = 1
	}
	if requested > s.maxTTLSeconds {
		requested = s.maxTTLSeconds
	}
	s.ttlSeconds = requested
	return s.ttlSeconds, s.maxTTLSeconds
}

// GetAdvancedMode returns the current advanced mode toggle state.
func (s *SettingsStore) GetAdvancedMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.advancedMode
}

// SetAdvancedMode sets the advanced mode toggle state and returns the stored value.
// Returning the stored value avoids a separate GetAdvancedMode() call (which would
// require a second lock acquisition and introduce a race window).
func (s *SettingsStore) SetAdvancedMode(enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advancedMode = enabled
	return s.advancedMode
}

// GetOperatingMode returns the current operating mode.
func (s *SettingsStore) GetOperatingMode() OperatingModeValue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.operatingMode
}

// SetOperatingMode sets the operating mode and returns the stored value.
// Returns an error string if the mode is not in validOperatingModes.
func (s *SettingsStore) SetOperatingMode(mode OperatingModeValue) (OperatingModeValue, bool) {
	if !validOperatingModes[mode] {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operatingMode = mode
	return s.operatingMode, true
}

// GetTelemetryDisable returns whether the telemetry kill-switch is active.
func (s *SettingsStore) GetTelemetryDisable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.telemetryDisable
}

// SetTelemetryDisable sets the telemetry kill-switch and returns the stored value.
// In-process mutation: os.Setenv/os.Unsetenv is called so that internal/telemetry/sink.go
// (which reads KEYLATCH_TELEMETRY_DISABLE directly) sees the change immediately.
// Note: this mutates the current process environment. Set the environment variable
// directly for persistence across restarts.
func (s *SettingsStore) SetTelemetryDisable(disabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telemetryDisable = disabled
	if disabled {
		_ = os.Setenv("KEYLATCH_TELEMETRY_DISABLE", "1")
	} else {
		_ = os.Unsetenv("KEYLATCH_TELEMETRY_DISABLE")
	}
	return s.telemetryDisable
}

// GetExperimental returns the experimental opt-in flag.
func (s *SettingsStore) GetExperimental() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.experimental
}

// SetExperimental sets the experimental opt-in flag and returns the stored value.
// In-process mutation: os.Setenv/os.Unsetenv is called so that internal/cli/experimental.go
// (which reads KEYLATCH_EXPERIMENTAL directly) sees the change immediately.
// Note: this mutates the current process environment. Set the environment variable
// directly for persistence across restarts.
func (s *SettingsStore) SetExperimental(enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.experimental = enabled
	if enabled {
		_ = os.Setenv("KEYLATCH_EXPERIMENTAL", "1")
	} else {
		_ = os.Unsetenv("KEYLATCH_EXPERIMENTAL")
	}
	return s.experimental
}

// GetApprovalPolicy returns the current approval policy default.
func (s *SettingsStore) GetApprovalPolicy() ApprovalPolicyValue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.approvalPolicy
}

// SetApprovalPolicy sets the approval policy default and returns the stored value.
// Returns false if the policy is not in validApprovalPolicies.
func (s *SettingsStore) SetApprovalPolicy(policy ApprovalPolicyValue) (ApprovalPolicyValue, bool) {
	if !validApprovalPolicies[policy] {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approvalPolicy = policy
	return s.approvalPolicy, true
}

// SettingsHandler handles GET /api/settings and PUT /api/settings.
type SettingsHandler struct {
	Store *SettingsStore
}

// settingsResponse is the JSON shape returned by GET and PUT.
type settingsResponse struct {
	ApprovalTTLSeconds    int                 `json:"approval_ttl_seconds"`
	ApprovalTTLMaxSeconds int                 `json:"approval_ttl_max_seconds"`
	AdvancedMode          bool                `json:"advanced_mode"`
	OperatingMode         OperatingModeValue  `json:"operating_mode"`
	TelemetryDisable      bool                `json:"telemetry_disable"`
	Experimental          bool                `json:"experimental"`
	ApprovalPolicy        ApprovalPolicyValue `json:"approval_policy"`
}

// settingsPutRequest is the JSON body accepted by PUT.
type settingsPutRequest struct {
	ApprovalTTLSeconds *int                 `json:"approval_ttl_seconds"`
	AdvancedMode       *bool                `json:"advanced_mode"`
	OperatingMode      *OperatingModeValue  `json:"operating_mode"`
	TelemetryDisable   *bool                `json:"telemetry_disable"`
	Experimental       *bool                `json:"experimental"`
	ApprovalPolicy     *ApprovalPolicyValue `json:"approval_policy"`
}

func (h *SettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	store := h.Store
	if store == nil {
		// Fallback: ephemeral in-handler store (never shared; useful in tests).
		store = NewSettingsStore()
	}

	switch r.Method {
	case http.MethodGet:
		ttl, max := store.GetTTL()
		writeJSON(w, settingsResponse{
			ApprovalTTLSeconds:    ttl,
			ApprovalTTLMaxSeconds: max,
			AdvancedMode:          store.GetAdvancedMode(),
			OperatingMode:         store.GetOperatingMode(),
			TelemetryDisable:      store.GetTelemetryDisable(),
			Experimental:          store.GetExperimental(),
			ApprovalPolicy:        store.GetApprovalPolicy(),
		})

	case http.MethodPut:
		var req settingsPutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: invalid JSON", http.StatusBadRequest)
			return
		}
		// At least one field must be present.
		if req.ApprovalTTLSeconds == nil && req.AdvancedMode == nil &&
			req.OperatingMode == nil && req.TelemetryDisable == nil &&
			req.Experimental == nil && req.ApprovalPolicy == nil {
			http.Error(w, "bad request: at least one settings field is required", http.StatusBadRequest)
			return
		}
		ttl, max := store.GetTTL()
		if req.ApprovalTTLSeconds != nil {
			ttl, max = store.SetTTL(*req.ApprovalTTLSeconds)
		}
		advancedMode := store.GetAdvancedMode()
		if req.AdvancedMode != nil {
			advancedMode = store.SetAdvancedMode(*req.AdvancedMode)
		}
		operatingMode := store.GetOperatingMode()
		if req.OperatingMode != nil {
			stored, ok := store.SetOperatingMode(*req.OperatingMode)
			if !ok {
				http.Error(w, "bad request: invalid operating_mode value", http.StatusBadRequest)
				return
			}
			operatingMode = stored
		}
		telemetryDisable := store.GetTelemetryDisable()
		if req.TelemetryDisable != nil {
			telemetryDisable = store.SetTelemetryDisable(*req.TelemetryDisable)
		}
		experimental := store.GetExperimental()
		if req.Experimental != nil {
			experimental = store.SetExperimental(*req.Experimental)
		}
		approvalPolicy := store.GetApprovalPolicy()
		if req.ApprovalPolicy != nil {
			stored, ok := store.SetApprovalPolicy(*req.ApprovalPolicy)
			if !ok {
				http.Error(w, "bad request: invalid approval_policy value", http.StatusBadRequest)
				return
			}
			approvalPolicy = stored
		}
		writeJSON(w, settingsResponse{
			ApprovalTTLSeconds:    ttl,
			ApprovalTTLMaxSeconds: max,
			AdvancedMode:          advancedMode,
			OperatingMode:         operatingMode,
			TelemetryDisable:      telemetryDisable,
			Experimental:          experimental,
			ApprovalPolicy:        approvalPolicy,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
