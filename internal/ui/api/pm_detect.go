package api

import (
	"net/http"
	"os/exec"
	"sync"
)

// PmAvailability holds which PM CLIs are detectable on the system PATH.
// Exported so tests can construct and compare values without internal coupling.
type PmAvailability struct {
	Op         bool `json:"op"`
	AwsSM      bool `json:"aws_sm"`
	HashiVault bool `json:"hashivault"`
}

var (
	pmMu    sync.Mutex
	pmOnce  sync.Once
	pmCache PmAvailability
)

// detectPMs runs exec.LookPath for each known PM binary and caches the result.
// The cache lives for the lifetime of the UI server process (sync.Once).
func detectPMs() PmAvailability {
	pmOnce.Do(func() {
		_, opErr := exec.LookPath("op")
		_, awsErr := exec.LookPath("aws")
		_, vaultErr := exec.LookPath("vault")
		pmMu.Lock()
		pmCache = PmAvailability{
			Op:         opErr == nil,
			AwsSM:      awsErr == nil,
			HashiVault: vaultErr == nil,
		}
		pmMu.Unlock()
	})
	pmMu.Lock()
	defer pmMu.Unlock()
	return pmCache
}

// ResetPMCache resets the detection cache. Exported for use in tests only.
// Protected by pmMu to avoid a data race when tests call this concurrently.
// ResetPMCache is test-only; not safe to call concurrently with pmOnce.Do.
func ResetPMCache() {
	pmMu.Lock()
	defer pmMu.Unlock()
	pmOnce = sync.Once{}
	pmCache = PmAvailability{}
}

// PMDetectHandler handles GET /api/password-managers.
// Returns which PM CLIs are available on PATH; result is cached per session.
// Relies on the local-loopback trust model shared by all /api/ routes.
type PMDetectHandler struct {
	// detect overrides the PM detection function in tests.
	detect func() PmAvailability
}

// SetDetect injects a custom detection function (for testing).
func (h *PMDetectHandler) SetDetect(fn func() PmAvailability) {
	h.detect = fn
}

func (h *PMDetectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fn := detectPMs
	if h.detect != nil {
		fn = h.detect
	}
	writeJSON(w, fn())
}
