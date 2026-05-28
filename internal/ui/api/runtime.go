package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/runtime"
)

// uiValidRuntimeModes lists the v1.0.0 runtime modes surfaced in the UI.
// direct_classic and direct_classic_sandboxed are removed in v1.0.0 (T-10-03).
var uiValidRuntimeModes = map[runtime.RuntimeMode]bool{
	runtime.RuntimeGatewayTyped:   true,
	runtime.RuntimeGatewaySDK:     true,
	runtime.RuntimeDirectBrokered: true,
	runtime.RuntimeGatewayProxy:   true,
}

// RuntimeTestHandler handles POST /api/connections/{name}/test.
type RuntimeTestHandler struct {
	Store connections.Store
}

func (h *RuntimeTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Runtime string `json:"runtime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	mode := runtime.RuntimeMode(req.Runtime)
	if req.Runtime != "" && !uiValidRuntimeModes[mode] {
		http.Error(w, "invalid runtime mode", http.StatusBadRequest)
		return
	}

	// Extract connection name from path: /api/connections/{name}/test
	path := strings.TrimPrefix(r.URL.Path, "/api/connections/")
	name := strings.TrimSuffix(path, "/test")
	provider, account := parseConnectionName(name)
	if provider == "" {
		http.Error(w, "connection is required", http.StatusBadRequest)
		return
	}
	if h.Store == nil {
		http.Error(w, "connection store unavailable", http.StatusServiceUnavailable)
		return
	}

	result, err := connections.Test(r.Context(), provider, account, defaultConnectionNamespace, h.Store, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

// DoctorHandler handles GET /api/runtime/doctor/{connection} and
// GET /api/doctor?connection=<provider>&json=true (T-14-07).
//
// Exit code mapping (mirroring the CLI exit codes):
//
//	0 → all checks pass (green)
//	1 → at least one warning (yellow)
//	2 → at least one hard failure (red)
type DoctorHandler struct{}

func (h *DoctorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read optional ?connection= filter.  When present, only checks whose Section
	// contains the provider name (case-insensitive) are returned.  This prevents
	// N cards firing identical global-scope doctor runs and receiving redundant data.
	connectionFilter := strings.TrimSpace(r.URL.Query().Get("connection"))

	report, err := doctor.Run(r.Context(), doctor.Options{
		Verbose:     false,
		RedactPaths: true,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Post-filter checks to the requested provider when a connection filter is supplied.
	checks := report.Checks
	sections := report.Sections
	if connectionFilter != "" {
		filterLower := strings.ToLower(connectionFilter)
		var filtered []doctor.Status
		for _, c := range report.Checks {
			if strings.Contains(strings.ToLower(c.Section), filterLower) ||
				strings.Contains(strings.ToLower(c.Name), filterLower) {
				filtered = append(filtered, c)
			}
		}
		// Fall back to the full check list when no checks match the filter
		// (avoids returning an empty list for providers with no dedicated checks).
		if len(filtered) > 0 {
			checks = filtered
		}

		// Re-filter sections similarly.
		var filteredSections []doctor.SectionSummary
		for _, s := range report.Sections {
			if strings.Contains(strings.ToLower(s.Name), filterLower) {
				filteredSections = append(filteredSections, s)
			}
		}
		if len(filteredSections) > 0 {
			sections = filteredSections
		}
	}

	// Compute exit code: 0 = ok, 1 = warnings only, 2 = errors.
	exitCode := 0
	if !report.OverallOK {
		exitCode = 2
	} else if report.HasWarnings {
		exitCode = 1
	}

	writeJSON(w, map[string]interface{}{
		"exit":     exitCode,
		"healthy":  report.OverallOK,
		"warnings": report.HasWarnings,
		"checks":   checks,
		"sections": sections,
		"version":  report.Version,
		"platform": report.Platform,
	})
}
