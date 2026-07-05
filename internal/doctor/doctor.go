// Package doctor implements the `keylatch doctor` diagnostic report.
// It runs ordered checks and returns a Report with metadata-only Status values.
//
// Security invariant no secret values appear in any Status.Detail.
// Security invariant KEYLATCH_CANARY_DO_NOT_LEAK_0xDEADBEEF never appears in output.
package doctor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"runtime"
	"strings"

	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// cipherSuiteDefault is the AEAD algorithm for non-FIPS builds.
// A FIPS build tag overrides this constant at compile time.
const cipherSuiteDefault = "xchacha20-poly1305"

// Status represents the result of a single diagnostic check.
type Status struct {
	Name    string   `json:"name"`
	Section string   `json:"section"` // "environment" | "daemon" | "backends" | "providers"
	OK      bool     `json:"ok"`
	Warn    bool     `json:"warn,omitempty"`
	Detail  string   `json:"detail"`
	Fix     string   `json:"fix,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

// SectionSummary aggregates results for a single labeled section.
type SectionSummary struct {
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	HasWarn    bool   `json:"has_warn"`
	CheckCount int    `json:"check_count"`
}

// Report is the full doctor output.
type Report struct {
	Version     string           `json:"version"`
	Platform    string           `json:"platform"`
	LLMSession  bool             `json:"llm_session"`
	LLMReasons  []string         `json:"llm_reasons,omitempty"`
	Checks      []Status         `json:"checks"`
	Sections    []SectionSummary `json:"sections,omitempty"`
	OverallOK   bool             `json:"overall_ok"`
	HasWarnings bool             `json:"has_warnings"`
	CipherSuite string           `json:"cipher_suite"`
	FIPSBuild   bool             `json:"fips_build"`
}

// Options controls doctor behavior.
type Options struct {
	JSON        bool
	Verbose     bool
	RedactPaths bool
	Quiet       bool     // suppress table output; only exit code
	Categories  []string // if non-empty, only run checks whose Section matches one of these
	Env         llmcontext.Lookup
	// Probe is injected for external-binary checks. If nil, RealProbe is used.
	Probe kexec.Probe
}

// categoryMatches returns true if the normalised section matches any of the
// requested categories (already normalised to lowercase). When categories is
// empty, all checks match.
func categoryMatches(section string, categories []string) bool {
	if len(categories) == 0 {
		return true
	}
	norm := strings.ToLower(section)
	for _, c := range categories {
		if c == norm {
			return true
		}
	}
	return false
}

// Check is a function that runs a single diagnostic check.
type Check func(ctx context.Context) Status

// Run executes all diagnostic checks and returns a Report.
func Run(ctx context.Context, opts Options) (Report, error) {
	env := opts.Env
	if env == nil {
		env = llmcontext.DefaultLookup
	}

	probe := opts.Probe
	if probe == nil {
		probe = kexec.RealProbe{}
	}

	// Gather all checks in order.
	allChecks := gatherChecks(env, probe)

	// Normalise requested categories to lowercase (W8).
	var normCategories []string
	for _, c := range opts.Categories {
		normCategories = append(normCategories, strings.ToLower(strings.TrimSpace(c)))
	}

	// Validate that every requested category matches at least one known check (W8).
	// Return an error early rather than silently producing an empty report.
	if len(normCategories) > 0 {
		matched := false
		for _, nc := range allChecks {
			if categoryMatches(nc.section, normCategories) {
				matched = true
				break
			}
		}
		if !matched {
			return Report{}, fmt.Errorf("unknown category %q — valid categories: keyring, runtime, gateway, policy, external, environment, backends, daemon, providers", opts.Categories[0])
		}
	}

	// Build full list of check results for OverallOK computation.
	// Apply category filter before executing each check (W5): skip checks whose
	// declared section does not match the requested categories.
	var allStatuses []Status
	for _, nc := range allChecks {
		if !categoryMatches(nc.section, normCategories) {
			continue
		}
		s := nc.fn(ctx)
		if opts.RedactPaths {
			s.Detail = redactPathsInString(s.Detail)
			s.Fix = redactPathsInString(s.Fix)
		}
		allStatuses = append(allStatuses, s)
	}

	// Compute overallOK and hasWarnings from all check results.
	overallOK := true
	hasWarnings := false
	for _, s := range allStatuses {
		if !s.OK {
			overallOK = false
		}
		if s.Warn {
			hasWarnings = true
		}
	}

	// Choose which statuses to return based on verbose flag.
	returnedChecks := allStatuses
	if !opts.Verbose {
		returnedChecks = nil
		for _, s := range allStatuses {
			if s.OK && !s.Warn {
				continue
			}
			returnedChecks = append(returnedChecks, s)
		}
	}

	// Compute section summaries from allStatuses (always the full set).
	sections := computeSections(allStatuses)

	llmSession := llmcontext.IsLLMSession(env)
	var llmReasons []string
	if llmSession {
		llmReasons = llmcontext.Reasons(env)
	}

	return Report{
		Version:     version(),
		Platform:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		LLMSession:  llmSession,
		LLMReasons:  llmReasons,
		Checks:      returnedChecks,
		Sections:    sections,
		OverallOK:   overallOK,
		HasWarnings: hasWarnings,
		CipherSuite: CipherSuite(),
		FIPSBuild:   FIPSBuild(),
	}, nil
}

// sectionOrder defines the canonical display order for sections.
// "external" is placed after "backends" so PM CLI checks appear alongside
// credential-store backend checks.
var sectionOrder = []string{"environment", "daemon", "backends", "external", "providers"}

// computeSections builds a SectionSummary slice from allStatuses, in canonical order.
// Only sections that have at least one check appear.
func computeSections(statuses []Status) []SectionSummary {
	type sectionAcc struct {
		ok         bool
		hasWarn    bool
		checkCount int
	}
	acc := make(map[string]*sectionAcc)
	for _, s := range statuses {
		sec := s.Section
		if sec == "" {
			continue
		}
		a, exists := acc[sec]
		if !exists {
			a = &sectionAcc{ok: true}
			acc[sec] = a
		}
		a.checkCount++
		if !s.OK {
			a.ok = false
		}
		if s.Warn {
			a.hasWarn = true
		}
	}

	var result []SectionSummary
	for _, name := range sectionOrder {
		a, exists := acc[name]
		if !exists {
			continue
		}
		result = append(result, SectionSummary{
			Name:       name,
			OK:         a.ok,
			HasWarn:    a.hasWarn,
			CheckCount: a.checkCount,
		})
	}
	return result
}

// redactPathsInString replaces absolute path segments with stable hashes.
// This is a best-effort implementation for --redact-paths mode.
func redactPathsInString(s string) string {
	if s == "" {
		return s
	}
	// Hash the entire value if it looks like a path.
	if len(s) > 1 && s[0] == '/' {
		h := sha256.Sum256([]byte(s))
		return fmt.Sprintf("<redacted:%x>", h[:4])
	}
	return s
}

// CipherSuite returns the AEAD algorithm in effect for this build.
// FIPS builds override this via build tags.
func CipherSuite() string {
	return cipherSuiteDefault
}

// FIPSBuild returns true when this binary was built with -tags=fips.
func FIPSBuild() bool {
	return false
}
