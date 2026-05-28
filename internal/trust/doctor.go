package trust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ReportRow is the probe result for a single registered root type.
type ReportRow struct {
	// Type is the RootType that was probed.
	Type RootType `json:"type"`

	// Available indicates whether the adapter was reachable.
	Available bool `json:"available"`

	// Capabilities lists the capability names the adapter reports as supported.
	// Only populated when Available is true.
	Capabilities []string `json:"capabilities,omitempty"`

	// Error is a non-sensitive description of the failure, when Available is false.
	Error string `json:"error,omitempty"`
}

// Report is the result of a Doctor probe across all registered adapters.
type Report struct {
	Rows []ReportRow `json:"rows"`
}

// JSON serialises the report as compact JSON.
// The output is value-free (no key material, pins, or passphrases).
func (r Report) JSON() []byte {
	b, _ := json.Marshal(r)
	return b
}

// String returns a human-readable table representation of the report.
// The output is value-free.
func (r Report) String() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%-20s %-9s %s\n", "TYPE", "AVAILABLE", "CAPABILITIES / ERROR")
	fmt.Fprintf(&buf, "%s\n", strings.Repeat("-", 70))
	for _, row := range r.Rows {
		if row.Available {
			caps := strings.Join(row.Capabilities, ",")
			if caps == "" {
				caps = "(none)"
			}
			fmt.Fprintf(&buf, "%-20s %-9s %s\n", row.Type, "yes", caps)
		} else {
			errStr := row.Error
			if errStr == "" {
				errStr = "unavailable"
			}
			fmt.Fprintf(&buf, "%-20s %-9s %s\n", row.Type, "no", errStr)
		}
	}
	return buf.String()
}

// capabilityNames maps each Capability flag to its string name.
var capabilityNames = []struct {
	cap  Capability
	name string
}{
	{CapWrap, "wrap"},
	{CapSignChallenge, "sign_challenge"},
	{CapUserPresence, "user_presence"},
	{CapHardwareBound, "hardware_bound"},
	{CapLaunchdSafe, "launchd_safe"},
	{CapAttestation, "attestation"},
	{CapMTLSClientAuth, "mtls_client_auth"},
}

// Doctor probes every registered adapter type and returns a Report.
// A probe is attempted with a zero-value RootSpec for each available type.
// Sensitive data MUST NOT appear in any ReportRow field.
func Doctor(ctx context.Context) Report {
	types := Available()
	rows := make([]ReportRow, 0, len(types))

	for _, t := range types {
		spec := RootSpec{Type: t, Status: RootActive}
		row := ReportRow{Type: t}

		root, err := New(spec)
		if err != nil {
			row.Available = false
			row.Error = sanitiseError(err)
			rows = append(rows, row)
			continue
		}

		row.Available = true
		for _, cn := range capabilityNames {
			if root.Has(cn.cap) {
				row.Capabilities = append(row.Capabilities, cn.name)
			}
		}
		rows = append(rows, row)
		_ = root.Close() // explicit close; not deferred to avoid leak inside loop
	}

	return Report{Rows: rows}
}

// sanitiseError returns a non-sensitive string representation of an error.
// Never returns the error's underlying message verbatim if it might contain paths
// with key material.
func sanitiseError(err error) string {
	if err == nil {
		return ""
	}
	// Return value-free sentinel descriptions.
	switch {
	case isErrType(err, ErrRootUnavailable):
		return "unavailable"
	case isErrType(err, ErrCapabilityUnsupported):
		return "capability unsupported"
	case isErrType(err, ErrRootRevoked):
		return "revoked"
	case isErrType(err, ErrRootExpired):
		return "expired"
	default:
		return "probe failed"
	}
}

func isErrType(err, target error) bool {
	return errors.Is(err, target)
}
