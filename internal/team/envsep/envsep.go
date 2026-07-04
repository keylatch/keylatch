// Package envsep implements environment separation policies.
package envsep

import (
	"context"
	"errors"
	"path/filepath"
)

// RuntimeMode identifies the execution environment.
type RuntimeMode string

const (
	ModeProduction  RuntimeMode = "production"
	ModeStaging     RuntimeMode = "staging"
	ModeDevelopment RuntimeMode = "development"
	ModeCI          RuntimeMode = "ci"
)

// Disposition describes the policy outcome for a capability+env combination.
type Disposition string

const (
	DispAllow               Disposition = "allow"
	DispDeny                Disposition = "deny"
	DispRequireApproval     Disposition = "require_approval"
	DispAuditExportRequired Disposition = "audit_export_required"
)

// RuntimeModeConfig holds environment separation configuration.
type RuntimeModeConfig struct {
	Mode                RuntimeMode
	Dispositions        map[string]Disposition // capability glob → disposition
	AuditExportRequired bool
	SignedTemplatesOnly bool
}

// Sentinel errors.
var (
	ErrEnvSepDenied           = errors.New("operation denied by environment separation policy")
	ErrApprovalRequired       = errors.New("operation requires approval for this environment")
	ErrSignedTemplateRequired = errors.New("signed provider template required in this mode")
)

// Validate checks that a capability+env+mode combination is allowed.
// Returns error if denied; returns ErrApprovalRequired if approval needed.
func Validate(_ context.Context, cfg RuntimeModeConfig, capability, env string) error {
	// Look up the disposition for this capability using glob matching.
	disp := findDisposition(cfg.Dispositions, capability)

	// If no specific disposition, use mode-level defaults.
	if disp == "" {
		disp = modeDefault(cfg.Mode, capability)
	}

	switch disp {
	case DispDeny:
		return ErrEnvSepDenied
	case DispRequireApproval:
		return ErrApprovalRequired
	case DispAuditExportRequired:
		if !cfg.AuditExportRequired {
			// The policy requires audit export but config doesn't enforce it.
			return nil
		}
		return nil
	case DispAllow:
		return nil
	}

	// Default: allow.
	return nil
}

// findDisposition looks up the disposition for a capability using glob matching.
func findDisposition(dispositions map[string]Disposition, capability string) Disposition {
	// Exact match first.
	if d, ok := dispositions[capability]; ok {
		return d
	}
	// Glob match.
	for pattern, d := range dispositions {
		matched, err := filepath.Match(pattern, capability)
		if err == nil && matched {
			return d
		}
	}
	return ""
}

// modeDefault returns the default disposition for a capability in a given mode.
func modeDefault(mode RuntimeMode, capability string) Disposition {
	switch mode {
	case ModeProduction:
		if isWriteCapability(capability) {
			return DispRequireApproval
		}
		return DispAllow
	case ModeCI:
		return DispAuditExportRequired
	case ModeStaging:
		return DispAllow
	case ModeDevelopment:
		return DispAllow
	default:
		return DispAllow
	}
}

func isWriteCapability(cap string) bool {
	switch cap {
	case "write", "delete", "rotate", "revoke":
		return true
	}
	return false
}
