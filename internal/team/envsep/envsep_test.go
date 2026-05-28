package envsep_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/team/envsep"
)

func TestProductionMode_WriteRequiresApproval(t *testing.T) {
	cfg := envsep.RuntimeModeConfig{
		Mode:         envsep.ModeProduction,
		Dispositions: map[string]envsep.Disposition{},
	}

	err := envsep.Validate(context.Background(), cfg, "write", "production")
	if err != envsep.ErrApprovalRequired {
		t.Errorf("write in production: got %v, want ErrApprovalRequired", err)
	}
}

func TestCIMode_AuditExportRequired(t *testing.T) {
	cfg := envsep.RuntimeModeConfig{
		Mode:                envsep.ModeCI,
		Dispositions:        map[string]envsep.Disposition{},
		AuditExportRequired: true,
	}

	err := envsep.Validate(context.Background(), cfg, "read", "ci")
	if err != nil {
		t.Errorf("read in CI with audit export: got %v, want nil", err)
	}
}

func TestSignedTemplatesOnly_UnsignedDenied(t *testing.T) {
	cfg := envsep.RuntimeModeConfig{
		Mode:                envsep.ModeProduction,
		Dispositions:        map[string]envsep.Disposition{"provision": envsep.DispDeny},
		SignedTemplatesOnly: true,
	}

	err := envsep.Validate(context.Background(), cfg, "provision", "production")
	if err != envsep.ErrEnvSepDenied {
		t.Errorf("unsigned template: got %v, want ErrEnvSepDenied", err)
	}
}

func TestDisposition_GlobMatch(t *testing.T) {
	cfg := envsep.RuntimeModeConfig{
		Mode: envsep.ModeDevelopment,
		Dispositions: map[string]envsep.Disposition{
			"write.*": envsep.DispDeny,
		},
	}

	// write.secrets matches write.* → deny.
	err := envsep.Validate(context.Background(), cfg, "write.secrets", "dev")
	if err != envsep.ErrEnvSepDenied {
		t.Errorf("write.secrets: got %v, want ErrEnvSepDenied", err)
	}

	// read is not in glob → allow.
	err = envsep.Validate(context.Background(), cfg, "read", "dev")
	if err != nil {
		t.Errorf("read: got %v, want nil", err)
	}
}

func TestDevelopmentMode_AllowAll(t *testing.T) {
	cfg := envsep.RuntimeModeConfig{
		Mode:         envsep.ModeDevelopment,
		Dispositions: map[string]envsep.Disposition{},
	}

	for _, cap := range []string{"read", "write", "delete"} {
		err := envsep.Validate(context.Background(), cfg, cap, "dev")
		if err != nil {
			t.Errorf("dev mode %q: got %v, want nil", cap, err)
		}
	}
}
