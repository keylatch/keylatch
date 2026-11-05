package envsep_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/team/envsep"
	"github.com/stretchr/testify/assert"
)

func TestModeDefaults(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		mode envsep.RuntimeMode
		cap  string
		want error
	}{
		{envsep.ModeProduction, "revoke", envsep.ErrApprovalRequired},
		{envsep.ModeProduction, "delete", envsep.ErrApprovalRequired},
		{envsep.ModeProduction, "inject", nil},
		{envsep.ModeStaging, "write", nil},
		{envsep.ModeCI, "write", nil},
		{envsep.RuntimeMode("unknown"), "write", nil},
	}
	for _, tc := range cases {
		err := envsep.Validate(ctx, envsep.RuntimeModeConfig{Mode: tc.mode}, tc.cap, "")
		assert.ErrorIs(t, err, tc.want, "%s/%s", tc.mode, tc.cap)
		if tc.want == nil {
			assert.NoError(t, err, "%s/%s", tc.mode, tc.cap)
		}
	}
}

func TestExplicitDispositionsBeatModeDefaults(t *testing.T) {
	ctx := context.Background()
	cfg := envsep.RuntimeModeConfig{
		Mode: envsep.ModeProduction,
		Dispositions: map[string]envsep.Disposition{
			"write":        envsep.DispAllow,
			"export*":      envsep.DispDeny,
			"audit.*":      envsep.DispAuditExportRequired,
			"[":            envsep.DispDeny,
			"custom.thing": envsep.Disposition("unrecognised"),
		},
	}
	assert.NoError(t, envsep.Validate(ctx, cfg, "write", ""), "explicit allow overrides production approval")
	assert.ErrorIs(t, envsep.Validate(ctx, cfg, "export.all", ""), envsep.ErrEnvSepDenied)
	assert.NoError(t, envsep.Validate(ctx, cfg, "audit.read", ""))
	cfg.AuditExportRequired = true
	assert.NoError(t, envsep.Validate(ctx, cfg, "audit.read", ""))
	assert.NoError(t, envsep.Validate(ctx, cfg, "custom.thing", ""), "unknown dispositions fall through to allow")
}
