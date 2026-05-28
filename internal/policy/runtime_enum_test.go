package policy

import (
	"strings"
	"testing"
)

func TestValidateRuntimeMode(t *testing.T) {
	type tc struct {
		input   string
		wantErr bool
		wantMsg string // substring expected in error
	}
	cases := []tc{
		// Valid modes.
		{input: "gateway_typed", wantErr: false},
		{input: "gateway_sdk", wantErr: false},
		{input: "direct_brokered", wantErr: false},
		{input: "direct_classic", wantErr: false},
		{input: "gateway_proxy", wantErr: false},
		// Removed modes — must mention migration table.
		{input: "direct_run", wantErr: true, wantMsg: "migration table"},
		{input: "local_gateway", wantErr: true, wantMsg: "migration table"},
		{input: "hosted_gateway", wantErr: true, wantMsg: "migration table"},
		// Planned but not yet available — must mention 0.2.0 and direct_classic.
		{input: "direct_classic_sandboxed", wantErr: true, wantMsg: "0.2.0"},
		// Unknown string.
		{input: "some_future_mode", wantErr: true, wantMsg: "not a valid runtime mode"},
		{input: "", wantErr: true, wantMsg: "not a valid runtime mode"},
	}

	for _, c := range cases {
		err := ValidateRuntimeMode(c.input)
		if c.wantErr && err == nil {
			t.Errorf("ValidateRuntimeMode(%q): want error, got nil", c.input)
			continue
		}
		if !c.wantErr && err != nil {
			t.Errorf("ValidateRuntimeMode(%q): want nil error, got %v", c.input, err)
			continue
		}
		if c.wantErr && c.wantMsg != "" && !strings.Contains(err.Error(), c.wantMsg) {
			t.Errorf("ValidateRuntimeMode(%q): error %q does not contain %q", c.input, err.Error(), c.wantMsg)
		}
	}
}
