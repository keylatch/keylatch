//go:build experimental

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBackendVaultInit_Validation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing addr", []string{"--transit-key", "k"}, "--addr is required"},
		{"missing transit key", []string{"--addr", "https://vault.invalid"}, "--transit-key is required"},
		{"unreadable CA file", []string{"--addr", "https://vault.invalid", "--transit-key", "k", "--ca-file", "/nonexistent/ca.pem"}, "backend vault init:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdIsolate(t)
			t.Setenv("VAULT_SECRET_ID", "")
			r := cdExec(t, newBackendVaultInitCmd(), nil, tc.args...)
			if r.e == nil || !strings.Contains(r.e.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", r.e, tc.wantErr)
			}
			if strings.Contains(r.out, "initialized") {
				t.Fatalf("must not report success: %q", r.out)
			}
		})
	}
}

func TestBackendVaultInit_SuccessIsValueFree(t *testing.T) {
	cdIsolate(t)
	secretID := "cd-secret-id-" + strings.Repeat("q", 8)
	t.Setenv("VAULT_SECRET_ID", secretID)
	r := cdExec(t, newBackendVaultInitCmd(), nil,
		"--addr", "https://vault.invalid:8200", "--transit-key", "kl-key", "--auth-method", "approle", "--role-id", "role")
	if r.e != nil {
		t.Fatalf("init: %v", r.e)
	}
	if strings.TrimSpace(r.out) != "vault backend initialized: key=kl-key auth=approle" {
		t.Fatalf("unexpected output %q", r.out)
	}
	if strings.Contains(r.out+r.err, secretID) {
		t.Fatal("secret ID must never be printed")
	}
}

func TestBackendVaultInit_SecretIDFlagOverridesEnvWithWarning(t *testing.T) {
	cdIsolate(t)
	t.Setenv("VAULT_SECRET_ID", "from-env")
	r := cdExec(t, newBackendVaultInitCmd(), nil,
		"--addr", "https://vault.invalid", "--transit-key", "k", "--auth-method", "approle", "--secret-id", "from-flag")
	if r.e != nil {
		t.Fatalf("init: %v", r.e)
	}
	if !strings.Contains(r.err, "--secret-id takes precedence over VAULT_SECRET_ID") {
		t.Fatalf("expected precedence warning, got %q", r.err)
	}
	if strings.Contains(r.out+r.err, "from-flag") || strings.Contains(r.out+r.err, "from-env") {
		t.Fatal("secret ID values must never be printed")
	}
}

func TestBackendVaultTest_Outcomes(t *testing.T) {
	cdIsolate(t)

	r := cdExec(t, newBackendVaultTestCmd(), nil)
	if r.e == nil || !strings.Contains(r.e.Error(), "--addr is required") {
		t.Fatalf("missing addr: err = %v", r.e)
	}

	r = cdExec(t, newBackendVaultTestCmd(), nil, "--addr", "https://vault.invalid", "--transit-key", "k")
	if r.e != nil || !strings.Contains(r.out, "vault backend test OK: https://vault.invalid (key=k)") {
		t.Fatalf("ok case: err=%v out=%q", r.e, r.out)
	}

	r = cdExec(t, newBackendVaultTestCmd(), nil, "--addr", "https://vault.invalid", "--auth-method", "mtls")
	if r.e != nil {
		t.Fatalf("test should not error: %v", r.e)
	}

	type res struct {
		Addr       string `json:"addr"`
		TransitKey string `json:"transit_key"`
		Available  bool   `json:"available"`
		Error      string `json:"error"`
	}
	r = cdExec(t, newBackendVaultTestCmd(), nil, "--addr", "https://vault.invalid", "--transit-key", "k", "--json")
	var got res
	if err := json.Unmarshal([]byte(r.out), &got); err != nil || !got.Available || got.Error != "" || got.Addr != "https://vault.invalid" {
		t.Fatalf("json ok: %+v (%v) raw=%q", got, err, r.out)
	}
}

func TestBackendVaultStatus_Outputs(t *testing.T) {
	cdIsolate(t)
	r := cdExec(t, newBackendVaultStatusCmd(), nil)
	if r.e != nil || !strings.Contains(r.out, "backend:     vault_transit") || !strings.Contains(r.out, "status:      unconfigured") ||
		strings.Contains(r.out, "addr:") {
		t.Fatalf("unconfigured: err=%v out=%q", r.e, r.out)
	}

	r = cdExec(t, newBackendVaultStatusCmd(), nil, "--addr", "https://v.invalid", "--transit-key", "kk")
	for _, w := range []string{"addr:        https://v.invalid", "transit-key: kk", "status:      configured"} {
		if !strings.Contains(r.out, w) {
			t.Errorf("configured output missing %q: %q", w, r.out)
		}
	}

	r = cdExec(t, newBackendVaultStatusCmd(), nil, "--addr", "https://v.invalid", "--json")
	var s map[string]string
	if err := json.Unmarshal([]byte(r.out), &s); err != nil {
		t.Fatalf("json: %v %q", err, r.out)
	}
	if s["backend"] != "vault_transit" || s["status"] != "configured" || s["addr"] != "https://v.invalid" {
		t.Fatalf("unexpected json %v", s)
	}
	if _, ok := s["transit_key"]; ok {
		t.Fatalf("empty transit key must be omitted: %v", s)
	}
}

func TestBackendCmd_Tree(t *testing.T) {
	cmd := newBackendCmd()
	r := cdExec(t, cmd, nil, "vault", "status", "--json")
	if r.e != nil || !strings.Contains(r.out, `"unconfigured"`) {
		t.Fatalf("backend vault status via group: err=%v out=%q", r.e, r.out)
	}
}
