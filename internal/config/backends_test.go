package config

import (
	"strings"
	"testing"
)

func TestBackendCredentialsConfig(t *testing.T) {
	load := func(backends string) error {
		_, err := LoadBytes("config.json", []byte(`{"version":1,"backend":"file","backends":`+backends+`}`))
		return err
	}
	if err := load(`{"vault":{"credential_ref":"prod.vault-1"},"awssm":{"allow_env_credentials":true}}`); err != nil {
		t.Fatalf("valid backends rejected: %v", err)
	}
	for backends, want := range map[string]string{
		`{"file":{"credential_ref":"x"}}`:              "not a backend that takes credentials",
		`{"vault":{"credential_ref":"../escape"}}`:     "credential_ref",
		`{"vault":{"credential_ref":"has space"}}`:     "credential_ref",
		`{"vault":{"credential_token":"unknown-key"}}`: "unknown field",
	} {
		err := load(backends)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("backends %s: error = %v, want %q", backends, err, want)
		}
	}
	if BackendID("aws-sm") != "awssm" || BackendID("op-connect") != "opconnect" || BackendID("vault") != "vault" {
		t.Error("BackendID does not map registry names to config ids")
	}
}
