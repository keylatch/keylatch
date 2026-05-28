package proxy

import (
	"testing"
)

func TestParseProxyProfile_Valid(t *testing.T) {
	raw := []byte(`{
		"id": "test-profile",
		"mode": "gateway_proxy",
		"hosts": ["api.openai.com"],
		"routes": [{
			"method": "POST",
			"path": "/v1/chat/completions",
			"capability": "chat",
			"auth_injection": {"placement": "header", "name": "Authorization", "value": "{{ secret.openai/api_key }}"},
			"masking": "basic"
		}],
		"tls": {"mode": "local_ca", "ca_key_storage": "keyring"},
		"ssrf": {"deny_private_ranges": true, "resolve_and_verify_each_request": true}
	}`)

	p, err := ParseProxyProfile(raw)
	if err != nil {
		t.Fatalf("ParseProxyProfile: %v", err)
	}
	if p.ID != "test-profile" {
		t.Errorf("id mismatch: got %q", p.ID)
	}
}

func TestParseProxyProfile_InvalidTLSMode(t *testing.T) {
	raw := []byte(`{
		"id": "bad",
		"mode": "gateway_proxy",
		"hosts": ["api.example.com"],
		"tls": {"mode": "invalid_mode", "ca_key_storage": "keyring"},
		"ssrf": {}
	}`)

	_, err := ParseProxyProfile(raw)
	if err == nil {
		t.Error("expected error for invalid tls.mode")
	}
}

func TestParseProxyProfile_InvalidCAKeyStorage(t *testing.T) {
	raw := []byte(`{
		"id": "bad",
		"mode": "gateway_proxy",
		"hosts": ["api.example.com"],
		"tls": {"mode": "local_ca", "ca_key_storage": "plaintext_file"},
		"ssrf": {}
	}`)

	_, err := ParseProxyProfile(raw)
	if err == nil {
		t.Error("expected error for ca_key_storage != keyring")
	}
}

func TestValidateProxyProfile_EmptyHosts(t *testing.T) {
	p := ProxyProfile{
		Mode:  "gateway_proxy",
		Hosts: []string{},
		SSRF:  ProxySsrf{DenyPrivateRanges: true, ResolveAndVerifyEachRequest: true},
	}
	err := ValidateProxyProfile(p, nil)
	if err == nil {
		t.Error("expected error for empty hosts")
	}
}

func TestValidateProxyProfile_SSRFFlagsRequired(t *testing.T) {
	p := ProxyProfile{
		Mode:  "gateway_proxy",
		Hosts: []string{"api.openai.com"},
		SSRF:  ProxySsrf{DenyPrivateRanges: false, ResolveAndVerifyEachRequest: false},
	}
	err := ValidateProxyProfile(p, nil)
	if err == nil {
		t.Error("expected error when SSRF flags are false")
	}
}

func TestValidateProxyProfile_InvalidSecretTemplate(t *testing.T) {
	p := ProxyProfile{
		Mode:  "gateway_proxy",
		Hosts: []string{"api.openai.com"},
		Routes: []ProxyRoute{
			{
				AuthInjection: AuthInjection{Value: "{{ invalid syntax!!"},
			},
		},
		SSRF: ProxySsrf{DenyPrivateRanges: true, ResolveAndVerifyEachRequest: true},
	}
	err := ValidateProxyProfile(p, nil)
	if err == nil {
		t.Error("expected error for invalid secret template syntax")
	}
}
