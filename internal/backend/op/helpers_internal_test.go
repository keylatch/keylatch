package op

import (
	"errors"
	"fmt"
	"testing"
)

func TestParsePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, conn, field string
		wantErr         bool
	}{
		{"default/openrouter/api_key", "openrouter", "api_key", false},
		{"default/conn/nested/field", "conn", "nested/field", false},
		{"conn/field", "conn", "field", false},
		{"justone", "", "", true},
	}
	for _, tc := range cases {
		conn, field, err := parsePath(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parsePath(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil || conn != tc.conn || field != tc.field {
			t.Errorf("parsePath(%q) = (%q, %q, %v), want (%q, %q)", tc.in, conn, field, err, tc.conn, tc.field)
		}
	}
}

func TestParseConnectionAccount(t *testing.T) {
	t.Parallel()
	if c, a := parseConnectionAccount("github:work"); c != "github" || a != "work" {
		t.Errorf("got (%q, %q)", c, a)
	}
	if c, a := parseConnectionAccount("github"); c != "github" || a != "" {
		t.Errorf("got (%q, %q)", c, a)
	}
}

func TestClassifyFieldType(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"api_key":      "concealed",
		"oauth_secret": "concealed",
		"my_token":     "concealed",
		"password":     "concealed",
		"username":     "string",
		"endpoint_url": "string",
	}
	for field, want := range cases {
		if got := classifyFieldType(field); got != want {
			t.Errorf("classifyFieldType(%q) = %q, want %q", field, got, want)
		}
	}
}

func TestClassifyCategory(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"oauth_token_x": "Login",
		"api_key":       "API Credential",
		"some_token":    "API Credential",
		"passphrase":    "Password",
	}
	for field, want := range cases {
		if got := classifyCategory(field); got != want {
			t.Errorf("classifyCategory(%q) = %q, want %q", field, got, want)
		}
	}
}

func TestErrAmbiguous(t *testing.T) {
	t.Parallel()
	e := ErrAmbiguous{Connection: "github", Count: 2}
	if e.Error() == "" {
		t.Error("ErrAmbiguous.Error empty")
	}
	wrapped := fmt.Errorf("outer: %w", e)
	if !isErrAmbiguous(wrapped) {
		t.Error("isErrAmbiguous must unwrap")
	}
	if isErrAmbiguous(errors.New("other")) {
		t.Error("isErrAmbiguous false positive")
	}
}
