package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type ccTransportFunc func(*http.Request) (*http.Response, error)

func (f ccTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ccShareTransport routes the default HTTP client through fn for one test.
func ccShareTransport(t *testing.T, fn ccTransportFunc) {
	t.Helper()
	old := http.DefaultClient.Transport
	http.DefaultClient.Transport = fn
	t.Cleanup(func() { http.DefaultClient.Transport = old })
}

func TestCCSharePublic_Responses(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		netErr  error
		wantOut string
		wantErr string
	}{
		{name: "created", status: 201, body: `{"url":"https://keylatch.dev/r/abc"}`, wantOut: "Shared at: https://keylatch.dev/r/abc\n"},
		{name: "created bad json", status: 201, body: `{`, wantErr: "share: parse response"},
		{name: "rate limited", status: 429, wantErr: "share: rate limited"},
		{name: "too large", status: 413, wantErr: "share: receipt too large"},
		{name: "server error", status: 503, wantErr: "share: server error (503)"},
		{name: "network", netErr: errors.New("dial refused"), wantErr: "dial refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sent map[string]string
			var target string
			ccShareTransport(t, func(r *http.Request) (*http.Response, error) {
				target = r.Method + " " + r.URL.String()
				b, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(b, &sent)
				if tc.netErr != nil {
					return nil, tc.netErr
				}
				return &http.Response{
					StatusCode: tc.status,
					Body:       io.NopCloser(strings.NewReader(tc.body)),
					Header:     http.Header{},
					Request:    r,
				}, nil
			})

			out, _, err := ccRun(t, "y\n", "share", "openai", "--public")
			if target != "POST https://share.keylatch.dev/v1/receipts" {
				t.Fatalf("request = %q", target)
			}
			if sent["provider_name"] != "openai" || sent["exit_code_class"] != "success" || sent["runtime_mode"] != "gateway_typed" || sent["timestamp"] == "" {
				t.Fatalf("payload = %v", sent)
			}
			if len(sent) != 5 {
				t.Fatalf("payload carries unexpected keys: %v", sent)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("share: %v", err)
			}
			if !strings.HasSuffix(out, tc.wantOut) {
				t.Fatalf("out = %q", out)
			}
		})
	}
}

func TestCCSharePublic_DeclinedSendsNothing(t *testing.T) {
	for _, answer := range []string{"n\n", "", "yes\n"} {
		called := false
		ccShareTransport(t, func(r *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected request")
		})
		out, _, err := ccRun(t, answer, "share", "openai", "--public")
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if called {
			t.Fatalf("answer %q sent a request", answer)
		}
		if !strings.Contains(out, "Continue? (y/N)") || !strings.HasSuffix(out, "Cancelled.\n") {
			t.Fatalf("answer %q out = %q", answer, out)
		}
	}
}
