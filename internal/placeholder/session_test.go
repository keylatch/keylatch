package placeholder

import (
	"net/http"
	"testing"
	"time"
)

func TestManagerGetAndSessionAccessors(t *testing.T) {
	h := newHarness(t)

	got, ok := h.mgr.Get(h.sess.ID())
	if !ok || got != h.sess {
		t.Fatalf("Get(%q) = %v, %v; want the open session", h.sess.ID(), got, ok)
	}
	if _, ok := h.mgr.Get("missing"); ok {
		t.Fatal("Get of an unknown id must report false")
	}
	if c := h.sess.Connection(); c != "stripe" {
		t.Fatalf("Connection() = %q, want stripe", c)
	}
	if ttl := h.sess.TTL(); ttl <= 0 || ttl > maxTTL {
		t.Fatalf("TTL() = %v, want within (0, %v]", ttl, maxTTL)
	}

	h.sess.Close("test")
	time.Sleep(10 * time.Millisecond)
	if _, ok := h.mgr.Get(h.sess.ID()); ok {
		t.Fatal("a closed session must be forgotten")
	}
}

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in         string
		host, port string
		ok         bool
	}{
		{"api.stripe.com:443", "api.stripe.com", "443", true},
		{"API.Stripe.com.:8443", "api.stripe.com", "8443", true},
		{"api.stripe.com", "api.stripe.com", "443", true},
		{"a:b:c", "", "", false},
		{":443", "", "443", false},
	}
	for _, c := range cases {
		host, port, ok := splitTarget(c.in)
		if host != c.host || port != c.port || ok != c.ok {
			t.Errorf("splitTarget(%q) = %q, %q, %v; want %q, %q, %v", c.in, host, port, ok, c.host, c.port, c.ok)
		}
	}
}

func TestIsUpgrade(t *testing.T) {
	cases := []struct {
		name   string
		method string
		hdr    map[string][]string
		want   bool
	}{
		{"plain get", http.MethodGet, nil, false},
		{"connect", http.MethodConnect, nil, true},
		{"upgrade header", http.MethodGet, map[string][]string{"Upgrade": {"websocket"}}, true},
		{"connection token list", http.MethodGet, map[string][]string{"Connection": {"keep-alive, Upgrade"}}, true},
		{"connection keep-alive", http.MethodGet, map[string][]string{"Connection": {"keep-alive"}}, false},
	}
	for _, c := range cases {
		r, _ := http.NewRequest(c.method, "http://example.test/", nil)
		for k, vs := range c.hdr {
			for _, v := range vs {
				r.Header.Add(k, v)
			}
		}
		if got := isUpgrade(r); got != c.want {
			t.Errorf("%s: isUpgrade = %v, want %v", c.name, got, c.want)
		}
	}
}
