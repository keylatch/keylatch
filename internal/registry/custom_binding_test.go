package registry

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func validCustom() CustomBinding {
	h := []string{"api.billing.internal.example:443"}
	return CustomBinding{
		Hosts: h,
		Slots: []Slot{{Field: "api_key", In: SlotHeader, Name: "Authorization", Scheme: "Bearer", Hosts: h}},
		Shape: PlaceholderShape{MinLength: DefaultCustomMinLength},
		Env:   map[string]string{"api_key": "BILLING_API_KEY"},
	}
}

func TestCustomBindingValidate(t *testing.T) {
	if err := validCustom().Validate("billing-internal", []string{"api_key"}); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	cases := map[string]func(*CustomBinding){
		"bare star":          func(c *CustomBinding) { c.Hosts = []string{"*"}; c.Slots[0].Hosts = c.Hosts },
		"star with port":     func(c *CustomBinding) { c.Hosts = []string{"*:443"}; c.Slots[0].Hosts = c.Hosts },
		"wildcard apex":      func(c *CustomBinding) { c.Hosts = []string{"*.com"}; c.Slots[0].Hosts = c.Hosts },
		"wildcard suffix":    func(c *CustomBinding) { c.Hosts = []string{"*.co.uk"}; c.Slots[0].Hosts = c.Hosts },
		"exact suffix":       func(c *CustomBinding) { c.Hosts = []string{"co.uk"}; c.Slots[0].Hosts = c.Hosts },
		"mid wildcard":       func(c *CustomBinding) { c.Hosts = []string{"api.*.example.com"}; c.Slots[0].Hosts = c.Hosts },
		"slot outside hosts": func(c *CustomBinding) { c.Slots[0].Hosts = []string{"evil.example:443"} },
		"no slots":           func(c *CustomBinding) { c.Slots = nil },
		"no hosts":           func(c *CustomBinding) { c.Hosts = nil; c.Slots[0].Hosts = nil },
		"no shape":           func(c *CustomBinding) { c.Shape.MinLength = 0 },
		"no env":             func(c *CustomBinding) { c.Env = nil },
		"bad env name":       func(c *CustomBinding) { c.Env = map[string]string{"api_key": "A B"} },
		"unknown env field":  func(c *CustomBinding) { c.Env = map[string]string{"other": "X"} },
		"unknown slot field": func(c *CustomBinding) { c.Slots[0].Field = "other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validCustom()
			mutate(&c)
			if err := c.Validate("billing-internal", []string{"api_key"}); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestCustomBindingWidenedBy(t *testing.T) {
	base := validCustom()
	wider := validCustom()
	wider.Hosts = append(wider.Hosts, "other.example:443")
	if !base.WidenedBy(wider) || wider.WidenedBy(base) {
		t.Fatal("added host must widen, removing it must not")
	}
	slot := validCustom()
	slot.Slots = append(slot.Slots, Slot{Field: "api_key", In: SlotHeader, Name: "X-Api-Key", Hosts: base.Hosts})
	if !base.WidenedBy(slot) {
		t.Fatal("added slot must widen")
	}
}

func TestParseSlot(t *testing.T) {
	s, err := ParseSlot("header:Authorization:Bearer")
	if err != nil || s.In != SlotHeader || s.Name != "Authorization" || s.Scheme != "Bearer" || s.Field != "" {
		t.Fatalf("got %+v, %v", s, err)
	}
	s, err = ParseSlot("token=query:key")
	if err != nil || s.Field != "token" || s.In != SlotQuery || s.Name != "key" {
		t.Fatalf("got %+v, %v", s, err)
	}
	s, err = ParseSlot("basic:password")
	if err != nil || s.In != SlotBasic || s.Part != BasicPassword {
		t.Fatalf("got %+v, %v", s, err)
	}
	for _, bad := range []string{"", "cookie:a", "header", "query:a:b", "basic"} {
		if _, err := ParseSlot(bad); err == nil {
			t.Errorf("ParseSlot(%q) accepted", bad)
		}
	}
}

func TestCustomBindingResolvesLikeTemplates(t *testing.T) {
	c := validCustom()
	b := c.Binding("billing-internal")
	if !b.AllowsHost("api.billing.internal.example:443") || b.AllowsHost("evil.example:443") {
		t.Fatal("host matching wrong")
	}
	if got := b.SlotsFor("api_key", "api.billing.internal.example:443"); len(got) != 1 {
		t.Fatalf("slots = %v", got)
	}
	if b.Env["api_key"] != "BILLING_API_KEY" {
		t.Fatalf("env = %v", b.Env)
	}
}

func TestCustomSlotMatchesCurlAndNodeClients(t *testing.T) {
	c := validCustom()
	slot := c.Slots[0]
	placeholder := c.Shape.Wrap("klph_abc")

	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := slot.Extract(r)
		if !ok {
			v = "<none>"
		}
		got <- v
	}))
	defer srv.Close()

	// curl -H "Authorization: Bearer $KEY": canonical header casing
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if v := <-got; v != placeholder {
		t.Fatalf("curl-style client: got %q", v)
	}

	// Node fetch/undici: lowercase header name on the wire
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw := "GET / HTTP/1.1\r\nhost: x\r\nauthorization: Bearer " + placeholder + "\r\nconnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if v := <-got; v != placeholder {
		t.Fatalf("node-style client: got %q", v)
	}
}

func TestSlotExtractRejectsOtherPositions(t *testing.T) {
	slot := validCustom().Slots[0]
	for name, h := range map[string]http.Header{
		"wrong scheme": {"Authorization": {"Basic abc"}},
		"no value":     {"Authorization": {"Bearer "}},
		"other header": {"X-Api-Key": {"Bearer abc"}},
	} {
		r := &http.Request{Header: h}
		if v, ok := slot.Extract(r); ok {
			t.Errorf("%s: extracted %q", name, v)
		}
	}
	q, _ := http.NewRequest(http.MethodGet, "http://x/?key=abc", nil)
	if v, ok := (Slot{In: SlotQuery, Name: "key"}).Extract(q); !ok || v != "abc" {
		t.Errorf("query slot: %q %v", v, ok)
	}
	b, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	b.SetBasicAuth("u", "p")
	if v, ok := (Slot{In: SlotBasic, Part: BasicPassword}).Extract(b); !ok || v != "p" {
		t.Errorf("basic slot: %q %v", v, ok)
	}
}

func TestNoBindingFix(t *testing.T) {
	if NoBindingReason != "no_binding" || !strings.Contains(NoBindingFix("svc"), "keylatch connect svc --provider custom --host") {
		t.Fatal(NoBindingFix("svc"))
	}
}

func TestCustomBindingTemplateFeedsThePlaceholderTier(t *testing.T) {
	tmpl := validCustom().Template("billing-internal", []string{"api_key"})
	b, ok := tmpl.Binding()
	if !ok || len(b.Slots) != 1 || !b.AllowsHost("api.billing.internal.example:443") {
		t.Fatalf("binding = %+v ok=%v", b, ok)
	}
	if tmpl.Provider != "billing-internal" || tmpl.Category != CustomCategory || len(tmpl.SecretFields) != 1 {
		t.Fatalf("template = %+v", tmpl)
	}
	if len(tmpl.InjectionRules) != 1 || tmpl.InjectionRules[0] != (InjectionRule{EnvVar: "BILLING_API_KEY", Source: "api_key"}) {
		t.Fatalf("rules = %+v", tmpl.InjectionRules)
	}
}
