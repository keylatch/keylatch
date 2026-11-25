package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

type testInfo struct {
	Listen string `json:"listen"`
}

func (h *mintHarness) get(path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.srv.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

func newInfoHarness(t *testing.T) *mintHarness {
	t.Helper()
	return newMintHarnessInfo(t, testMintPolicy, true, testInfo{Listen: "10.0.2.2:7878"})
}

func TestInfo_Route(t *testing.T) {
	h := newInfoHarness(t)
	if w := h.get(InfoPath, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := h.get(InfoPath, "not-a-token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", w.Code)
	}
	for _, jwt := range []string{h.jwt, h.noCapJW} {
		w := h.get(InfoPath, jwt)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"listen":"10.0.2.2:7878"`) {
			t.Fatalf("valid token (any capability): %d %s", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("info must not be cached")
		}
	}
	if w := h.postInfo(); w.Code == http.StatusOK {
		t.Fatal("only GET is served")
	}
}

func TestInfo_AbsentUnlessConfigured(t *testing.T) {
	h := newMintHarness(t, testMintPolicy, true)
	if w := h.get(InfoPath, h.jwt); w.Code == http.StatusOK {
		t.Fatalf("/info must be absent without Info, got %d", w.Code)
	}
}

func TestInfo_SourceAllowlistRunsFirst(t *testing.T) {
	h := newInfoHarness(t)
	h.srv.httpSrv.Handler = h.srv.allowSourceMiddleware(h.srv.httpSrv.Handler, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	w := h.get(InfoPath, h.jwt)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "source_not_allowed") {
		t.Fatalf("outside the allowlist: %d %s", w.Code, w.Body.String())
	}
}

func (h *mintHarness) postInfo() *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+InfoPath, nil)
	req.Header.Set("Authorization", "Bearer "+h.jwt)
	w := httptest.NewRecorder()
	h.srv.httpSrv.Handler.ServeHTTP(w, req)
	return w
}
