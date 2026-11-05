package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
)

type trRequest struct {
	Method    string
	Path      string
	Query     string
	Token     string
	Namespace string
	Body      string
}

type trFakeVault struct {
	t        *testing.T
	mu       sync.Mutex
	reqs     []trRequest
	token    string
	handlers map[string]http.HandlerFunc
}

func trNewFakeVault(t *testing.T) (*trFakeVault, *httptest.Server) {
	t.Helper()
	fv := &trFakeVault{t: t, token: "tok-" + strings.Repeat("x", 8), handlers: map[string]http.HandlerFunc{}}
	srv := httptest.NewServer(http.HandlerFunc(fv.serve))
	t.Cleanup(srv.Close)
	return fv, srv
}

func (fv *trFakeVault) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	fv.mu.Lock()
	fv.reqs = append(fv.reqs, trRequest{
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Token:     r.Header.Get("X-Vault-Token"),
		Namespace: r.Header.Get("X-Vault-Namespace"),
		Body:      string(body),
	})
	h, ok := fv.handlers[r.Method+" "+r.URL.Path]
	fv.mu.Unlock()
	if ok {
		h(w, r)
		return
	}
	if r.URL.Path == "/v1/auth/approle/login" || r.URL.Path == "/v1/auth/cert/login" {
		_, _ = io.WriteString(w, `{"auth":{"client_token":"`+fv.token+`"}}`)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (fv *trFakeVault) handle(methodPath string, h http.HandlerFunc) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	fv.handlers[methodPath] = h
}

func (fv *trFakeVault) requests() []trRequest {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	return append([]trRequest(nil), fv.reqs...)
}

func (fv *trFakeVault) last(path string) (trRequest, bool) {
	rs := fv.requests()
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].Path == path {
			return rs[i], true
		}
	}
	return trRequest{}, false
}

func trAppRoleAdapter(t *testing.T, addr string) *Adapter {
	t.Helper()
	a, err := New(Options{
		Addr:           addr,
		AuthMethod:     "approle",
		Namespace:      "team-a",
		TransitKeyName: "kek",
		RoleID:         "role-1",
		SecretID:       "sec-" + strings.Repeat("s", 6),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestWrapSendsBase64PlaintextAndZerosDEK(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("POST /v1/transit/encrypt/kek", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"ciphertext":"vault:v1:abc"}}`)
	})
	a := trAppRoleAdapter(t, srv.URL)

	dek := []byte("0123456789abcdef")
	out, err := a.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if string(out) != "vault:v1:abc" {
		t.Fatalf("ciphertext = %q", out)
	}
	for i, b := range dek {
		if b != 0 {
			t.Fatalf("dek[%d] not zeroed", i)
		}
	}

	login, ok := fv.last("/v1/auth/approle/login")
	if !ok {
		t.Fatal("no approle login request")
	}
	var creds map[string]string
	if err := json.Unmarshal([]byte(login.Body), &creds); err != nil {
		t.Fatalf("login body not JSON: %v (%q)", err, login.Body)
	}
	if creds["role_id"] != "role-1" || creds["secret_id"] != "sec-ssssss" {
		t.Fatalf("login creds = %v", creds)
	}
	if login.Namespace != "team-a" || login.Token != "" {
		t.Fatalf("login headers: ns=%q token=%q", login.Namespace, login.Token)
	}

	enc, _ := fv.last("/v1/transit/encrypt/kek")
	if enc.Token != fv.token || enc.Namespace != "team-a" {
		t.Fatalf("encrypt headers: token=%q ns=%q", enc.Token, enc.Namespace)
	}
	want := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	if !strings.Contains(enc.Body, want) {
		t.Fatalf("encrypt body %q missing %q", enc.Body, want)
	}
}

func TestUnwrapDecodesPlaintext(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("POST /v1/transit/decrypt/kek", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"plaintext":"`+base64.StdEncoding.EncodeToString([]byte("dek-bytes"))+`"}}`)
	})
	a := trAppRoleAdapter(t, srv.URL)

	dek, err := a.Unwrap(context.Background(), []byte("vault:v1:abc"))
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(dek) != "dek-bytes" {
		t.Fatalf("dek = %q", dek)
	}
	req, _ := fv.last("/v1/transit/decrypt/kek")
	if !strings.Contains(req.Body, `"ciphertext":"vault:v1:abc"`) {
		t.Fatalf("decrypt body = %q", req.Body)
	}
}

func TestSignReturnsVaultSignature(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("POST /v1/transit/sign/kek", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"signature":"vault:v1:sig"}}`)
	})
	a := trAppRoleAdapter(t, srv.URL)

	sig, pub, err := a.Sign(context.Background(), []byte("challenge"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(sig) != "vault:v1:sig" || pub != nil {
		t.Fatalf("sig=%q pub=%v", sig, pub)
	}
	req, _ := fv.last("/v1/transit/sign/kek")
	if !strings.Contains(req.Body, base64.StdEncoding.EncodeToString([]byte("challenge"))) {
		t.Fatalf("sign body = %q", req.Body)
	}
}

func TestTransitOperationErrors(t *testing.T) {
	type op struct {
		name string
		path string
		call func(a *Adapter) error
	}
	ops := []op{
		{"wrap", "/v1/transit/encrypt/kek", func(a *Adapter) error {
			_, err := a.Wrap(context.Background(), []byte("k"))
			return err
		}},
		{"unwrap", "/v1/transit/decrypt/kek", func(a *Adapter) error {
			_, err := a.Unwrap(context.Background(), []byte("c"))
			return err
		}},
		{"sign", "/v1/transit/sign/kek", func(a *Adapter) error {
			_, _, err := a.Sign(context.Background(), []byte("c"))
			return err
		}},
	}
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"server error sanitized", http.StatusForbidden, "permission\x00 denied\x1b", "(status 403): permission denied"},
		{"missing field", http.StatusOK, `{"data":{}}`, "no "},
	}
	for _, o := range ops {
		for _, tc := range cases {
			t.Run(o.name+"/"+tc.name, func(t *testing.T) {
				fv, srv := trNewFakeVault(t)
				fv.handle("POST "+o.path, func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
				})
				err := o.call(trAppRoleAdapter(t, srv.URL))
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("err = %v, want substring %q", err, tc.want)
				}
			})
		}
	}
}

func TestUnwrapRejectsInvalidBase64(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("POST /v1/transit/decrypt/kek", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"plaintext":"!!!not-base64"}}`)
	})
	_, err := trAppRoleAdapter(t, srv.URL).Unwrap(context.Background(), []byte("c"))
	if err == nil || !strings.Contains(err.Error(), "decode plaintext") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthFailurePropagates(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("POST /v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"errors":["invalid role ID"]}`)
	})
	a := trAppRoleAdapter(t, srv.URL)
	ctx := context.Background()

	checks := map[string]error{}
	_, checks["wrap"] = a.Wrap(ctx, []byte("k"))
	_, checks["unwrap"] = a.Unwrap(ctx, []byte("c"))
	_, _, checks["sign"] = a.Sign(ctx, []byte("c"))
	_, checks["get"] = a.Get(ctx, "k")
	checks["set"] = a.Set(ctx, "k", []byte("v"))
	checks["delete"] = a.Delete(ctx, "k")
	_, checks["list"] = a.List(ctx, "p")
	for name, err := range checks {
		if err == nil || !strings.Contains(err.Error(), "auth failed (status 400)") || !strings.Contains(err.Error(), "invalid role ID") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for _, r := range fv.requests() {
		if !strings.HasPrefix(r.Path, "/v1/auth/") {
			t.Fatalf("unexpected request after failed auth: %s %s", r.Method, r.Path)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close should swallow auth errors, got %v", err)
	}
}

func TestAuthResponseWithoutToken(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("POST /v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"auth":{}}`)
	})
	_, err := trAppRoleAdapter(t, srv.URL).Wrap(context.Background(), []byte("k"))
	if err == nil || !strings.Contains(err.Error(), "no client_token") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthAgainstClosedServer(t *testing.T) {
	_, srv := trNewFakeVault(t)
	a := trAppRoleAdapter(t, srv.URL)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	a.opts.Addr = deadURL
	_, err := a.Wrap(context.Background(), []byte("k"))
	if err == nil || !strings.Contains(err.Error(), "approle auth") {
		t.Fatalf("auth against dead server: err = %v", err)
	}
}

func TestTransportErrorsWrapRootUnavailable(t *testing.T) {
	_, srv := trNewFakeVault(t)
	a := trAppRoleAdapter(t, srv.URL)
	a.httpClient.Transport = &trFailAfterAuth{base: http.DefaultTransport}
	ctx := context.Background()

	errs := map[string]error{}
	_, errs["wrap"] = a.Wrap(ctx, []byte("k"))
	_, errs["unwrap"] = a.Unwrap(ctx, []byte("c"))
	_, _, errs["sign"] = a.Sign(ctx, []byte("c"))
	_, errs["get"] = a.Get(ctx, "k")
	errs["set"] = a.Set(ctx, "k", []byte("v"))
	errs["delete"] = a.Delete(ctx, "k")
	_, errs["list"] = a.List(ctx, "p")
	for name, err := range errs {
		if !errors.Is(err, trust.ErrRootUnavailable) {
			t.Errorf("%s: err = %v, want ErrRootUnavailable", name, err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// trFailAfterAuth lets auth logins through and fails every other request at the transport.
type trFailAfterAuth struct{ base http.RoundTripper }

func (f *trFailAfterAuth) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.URL.Path, "/v1/auth/approle/") {
		return f.base.RoundTrip(r)
	}
	return nil, errors.New("connection refused")
}

func TestKVGetSetDeleteList(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("GET /v1/secret/data/app/db", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"data":{"value":"dg=="}}}`)
	})
	fv.handle("POST /v1/secret/data/app/db", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	fv.handle("DELETE /v1/secret/metadata/app/db", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	fv.handle("GET /v1/secret/metadata/app", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") != "true" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"keys":["db","cache/"]}}`)
	})
	a := trAppRoleAdapter(t, srv.URL)
	ctx := context.Background()

	got, err := a.Get(ctx, "app/db")
	if err != nil || string(got) != `{"data":{"data":{"value":"dg=="}}}` {
		t.Fatalf("Get = %q, %v", got, err)
	}

	if err := a.Set(ctx, "app/db", []byte("v")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	setReq, _ := fv.last("/v1/secret/data/app/db")
	var payload struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(setReq.Body), &payload); err != nil || payload.Data.Value != "dg==" {
		t.Fatalf("Set body = %q (%v)", setReq.Body, err)
	}
	if setReq.Token != fv.token {
		t.Fatalf("Set token = %q", setReq.Token)
	}

	if err := a.Delete(ctx, "app/db"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if r, ok := fv.last("/v1/secret/metadata/app/db"); !ok || r.Method != http.MethodDelete {
		t.Fatalf("Delete request = %+v", r)
	}

	keys, err := a.List(ctx, "app")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if strings.Join(keys, ",") != "db,cache/" {
		t.Fatalf("keys = %v", keys)
	}
}

func TestKVGetErrors(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("GET /v1/secret/data/boom", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "internal")
	})
	a := trAppRoleAdapter(t, srv.URL)

	if _, err := a.Get(context.Background(), "missing"); err == nil || err.Error() != "vault: key not found" {
		t.Fatalf("missing key: err = %v", err)
	}
	if _, err := a.Get(context.Background(), "boom"); err == nil || !strings.Contains(err.Error(), "kv get failed (status 500): internal") {
		t.Fatalf("server error: err = %v", err)
	}
}

func TestKVListNonOKAndBadJSON(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	fv.handle("GET /v1/secret/metadata/bad", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{not json`)
	})
	a := trAppRoleAdapter(t, srv.URL)

	keys, err := a.List(context.Background(), "absent")
	if err != nil || keys != nil {
		t.Fatalf("non-OK list = %v, %v; want nil, nil", keys, err)
	}
	if _, err := a.List(context.Background(), "bad"); err == nil || !strings.Contains(err.Error(), "parse list response") {
		t.Fatalf("bad JSON: err = %v", err)
	}
}

func TestCloseRevokesToken(t *testing.T) {
	fv, srv := trNewFakeVault(t)
	revoked := make(chan string, 1)
	fv.handle("POST /v1/auth/token/revoke-self", func(w http.ResponseWriter, r *http.Request) {
		revoked <- r.Header.Get("X-Vault-Token")
		w.WriteHeader(http.StatusNoContent)
	})
	a := trAppRoleAdapter(t, srv.URL)
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case tok := <-revoked:
		if tok != fv.token {
			t.Fatalf("revoked token = %q", tok)
		}
	default:
		t.Fatal("revoke-self not called")
	}
}

func TestInvalidAddrRequestErrors(t *testing.T) {
	a, err := New(Options{Addr: "http://bad host\x7f", AuthMethod: "approle", TransitKeyName: "k"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Wrap(context.Background(), []byte("k")); err == nil || !strings.Contains(err.Error(), "approle auth request") {
		t.Fatalf("err = %v", err)
	}
	a.opts.AuthMethod = "mtls"
	if _, err := a.Wrap(context.Background(), []byte("k")); err == nil || !strings.Contains(err.Error(), "mtls auth request") {
		t.Fatalf("err = %v", err)
	}
	if err := a.revokeToken(context.Background(), "t"); err == nil {
		t.Fatal("revokeToken with invalid addr should fail")
	}
}

func TestControlCharInKeyNameFailsRequestBuild(t *testing.T) {
	_, srv := trNewFakeVault(t)
	a := trAppRoleAdapter(t, srv.URL)
	a.opts.TransitKeyName = "k\x7f"
	ctx := context.Background()

	if _, err := a.Wrap(ctx, []byte("k")); err == nil || !strings.Contains(err.Error(), "wrap request") {
		t.Errorf("wrap: %v", err)
	}
	if _, err := a.Unwrap(ctx, []byte("c")); err == nil || !strings.Contains(err.Error(), "unwrap request") {
		t.Errorf("unwrap: %v", err)
	}
	if _, _, err := a.Sign(ctx, []byte("c")); err == nil || !strings.Contains(err.Error(), "sign request") {
		t.Errorf("sign: %v", err)
	}
	if _, err := a.Get(ctx, "k\x7f"); err == nil || !strings.Contains(err.Error(), "get request") {
		t.Errorf("get: %v", err)
	}
	if err := a.Set(ctx, "k\x7f", nil); err == nil || !strings.Contains(err.Error(), "set request") {
		t.Errorf("set: %v", err)
	}
	if err := a.Delete(ctx, "k\x7f"); err == nil || !strings.Contains(err.Error(), "delete request") {
		t.Errorf("delete: %v", err)
	}
	if _, err := a.List(ctx, "k\x7f"); err == nil || !strings.Contains(err.Error(), "list request") {
		t.Errorf("list: %v", err)
	}
}
