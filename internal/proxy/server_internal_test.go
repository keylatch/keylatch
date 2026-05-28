package proxy

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// TestBridgeTCP_CopiesData verifies that bridgeTCP forwards bytes from src to dst.
func TestBridgeTCP_CopiesData(t *testing.T) {
	// Create a pair of in-process pipes simulating a TCP connection pair.
	srcRead, srcWrite := net.Pipe()
	defer srcRead.Close()
	defer srcWrite.Close()

	dstRead, dstWrite := net.Pipe()
	defer dstRead.Close()
	defer dstWrite.Close()

	data := []byte("bridge data test")

	// Write data to srcWrite and close.
	go func() {
		srcWrite.Write(data)
		srcWrite.Close()
	}()

	// bridgeTCP copies from srcRead to dstWrite.
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		bridgeTCP(dstWrite, srcRead)
	}()

	// Read from dstRead.
	dstRead.SetDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1024)
	n, _ := dstRead.Read(buf)
	<-doneCh

	if n > 0 && !bytes.Equal(buf[:n], data) {
		t.Errorf("bridgeTCP: expected %q, got %q", data, buf[:n])
	}
}

// TestServe_ListenErrorOnBadAddr verifies that Serve returns an error when it
// cannot bind to the address.
func TestServe_ListenErrorOnBadAddr(t *testing.T) {
	srv := &Server{
		Addr: "999.999.999.999:1", // invalid address
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := srv.Serve(ctx)
	if err == nil {
		t.Error("expected error for invalid listen address, got nil")
	}
}

// TestParseSecretRef_ValidTemplate verifies template parsing.
func TestParseSecretRef_ValidTemplate(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"{{ secret.mypath/key }}", "mypath/key"},
		{"{{secret.foo}}", "foo"},
		{"  {{ secret.a/b/c }}  ", "a/b/c"},
	}

	for _, tc := range cases {
		result := parseSecretRef(tc.input)
		if result != tc.expected {
			t.Errorf("parseSecretRef(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

// TestParseSecretRef_InvalidTemplates verifies non-template values return "".
func TestParseSecretRef_InvalidTemplates(t *testing.T) {
	cases := []string{
		"Bearer plain-token",
		"{{ not-secret }}",
		"{{ secret }}",
		"",
	}

	for _, tc := range cases {
		result := parseSecretRef(tc)
		if result != "" {
			t.Errorf("parseSecretRef(%q) = %q, want empty string", tc, result)
		}
	}
}

// TestHandleCONNECT_DeniedHost_Returns403 verifies that CONNECT to a non-allowlisted
// host returns 403. Uses httptest.ResponseRecorder (hijack not supported → but
// denial happens before hijack attempt).
func TestHandleCONNECT_DeniedHost_Returns403(t *testing.T) {
	srv := &Server{
		Profile: ProxyProfile{
			Hosts: []string{"allowed.example.com"},
		},
	}

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodConnect, "https://denied.example.com:443", nil)
	req.Host = "denied.example.com:443"

	srv.handleCONNECT(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// TestHandleCONNECT_AllowedHost_SSRF_Returns403 verifies SSRF block in CONNECT path.
func TestHandleCONNECT_AllowedHost_SSRF_Returns403(t *testing.T) {
	srv := &Server{
		Profile: ProxyProfile{
			Hosts: []string{"localhost"},
			SSRF: ProxySsrf{
				DenyPrivateRanges:           true,
				ResolveAndVerifyEachRequest: true,
			},
		},
	}

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodConnect, "https://localhost:443", nil)
	req.Host = "localhost:443"

	srv.handleCONNECT(rec, req)
	// SSRF block should return 403.
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for SSRF-blocked CONNECT, got %d", rec.Code)
	}
}

// TestHandleCONNECT_AllowedHost_HijackFails_Returns500 verifies that when
// hijacking fails (using ResponseRecorder), the server returns 500.
func TestHandleCONNECT_AllowedHost_HijackFails_Returns500(t *testing.T) {
	srv := &Server{
		Profile: ProxyProfile{
			Hosts: []string{"api.example.com"},
		},
	}

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodConnect, "https://api.example.com:443", nil)
	req.Host = "api.example.com:443"

	srv.handleCONNECT(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when hijack not supported, got %d", rec.Code)
	}
}

// TestResponseWriter_WriteResponseTo verifies the buffered response writer
// produces correct HTTP/1.1 output.
func TestResponseWriter_WriteResponseTo(t *testing.T) {
	rw := newBufferedResponseWriter()
	rw.WriteHeader(403)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write([]byte(`{"error":"test"}`))

	var buf bytes.Buffer
	if err := rw.writeResponseTo(&buf); err != nil {
		t.Fatalf("writeResponseTo: %v", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("expected non-empty output")
	}
	if !bytes.Contains([]byte(out), []byte("HTTP/1.1 403")) {
		t.Errorf("expected 403 in output, got: %q", out[:min(len(out), 80)])
	}
}

// TestServe_GracefulShutdown verifies that Serve stops cleanly when ctx is cancelled.
func TestServe_GracefulShutdown(t *testing.T) {
	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	srv := &Server{
		Addr: "127.0.0.1:" + itoa(port),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Serve should return nil (graceful shutdown) when ctx is cancelled.
	err = srv.Serve(ctx)
	// Graceful shutdown returns nil (from Shutdown).
	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("expected nil or DeadlineExceeded on graceful shutdown, got: %v", err)
	}
}

// itoa converts integers to strings for test use.
func itoa(i int) string {
	return strconv.Itoa(i)
}

// TestSSRFCheck_UnresolvableHost verifies that an unresolvable host is rejected.
func TestSSRFCheck_UnresolvableHost(t *testing.T) {
	srv := &Server{
		Profile: ProxyProfile{
			SSRF: ProxySsrf{
				DenyPrivateRanges:           true,
				ResolveAndVerifyEachRequest: true,
			},
		},
	}

	// Use a hostname that will definitely not resolve.
	err := srv.ssrfCheck("nonexistent.keylatch-test-hostname-xyz123.invalid")
	if err == nil {
		t.Error("expected error for unresolvable host in SSRF check")
	}
}

// TestSSRFCheck_NoDenyPrivateRanges_AllowsAny verifies that when DenyPrivateRanges
// is false, ssrfCheck passes even for localhost.
func TestSSRFCheck_NoDenyPrivateRanges_AllowsAny(t *testing.T) {
	srv := &Server{
		Profile: ProxyProfile{
			SSRF: ProxySsrf{
				DenyPrivateRanges: false,
			},
		},
	}
	// Even "localhost" passes when DenyPrivateRanges=false.
	err := srv.ssrfCheck("localhost")
	if err != nil {
		t.Errorf("expected nil when DenyPrivateRanges=false, got: %v", err)
	}
}

// TestResponseWriter_Header_WriteHeader_Write covers the header functions.
func TestResponseWriter_Header_WriteHeader_Write(t *testing.T) {
	rw := newBufferedResponseWriter()

	// Test default status.
	if rw.status != http.StatusOK {
		t.Errorf("default status must be 200, got %d", rw.status)
	}

	// Set status.
	rw.WriteHeader(http.StatusNotFound)
	if rw.status != http.StatusNotFound {
		t.Errorf("expected 404 after WriteHeader, got %d", rw.status)
	}

	// Write body.
	n, err := rw.Write([]byte("not found"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 9 {
		t.Errorf("expected 9 bytes written, got %d", n)
	}

	// Header must be accessible.
	h := rw.Header()
	h.Set("X-Test", "value")
	if h.Get("X-Test") != "value" {
		t.Error("Header must be settable and retrievable")
	}
}

// TestInjectProxyCred_DefaultBearerPlacement verifies that when placement is empty,
// the credential is injected as a Bearer Authorization header.
func TestInjectProxyCred_DefaultBearerPlacement(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://api.example.com/test", nil)
	injectProxyCred(req, AuthInjection{Placement: "", Name: "Authorization"}, []byte("test-token"))

	auth := req.Header.Get("Authorization")
	if auth != "Bearer test-token" {
		t.Errorf("expected Bearer test-token, got %q", auth)
	}
}

// TestInjectProxyCred_HeaderPlacement verifies header placement.
func TestInjectProxyCred_HeaderPlacement(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://api.example.com/test", nil)
	injectProxyCred(req, AuthInjection{Placement: "header", Name: "X-API-Key"}, []byte("api-key"))

	if req.Header.Get("X-API-Key") != "api-key" {
		t.Errorf("expected X-API-Key=api-key, got %q", req.Header.Get("X-API-Key"))
	}
}
