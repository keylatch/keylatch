package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// DefaultMaxBody is the largest request body the gateway inspects and
// forwards (10 MiB); gateway.max_body in the config overrides it.
const DefaultMaxBody int64 = 10 << 20

// blockedTokenEndpoints are provider token endpoints that agents must not call directly.
var blockedTokenEndpoints = []string{
	"/oauth/token",
	"/token",
	"/v1/tokens",
}

// bearerPattern matches Bearer-token-pattern strings in request bodies.
var bearerPattern = regexp.MustCompile(`Bearer\s+[A-Za-z0-9\-._~+/]+=*`)

// blockedQueryParams are query parameter names that agents must not supply.
var blockedQueryParams = []string{"api_key", "apikey", "access_token", "token"}

// authBlockerMiddleware intercepts outbound provider requests and rejects:
//  1. Sensitive query params (api_key, apikey, access_token, token).
//  2. Bearer-token-pattern strings in request body.
//  3. Calls to token endpoints (/oauth/token, /token, /v1/tokens).
//
// The Authorization header itself is NOT blocked here. The gateway consumes
// it as the keylatch session JWT in token.Verify, and handler.go explicitly
// strips Authorization before forwarding upstream (see "Skip auth and
// keylatch-internal headers" in gatewayHandler). Blocking Authorization at
// this layer would prevent the agent from authenticating to the gateway at
// all. Upstream credential isolation is enforced by the handler's strip-and-
// inject logic, not by this middleware.
//
// Exceptions apply only when provider template explicitly permits (allowSelfAuth=true).
//
// The whole request body, up to maxBody bytes, is inspected; a larger body is
// rejected with 413 instead of being truncated and passed on.
func authBlockerMiddleware(next http.Handler, allowSelfAuth bool, maxBody int64) http.Handler {
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowSelfAuth {
			next.ServeHTTP(w, r)
			return
		}

		// Block sensitive query params.
		q := r.URL.Query()
		for _, param := range blockedQueryParams {
			if q.Get(param) != "" {
				writeAuthBlockedError(w, "agent_supplied_credential_query_param",
					"credential query parameters must not be supplied by agent")
				return
			}
		}

		// Block Bearer-token-pattern in body.
		// Only inspect if there is a body (Content-Length > 0 or chunked).
		if r.Body != nil && r.ContentLength != 0 {
			bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
			_ = r.Body.Close()
			if err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					writeAuthBlockedStatus(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the gateway's maximum size")
					return
				}
				writeAuthBlockedStatus(w, http.StatusBadRequest, "body_read_error", "failed to read request body")
				return
			}

			if bearerPattern.Match(bodyBytes) {
				writeAuthBlockedError(w, "bearer_token_in_body",
					"Bearer token pattern detected in request body — credentials must not be included by agent")
				return
			}

			// Restore body for downstream handlers.
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// Block calls to token endpoints.
		path := r.URL.Path
		for _, ep := range blockedTokenEndpoints {
			if path == ep || strings.HasSuffix(path, ep) {
				writeAuthBlockedError(w, "token_endpoint_direct_call",
					"Direct calls to token endpoints are not permitted; use the broker")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// writeAuthBlockedError writes a 403 with a value-free receipt.
func writeAuthBlockedError(w http.ResponseWriter, code, message string) {
	writeAuthBlockedStatus(w, http.StatusForbidden, code, message)
}

func writeAuthBlockedStatus(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]string{
		"error":   code,
		"message": message,
	})
	_, _ = w.Write(b)
}
