package gateway

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// forwardedHeaders are the inbound headers passed to the provider. Anything
// else, notably Accept-Encoding, Range, If-Range and Cookie, is dropped:
// a compressed or partial response would reach the client without passing
// through redaction intact.
var forwardedHeaders = map[string]bool{
	"accept":               true,
	"accept-language":      true,
	"content-type":         true,
	"user-agent":           true,
	"idempotency-key":      true,
	"x-request-id":         true,
	"notion-version":       true,
	"stripe-version":       true,
	"x-github-api-version": true,
}

// forwardedHeaderPrefixes cover provider SDK headers (API version, beta
// flags, client metadata).
var forwardedHeaderPrefixes = []string{"anthropic-", "openai-", "x-stainless-"}

// credentialHeaderWords marks header names that may carry a credential even
// under an allowed prefix; the gateway injects credentials itself.
var credentialHeaderWords = []string{"key", "token", "auth", "secret", "cookie", "session", "signature", "password"}

func forwardHeader(name string) bool {
	lower := strings.ToLower(name)
	for _, w := range credentialHeaderWords {
		if strings.Contains(lower, w) {
			return false
		}
	}
	if forwardedHeaders[lower] {
		return true
	}
	for _, p := range forwardedHeaderPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// copyForwardedHeaders copies the allowed inbound headers onto the upstream
// request.
func copyForwardedHeaders(dst, src http.Header) {
	for k, vv := range src {
		if !forwardHeader(k) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

var (
	errUnsupportedEncoding = errors.New("unsupported upstream content encoding")
	errBodyTooLarge        = errors.New("upstream response exceeds the size limit")
)

// readUpstreamBody returns the upstream body decoded to plain bytes, at most
// limit of them, so redaction always sees the content the client gets.
// gzip and deflate are decoded; any other encoding is refused.
func readUpstreamBody(resp *http.Response, limit int64) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	var r io.ReadCloser
	switch enc {
	case "", "identity":
		return raw, nil
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(raw))
	case "deflate":
		// HTTP deflate is zlib-wrapped, but some servers send raw DEFLATE.
		if r, err = zlib.NewReader(bytes.NewReader(raw)); err != nil {
			r, err = flate.NewReader(bytes.NewReader(raw)), nil
		}
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedEncoding, enc)
	}
	if err != nil {
		return nil, fmt.Errorf("decode %s response: %w", enc, err)
	}
	defer func() { _ = r.Close() }()
	plain, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("decode %s response: %w", enc, err)
	}
	if int64(len(plain)) > limit {
		return nil, errBodyTooLarge
	}
	return plain, nil
}

// responseHeadersDroppedAfterDecode no longer describe the body the gateway
// writes once it is decoded and redacted.
var responseHeadersDroppedAfterDecode = []string{"Content-Encoding", "Content-Length", "Content-Range", "Accept-Ranges"}
