package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxRetryBody is the largest request body held in memory so a request that
// upstream rejects with 401 can be replayed once with a fresh token. Larger
// bodies (a big push) are streamed and not replayed.
const maxRetryBody = 1 << 20

var hopHeaders = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true, "te": true,
	"trailer": true, "transfer-encoding": true, "upgrade": true, "proxy-authenticate": true,
}

func (s *Server) githubClient() *http.Client {
	s.ghOnce.Do(func() {
		var rt http.RoundTripper = &http.Transport{ResponseHeaderTimeout: 60 * time.Second, Proxy: nil}
		if s.UpstreamTransport != nil {
			rt = s.UpstreamTransport
		}
		s.ghClient = &http.Client{
			Transport: rt,
			// Redirects go back to the caller: a credential is never replayed
			// to another host, and the caller's next request comes through here.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	})
	return s.ghClient
}

func jsonError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`+"\n")
}

// githubForward serves one request for a GitHub host. The caller's
// Authorization was already stripped by routeHandler.
func (s *Server) githubForward(w http.ResponseWriter, r *http.Request, host string) {
	scheme, refusal := s.GitHub.Authorize(host, r.Method, r.URL)
	if refusal != "" {
		s.auditDeny(r.Context(), refusal, host+r.URL.Path)
		jsonError(w, http.StatusForbidden, refusal)
		return
	}
	ctx := r.Context()
	tok, err := s.GitHub.Token(ctx)
	if err != nil {
		s.auditDeny(ctx, "credential_unavailable", host)
		jsonError(w, http.StatusServiceUnavailable, "credential_unavailable")
		return
	}

	var buffered []byte
	var stream io.Reader
	canReplay := true
	if r.Body != nil && r.Body != http.NoBody {
		head, _ := io.ReadAll(io.LimitReader(r.Body, maxRetryBody+1))
		if len(head) > maxRetryBody {
			stream, canReplay = io.MultiReader(bytes.NewReader(head), r.Body), false
		} else {
			buffered = head
		}
	}

	do := func(token string) (*http.Response, error) {
		var body io.Reader
		switch {
		case stream != nil:
			body = stream
		case buffered != nil:
			body = bytes.NewReader(buffered)
		}
		u := *r.URL
		u.Scheme, u.Host, u.User = "https", host, nil
		req, err := http.NewRequestWithContext(ctx, r.Method, u.String(), body)
		if err != nil {
			return nil, err
		}
		for k, vv := range r.Header {
			lower := strings.ToLower(k)
			if lower == "authorization" || lower == "proxy-authorization" || hopHeaders[lower] || strings.HasPrefix(lower, "x-keylatch-") {
				continue
			}
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
		req.Header.Set("Authorization", HeaderValue(scheme, token))
		return s.githubClient().Do(req) //nolint:gosec // host is one of the three allowlisted GitHub hosts
	}

	resp, err := do(tok)
	if err == nil && resp.StatusCode == http.StatusUnauthorized && canReplay {
		if fresh, rerr := s.GitHub.Refresh(ctx, tok); rerr == nil {
			resp.Body.Close() //nolint:errcheck,gosec // replaced by the retry
			resp, err = do(fresh)
		}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		jsonError(w, http.StatusBadGateway, "upstream_error")
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	for k, vv := range resp.Header {
		if hopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if rerr != nil {
			return
		}
	}
}
