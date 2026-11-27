// Package targets talks to the places a sync manifest writes to: the Vercel
// and GitHub REST APIs and local env files. Clients take their credential as a
// function the daemon supplies, so a token is read when a request is made and
// never held by the client.
package targets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Options configures a client.
type Options struct {
	// Client sends the requests. Nil uses a client with a 30 second timeout.
	Client *http.Client
}

func (o Options) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Token returns the credential for one request. The caller of the function
// owns the returned bytes' lifetime; the client copies them into a header and
// does not keep them.
type Token func(ctx context.Context) (string, error)

// HTTPError is a non-2xx answer. It carries the status and the API's error
// code, never the body: a body can echo what was sent.
type HTTPError struct {
	Method string
	Path   string
	Status int
	Code   string
}

func (e *HTTPError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s %s: status %d (%s)", e.Method, e.Path, e.Status, e.Code)
	}
	return fmt.Sprintf("%s %s: status %d", e.Method, e.Path, e.Status)
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Status == http.StatusNotFound
}

type api struct {
	base  string
	http  *http.Client
	token Token
	// headers are added to every request.
	headers map[string]string
}

func (a *api) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	tok, err := a.token(ctx)
	if err != nil {
		return err
	}
	u := a.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", "keylatch-sync")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		he := &HTTPError{Method: method, Path: path, Status: resp.StatusCode}
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil {
			he.Code = e.Error.Code
		}
		return he
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}
