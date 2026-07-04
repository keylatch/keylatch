package connections

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/registry"
)

// tokenShapeRE matches high-entropy token-shaped substrings that must not
// appear in test result markers.
var tokenShapeRE = regexp.MustCompile(`[A-Za-z0-9\-_\.]{32,}`)

// Test verifies that a stored connection is healthy by executing its provider's
// TestStrategy. Returns a TestResult with a fixed-enum status; free-form
// upstream error text is NEVER propagated.
func Test(ctx context.Context, provider, account, namespace string, store Store, httpClient *http.Client) (TestResult, error) {
	if namespace == "" {
		namespace = "default"
	}
	if account == "" {
		account = "default"
	}

	// Load connection metadata.
	conn, err := loadConnection(ctx, namespace, provider, account, store)
	if err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return TestResult{
				Status:   TestStatusMissing,
				Provider: provider,
			}, nil
		}
		return TestResult{}, fmt.Errorf("connections: load connection: %w", err)
	}

	// Look up test strategy from registry.
	tmpl, err := registry.Get(provider)
	if err != nil {
		return TestResult{}, ErrProviderNotFound
	}
	strategy := tmpl.TestStrategy

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	start := time.Now()
	result, err := executeTestStrategy(ctx, strategy, provider, account, namespace, conn, store, httpClient)
	result.Duration = time.Since(start).String()
	result.Provider = provider
	result.Connection = fmt.Sprintf("%s/%s/%s", namespace, provider, account)

	if err != nil {
		// Map error to NetworkError — never expose raw error message.
		result.Status = TestStatusNetworkError
		return result, nil
	}

	// Update LastTested timestamp in vault.
	_ = updateLastTested(ctx, namespace, provider, account, store)

	return result, nil
}

// executeTestStrategy runs the appropriate strategy based on TestStrategy.Kind.
func executeTestStrategy(
	ctx context.Context,
	strategy registry.TestStrategy,
	provider, account, namespace string,
	conn *Connection,
	store Store,
	httpClient *http.Client,
) (TestResult, error) {
	switch strategy.Kind {
	case "http_get":
		return runHTTPStrategy(ctx, "GET", strategy, provider, account, namespace, store, httpClient)
	case "http_post":
		return runHTTPStrategy(ctx, "POST", strategy, provider, account, namespace, store, httpClient)
	case "sdk_call":
		// SDK call is provider-specific; maps it to an HTTP GET for now.
		return runHTTPStrategy(ctx, "GET", strategy, provider, account, namespace, store, httpClient)
	default:
		return TestResult{Status: TestStatusNetworkError}, nil
	}
}

// runHTTPStrategy executes an HTTP-based test strategy.
// Auth credentials are read from vault and injected into the request.
// Status codes are mapped to a fixed enum.
func runHTTPStrategy(
	ctx context.Context,
	method string,
	strategy registry.TestStrategy,
	provider, account, namespace string,
	store Store,
	httpClient *http.Client,
) (TestResult, error) {
	// Build request.
	var bodyReader io.Reader
	req, err := http.NewRequestWithContext(ctx, method, strategy.Endpoint, bodyReader)
	if err != nil {
		return TestResult{}, fmt.Errorf("build request: %w", err)
	}

	// Inject auth from vault. Read the first secret field for this provider's
	// auth placement. We read without logging the value (value-bearing read).
	tmpl, _ := registry.Get(provider)
	cat := tmpl.Category
	if cat == "" {
		cat = "ai"
	}
	if len(tmpl.SecretFields) > 0 {
		sf := tmpl.SecretFields[0]
		fieldPath := secretFieldPath(namespace, cat, provider, sf.Name)
		authValue, _, err := store.Get(ctx, fieldPath)
		if err == nil && len(authValue) > 0 {
			ap := tmpl.AuthPlacement
			if ap.In == "header" { //nolint:staticcheck // QF1003: tagged switch would reduce clarity for this 2-branch case
				if ap.Scheme != "" {
					req.Header.Set(ap.Name, ap.Scheme+" "+string(authValue))
				} else {
					req.Header.Set(ap.Name, string(authValue))
				}
			} else if ap.In == "query" {
				q := req.URL.Query()
				q.Set(ap.Name, string(authValue))
				req.URL.RawQuery = q.Encode()
			}
			// Zero after use.
			zeroBytes(authValue)
		}
	}

	// Execute request.
	resp, err := httpClient.Do(req)
	if err != nil {
		return TestResult{}, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	// Read body, limited to 4KB to prevent memory exhaustion.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	// Map status code to fixed enum.
	status := mapHTTPStatusToEnum(resp.StatusCode)

	// Extract allowed markers from body (no free-form text, no token-shaped strings).
	var markers []string
	if len(strategy.Expect.Markers) > 0 {
		for _, marker := range strategy.Expect.Markers {
			if bytes.Contains(bodyBytes, []byte(marker)) {
				// Only include marker if it doesn't look like a token itself.
				if !tokenShapeRE.MatchString(marker) || len(marker) < 32 {
					markers = append(markers, marker)
				}
			}
		}
	}

	return TestResult{
		Status:     status,
		StatusCode: resp.StatusCode,
		Markers:    markers,
	}, nil
}

// mapHTTPStatusToEnum maps an HTTP status code to a fixed TestResult.Status enum.
// no free-form text; fixed enum only.
func mapHTTPStatusToEnum(code int) string {
	switch {
	case code == 200 || code == 201 || code == 204:
		return TestStatusConnected
	case code == 401:
		return TestStatusInvalid
	case code == 403:
		return TestStatusInsufficientScope
	case code == 404:
		return TestStatusMissing
	case code == 429:
		return TestStatusRateLimited
	case code >= 500:
		return TestStatusNetworkError
	default:
		return TestStatusNetworkError
	}
}

// updateLastTested writes the current timestamp as LastTested in vault.
func updateLastTested(ctx context.Context, namespace, provider, _ string, store Store) error {
	tmpl, _ := registry.Get(provider)
	cat := tmpl.Category
	if cat == "" {
		cat = "ai"
	}
	metaPath := connectionMetaPath(namespace, cat, provider)
	data, _, err := store.Get(ctx, metaPath)
	if err != nil {
		return err
	}
	conn, err := unmarshalConnection(data)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	conn.LastTested = &now
	connBytes, err := marshalConnection(conn)
	if err != nil {
		return err
	}
	return store.Set(ctx, metaPath, connBytes, backend.Meta{
		Path:    metaPath,
		Backend: "vault",
		Version: 1,
	})
}

// loadConnection retrieves a Connection from vault metadata.
func loadConnection(ctx context.Context, namespace, provider, _ string, store Store) (*Connection, error) {
	tmpl, _ := registry.Get(provider)
	cat := tmpl.Category
	if cat == "" {
		cat = "ai"
	}
	metaPath := connectionMetaPath(namespace, cat, provider)
	data, _, err := store.Get(ctx, metaPath)
	if err != nil {
		return nil, err
	}
	return unmarshalConnection(data)
}

// stripTokenShapedSubstrings removes any token-shaped substring from s.
// Used for additional safety when constructing marker strings.
func stripTokenShapedSubstrings(s string) string {
	return tokenShapeRE.ReplaceAllStringFunc(s, func(match string) string {
		if len(match) >= 32 {
			return strings.Repeat("*", 4)
		}
		return match
	})
}
