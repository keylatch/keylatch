package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/template"
)

// ActionResult carries the result of a single action dispatch.
// It never contains credential bytes — only status metadata and the response body.
type ActionResult struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
	DurationMs int64
}

// actionCalledEvent is the audit payload emitted for every ExecuteAction call.
// No credential bytes appear in any field (security invariant).
type actionCalledEvent struct {
	Provider    string `json:"provider"`
	Action      string `json:"action"`
	RuntimeMode string `json:"runtime_mode"`
	StatusCode  int    `json:"status_code"`
	ActorID     string `json:"actor_id"`
	Timestamp   string `json:"timestamp"`
}

// ErrActionNotFound is returned when the requested action name is not in the template.
var ErrActionNotFound = fmt.Errorf("runner: action not found")

// ErrMissingRequiredParam is returned when a required action param is absent.
var ErrMissingRequiredParam = fmt.Errorf("runner: missing required parameter")

// ExecuteAction looks up the named action from the provider template, validates
// params, builds and dispatches the HTTP request using the supplied bearer token,
// and returns the result.
//
// Security invariants:
//   - creds is used only as an Authorization header value; it is never logged or included in ActionResult.
//   - The audit event (action_called) contains only metadata — no credential bytes.
//
// Parameters:
//   - baseURL:    root URL of the provider (e.g. "https://api.openai.com")
//   - provider:   provider slug (e.g. "openai")
//   - actionName: action key in the template's Actions map (e.g. "list-models")
//   - params:     caller-supplied key=value pairs; routed to query/path/body per ParamSpec.In
//   - creds:      raw bearer token; sent as "Authorization: Bearer <creds>"
func ExecuteAction(
	ctx context.Context,
	baseURL, provider, actionName string,
	params map[string]string,
	creds string,
) (*ActionResult, error) {
	return executeAction(ctx, baseURL, provider, actionName, params, creds, nil)
}

// executeAction is the internal implementation; httpClient may be injected for tests.
func executeAction(
	ctx context.Context,
	baseURL, provider, actionName string,
	params map[string]string,
	creds string,
	httpClient *http.Client,
) (*ActionResult, error) {
	// 1. Look up provider template.
	tmpl, err := registry.Get(provider)
	if err != nil {
		return nil, fmt.Errorf("runner: provider %q not found: %w", provider, err)
	}

	// 2. Find action by name.
	action, ok := tmpl.Actions[actionName]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not defined for provider %q", ErrActionNotFound, actionName, provider)
	}

	// 3. Validate required params.
	if err := validateActionParams(action, params); err != nil {
		return nil, err
	}

	// 4. Build URL from base + path with {param} substitution.
	rawURL, err := buildActionURL(baseURL, action.Path, params, action.Params)
	if err != nil {
		return nil, fmt.Errorf("runner: build action URL: %w", err)
	}

	// 5. Build body (JSON-encoded body params).
	var bodyBytes []byte
	if bodyMap := collectParamsByIn(params, action.Params, "body"); len(bodyMap) > 0 {
		bodyBytes, err = json.Marshal(bodyMap)
		if err != nil {
			return nil, fmt.Errorf("runner: marshal body params: %w", err)
		}
	}

	// 6. Build request.
	method := strings.ToUpper(action.Method)
	var bodyReader *bytes.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("runner: build request: %w", err)
	}
	if len(bodyBytes) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// 7. Inject auth credential using the template's AuthPlacement — never logged.
	ap := tmpl.AuthPlacement
	headerName := "Authorization"
	if ap.Name != "" {
		headerName = ap.Name
	}
	headerVal := creds
	if ap.Scheme != "" {
		headerVal = ap.Scheme + " " + creds
	}
	req.Header.Set(headerName, headerVal)

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	// 8. Dispatch.
	start := time.Now()
	resp, err := httpClient.Do(req)
	durationMs := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("runner: http request: %w", err)
	}
	defer resp.Body.Close()

	// Read up to 8 MB — cap applied before buffering to prevent OOM.
	const maxBody = 8 * 1024 * 1024
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("runner: read response body: %w", err)
	}

	result := &ActionResult{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
		DurationMs: durationMs,
	}

	// 9. Emit audit event — no credential bytes.
	emitActionCalledEvent(provider, actionName, string(tmpl.RuntimeSupport.Preferred), resp.StatusCode)

	return result, nil
}

// validateActionParams checks that all required params defined in the action spec
// are present in the caller-supplied params map.
func validateActionParams(action template.Action, params map[string]string) error {
	for name, spec := range action.Params {
		if !spec.Required {
			continue
		}
		if _, ok := params[name]; !ok {
			return fmt.Errorf("%w: %q (in: %s)", ErrMissingRequiredParam, name, spec.In)
		}
	}
	return nil
}

// buildActionURL constructs the full URL for an action:
//  1. Substitutes {param} placeholders in the path with path-type params.
//  2. Appends query-type params as query string.
func buildActionURL(baseURL, path string, params map[string]string, paramSpecs map[string]template.ParamSpec) (string, error) {
	// Substitute path params.
	resolvedPath := path
	for name, spec := range paramSpecs {
		if spec.In != "path" {
			continue
		}
		placeholder := "{" + name + "}"
		val, ok := params[name]
		if !ok {
			if spec.Required {
				return "", fmt.Errorf("path param %q is required but missing", name)
			}
			continue
		}
		resolvedPath = strings.ReplaceAll(resolvedPath, placeholder, url.PathEscape(val))
	}

	if strings.Contains(resolvedPath, "{") {
		return "", fmt.Errorf("path %q has unresolved placeholders after param substitution", resolvedPath)
	}

	full := strings.TrimRight(baseURL, "/") + resolvedPath

	// Parse and append query params.
	parsedURL, err := url.Parse(full)
	if err != nil {
		return "", fmt.Errorf("parse URL %q: %w", full, err)
	}

	queryParams := collectParamsByIn(params, paramSpecs, "query")
	if len(queryParams) > 0 {
		q := parsedURL.Query()
		for k, v := range queryParams {
			q.Set(k, v)
		}
		parsedURL.RawQuery = q.Encode()
	}

	return parsedURL.String(), nil
}

// collectParamsByIn returns a map of param name → value for params whose In field
// matches the requested location ("query", "path", or "body").
// Params not in the spec are not collected (they are ignored).
// Params in the spec with the right location are included if the caller supplied them.
func collectParamsByIn(params map[string]string, specs map[string]template.ParamSpec, in string) map[string]string {
	out := make(map[string]string)
	for name, spec := range specs {
		if spec.In != in {
			continue
		}
		val, ok := params[name]
		if !ok {
			continue
		}
		out[name] = val
	}
	return out
}

// emitActionCalledEvent logs the audit event. The runtime actor_id is derived
// from the runtime mode string; no credential bytes are included.
func emitActionCalledEvent(provider, action, runtimeMode string, statusCode int) {
	evt := actionCalledEvent{
		Provider:    provider,
		Action:      action,
		RuntimeMode: runtimeMode,
		StatusCode:  statusCode,
		ActorID:     "cli", // ephemeral CLI invocation — no HMAC required at this layer
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
	evtBytes, _ := json.Marshal(evt)
	slog.Info("action_called", "event", string(evtBytes))
}
