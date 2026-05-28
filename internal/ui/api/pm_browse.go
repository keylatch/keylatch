package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// PMBrowseItem is a single item returned by a PM CLI list command.
type PMBrowseItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// PMBrowseResponse is the JSON body returned by GET /api/pm-browse.
type PMBrowseResponse struct {
	Authenticated bool           `json:"authenticated"`
	Items         []PMBrowseItem `json:"items,omitempty"`
	// Hint is populated when Authenticated is false and provides a remedy command.
	Hint string `json:"hint,omitempty"`
}

// PMBrowseHandler handles GET /api/pm-browse?pm=op|aws_sm|hashivault.
//
// Runs the respective PM CLI to list secrets/items. If the CLI exits non-zero
// (unauthenticated or misconfigured), returns {authenticated:false, hint: ...}.
// If successful, returns {authenticated:true, items:[...]}.
type PMBrowseHandler struct {
	// runner is injected in tests; nil → real exec.
	runner func(ctx context.Context, bin string, args []string) ([]byte, int, error)
}

// NewPMBrowseHandler returns a PMBrowseHandler with an optional custom runner.
// Pass nil for the production default (real exec.Command).
func NewPMBrowseHandler(runner func(ctx context.Context, bin string, args []string) ([]byte, int, error)) *PMBrowseHandler {
	return &PMBrowseHandler{runner: runner}
}

func (h *PMBrowseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pm := strings.TrimSpace(r.URL.Query().Get("pm"))
	if pm == "" {
		http.Error(w, "pm query parameter is required (op|aws_sm|hashivault)", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, err := h.browse(ctx, pm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, resp)
}

func (h *PMBrowseHandler) browse(ctx context.Context, pm string) (*PMBrowseResponse, error) {
	run := h.runner
	if run == nil {
		run = defaultRun
	}

	switch pm {
	case "op":
		return browseOP(ctx, run)
	case "aws_sm":
		return browseAWSSM(ctx, run)
	case "hashivault":
		return browseHashiVault(ctx, run)
	default:
		return nil, fmt.Errorf("unsupported pm value %q — expected op|aws_sm|hashivault", pm)
	}
}

// defaultRun shells out to the given binary with args and returns stdout, exit code, and any error.
func defaultRun(ctx context.Context, bin string, args []string) ([]byte, int, error) {
	abs, err := exec.LookPath(bin)
	if err != nil {
		return nil, 1, fmt.Errorf("binary %q not found on PATH", bin)
	}
	cmd := exec.CommandContext(ctx, abs, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.ExitCode(), nil
		}
		return nil, 1, err
	}
	return out, 0, nil
}

// --- 1Password ---

func browseOP(ctx context.Context, run func(context.Context, string, []string) ([]byte, int, error)) (*PMBrowseResponse, error) {
	out, code, err := run(ctx, "op", []string{"item", "list", "--format=json"})
	if err != nil {
		return &PMBrowseResponse{Authenticated: false, Hint: "Run: op signin"}, nil
	}
	if code != 0 {
		return &PMBrowseResponse{Authenticated: false, Hint: "Run: op signin"}, nil
	}

	var raw []struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return &PMBrowseResponse{Authenticated: true, Items: []PMBrowseItem{}}, nil
	}
	items := make([]PMBrowseItem, 0, len(raw))
	for _, r := range raw {
		items = append(items, PMBrowseItem{ID: r.ID, Title: r.Title})
	}
	return &PMBrowseResponse{Authenticated: true, Items: items}, nil
}

// --- AWS Secrets Manager ---

func browseAWSSM(ctx context.Context, run func(context.Context, string, []string) ([]byte, int, error)) (*PMBrowseResponse, error) {
	out, code, err := run(ctx, "aws", []string{"secretsmanager", "list-secrets", "--output", "json"})
	if err != nil {
		return &PMBrowseResponse{Authenticated: false, Hint: "Run: aws configure"}, nil
	}
	if code != 0 {
		return &PMBrowseResponse{Authenticated: false, Hint: "Run: aws configure"}, nil
	}

	var raw struct {
		SecretList []struct {
			ARN  string `json:"ARN"`
			Name string `json:"Name"`
		} `json:"SecretList"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return &PMBrowseResponse{Authenticated: true, Items: []PMBrowseItem{}}, nil
	}
	items := make([]PMBrowseItem, 0, len(raw.SecretList))
	for _, s := range raw.SecretList {
		items = append(items, PMBrowseItem{ID: s.ARN, Title: s.Name})
	}
	return &PMBrowseResponse{Authenticated: true, Items: items}, nil
}

// --- HashiCorp Vault ---

func browseHashiVault(ctx context.Context, run func(context.Context, string, []string) ([]byte, int, error)) (*PMBrowseResponse, error) {
	out, code, err := run(ctx, "vault", []string{"kv", "list", "-format=json", "secret"})
	if err != nil {
		return &PMBrowseResponse{Authenticated: false, Hint: "Run: vault login"}, nil
	}
	if code != 0 {
		return &PMBrowseResponse{Authenticated: false, Hint: "Run: vault login"}, nil
	}

	var keys []string
	if err := json.Unmarshal(out, &keys); err != nil {
		return &PMBrowseResponse{Authenticated: true, Items: []PMBrowseItem{}}, nil
	}
	items := make([]PMBrowseItem, 0, len(keys))
	for _, k := range keys {
		items = append(items, PMBrowseItem{ID: k, Title: k})
	}
	return &PMBrowseResponse{Authenticated: true, Items: items}, nil
}
