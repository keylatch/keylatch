package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
)

// ApprovalBroker leaves authorization and signing with the kernel-authenticated broker.
type ApprovalBroker interface {
	CallContext(context.Context, brokerapi.Request) (brokerapi.Response, error)
}

// ApprovalsHandler handles GET /api/approvals, GET /api/approvals/stream (SSE),
// and POST /api/approvals/{token}/approve|deny.
type ApprovalsHandler struct {
	Broker    ApprovalBroker
	CanDecide bool
}

func (h *ApprovalsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/approvals")

	switch path { //nolint:staticcheck // QF1002: default case has complex prefix matching incompatible with tagged switch
	case "", "/":
		if r.Method == http.MethodGet {
			h.list(w, r, false)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case "/stream":
		if r.Method == http.MethodGet {
			h.list(w, r, true)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		// POST /api/approvals/{token}/approve|deny
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
		if len(parts) == 2 && r.Method == http.MethodPost && (parts[1] == "approve" || parts[1] == "deny") {
			h.decide(w, r, parts[0], parts[1])
		} else {
			http.NotFound(w, r)
		}
	}
}

func (h *ApprovalsHandler) decide(w http.ResponseWriter, r *http.Request, token, decision string) {
	if h.Broker == nil {
		h.unavailable(w)
		return
	}
	if !h.CanDecide {
		approvalHTTPError(w, http.StatusForbidden, "forbidden", "approval decisions require an admin session")
		return
	}
	var body struct {
		Digest string `json:"digest"`
		Reason string `json:"reason,omitempty"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		approvalHTTPError(w, http.StatusBadRequest, "bad_request", "expected a reviewed digest and optional reason")
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		approvalHTTPError(w, http.StatusBadRequest, "bad_request", "expected one decision object")
		return
	}
	req := brokerapi.Request{Op: brokerapi.OpApprovalDecide, Approval: &brokerapi.ApprovalDecision{Token: token, Digest: body.Digest, Decision: decision, Reason: body.Reason}}
	if err := req.Validate(); err != nil {
		approvalHTTPError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	resp, err := h.Broker.CallContext(ctx, req)
	if !approvalResponseOK(w, resp, err) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]bool{"ok": true})
}

func (h *ApprovalsHandler) list(w http.ResponseWriter, r *http.Request, stream bool) {
	if h.Broker == nil {
		h.unavailable(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	fetch := func() (brokerapi.Response, error) {
		requestCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		return h.Broker.CallContext(requestCtx, brokerapi.Request{Op: brokerapi.OpApprovalList})
	}
	resp, err := fetch()
	if !approvalResponseOK(w, resp, err) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !stream {
		if resp.Approvals == nil {
			resp.Approvals = []brokerapi.ApprovalEntry{}
		}
		writeJSON(w, resp.Approvals)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	rc := http.NewResponseController(w)
	notify := func() bool {
		_, err := io.WriteString(w, "event: approval\ndata: {}\n\n")
		return err == nil && rc.Flush() == nil
	}
	if !notify() {
		return
	}
	fingerprint := func(entries []brokerapi.ApprovalEntry) [32]byte {
		b, _ := json.Marshal(entries)
		return sha256.Sum256(b)
	}
	last := fingerprint(resp.Approvals)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resp, err := fetch()
			if err != nil || !resp.OK {
				return
			}
			next := fingerprint(resp.Approvals)
			if next != last {
				if !notify() {
					return
				}
				last = next
			}
		}
	}
}

func approvalResponseOK(w http.ResponseWriter, resp brokerapi.Response, err error) bool {
	if err != nil {
		approvalHTTPError(w, http.StatusServiceUnavailable, "unavailable", "approval broker is unavailable")
		return false
	}
	if resp.OK {
		return true
	}
	status := http.StatusServiceUnavailable
	switch resp.Code {
	case brokerapi.CodeBadRequest:
		status = http.StatusBadRequest
	case brokerapi.CodeRefused, brokerapi.CodePresenceRequired:
		status = http.StatusForbidden
	case brokerapi.CodeNotFound:
		status = http.StatusNotFound
	}
	approvalHTTPError(w, status, resp.Code, resp.Error)
	return false
}

func approvalHTTPError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"error": code, "message": message})
}

func (h *ApprovalsHandler) unavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	writeJSON(w, map[string]string{
		"error":   "not_implemented",
		"message": "the approval workflow is not available in this build",
	})
}
