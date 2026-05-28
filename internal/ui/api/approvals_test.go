package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApprovalsHandler_List(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "approvals")
}

func TestApprovalsHandler_Approve(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/approvals/abc123/approve", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "approve")
}

func TestApprovalsHandler_Deny(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/approvals/abc123/deny", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "deny")
}

func TestApprovalsHandler_InvalidAction(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/approvals/abc123/delete", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestApprovalsHandler_Stream_SSE(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/approvals/stream", nil)
	// Cancel context immediately so stream exits.
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "heartbeat")
}
