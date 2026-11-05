package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type approvalBrokerFunc func(context.Context, brokerapi.Request) (brokerapi.Response, error)

func (f approvalBrokerFunc) CallContext(ctx context.Context, req brokerapi.Request) (brokerapi.Response, error) {
	return f(ctx, req)
}

func TestApprovalListPreservesReviewedDetails(t *testing.T) {
	entry := brokerapi.ApprovalEntry{Token: "apv_" + strings.Repeat("a", 32), Digest: strings.Repeat("b", 64), Summary: "argv: [\"deploy\"]\nhosts: [\"example.test\"]", RequestHash: "request-hash", Actor: "agent", Status: "pending"}
	h := &api.ApprovalsHandler{Broker: approvalBrokerFunc(func(_ context.Context, req brokerapi.Request) (brokerapi.Response, error) {
		require.Equal(t, brokerapi.OpApprovalList, req.Op)
		return brokerapi.Response{OK: true, Approvals: []brokerapi.ApprovalEntry{entry}}, nil
	})}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/approvals", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var entries []brokerapi.ApprovalEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	require.Equal(t, []brokerapi.ApprovalEntry{entry}, entries)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestApprovalDecisionRequiresReviewedDigestAndAdmin(t *testing.T) {
	token, digest := "apv_"+strings.Repeat("a", 32), strings.Repeat("b", 64)
	for _, action := range []string{"approve", "deny"} {
		t.Run(action, func(t *testing.T) {
			calls := 0
			h := &api.ApprovalsHandler{CanDecide: true, Broker: approvalBrokerFunc(func(ctx context.Context, req brokerapi.Request) (brokerapi.Response, error) {
				calls++
				require.Equal(t, brokerapi.OpApprovalDecide, req.Op)
				require.Equal(t, &brokerapi.ApprovalDecision{Token: token, Digest: digest, Decision: action, Reason: "reviewed"}, req.Approval)
				_, bounded := ctx.Deadline()
				require.True(t, bounded)
				return brokerapi.Response{OK: true}, nil
			})}
			request := func(body string) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/approvals/"+token+"/"+action, strings.NewReader(body)))
				return rec
			}
			valid := `{"digest":"` + digest + `","reason":"reviewed"}`
			for _, body := range []string{`{}`, `{"digest":"bad"}`, valid + ` {}`, `{"digest":"` + digest + `","presence_digest":"forged"}`, `{"digest":"` + digest + `","summary":"different command"}`, `{"digest":"` + digest + `","reason":"` + strings.Repeat("x", 9000) + `"}`} {
				require.Equal(t, http.StatusBadRequest, request(body).Code)
			}
			require.Zero(t, calls)
			h.CanDecide = false
			require.Equal(t, http.StatusForbidden, request(valid).Code)
			require.Zero(t, calls)
			h.CanDecide = true
			require.Equal(t, http.StatusOK, request(valid).Code)
			require.Equal(t, 1, calls)
		})
	}
}

func TestApprovalBrokerRefusalIsNotSuccess(t *testing.T) {
	for _, tc := range []struct {
		code   string
		err    error
		status int
	}{
		{brokerapi.CodeRefused, nil, http.StatusForbidden},
		{brokerapi.CodeNotFound, nil, http.StatusNotFound},
		{brokerapi.CodeUnavailable, nil, http.StatusServiceUnavailable},
		{"", errors.New("connection refused"), http.StatusServiceUnavailable},
	} {
		h := &api.ApprovalsHandler{Broker: approvalBrokerFunc(func(context.Context, brokerapi.Request) (brokerapi.Response, error) {
			return brokerapi.Response{Code: tc.code, Error: "request refused"}, tc.err
		})}
		for _, path := range []string{"/api/approvals", "/api/approvals/stream"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			require.Equal(t, tc.status, rec.Code)
			require.NotContains(t, rec.Body.String(), "event: approval")
		}
	}
}

func TestApprovalStreamStopsOnRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h := &api.ApprovalsHandler{Broker: approvalBrokerFunc(func(context.Context, brokerapi.Request) (brokerapi.Response, error) {
		cancel()
		return brokerapi.Response{OK: true}, nil
	})}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/approvals/stream", nil).WithContext(ctx))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	require.Contains(t, rec.Body.String(), "event: approval\ndata: {}\n\n")
}

func TestApprovalsHandler_List(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.Contains(t, rec.Body.String(), "not_implemented")
}

func TestApprovalsHandler_Approve(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/approvals/abc123/approve", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.Contains(t, rec.Body.String(), "not_implemented")
}

func TestApprovalsHandler_Deny(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/approvals/abc123/deny", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.Contains(t, rec.Body.String(), "not_implemented")
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
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.Contains(t, rec.Body.String(), "not_implemented")
}
