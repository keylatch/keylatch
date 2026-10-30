package ui_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/require"
)

type approvalCaller func(context.Context, brokerapi.Request) (brokerapi.Response, error)

func (f approvalCaller) CallContext(ctx context.Context, req brokerapi.Request) (brokerapi.Response, error) {
	return f(ctx, req)
}

func TestApprovalRoutesRequireSessionCSRFAndAdmin(t *testing.T) {
	for _, scope := range []ui.UISessionScope{ui.ScopeSetup, ui.ScopeAdmin} {
		t.Run(scope.String(), func(t *testing.T) {
			calls := 0
			opts := defaultOpts(t)
			opts.Scope = scope
			opts.ApprovalBroker = approvalCaller(func(_ context.Context, req brokerapi.Request) (brokerapi.Response, error) {
				calls++
				require.Equal(t, brokerapi.OpApprovalDecide, req.Op)
				return brokerapi.Response{OK: true}, nil
			})
			srv, err := ui.New(opts)
			require.NoError(t, err)
			bootstrap := httptest.NewRecorder()
			srv.TestServeHTTP(bootstrap, httptest.NewRequest(http.MethodGet, srv.BootstrapURL(), nil))
			require.Equal(t, http.StatusSeeOther, bootstrap.Code)
			cookie := findCookie(bootstrap, "kl_session")
			require.NotNil(t, cookie)
			for _, prefix := range []string{"/api", "/v1"} {
				path := prefix + "/approvals/apv_" + strings.Repeat("a", 32) + "/approve"
				request := func(auth, csrf bool) int {
					req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"digest":"`+strings.Repeat("b", 64)+`"}`))
					if auth {
						req.AddCookie(cookie)
					}
					if csrf {
						req.AddCookie(&http.Cookie{Name: "kl_csrf", Value: "test-token"})
						req.Header.Set("X-CSRF-Token", "test-token")
					}
					rec := httptest.NewRecorder()
					srv.TestServeHTTP(rec, req)
					return rec.Code
				}
				before := calls
				require.Equal(t, http.StatusUnauthorized, request(false, true))
				require.Equal(t, http.StatusForbidden, request(true, false))
				require.Equal(t, before, calls)
				if scope == ui.ScopeSetup {
					require.Equal(t, http.StatusForbidden, request(true, true))
					require.Equal(t, before, calls)
				} else {
					require.Equal(t, http.StatusOK, request(true, true))
					require.Equal(t, before+1, calls)
				}
			}
		})
	}
}
