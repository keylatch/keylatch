package scim_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/scim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mxToken = "scim-test-bearer"

func mxSCIM(t *testing.T) (*team.Team, http.Handler) {
	t.Helper()
	t.Setenv("KEYLATCH_TEAM_DIR", filepath.Join(t.TempDir(), "team"))
	tm := &team.Team{ID: "t1", Members: []team.Member{
		{ID: "u1", HMAC: "hmac-u1", Role: team.RoleDeveloper, Status: team.MemberActive, JoinedAt: time.Unix(1700000000, 0).UTC()},
	}}
	return tm, scim.NewServer(tm, scim.ServerOpts{BearerToken: mxToken}).Handler()
}

func mxCall(h http.Handler, method, path, body string, authed bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authed {
		req.Header.Set("Authorization", "Bearer "+mxToken)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSCIM_AuthRequiredEverywhere(t *testing.T) {
	_, h := mxSCIM(t)
	for _, p := range []string{"/scim/v2/Users", "/scim/v2/Users/u1", "/scim/v2/Groups", "/scim/v2/Groups/g"} {
		rec := mxCall(h, http.MethodGet, p, "", false)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, p)
		assert.Equal(t, "application/scim+json", rec.Header().Get("Content-Type"))
	}

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// No configured token means every request is denied, even an empty bearer.
	open := scim.NewServer(&team.Team{}, scim.ServerOpts{}).Handler()
	req = httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec = httptest.NewRecorder()
	open.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestSCIM_UserLifecycle(t *testing.T) {
	tm, h := mxSCIM(t)

	rec := mxCall(h, http.MethodGet, "/scim/v2/Users/u1", "", true)
	require.Equal(t, http.StatusOK, rec.Code)
	var u map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&u))
	assert.Equal(t, "hmac-u1", u["userName"])
	assert.Equal(t, true, u["active"])
	assert.Contains(t, u["meta"].(map[string]any)["location"], "/scim/v2/Users/u1")

	assert.Equal(t, http.StatusNotFound, mxCall(h, http.MethodGet, "/scim/v2/Users/nope", "", true).Code)
	assert.Equal(t, http.StatusOK, mxCall(h, http.MethodPatch, "/scim/v2/Users/u1/", `{}`, true).Code)
	assert.Equal(t, http.StatusNotFound, mxCall(h, http.MethodPut, "/scim/v2/Users/nope", `{}`, true).Code)
	assert.Equal(t, http.StatusMethodNotAllowed, mxCall(h, http.MethodPost, "/scim/v2/Users/u1", `{}`, true).Code)
	assert.Equal(t, http.StatusMethodNotAllowed, mxCall(h, http.MethodDelete, "/scim/v2/Users", "", true).Code)

	rec = mxCall(h, http.MethodPost, "/scim/v2/Users", `{"userName":"hmac-new","active":false}`, true)
	require.Equal(t, http.StatusCreated, rec.Code)
	require.Len(t, tm.Members, 2)
	assert.Equal(t, team.MemberSuspended, tm.Members[1].Status, "inactive provisioned users are suspended")
	assert.Equal(t, team.RoleDeveloper, tm.Members[1].Role, "SCIM never grants elevated roles")

	assert.Equal(t, http.StatusBadRequest, mxCall(h, http.MethodPost, "/scim/v2/Users", `{`, true).Code)

	rec = mxCall(h, http.MethodDelete, "/scim/v2/Users/u1", "", true)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, team.MemberRemoved, tm.Members[0].Status)
	assert.Equal(t, http.StatusNotFound, mxCall(h, http.MethodDelete, "/scim/v2/Users/nope", "", true).Code)
}

func TestSCIM_DeletePersistFailureIs500(t *testing.T) {
	_, h := mxSCIM(t)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	t.Setenv("KEYLATCH_TEAM_DIR", filepath.Join(blocker, "team"))
	rec := mxCall(h, http.MethodDelete, "/scim/v2/Users/u1", "", true)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSCIM_Groups(t *testing.T) {
	_, h := mxSCIM(t)
	rec := mxCall(h, http.MethodGet, "/scim/v2/Groups", "", true)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"totalResults":0`)
	assert.Equal(t, http.StatusMethodNotAllowed, mxCall(h, http.MethodPost, "/scim/v2/Groups", "{}", true).Code)
	assert.Equal(t, http.StatusNotImplemented, mxCall(h, http.MethodGet, "/scim/v2/Groups/g1", "", true).Code)
}

func TestSCIM_ServeLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8763", "localhost:8763", "no-port"} {
		err := scim.NewServer(&team.Team{}, scim.ServerOpts{Addr: addr}).Serve(context.Background())
		require.Error(t, err, addr)
	}

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()
	err = scim.NewServer(&team.Team{}, scim.ServerOpts{Addr: busy.Addr().String()}).Serve(context.Background())
	require.Error(t, err, "port already in use")

	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := free.Addr().String()
	require.NoError(t, free.Close())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- scim.NewServer(&team.Team{}, scim.ServerOpts{Addr: addr, BearerToken: mxToken}).Serve(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/scim/v2/Users") //nolint:noctx // local test server
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not shut down")
	}
}
