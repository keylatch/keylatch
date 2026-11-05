package awscreds_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/awscreds"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rolePolicy = `{"Version":"2012-10-17","Statement":[]}`
	roleARN    = "arn:aws:iam::123456789012:role/Reader"
	// Key-shaped fixtures are built by concatenation so scanners do not flag them.
	sessionKeyID = "AS" + "IAEXAMPLESESSION"
)

type fakeMinter struct {
	mu     sync.Mutex
	calls  []strategies.AWSScope
	life   time.Duration
	now    func() time.Time
	err    error
	secret string
}

func (m *fakeMinter) MintScoped(_ context.Context, _ string, scope strategies.AWSScope) (strategies.AWSCredentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, scope)
	if m.err != nil {
		return strategies.AWSCredentials{}, m.err
	}
	return strategies.AWSCredentials{
		AccessKeyID: sessionKeyID, SecretAccessKey: m.secret, SessionToken: "session-token",
		Expiration: m.now().Add(m.life),
	}, nil
}

func (m *fakeMinter) mints() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

type failingAudit struct{}

func (failingAudit) Emit(context.Context, audit.Event) error { return errors.New("disk full") }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	srv    *awscreds.Server
	minter *fakeMinter
	audit  *testutil.AuditRecorder
	clock  *clock
}

func start(t *testing.T) *fixture {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	f := &fixture{
		minter: &fakeMinter{life: 15 * time.Minute, now: clk.now, secret: "session-secret"},
		audit:  &testutil.AuditRecorder{},
		clock:  clk,
	}
	srv, err := awscreds.Start(awscreds.Config{
		Minter: f.minter, Connection: "aws", Namespace: "default", RoleARN: roleARN,
		Scope:  strategies.AWSScope{SessionName: "run", SessionPolicy: rolePolicy, Duration: 15 * time.Minute},
		Caller: callerkind.Service, Audit: f.audit, Now: clk.now,
	})
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	f.srv = srv
	return f
}

func (f *fixture) get(t *testing.T, token string, mutate func(*http.Request)) (*http.Response, map[string]string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.srv.URI(), nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func TestServesTheContainerCredentialsFormat(t *testing.T) {
	f := start(t)
	resp, body := f.get(t, f.srv.Token(), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Equal(t, sessionKeyID, body["AccessKeyId"])
	assert.Equal(t, "session-secret", body["SecretAccessKey"])
	assert.Equal(t, "session-token", body["Token"])
	assert.Equal(t, roleARN, body["RoleArn"])
	assert.Equal(t, f.clock.now().Add(15*time.Minute).Format(time.RFC3339), body["Expiration"])

	require.Equal(t, 1, f.minter.mints())
	assert.Equal(t, rolePolicy, f.minter.calls[0].SessionPolicy, "the configured session policy is what is minted")
}

func TestRefusesRequestsWithoutTheToken(t *testing.T) {
	f := start(t)
	for name, token := range map[string]string{"none": "", "wrong": "not-the-token"} {
		t.Run(name, func(t *testing.T) {
			resp, body := f.get(t, token, nil)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Empty(t, body)
		})
	}
	assert.Zero(t, f.minter.mints(), "no session is minted for a caller without the token")
}

func TestRefusesAForeignHost(t *testing.T) {
	f := start(t)
	resp, _ := f.get(t, f.srv.Token(), func(r *http.Request) { r.Host = "rebind.example" })
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Zero(t, f.minter.mints())
}

func TestOnlyServesGETOnTheCredentialsPath(t *testing.T) {
	f := start(t)
	resp, _ := f.get(t, f.srv.Token(), func(r *http.Request) { r.Method = http.MethodPost })
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp, _ = f.get(t, f.srv.Token(), func(r *http.Request) { r.URL.Path = "/latest/meta-data/" })
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestReusesTheSessionUntilItIsNearExpiry(t *testing.T) {
	f := start(t)
	f.get(t, f.srv.Token(), nil)
	f.get(t, f.srv.Token(), nil)
	assert.Equal(t, 1, f.minter.mints())

	f.clock.advance(14 * time.Minute)
	_, body := f.get(t, f.srv.Token(), nil)
	assert.Equal(t, 2, f.minter.mints(), "a session within two minutes of expiry is replaced")
	assert.Equal(t, f.clock.now().Add(15*time.Minute).Format(time.RFC3339), body["Expiration"])
}

func TestEveryMintIsAudited(t *testing.T) {
	f := start(t)
	f.get(t, f.srv.Token(), nil)
	events := f.audit.Events()
	require.Len(t, events, 1)
	ev := events[0]
	assert.Equal(t, audit.ActionMint, ev.Action)
	assert.Equal(t, audit.OutcomeOK, ev.Outcome)
	assert.Equal(t, "minted", ev.RuntimeMode)
	assert.Equal(t, roleARN, ev.Extra["role_arn"])
	assert.Equal(t, "service", ev.Extra["caller_kind"])
	assert.Len(t, ev.Extra["session_policy_sha256"], 64)
	for _, v := range ev.Extra {
		assert.NotContains(t, v, "session-secret")
	}
}

func TestMintFailureIsReportedAndAudited(t *testing.T) {
	f := start(t)
	f.minter.err = strategies.ErrAWSScopeMismatch
	resp, body := f.get(t, f.srv.Token(), nil)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Empty(t, body)
	events := f.audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, audit.OutcomeError, events[0].Outcome)
	assert.Equal(t, "scope_mismatch", events[0].Extra["reason"])
}

func TestAuditFailureWithholdsTheSession(t *testing.T) {
	srv, err := awscreds.Start(awscreds.Config{
		Minter: &fakeMinter{life: time.Hour, now: time.Now, secret: "s"}, Connection: "aws", Namespace: "default", RoleARN: roleARN,
		Scope: strategies.AWSScope{SessionName: "run", SessionPolicy: rolePolicy}, Audit: &flaky{ready: true},
	})
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URI(), nil)
	req.Header.Set("Authorization", srv.Token())
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

type flaky struct{ ready bool }

func (flaky) Emit(context.Context, audit.Event) error { return errors.New("disk full") }

func TestStartRefusesWhatItCannotAudit(t *testing.T) {
	_, err := awscreds.Start(awscreds.Config{Minter: &fakeMinter{}, Scope: strategies.AWSScope{SessionPolicy: rolePolicy}})
	require.Error(t, err, "no audit log")
	_, err = awscreds.Start(awscreds.Config{Audit: failingAudit{}})
	require.Error(t, err, "no minter")
}

func TestCloseStopsTheEndpoint(t *testing.T) {
	f := start(t)
	uri, token := f.srv.URI(), f.srv.Token()
	f.get(t, token, nil)
	f.srv.Close()

	req, _ := http.NewRequest(http.MethodGet, uri, nil)
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "the endpoint is gone once the run ends")
}
