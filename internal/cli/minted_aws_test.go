package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fieldStore is an in-memory connections.Store.
type fieldStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *fieldStore) Get(_ context.Context, p string) ([]byte, backend.Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[p]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return append([]byte(nil), v...), backend.Meta{}, nil
}
func (s *fieldStore) Set(context.Context, string, []byte, backend.Meta) error { return nil }
func (s *fieldStore) List(context.Context, string) ([]backend.Entry, error)   { return nil, nil }
func (s *fieldStore) Delete(context.Context, string) error                    { return nil }

const (
	awsTestRole   = "arn:aws:iam::123456789012:role/Reader"
	awsTestPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`
	// Key-shaped fixtures are built by concatenation so scanners do not flag them.
	awsTestBaseKeyID    = "AK" + "IAEXAMPLEBASE"
	awsTestSessionKeyID = "AS" + "IAEXAMPLESESSION"
)

type awsFixture struct {
	tmpl  registry.ConnectionTemplate
	store *fieldStore
	cfg   config.Config
	audit *testutil.AuditRecorder
	forms chan url.Values
}

func newAWSFixture(t *testing.T) *awsFixture {
	t.Helper()
	require.NoError(t, registry.InitFromConfig(context.Background(), func(string) string { return "" }))
	tmpl, err := registry.Get("aws")
	require.NoError(t, err)

	f := &awsFixture{tmpl: tmpl, audit: &testutil.AuditRecorder{}, forms: make(chan url.Values, 8)}
	f.store = &fieldStore{m: map[string][]byte{
		connections.ConfigFieldPath("default", tmpl.Category, "aws", "access_key_id"):     []byte(awsTestBaseKeyID),
		connections.SecretFieldPath("default", tmpl.Category, "aws", "secret_access_key"): []byte("base-secret"),
	}}
	f.cfg = config.Default()
	f.cfg.Connections = map[string]config.ConnectionPolicy{"aws": {Mint: &config.MintPolicy{AWS: &config.AWSMintPolicy{
		RoleARN: awsTestRole, SessionPolicy: json.RawMessage(awsTestPolicy),
	}}}}

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		f.forms <- form
		fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/Reader/%s</Arn></AssumedRoleUser>
<Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>session-secret</SecretAccessKey><SessionToken>session-token</SessionToken><Expiration>%s</Expiration></Credentials>
</AssumeRoleResult></AssumeRoleResponse>`, form.Get("RoleSessionName"), awsTestSessionKeyID, time.Now().Add(15*time.Minute).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(sts.Close)
	prev := mintAWSSTSEndpoint
	mintAWSSTSEndpoint = sts.URL
	t.Cleanup(func() { mintAWSSTSEndpoint = prev })
	return f
}

func (f *awsFixture) open(caller callerkind.Kind) (runner.MintedCredential, error) {
	return openAWS(context.Background(), f.store, f.cfg, f.audit, f.tmpl,
		runner.MintOpenRequest{Connection: "aws", Namespace: "default", Caller: caller})
}

func TestMintedAWSServesScopedCredentialsToTheCommand(t *testing.T) {
	f := newAWSFixture(t)
	cred, err := f.open(callerkind.Service)
	require.NoError(t, err)
	t.Cleanup(cred.Close)

	uri, err := cred.Value(context.Background(), "container_credentials_uri")
	require.NoError(t, err)
	token, err := cred.Value(context.Background(), "container_authorization_token")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(uri), "http://127.0.0.1:"))
	assert.Empty(t, f.forms, "nothing is minted until the command asks")

	req, _ := http.NewRequest(http.MethodGet, string(uri), nil)
	req.Header.Set("Authorization", string(token))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, awsTestSessionKeyID, body["AccessKeyId"])
	assert.Equal(t, awsTestRole, body["RoleArn"])

	form := <-f.forms
	assert.JSONEq(t, awsTestPolicy, form.Get("Policy"), "the policy from the operator's config limits the session")
	assert.Equal(t, "900", form.Get("DurationSeconds"))
	assert.Equal(t, awsTestRole, form.Get("RoleArn"))

	events := f.audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, audit.ActionMint, events[0].Action)
	assert.Equal(t, "minted", events[0].RuntimeMode)

	_, err = cred.Value(context.Background(), "secret_access_key")
	require.Error(t, err, "the long-lived key is not a field the command can be given")
}

func TestMintedAWSRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*awsFixture)
		caller callerkind.Kind
		want   string
	}{
		{"agent session", func(*awsFixture) {}, callerkind.Agent, "agent sessions cannot"},
		{"human not listed", func(*awsFixture) {}, callerkind.Human, "not allowed"},
		{"no policy", func(f *awsFixture) { f.cfg.Connections = nil }, callerkind.Service, "no mint.aws policy"},
		{"no session policy", func(f *awsFixture) { f.cfg.Connections["aws"].Mint.AWS.SessionPolicy = nil }, callerkind.Service, "session_policy"},
		{"no access key id", func(f *awsFixture) {
			delete(f.store.m, connections.ConfigFieldPath("default", f.tmpl.Category, "aws", "access_key_id"))
		}, callerkind.Service, "has no access_key_id"},
		{"no secret", func(f *awsFixture) {
			delete(f.store.m, connections.SecretFieldPath("default", f.tmpl.Category, "aws", "secret_access_key"))
		}, callerkind.Service, "has no secret_access_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAWSFixture(t)
			tc.mutate(f)
			cred, err := f.open(tc.caller)
			require.Error(t, err)
			assert.Nil(t, cred)
			assert.Contains(t, err.Error(), tc.want)
			assert.Empty(t, f.forms)
		})
	}
}

func TestMintedAWSDenialIsAPolicyDenial(t *testing.T) {
	f := newAWSFixture(t)
	_, err := f.open(callerkind.Agent)
	require.ErrorIs(t, err, mint.ErrDenied)
}

func TestMintedRunHoldsOnlyTheEndpoint(t *testing.T) {
	f := newAWSFixture(t)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "parent-long-lived-secret")
	t.Setenv("AWS_ACCESS_KEY_ID", awsTestBaseKeyID)
	var out strings.Builder
	driver := runner.NewMintedDriver(func(ctx context.Context, tmpl registry.ConnectionTemplate, req runner.MintOpenRequest) (runner.MintedCredential, error) {
		return openAWS(ctx, f.store, f.cfg, f.audit, tmpl, req)
	})
	receipt, err := driver.Run(context.Background(), runner.ExecRequest{
		ConnectionSlug: "aws", Caller: callerkind.Service,
		Command: []string{"sh", "-c", `env | grep '^AWS_' | sed 's/=.*//' | sort`},
		Stdout:  &out, Stderr: &strings.Builder{},
	}, f.tmpl)
	require.NoError(t, err)
	assert.Zero(t, receipt.ExitCode)
	assert.Equal(t, "AWS_CONTAINER_AUTHORIZATION_TOKEN\nAWS_CONTAINER_CREDENTIALS_FULL_URI\n", out.String(),
		"no long-lived key, and no other AWS variable of the parent, reaches the command")
}
