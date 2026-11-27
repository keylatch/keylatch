package providermint_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/providermint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func awsPolicy() config.MintPolicy {
	return config.MintPolicy{AWS: &config.AWSMintPolicy{
		RoleARN: "arn:aws:iam::123456789012:role/Reader", MaxTTL: 3600,
		SessionPolicy: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`),
	}}
}

func TestAWSMintUsesScopedSession(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.Form
		_, _ = fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/Reader/%s</Arn></AssumedRoleUser><Credentials><AccessKeyId>session-id</AccessKeyId><SecretAccessKey>session-key</SecretAccessKey><SessionToken>session-token</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`, form.Get("RoleSessionName"), time.Now().Add(15*time.Minute).UTC().Format(time.RFC3339))
	}))
	defer srv.Close()
	st := fill(t, providermint.ProviderAWS, map[string]string{"access_key_id": "base-id"}, map[string]string{"secret_access_key": "base-secret"})
	r := request(providermint.ProviderAWS, st, policyConfig(awsPolicy()), &recorder{})
	r.Scope = map[string][]string{"role_arn": {awsPolicy().AWS.RoleARN}, "duration": {"900"}}
	r.Endpoints.AWSSTS = srv.URL
	s, err := providermint.Mint(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, "900", form.Get("DurationSeconds"))
	assert.JSONEq(t, string(awsPolicy().AWS.SessionPolicy), form.Get("Policy"))
	value, ok := s.Value("secret_access_key")
	require.True(t, ok)
	assert.Equal(t, "session-key", string(value))
	require.NoError(t, s.Close())
	assert.Empty(t, s.Fields)
	r.Scope = nil
	s, err = providermint.Mint(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, "3600", form.Get("DurationSeconds"))
	require.NoError(t, s.Close())
}

func TestAWSMintRefusesBeforeReadingCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scope  map[string][]string
		policy config.MintPolicy
		caller mint.CallerKind
	}{
		{"no policy", nil, config.MintPolicy{}, mint.CallerService},
		{"agent", nil, awsPolicy(), mint.CallerAgent},
		{"other role", map[string][]string{"role_arn": {"arn:aws:iam::123456789012:role/Admin"}}, awsPolicy(), mint.CallerService},
		{"unbounded duration", map[string][]string{"duration": {"7200"}}, awsPolicy(), mint.CallerService},
		{"duration overflow", map[string][]string{"duration": {"999999999999999999999"}}, awsPolicy(), mint.CallerService},
		{"multiple roles", map[string][]string{"role_arn": {"a", "b"}}, awsPolicy(), mint.CallerService},
		{"multiple durations", map[string][]string{"duration": {"900", "1800"}}, awsPolicy(), mint.CallerService},
		{"policy override", map[string][]string{"session_policy": {`{"Statement":[]}`}}, awsPolicy(), mint.CallerService},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(providermint.ProviderAWS, nil, policyConfig(tc.policy), &recorder{})
			r.Caller, r.Scope = tc.caller, tc.scope
			secret, err := providermint.Mint(context.Background(), r)
			require.Error(t, err)
			assert.Nil(t, secret)
		})
	}
}

func TestAWSMintReportsMissingFieldsAndProviderFailure(t *testing.T) {
	for _, fields := range []struct{ config, secret map[string]string }{
		{},
		{config: map[string]string{"access_key_id": "base-id"}},
		{config: map[string]string{"access_key_id": "base-id"}, secret: map[string]string{"secret_access_key": "base-secret"}},
	} {
		r := request(providermint.ProviderAWS, fill(t, providermint.ProviderAWS, fields.config, fields.secret), policyConfig(awsPolicy()), &recorder{})
		r.Endpoints.AWSSTS = "http://127.0.0.1:1"
		secret, err := providermint.Mint(context.Background(), r)
		require.Error(t, err)
		assert.Nil(t, secret)
		assert.NotContains(t, err.Error(), "base-secret")
	}
}
