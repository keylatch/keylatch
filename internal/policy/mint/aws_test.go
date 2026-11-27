package mint_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func awsPolicy() *config.AWSMintPolicy {
	return &config.AWSMintPolicy{
		RoleARN:       "arn:aws:iam::123456789012:role/Reader",
		SessionPolicy: json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`),
	}
}

func TestCheckAWS(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*config.AWSMintPolicy)
		caller mint.CallerKind
		want   string
	}{
		{"service by default", func(*config.AWSMintPolicy) {}, mint.CallerService, ""},
		{"host by default", func(*config.AWSMintPolicy) {}, mint.CallerHost, ""},
		{"human not by default", func(*config.AWSMintPolicy) {}, mint.CallerHuman, "not allowed"},
		{"human when listed", func(p *config.AWSMintPolicy) { p.Callers = []string{"human"} }, mint.CallerHuman, ""},
		{"agent never", func(*config.AWSMintPolicy) {}, mint.CallerAgent, "agent sessions cannot"},
		{"agent cannot be listed", func(p *config.AWSMintPolicy) { p.Callers = []string{"agent"} }, mint.CallerService, "can never hold"},
		{"unknown caller kind", func(p *config.AWSMintPolicy) { p.Callers = []string{"robot"} }, mint.CallerService, "unknown caller kind"},
		{"not a role", func(p *config.AWSMintPolicy) { p.RoleARN = "arn:aws:iam::123456789012:user/Bob" }, mint.CallerService, "role_arn"},
		{"no session policy", func(p *config.AWSMintPolicy) { p.SessionPolicy = nil }, mint.CallerService, "session_policy"},
		{"session policy not json", func(p *config.AWSMintPolicy) { p.SessionPolicy = json.RawMessage("x") }, mint.CallerService, "session_policy"},
		{"session policy too long", func(p *config.AWSMintPolicy) {
			p.SessionPolicy = json.RawMessage(`"` + strings.Repeat("a", 3000) + `"`)
		}, mint.CallerService, "session_policy"},
		{"ttl too short", func(p *config.AWSMintPolicy) { p.MaxTTL = 60 }, mint.CallerService, "max_ttl"},
		{"ttl too long", func(p *config.AWSMintPolicy) { p.MaxTTL = 7200 }, mint.CallerService, "max_ttl"},
		{"ttl in range", func(p *config.AWSMintPolicy) { p.MaxTTL = 1800 }, mint.CallerService, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := awsPolicy()
			tc.mutate(p)
			err := mint.CheckAWS(p, tc.caller)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestCheckAWSWithoutPolicyDenies(t *testing.T) {
	err := mint.CheckAWS(nil, mint.CallerService)
	require.ErrorIs(t, err, mint.ErrDenied)
}

func TestAWSLifetime(t *testing.T) {
	p := awsPolicy()
	assert.Equal(t, 15*time.Minute, mint.AWSLifetime(p))
	p.MaxTTL = 1800
	assert.Equal(t, 30*time.Minute, mint.AWSLifetime(p))
}
