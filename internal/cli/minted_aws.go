package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/awscreds"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

// mintAWSSTSEndpoint overrides the STS endpoint in tests.
var mintAWSSTSEndpoint = ""

const (
	awsKeyIDField     = "access_key_id"
	awsSecretField    = "secret_access_key"
	awsURIField       = "container_credentials_uri"
	awsAuthTokenField = "container_authorization_token"
)

// awsCredential is the credential endpoint of one run. The command gets its
// address and the token that opens it; STS credentials are minted when the
// command first asks for them.
type awsCredential struct{ srv *awscreds.Server }

func (c *awsCredential) Value(_ context.Context, field string) ([]byte, error) {
	switch field {
	case awsURIField:
		return []byte(c.srv.URI()), nil
	case awsAuthTokenField:
		return []byte(c.srv.Token()), nil
	}
	return nil, fmt.Errorf("aws credential has no field %q", field)
}

func (c *awsCredential) Close() { c.srv.Close() }

// openAWS applies the connection's mint.aws policy and starts the endpoint.
func openAWS(ctx context.Context, store connections.Store, cfg config.Config, em audit.Emitter, tmpl registry.ConnectionTemplate, req runner.MintOpenRequest) (runner.MintedCredential, error) {
	var policy *config.AWSMintPolicy
	if cp, ok := cfg.Connections[req.Connection]; ok && cp.Mint != nil {
		policy = cp.Mint.AWS
	}
	if err := mint.CheckAWS(policy, req.Caller); err != nil {
		return nil, err
	}
	keyPath := connections.ConfigFieldPath(req.Namespace, tmpl.Category, req.Connection, awsKeyIDField)
	secretPath := connections.SecretFieldPath(req.Namespace, tmpl.Category, req.Connection, awsSecretField)
	for _, p := range []struct{ path, field string }{{keyPath, awsKeyIDField}, {secretPath, awsSecretField}} {
		v, _, err := store.Get(ctx, p.path)
		missing := len(v) == 0
		clear(v)
		if errors.Is(err, backend.ErrNotFound) || (err == nil && missing) {
			return nil, fmt.Errorf("connection %s (namespace %s) has no %s; add it with keylatch connect", req.Connection, req.Namespace, p.field)
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p.field, err)
		}
	}

	var sessionPolicy bytes.Buffer
	if err := json.Compact(&sessionPolicy, policy.SessionPolicy); err != nil {
		return nil, fmt.Errorf("mint.aws session_policy: %w", err)
	}
	region := policy.Region
	if region == "" {
		region = "us-east-1"
	}
	opts := []strategies.AWSStsOption{}
	if mintAWSSTSEndpoint != "" {
		opts = append(opts, strategies.WithSTSEndpoint(mintAWSSTSEndpoint))
	}
	strategy := strategies.NewAWSStsStrategy(policy.RoleARN, region, func(namespace string) (string, string, error) {
		id, _, err := store.Get(ctx, keyPath)
		if err != nil {
			return "", "", err
		}
		secret, _, err := store.Get(ctx, secretPath)
		if err != nil {
			return "", "", err
		}
		defer clear(secret)
		return strings.TrimSpace(string(id)), strings.TrimSpace(string(secret)), nil
	}, opts...)

	srv, err := awscreds.Start(awscreds.Config{
		Minter: strategy, Connection: req.Connection, Namespace: req.Namespace, RoleARN: policy.RoleARN,
		Scope: strategies.AWSScope{
			SessionName:   fmt.Sprintf("keylatch-%s-%d", req.Connection, time.Now().Unix()),
			SessionPolicy: sessionPolicy.String(),
			Duration:      mint.AWSLifetime(policy),
		},
		Caller: req.Caller, Audit: em,
	})
	if err != nil {
		return nil, err
	}
	return &awsCredential{srv: srv}, nil
}
