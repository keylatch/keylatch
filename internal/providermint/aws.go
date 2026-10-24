package providermint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy/mint"
)

func mintAWS(ctx context.Context, r Request, p *config.AWSMintPolicy) (*Secret, error) {
	if err := r.rejectOtherKeys(ProviderAWS); err != nil {
		return nil, err
	}
	if err := mint.CheckAWS(p, r.Caller); err != nil {
		return nil, err
	}
	role, err := r.oneScope("role_arn")
	if err != nil {
		return nil, err
	}
	if role != "" && role != p.RoleARN {
		return nil, fmt.Errorf("%w: role_arn differs from the policy's role", mint.ErrDenied)
	}
	duration, err := r.oneScope("duration")
	if err != nil {
		return nil, err
	}
	lifetime := mint.AWSLifetime(p)
	if duration != "" {
		seconds, err := strconv.Atoi(duration)
		if err != nil || seconds < 900 || seconds > int(lifetime/time.Second) {
			return nil, fmt.Errorf("%w: duration must be 900 to %d seconds", mint.ErrDenied, int(lifetime/time.Second))
		}
		lifetime = time.Duration(seconds) * time.Second
	}
	var sessionPolicy bytes.Buffer
	if err := json.Compact(&sessionPolicy, p.SessionPolicy); err != nil {
		return nil, fmt.Errorf("%w: invalid session policy", mint.ErrInvalidAWSPolicy)
	}
	region := p.Region
	if region == "" {
		region = "us-east-1"
	}
	var opts []strategies.AWSStsOption
	if r.Endpoints.AWSSTS != "" {
		opts = append(opts, strategies.WithSTSEndpoint(r.Endpoints.AWSSTS))
	}
	strategy := strategies.NewAWSStsStrategy(p.RoleARN, region, func(string) (string, string, error) {
		id, err := r.config(ctx, "access_key_id")
		if err != nil {
			return "", "", err
		}
		secret, err := r.secretGetter(ctx, "secret_access_key")(r.Namespace)
		if err != nil {
			return "", "", err
		}
		defer clear(secret)
		return id, string(secret), nil
	}, opts...)
	credential, err := strategy.MintScoped(ctx, r.Namespace, strategies.AWSScope{
		SessionName: "keylatch-mint", SessionPolicy: sessionPolicy.String(), Duration: lifetime,
	})
	if err != nil {
		return nil, err
	}
	defer credential.Zero()
	return &Secret{
		Fields: map[string][]byte{
			"access_key_id": []byte(credential.AccessKeyID), "secret_access_key": []byte(credential.SecretAccessKey),
			"session_token": []byte(credential.SessionToken),
		},
		ExpiresAt: credential.Expiration,
		Scope: map[string][]string{
			"role_arn": {p.RoleARN}, "duration": {strconv.Itoa(int(lifetime / time.Second))}, "session_policy": {sessionPolicy.String()},
		},
	}, nil
}
