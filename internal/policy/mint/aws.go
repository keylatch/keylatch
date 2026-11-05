package mint

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/config"
)

const (
	// DefaultAWSTTL is the session lifetime when the policy sets none.
	DefaultAWSTTL = 15 * time.Minute
	// MaxAWSTTL is the longest session a policy may allow.
	MaxAWSTTL = time.Hour
	// maxSessionPolicyBytes is the plain-text limit STS puts on an inline session policy.
	maxSessionPolicyBytes = 2048
)

// ErrInvalidAWSPolicy is wrapped when the configured policy itself is invalid.
var ErrInvalidAWSPolicy = errors.New("invalid mint.aws policy")

// ValidateAWS checks a policy for values that can never be honoured.
func ValidateAWS(p *config.AWSMintPolicy) error {
	if !strings.HasPrefix(p.RoleARN, "arn:") || !strings.Contains(p.RoleARN, ":role/") {
		return fmt.Errorf("%w: role_arn must be the ARN of an IAM role", ErrInvalidAWSPolicy)
	}
	if len(p.SessionPolicy) == 0 || len(p.SessionPolicy) > maxSessionPolicyBytes || !json.Valid(p.SessionPolicy) {
		return fmt.Errorf("%w: session_policy must be an IAM policy document of at most %d bytes; a role session without one is never issued", ErrInvalidAWSPolicy, maxSessionPolicyBytes)
	}
	if p.MaxTTL != 0 && (time.Duration(p.MaxTTL)*time.Second < 15*time.Minute || time.Duration(p.MaxTTL)*time.Second > MaxAWSTTL) {
		return fmt.Errorf("%w: max_ttl %d must be between 900 and %d seconds", ErrInvalidAWSPolicy, p.MaxTTL, int(MaxAWSTTL.Seconds()))
	}
	for _, c := range p.Callers {
		switch CallerKind(c) {
		case CallerService, CallerHost, CallerHuman:
		case CallerAgent:
			return fmt.Errorf("%w: agent sessions can never hold minted AWS credentials", ErrInvalidAWSPolicy)
		default:
			return fmt.Errorf("%w: unknown caller kind %q", ErrInvalidAWSPolicy, c)
		}
	}
	return nil
}

// CheckAWS decides whether caller may run a command with an STS session the
// policy describes. A nil policy denies.
func CheckAWS(p *config.AWSMintPolicy, caller CallerKind) error {
	if caller == CallerAgent {
		return fmt.Errorf("%w: agent sessions cannot hold minted credentials", ErrDenied)
	}
	if p == nil {
		return fmt.Errorf("%w: the connection has no mint.aws policy", ErrDenied)
	}
	if err := ValidateAWS(p); err != nil {
		return err
	}
	allowed := defaultCallers
	if len(p.Callers) > 0 {
		allowed = callerKinds(p.Callers)
	}
	if !slices.Contains(allowed, caller) {
		return fmt.Errorf("%w: caller kind %q is not allowed to run with minted AWS credentials", ErrDenied, caller)
	}
	return nil
}

// AWSLifetime returns the session lifetime the policy asks for.
func AWSLifetime(p *config.AWSMintPolicy) time.Duration {
	if p.MaxTTL == 0 {
		return DefaultAWSTTL
	}
	return time.Duration(p.MaxTTL) * time.Second
}
