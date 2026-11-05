package strategies

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// MaxAWSSessionDuration is the longest session MintScoped asks STS for.
const MaxAWSSessionDuration = time.Hour

const (
	minAWSSessionDuration = 15 * time.Minute
	// maxSessionPolicyLen is the plain-text size STS accepts for an inline
	// session policy.
	maxSessionPolicyLen = 2048
	// stsClockSkew absorbs drift between this host and STS when the reply's
	// expiry is compared with the lifetime that was asked for.
	stsClockSkew = 2 * time.Minute
)

// ErrAWSScopeMismatch is returned when STS answered with a session other than
// the one requested. No credential is returned with it.
var ErrAWSScopeMismatch = errors.New("aws_sts: issued session does not match the requested scope")

// roleSessionNameRe matches characters that are NOT allowed in AWS RoleSessionName.
// Allowed: a-z, A-Z, 0-9, =, ,, ., @, _, -.
var roleSessionNameRe = regexp.MustCompile(`[^a-zA-Z0-9=,.@_-]`)

// AWSScope is what one STS session may do: the permissions of the role
// intersected with SessionPolicy, for at most Duration.
type AWSScope struct {
	// SessionName becomes the role session name; STS echoes it in the ARN of
	// the assumed role, which is how the reply is matched to the request.
	SessionName string
	// SessionPolicy is the inline IAM policy that narrows the role. It is
	// required: an unrestricted AssumeRole is never issued.
	SessionPolicy string
	// Duration defaults to MaxAWSSessionDuration and may not exceed it.
	Duration time.Duration
}

// AWSCredentials is one STS session.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string //nolint:gosec // G117: session token of a scoped STS session, held in memory only
	Expiration      time.Time
}

// Zero overwrites the secret fields. Go strings are immutable, so this drops
// the references; the bytes go with the next collection.
func (c *AWSCredentials) Zero() { *c = AWSCredentials{} }

// AWSStsStrategy calls STS AssumeRole with a session policy using Signature
// Version 4. No AWS SDK is used.
type AWSStsStrategy struct {
	provider string
	roleARN  string
	region   string
	endpoint string
	// getBaseCredentials returns the long-lived key pair that may assume the role.
	getBaseCredentials func(namespace string) (accessKeyID, secretAccessKey string, err error)
	httpClient         *http.Client
	now                func() time.Time
}

// AWSStsOption configures an AWSStsStrategy.
type AWSStsOption func(*AWSStsStrategy)

// WithSTSEndpoint points the strategy at another STS endpoint URL.
func WithSTSEndpoint(endpoint string) AWSStsOption {
	return func(s *AWSStsStrategy) { s.endpoint = strings.TrimRight(endpoint, "/") }
}

// WithSTSHTTPClient replaces the HTTP client.
func WithSTSHTTPClient(c *http.Client) AWSStsOption {
	return func(s *AWSStsStrategy) { s.httpClient = c }
}

// WithSTSClock replaces the clock used to check the reply's expiry.
func WithSTSClock(now func() time.Time) AWSStsOption {
	return func(s *AWSStsStrategy) { s.now = now }
}

// NewAWSStsStrategy creates an AWSStsStrategy.
func NewAWSStsStrategy(
	roleARN, region string,
	getBaseCredentials func(namespace string) (string, string, error),
	opts ...AWSStsOption,
) *AWSStsStrategy {
	s := &AWSStsStrategy{
		provider:           "aws",
		roleARN:            roleARN,
		region:             region,
		endpoint:           "https://sts." + region + ".amazonaws.com",
		getBaseCredentials: getBaseCredentials,
		httpClient:         &http.Client{Timeout: 15 * time.Second},
		now:                time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Provider returns the provider slug.
func (s *AWSStsStrategy) Provider() string { return s.provider }

// MintScoped assumes the role with the session policy and duration of scope
// and checks the reply: the assumed-role ARN must name the requested role and
// session, and the session may not outlive the requested duration. STS has no
// revocation call, so a reply that does not match is dropped unused.
func (s *AWSStsStrategy) MintScoped(ctx context.Context, namespace string, scope AWSScope) (AWSCredentials, error) {
	scope, err := normalizeAWSScope(scope)
	if err != nil {
		return AWSCredentials{}, err
	}
	accessKeyID, secretAccessKey, err := s.getBaseCredentials(namespace)
	if err != nil {
		return AWSCredentials{}, broker.ErrUnsupportedExchange
	}

	form := url.Values{}
	form.Set("Action", "AssumeRole")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", s.roleARN)
	form.Set("RoleSessionName", scope.SessionName)
	form.Set("DurationSeconds", strconv.Itoa(int(scope.Duration.Seconds())))
	form.Set("Policy", scope.SessionPolicy)
	payload := []byte(form.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/", bytes.NewReader(payload))
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("aws_sts: build request: %w", err)
	}
	s.sign(req, payload, accessKeyID, secretAccessKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("aws_sts: http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("aws_sts: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return AWSCredentials{}, fmt.Errorf("aws_sts: STS returned %d", resp.StatusCode)
	}

	var parsed struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"AssumeRoleResult>Credentials"`
		AssumedRoleARN string `xml:"AssumeRoleResult>AssumedRoleUser>Arn"`
	}
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return AWSCredentials{}, fmt.Errorf("aws_sts: parse XML: %w", err)
	}
	c := parsed.Credentials
	exp, err := time.Parse(time.RFC3339, c.Expiration)
	if err != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return AWSCredentials{}, fmt.Errorf("%w: incomplete credentials", ErrAWSScopeMismatch)
	}
	if !strings.HasSuffix(parsed.AssumedRoleARN, ":assumed-role/"+roleName(s.roleARN)+"/"+scope.SessionName) {
		return AWSCredentials{}, fmt.Errorf("%w: assumed role %q is not the requested role session", ErrAWSScopeMismatch, parsed.AssumedRoleARN)
	}
	now := s.now()
	if !exp.After(now) || exp.After(now.Add(scope.Duration+stsClockSkew)) {
		return AWSCredentials{}, fmt.Errorf("%w: session expires at %s, outside the requested %s", ErrAWSScopeMismatch, exp.UTC().Format(time.RFC3339), scope.Duration)
	}
	return AWSCredentials{
		AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Expiration: exp,
	}, nil
}

func normalizeAWSScope(scope AWSScope) (AWSScope, error) {
	scope.SessionName = roleSessionNameRe.ReplaceAllString(scope.SessionName, "_")
	if len(scope.SessionName) > 64 {
		scope.SessionName = scope.SessionName[:64]
	}
	if len(scope.SessionName) < 2 {
		return AWSScope{}, errors.New("aws_sts: a session name of at least two characters is required")
	}
	if scope.SessionPolicy == "" {
		return AWSScope{}, errors.New("aws_sts: a session policy is required; an unrestricted role session is never issued")
	}
	if len(scope.SessionPolicy) > maxSessionPolicyLen || !json.Valid([]byte(scope.SessionPolicy)) {
		return AWSScope{}, fmt.Errorf("aws_sts: the session policy must be JSON of at most %d bytes", maxSessionPolicyLen)
	}
	if scope.Duration == 0 {
		scope.Duration = MaxAWSSessionDuration
	}
	if scope.Duration < minAWSSessionDuration || scope.Duration > MaxAWSSessionDuration {
		return AWSScope{}, fmt.Errorf("aws_sts: the session duration must be between %s and %s", minAWSSessionDuration, MaxAWSSessionDuration)
	}
	return scope, nil
}

// roleName is the last segment of a role ARN's resource, which is what
// appears in the ARN of the assumed role regardless of the role's path.
func roleName(roleARN string) string {
	_, resource, _ := strings.Cut(strings.TrimPrefix(roleARN, "arn:"), ":iam::")
	_, resource, _ = strings.Cut(resource, ":")
	resource = strings.TrimPrefix(resource, "role/")
	if i := strings.LastIndex(resource, "/"); i >= 0 {
		resource = resource[i+1:]
	}
	return resource
}

// sign adds the Signature Version 4 headers for an STS POST.
func (s *AWSStsStrategy) sign(req *http.Request, payload []byte, accessKeyID, secretAccessKey string) {
	now := s.now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")
	const contentType = "application/x-www-form-urlencoded; charset=utf-8"

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Amz-Date", amzDate)
	host := req.URL.Host
	signedHeaders := "content-type;host;x-amz-date"
	canonicalRequest := strings.Join([]string{
		http.MethodPost, "/", "",
		"content-type:" + contentType + "\nhost:" + host + "\nx-amz-date:" + amzDate + "\n",
		signedHeaders,
		sha256hex(payload),
	}, "\n")

	credScope := dateStamp + "/" + s.region + "/sts/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, credScope, sha256hex([]byte(canonicalRequest))}, "\n")
	signature := hmacHex(deriveSigningKey(secretAccessKey, dateStamp, s.region, "sts"), []byte(stringToSign))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, credScope, signedHeaders, signature))
}

// sha256hex returns the lowercase hex-encoded SHA256 of data.
func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// hmacHex returns the lowercase hex-encoded HMAC-SHA256 of data with key.
func hmacHex(key, data []byte) string { return hex.EncodeToString(hmacBytes(key, data)) }

// deriveSigningKey derives the AWS Signature Version 4 signing key.
func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacBytes([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacBytes(kDate, []byte(region))
	kService := hmacBytes(kRegion, []byte(service))
	return hmacBytes(kService, []byte("aws4_request"))
}

func hmacBytes(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
