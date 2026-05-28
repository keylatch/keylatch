package strategies

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// stsCredentials represents the structured AWS STS credentials stored in tokenBytes.
// This JSON blob is never exposed in metadata — only in the unexported tokenBytes.
type stsCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"` //nolint:gosec // G117: session_token is a legitimate AWS STS field name; it is credential data stored in encrypted tokenBytes only
	Expiration      string `json:"expiration"`
}

// roleSessionNameRe matches characters that are NOT allowed in AWS RoleSessionName.
// Allowed: a-z, A-Z, 0-9, =, ,, ., @, _, - (N-6).
var roleSessionNameRe = regexp.MustCompile(`[^a-zA-Z0-9=,.@_-]`)

// AWSStsStrategy calls AWS STS AssumeRole using Signature Version 4.
// No AWS SDK is used — the request is signed manually with crypto/hmac and crypto/sha256.
type AWSStsStrategy struct {
	provider    string
	roleARN     string
	stsEndpoint string
	region      string
	// getBaseCredentials retrieves the base AWS key pair for a given namespace.
	getBaseCredentials func(namespace string) (accessKeyID, secretAccessKey string, err error)
	httpClient         *http.Client
}

// NewAWSStsStrategy creates an AWSStsStrategy.
func NewAWSStsStrategy(
	roleARN, region string,
	getBaseCredentials func(namespace string) (string, string, error),
) *AWSStsStrategy {
	return &AWSStsStrategy{
		provider:           "aws",
		roleARN:            roleARN,
		stsEndpoint:        "https://sts.amazonaws.com",
		region:             region,
		getBaseCredentials: getBaseCredentials,
		httpClient:         &http.Client{Timeout: 15 * time.Second},
	}
}

// Provider returns the provider slug.
func (s *AWSStsStrategy) Provider() string { return s.provider }

// Exchange calls STS AssumeRole and returns credentials in tokenBytes as JSON.
func (s *AWSStsStrategy) Exchange(ctx context.Context, actor, sessionID, namespace string) (broker.ExchangeResult, error) {
	accessKeyID, secretAccessKey, err := s.getBaseCredentials(namespace)
	if err != nil {
		return broker.ExchangeResult{}, broker.ErrUnsupportedExchange
	}

	// Build AssumeRole query.
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	params := url.Values{}
	// Sanitize sessionID for AWS RoleSessionName: only a-z, A-Z, 0-9, =, ,, ., @, _, - allowed.
	sanitizedSessionID := roleSessionNameRe.ReplaceAllString(sessionID, "_")
	if len(sanitizedSessionID) > 64 {
		sanitizedSessionID = sanitizedSessionID[:64]
	}
	params.Set("Action", "AssumeRole")
	params.Set("RoleArn", s.roleARN)
	params.Set("RoleSessionName", sanitizedSessionID)
	params.Set("DurationSeconds", "3600")
	params.Set("Version", "2011-06-15")

	canonicalURI := "/"
	canonicalQueryString := params.Encode()
	canonicalHeaders := "host:sts.amazonaws.com\nx-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"
	payloadHash := sha256hex(nil)

	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credScope := dateStamp + "/" + s.region + "/sts/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		sha256hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(secretAccessKey, dateStamp, s.region, "sts")
	sig := hmacHex(signingKey, []byte(stringToSign))

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, credScope, signedHeaders, sig,
	)

	reqURL := s.stsEndpoint + "/?" + canonicalQueryString
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("aws_sts: build request: %w", err)
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Host", "sts.amazonaws.com")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("aws_sts: http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("aws_sts: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return broker.ExchangeResult{}, fmt.Errorf("aws_sts: STS returned %d", resp.StatusCode)
	}

	// Parse STS XML response.
	type Credentials struct {
		AccessKeyID     string `xml:"AccessKeyId"`
		SecretAccessKey string `xml:"SecretAccessKey"`
		SessionToken    string `xml:"SessionToken"`
		Expiration      string `xml:"Expiration"`
	}
	type AssumeRoleResult struct {
		Credentials Credentials `xml:"AssumeRoleResult>Credentials"`
	}
	var result AssumeRoleResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("aws_sts: parse XML: %w", err)
	}

	creds := result.Credentials
	exp, _ := time.Parse(time.RFC3339, creds.Expiration)
	ttl := time.Until(exp)
	if ttl <= 0 {
		ttl = time.Hour
	}

	// Marshal credentials as JSON blob for tokenBytes — never exposed as metadata.
	// S1016: struct literal required; XML Credentials and stsCredentials have different field tags.
	credJSON, err := json.Marshal(stsCredentials{ //nolint:gosec,staticcheck // G117: SessionToken in encrypted tokenBytes only; S1016: different JSON vs XML field tags prevent type conversion
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expiration,
	})
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("aws_sts: marshal credentials: %w", err)
	}

	res := broker.NewExchangeResult(s.provider, "", ttl, broker.FreshExchange, credJSON)
	zeroBytes(credJSON)
	return res, nil
}

// sha256hex returns the lowercase hex-encoded SHA256 of data.
func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

// hmacHex returns the lowercase hex-encoded HMAC-SHA256 of data with key.
func hmacHex(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// deriveSigningKey derives the AWS Signature Version 4 signing key.
func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacBytes([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacBytes(kDate, []byte(region))
	kService := hmacBytes(kRegion, []byte(service))
	kSigning := hmacBytes(kService, []byte("aws4_request"))
	return kSigning
}

func hmacBytes(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
