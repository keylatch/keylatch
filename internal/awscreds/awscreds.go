// Package awscreds serves the AWS container-credentials protocol on loopback.
// A command whose environment names the endpoint and its authorization token
// gets short-lived STS credentials, limited by a session policy, without any
// long-lived key in its environment: the AWS CLI and every AWS SDK read
// AWS_CONTAINER_CREDENTIALS_FULL_URI and AWS_CONTAINER_AUTHORIZATION_TOKEN.
package awscreds

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/callerkind"
)

// refreshMargin is how long before expiry the next request mints a new session.
const refreshMargin = 2 * time.Minute

// Minter issues one scoped STS session.
type Minter interface {
	MintScoped(ctx context.Context, namespace string, scope strategies.AWSScope) (strategies.AWSCredentials, error)
}

// Config describes one endpoint.
type Config struct {
	Minter     Minter
	Connection string
	Namespace  string
	RoleARN    string
	Scope      strategies.AWSScope
	Caller     callerkind.Kind
	// Audit receives one event per mint. The endpoint is refused without it:
	// Keylatch does not issue unaudited credentials.
	Audit audit.Emitter
	// Listener is where the endpoint listens; nil selects an ephemeral
	// loopback port.
	Listener net.Listener
	// Now replaces the clock in tests.
	Now func() time.Time
}

// Server is one command's credential endpoint.
type Server struct {
	cfg    Config
	token  string
	uri    string
	host   string
	srv    *http.Server
	policy string

	mu      sync.Mutex
	creds   strategies.AWSCredentials
	expires time.Time
}

// Start opens the endpoint. It returns when the endpoint is accepting
// connections; Close stops it and drops the cached session.
func Start(cfg Config) (*Server, error) {
	if cfg.Minter == nil {
		return nil, errors.New("awscreds: no minter is configured")
	}
	if err := audit.Ready(cfg.Audit); err != nil {
		return nil, fmt.Errorf("awscreds: the audit log is not available (%v); Keylatch does not issue unaudited credentials", err)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ln := cfg.Listener
	if ln == nil {
		var err error
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			return nil, fmt.Errorf("awscreds: listen: %w", err)
		}
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("awscreds: random source: %w", err)
	}
	sum := sha256.Sum256([]byte(cfg.Scope.SessionPolicy))
	s := &Server{cfg: cfg, token: base64.RawURLEncoding.EncodeToString(raw), policy: hex.EncodeToString(sum[:])}
	s.host = ln.Addr().String()
	s.uri = "http://" + s.host + "/credentials"
	s.srv = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// URI is the value for AWS_CONTAINER_CREDENTIALS_FULL_URI.
func (s *Server) URI() string { return s.uri }

// Token is the value for AWS_CONTAINER_AUTHORIZATION_TOKEN. It opens this
// endpoint only and is worth nothing once the run ends.
func (s *Server) Token() string { return s.token }

// Close stops the endpoint and drops the cached session.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
	s.mu.Lock()
	s.creds.Zero()
	s.expires = time.Time{}
	s.mu.Unlock()
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	// A request carrying a Host other than the loopback address is a DNS
	// rebinding attempt from a browser.
	if r.Host != s.host {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet || r.URL.Path != "/credentials" {
		http.NotFound(w, r)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(s.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	creds, err := s.session(r.Context())
	if err != nil {
		http.Error(w, "credentials unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"AccessKeyId":     creds.AccessKeyID,
		"SecretAccessKey": creds.SecretAccessKey,
		"Token":           creds.SessionToken,
		"Expiration":      creds.Expiration.UTC().Format(time.RFC3339),
		"RoleArn":         s.cfg.RoleARN,
	})
}

// session returns the cached session or mints one shortly before it expires.
func (s *Server) session(ctx context.Context) (strategies.AWSCredentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.creds.SecretAccessKey != "" && s.cfg.Now().Add(refreshMargin).Before(s.expires) {
		return s.creds, nil
	}
	s.creds.Zero()
	creds, err := s.cfg.Minter.MintScoped(ctx, s.cfg.Namespace, s.cfg.Scope)
	if err != nil {
		reason := "sts_error"
		if errors.Is(err, strategies.ErrAWSScopeMismatch) {
			reason = "scope_mismatch"
		}
		_ = s.emit(ctx, time.Time{}, audit.OutcomeError, reason)
		return strategies.AWSCredentials{}, err
	}
	if err := s.emit(ctx, creds.Expiration, audit.OutcomeOK, ""); err != nil {
		creds.Zero()
		return strategies.AWSCredentials{}, fmt.Errorf("the audit line could not be written: %w", err)
	}
	s.creds, s.expires = creds, creds.Expiration
	return creds, nil
}

func (s *Server) emit(ctx context.Context, expires time.Time, outcome audit.Outcome, reason string) error {
	extra := map[string]any{
		"connection":            s.cfg.Connection,
		"namespace":             s.cfg.Namespace,
		"caller_kind":           string(s.cfg.Caller),
		"role_arn":              s.cfg.RoleARN,
		"session_policy_sha256": s.policy,
	}
	if !expires.IsZero() {
		extra["expires_at"] = expires.UTC().Format(time.RFC3339)
	}
	if reason != "" {
		extra["reason"] = reason
	}
	return s.cfg.Audit.Emit(ctx, audit.Event{
		Timestamp: time.Now().UTC(), Action: audit.ActionMint, Outcome: outcome, RuntimeMode: "minted", Extra: extra,
	})
}
