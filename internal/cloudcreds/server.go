// Package cloudcreds serves policy-bound cloud tokens through local metadata protocols.
package cloudcreds

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/providermint"
)

// Config binds one endpoint to the identity and scope already approved for its run.
type Config struct {
	Provider, Connection, Account, Resource string
	Scopes                                  []string
	Initial                                 *providermint.Secret
	Audit                                   audit.Emitter
	Now                                     func() time.Time
}

// Server owns the cached credential and the loopback listener for one child.
type Server struct {
	cfg               Config
	host, token, base string
	server            *http.Server
	ctx               context.Context
	cancel            context.CancelFunc
	mu                sync.Mutex
	closed            bool
	cached            *providermint.Secret
	timer             *time.Timer
}

// Start takes ownership of Initial on success. It never binds a public interface.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Provider != "gcp" && cfg.Provider != "azure" {
		return nil, errors.New("cloudcreds: unsupported provider")
	}
	if cfg.Initial == nil {
		return nil, errors.New("cloudcreds: a minted credential is required")
	}
	if err := audit.Ready(cfg.Audit); err != nil {
		return nil, errors.New("cloudcreds: audit log unavailable")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Provider == "gcp" && (cfg.Account == "" || strings.ContainsAny(cfg.Account, "\r\n") || len(cfg.Scopes) == 0) {
		return nil, errors.New("cloudcreds: service account and scopes are required")
	}
	if cfg.Provider == "azure" && cfg.Resource == "" {
		return nil, errors.New("cloudcreds: resource is required")
	}
	cfg.Scopes = slices.Clone(cfg.Scopes)
	s := &Server{cfg: cfg, cached: cfg.Initial}
	if !s.valid(cfg.Initial) {
		return nil, errors.New("cloudcreds: invalid initial credential")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		_ = ln.Close()
		return nil, err
	}
	s.token = "klph_" + base64.RawURLEncoding.EncodeToString(raw)
	s.host = ln.Addr().String()
	s.base = "http://" + s.host + "/" + s.token
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.server = &http.Server{Handler: http.HandlerFunc(s.serve), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = s.server.Serve(ln) }()
	s.mu.Lock()
	s.timer = time.AfterFunc(cfg.Initial.ExpiresAt.Sub(cfg.Now()), s.Close)
	s.mu.Unlock()
	go func() { <-s.ctx.Done(); s.Close() }()
	return s, nil
}

// MetadataHost is the GCE_METADATA_HOST value, including the session access path.
func (s *Server) MetadataHost() string { return strings.TrimPrefix(s.base, "http://") }

// IdentityEndpoint is the Azure SDK's IDENTITY_ENDPOINT and the IMDS-shaped token route.
func (s *Server) IdentityEndpoint() string { return s.base + "/metadata/identity/oauth2/token" }

// IdentityHeader is the Azure SDK's IDENTITY_HEADER value.
func (s *Server) IdentityHeader() string { return s.token }

// RedactionValues copies values for the output guard without exposing them as environment fields.
func (s *Server) RedactionValues() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil {
		return nil
	}
	value, _ := s.cached.Value("access_token")
	return [][]byte{value}
}

// Close ends access, cancels outstanding exchanges and wipes the cached token.
func (s *Server) Close() {
	s.cancel()
	_ = s.server.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.cached != nil {
		_ = s.cached.Close()
		s.cached = nil
	}
}

func (s *Server) valid(secret *providermint.Secret) bool {
	maxLifetime := time.Hour
	if s.cfg.Provider == "azure" {
		maxLifetime = 90 * time.Minute
	}
	if secret == nil || len(secret.Fields["access_token"]) == 0 || !secret.ExpiresAt.After(s.cfg.Now()) || secret.ExpiresAt.After(s.cfg.Now().Add(maxLifetime+30*time.Second)) {
		return false
	}
	if s.cfg.Provider == "gcp" {
		return sameScopes(secret.Scope["scope"], s.cfg.Scopes)
	}
	return slices.Equal(secret.Scope["resource"], []string{s.cfg.Resource})
}

func sameScopes(a, b []string) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Host != s.host || r.Method != http.MethodGet || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) != 2 || subtle.ConstantTimeCompare([]byte(parts[0]), []byte(s.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if s.cfg.Provider == "gcp" {
		s.serveGCP(w, r)
	} else {
		s.serveAzure(w, r)
	}
}

func (s *Server) serveGCP(w http.ResponseWriter, r *http.Request) {
	path, ok := strings.CutPrefix(r.URL.Path, "/"+s.token+"/computeMetadata/v1/")
	if !ok || r.Header.Get("Metadata-Flavor") != "Google" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Metadata-Flavor", "Google")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "query refused", http.StatusBadRequest)
		return
	}
	if path == "instance/service-accounts/default/token" {
		for key, values := range q {
			if key != "scopes" || len(values) != 1 || !sameScopes(strings.Split(values[0], ","), s.cfg.Scopes) {
				http.Error(w, "scope refused", http.StatusForbidden)
				return
			}
		}
		s.serveToken(w, r)
		return
	}
	if len(q) != 0 && (path != "instance/service-accounts/default/" || len(q) != 1 || q.Get("recursive") != "true" || len(q["recursive"]) != 1) {
		http.Error(w, "query refused", http.StatusBadRequest)
		return
	}
	switch path {
	case "project/project-id":
		_, project, _ := strings.Cut(s.cfg.Account, "@")
		_, _ = fmt.Fprint(w, strings.TrimSuffix(project, ".iam.gserviceaccount.com"))
	case "instance/service-accounts/":
		_, _ = fmt.Fprint(w, "default\n"+s.cfg.Account+"\n")
	case "instance/service-accounts/default/email":
		_, _ = fmt.Fprint(w, s.cfg.Account)
	case "instance/service-accounts/default/scopes":
		_, _ = fmt.Fprint(w, strings.Join(s.cfg.Scopes, "\n"))
	case "instance/service-accounts/default/":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"email": s.cfg.Account, "aliases": []string{"default"}, "scopes": s.cfg.Scopes})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveAzure(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/"+s.token+"/metadata/identity/oauth2/token" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	header := r.Header.Get("X-IDENTITY-HEADER")
	if (header != "" && subtle.ConstantTimeCompare([]byte(header), []byte(s.token)) != 1) || (header == "" && r.Header.Get("Metadata") != "true") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "query refused", http.StatusBadRequest)
		return
	}
	for key, values := range q {
		if (key != "resource" && key != "api-version") || len(values) != 1 {
			http.Error(w, "query refused", http.StatusBadRequest)
			return
		}
	}
	if strings.TrimRight(q.Get("resource"), "/") != strings.TrimRight(s.cfg.Resource, "/") {
		http.Error(w, "resource refused", http.StatusForbidden)
		return
	}
	if q.Get("api-version") != "2018-02-01" && q.Get("api-version") != "2019-08-01" {
		http.Error(w, "unsupported version", http.StatusBadRequest)
		return
	}
	s.serveToken(w, r)
}

func (s *Server) credential(ctx context.Context) ([]byte, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx.Err() != nil || s.cached == nil || !s.cached.ExpiresAt.After(s.cfg.Now()) {
		return nil, time.Time{}, errors.New("cloudcreds: closed")
	}
	token, _ := s.cached.Value("access_token")
	return token, s.cached.ExpiresAt, nil
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	token, expires, err := s.credential(ctx)
	defer clear(token)
	if err != nil {
		http.Error(w, "credentials unavailable", http.StatusBadGateway)
		return
	}
	scope := map[string][]string{"scope": s.cfg.Scopes}
	if s.cfg.Provider == "azure" {
		scope = map[string][]string{"resource": {s.cfg.Resource}}
	}
	if err := s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionMint, Outcome: audit.OutcomeOK, RuntimeMode: "minted", Timestamp: s.cfg.Now().UTC(), Extra: map[string]any{"connection": s.cfg.Connection, "provider": s.cfg.Provider, "scope": scope, "expires_at": expires.UTC().Format(time.RFC3339), "reason": "metadata_token"}}); err != nil || ctx.Err() != nil {
		http.Error(w, "credentials unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	seconds := int64(expires.Sub(s.cfg.Now()).Seconds())
	if seconds <= 0 {
		http.Error(w, "credentials unavailable", http.StatusBadGateway)
		return
	}
	response := map[string]any{"access_token": string(token), "token_type": "Bearer", "expires_in": seconds}
	if s.cfg.Provider == "azure" {
		response["expires_in"] = strconv.FormatInt(seconds, 10)
		response["expires_on"] = strconv.FormatInt(expires.Unix(), 10)
		response["resource"] = s.cfg.Resource
	}
	_ = json.NewEncoder(w).Encode(response)
}
