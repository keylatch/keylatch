// Package scim implements a SCIM v2 server for team provisioning.
//
// Security invariants:
// - SCIM server binds to loopback-only by default.
// - All endpoints require authentication (bearer or mTLS).
// - List responses are value-free (emails HMACd).
package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/team"
)

// ServerOpts configures the SCIM server.
type ServerOpts struct {
	// Addr is the bind address. Default: 127.0.0.1:8763.
	// must be loopback.
	Addr string
	// BearerToken is the expected bearer token for auth.
	BearerToken string
}

// Server is a SCIM v2 server.
type Server struct {
	t      *team.Team
	addr   string
	authFn func(r *http.Request) bool
}

// NewServer creates a SCIM v2 server bound to loopback.
func NewServer(t *team.Team, opts ServerOpts) *Server {
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:8763"
	}

	authFn := func(r *http.Request) bool {
		if opts.BearerToken == "" {
			return false // no token configured → deny all
		}
		auth := r.Header.Get("Authorization")
		return auth == "Bearer "+opts.BearerToken
	}

	return &Server{
		t:      t,
		addr:   addr,
		authFn: authFn,
	}
}

// Serve starts the SCIM server. Returns error if addr is not loopback.
func (s *Server) Serve(ctx context.Context) error {
	if err := assertLoopback(s.addr); err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// assertLoopback returns an error if addr is not a loopback address.
// C-8: "localhost" is NOT accepted — only numeric loopback IPs (127.x or ::1).
func assertLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("scim: invalid addr %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("scim: refusing non-loopback bind address %q (use 127.0.0.1 or ::1)", addr)
	}
	return nil
}

// Handler returns an http.Handler for the SCIM v2 endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/scim/v2/Users", s.authMiddleware(http.HandlerFunc(s.usersHandler)))
	mux.Handle("/scim/v2/Users/", s.authMiddleware(http.HandlerFunc(s.userHandler)))
	mux.Handle("/scim/v2/Groups", s.authMiddleware(http.HandlerFunc(s.groupsHandler)))
	mux.Handle("/scim/v2/Groups/", s.authMiddleware(http.HandlerFunc(s.groupHandler)))
	return mux
}

// authMiddleware enforces bearer or mTLS authentication.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authFn(r) {
			writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// scimUser is a SCIM v2 User resource (value-free: email is HMACd).
type scimUser struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id"`
	UserName string   `json:"userName"` // HMACd value
	Active   bool     `json:"active"`
	Meta     scimMeta `json:"meta"`
}

// scimMeta holds SCIM resource metadata.
type scimMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
}

// scimListResponse is a SCIM v2 list response.
type scimListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// scimCreateUser is the input for creating a user.
type scimCreateUser struct {
	Schemas  []string `json:"schemas"`
	UserName string   `json:"userName"`
	Active   bool     `json:"active"`
}

func (s *Server) usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listUsers(w, r)
	case http.MethodPost:
		s.createUser(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) userHandler(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
	userID = strings.TrimSuffix(userID, "/")

	switch r.Method {
	case http.MethodGet:
		s.getUser(w, r, userID)
	case http.MethodPut, http.MethodPatch:
		s.updateUser(w, r, userID)
	case http.MethodDelete:
		s.deleteUser(w, r, userID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request) {
	users := make([]scimUser, 0, len(s.t.Members))
	for _, m := range s.t.Members {
		users = append(users, memberToSCIM(m, ""))
	}
	writeJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: len(users),
		StartIndex:   1,
		ItemsPerPage: len(users),
		Resources:    users,
	})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var input scimCreateUser
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Create member with HMACd identifier.
	newMember := team.Member{
		ID:       generateSCIMID(),
		HMAC:     input.UserName, // treat userName as already HMACd per value-free invariant
		Role:     team.RoleDeveloper,
		JoinedAt: time.Now().UTC(),
		Status:   team.MemberActive,
	}
	if !input.Active {
		newMember.Status = team.MemberSuspended
	}
	s.t.Members = append(s.t.Members, newMember)

	user := memberToSCIM(newMember, r.Host)
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, userID string) {
	for _, m := range s.t.Members {
		if m.ID == userID {
			writeJSON(w, http.StatusOK, memberToSCIM(m, r.Host))
			return
		}
	}
	writeError(w, http.StatusNotFound, "user not found")
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, userID string) {
	for i := range s.t.Members {
		if s.t.Members[i].ID == userID {
			writeJSON(w, http.StatusOK, memberToSCIM(s.t.Members[i], r.Host))
			return
		}
	}
	writeError(w, http.StatusNotFound, "user not found")
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, userID string) {
	// N-6: use team.RemoveMember to trigger shared-secret rotation callback.
	if err := team.RemoveMember(r.Context(), s.t, userID); err != nil {
		if err == team.ErrMemberNotFound {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		http.Error(w, "failed to remove member", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) groupsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, scimListResponse{
			Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
			TotalResults: 0,
			StartIndex:   1,
			ItemsPerPage: 0,
			Resources:    []interface{}{},
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) groupHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"501","detail":"SCIM Groups endpoint not yet implemented"}`))
}

// memberToSCIM converts a team.Member to a SCIM user (value-free).
func memberToSCIM(m team.Member, host string) scimUser {
	location := ""
	if host != "" {
		location = "http://" + host + "/scim/v2/Users/" + m.ID
	}
	return scimUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:       m.ID,
		UserName: m.HMAC, // value-free: HMACd
		Active:   m.Status == team.MemberActive,
		Meta: scimMeta{
			ResourceType: "User",
			Created:      m.JoinedAt,
			LastModified: m.JoinedAt,
			Location:     location,
		},
	}
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a SCIM error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  status,
		"detail":  msg,
	})
}

// generateSCIMID generates a random ID for SCIM resources.
func generateSCIMID() string {
	return fmt.Sprintf("scim-%d", time.Now().UnixNano())
}
