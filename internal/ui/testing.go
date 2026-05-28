//go:build !release

package ui

import "net/http"

// TestServeHTTP allows tests to call into the server's mux directly without
// needing a real TCP connection. It is compiled out in release builds.
func (s *Server) TestServeHTTP(w http.ResponseWriter, r *http.Request) {
	chain(s.mux, SecurityHeaders, StrictCSP).ServeHTTP(w, r)
}
