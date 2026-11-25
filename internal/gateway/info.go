package gateway

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/gateway/token"
)

// InfoPath serves the effective, value-free gateway settings.
const InfoPath = "/info"

// infoHandler answers with ServerOptions.Info. It sits behind the source
// allowlist like every route and also needs a valid session token (any
// capability): the reply names repositories and permissions, and every
// legitimate caller already holds a token, so the extra check costs nothing.
func (s *Server) infoHandler(w http.ResponseWriter, r *http.Request) {
	jwtStr, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || jwtStr == "" {
		writeError(w, http.StatusUnauthorized, "missing_token", "authorization token required")
		return
	}
	if _, err := token.Verify(jwtStr, r, s.opts.SigningKey, s.opts.TokenStorePath); err != nil {
		writeError(w, http.StatusUnauthorized, "token_invalid", "token verification failed")
		s.logAudit(r.Context(), audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{"error": "token_invalid"})
		return
	}
	out, err := json.Marshal(s.opts.Info)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode_failed", "failed to encode the reply")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out)
}
