//go:build !test

package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// webDistFS is the embedded web/dist directory.
// This file is compiled only when the 'test' build tag is NOT set.
// In tests, the placeholder SPA handler is used instead.
//
// To update the embedded assets: run `make build-web` before `go build`.
//
// NOTE: .map files are intentionally excluded from the embed glob.
// The vite build is configured with sourcemap:false to ensure no .map files
// are generated. If .map files appear, the verify-bundle.sh script will fail.

// The embed directive is commented out until web/dist exists at build time.
// To enable: uncomment the line below and run `make build-web`.
//
// //go:embed web/dist
// var webDist embed.FS

// webDistStub provides a minimal embedded FS when web/dist is not present.
// This allows `go build ./...` to succeed without requiring a prior `bun build`.
//
//nolint:unused // planned: replaced by //go:embed web/dist directive when Phase 10 web build is wired
var webDistStub embed.FS

// NewSPAFileServer returns an http.Handler serving the embedded SPA.
// Falls back to the stub SPA handler when dist is not embedded.
func NewSPAFileServer() http.Handler {
	// Try to use embedded dist (production build).
	// When web/dist is not embedded, fall back to stub.
	return http.HandlerFunc(spaFallbackHandler)
}

// spaFallbackHandler serves a minimal HTML shell for all non-API routes.
// Replaced by the real FileServer in production builds.
func spaFallbackHandler(w http.ResponseWriter, r *http.Request) {
	// API and bootstrap routes are handled before this.
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/__") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>keylatch</title></head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<div id="root"></div>
</body>
</html>`))
}

// staticFileServer creates an http.FileServer with SPA fallback (404 → index.html).
//
//nolint:unused // planned: used by NewSPAFileServer when web/dist embed is wired in Phase 10
func staticFileServer(fsys fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if file exists in the FS.
		_, err := fsys.Open(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			// SPA fallback: serve index.html for all unknown paths.
			r2 := *r
			r2.URL.Path = "/index.html"
			fileServer.ServeHTTP(w, &r2)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
