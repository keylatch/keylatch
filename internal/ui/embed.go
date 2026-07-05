//go:build !test && !embedded_ui

package ui

import (
	"net/http"
	"strings"
)

// NewSPAFileServer returns an http.Handler serving the embedded SPA.
// This fallback is used for source builds that do not opt into embedded_ui.
func NewSPAFileServer() http.Handler {
	return http.HandlerFunc(spaFallbackHandler)
}

// spaFallbackHandler serves an explicit diagnostic page for builds that do not
// embed the browser bundle. Release builds must use the embedded_ui build tag.
func spaFallbackHandler(w http.ResponseWriter, r *http.Request) {
	// API and bootstrap routes are handled before this.
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/__") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>keylatch UI unavailable</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:2rem;line-height:1.5;color:#111827;background:#fff}
main{max-width:48rem}
code{background:#f3f4f6;border-radius:4px;padding:.1rem .25rem}
</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<main id="main-content">
<h1>Keylatch UI assets are not embedded</h1>
<p>This binary was built without the browser UI bundle. Release builds should embed <code>web/dist</code>.</p>
<p>From source, run <code>make build-web</code> and rebuild with the <code>embedded_ui</code> build tag.</p>
</main>
</body>
</html>`))
}
