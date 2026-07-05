//go:build !test && embedded_ui

package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// webDist contains the Vite production build copied by scripts/sync-embedded-ui.sh.
//
//go:embed web/dist
var webDist embed.FS

// NewSPAFileServer returns an http.Handler serving the embedded browser UI.
func NewSPAFileServer() http.Handler {
	dist, err := fs.Sub(webDist, "web/dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "keylatch UI assets unavailable", http.StatusInternalServerError)
		})
	}
	return staticFileServer(dist)
}

// staticFileServer creates an http.FileServer with SPA fallback (404 -> index.html).
func staticFileServer(fsys fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if f, err := fsys.Open(path); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		r2 := *r
		r2.URL.Path = "/index.html"
		fileServer.ServeHTTP(w, &r2)
	})
}
