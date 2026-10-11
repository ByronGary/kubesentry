// Package web embeds the built user interface so the server ships as one binary.
//
// The UI uses hash-based routing, so the only document the server ever has to
// serve for navigation is "/". Everything else is a static asset.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// dist holds the output of `npm run build` in web/ (Vite writes it here).
//
//go:embed all:dist
var dist embed.FS

// Handler serves the embedded UI. Hashed assets are cached for a year;
// index.html is never cached so a new build is picked up on reload.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // the embed directive guarantees dist exists
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Unknown API paths should not fall through to a static file lookup.
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/audit/") {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
