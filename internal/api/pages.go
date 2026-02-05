package api

import (
	"fmt"
	"net/http"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>secret.fullspec.ca</title>
  </head>
  <body>
    <h1>secret.fullspec.ca</h1>
    <p>Backend is running. Frontend UI is not implemented yet.</p>
    <h2>Endpoints</h2>
    <ul>
      <li><code>GET /healthz</code></li>
      <li><code>POST /api/v1/public/secrets</code> (anonymous create)</li>
      <li><code>POST /api/v1/secrets</code> (API key create)</li>
      <li><code>POST /api/v1/secrets/{id}/claim</code> (one-time claim)</li>
    </ul>
  </body>
</html>`)
}

func (s *Server) handleSecretPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Secret %s</title>
  </head>
  <body>
    <h1>Secret</h1>
    <p>This is a placeholder page for secret <code>%s</code>.</p>
    <p>This service is designed for client-side (zero-knowledge) encryption. A browser UI is not wired up yet.</p>
    <p>Use a compatible client/CLI to claim and decrypt the stored envelope via <code>POST /api/v1/secrets/%s/claim</code>.</p>
  </body>
</html>`, id, id, id)
}

func (s *Server) handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
}
