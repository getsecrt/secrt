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
    <title>secrt.ca</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-zinc-950 text-zinc-100 min-h-screen flex items-center justify-center antialiased">
    <div class="max-w-lg w-full mx-auto px-6 py-16">

      <div class="text-center mb-10">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-zinc-800/80 border border-zinc-700/50 mb-6 shadow-lg shadow-emerald-500/5">
          <svg class="w-8 h-8 text-emerald-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
          </svg>
        </div>
        <h1 class="text-3xl font-bold tracking-tight">secrt<span class="text-emerald-400">.</span>ca</h1>
        <p class="mt-3 text-zinc-400">One-time secret sharing with zero-knowledge encryption</p>
      </div>

      <div class="rounded-xl bg-zinc-900/60 border border-zinc-800 p-5 mb-4">
        <div class="flex items-center gap-2.5 mb-3">
          <span class="relative flex h-2.5 w-2.5">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400"></span>
          </span>
          <span class="text-sm font-medium text-zinc-300">Backend is running</span>
        </div>
        <p class="text-sm text-zinc-500 leading-relaxed">The browser UI is under development. Use the <a href="https://github.com/jdlien/secret" class="text-emerald-400/80 hover:text-emerald-400 underline decoration-zinc-700 hover:decoration-emerald-400/40 transition-colors">CLI</a> or API to create and claim secrets.</p>
      </div>

      <div class="rounded-xl bg-zinc-900/60 border border-zinc-800 p-5">
        <h2 class="text-xs font-semibold uppercase tracking-widest text-zinc-500 mb-4">API Endpoints</h2>
        <div class="space-y-3">
          <div class="flex items-start gap-3">
            <code class="shrink-0 rounded bg-zinc-800 px-2 py-0.5 text-xs font-medium text-emerald-400 border border-zinc-700/50">GET</code>
            <code class="text-sm text-zinc-300">/healthz</code>
          </div>
          <div class="flex items-start gap-3">
            <code class="shrink-0 rounded bg-zinc-800 px-2 py-0.5 text-xs font-medium text-sky-400 border border-zinc-700/50">POST</code>
            <div>
              <code class="text-sm text-zinc-300">/api/v1/public/secrets</code>
              <span class="text-xs text-zinc-600 ml-2">anonymous</span>
            </div>
          </div>
          <div class="flex items-start gap-3">
            <code class="shrink-0 rounded bg-zinc-800 px-2 py-0.5 text-xs font-medium text-sky-400 border border-zinc-700/50">POST</code>
            <div>
              <code class="text-sm text-zinc-300">/api/v1/secrets</code>
              <span class="text-xs text-zinc-600 ml-2">api key</span>
            </div>
          </div>
          <div class="flex items-start gap-3">
            <code class="shrink-0 rounded bg-zinc-800 px-2 py-0.5 text-xs font-medium text-sky-400 border border-zinc-700/50">POST</code>
            <div>
              <code class="text-sm text-zinc-300">/api/v1/secrets/{id}/claim</code>
              <span class="text-xs text-zinc-600 ml-2">one-time claim</span>
            </div>
          </div>
        </div>
      </div>

      <p class="text-center text-xs text-zinc-700 mt-8">End-to-end encrypted &middot; Secrets are deleted after a single read</p>
    </div>
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
    <title>secrt.ca &middot; Secret %s</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-zinc-950 text-zinc-100 min-h-screen flex items-center justify-center antialiased">
    <div class="max-w-lg w-full mx-auto px-6 py-16">

      <div class="text-center mb-10">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-zinc-800/80 border border-zinc-700/50 mb-6 shadow-lg shadow-amber-500/5">
          <svg class="w-8 h-8 text-amber-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 10.5V6.75a4.5 4.5 0 1 1 9 0v3.75M3.75 21.75h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H3.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
          </svg>
        </div>
        <h1 class="text-3xl font-bold tracking-tight">Someone sent you a secret</h1>
        <p class="mt-3 text-zinc-400">This link contains a one-time encrypted message</p>
      </div>

      <div class="rounded-xl bg-zinc-900/60 border border-zinc-800 p-5 mb-4">
        <h2 class="text-xs font-semibold uppercase tracking-widest text-zinc-500 mb-3">Secret ID</h2>
        <code class="block text-sm text-amber-400/90 bg-zinc-800/80 rounded-lg px-4 py-3 border border-zinc-700/50 font-mono break-all select-all">%s</code>
      </div>

      <div class="rounded-xl bg-zinc-900/60 border border-zinc-800 p-5">
        <p class="text-sm text-zinc-400 leading-relaxed mb-4">This service uses <span class="text-zinc-300">zero-knowledge encryption</span>. The server only stores ciphertext&mdash;decryption happens entirely in your browser or CLI.</p>
        <p class="text-sm text-zinc-500 leading-relaxed">The browser UI is not wired up yet. Use a compatible client to claim and decrypt:</p>
        <code class="block mt-3 text-xs text-zinc-400 bg-zinc-800/80 rounded-lg px-4 py-3 border border-zinc-700/50 font-mono break-all">POST /api/v1/secrets/%s/claim</code>
      </div>

      <div class="text-center mt-8">
        <a href="/" class="text-xs text-zinc-600 hover:text-zinc-400 transition-colors">secrt.ca</a>
      </div>
    </div>
  </body>
</html>`, id, id, id)
}

func (s *Server) handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
}
