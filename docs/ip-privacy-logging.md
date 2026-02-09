# IP Privacy Logging: Implementation Report

*Date: 2026-02-09*

This document describes the nginx IP truncation changes applied to secrt.ca and provides detailed implementation guidance for adding a `X-Privacy-Log` header check to the Go application.

---

## 1. What was done (nginx layer)

### 1.1 IP truncation log format

A new `log_format privacy` was added to `/etc/nginx/nginx.conf` (in the `http{}` block) that truncates IP addresses before they are written to disk:

- **IPv4:** Last octet replaced with `0` (e.g., `192.168.1.234` becomes `192.168.1.0`). This preserves the `/24` subnet, which is sufficient for identifying abusive networks and applying subnet-level blocks, without identifying individual users.
- **IPv6:** Truncated to the first three groups (roughly `/48`), with the remainder replaced by `::`.
- **User-agent stripped:** The `$http_user_agent` field is omitted from the privacy log format. User-agent strings are a well-known browser fingerprinting vector and are not useful for abuse detection on an API-focused service.
- **Referer stripped:** The `$http_referer` field is also omitted, as it can leak the referring page and has no operational value for this service.

The `privacy` log format is used **only** for secrt.ca (both the HTTP redirect block and the HTTPS main block). All other sites on this nginx instance continue using the default `combined` format with full IPs.

### 1.2 Privacy-Log header

A `proxy_set_header X-Privacy-Log "truncated-ip"` directive was added to the secrt.ca proxy block. This header is sent upstream to the Go application on every request and serves as a machine-readable declaration that the reverse proxy has been configured for privacy-preserving logging.

### 1.3 Files changed

- `/etc/nginx/nginx.conf` — added `map $remote_addr $truncated_ip` and `log_format privacy`
- `/etc/nginx/sites-available/secrt.ca.conf` — switched `access_log` to `privacy` format, added `X-Privacy-Log` header

### 1.4 What is NOT affected

- **Rate limiting:** The Go app still receives full, untruncated IPs via `X-Forwarded-For` (and `X-Real-IP`) for in-memory rate limiting. These are never written to disk by the Go app's logging middleware (confirmed: `loggingMiddleware` in `internal/api/middleware.go` logs only `method`, `path`, `status`, `bytes`, `duration_ms`, and `request_id`).
- **Owner key hashing:** Public secret creation uses `hmacOwnerKey()` (in `internal/api/server.go`) to HMAC-hash the client IP with a per-process random key before storing it as `owner_key` in the database. Raw IPs are never persisted to the database.
- **Other sites:** No changes to any other nginx vhost.

---

## 2. Implementation guide: Go application `X-Privacy-Log` check

### 2.1 Design goals

The Go app should:

1. Detect when it is running behind a reverse proxy that has **not** declared privacy-preserving log configuration.
2. Emit a clear, structured warning log that operators will notice during deployment verification.
3. **Not** block requests or refuse to start — this is an advisory check, not a hard gate. The app may legitimately run without a reverse proxy in development.
4. Fire the warning at most once (or at a low frequency) to avoid log spam.
5. Be testable without requiring nginx.

### 2.2 Recommended approach: middleware with `sync.Once`

Add a new middleware function in `internal/api/middleware.go` that checks the first proxied request for the `X-Privacy-Log` header. Use `sync.Once` so the check and log message happen exactly once per process lifetime.

#### Proposed code

```go
// privacyLogCheckMiddleware logs a warning if the reverse proxy has not
// declared privacy-preserving access logging via the X-Privacy-Log header.
//
// The check fires once (on the first request that appears to come through
// a reverse proxy). It is advisory only and does not block requests.
func privacyLogCheckMiddleware(next http.Handler) http.Handler {
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			// Only check when behind a reverse proxy (X-Forwarded-For present).
			if r.Header.Get("X-Forwarded-For") == "" {
				// Direct connection (likely dev/test). Skip the check and
				// reset once so we check again on the next request that
				// does have proxy headers.
				once = sync.Once{} // allow re-check
				return
			}

			val := r.Header.Get("X-Privacy-Log")
			switch val {
			case "truncated-ip":
				slog.Info("privacy_log_check",
					"status", "ok",
					"mode", val,
					"msg", "reverse proxy declares truncated-ip access logging",
				)
			case "":
				slog.Warn("privacy_log_check",
					"status", "missing",
					"msg", "reverse proxy did not send X-Privacy-Log header; "+
						"access logs may contain full client IP addresses. "+
						"See docs/ip-privacy-logging.md for configuration guidance.",
				)
			default:
				slog.Warn("privacy_log_check",
					"status", "unknown",
					"mode", val,
					"msg", "reverse proxy sent unrecognized X-Privacy-Log value; "+
						"expected 'truncated-ip'",
				)
			}
		})
		next.ServeHTTP(w, r)
	})
}
```

**Note on `sync.Once` reset:** The standard `sync.Once` cannot be safely reset after `Do` has started. A cleaner alternative is to use an `atomic.Bool`:

```go
func privacyLogCheckMiddleware(next http.Handler) http.Handler {
	var checked atomic.Bool
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !checked.Load() {
			// Only check when behind a reverse proxy.
			if r.Header.Get("X-Forwarded-For") != "" {
				checked.Store(true)

				val := r.Header.Get("X-Privacy-Log")
				switch val {
				case "truncated-ip":
					slog.Info("privacy_log_check",
						"status", "ok",
						"mode", val,
						"msg", "reverse proxy declares truncated-ip access logging",
					)
				case "":
					slog.Warn("privacy_log_check",
						"status", "missing",
						"msg", "reverse proxy did not send X-Privacy-Log header; "+
							"access logs may contain full client IP addresses. "+
							"See docs/ip-privacy-logging.md for configuration guidance.",
					)
				default:
					slog.Warn("privacy_log_check",
						"status", "unknown",
						"mode", val,
						"msg", "reverse proxy sent unrecognized X-Privacy-Log value; "+
							"expected 'truncated-ip'",
					)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
```

This version correctly skips the check for direct connections (no `X-Forwarded-For`) and waits until a proxied request arrives before committing the result.

#### Where to insert in the middleware chain

In `withMiddleware()` (`internal/api/middleware.go:16`), insert the privacy check as the **outermost** wrapper so it runs before any other middleware:

```go
func withMiddleware(h http.Handler) http.Handler {
	h = recoverMiddleware(h)
	h = requestIDMiddleware(h)
	h = securityHeadersMiddleware(h)
	h = loggingMiddleware(h)
	h = privacyLogCheckMiddleware(h) // outermost — runs first on each request
	return h
}
```

Placing it outermost means it executes before `loggingMiddleware` writes the request log line, so the privacy warning (if any) will appear in the logs before the first request log entry. This makes the warning highly visible in deployment logs.

### 2.3 Header contract

| Header | Value | Meaning |
|---|---|---|
| `X-Privacy-Log` | `truncated-ip` | Reverse proxy truncates IPs to /24 (IPv4) or /48 (IPv6) before writing access logs |
| `X-Privacy-Log` | (absent) | Unknown logging configuration — warn operator |
| `X-Privacy-Log` | any other value | Unrecognized mode — warn operator |

Future values could include `hashed-ip`, `no-log`, or `full-ip` (explicit opt-in to full logging for non-privacy-sensitive deployments). For now, only `truncated-ip` is recognized.

### 2.4 Important: strip the header from responses

The `X-Privacy-Log` header is an internal signal between the reverse proxy and the application. It should **not** be forwarded to clients, as it leaks operational details about logging configuration. The header is a request header (set by `proxy_set_header`), so it is not included in responses by default. No additional action is needed unless custom logic copies request headers to responses.

### 2.5 Security consideration: header trust

The Go app already trusts proxy headers (`X-Forwarded-For`, `X-Real-IP`) only from loopback addresses (`127.0.0.1` / `::1`) — see `clientIP()` in `internal/api/server.go:386`. The `X-Privacy-Log` header check does not need the same trust boundary because:

- It is advisory only (does not affect request processing or security decisions).
- An attacker spoofing `X-Privacy-Log: truncated-ip` can only suppress a warning, not gain access to anything.

If you later want to make this a hard requirement (refuse to serve if the header is missing), you should add the same loopback trust check.

### 2.6 Testing

```go
func TestPrivacyLogCheckMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		xff        string // X-Forwarded-For value
		privacyLog string // X-Privacy-Log value
		wantLevel  slog.Level
		wantCheck  bool   // whether the check should fire
	}{
		{
			name:      "no proxy headers — skip check",
			wantCheck: false,
		},
		{
			name:       "proxied, header present and correct",
			xff:        "1.2.3.4",
			privacyLog: "truncated-ip",
			wantCheck:  true,
			wantLevel:  slog.LevelInfo,
		},
		{
			name:      "proxied, header missing",
			xff:       "1.2.3.4",
			wantCheck: true,
			wantLevel: slog.LevelWarn,
		},
		{
			name:       "proxied, unrecognized value",
			xff:        "1.2.3.4",
			privacyLog: "full-ip",
			wantCheck:  true,
			wantLevel:  slog.LevelWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a custom slog handler that captures log records.
			var records []slog.Record
			handler := &captureHandler{records: &records}
			slog.SetDefault(slog.New(handler))

			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			mid := privacyLogCheckMiddleware(inner)

			req := httptest.NewRequest("GET", "/healthz", nil)
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.privacyLog != "" {
				req.Header.Set("X-Privacy-Log", tt.privacyLog)
			}

			rec := httptest.NewRecorder()
			mid.ServeHTTP(rec, req)

			if tt.wantCheck {
				if len(records) == 0 {
					t.Fatal("expected a log record, got none")
				}
				if records[0].Level != tt.wantLevel {
					t.Errorf("log level = %v, want %v", records[0].Level, tt.wantLevel)
				}
			}
		})
	}
}
```

### 2.7 Production log output examples

When correctly configured (header present):

```json
{
  "time": "2026-02-09T01:15:00Z",
  "level": "INFO",
  "msg": "privacy_log_check",
  "status": "ok",
  "mode": "truncated-ip",
  "msg": "reverse proxy declares truncated-ip access logging"
}
```

When misconfigured (header missing):

```json
{
  "time": "2026-02-09T01:15:00Z",
  "level": "WARN",
  "msg": "privacy_log_check",
  "status": "missing",
  "msg": "reverse proxy did not send X-Privacy-Log header; access logs may contain full client IP addresses. See docs/ip-privacy-logging.md for configuration guidance."
}
```

---

## 3. Deployment checklist for other environments

If secrt-server is deployed behind a different reverse proxy (Caddy, Traefik, HAProxy, etc.), operators should:

1. Configure their proxy's access log to truncate or hash client IPs.
2. Add a request header `X-Privacy-Log: truncated-ip` to signal the Go app.
3. Verify the warning does not appear in the application's startup logs after the first request.

### Caddy example

```caddy
secrt.example.com {
	log {
		output file /var/log/caddy/secrt-access.log
		format transform `{request>client_ip |truncate_ip} - [{ts}] "{request>method} {request>uri}" {status} {size}` {
			# Caddy doesn't have native IP truncation — use a log filter plugin
			# or disable client_ip logging entirely.
		}
	}
	reverse_proxy localhost:8081 {
		header_up X-Privacy-Log "truncated-ip"
		header_up X-Forwarded-For {client_ip}
		header_up X-Real-IP {client_ip}
	}
}
```

### Traefik example

```yaml
http:
  middlewares:
    privacy-headers:
      headers:
        customRequestHeaders:
          X-Privacy-Log: "truncated-ip"
```

---

## 4. Consistency with the secrt.ca spec

The IP truncation approach is consistent with the spec's guidance in `docs/one-time-secret-service.md`:

- **Section 2.4** ("Storage, backups, and 'no traces'"): *"Add strict log hygiene: never log request bodies; avoid logging identifiers at high verbosity."* Full IP addresses are identifiers; truncating them satisfies this guidance.
- **Section 2.6** (Logging): *"Follow OWASP Logging guidance: avoid secrets, PINs, and request bodies in logs."* OWASP also advises collecting only what is necessary (data minimization).
- **Section 3.3** (Transparency): *"Provide minimal, privacy-preserving operational telemetry."* Truncated IPs provide operational signal (subnet-level abuse patterns) without individual identification.
- **Section 5** (Security/ops features): *"Rate limiting / quotas by IP and key"* — this continues to work because rate limiting uses in-memory full IPs (via `X-Forwarded-For`), not the truncated log output.

The Go application's existing privacy posture is already strong:
- `loggingMiddleware` does not log client IPs.
- `hmacOwnerKey()` hashes IPs with a per-process random key before database storage.
- Rate limiters hold full IPs in memory only; they are never persisted.

The nginx truncation change closes the last gap: the reverse proxy's access log was the only place full IPs were written to disk.

---

## 5. Future considerations

- **Log rotation:** Ensure existing nginx access logs with full IPs are rotated out promptly. The default `logrotate` config for nginx typically rotates weekly with 14 days retention. Consider a one-time manual rotation (`nginx -s reopen` after moving the old log file) to purge pre-truncation log entries sooner.
- **Error log:** nginx's `error_log` may occasionally include client IPs in error messages (e.g., connection resets). The `error_log` directive does not support custom formats. This is a low-frequency, low-risk exposure, but be aware of it.
- **Hardening to a hard requirement:** If desired in the future, the middleware check can be upgraded from a warning to a startup-time hard failure (refuse to serve if the first proxied request lacks the header). This would require a configuration flag like `REQUIRE_PRIVACY_LOG=true` to avoid breaking development setups.
