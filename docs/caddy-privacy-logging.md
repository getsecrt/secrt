# Caddy Reverse Proxy Configuration for secrt

This document describes how to configure [Caddy](https://caddyserver.com/) as a
reverse proxy for secrt with privacy-preserving logging and related security
features.

## Background

secrt is a zero-knowledge secret sharing service. As a privacy-focused product,
access logs must never contain full client IP addresses. The server application
checks for an `X-Privacy-Log: truncated-ip` header from the reverse proxy on
startup and will warn if it is missing.

The current production deployment uses nginx with a custom `log_format` that
truncates IPs via regex `map` blocks. Caddy provides equivalent (and in some
areas superior) functionality through its built-in log filters, which are
purpose-built for this use case and require no plugins.

## Privacy requirements

| Requirement | Detail |
|---|---|
| IPv4 masking | Keep first 24 bits (/24) — zeroes the last octet |
| IPv6 masking | Keep first 48 bits (/48) — zeroes the last 80 bits |
| User-Agent | Strip from access logs |
| Referer | Strip from access logs (could leak secret page URLs) |
| Query strings | Strip from logged URIs (defense-in-depth) |
| Sensitive headers | Redact Cookie, Authorization (Caddy does this by default) |
| Log retention | Bounded size and age to limit exposure window |
| Privacy header | Send `X-Privacy-Log: truncated-ip` to the backend |

## Other requirements

| Requirement | Detail |
|---|---|
| HSTS | `max-age=63072000; includeSubDomains; preload` |
| CSP | Restrictive policy (self-only, inline styles/scripts) |
| TLS | TLS 1.3, automatic certificates via ACME |
| HTTP/3 | Enabled (Caddy enables this by default) |

## Caddyfile

```caddyfile
secrt.ca {
    # Privacy-preserving access log
    log {
        output file /var/log/caddy/secrt.ca_access.log {
            roll_size 50MiB
            roll_keep 5
            roll_keep_for 168h  # 7 days
        }
        format filter {
            wrap json
            fields {
                # Mask IPs: keep /24 for IPv4, /48 for IPv6
                request>remote_ip                ip_mask 24 48
                request>client_ip                ip_mask 24 48
                request>headers>X-Forwarded-For  ip_mask 24 48

                # Strip headers that could leak secret page URLs or
                # fingerprint users
                request>headers>User-Agent  delete
                request>headers>Referer     delete

                # Strip query strings from logged URIs. Secret keys live
                # in the URL fragment (never sent to the server), but
                # defense-in-depth protects against future query use.
                request>uri  query {
                    delete *
                }
            }
        }
    }

    # Security headers
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options           "SAMEORIGIN"
        X-Content-Type-Options    "nosniff"
        Referrer-Policy           "strict-origin-when-cross-origin"
        Content-Security-Policy   "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'self'"
    }

    # Reverse proxy to the secrt Rust backend
    #
    # IMPORTANT: Full IPs are passed to the backend via X-Forwarded-For.
    # The app needs these for rate limiting (IPs are HMAC-hashed in memory
    # with a per-process random key and never persisted in plaintext).
    # Masking only happens at the log-write layer above.
    reverse_proxy localhost:8081 {
        header_up X-Privacy-Log   "truncated-ip"
        header_up X-Real-IP       {remote_host}
        header_up X-Forwarded-For {remote_host}
    }
}

# Redirect www to bare domain
www.secrt.ca {
    redir https://secrt.ca{uri} permanent
}

# Redirect alias domain
secrt.app, www.secrt.app {
    redir https://secrt.ca{uri} permanent
}
```

## How `ip_mask` works

Caddy's `ip_mask` filter is applied at log-write time. It takes two arguments:

```
ip_mask <ipv4_prefix_bits> <ipv6_prefix_bits>
```

- `ip_mask 24 48` keeps the first 24 bits of IPv4 addresses and the first
  48 bits of IPv6 addresses, zeroing the rest.
- Applied to `remote_ip`, `client_ip`, and any header fields that may contain
  IP addresses (including comma-separated lists in `X-Forwarded-For`).

### Examples

| Original IP | Masked output |
|---|---|
| `203.0.113.42` | `203.0.113.0` |
| `2001:db8:abcd:1234:5678:9abc:def0:1234` | `2001:db8:abcd::` |

This is equivalent to the nginx configuration:

```nginx
map $remote_addr $truncated_ip {
    ~^(\d+\.\d+\.\d+)\.\d+$  "$1.0";
    ~^([0-9a-fA-F:]*:[0-9a-fA-F]*:[0-9a-fA-F]*):[0-9a-fA-F:]+$  "$1::";
    default  "0.0.0.0";
}
```

## Privacy features Caddy provides by default

- **Sensitive header redaction**: `Cookie`, `Set-Cookie`, and `Authorization`
  headers are automatically redacted in logs unless `log_credentials` is
  explicitly enabled. This is an improvement over nginx, which requires manual
  configuration to achieve the same.
- **Structured JSON logs**: All log output is structured JSON by default,
  making it straightforward to process, filter, or forward to log aggregation
  systems.
- **Automatic HTTPS**: Caddy obtains and renews TLS certificates automatically
  via ACME, eliminating the need for certbot or snap.

## Additional privacy recommendations

### Recommended (no operational downside)

These are included in the Caddyfile above:

- **Referer header deletion** — A `Referer` header could leak the URL of the
  page a user came from. If a user follows a link from a secrt secret page,
  the referer could expose the secret's URL path. The nginx `privacy` log
  format currently _includes_ `$http_referer`, which is a gap worth fixing
  regardless of whether a Caddy migration happens.

- **Query string stripping** — secrt's secret keys live in the URL fragment
  (which is never sent to the server), so query strings don't currently carry
  sensitive data. Stripping them from logs is defense-in-depth against future
  query parameter use or accidental leakage.

- **Log rotation and retention** — The Caddyfile configures `roll_size`,
  `roll_keep`, and `roll_keep_for` to cap log files at 50 MiB each, keep at
  most 5 rotated files, and delete logs older than 7 days. This limits the
  exposure window if masked logs are ever compromised.

### Considered but not recommended

- **Hash instead of mask for IPs** — Caddy's `hash` filter could replace
  `ip_mask` to make IPs completely irreversible. However, hashed IPs make
  abuse investigation nearly impossible — you can't even identify the subnet
  of an attacker. The /24 mask is a good balance: it prevents identifying
  individuals while still allowing "this came from a Comcast range in
  Chicago" level analysis for dealing with abuse.

- **Request ID correlation** — Caddy can generate request IDs and pass them
  to the backend, which would allow correlating Caddy access logs with app
  logs without relying on timestamps. The secrt app already generates its own
  `x-request-id`, so this would require the app to prefer an upstream ID
  when present. Worth considering but not essential — the app already handles
  this via its own ID generation, and the Caddy config above passes
  `{remote_host}` so the app's existing `get_client_ip()` function works
  unchanged.

### Do not change

- **Full IPs in `X-Forwarded-For` to the backend** — The app needs
  unmasked IPs for rate limiting. IPs are HMAC-SHA256 hashed with a
  per-process random key before being stored in the rate limiter's in-memory
  HashMap, and the raw IP is never persisted to the database. The GC thread
  sweeps stale buckets every 2 minutes and evicts anything idle for over
  10 minutes. Masking must only happen at the log-write layer — never in the
  proxy headers sent to the backend.

## Verifying the privacy check

On first proxied request after startup, the secrt server logs a
`privacy_log_check` entry. With the `X-Privacy-Log: truncated-ip` header
configured above, you should see:

```json
{
  "level": "INFO",
  "fields": {
    "message": "privacy_log_check",
    "status": "ok",
    "mode": "truncated-ip",
    "detail": "reverse proxy declares truncated-ip access logging"
  }
}
```

If the header is missing or has an unexpected value, the server logs a warning
instead. This is advisory only and does not affect request handling.

## Note on the current nginx configuration

The production nginx `privacy` log format has a minor gap: it includes
`$http_referer` in the log line, which could leak secret page URLs via
referrer headers. If continuing with nginx, consider removing `"$http_referer"`
from the `log_format privacy` directive in `/etc/nginx/nginx.conf`.
