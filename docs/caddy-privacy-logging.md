# Caddy Reverse Proxy Configuration for secrt

This document describes how to configure [Caddy](https://caddyserver.com/) as a
reverse proxy for secrt with the privacy-preserving logging that the service
requires.

## Background

secrt is a zero-knowledge secret sharing service. As a privacy-focused product,
access logs must never contain full client IP addresses. The server application
checks for an `X-Privacy-Log: truncated-ip` header from the reverse proxy on
startup and will warn if it is missing.

The current production deployment uses nginx with a custom `log_format` that
truncates IPs via regex `map` blocks. Caddy provides equivalent functionality
through its built-in `ip_mask` log filter, which is purpose-built for this use
case and requires no plugins.

## Requirements

| Requirement | Detail |
|---|---|
| IPv4 masking | Keep first 24 bits (/24) — zeroes the last octet |
| IPv6 masking | Keep first 48 bits (/48) — zeroes the last 80 bits |
| User-Agent | Strip from access logs |
| Privacy header | Send `X-Privacy-Log: truncated-ip` to the backend |
| HSTS | `max-age=63072000; includeSubDomains; preload` |
| CSP | Restrictive policy (self-only, inline styles/scripts) |
| TLS | TLS 1.3, automatic certificates via ACME |
| HTTP/3 | Enabled (Caddy enables this by default) |

## Caddyfile

```caddyfile
secrt.ca {
    # Privacy-preserving access log
    log {
        output file /var/log/caddy/secrt.ca_access.log
        format filter {
            wrap json
            fields {
                # Mask IPs: keep /24 for IPv4, /48 for IPv6
                request>remote_ip                ip_mask 24 48
                request>client_ip                ip_mask 24 48
                request>headers>X-Forwarded-For  ip_mask 24 48

                # Strip User-Agent from logs
                request>headers>User-Agent  delete
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

## Additional privacy features Caddy provides by default

- **Sensitive header redaction**: `Cookie`, `Set-Cookie`, and `Authorization`
  headers are automatically redacted in logs unless `log_credentials` is
  explicitly enabled.
- **Structured JSON logs**: All log output is structured JSON by default,
  making it straightforward to process, filter, or forward to log aggregation
  systems.
- **Automatic HTTPS**: Caddy obtains and renews TLS certificates automatically
  via ACME, eliminating the need for certbot or snap.

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
