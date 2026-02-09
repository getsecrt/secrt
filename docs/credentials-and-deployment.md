# Credentials & Deployment Security

## Policy

This project handles secrets on behalf of users. Our own operational credentials must be managed accordingly.

### Rules

1. **Never commit credentials to git.** No `.env` files, no API keys, no peppers, no database passwords — not even in "example" values that look real. `.env.example` may contain placeholder keys with empty values only.

2. **`.env` files are for local development only.** The server auto-loads `.env` when `ENV != production` as a convenience. In production, credentials must come from a controlled source (see below).

3. **Production credentials must be restricted at the filesystem level.** Credential files must be owned by root with mode `0600` (readable only by root). The application process must not have direct read access to the credential file after startup.

4. **`API_KEY_PEPPER` is mandatory in production.** The server enforces this: it refuses to start when `ENV=production` and `API_KEY_PEPPER` is empty.

5. **Database passwords must not be empty in production.** Use strong, randomly generated passwords for `DB_PASSWORD` or embed credentials in `DATABASE_URL`.

6. **Rotate credentials when compromised.** If a pepper, database password, or API key is leaked, rotate it immediately. Pepper rotation invalidates all existing API keys (by design — they can be re-issued).

### Sensitive environment variables

| Variable | Contains | Notes |
|---|---|---|
| `API_KEY_PEPPER` | HMAC pepper for API key hashing | Rotation invalidates all API keys |
| `DB_PASSWORD` | Database credential | |
| `DATABASE_URL` | Full connection string (may embed password) | Prefer this over individual `DB_*` vars in production |
| `DB_SSLROOTCERT` | Path to CA certificate | Not a secret itself, but its absence weakens TLS |

## Recommended Production Setup (Single Server)

For a single Linux server (e.g. a DigitalOcean droplet), the simplest secure approach uses **systemd `EnvironmentFile=`** with restricted file permissions.

### 1. Create the credential file

```bash
sudo mkdir -p /etc/secrt-server
sudo touch /etc/secrt-server/env
sudo chmod 600 /etc/secrt-server/env
sudo chown root:root /etc/secrt-server/env
```

Edit with `sudo`:

```bash
sudo editor /etc/secrt-server/env
```

Contents (example — use real values):

```
ENV=production
LISTEN_ADDR=127.0.0.1:8080
PUBLIC_BASE_URL=https://secrt.ca
LOG_LEVEL=info
DATABASE_URL=postgres://secrt_app:STRONG_PASSWORD@127.0.0.1:5432/secrt?sslmode=disable
API_KEY_PEPPER=generated-random-pepper-value
```

Generate a pepper:

```bash
openssl rand -base64 32
```

### 2. Create a systemd service unit

Place at `/etc/systemd/system/secrt-server.service`:

```ini
[Unit]
Description=secrt.ca one-time secret server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
ExecStart=/opt/secrt-server/secrt-server
EnvironmentFile=/etc/secrt-server/env
Restart=on-failure
RestartSec=5

# Security hardening
User=secrt-server
Group=secrt-server
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/
ReadWritePaths=/tmp

# The service process cannot read the EnvironmentFile after startup.
# systemd injects the variables before dropping privileges.

[Install]
WantedBy=multi-user.target
```

### 3. Create the service user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin secrt-server
```

### 4. Deploy the binary

```bash
sudo mkdir -p /opt/secrt-server
sudo cp secrt-server /opt/secrt-server/
sudo chmod 755 /opt/secrt-server/secrt-server
```

### 5. Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable secrt-server
sudo systemctl start secrt-server
sudo journalctl -u secrt-server -f
```

### 6. Reverse proxy (nginx)

The server listens on `127.0.0.1:8080`. Put nginx or Caddy in front for TLS termination.

#### IP privacy in access logs

This is a privacy-sensitive service. **Do not log full client IPs.** Truncate the last octet of IPv4 addresses and the last 80 bits of IPv6 addresses. This preserves enough information to detect /24 abuse clusters and geographic patterns without identifying individual users.

Add the following to your `http {}` block (e.g., in `/etc/nginx/nginx.conf` or a conf.d snippet):

```nginx
# Truncate IPs: 1.2.3.4 → 1.2.3.0, 2001:db8::1 → 2001:db8::
map $remote_addr $truncated_ip {
    ~(?P<prefix>\d+\.\d+\.\d+)\.\d+$    $prefix.0;
    ~(?P<prefix>[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+):    $prefix::;
    default                               0.0.0.0;
}

log_format secrt '$truncated_ip - $remote_user [$time_local] '
                 '"$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent"';
```

Then reference this format in the server block:

```nginx
server {
    listen 443 ssl http2;
    server_name secrt.ca;

    access_log /var/log/nginx/secrt-access.log secrt;

    ssl_certificate     /etc/letsencrypt/live/secrt.ca/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/secrt.ca/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> **Note:** The `X-Forwarded-For` header sent to the backend still contains the full IP — this is needed for rate limiting (the app hashes it in memory). Only the nginx *log file* is truncated.

#### Responding to active abuse

If you are under active attack and need full IPs temporarily:

1. Switch `access_log` to the default `combined` format (which logs full IPs).
2. Respond to the abuse (block at firewall, report, etc.).
3. Revert to the `secrt` format and **delete the full-IP log** when done.

Do not leave full IP logging enabled as the default.

#### `X-Privacy-Log` header (application-level verification)

The Go application can verify that the reverse proxy has been configured for privacy-preserving logging. This is done via a convention header that the reverse proxy sets on every proxied request.

Add this directive inside the `location /` block that proxies to the Go backend:

```nginx
proxy_set_header X-Privacy-Log "truncated-ip";
```

The application checks for this header on the first proxied request (identified by the presence of `X-Forwarded-For`). If the header is missing or has an unrecognized value, the application logs a structured warning:

```json
{"level":"WARN","msg":"privacy_log_check","status":"missing","msg":"reverse proxy did not send X-Privacy-Log header; access logs may contain full client IP addresses."}
```

If the header is present and correct, an informational confirmation is logged once at startup.

**Header contract:**

| `X-Privacy-Log` value | Meaning |
|---|---|
| `truncated-ip` | Reverse proxy truncates IPs to /24 (IPv4) or /48 (IPv6) before writing access logs |
| (absent) | Unknown logging configuration — application warns |
| any other value | Unrecognized mode — application warns |

This is an advisory check only — it does not block requests. The header is an internal signal between the reverse proxy and the application and is not forwarded to clients.

For other reverse proxies (Caddy, Traefik, HAProxy), set the same header after configuring their equivalent IP truncation/anonymization.

## Why Not Other Approaches?

| Approach | Verdict | Reason |
|---|---|---|
| `.env` in production | **No** | Readable by app user, often in repo directory, easy to accidentally commit |
| systemd `EnvironmentFile=` | **Yes — recommended** | Zero cost, zero dependencies, root-only file, vars injected before privilege drop |
| Docker secrets | Fine | Good if already using Docker/Swarm; adds container overhead |
| HashiCorp Vault | Overkill | Requires running another service; justified at scale, not for a single server |
| SOPS + age | Optional upgrade | Encrypts secrets at rest, can version encrypted files in git; good addition on top of systemd approach |
| Cloud secret managers (AWS SSM, DO App Platform) | Fine | Platform-specific; good if already on that platform |

## Upgrade Path: SOPS + age

If you later want secrets encrypted at rest (e.g., to safely store an encrypted copy in a private repo for disaster recovery):

1. Install [SOPS](https://github.com/getsops/sops) and [age](https://github.com/FiloSottile/age)
2. Generate an age key: `age-keygen -o key.txt`
3. Encrypt: `sops --encrypt --age <public-key> env.plain > env.enc`
4. Decrypt at deploy: `sops --decrypt env.enc > /etc/secrt-server/env`
5. Store `env.enc` in the repo; never store `env.plain` or `key.txt`
