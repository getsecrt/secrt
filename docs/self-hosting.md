# Self-Hosting secrt

This guide walks through deploying a production-ready secrt instance on a single VPS — Caddy as the reverse proxy + automatic TLS, `secrt-server` as the Rust backend, and PostgreSQL for storage. Targeted at Ubuntu 24.04 on a minimum 1 GB / 1 vCPU box (cheapest tier on most providers); the same steps work fine on larger instances.

This guide was distilled from a real production deployment runbook, so it covers things you actually hit (SSH drop-ins silently disabled by stock images, Postfix listening on `0.0.0.0:25` after `unattended-upgrades` pulls it in, OOM-killer prioritizing PostgreSQL, etc.) — not just the happy path.

Throughout, replace these placeholders with your own values:

| Placeholder | Meaning |
|---|---|
| `your-domain.example` | The domain your secrt instance will run on |
| `secrt-srv` | The server's hostname (whatever you like) |
| `you@your-domain.example` | Your email — Caddy uses this to register Let's Encrypt account |
| `youradmin` | The non-root admin username for SSH |
| `your-old-server` | If migrating from an existing instance, the source server |

Related operator docs:
- [`instance-trust-model.md`](instance-trust-model.md) — what an operator can and can't see
- [`caddy-privacy-logging.md`](caddy-privacy-logging.md) — deeper dive on the Caddy/logging slice
- [`whitepaper.md`](whitepaper.md) — design and threat model

---

## Memory Budget

Target memory budget on a 1 GB box:

| Component | RAM |
|---|---|
| OS + systemd + SSH | ~100 MB |
| PostgreSQL (64 MB shared_buffers) | ~50 MB |
| Caddy (single site) | ~30–40 MB |
| secrt-server | ~3 MB |
| fail2ban + sshd | ~40 MB |
| **Headroom** | **~750 MB free** |

---

## Important Notes Before You Start

- **Do NOT compile Rust on a 1 GB box** — it needs 2+ GB RAM. Download prebuilt binaries from [GitHub Releases](https://github.com/getsecrt/secrt/releases) instead.
- **All secrets/passwords below are placeholders** — generate fresh ones (`openssl rand -base64 32`).
- **Test SSH key login in a second session before closing your current one** when restarting `sshd`. Locking yourself out of a fresh box is a memorable experience.

---

## Phase 1: Initial System Setup

### 1.1 System updates & basics

```bash
apt update && apt upgrade -y
apt install -y curl wget git ufw fail2ban unattended-upgrades \
  apt-listchanges needrestart software-properties-common

# Set timezone to UTC (standard for servers)
timedatectl set-timezone UTC

# Set hostname
hostnamectl set-hostname secrt-srv
```

### 1.2 Create service user

```bash
useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent secrt-server
```

### 1.3 Swap (critical for 1 GB boxes)

A 2 GB swap file is insurance against OOM during traffic spikes or maintenance:

```bash
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Tune swappiness — prefer keeping app memory in RAM
sysctl vm.swappiness=10
echo 'vm.swappiness=10' > /etc/sysctl.d/99-swap.conf
```

### 1.4 Limit journald disk + memory

```bash
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/size.conf << 'EOF'
[Journal]
SystemMaxUse=100M
RuntimeMaxUse=50M
EOF
systemctl restart systemd-journald
```

---

## Phase 2: SSH Hardening

### 2.1 Ensure drop-in includes are enabled

⚠️ **Provider gotcha:** some VPS provider images ship Ubuntu 24.04 with a stock `sshd_config` that does *not* include `Include /etc/ssh/sshd_config.d/*.conf`. Any drop-in you write will silently do nothing. Verify and fix before writing the hardening drop-in:

```bash
# Check
grep -E "^Include" /etc/ssh/sshd_config || echo "MISSING — will add"

# Add at top of file if missing (before any directives; first-match-wins)
if ! grep -qE "^Include" /etc/ssh/sshd_config; then
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
  sed -i '14i\\nInclude /etc/ssh/sshd_config.d/*.conf\n' /etc/ssh/sshd_config
fi
```

Also remove/comment any stock `X11Forwarding yes` line — because it comes *before* any drop-ins, it'd win first-match-wins. Safer to neutralize it:

```bash
sed -i 's/^X11Forwarding yes/#X11Forwarding yes  # overridden by drop-in/' /etc/ssh/sshd_config
```

### 2.2 SSH configuration drop-in

```bash
cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# Authentication
PasswordAuthentication no
KbdInteractiveAuthentication no
MaxAuthTries 3
MaxSessions 10

# Forwarding
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no

# Keepalive
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# Logging
LogLevel VERBOSE
EOF

# Validate before restarting
sshd -t && systemctl restart ssh
```

### 2.3 Verify the drop-in is actually loaded

```bash
# These should match the drop-in, not the stock defaults
sshd -T | grep -iE "^(maxauthtries|allowtcpforwarding|allowagentforwarding|x11forwarding|loglevel|clientaliveinterval)"
# Expect:
#   maxauthtries 3
#   allowtcpforwarding no
#   allowagentforwarding no
#   x11forwarding no
#   loglevel VERBOSE
#   clientaliveinterval 300
```

⚠️ **Test from a second SSH session before closing your current one.** Make sure your SSH key is in `~/.ssh/authorized_keys` first.

---

## Phase 3: Firewall (UFW)

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp    # HTTP (ACME challenges + redirect)
ufw allow 443/tcp   # HTTPS
ufw allow 60000:61000/udp  # Mosh (optional, remove if not needed)
ufw --force enable
```

---

## Phase 4: Fail2ban

### 4.1 SSH jail

```bash
cat > /etc/fail2ban/jail.d/sshd.conf << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
backend = systemd
maxretry = 3
findtime = 6h
bantime = 24h
EOF
```

### 4.2 Recidive jail (repeat offenders)

```bash
cat > /etc/fail2ban/jail.d/recidive.conf << 'EOF'
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
maxretry = 3
findtime = 1d
bantime = 1w
banaction = %(banaction_allports)s
EOF
```

### 4.3 Caddy credential-scanner jail

Catches the relentless internet-wide scans for `.git`, `.env`, `wp-login.php`, etc.:

```bash
cat > /etc/fail2ban/filter.d/caddy-credential-scanner.conf << 'EOF'
[Definition]
failregex = ^.*"client_ip":"<HOST>".*"status":(404|403).*"uri":".*\.(git|env|bak|sql|config|yml|yaml|json|ini|conf|log|old|orig|save|swp|DS_Store).*$
            ^.*"client_ip":"<HOST>".*"status":(404|403).*"uri":".*(wp-login|wp-admin|xmlrpc|phpmyadmin|\.php|cgi-bin|actuator|api/v1/auth).*$
ignoreregex =
datepattern = "ts":({EPOCH})
EOF

cat > /etc/fail2ban/jail.d/caddy-credential-scanner.conf << 'EOF'
[caddy-credential-scanner]
enabled = true
port = http,https
filter = caddy-credential-scanner
logpath = /var/log/caddy/*_access.log
maxretry = 5
findtime = 300
bantime = 86400
EOF
```

### 4.4 Start fail2ban

```bash
systemctl enable fail2ban
systemctl start fail2ban
fail2ban-client status
```

---

## Phase 5: PostgreSQL

### 5.1 Install

```bash
# Add PostgreSQL APT repo for latest version
sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg
apt update
apt install -y postgresql-18
```

### 5.2 Tune for 1 GB RAM

Edit `/etc/postgresql/18/main/postgresql.conf`:

```ini
# Connection
listen_addresses = 'localhost'
max_connections = 20          # secrt only needs a few

# Memory — tuned for 1 GB total RAM
shared_buffers = 64MB         # ~6% of RAM (conservative for small box)
work_mem = 4MB                # per-sort, keep low with limited RAM
maintenance_work_mem = 32MB   # VACUUM, CREATE INDEX
effective_cache_size = 256MB  # hint to planner: OS cache estimate

# WAL
wal_buffers = 4MB
checkpoint_completion_target = 0.9

# Planner
random_page_cost = 1.1        # SSD

# Logging
log_min_duration_statement = 1000   # log queries > 1s
log_line_prefix = '%t [%p] %u@%d '
```

### 5.3 Create database & user

```bash
sudo -u postgres psql << 'EOF'
CREATE USER secrt_app WITH PASSWORD 'GENERATE_A_STRONG_PASSWORD_HERE';
CREATE DATABASE secrt OWNER secrt_app;
\c secrt
-- secrt-server runs migrations automatically on startup
EOF
```

### 5.4 pg_hba.conf

Ensure local connections use scram-sha-256:

```
# /etc/postgresql/18/main/pg_hba.conf
local   all   postgres                peer
local   all   all                     peer
host    all   all   127.0.0.1/32      scram-sha-256
host    all   all   ::1/128           scram-sha-256
```

```bash
systemctl restart postgresql
```

### 5.5 Protect PostgreSQL from the OOM killer

```bash
mkdir -p /etc/systemd/system/postgresql@.service.d
cat > /etc/systemd/system/postgresql@.service.d/oom.conf << 'EOF'
[Service]
OOMScoreAdjust=-900
EOF
systemctl daemon-reload
```

---

## Phase 6: Caddy

### 6.1 Install

```bash
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update
apt install -y caddy
```

> **Optional:** If you want Brotli compression, build Caddy with xcaddy + caddy-cbrotli. This requires CGO and ~1 GB RAM to compile — do it on another machine or stick with stock Caddy (gzip + zstd are fine).

### 6.2 Global Caddyfile

```bash
cat > /etc/caddy/Caddyfile << 'CADDYEOF'
{
    email you@your-domain.example
    servers {
        protocols h1 h2 h3
    }
}

# Security headers snippet
(security_headers) {
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        -Server
    }
}

# Same as above but with the `preload` directive — use this snippet only on
# domains you intend to submit to https://hstspreload.org/. See Phase 15.
(security_headers_preload) {
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        -Server
    }
}

(encode) {
    encode gzip zstd
}

import /etc/caddy/sites/*.caddy
CADDYEOF
```

### 6.3 Site config

```bash
mkdir -p /etc/caddy/sites

cat > /etc/caddy/sites/secrt.caddy << 'SITEEOF'
# secrt — zero-knowledge secret sharing
your-domain.example {
    import encode
    import security_headers_preload   # or security_headers if not preloading

    # NOTE: Content-Security-Policy is owned by secrt-server (since 0.16.4).
    # The app middleware ships a strict CSP on HTML responses (with hash-pinned
    # inline scripts) and `upgrade-insecure-requests` enforcing on every response.
    # Do NOT add a `header Content-Security-Policy ...` line here — a second,
    # looser policy from Caddy would be confusing and pointless: multiple CSPs
    # are AND'd, so the strict app policy already wins, and a Caddy-level CSP
    # would also bleed onto API JSON responses where it has no purpose.

    # Reverse proxy to secrt-server
    reverse_proxy localhost:8081 {
        header_up X-Real-IP {remote_host}
    }

    # Privacy-preserving access log
    log {
        output file /var/log/caddy/secrt_access.log {
            roll_size 50MiB
            roll_keep 3
            roll_keep_for 168h
        }
        format filter {
            wrap json
            fields {
                request>remote_ip                ip_mask 24 48
                request>client_ip                ip_mask 24 48
                request>headers>X-Forwarded-For  ip_mask 24 48
                request>headers>User-Agent       delete
                request>headers>Referer          delete
                request>uri query {
                    delete *
                }
            }
        }
    }
}

# Optional: vanity subdomain redirects
www.your-domain.example, my.your-domain.example, your.your-domain.example, our.your-domain.example {
    redir https://your-domain.example{uri} permanent
}
SITEEOF
```

See [`caddy-privacy-logging.md`](caddy-privacy-logging.md) for the full rationale on the log filter — what's masked, what's deleted, what an operator can still see.

### 6.4 Catch-all for unknown hosts

```bash
cat > /etc/caddy/sites/000-default-catchall.caddy << 'EOF'
# Catch-all: reject requests for unknown hostnames
:443 {
    tls internal
    respond 404
}
EOF
```

### 6.5 Validate & start

```bash
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl enable caddy
systemctl start caddy
```

---

## Phase 7: Deploy secrt-server

### 7.1 Install binary

Download prebuilt binaries from GitHub. Pick `amd64` or `arm64` based on the VPS architecture (`uname -m` — `x86_64` = amd64, `aarch64` = arm64):

```bash
mkdir -p /opt/secrt/bin

# Set architecture (change to arm64 if needed)
ARCH=amd64
# Use the latest server release tag (check https://github.com/getsecrt/secrt/releases?q=server)
VERSION="server/v0.18.1"

cd /tmp
gh release download "$VERSION" --repo getsecrt/secrt \
  --pattern "secrt-server-linux-${ARCH}" \
  --pattern "secrt-admin-linux-${ARCH}" \
  --pattern "secrt-server-checksums-sha256.txt"

# Verify checksums
grep "linux-${ARCH}" secrt-server-checksums-sha256.txt | sha256sum -c

# Install
mv secrt-server-linux-${ARCH} /opt/secrt/bin/secrt-server
mv secrt-admin-linux-${ARCH} /opt/secrt/bin/secrt-admin
chmod 755 /opt/secrt/bin/secrt-server /opt/secrt/bin/secrt-admin
rm secrt-server-checksums-sha256.txt
```

> **Note:** If `gh` is not installed, you can download directly:
> `curl -fsSL -o /tmp/secrt-server-linux-${ARCH} "https://github.com/getsecrt/secrt/releases/download/server%2Fv0.18.1/secrt-server-linux-${ARCH}"`

### 7.2 Environment config

```bash
mkdir -p /etc/secrt-server
cat > /etc/secrt-server/env << 'EOF'
ENV=production
LISTEN_ADDR=127.0.0.1:8081
PUBLIC_BASE_URL=https://your-domain.example
LOG_LEVEL=info

# Database
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=secrt
DB_USER=secrt_app
DB_PASSWORD=GENERATE_A_STRONG_PASSWORD_HERE
DB_SSLMODE=disable

# Security — generate fresh 32-byte base64 secrets:
#   openssl rand -base64 32
API_KEY_PEPPER=GENERATE_ME
SESSION_TOKEN_PEPPER=GENERATE_ME

# Limits (public/unauthenticated)
MAX_ENVELOPE_BYTES=262144
MAX_SECRETS=200
MAX_TOTAL_BYTES=2097152

# Limits (authenticated)
AUTH_MAX_ENVELOPE_BYTES=1048576
AUTH_MAX_SECRETS=1000
AUTH_MAX_TOTAL_BYTES=20971520

# Rate limits (public)
CREATE_RATE=0.5
CREATE_BURST=6
CLAIM_RATE=1.0
CLAIM_BURST=10

# Rate limits (authenticated)
AUTH_CREATE_RATE=2.0
AUTH_CREATE_BURST=20

# API key registration limits
APIKEY_REGISTER_RATE=0.5
APIKEY_REGISTER_BURST=6
APIKEY_REGISTER_ACCOUNT_MAX_PER_HOUR=5
APIKEY_REGISTER_ACCOUNT_MAX_PER_DAY=20
APIKEY_REGISTER_IP_MAX_PER_HOUR=5
APIKEY_REGISTER_IP_MAX_PER_DAY=20
EOF

chmod 600 /etc/secrt-server/env
chown root:root /etc/secrt-server/env
```

See [`crates/secrt-server/README.md`](../crates/secrt-server/README.md) for the full reference of every env var.

### 7.3 Systemd service

```bash
cat > /etc/systemd/system/secrt.service << 'EOF'
[Unit]
Description=secrt one-time secret server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
ExecStart=/opt/secrt/bin/secrt-server
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

# systemd injects env vars before dropping privileges,
# so the service process cannot read /etc/secrt-server/env after startup.

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable secrt
systemctl start secrt

# Verify
systemctl status secrt
curl -s http://127.0.0.1:8081/ | head
```

---

## Phase 8: Kernel & Sysctl Hardening

```bash
cat > /etc/sysctl.d/99-secrt-hardening.conf << 'EOF'
# Restrict kernel address visibility
kernel.kptr_restrict = 1

# Restrict ptrace to child processes
kernel.yama.ptrace_scope = 1

# Loose reverse path filtering (required for some cloud providers)
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.rp_filter = 2

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
EOF

sysctl --system
```

---

## Phase 9: Unattended Upgrades

Enable via `dpkg-reconfigure`, then add a local drop-in to turn on auto-reboot. Without auto-reboot, kernel and libc patches install but stay dormant until someone manually reboots.

```bash
dpkg-reconfigure -plow unattended-upgrades
# Select "Yes" to enable automatic security updates

# Local overrides — survives package upgrades that rewrite 50unattended-upgrades
cat > /etc/apt/apt.conf.d/52unattended-upgrades-local << 'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

# Verify effective config
apt-config dump | grep -E "Unattended-Upgrade::(Automatic-Reboot|Remove-Unused)"
systemctl status unattended-upgrades
```

The 03:00 UTC reboot window intentionally overlaps the quietest user-traffic band. Downtime is ~20–40 s on a 1 GB KVM VPS; Caddy + postgres + secrt-server come back automatically and in-flight client reconnects are transparent for a one-time-secret flow.

If you want zero-downtime kernel patching, skip ahead to Phase 14 (Ubuntu Pro + Livepatch).

---

## Phase 9.5: Outbound Mail (msmtp + Transactional Relay)

Ubuntu's `unattended-upgrades` / `apt-listchanges` / `needrestart` install chain pulls in Postfix as a dependency for local mail delivery. We don't actually need a full SMTP daemon on this box — we need a *send-only* relay so cron, unattended-upgrades, and (later) monitoring alerts can deliver mail to a real inbox. Replace Postfix with `msmtp` and route through a transactional email provider.

**Why a transactional provider over Gmail/Workspace SMTP:** consumer mail (Gmail, Outlook 365, Workspace) is increasingly hostile to long-lived app-password authentication for SMTP — Google has been narrowing scopes year-over-year, and OAuth2 SMTP is high-maintenance for headless servers. Transactional providers issue long-lived API tokens that don't deprecate, segregate transactional traffic from marketing-email reputation pools, and offer better deliverability for system-generated mail.

**Pick any one — they're functionally interchangeable here:**

| Provider | Free tier | Notes |
|---|---|---|
| **Zoho ZeptoMail** | ~250 emails/day after onboarding | Strict transactional-only enforcement; Zoho ecosystem if you already use Zoho Mail |
| **AWS SES** | 200 emails/day from EC2, $0.10/1000 elsewhere | Lowest cost at scale; needs AWS account |
| **Postmark** | 100 emails/month | Excellent transactional reputation, simple onboarding |
| **Mailgun** | 5,000 emails/month for 3 months, then paid | Strong API; good for higher-volume needs |
| **Resend** | 3,000 emails/month | Newer, developer-friendly tooling |

The setup pattern is the same regardless — the only difference is the SMTP host/port/credentials. Examples below use the ZeptoMail values; substitute your provider's.

### 9.5.1 — Set up the sender (one-time, web UI)

1. Sign up with your chosen provider.
2. **Add Domain** → enter `your-domain.example`. The provider issues 2–3 DNS records:
   - **TXT** at `<selector>._domainkey.your-domain.example` — DKIM public key
   - **TXT** at `your-domain.example` — SPF: ensure their `include:` directive is present alongside any existing SPF (do NOT replace — merge)
   - **CNAME** for return-path verification (some providers)
3. Add the records at your DNS provider. The DKIM record name is typically entered *relative* (`<selector>._domainkey`) — most interfaces auto-append the apex.
4. Wait for propagation (authoritative ~seconds, public resolvers ~minutes), then verify each record at the provider.
5. Generate an SMTP credential (often called "API token", "Mail Agent", or "SMTP credentials" depending on provider). Save it securely — most providers won't show it again, only let you regenerate.

### 9.5.2 — Replace Postfix with msmtp

```bash
# Install msmtp (relay-only MTA), msmtp-mta (sendmail symlink), mailutils (`mail` cmd).
# Auto-removes postfix as part of resolving the sendmail-providing alternatives.
apt install -y msmtp msmtp-mta mailutils

# Confirm sendmail is now msmtp:
ls -la /usr/sbin/sendmail   # should symlink to ../bin/msmtp

# Postfix may linger as installed-but-inactive after the install. Purge explicitly:
apt purge -y postfix
```

### 9.5.3 — Configure msmtp

Write `/etc/msmtprc`. **Mode 640, group `mail`** so unprivileged service users (e.g. `netdata`, added in Phase 16) can read it without exposing the credential to all users on the system.

```bash
cat > /etc/msmtprc << 'EOF'
# Global settings
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log
aliases        /etc/msmtp-aliases
source_ip      0.0.0.0
timeout        30

# Transactional account (substitute your provider's host/port/user)
account        relay
host           smtp.zeptomail.com
protocol       smtp
port           587
from           you@your-domain.example
user           emailapikey
password       <PASTE PROVIDER TOKEN HERE>

# Default
account default : relay
EOF

chown root:mail /etc/msmtprc
chmod 640 /etc/msmtprc

# Pre-create the log file world-writable so any user invoking msmtp can append.
# Without this, only root sends will succeed; unprivileged users get a silent
# "account default not found: no configuration file available" failure
# because msmtp can't write its log before reading its config.
touch /var/log/msmtp.log
chown root:root /var/log/msmtp.log
chmod 666 /var/log/msmtp.log
```

Common SMTP endpoints for the providers above:

| Provider | Host | Port | Username |
|---|---|---|---|
| ZeptoMail | `smtp.zeptomail.com` | 587 | `emailapikey` (literal) |
| AWS SES | `email-smtp.<region>.amazonaws.com` | 587 | IAM access key ID |
| Postmark | `smtp.postmarkapp.com` | 587 | server token (used as both user + pass) |
| Mailgun | `smtp.mailgun.org` | 587 | mailbox username |
| Resend | `smtp.resend.com` | 587 | `resend` (literal) |

### 9.5.4 — Aliases (so system mail to `root` reaches a real inbox)

```bash
cat > /etc/aliases << 'EOF'
root: you@your-domain.example
EOF

cat > /etc/msmtp-aliases << 'EOF'
root: you@your-domain.example
default: you@your-domain.example
EOF

chmod 644 /etc/aliases /etc/msmtp-aliases
```

### 9.5.5 — Add users that need to send mail to the `mail` group

Any service or shell user that needs to relay mail must be in the `mail` group to read `/etc/msmtprc`. Add the admin user now; service users (Phase 16) get added when their service first needs to alert.

```bash
usermod -aG mail youradmin

# Service users will be added later as needed:
# usermod -aG mail netdata     # for Netdata alerts (Phase 16)

# A user's existing processes don't pick up the new group until they re-login.
# For a service: systemctl restart <service>.
# For a shell session: log out/back in, or use `sg mail -c '...'` for one-offs.
```

### 9.5.6 — Verify

```bash
# Test as root (works immediately)
echo 'Test from secrt-srv via msmtp+relay.' | mail -s '[secrt-srv] relay test (root)' you@your-domain.example

# Test as unprivileged user (verifies the mail-group permission pattern)
sg mail -c "echo 'Test from unprivileged user.' | mail -s '[secrt-srv] relay test (user)' you@your-domain.example"

# Check log — both should show smtpstatus=250, exitcode=EX_OK
tail -5 /var/log/msmtp.log

# Both messages should land in the recipient inbox within seconds.
```

If the user-level send fails with `account default not found: no configuration file available`, the user is not in the `mail` group yet. Run `groups` to confirm.

---

## Phase 10: DNS

Once the server has an IP, configure these records at your DNS provider:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | @ | SERVER_IP | 600 |
| A | www | SERVER_IP | 600 |

Optional vanity subdomains (only if you also added them to the Caddy site config):

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | my | SERVER_IP | 600 |
| A | your | SERVER_IP | 600 |
| A | our | SERVER_IP | 600 |

Add an `AAAA` record for each name if your VPS has IPv6.

DNSSEC is optional but recommended. Most providers will sign your zone automatically once you opt in; you'll then need to publish the DS record at your registrar.

CAA records and HSTS preload submission come *later*, after the site is live and certs are issuing — see Phase 15.

---

## Phase 11: (Optional) Migrate from an Existing Instance

If you're moving from another secrt server, dump and restore the database:

```bash
# On your-old-server:
sudo -u postgres pg_dump --format=custom secrt > /tmp/secrt-backup.dump

# Transfer to new server:
scp /tmp/secrt-backup.dump root@secrt-srv:/tmp/

# On secrt-srv:
sudo -u postgres pg_restore --dbname=secrt --no-owner /tmp/secrt-backup.dump
rm /tmp/secrt-backup.dump
```

The peppers (`API_KEY_PEPPER`, `SESSION_TOKEN_PEPPER`) must match the old server, or all existing API keys and sessions will be invalidated. Copy them into the new `/etc/secrt-server/env` before starting `secrt-server`.

---

## Phase 12: (Optional) MOTD & sysstat

For a cleaner login experience and a 24h load-history graph in your MOTD:

```bash
# Install sysstat (collects metrics for load history)
apt install -y sysstat
systemctl enable sysstat
systemctl start sysstat

# Disable Ubuntu's default MOTD noise
chmod -x /etc/update-motd.d/10-help-text 2>/dev/null
chmod -x /etc/update-motd.d/50-motd-news 2>/dev/null
chmod -x /etc/update-motd.d/91-contract-ua-esm-status 2>/dev/null
```

The default MOTD is now quiet. Add your own `/etc/update-motd.d/` scripts if you want a custom banner — totally optional.

---

## Phase 13: (Optional) Admin Shell Ergonomics

Operator quality-of-life — zsh, powerlevel10k, fzf, zoxide, and friends. Skip this entirely if you have your own preferred setup.

Run **as the admin user (not root)**. Leave root's login shell as bash so you have a known-good recovery shell via `sudo su -` if anything breaks.

```bash
sudo apt install -y \
  zsh git \
  zoxide fzf eza fd-find bat \
  ripgrep jq htop ncdu tealdeer \
  tmux mosh unzip

# Powerlevel10k (standalone, no oh-my-zsh)
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/.powerlevel10k

# Switch login shell
sudo chsh -s "$(which zsh)" "$USER"
```

Tool notes:
- **eza** — maintained fork of the abandoned `exa`.
- **fd-find / bat** — Ubuntu ships these as `fdfind` and `batcat` to avoid name clashes; alias them back in your `.zshrc`.
- **jq** — essential for querying the Caddy JSON access logs.
- **mosh** — UFW already allows `60000:61000/udp` from Phase 3.

A reasonable starter `.zshrc` lives in [the original deployment runbook this guide derives from] — copy whatever subset you like.

After login, run `p10k configure` once to generate `~/.p10k.zsh`. Powerlevel10k uses Nerd Font glyphs; set MesloLGS NF (or any Nerd Font) in your terminal client.

**Resource cost:** zero when nobody's logged in; ~15 MB per live SSH session.

---

## Phase 14: Ubuntu Pro + Livepatch (Zero-Downtime Kernel Patching)

Ubuntu Pro offers a free tier for personal use covering up to 5 machines and **including Livepatch** (kernel live patching — security kernels apply without a reboot). Commercial use technically requires the paid tier ($500/yr for unlimited VMs under one subscription). Use the free tier for pre-launch / evaluation; convert to paid before taking paying customers.

```bash
# Grab your token from https://ubuntu.com/pro/dashboard (Ubuntu One login).
sudo pro attach <YOUR_TOKEN> --no-auto-enable

# Enable the three services that matter on this tier
sudo pro enable livepatch --assume-yes   # live kernel patches
sudo pro enable esm-infra --assume-yes   # extended main/core security
sudo pro enable esm-apps --assume-yes    # extended universe security (libssl, jq, etc.)

# Verify
sudo pro status
sudo canonical-livepatch status
apt list --upgradable 2>/dev/null | grep -i esm
```

Once livepatch is active, the Phase 9 `Unattended-Upgrade::Automatic-Reboot "true"` setting still fires for non-kernel package updates that need a restart (libc, systemd, glibc-dependent daemons). Livepatch just lets most kernel CVEs skip the reboot.

---

## Phase 15: DNS & Browser Hardening

Two external steps that complete the TLS story. Both are post-deploy — the site has to be live, certs issuing cleanly, and HTTPS working everywhere before you do these.

### 15.1 CAA records

CAA (Certification Authority Authorization) is a DNS record that tells the world "only these CAs are allowed to issue certs for my domain." Without CAA, *any* CA can issue a cert for your domain if they're tricked or compromised. With CAA, Let's Encrypt is the only allowed issuer, and any other CA must refuse.

Three records on the apex (`@`):

| Tag | Value | Meaning |
|------|-------|---------|
| `issue` | `letsencrypt.org` | LE is the only CA allowed to issue regular certs |
| `issuewild` | `;` | Block all wildcard cert issuance (we don't use wildcards) |
| `iodef` | `mailto:security@your-domain.example` | Where misissuance attempts get reported |

**How to add depends on the DNS provider:**
- **DigitalOcean / 1984 Hosting / most modern panels**: separate fields for tag (dropdown) and value. Enter values bare (no quotes, no flag prefix).
- **Older / single-field panels**: enter the full record line: `0 issue "letsencrypt.org"` etc.

⚠️ **Match the iodef email to the domain.** Mismatched domains may cause CAs to reject the report destination.

**Verify from the wire:**

```bash
# Should return all three records
dig CAA your-domain.example +short

# Or directly from each authoritative nameserver (catches replication lag)
for ns in $(dig NS your-domain.example +short); do
  echo "== $ns =="
  dig CAA your-domain.example @$ns +short
done
```

Expected output:

```
0 issue "letsencrypt.org"
0 issuewild ";"
0 iodef "mailto:security@your-domain.example"
```

### 15.2 HSTS preload submission

The Caddy config in Phase 6.2 already serves the right header (when you import `security_headers_preload`):

```
Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
```

But that header alone only protects users who have already visited the site once — first-time visitors are still vulnerable to a downgrade attack on their initial connection. The HSTS preload list (maintained by Chrome, consumed by all major browsers) hardcodes the domain into the browser, so even *first* connections are forced to HTTPS.

**Requirements** (the submission tool checks all of these):
- Valid HTTPS cert on `your-domain.example` and `www.your-domain.example`
- HTTP redirects to HTTPS on the *same host* (not straight to www)
- All subdomains served over HTTPS
- HSTS header on the apex with `max-age ≥ 31536000`, `includeSubDomains`, and `preload` directives

**Submit at**: <https://hstspreload.org/>

Enter the domain, run the automated checks, click submit. Takes a few weeks to land in Chrome stable; other browsers pick it up downstream.

⚠️ **Removal is slow.** Once preloaded, getting *off* the list takes weeks-to-months as browser releases roll out. Only submit if you're certain you'll never need a plaintext subdomain (dev tunnels, IoT devices, third-party landing pages that don't do HTTPS, etc.). For a security product like secrt this is a non-issue — plaintext anywhere would be a bug.

⚠️ **Cert renewal failure = total outage.** On a preloaded domain, a lapsed cert means browsers won't connect *at all* (no user-facing override). Make sure Caddy's auto-renewal is healthy and monitored before submitting.

### 15.3 Final verification

Run an SSL Labs scan: `https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.example`

Targets:
- **Overall grade**: A+
- **HSTS**: long duration deployed
- **DNS CAA**: green "Yes" (orange "No" means CAA records aren't in place)
- **Protocols**: TLS 1.3 + 1.2 only (no 1.0/1.1, no SSL 2/3)
- **Cipher suites**: ECDHE forward-secret only

Anything less than A+ is a regression — investigate before letting the preload submission propagate, since once it's in Chrome stable, any cert/config issue becomes much more visible.

---

## Phase 16: Monitoring (Netdata)

Lightweight, all-local metrics collection with anomaly detection and email alerts. Uses Netdata as the substrate — it covers system, processes, disk, network, systemd units, journald, and PostgreSQL out of the box, plus has built-in ML anomaly detection that becomes useful after ~1 week of baselines.

**What this gives you:**
- Real-time + historical metrics dashboard
- ~125 stock alarms covering the obvious operational surfaces
- PostgreSQL collector with 50+ charts including per-database size, connections, deadlocks, transactions
- Email alerts routed through Phase 9.5's mail relay

**What this deliberately does NOT include and why:**
- **AIDE** (file integrity monitoring) — marginal here. `secrt-server`'s systemd hardening (`ProtectSystem=strict`, `ReadOnlyPaths=/`, `NoNewPrivileges=true`) already prevents the file-modification scenarios AIDE would detect after the fact. A cheaper alternative: a fixed `sha256sum` baseline on a handful of files (the secrt-server binary, Caddyfile, sudoers, key configs) refreshed on each release.
- **ClamAV** — secrt's payloads are ciphertext the server cannot decrypt. Signature-matching against random bytes adds zero security value. Also won't fit memory-wise on a 1 GB box.
- **Heavy Netdata plugins** (eBPF, OTel collectors, Python plugins) — they don't auto-enable on most KVM/QEMU/Vultr-class virtual NICs anyway, and we'd disable them if they did.

### 16.1 Install Netdata

```bash
# Pull the official kickstart. Inspect before running (good habit).
wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh
less /tmp/netdata-kickstart.sh

# Dry-run first (shows which install path it picks — native package on Ubuntu).
sh /tmp/netdata-kickstart.sh --dry-run

# Install. Don't start it yet — we want to bind to localhost first.
sh /tmp/netdata-kickstart.sh \
  --non-interactive \
  --stable-channel \
  --disable-telemetry \
  --dont-start-it

# Disk: ~500 MB (most plugins ship as separate packages but don't all run).
# Active RSS: ~65 MB across all running plugins on a 1 GB box.
```

### 16.2 Bind dashboard to localhost only

UFW already blocks port 19999, but defense-in-depth: the dashboard listens on `0.0.0.0:19999` by default — change that before first start.

```bash
cat >> /etc/netdata/netdata.conf << 'EOF'

[web]
    bind to = 127.0.0.1
EOF

systemctl enable --now netdata

# Verify — should show 127.0.0.1:19999 only, no 0.0.0.0 or [::]
ss -tlnp | grep 19999
```

To view the dashboard from your workstation: `ssh -L 19999:127.0.0.1:19999 secrt-srv` then http://localhost:19999.

**Alternative — Caddy-fronted with auth:** If the SSH-tunnel pattern feels too friction-heavy, you can serve the dashboard at e.g. `https://monitor.your-domain.example` through Caddy with passkey or basic auth. Cost: more attack surface, more cert/auth machinery to maintain. Benefit: one less manual step to glance at metrics. The SSH-tunnel default is the more security-aligned choice for a single-admin appliance — but document your choice if you change it, since it affects the threat model.

### 16.3 Disable the auto-updater (rely on apt)

The kickstart sets up its own update mechanism. Two update systems racing each other is a recipe for surprises.

```bash
/usr/libexec/netdata/netdata-updater.sh --disable-auto-updates

# Verify — no /etc/cron.daily/netdata*, no netdata-updater.timer
ls /etc/cron.daily/netdata* 2>/dev/null
systemctl list-timers --all | grep netdata
```

Updates now flow through `apt upgrade` when you SSH in. Note: Netdata's third-party repo is *not* in `unattended-upgrades`' allowlist by default. If you want truly hands-off updates, add `"Netdata:*";` to `/etc/apt/apt.conf.d/50unattended-upgrades` — but for a single-purpose box where Netdata changes ought to be visible events, manual `apt upgrade` is the saner posture.

### 16.4 PostgreSQL collector (peer auth, no password)

Create a dedicated PostgreSQL role for Netdata. Linux user `netdata` ↔ PG role `netdata` ↔ unix-socket peer auth = no password stored anywhere.

```bash
# Create the PG role with monitoring permissions (built-in pg_monitor role).
sudo -u postgres psql << 'SQL'
CREATE ROLE netdata WITH LOGIN INHERIT;
GRANT pg_monitor TO netdata;
SQL

# Verify peer auth works:
sudo -u netdata psql -d postgres -c 'SELECT current_user;'
# → should print "netdata"
```

`pg_hba.conf` needs no edits — Ubuntu's default `local all all peer` rule covers it.

Configure the collector:

```bash
cat > /etc/netdata/go.d/postgres.conf << 'EOF'
# Connects via unix socket using peer auth (no password stored).
# Linux user 'netdata' maps to PG role 'netdata' with pg_monitor membership.
# Collector auto-discovers all databases in the cluster from this connection.

jobs:
  - name: local
    dsn: 'host=/run/postgresql dbname=postgres user=netdata'
EOF

chown root:netdata /etc/netdata/go.d/postgres.conf
chmod 640 /etc/netdata/go.d/postgres.conf

systemctl restart netdata
sleep 8

# Verify — should report ~50 charts under postgres_local.* including per-DB
# series like postgres_local.db_secrt_size, db_secrt_connections, etc.
curl -s http://127.0.0.1:19999/api/v1/charts | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); pg=[k for k in d.get("charts",{}) if k.startswith("postgres_local.")]; print(f"go.d postgres charts: {len(pg)}")'
```

### 16.5 Email alerts via Phase 9.5 relay

Add the `netdata` service user to the `mail` group, then point Netdata's notifier at your alert recipient.

```bash
# Group membership (requires service restart to take effect for running netdata)
usermod -aG mail netdata

# Copy stock health_alarm_notify.conf to /etc/netdata/ for editing
cd /etc/netdata && ./edit-config health_alarm_notify.conf
# (the editor may complain about a terminal; that's OK — the file gets copied
#  to /etc/netdata/ regardless. Edit with sed or your editor of choice.)

# Patch the three values that matter for email
sed -i -E '
  s|^SEND_EMAIL=.*|SEND_EMAIL="YES"|
  s|^EMAIL_SENDER=.*|EMAIL_SENDER="you@your-domain.example"|
  s|^DEFAULT_RECIPIENT_EMAIL=.*|DEFAULT_RECIPIENT_EMAIL="you@your-domain.example"|
' /etc/netdata/health_alarm_notify.conf

# Restart so netdata picks up its new mail-group membership AND the config
systemctl restart netdata

# Verify supplementary group on the running process
ps -o user,group,supgrp -p "$(pgrep -x netdata | head -1)"
# → SUPGRP should include "mail"

# Send test alarms (WARNING + CRITICAL + CLEAR roundtrip)
sudo -u netdata /usr/libexec/netdata/plugins.d/alarm-notify.sh test
# → Three messages should arrive in your inbox.
# → /var/log/msmtp.log should show three entries with smtpstatus=250.
```

**Optional — plain-text email mode.** Stock Netdata emails are HTML with hardcoded light-theme colors (no `prefers-color-scheme: dark` support). If you prefer plain-text emails (for dark-mode clients, smaller inbox previews), set `EMAIL_PLAINTEXT_ONLY="YES"` in `/etc/netdata/health_alarm_notify.conf`. You lose visual severity color-coding but the subject line still has the severity word.

### 16.6 Initial alarms

Beyond the ~125 stock alarms Netdata loads automatically, four custom alarms cover signals specific to a single-purpose appliance like this one. All thresholds are starting points — refine after observing real load patterns for ~1 week.

**Custom health alarms** — write to `/etc/netdata/health.d/secrt-custom.conf` (640 root:netdata):

```
# secrt.service must be in active state
# Chart dimensions: active, inactive, activating, deactivating, failed.
# Healthy: active=1, all others=0.

 alarm: secrt_service_failed
    on: systemdunits_service-units.unit_secrt_service_state
 every: 30s
  calc: $failed
 units: bool
  crit: $this > 0
 delay: up 30s down 5m
 class: Errors
  type: secrt
  info: secrt.service entered failed state — service is down
    to: sysadmin

 alarm: secrt_service_inactive
    on: systemdunits_service-units.unit_secrt_service_state
 every: 30s
  calc: $inactive
 units: bool
  warn: $this > 0
 delay: up 1m down 5m
  info: secrt.service is inactive (stopped)
    to: sysadmin

# secrt PG database hard size threshold (backstop for disk-fill abuse scenario).
# Pick thresholds well below your free disk; refine after baselines.

 alarm: secrt_db_size_high
    on: postgres_local.db_secrt_size
 every: 1m
  calc: $size / 1073741824
 units: GB
  warn: $this > 3
  crit: $this > 5
 delay: up 5m down 1h
 class: Capacity
  type: postgres
component: secrt
  info: secrt PG database growing larger than expected; investigate inserts/abuse
    to: sysadmin
```

**Cert expiry monitoring** — write to `/etc/netdata/go.d/x509check.conf` (640 root:netdata). Stock alarms (`x509check_days_until_expiration`) fire warn at <14 days, crit at <7 days; that's usually fine, no override needed.

```yaml
jobs:
  - name: apex
    source: https://your-domain.example:443
  - name: www
    source: https://www.your-domain.example:443
  # Add an entry per public hostname Caddy serves a cert for.
```

**SSH login anomaly watch** — `/usr/local/sbin/ssh-login-watch.sh` (755 root:root) + `/etc/cron.d/ssh-login-watch` (644 root:root). Watches `journalctl _SYSTEMD_UNIT=ssh.service` every minute for `Accepted publickey/password/keyboard-interactive` events from a user other than the expected admin user; emails on anomaly. Window matches polling frequency (60s/60s) to avoid duplicate alerts.

```bash
sudo tee /usr/local/sbin/ssh-login-watch.sh > /dev/null << 'SCRIPT'
#!/bin/bash
set -euo pipefail

EXPECTED_USER="youradmin"   # change to your admin username
RECIPIENT="you@your-domain.example"
SENDER="you@your-domain.example"
HOST="$(hostname -f 2>/dev/null || hostname)"

ANOMALIES=$(journalctl _SYSTEMD_UNIT=ssh.service --since '60 seconds ago' --no-pager 2>/dev/null \
  | grep -E 'Accepted (publickey|password|keyboard-interactive)' \
  | grep -v " for ${EXPECTED_USER} from " \
  || true)

[ -z "$ANOMALIES" ] && exit 0

{
  echo "Subject: [${HOST}] UNEXPECTED SSH LOGIN"
  echo "From: $SENDER"
  echo "To: $RECIPIENT"
  echo ""
  echo "Successful SSH login(s) from user other than '${EXPECTED_USER}' on ${HOST}:"
  echo ""
  echo "$ANOMALIES"
} | /usr/sbin/sendmail -t
SCRIPT

sudo chmod 755 /usr/local/sbin/ssh-login-watch.sh

sudo tee /etc/cron.d/ssh-login-watch > /dev/null << 'CRON'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root /usr/local/sbin/ssh-login-watch.sh 2>/dev/null
CRON
sudo chmod 644 /etc/cron.d/ssh-login-watch
```

If you've restricted SSH to a specific country at the firewall layer (e.g. via GeoIP ipset rules in UFW), this catches "wrong username from a permitted IP." For "logins from unfamiliar IPs within the permitted geography," fail2ban + ipban patterns are a separate (heavier) tool.

Restart Netdata so the new health configs load:

```bash
systemctl restart netdata
```

### 16.7 Verification + day-1 noise expectations

```bash
# Round-trip the email pipe (3 messages: WARNING, CRITICAL, CLEAR)
sudo -u netdata /usr/libexec/netdata/plugins.d/alarm-notify.sh test

# Alarm count summary — total / warning / critical
curl -s 'http://127.0.0.1:19999/api/v1/info' | jq '.alarms'
# Healthy looks like: {"normal": 125+, "warning": 0, "critical": 0}

# Daily-check filter — show only alarms in actually-actionable states.
# (Intentionally excludes UNDEFINED — see below.)
curl -s 'http://127.0.0.1:19999/api/v1/alarms?all=true' \
  | jq -r '.alarms | to_entries[]
           | select(.value.status == "WARNING" or .value.status == "CRITICAL")
           | "[\(.value.status)] \(.key)"'
```

**Expected `UNDEFINED` alarms on a fresh install — don't panic.** A freshly-installed Netdata will report ~10 alarms in `UNDEFINED` state because their math depends on time-series history that doesn't exist yet. Typical list: `disk_fill_rate`, `disk_inode_rate`, `1m_ip_tcp_resets_*`, `load_cpu_number`, various `1m_*` packet-rate alarms. **These self-resolve within hours-to-a-few-days as data accumulates.**

**One UNDEFINED alarm that won't self-resolve on virtualized hosts:** `net.<iface>.interface_speed`. The kernel can't read link speed from `virtio-net` virtual NICs (returns 0 or "unknown"), so the divide-by-zero in the alarm's calc never produces a value. To suppress permanently, drop a same-named override into `/etc/netdata/health.d/` setting the template to `enabled: no`, or route it to `to: silent`.

### 16.8 Anomaly-driven alarms (do later, after ~1 week of baselines)

Once Netdata's ML has established a baseline for normal traffic patterns, layer in alarms for:

- **PostgreSQL growth-rate projection** — alert if at the current 7-day growth rate the volume will fill within N days (operational early warning vs. just disk-full).
- **Per-IP secret-creation volume** — abuse signal (someone using your instance as anonymous binary storage).
- **Payload size distribution shift** — p95 size moving up materially indicates pattern-of-use change worth a human look.
- **Anomaly-driven `secrt-server` restart count** — frequent restarts on a single-purpose box = bad day.

All optional. Stock Netdata health rules cover the obvious operational surfaces (disk, memory, swap pressure, postgres connection saturation, autovacuum, replication slots) out of the box — these anomaly-driven additions are second-order refinements, not gaps.

---

## Post-Setup Verification

```bash
# Services running
systemctl is-active caddy secrt postgresql ssh fail2ban ufw netdata

# Memory usage — should be well under 500 MB on a 1 GB box
# (with Netdata enabled, expect ~480 MB used / 961 MB total)
free -h

# secrt responding
curl -sI https://your-domain.example

# TLS certificate valid
echo | openssl s_client -connect your-domain.example:443 2>/dev/null | openssl x509 -noout -dates

# Firewall active
ufw status

# Fail2ban jails active
fail2ban-client status

# PostgreSQL connections
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname='secrt';"

# Netdata listening on localhost only
ss -tlnp | grep 19999

# Mail relay healthy — recent smtpstatus=250 entries expected
tail -3 /var/log/msmtp.log

# Postgres collector reporting (~50 charts under postgres_local.*)
curl -s http://127.0.0.1:19999/api/v1/charts | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(len([k for k in d.get("charts",{}) if k.startswith("postgres_local.")]),"postgres charts")'
```

---

## Memory Monitoring

On a 1 GB box, keep an eye on memory:

```bash
# Quick check
free -h

# Top consumers
ps -eo rss,comm --sort=-rss | head -10 | awk '{printf "%6.1f MB  %s\n", $1/1024, $2}'

# If memory pressure becomes an issue, reduce PostgreSQL further:
# shared_buffers = 32MB, max_connections = 10
```

---

## Upgrading

`secrt-server` is a single binary; upgrades are:

1. Download the new release binary (Phase 7.1, with the new `VERSION`).
2. Verify checksum.
3. `systemctl stop secrt`
4. `mv` the new binary into `/opt/secrt/bin/secrt-server`.
5. `systemctl start secrt`
6. `journalctl -u secrt -f` and confirm migrations applied cleanly.

Database migrations run automatically on startup. Always read the [server CHANGELOG](../crates/secrt-server/CHANGELOG.md) for breaking-change notes before upgrading.
