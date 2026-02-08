# secrt.ca

One-time secret sharing service (v1.0 planned backend: Go).

> **Repo:** [github.com/getsecrt/secrt](https://github.com/getsecrt/secrt)

## Specs

- v1 spec index: `spec/v1/README.md`
- API: `spec/v1/api.md`
- Envelope format and client crypto contract: `spec/v1/envelope.md`
- Server runtime behavior: `spec/v1/server.md`
- CLI command contract: `spec/v1/cli.md`

## CLI

Two CLI implementations exist, both implementing the same [v1 spec](spec/v1/cli.md):

| Implementation | Repo | Status |
| -------------- | ---- | ------ |
| **Rust** (recommended) | [getsecrt/secrt-rs](https://github.com/getsecrt/secrt-rs) | Primary — install this one |
| Go | `cmd/secrt/` (this repo) | Reference implementation, maintained at feature parity |

The Rust CLI is the recommended distribution for end users. The Go CLI remains maintained at feature parity and serves as a reference implementation — particularly useful for contributors already working in the Go server codebase.

### Benchmarks (Rust vs Go)

| Metric | Rust | Go | Delta |
| ----------- | ------- | ------- | ---------------------- |
| Binary size | 1.3 MB | 5.5 MB | Rust 4.2x smaller |
| Startup | ~1.7 ms | ~3.3 ms | Rust 2x faster |
| Encrypt | ~2.3 ms | ~4.1 ms | Rust 1.8x faster |
| PBKDF2 | ~65.5 ms | 71.8 ms | Rust 1.1x faster |

Both produce identical envelopes and pass the same [test vectors](spec/v1/envelope.vectors.json).

## Dev setup

### Postgres

Create a database and least-privilege user (adjust usernames as desired):

```bash
sudo -u postgres psql -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE secret_app LOGIN PASSWORD 'REPLACE_ME_WITH_PASSWORD';
CREATE DATABASE secret OWNER secret_app;
\connect secret
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS secret AUTHORIZATION secret_app;
ALTER ROLE secret_app SET search_path = secret,public;
SQL
```

### App config

1. Copy env template:

```bash
cp .env.example .env
```

2. Fill in DB credentials and generate a pepper:

```bash
openssl rand -base64 32
```

3. Run (loads `.env` automatically in non-production):

```bash
make run
```

Health check: `GET /healthz`

## Security

- Zero-knowledge architecture: the server stores ciphertext only and never sees decryption keys.
- HSTS preload: `secrt.ca` has been submitted to the [HSTS preload list](https://hstspreload.org/?domain=secrt.ca), ensuring browsers never attempt a plaintext HTTP connection.
- Production credentials are managed via systemd `EnvironmentFile=` with root-only permissions — see `docs/credentials-and-deployment.md`.

## API keys (for automation)

API-key endpoints require `API_KEY_PEPPER` to be set.

```bash
make build
./bin/secretctl apikey create
```

## Tooling

```bash
make fmt
make lint
make test
make test-race
make govulncheck
make check
```

## Tests

- Unit tests run without external dependencies.
- Postgres integration tests (migrations + `internal/storage/postgres`) run when a database is reachable via `TEST_DATABASE_URL` (preferred for CI) or your repo-root `.env`. If Postgres isn’t reachable, they will be skipped.

Coverage report:

```bash
make test-cover
```
