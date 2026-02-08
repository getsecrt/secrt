# secrt.ca

One-time secret sharing service (v1.0 planned backend: Go).

> **Note:** This repo will move to [github.com/getsecrt](https://github.com/getsecrt) once the project reaches v1.0.

## Specs

- v1 spec index: `spec/v1/README.md`
- API: `spec/v1/api.md`
- Envelope format and client crypto contract: `spec/v1/envelope.md`
- Server runtime behavior: `spec/v1/server.md`
- CLI command contract: `spec/v1/cli.md`

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
