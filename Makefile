.PHONY: dev server web \
       test test-rust test-rust-fallback test-doc test-app \
       test-cli test-server test-core test-web \
       lint lint-rust lint-web \
       build build-rust build-web \
       fmt clean help \
       check-nextest

# ── Development ──────────────────────────────────────────

dev: ## Start backend + frontend (Ctrl+C stops both)
	@trap 'kill 0' INT TERM; \
	cargo run --bin secrt-server & \
	sleep 1; \
	pnpm -C web dev & \
	wait

server: ## Start backend only
	cargo run --bin secrt-server

web: ## Start frontend only
	pnpm -C web dev

# ── Testing ──────────────────────────────────────────────
#
# Default Rust test runs use cargo-nextest (~3.5× faster than `cargo test`
# on this workspace) and exclude `secrt-app` (Tauri) — local devs working
# on CLI/server should not pay Tauri's 12× target-dir cost. Use
# `make test-app` when you actually need to test the desktop app.
#
# Scoped targets (`test-cli`, `test-server`, `test-core`) avoid rebuilding
# unrelated crates' deps when iterating on a single area.

test: test-rust test-web ## Run all tests (Rust + frontend)

test-rust: check-nextest ## Run Rust tests (nextest, excludes secrt-app)
	cargo nextest run --workspace --exclude secrt-app
	$(MAKE) --no-print-directory test-doc

test-rust-fallback: ## Run Rust tests via cargo (slower; for envs without nextest)
	cargo test --workspace --exclude secrt-app

test-doc: ## Run doctests (nextest skips these)
	cargo test --doc --workspace --exclude secrt-app

test-cli: check-nextest ## Run only secrt-cli tests
	cargo nextest run -p secrt-cli

test-server: check-nextest ## Run only secrt-server tests
	cargo nextest run -p secrt-server

test-core: check-nextest ## Run only secrt-core tests
	cargo nextest run -p secrt-core

test-app: ## Run secrt-app (Tauri desktop) tests — heavy, opt-in
	cargo test -p secrt-app

test-web: ## Run frontend tests
	pnpm -C web test

test-web-coverage: ## Run frontend tests with coverage
	pnpm -C web test:coverage

test-e2e: ## Run Playwright E2E tests
	pnpm -C web test:e2e

check-nextest:
	@command -v cargo-nextest >/dev/null 2>&1 || { \
	  echo "cargo-nextest is required. Install with:"; \
	  echo "  cargo install --locked cargo-nextest"; \
	  echo "Or fall back to: make test-rust-fallback"; \
	  exit 1; \
	}

# ── Linting ──────────────────────────────────────────────
#
# Excludes secrt-app to match CI; the Tauri target dir bloat is not worth
# paying on every clippy run. If you're touching secrt-app, lint it
# explicitly with: cargo clippy -p secrt-app -- -D warnings

lint: lint-rust lint-web ## Run all linters

lint-rust: ## Run Rust linters (excludes secrt-app)
	cargo clippy --workspace --exclude secrt-app -- -D warnings
	cargo fmt --all -- --check

lint-web: ## Run frontend linters
	pnpm -C web check
	pnpm -C web format:check

# ── Building ─────────────────────────────────────────────

build: build-rust build-web ## Build everything

build-rust: ## Build all Rust crates
	cargo build --workspace

build-web: ## Build frontend for production
	pnpm -C web build

release: ## Build optimized release binary
	cargo build --release -p secrt-cli

# ── Formatting ───────────────────────────────────────────

fmt: ## Auto-format all code
	cargo fmt --all
	pnpm -C web format

# ── Cleanup ──────────────────────────────────────────────

clean: ## Remove build artifacts
	cargo clean
	rm -rf web/dist web/coverage

# ── Help ─────────────────────────────────────────────────

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
	  awk -F ':.*## ' '{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
