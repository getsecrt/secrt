.PHONY: dev server web test test-rust test-web lint lint-rust lint-web \
       build build-rust build-web fmt clean help

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

test: test-rust test-web ## Run all tests

test-rust: ## Run Rust tests
	cargo test --workspace

test-web: ## Run frontend tests
	pnpm -C web test

test-web-coverage: ## Run frontend tests with coverage
	pnpm -C web test:coverage

test-e2e: ## Run Playwright E2E tests
	pnpm -C web test:e2e

# ── Linting ──────────────────────────────────────────────

lint: lint-rust lint-web ## Run all linters

lint-rust: ## Run Rust linters
	cargo clippy --workspace -- -D warnings
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
