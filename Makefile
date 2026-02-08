.PHONY: build build-prod run test test-cover test-race clean deps fmt fmt-check lint golangci-lint govulncheck vet tools check css css-watch css-prod tailwind-cli

BIN_DIR := bin
APP := secrt-server
CTL := secretctl
CLI := secrt
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Tailwind CSS
TAILWIND_VERSION := v4.1.4
TAILWIND_BIN := $(BIN_DIR)/tailwindcss
CSS_INPUT := web/static/css/input.css
CSS_OUTPUT := web/static/css/output.css

# Detect OS/arch for Tailwind binary download
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Linux)
	ifeq ($(UNAME_M),x86_64)
		TAILWIND_PLATFORM := linux-x64
	else ifeq ($(UNAME_M),aarch64)
		TAILWIND_PLATFORM := linux-arm64
	endif
else ifeq ($(UNAME_S),Darwin)
	ifeq ($(UNAME_M),x86_64)
		TAILWIND_PLATFORM := macos-x64
	else ifeq ($(UNAME_M),arm64)
		TAILWIND_PLATFORM := macos-arm64
	endif
endif

# Build the application (with debug symbols)
build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(APP) ./cmd/secrt-server
	go build -o $(BIN_DIR)/$(CTL) ./cmd/secretctl
	go build -ldflags="-X main.version=$(VERSION)" -o $(BIN_DIR)/$(CLI) ./cmd/secrt

# Build for production (stripped, smaller)
build-prod: css-prod
	mkdir -p $(BIN_DIR)
	go build -ldflags="-s -w" -o $(BIN_DIR)/$(APP) ./cmd/secrt-server
	go build -ldflags="-s -w" -o $(BIN_DIR)/$(CTL) ./cmd/secretctl
	go build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/$(CLI) ./cmd/secrt

# Run the application
run:
	go run ./cmd/secrt-server

# Run all tests
test:
	go test -v ./...

# Run tests with coverage report
test-cover:
	# -count=1 avoids stale coverage block mismatches when packages are cached.
	go test -count=1 -coverprofile=coverage.out -coverpkg=./internal/... ./internal/...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run tests with race detection
test-race:
	go test -race ./...

# Format code
fmt:
	@command -v goimports > /dev/null 2>&1 || (echo "Installing goimports..." && go install golang.org/x/tools/cmd/goimports@latest)
	gofmt -w .
	goimports -w .

# Check formatting (for CI)
fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "Files not formatted:"; gofmt -l .; exit 1)

# Run go vet for static analysis
vet:
	go vet ./...

# Run golangci-lint for comprehensive static analysis
# Auto-installs if not present
golangci-lint:
	@command -v golangci-lint > /dev/null 2>&1 || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@if command -v golangci-lint > /dev/null 2>&1; then golangci-lint run; else $$(go env GOPATH)/bin/golangci-lint run; fi

# Run vulnerability scanner
govulncheck:
	@command -v govulncheck > /dev/null 2>&1 || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	@if command -v govulncheck > /dev/null 2>&1; then govulncheck ./...; else $$(go env GOPATH)/bin/govulncheck ./...; fi

# Install all development tools
tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install golang.org/x/tools/cmd/goimports@latest

# Run all linters
lint: golangci-lint

# Run all checks (lint + test + race + vulncheck)
check: lint test test-race govulncheck

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html
	rm -f $(CSS_OUTPUT)

# Install dependencies
deps:
	go mod download
	go mod verify

# Download Tailwind CLI binary
tailwind-cli:
	@if [ ! -f $(TAILWIND_BIN) ]; then \
		echo "Downloading Tailwind CSS CLI $(TAILWIND_VERSION) for $(TAILWIND_PLATFORM)..."; \
		mkdir -p $(BIN_DIR); \
		curl -sL https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$(TAILWIND_PLATFORM) -o $(TAILWIND_BIN); \
		chmod +x $(TAILWIND_BIN); \
	fi

# Build CSS (development)
css: tailwind-cli
	$(TAILWIND_BIN) -i $(CSS_INPUT) -o $(CSS_OUTPUT)

# Build CSS (production, minified)
css-prod: tailwind-cli
	$(TAILWIND_BIN) -i $(CSS_INPUT) -o $(CSS_OUTPUT) --minify

# Watch CSS for development
css-watch: tailwind-cli
	$(TAILWIND_BIN) -i $(CSS_INPUT) -o $(CSS_OUTPUT) --watch
