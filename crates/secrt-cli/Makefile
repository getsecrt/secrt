.PHONY: build release test check size clean coverage

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

check:
	cargo clippy -- -D warnings
	cargo fmt -- --check

size: release
	@ls -la target/release/secrt
	@du -h target/release/secrt

coverage:
	cargo llvm-cov --html --open --ignore-filename-regex "(main|keychain)\.rs"

clean:
	cargo clean
