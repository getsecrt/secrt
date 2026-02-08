.PHONY: build release test check size clean

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

clean:
	cargo clean
