RUSTTAGS = aarch64-apple-darwin \
	x86_64-apple-darwin \
	aarch64-pc-windows-msvc \
	x86_64-pc-windows-msvc \
	aarch64-unknown-linux-musl \
	x86_64-unknown-linux-musl

OSS = windows linux darwin
ARCHS = x86_64 aarch64

local-install:
	cargo install --bin enyo --path . --locked

build-windows-x86_64:
	@echo "Building Windows x86_64"
	cargo build --release --target x86_64-pc-windows-gnu
build-windows-aarch64:
	@echo "Building Windows aarch64"
	cargo build --release --target aarch64-pc-windows-gnullvm
build-linux-x86_64:
	@echo "Building Linux x86_64"
	cargo build --release --target x86_64-unknown-linux-musl
build-linux-aarch64:
	@echo "Building Linux aarch64"
	cargo build --release --target aarch64-unknown-linux-musl
build-darwin-x86_64:
	@echo "Building Darwin x86_64"
	cargo build --release --target x86_64-apple-darwin
build-darwin-aarch64:
	@echo "Building Darwin aarch64"
	cargo build --release --target aarch64-apple-darwin

pre-build:
	@echo "Installing Rust Targets"
	@rustup target add $(RUSTTAGS)

build: pre-build
	@echo "Building Enyo Project"
	export OPENSSL_DIR=/opt/homebrew/ \
	for os in $(OSS); do \
		for arch in $(ARCHS); do \
			make build-$$os-$$arch; \
		done \
	done
