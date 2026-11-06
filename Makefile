# Host tests, lints and the QEMU stack usage check
.PHONY: test test-host test-qemu lint bless

# A failing command before a pipe fails the recipe
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

test: test-host test-qemu

test-host:
	cargo test --release

# Fails if the stack usage differs from qemu/stack-usage.txt
test-qemu:
	cd qemu && mkdir -p target && cargo run --release | tee target/stack-usage.txt
	diff -u qemu/stack-usage.txt qemu/target/stack-usage.txt

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cd qemu && cargo fmt --check
	cd qemu && cargo clippy --release -- -D warnings

# Overwrites qemu/stack-usage.txt with the current stack usage
bless:
	cd qemu && cargo run --release | tee stack-usage.txt
