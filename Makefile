# Host tests and the QEMU stack usage test
.PHONY: test test-host test-qemu

test: test-host test-qemu

test-host:
	cargo test --release

test-qemu:
	cd qemu && cargo run --release
