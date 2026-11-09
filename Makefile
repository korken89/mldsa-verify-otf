# Host tests, lints and the QEMU measurements
.PHONY: test test-host test-qemu lint bless

# A failing command before a pipe fails the recipe
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

QEMU_INCLUDE = $(shell dirname $$(dirname $$(readlink -f $$(command -v qemu-system-arm))))/include
PLUGIN := qemu/target/libicount.so
M3 := thumbv7m-none-eabi
M33 := thumbv8m.main-none-eabihf
MEASURE = cd qemu && cargo run --release --target $(M3) && echo && cargo run --release --target $(M33)

test: test-host test-qemu

test-host:
	cargo test --release

# Fails if the stack or instruction counts differ from qemu/stack-usage.txt
test-qemu: $(PLUGIN)
	($(MEASURE)) | tee qemu/target/stack-usage.txt
	diff -u qemu/stack-usage.txt qemu/target/stack-usage.txt

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cd qemu && cargo fmt --check
	cd qemu && cargo clippy --release --target $(M3) -- -D warnings
	cd qemu && cargo clippy --release --target $(M33) -- -D warnings

# Overwrites qemu/stack-usage.txt with the current measurements
bless: $(PLUGIN)
	($(MEASURE)) | tee qemu/stack-usage.txt

$(PLUGIN): qemu/icount.c
	mkdir -p qemu/target
	$(CC) -shared -fPIC -O2 -Wall -Werror $$(pkg-config --cflags glib-2.0) -I$(QEMU_INCLUDE) -o $@ $<
