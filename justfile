default: build

run:
	sudo pxeasy

build:
	cargo build -p pxeasy

gui:
	cargo run -p pxeasy-gui

check:
	cargo fmt --all
	cargo clippy --workspace --all-targets -- -D warnings

lint:
	cargo fmt --all

pxeasy-start image:
	sudo env RUST_LOG="${RUST_LOG:-warn}" cargo run -p pxeasy -- start "{{image}}" ${INTERFACE:+--interface "$INTERFACE"} ${BIND:+--bind "$BIND"}

build-harness:
	cargo build -p pxe-harness

pxe-smoke scenario="ubuntu-arm64-nfs":
	cargo run -p pxe-harness -- smoke {{scenario}}

windows-arm64 iso="assets/windows/Win11_25H2_English_Arm64_v2.iso":
	cargo run -p pxe-harness -- windows-arm64 {{iso}}

MAKEFS_BIN := "makefs"

# Build the main FreeBSD sanboot image
build-freebsd-img:
	MAKEFS_BIN={{MAKEFS_BIN}} ./scripts/build-freebsd.sh \
		assets/freebsd/FreeBSD-15.0-RELEASE-arm64-aarch64-bootonly.iso \
		assets/freebsd/FreeBSD-15.0-RELEASE-arm64-aarch64-mini.img
