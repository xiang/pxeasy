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

qemu-list:
	./scripts/qemu-scenario.sh list

pxe-smoke scenario="ubuntu-arm64-nfs":
	./scripts/qemu-scenario.sh run {{scenario}}

windows-arm64 iso="assets/windows/Win11_25H2_English_Arm64_v2.iso":
	./scripts/qemu-scenario.sh windows-arm64 {{iso}}
