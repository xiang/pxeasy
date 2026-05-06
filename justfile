default: build

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
