## Commands

```bash
# Build
cargo build

# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p pxe-proto

# Run a single test by name
cargo test -p pxe-proto test_name

# Lint (must be clean — warnings are errors)
cargo clippy -- -D warnings

# Check without building
cargo check
```

## Architecture

`pxeasy` is a Rust workspace implementing a zero-config PXE boot server. The planned crate graph is:

```
CLI (pxeasy)
├── pxe-dhcp  → pxe-proto
├── pxe-tftp
├── pxe-http  → pxe-profiles
└── pxe-profiles
```

Only `pxe-proto` is implemented so far (Phase 1). The remaining crates are defined in `.docs/` specs and will be added as workspace members in implementation order.

Primary platform target is modern UEFI hardware, with arm64 support treated as first-class alongside x86_64. Legacy BIOS support is lower priority than getting the UEFI boot path working cleanly on current hardware and VMs.

### `pxe-proto` (implemented)

Pure DHCP/PXE packet parsing and serialization. No I/O, no async, no external crates in production code (`std`-only). Key invariants:
- `DhcpPacket::parse()` never panics — all errors go through `ParseError`
- `parse(serialize(p)) == p` for all valid packets
- Pad (0) and End (255) bytes are structural — not stored in the `options` vec
- `DhcpOption::Unknown` preserves unrecognized options through round-trips

Option 43 (`VendorSpecific`) is stored as raw bytes in `DhcpOption` and decoded separately via `PxeVendorOptions::parse()` — two-step decode by design.

### Planned crates (specs in `.docs/`)

- **`pxe-profiles`** (Phase 2): ISO 9660 inspection → `BootProfile` + iPXE script generation. Detection heuristics are the most fragile part — test-first.
- **`pxe-dhcp`** (Phase 3): ProxyDHCP only — injects boot params, never assigns IPs. The `build_offer`/`build_ack` pure functions are the primary test target; option 43 content is the #1 real-world failure point.
- **`pxe-tftp`** (Phase 4): Read-only TFTP serving `ipxe.efi` and `boot.ipxe` from an in-memory `HashMap<String, Bytes>`.
- **`pxe-http`** (Phase 6): HTTP serving kernel/initrd from ISO; must support range requests (iPXE requires them).
- **`pxeasy` CLI** (Phase 5): `pxeasy start <iso-path> [--interface <iface>] [--bind <ip>]` — wires ProxyDHCP and TFTP together for the first boot to the iPXE prompt. HTTP integration follows in Phase 6.

## Code standards

- No `unwrap()` or `expect()` in non-test code — use `?` or explicit error handling
- iPXE script generation must use `\n` (LF only), no trailing whitespace — iPXE is sensitive
- `cargo clippy -- -D warnings` must pass before a phase is considered done
- Make atomic, meaningful commits as you do work.
