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

### Default boot flow policy

Use this as the generic assumption unless there is a clear compatibility reason to override it:
- First stage: PXE firmware chainloads `iPXE` over TFTP
- Second stage: `iPXE` boots over HTTP
- Boot source handling should be minimal: detect the source, expose the needed assets, generate the smallest boot script needed, and avoid parsing or rewriting upstream GRUB configs unless required
- TFTP is only the firmware-to-`iPXE` bridge by default; it should not be the main payload path
- Prefer one consistent flow across UEFI and BIOS, even if the first-stage `iPXE` binary differs by firmware type

Current implementation note: this is the intended default, but BIOS first-stage support may still lag UEFI in code.

### `pxe-proto` (implemented)

Pure DHCP/PXE packet parsing and serialization. No I/O, no async, no external crates in production code (`std`-only). Key invariants:
- `DhcpPacket::parse()` never panics — all errors go through `ParseError`
- `parse(serialize(p)) == p` for all valid packets
- Pad (0) and End (255) bytes are structural — not stored in the `options` vec
- `DhcpOption::Unknown` preserves unrecognized options through round-trips

Option 43 (`VendorSpecific`) is stored as raw bytes in `DhcpOption` and decoded separately via `PxeVendorOptions::parse()` — two-step decode by design.

### Planned crates (specs in `.docs/`)

- **`pxe-profiles`** (Phase 2): ISO 9660 inspection → `BootProfile` + boot metadata needed for the default `iPXE` → HTTP flow. Detection heuristics are the most fragile part - test-first.
- **`pxe-dhcp`** (Phase 3): ProxyDHCP only - injects boot params, never assigns IPs. By default it should point firmware at `iPXE`, then point `iPXE` at the HTTP boot script. The `build_offer`/`build_ack` pure functions are the primary test target; boot filename and option 43 content are the main failure points.
- **`pxe-tftp`** (Phase 4): Read-only TFTP serving the first-stage `iPXE` binary and only tiny compatibility files when justified.
- **`pxe-http`** (Phase 5): HTTP serving kernel/initrd and source payloads for the main boot path. Must support range requests.
- **`pxeasy` CLI** (Phase 6): `pxeasy start <iso-path> [--interface <iface>] [--bind <ip>]` - wires ProxyDHCP, TFTP, and HTTP together for PXE → `iPXE` → HTTP boot.

## Storage mode constraints

**Hard constraint: the booting machine must never need more RAM than Ubuntu requires to run (~4 GB for desktop, ~2 GB for server).** The PXE mechanism must not add to that requirement.

This rules out any approach that downloads the ISO or squashfs to client RAM before mounting:

| Mode | How casper finds the filesystem | Client RAM overhead | Works? |
|------|--------------------------------|---------------------|--------|
| NFS  | Mounts squashfs over NFS, reads blocks on demand | ~0 | ✓ Reliable |
| iSCSI | Exposes the ISO as a remote block device, reads blocks on demand | ~0 | ✓ Requires iSCSI in initrd |
| HTTP `fetch=<squashfs>` | Downloads squashfs (~2.5 GB) to tmpfs, then mounts | ~2.5 GB | ✓ Within constraint — squashfs IS the OS, same RAM either way |
| HTTP `url=<iso>` | Downloads entire ISO to tmpfs, then loop-mounts | = ISO size (2–6 GB) | ✗ Violates constraint — ISO is much larger than squashfs |

**Do not use `url=<iso>`.** Always use `fetch=<squashfs>` for HTTP live ISO boot.

For live ISO boot, use `--storage nfs` (always works) or `--storage iscsi` (requires the initrd to include iSCSI support).

## Code standards

- No `unwrap()` or `expect()` in non-test code — use `?` or explicit error handling
- Bootloader scripts, if added later, must use `\n` (LF only), no trailing whitespace
- `cargo clippy -- -D warnings` must pass before a phase is considered done
- Make atomic, meaningful commits as you do work.
- @STANDARDS.md
