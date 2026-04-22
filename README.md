# pxeasy

`pxeasy` is a zero-config, all-in-one PXE boot server written in Rust. It allows you to boot OS installers and live environments (ISO, disk images, netboot assets) over the network with a single command.

## Features

- **Zero-Config:** Automatically detects OS profiles and configures DHCP, TFTP, HTTP, NFS, and SMB services.
- **Multi-OS Support:**
  - **Ubuntu/Debian:** Live ISO boot via NFS or HTTP (casper).
  - **Windows:** WinPE/Installer boot with automatic SMB share setup for installation files.
  - **FreeBSD:** `sanboot` (HTTP) or direct EFI/TFTP boot.
- **Architectures:** First-class support for **x86_64** and **ARM64** UEFI.
- **ProxyDHCP:** Co-exists with your existing DHCP server; no need to modify your network's main DHCP configuration.
- **Integrated Services:** Includes internal implementations of DHCP, TFTP, HTTP, NFSv3, and SMB2 protocols.

## Requirements

- **Linux or macOS** (macOS requires `xorriso` for ISO extraction).
- **Root/Admin Privileges:** Required to bind to privileged ports (UDP 67 for DHCP, TCP 445 for SMB).
- **Dependencies:**
  - `xorriso`: Used for inspecting and extracting ISO contents.
  - `curl`: Used to download iPXE and wimboot binaries on demand.

## Installation

### From Source

```bash
cargo build --release -p pxeasy
sudo cp target/release/pxeasy /usr/local/bin/
```

## Usage

Start a boot session by pointing `pxeasy` to an ISO or boot image:

```bash
# Boot Ubuntu Live ISO
sudo pxeasy start ubuntu-24.04-server-amd64.iso

# Boot Windows Installer ISO
sudo pxeasy start Win11_English_x64.iso

# Specify a network interface
sudo pxeasy start --interface eth0 ubuntu.iso
```

### How it Works

1. **Detection:** `pxeasy` inspects the provided file to identify the OS and architecture.
2. **Staging:** It extracts or exposes necessary boot files (kernel, initrd, bootmgr).
3. **Serving:**
   - **DHCP:** Responds to PXE requests, pointing clients to the internal TFTP server.
   - **TFTP:** Serves `iPXE` as the first-stage bootloader.
   - **HTTP:** Serves the `iPXE` script and OS kernel/initrd/WIM files.
   - **NFS/SMB:** Automatically exports the ISO contents for the OS to mount its root filesystem or installation source.

### Windows Templates

Tracked default Windows templates live in `templates/windows/` in the repo.
Windows WinPE template files are managed under `~/.pxeasy/templates/windows/`.
On first use, `pxeasy` seeds default copies of `startnet.cmd`, `winpeshl.ini`, and `pxeasy-bootstrap.cmd` there, then reads from those paths for subsequent boots so local customizations do not depend on the repo checkout.

Optional Windows dev-only VirtIO drivers are loaded from `~/.pxeasy/dev/windows/virtio-win/` or `PXEASY_WINDOWS_VIRTIO_ROOT` when present. They are not part of the tracked repo templates or default runtime path.

## Project Architecture

`pxeasy` is composed of several specialized crates:

- `pxe-dhcp`: ProxyDHCP server logic.
- `pxe-tftp`: Read-only TFTP server.
- `pxe-http`: Range-request capable HTTP server for boot assets.
- `pxe-nfs`: NFSv3 server for Linux live ISOs.
- `pxe-smb`: SMB2 server for Windows installation files.
- `pxe-profiles`: OS-specific boot parameters and logic.
- `pxe-proto`: Low-level protocol packet parsing (DHCP/PXE).
- `pxeasy-runtime`: Orchestration layer for the various services.

## Development

Use the included `justfile` for common tasks:

```bash
# Run tests
cargo test

# Check for linting issues
just check

# Run a smoke test (requires QEMU)
just pxe-smoke
```

## License

[MIT or Apache-2.0]
