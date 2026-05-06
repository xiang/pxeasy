# pxeasy



`pxeasy` is an all-in-one network boot server.

The project is in early development. Expect breaking changes, bugs, and incomplete features.

## Features

- **Zero-Config:** Automatically detects OS profiles and configures DHCP, TFTP, HTTP, NFS, and SMB services.
- **Architectures:** First-class support for **x86_64** and **ARM64** UEFI.
- **ProxyDHCP:** Co-exists with your existing DHCP server; no need to modify your network's main DHCP configuration.
- **Integrated Services:** Internal implementations of DHCP, TFTP, HTTP, NFSv3, and SMB2 protocols.

## Supported Targets

- **Ubuntu 24.04+**: Live ISO boot via NFS or HTTP.
- **Debian 13+**: Live ISO boot via NFS or HTTP.
- **FreeBSD 15+**: Custom MFS via iPXE sanboot.
- **Windows 11**: WinPE/Installer boot with automatic SMB share setup for installation files.

## Requirements

- **Host OS:** macOS (Priority), Linux and Windows (Best Effort).
- **Privileges:** Root/Admin privileges are required to bind to privileged ports (UDP 67 for DHCP, TCP 445 for SMB).

## Installation

### From Source

Build the pxeasy binary:
```bash
cargo build --release -p pxeasy
```
To run it, either use the `just` commands defined in the `justfile` (which handle `sudo` automatically for the `run` command) or invoke the `qemu-test/run` script.

## Usage

`pxeasy` requires root/admin privileges to bind to privileged ports (UDP 67 for DHCP, TCP 445 for SMB). Always run `pxeasy` with `sudo`.

Start a boot session by pointing `pxeasy` to an ISO or boot image:

```bash
# Boot Ubuntu Live ISO
sudo pxeasy start ubuntu-24.04-server-amd64.iso

# Boot Windows Installer ISO
sudo pxeasy start Win11_English_x64.iso

# Specify a network interface
sudo pxeasy start --interface en0 ubuntu.iso
```
It is recommended to use the `just` commands or the `qemu-test/run` script for development and testing.

For local QEMU bring-up, use the shell runner:

```bash
./qemu-test/run list
./qemu-test/run ubuntu-arm64-nfs
WINDOWS_ISO=assets/windows/Win11_25H2_English_Arm64_v2.iso ./qemu-test/run windows-arm64
```

### How it Works

1. **Detection:** `pxeasy` inspects the provided file to identify the OS and architecture.
2. **Staging:** It extracts or exposes necessary boot files (kernel, initrd, bootmgr).
3. **Serving:**
   - **DHCP:** Responds to PXE requests, pointing clients to the internal TFTP server.
   - **TFTP:** Serves `iPXE` as the first-stage bootloader.
   - **HTTP:** Serves the `iPXE` script and OS kernel/initrd/WIM files.
   - **NFS/SMB:** Automatically exports the ISO contents for the OS to mount its root filesystem or installation source.

## License

[MIT]
