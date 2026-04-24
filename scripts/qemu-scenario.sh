#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCENARIO_DIR="$SCRIPT_DIR/qemu-scenarios"
TARGET_DIR="${PXEASY_QEMU_TARGET_DIR:-$REPO_ROOT/target/qemu-scenarios}"
CACHE_DIR="${PXEASY_QEMU_CACHE_DIR:-${TMPDIR:-/tmp}/pxeasy-qemu}"
LOG_DIR="$TARGET_DIR/logs"

SERVER_PID=""
QEMU_PID=""
SERVER_LOG=""
GUEST_LOG=""
TEMP_DIR=""
QEMU_SUDO_ACTIVE=0

usage() {
    cat <<'EOF'
usage:
  ./scripts/qemu-scenario.sh list
  ./scripts/qemu-scenario.sh run <scenario> [--no-build]
  ./scripts/qemu-scenario.sh windows-arm64 <iso-path> [--disk <raw-disk>] [--no-build]

environment:
  PXEASY_QEMU_BIN        Override QEMU binary (default: qemu-system-aarch64)
  PXEASY_QEMU_NETDEV     Override -netdev argument
  PXEASY_QEMU_SUDO       Force QEMU sudo usage (1/true or 0/false)
  PXEASY_QEMU_INTERFACE  Pass --interface to pxeasy
  PXEASY_QEMU_BIND       Pass --bind to pxeasy
  RUST_LOG               pxeasy log level (default: debug)
EOF
}

cleanup() {
    local status=$?
    set +e

    if [[ -n "$QEMU_PID" ]]; then
        if [[ "$QEMU_SUDO_ACTIVE" == "1" ]]; then
            sudo -n kill "$QEMU_PID" >/dev/null 2>&1 || true
        else
            kill "$QEMU_PID" >/dev/null 2>&1 || true
        fi
        wait "$QEMU_PID" >/dev/null 2>&1 || true
    fi

    if [[ -n "$SERVER_PID" ]]; then
        sudo -n kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi

    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi

    exit "$status"
}

trap cleanup EXIT INT TERM

log() {
    printf '[qemu-scenario] %s\n' "$*"
}

fail() {
    printf '[qemu-scenario] error: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || fail "missing required command: $cmd"
    done
}

is_macos() {
    [[ "$(uname -s)" == "Darwin" ]]
}

process_exists() {
    ps -p "$1" >/dev/null 2>&1
}

file_size() {
    if stat -f %z "$1" >/dev/null 2>&1; then
        stat -f %z "$1"
    else
        stat -c %s "$1"
    fi
}

list_scenarios() {
    local path
    for path in "$SCENARIO_DIR"/*.env; do
        basename "$path" .env
    done | sort
}

load_scenario() {
    local scenario_name="$1"
    local scenario_path="$SCENARIO_DIR/$scenario_name.env"
    [[ -f "$scenario_path" ]] || fail "unknown scenario: $scenario_name"

    SCENARIO_NAME="$scenario_name"
    SOURCE_PATH=""
    GUEST_MODE=""
    GUEST_SUCCESS_PATTERN=""
    SERVER_SUCCESS_PATTERN=""
    TIMEOUT_SECS=""
    PXEASY_ENV=()

    # shellcheck source=/dev/null
    source "$scenario_path"

    [[ -n "$SOURCE_PATH" ]] || fail "scenario $scenario_name is missing SOURCE_PATH"
    [[ -n "$GUEST_MODE" ]] || fail "scenario $scenario_name is missing GUEST_MODE"
    [[ -n "$GUEST_SUCCESS_PATTERN" ]] || fail "scenario $scenario_name is missing GUEST_SUCCESS_PATTERN"
    [[ -n "$TIMEOUT_SECS" ]] || fail "scenario $scenario_name is missing TIMEOUT_SECS"
}

build_source_if_needed() {
    if [[ -f "$SOURCE_PATH" ]]; then
        return
    fi

    fail "missing scenario source: $SOURCE_PATH"
}

build_pxeasy() {
    mkdir -p "$TARGET_DIR"
    (cd "$REPO_ROOT" && cargo build -p pxeasy --target-dir "$TARGET_DIR")
}

pxeasy_bin() {
    printf '%s\n' "$TARGET_DIR/debug/pxeasy"
}

start_server() {
    local source_path="$1"
    shift

    mkdir -p "$LOG_DIR"
    SERVER_LOG="$LOG_DIR/${SCENARIO_NAME:-windows-arm64}-server.log"
    : >"$SERVER_LOG"

    local bin
    bin="$(pxeasy_bin)"
    [[ -x "$bin" ]] || fail "missing built pxeasy binary at $bin"

    local cmd=(
        sudo -n env
        "RUST_LOG=${RUST_LOG:-debug}"
    )
    if ((${#PXEASY_ENV[@]})); then
        local entry
        for entry in "${PXEASY_ENV[@]}"; do
            cmd+=("$entry")
        done
    fi
    cmd+=("$bin" start "$source_path")

    if [[ -n "${PXEASY_QEMU_INTERFACE:-}" ]]; then
        cmd+=(--interface "$PXEASY_QEMU_INTERFACE")
    fi
    if [[ -n "${PXEASY_QEMU_BIND:-}" ]]; then
        cmd+=(--bind "$PXEASY_QEMU_BIND")
    fi

    "${cmd[@]}" >"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!

    wait_for_pattern "$SERVER_LOG" "waiting for PXE clients" 120 \
        || fail_with_logs "pxeasy did not become ready"
}

wait_for_pattern() {
    local file="$1"
    local pattern="$2"
    local timeout_secs="$3"
    local elapsed=0

    while (( elapsed < timeout_secs )); do
        if grep -Fq "$pattern" "$file"; then
            return 0
        fi
        if [[ -n "$SERVER_PID" ]] && ! process_exists "$SERVER_PID"; then
            return 1
        fi
        if [[ -n "$QEMU_PID" ]] && ! process_exists "$QEMU_PID"; then
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    return 1
}

tail_log() {
    local file="$1"
    if [[ -f "$file" ]]; then
        tail -n 40 "$file" >&2 || true
    fi
}

fail_with_logs() {
    local message="$1"
    printf '[qemu-scenario] error: %s\n' "$message" >&2
    if [[ -n "$SERVER_LOG" ]]; then
        printf '[qemu-scenario] server log tail:\n' >&2
        tail_log "$SERVER_LOG"
    fi
    if [[ -n "$GUEST_LOG" ]]; then
        printf '[qemu-scenario] guest log tail:\n' >&2
        tail_log "$GUEST_LOG"
    fi
    exit 1
}

find_arm64_firmware() {
    local homebrew_fw="/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
    local asset_fw="$REPO_ROOT/assets/RELEASEAARCH64_QEMU_EFI.fd"

    if [[ -f "$homebrew_fw" ]]; then
        printf '%s\n' "$homebrew_fw"
        return
    fi
    if [[ -f "$asset_fw" ]]; then
        printf '%s\n' "$asset_fw"
        return
    fi

    fail "no AARCH64 UEFI firmware found"
}

fresh_vars() {
    local vars_src="$REPO_ROOT/assets/RELEASEAARCH64_QEMU_VARS.fd"
    local vars_dst="$TEMP_DIR/vars.fd"
    [[ -f "$vars_src" ]] || fail "missing UEFI vars image: $vars_src"
    cp "$vars_src" "$vars_dst"
    printf '%s\n' "$vars_dst"
}

fetch_ipxe_disk_efi() {
    local arch="$1"
    local url=""

    case "$arch" in
        arm64|aarch64)
            url="https://boot.ipxe.org/arm64-efi/ipxe.efi"
            ;;
        amd64|x86_64)
            url="https://boot.ipxe.org/ipxe.efi"
            ;;
        *)
            fail "unsupported iPXE architecture: $arch"
            ;;
    esac

    mkdir -p "$CACHE_DIR"
    local out="$CACHE_DIR/ipxe-full-$arch.efi"
    if [[ ! -f "$out" ]]; then
        curl -fsSL "$url" -o "$out"
    fi
    printf '%s\n' "$out"
}

create_uefi_boot_disk() {
    local efi_app="$1"
    local disk="$TEMP_DIR/ipxe-boot.img"

    require_cmd dd mformat mmd mcopy

    dd if=/dev/zero of="$disk" bs=512 count=131072 >/dev/null 2>&1
    mformat -i "$disk" :: >/dev/null
    mmd -i "$disk" ::EFI >/dev/null
    mmd -i "$disk" ::EFI/BOOT >/dev/null
    mcopy -i "$disk" "$efi_app" ::EFI/BOOT/BOOTAA64.EFI >/dev/null

    printf '%s\n' "$disk"
}

default_netdev() {
    if is_macos; then
        printf '%s\n' "vmnet-bridged,id=net0,ifname=en0"
    else
        printf '%s\n' "user,id=net0"
    fi
}

qemu_use_sudo() {
    if [[ -n "${PXEASY_QEMU_SUDO:-}" ]]; then
        case "${PXEASY_QEMU_SUDO}" in
            1|true|TRUE|yes|YES) return 0 ;;
            0|false|FALSE|no|NO) return 1 ;;
        esac
        fail "PXEASY_QEMU_SUDO must be true/false or 1/0"
    fi

    is_macos
}

run_arm64_uefi_smoke() {
    require_cmd curl

    TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pxeasy-qemu.XXXXXX")"
    mkdir -p "$LOG_DIR"
    GUEST_LOG="$LOG_DIR/${SCENARIO_NAME}-guest.log"
    : >"$GUEST_LOG"

    local firmware vars ipxe_efi ipxe_disk qemu_bin netdev
    firmware="$(find_arm64_firmware)"
    vars="$(fresh_vars)"
    ipxe_efi="$(fetch_ipxe_disk_efi arm64)"
    ipxe_disk="$(create_uefi_boot_disk "$ipxe_efi")"
    qemu_bin="${PXEASY_QEMU_BIN:-qemu-system-aarch64}"
    netdev="${PXEASY_QEMU_NETDEV:-$(default_netdev)}"

    local cmd=()
    if qemu_use_sudo; then
        QEMU_SUDO_ACTIVE=1
        cmd=(sudo -n "$qemu_bin")
    else
        QEMU_SUDO_ACTIVE=0
        cmd=("$qemu_bin")
    fi

    cmd+=(
        -machine virt
    )
    if is_macos; then
        cmd+=(-cpu host -accel hvf)
    else
        cmd+=(-cpu cortex-a72 -accel tcg)
    fi
    cmd+=(
        -display none
        -serial stdio
        -m 8G
        -boot n
        -device virtio-net-pci,netdev=net0,romfile=
        -netdev "$netdev"
        -drive "if=pflash,format=raw,unit=0,file=$firmware,readonly=on"
        -drive "if=pflash,format=raw,unit=1,file=$vars"
        -drive "if=virtio,format=raw,file=$ipxe_disk"
    )

    log "launching $SCENARIO_NAME"
    "${cmd[@]}" >"$GUEST_LOG" 2>&1 &
    QEMU_PID=$!

    local start_ts now last_size current_size
    start_ts="$(date +%s)"
    last_size=0

    local failure_patterns=(
        "No bootable option or device was found"
        "BootManagerMenuApp"
        "UEFI Interactive Shell"
        "Shell>"
        "EFI Internal Shell"
        "Press ESC in"
        "No mapping found"
        "PXE-E"
        "No configuration methods"
        "Unable to obtain"
        "Connection timed out"
        "Error 0x"
    )

    while true; do
        if grep -Fq "$GUEST_SUCCESS_PATTERN" "$GUEST_LOG"; then
            return 0
        fi

        local pattern
        for pattern in "${failure_patterns[@]}"; do
            if grep -Fq "$pattern" "$GUEST_LOG"; then
                fail_with_logs "QEMU boot failed after matching: $pattern"
            fi
        done

        if ! process_exists "$QEMU_PID"; then
            wait "$QEMU_PID" || true
            fail_with_logs "QEMU exited before matching success pattern"
        fi

        now="$(date +%s)"
        if (( now - start_ts >= TIMEOUT_SECS )); then
            fail_with_logs "timeout waiting for guest success pattern: $GUEST_SUCCESS_PATTERN"
        fi

        current_size="$(file_size "$GUEST_LOG")"
        if [[ "$current_size" != "$last_size" ]]; then
            last_size="$current_size"
            start_idle="$now"
        fi
        if [[ -n "${start_idle:-}" ]] && (( now - start_idle >= 120 )); then
            fail_with_logs "guest console stalled for 120s"
        fi

        sleep 1
    done
}

ensure_disk_image() {
    local path="$1"
    local size_bytes=$((64 * 1024 * 1024 * 1024))

    mkdir -p "$(dirname "$path")"
    if [[ ! -f "$path" ]]; then
        truncate -s "$size_bytes" "$path"
        return
    fi

    local current_size
    current_size="$(file_size "$path")"
    if (( current_size < size_bytes )); then
        truncate -s "$size_bytes" "$path"
    fi
}

run_windows_arm64() {
    local iso_path="$1"
    local disk_path="$2"

    [[ -f "$iso_path" ]] || fail "missing Windows source: $iso_path"
    ensure_disk_image "$disk_path"

    TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pxeasy-qemu.XXXXXX")"

    local firmware vars ipxe_efi ipxe_disk qemu_bin netdev display
    firmware="$(find_arm64_firmware)"
    vars="$(fresh_vars)"
    ipxe_efi="$(fetch_ipxe_disk_efi arm64)"
    ipxe_disk="$(create_uefi_boot_disk "$ipxe_efi")"
    qemu_bin="${PXEASY_QEMU_BIN:-qemu-system-aarch64}"
    netdev="${PXEASY_QEMU_NETDEV:-$(default_netdev)}"

    if is_macos; then
        display="cocoa"
    else
        display="gtk"
    fi

    local cmd=()
    if qemu_use_sudo; then
        QEMU_SUDO_ACTIVE=1
        cmd=(sudo -n "$qemu_bin")
    else
        QEMU_SUDO_ACTIVE=0
        cmd=("$qemu_bin")
    fi

    cmd+=(
        -machine virt
        -cpu host
        -accel hvf
        -smp cpus=8,sockets=1,cores=8,threads=1
        -m 8G
        -boot n
        -no-reboot
        -no-shutdown
        -device virtio-net-pci,netdev=net0,romfile=
        -netdev "$netdev"
        -device qemu-xhci,id=usb-bus
        -device usb-tablet,bus=usb-bus.0
        -device usb-kbd,bus=usb-bus.0
        -display "$display"
        -serial stdio
        -drive "if=pflash,format=raw,unit=0,file=$firmware,readonly=on"
        -drive "if=pflash,format=raw,unit=1,file=$vars"
        -drive "if=virtio,format=raw,file=$ipxe_disk"
        -drive "if=none,id=installdisk,format=raw,file=$disk_path"
        -device nvme,serial=pxeasy0,drive=installdisk
    )

    log "launching Windows ARM64 QEMU with disk $disk_path"
    "${cmd[@]}"
}

run_scenario() {
    local scenario_name="$1"
    local no_build="$2"

    load_scenario "$scenario_name"
    build_source_if_needed

    if [[ "$no_build" != "1" ]]; then
        build_pxeasy
    fi

    start_server "$SOURCE_PATH"

    case "$GUEST_MODE" in
        arm64_uefi_smoke)
            run_arm64_uefi_smoke
            ;;
        *)
            fail "unsupported guest mode: $GUEST_MODE"
            ;;
    esac

    if [[ -n "$SERVER_SUCCESS_PATTERN" ]]; then
        wait_for_pattern "$SERVER_LOG" "$SERVER_SUCCESS_PATTERN" "$TIMEOUT_SECS" \
            || fail_with_logs "server pattern not seen: $SERVER_SUCCESS_PATTERN"
    fi

    log "scenario $SCENARIO_NAME passed"
}

main() {
    [[ $# -gt 0 ]] || {
        usage
        exit 1
    }

    mkdir -p "$TARGET_DIR" "$CACHE_DIR"

    local command="$1"
    shift

    case "$command" in
        list)
            list_scenarios
            ;;
        run)
            [[ $# -ge 1 ]] || fail "usage: ./scripts/qemu-scenario.sh run <scenario> [--no-build]"
            local scenario_name="$1"
            shift
            local no_build=0
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --no-build)
                        no_build=1
                        ;;
                    *)
                        fail "unexpected argument: $1"
                        ;;
                esac
                shift
            done
            run_scenario "$scenario_name" "$no_build"
            ;;
        windows-arm64)
            [[ $# -ge 1 ]] || fail "usage: ./scripts/qemu-scenario.sh windows-arm64 <iso-path> [--disk <raw-disk>] [--no-build]"
            local iso_path="$1"
            shift
            local disk_path="$TARGET_DIR/windows-arm64-installer.raw"
            local no_build=0
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --disk)
                        shift
                        [[ $# -gt 0 ]] || fail "--disk requires a path"
                        disk_path="$1"
                        ;;
                    --no-build)
                        no_build=1
                        ;;
                    *)
                        fail "unexpected argument: $1"
                        ;;
                esac
                shift
            done

            SCENARIO_NAME="windows-arm64"
            PXEASY_ENV=()
            if [[ "$no_build" != "1" ]]; then
                build_pxeasy
            fi
            start_server "$iso_path"
            run_windows_arm64 "$iso_path" "$disk_path"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
