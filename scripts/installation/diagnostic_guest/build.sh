#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -d $1 ]]; then
    printf 'usage: bash scripts/installation/diagnostic_guest/build.sh <existing-state-directory>\n' >&2
    exit 2
fi

state_dir=$(realpath -e -- "$1")
output=$state_dir/guest.cpio.gz
if [[ -e $output ]]; then
    printf 'refusing to replace existing initramfs output\n' >&2
    exit 2
fi

for tool in gcc cpio gzip find sort mktemp realpath install dirname mv; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'required build tool is unavailable: %s\n' "$tool" >&2
        exit 2
    fi
done

busybox=$(command -v busybox || true)
if [[ -z $busybox || ! -x $busybox ]]; then
    printf 'required static BusyBox binary is unavailable\n' >&2
    exit 2
fi

build_root=$(mktemp -d "$state_dir/.diagnostic-guest.XXXXXX")
cleanup_build_root() {
    rm -rf -- "$build_root"
}
trap cleanup_build_root EXIT

rootfs=$build_root/root
mkdir -p -- "$rootfs/bin" "$rootfs/dev"
gcc -static -Os -s -fno-ident -Wl,--build-id=none \
    -Wall -Wextra -Werror \
    -o "$rootfs/init" "$(dirname -- "${BASH_SOURCE[0]}")/init.c"
chmod 0755 "$rootfs/init"
install -m 0755 -- "$busybox" "$rootfs/bin/busybox"

(
    cd -- "$rootfs"
    find . -print0 | sort -z | cpio --null --create --format=newc --quiet
) | gzip -n -9 > "$build_root/guest.cpio.gz"

if [[ -e $output ]]; then
    printf 'refusing to replace existing initramfs output\n' >&2
    exit 2
fi
mv -- "$build_root/guest.cpio.gz" "$output"
printf 'created %s\n' "$output"
