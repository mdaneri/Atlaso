#!/usr/bin/env bash
set -euo pipefail

buildroot_version="2026.05.1"
package_version="2026.05.1+8"
buildroot_sha256="ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
source_root="${ATLASO_INVENTORY_BUILD_ROOT:-${script_dir}/.build}"
download_dir="${source_root}/downloads"
build_dir="${source_root}/buildroot-${buildroot_version}"
output_dir="${script_dir}/output"
archive="${download_dir}/buildroot-${buildroot_version}.tar.xz"
git_dir="${repo_root}/.git"
if [[ -f "${git_dir}" ]]; then
  git_dir="$(sed -n 's/^gitdir: //p' "${git_dir}")"
  if [[ "${git_dir}" =~ ^([A-Za-z]):[/\\](.*)$ ]]; then
    git_drive="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
    git_tail="${BASH_REMATCH[2]//\\//}"
    git_dir="/mnt/${git_drive}/${git_tail}"
  elif [[ "${git_dir}" != /* ]]; then
    git_dir="${repo_root}/${git_dir}"
  fi
fi
source_date_epoch="$(git --git-dir="${git_dir}" --work-tree="${repo_root}" log -1 --format=%ct -- image/inventory-linux 2>/dev/null || printf '0')"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-${source_date_epoch}}"

mkdir -p "${download_dir}" "${output_dir}"
if [[ ! -f "${archive}" ]]; then
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "${archive}.part" \
    "https://buildroot.org/downloads/buildroot-${buildroot_version}.tar.xz"
  mv "${archive}.part" "${archive}"
fi
printf '%s  %s\n' "${buildroot_sha256}" "${archive}" | sha256sum --check -

if [[ ! -d "${build_dir}" ]]; then
  tar --extract --xz --file "${archive}" --directory "${source_root}"
fi

make -C "${build_dir}" \
  BR2_EXTERNAL="${script_dir}/external" \
  O="${source_root}/output" \
  atlaso_inventory_x86_64_defconfig
make -C "${build_dir}" \
  BR2_EXTERNAL="${script_dir}/external" \
  O="${source_root}/output" \
  olddefconfig
make -C "${build_dir}" \
  BR2_EXTERNAL="${script_dir}/external" \
  O="${source_root}/output"
for inventory_tool_path in \
  "${source_root}/output/target/usr/bin/lscpu" \
  "${source_root}/output/target/bin/lsblk" \
  "${source_root}/output/target/usr/bin/lspci"; do
  inventory_tool="$(basename "${inventory_tool_path}")"
  if [[ ! -x "${inventory_tool_path}" ]]; then
    printf 'Required util-linux tool is missing: %s\n' "${inventory_tool}" >&2
    exit 1
  fi
  if [[ "$(readlink "${inventory_tool_path}" 2>/dev/null || true)" == *busybox* ]]; then
    printf 'Required util-linux tool resolves to BusyBox: %s\n' "${inventory_tool}" >&2
    exit 1
  fi
done
if [[ ! -s "${source_root}/output/target/usr/share/hwdata/pci.ids" && \
      ! -s "${source_root}/output/target/usr/share/pci.ids" && \
      ! -s "${source_root}/output/target/usr/share/pci.ids.gz" ]]; then
  printf 'Required pci.ids metadata is missing.\n' >&2
  exit 1
fi
make -C "${build_dir}" \
  BR2_EXTERNAL="${script_dir}/external" \
  O="${source_root}/output" \
  legal-info

install -m 0644 "${source_root}/output/images/bzImage" "${output_dir}/bzImage"
install -m 0644 "${source_root}/output/images/rootfs.cpio.gz" "${output_dir}/rootfs.cpio.gz"
mkdir -p "${output_dir}/legal-info"
rsync -a --delete "${source_root}/output/legal-info/" "${output_dir}/legal-info/"

kernel_sha256="$(sha256sum "${output_dir}/bzImage" | awk '{print $1}')"
initrd_sha256="$(sha256sum "${output_dir}/rootfs.cpio.gz" | awk '{print $1}')"
cat >"${output_dir}/manifest.json" <<EOF
{
  "kind": "atlaso-inventory-linux",
  "schema_version": 1,
  "environment": "inventory",
  "version": "${package_version}",
  "architecture": "x86_64",
  "buildroot": {
    "version": "${buildroot_version}",
    "source": "https://buildroot.org/downloads/buildroot-${buildroot_version}.tar.xz",
    "sha256": "${buildroot_sha256}"
  },
  "source_date_epoch": ${SOURCE_DATE_EPOCH},
  "boot": {
    "kernel": "/pxe/media/inventory/${package_version}/bzImage",
    "initrd": "/pxe/media/inventory/${package_version}/rootfs.cpio.gz",
    "arguments": "rdinit=/sbin/init console=tty0 quiet loglevel=3 logo.nologo vt.global_cursor_default=0 vga=791 video=efifb:1024x768 fbcon=font:VGA8x16 atlaso.inventory=1"
  },
  "artifacts": {
    "bzImage": "${kernel_sha256}",
    "rootfs.cpio.gz": "${initrd_sha256}"
  },
  "files": ["bzImage", "rootfs.cpio.gz", "manifest.json"]
}
EOF
