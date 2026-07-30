---
title: Atlaso Inventory Linux build
description: Build the reproducible read-only x86-64 Network Boot inventory environment.
audience:
  - contributor
  - maintainer
status: current
---

# Atlaso Inventory Linux build

Atlaso Inventory Linux is the safe default Network Boot environment for unknown
hardware. It is a Buildroot initramfs that runs entirely from RAM, does not
mount target filesystems, and submits one bounded inventory report before
waiting for a local or audited remote reboot request.

Package revision `2026.05.1+1` pins Buildroot 2026.05.1 by SHA-256. The suffix
advances independently when Atlaso changes the inventory client without
changing the upstream Buildroot base. Run on Linux:

```bash
./image/inventory-linux/build.sh
```

On Debian or Ubuntu, install the Buildroot host prerequisites first:

```bash
sudo apt-get install build-essential bison flex cpio rsync bc file wget curl \
  git perl python3 unzip patch gzip bzip2 xz-utils ca-certificates libelf-dev
```

The script writes `bzImage`, `rootfs.cpio.gz`, `manifest.json`, and Buildroot
legal metadata beneath `image/inventory-linux/output/`. The output directory is
intentionally ignored. Package the verified result with:

```bash
python scripts/build_inventory_linux_package.py
```

This creates the deterministic, independently versioned
`dist/inventory-linux/atlaso-inventory-linux-<version>.zip` release asset. Full
appliance images preinstall its runtime files; Atlaso releases publish the same
package so Network Boot can download or upload Inventory Linux updates without
coupling them to the Python wheel version.

The kernel fragment enables common server Ethernet, NVMe, SATA, SCSI, RAID, and
virtio drivers. The userspace collector reads DMI, CPU, memory, block-device,
and interface metadata only. It never invokes a filesystem mount, partition,
format, wipe, or block-write command.

## Included upstream components

Buildroot fetches and verifies its package sources using the hashes shipped in
the pinned Buildroot release. The principal runtime components are:

| Component | Version | License | Source |
| --- | --- | --- | --- |
| Buildroot build system | 2026.05.1 | GPL-2.0-or-later | `https://buildroot.org/downloads/buildroot-2026.05.1.tar.xz` |
| Linux kernel | 7.0.11 | GPL-2.0-only | `https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.0.11.tar.xz` |
| BusyBox | 1.38.0 | GPL-2.0-only | `https://busybox.net/downloads/busybox-1.38.0.tar.bz2` |
| musl libc | 1.2.6 | MIT | `https://musl.libc.org/releases/musl-1.2.6.tar.gz` |
| curl/libcurl | 8.21.0 | curl | `https://curl.se/download/curl-8.21.0.tar.xz` |
| jq | 1.8.2 | MIT | `https://github.com/jqlang/jq/releases/tag/jq-1.8.2` |
| util-linux | 2.41.5 | GPL-2.0-or-later and LGPL-2.1-or-later | `https://www.kernel.org/pub/linux/utils/util-linux/v2.41/` |
| dmidecode | 3.7 | GPL-2.0-or-later | `https://download.savannah.gnu.org/releases/dmidecode/` |
| ethtool | 7.0 | GPL-2.0-only | `https://www.kernel.org/pub/software/network/ethtool/` |

The generated Buildroot `legal-info` output is the authoritative machine-built
license/source inventory for a release image. Keep it with release build
artifacts when distributing the inventory binaries.
