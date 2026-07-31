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

Its built-in compatibility profile covers common physical NIC, HBA, RAID,
NVMe, and SATA families used by ESXi-capable x86-64 hosts, plus VMware,
Hyper-V, KVM/Proxmox/QEMU, Xen, and common emulated virtual devices. Selected
redistributable firmware is included for driver families that require it.
Exact hardware support still depends on the upstream Linux driver and firmware
available for the device; the ESXi hardware compatibility list is a separate
vendor certification matrix.

Package revision `2026.05.1+8` pins Buildroot 2026.05.1 by SHA-256. The suffix
advances independently when Atlaso changes the inventory client without
changing the upstream Buildroot base. Revision `+5` selects Buildroot's
util-linux basic binary set so collection uses full `lscpu --json` and
`lsblk --json` implementations instead of BusyBox's limited `lsblk` applet;
revision `+7` ignores optional current or permanent interface addresses that
are not six-octet Ethernet MACs. Revision `+8` introduces report schema v2,
sysfs-first complete device collection, PCI-readable names, and the paged local
console with its suspendable reboot countdown.
Run on Linux:

```bash
./image/inventory-linux/build.sh
```

The shared Windows Photon image wrappers build Inventory Linux through WSL.
They give Buildroot a Linux-only `PATH` for that child process because WSL's
default Windows path import can contain spaces that Buildroot rejects. The
wrappers also keep Buildroot's cache and work tree beneath the WSL user's native
Linux cache directory because a Windows-mounted, case-insensitive work tree can
corrupt host-package configuration. Final artifacts still land in the output
directory documented below. A per-repository lock serializes concurrent Windows
build requests that share this cache. This does not change the caller's Windows
`PATH` or global WSL configuration.

Atlaso's `.gitattributes` keeps Bash and PowerShell sources at LF in every
checkout, including Windows clones with Git's automatic line-ending conversion
enabled. If Bash reports an invalid `pipefail` option before the build starts,
verify the working-tree format from PowerShell:

```powershell
git ls-files --eol -- image/inventory-linux/build.sh
```

The result must report `w/lf`. After pulling the line-ending policy, restore an
older checkout that reports `w/crlf` with:

```powershell
git restore --source=HEAD --worktree -- image/inventory-linux/build.sh
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

The iPXE menu passes the PXE adapter MAC address to Inventory Linux. At startup,
the utility requests DHCP on that adapter first and falls back across the
remaining non-loopback adapters until one receives a default route. This keeps
multi-NIC hosts on the network they used to PXE boot.

If live clients temporarily occupy the bounded inventory-report store, the API
returns a retryable response and the client retries with bounded backoff for up
to 30 seconds. Other report errors remain terminal and never expose the session
token or response body.

The kernel fragment enables common server Ethernet, NVMe, SATA, SCSI, RAID,
VMware PVSCSI and legacy LSI Fusion, and virtio drivers. The userspace collector
uses sysfs as the authoritative device
source and emits bounded structured JSON for CPU topology, populated DIMMs,
every NIC and disk, storage controllers, PCI and USB devices, and
system/BIOS/baseboard/chassis identity. `pciutils` and its `pci.ids` data add
readable PCI names only; raw command output is never submitted. The collector
never invokes a filesystem mount, partition, format, wipe, or block-write
command.

The accepted report remains at most 256 KiB. Schema v2 bounds reports to 64
NICs, 128 disks, 64 storage controllers, 256 populated DIMMs, 512 PCI devices,
and 256 USB devices. Atlaso continues to accept schema v1 and normalizes it to
the retained v2 JSON shape in the existing report column.

After a report is accepted, the local console opens full-screen Atlaso-style
System/CPU/DIMMs, Network, and Storage pages. Use `N`/`P` or `1`-`3` to move
between pages. On lists larger than the fixed console viewport, use `J`/`K` to
move through bounded list windows; network windows show at most five adapters
and clip individual rows to the console width. Countdown updates repaint only
the fixed action footer so the hardware pages remain stable without full-screen
flicker. The 120-second reboot countdown starts only after successful
submission; navigation time still advances the countdown, `S` pauses or
resumes the remaining time, and `R` reboots immediately. An acknowledged
audited remote reboot remains authoritative.

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
| pciutils | 3.15.0 | GPL-2.0-or-later | `https://mj.ucw.cz/sw/pciutils/` |

The generated Buildroot `legal-info` output is the authoritative machine-built
license/source inventory for a release image. Keep it with release build
artifacts when distributing the inventory binaries.
