---
title: Physical installation
description: Install Atlaso from the planned signed offline ISO on x86-64 UEFI hardware.
audience:
  - operator
status: roadmap
---

# Physical installation

This guide describes the planned x86-64 physical installation path tracked by
[issue #542](https://github.com/mdaneri/Atlaso/issues/542). The ISO and installer workflow remain in development. The
supported VMware path has not yet recorded a blank-disk install-ISO boot and installer-console smoke test; native VM
validation and physical acceptance on real SATA or NVMe storage and wired Ethernet remain pending. This guide does not
establish installer acceptance or hardware support. See the
[installation ISO build and verification reference](../reference/installation-iso.md) for the release workflow and
verifier.

## Requirements

- An x86-64 system that boots in UEFI mode.
- Secure Boot disabled for phase one.
- The signed Atlaso installation ISO, written to removable media.
- A separate backup of any data that must survive installation.

The ISO embeds the same signed Atlaso software payload used for software releases, with the pinned
Photon installer, required firmware, and package repository embedded. Installation does not depend on a network
package repository.

## Choose disks and layout

The installer requires you to select installation disks, even when it finds only one eligible disk. Review the disk
identity and proposed layout for every selected disk before confirming.

- **Auto** installs the complete system to one selected disk using Photon’s default UEFI layout. Atlaso, its depot, and
  backups use space on that disk’s root filesystem.
- **Custom** uses Photon’s native partition editor for ext4, xfs, btrfs, and swap partitions. It lets you define a
  layout across multiple disks and place Atlaso paths on separate filesystems when desired. Only the disks you
  explicitly select for the layout are replaced. The boot filesystem must be ext4: use ext4 for `/`, or create a
  separate ext4 `/boot` when `/` uses xfs or btrfs. Root filesystems must be ext4, xfs, or btrfs.

Every selected disk is erased. Disks you do not select, including disks with existing Atlaso labels, must remain
untouched. Do not continue if a disk identity or proposed layout differs from what you intend. Cancel before
confirmation to leave disks unchanged.

The default layout shares root filesystem capacity among the operating system, Atlaso content under `/opt/atlaso`,
depot data under `/mnt/atlaso-vcf-offline-depot`, and backups under `/mnt/atlaso-vcf-backups`. Keep enough free space
for growth. A separate backup is required for recovery: reinstalling does not recover data that was stored only on a
selected installation disk.

Before writing the ISO to removable media, verify the signed release index, every asset checksum, and the reconstructed
ISO with the release-provided verifier. Obtain the public trust key from an independently trusted Atlaso repository
checkout; a key shipped only inside the release assets is not an independent trust anchor. See the
[verification instructions](../reference/installation-iso.md#verify-a-release) for the command. If the ISO is split
into ordered parts, the verifier checks each part and the reconstructed image.

## Install and configure

1. Boot the removable media in UEFI mode with Secure Boot disabled.
2. Select Auto or Custom, choose the disk or disks, and review the complete proposed layout.
3. For each selected disk, type the displayed confirmation `ERASE /dev/...` only after checking its identity and
   confirming that all data on it may be erased. Cancel if anything is unexpected.
4. Enter the administrator and root passwords at the installer’s concealed prompts. Passwords must use ASCII
   characters and meet the existing local-account password policy. The installer must not display or retain these
   values in ordinary logs.
5. Remove the installation media when prompted, then boot the installed system.
6. Use the existing tty1 networking setup on first boot to configure management networking.
7. Verify the management address and host-facing `/openapi.json` endpoint before beginning Atlaso configuration.

The ISO-installed profile records the installed filesystems and does not automatically discover or format additional
data disks during startup. Configure storage only through the supported Atlaso workflows.

## Recovery and platform scope

Keep backups on separate storage and verify that they are readable before installation. If installation fails, power
off before retrying, confirm the intended disk identities again, and reinstall only to explicitly selected disks.
Restore required data from the separate backup after the appliance is available.

Phase one covers x86-64 UEFI with Secure Boot disabled. ARM support is a possible second phase and is not included in
this installation path. Physical SATA/NVMe and wired-Ethernet validation remains outstanding; consult the release notes
for the hardware actually tested before deploying the ISO.
