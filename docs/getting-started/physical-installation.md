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
- At least one hardware-backed Ethernet adapter; an active link or Internet connection is not required to install.
- The signed Atlaso installation ISO, written to removable media.
- A separate backup of any data that must survive installation.

The ISO embeds the same signed Atlaso software payload used for software releases, with the pinned
Photon installer, required firmware, and package repository embedded. Installation does not depend on a network
package repository.

For a computer without a CD/DVD drive, follow
[Create an Atlaso installation USB](usb-installation.md) for Windows, macOS, or Linux writing and verification steps,
then continue with disk selection below. Use only an installation release with recorded USB acceptance.

## Choose disks and layout

The installer requires you to select installation disks, even when it finds only one eligible disk. Review the disk
identity and proposed layout for every selected disk before confirming.

- **Auto** installs the system to one selected disk using Photon’s default UEFI layout. The following service-storage
  screens let you keep shared storage or explicitly select separate disks for SFTP backups and the VCFDT depot.
- **Custom** uses Photon’s native partition editor for ext4, xfs, btrfs, and swap partitions. It lets you define a
  layout across multiple disks and place Atlaso paths on separate filesystems when desired. Only the disks you
  explicitly select for the layout are replaced. The boot filesystem must be ext4: use ext4 for `/`, or create a
  separate ext4 `/boot` when `/` uses xfs or btrfs. Root filesystems must be ext4, xfs, or btrfs.
  Mount points must not contain whitespace or backslashes: Photon's native `fstab` writer cannot escape those fields.
  Keep GRUB and kernel files on `/` or the supported separate `/boot`; nested mounts such as `/boot/grub2` are refused.
  Photon creates its own `/boot/efi` partition; do not create that mount or any of its descendants in Custom.
  You can mount `/opt/atlaso` on a system-content partition. Atlaso-owned symlinks, including `/opt/atlaso/current`
  and `/opt/atlaso/.venv`, and paths beneath them cannot be partition mount points; the editor reports **Atlaso symlink**.
  The installed layout supports 32 mounted filesystems, including Photon’s generated EFI partition. Custom therefore
  permits at most 31 operator-selected mounts and reports **31 mounts + EFI** at the limit. Swap does not consume a mount.

Both flows finish with **SFTP backup storage** and **VCFDT depot storage** choices. The default preserves an existing
service partition or keeps shared storage. You can assign a compatible Custom partition currently mounted under
`/mnt/`, or select an unused disk to create a full-disk ext4 data partition. The fixed service paths are
`/mnt/atlaso-vcf-backups` and `/mnt/atlaso-vcf-offline-depot`. A disk already used by the layout is never offered as a
whole-disk replacement. **Go Back** returns through the storage choices without committing tentative assignments.

For example, select the 64 GiB OS disk with Auto, the intended 500 GiB Backups disk for SFTP, and the other 500 GiB
disk for VCFDT. Review the actual disk identities; equal sizes do not identify their roles. A fourth 20 GiB disk stays
untouched unless you explicitly assign it in Custom, for example as `/opt/atlaso` for the application files.

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
   If no Ethernet adapter is detected, power off and add one before continuing; the installer stops before disk selection.
2. Select Auto or Custom, choose the disk or disks, assign service storage, and review the complete proposed layout.
3. Check the displayed disk identities and proposed partitions, then select **Yes** at **Erase selected disks?**
   only when all data on those disks may be erased. The confirmation defaults to **No**; decline if anything is unexpected.
4. Enter the administrator and root passwords at the installer’s concealed prompts. Passwords must use ASCII
   characters and meet the existing local-account password policy. The installer must not display or retain these
   values in ordinary logs. If a confirmation does not match, correct it in the same prompt; installation does not restart.
   **Go Back** from Custom returns to disk/layout selection. From the first admin password field it returns to disk
   review and requires another **Yes**; from the first root password field it returns to admin password entry.
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
