---
title: Physical installation
description: Install Atlaso from the planned signed offline ISO on x86-64 UEFI hardware.
audience:
  - operator
status: roadmap
---

# Physical installation

This guide describes the planned x86-64 physical installation path tracked by
[issue #542](https://github.com/mdaneri/Atlaso/issues/542). The ISO and installer workflow remain in development.
VMware virtual CD/DVD validation has recorded a fresh disconnected blank-disk ISO installation, strict installed-content
verification, and media-free boot. The immutable
[merge `51c7190`](https://github.com/mdaneri/Atlaso/commit/51c719000fa1444a976ab1ddcc47222fd6ccd586) and
[PR #1083](https://github.com/mdaneri/Atlaso/pull/1083) record the completed run; the earlier installation evidence and
corrected service/protocol database defect are retained in [issue #1087](https://github.com/mdaneri/Atlaso/issues/1087).

This virtual CD/DVD evidence does not establish USB-source acceptance, tracked separately in
[issue #1069](https://github.com/mdaneri/Atlaso/issues/1069). Physical SATA/NVMe and wired-Ethernet acceptance, a production
installation ISO release, and the remaining parent #542 acceptance are still pending. This guide does not establish
complete installer acceptance or physical hardware support. See the
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

The first storage screen is **Storage layout**. Review the root target and both service-storage assignments together,
even when only one eligible disk is available. The root begins in Auto on an eligible disk. Press **D** to cycle root
targets, **Tab** to focus the SFTP and VCFDT rows, and **Enter** to continue. Press **L** on the root row to open the
Custom partition editor. On **Storage layout**, **Esc** cancels setup and discards tentative assignments. In the Custom
editor, **Esc** returns to the combined screen.

- **Auto** installs the system to one selected disk using Photon’s default UEFI layout. Assign its root target and
  service storage on the shared **Storage layout** screen.
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

The **Storage layout** screen shows all three assignments together: the root installation target and Auto or Custom
layout, **SFTP backup storage** at `/mnt/atlaso-vcf-backups`, and **VCFDT depot storage** at
`/mnt/atlaso-vcf-offline-depot`. Each row shows its current volume and mount path. Keep an existing compatible partition
or shared storage, assign another compatible Custom partition mounted under `/mnt/`, or choose an unused disk for a
full-disk ext4 data partition. Source media, protected devices, and disks or partitions already assigned elsewhere are
not available for conflicting assignments. If a selection conflicts, correct it on the same screen.

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
   If no Ethernet adapter is detected, the installer stops before Storage layout. Power off and add an adapter
   before restarting.
2. On the first storage screen, **Storage layout**, review and adjust the root target and Auto or Custom layout,
   SFTP backup, and VCFDT depot assignments together before destructive review. Use **D** to cycle root targets,
   **Tab** to focus service rows, and **Enter** to continue. Use **Esc** to cancel setup.
3. Check the displayed disk identities and proposed partitions, then select **Yes** at **Erase selected disks?**
   only when all data on those disks may be erased. The confirmation defaults to **No**; decline if anything is unexpected.
4. Enter and confirm the admin and root passwords on **Account passwords**. All four fields are concealed.
   Use printable ASCII and follow the local-account password policy. Use Tab to move between fields and choose
   **Continue** when both pairs are ready. The screen identifies the account and field that need correction.
   Choose **Go Back** to discard both pairs and return to disk review, where **Yes** is required again.
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
