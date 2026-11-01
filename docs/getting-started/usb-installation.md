---
title: Create an Atlaso installation USB
description: Write the Atlaso ISO to a bootable USB on Windows, macOS, or Linux and install onto an internal disk.
audience:
  - operator
status: roadmap
---

# Create an Atlaso installation USB

Use a USB flash drive instead of a CD/DVD drive: write the Atlaso installation ISO to the USB, boot the target
computer from it, and use the existing installer to install Atlaso onto an explicitly selected internal disk.
Remove the USB after installation; Atlaso then runs from the internal disk.

USB acceptance is tracked in [#1069](https://github.com/mdaneri/Atlaso/issues/1069). This procedure is being validated;
it does not yet establish a generally supported hardware installation path. Existing optical-only test images
must be rebuilt with the USB disk layout. A software release alone is not an installation ISO release. Use only an
installation release whose notes explicitly identify a USB-capable image and its verification/acceptance results.

## What you need

- The complete Atlaso installation `.iso`, verified using the
  [installation release verifier](../reference/installation-iso.md#verify-a-release). Reconstruct split release parts
  first. Do not flash a single part, the application wheel, an OVA, or the upstream Photon ISO.
- A USB drive with actual capacity at least equal to the complete ISO's byte length. A 32 GB drive is recommended;
  smaller drives are usable only when the exact image fits. Writing erases the selected USB's contents.
- [balenaEtcher 2.1.9](https://github.com/balena-io/etcher/releases/tag/v2.1.9), using raw image writing with final
  validation enabled. The same workflow applies on Windows, macOS, and Linux. This is the selected writing workflow;
  platform-specific Atlaso acceptance results must still be recorded.
- An x86-64 target computer with UEFI firmware, Secure Boot disabled, a supported internal SATA/NVMe disk, and a
  hardware-backed Ethernet adapter. Installation does not require a connected Ethernet cable or Internet access.
  Photon must support the actual USB, storage, and Ethernet controllers.
- Backups of any data on the USB and the internal disks you intend to replace.

You can prepare the USB on an Apple Silicon Mac; this does not make the installed appliance an ARM image.
ARM targets, legacy BIOS boot, enabling Secure Boot, and permanently running Atlaso from the USB are outside this path.

## Identify the USB before writing

Disconnect other removable storage when practical. Check the drive's model, serial/unique identity, and capacity;
do not choose a drive from its letter, disk number, label, or position alone. Recheck after unplugging or reconnecting
devices, because operating systems can assign a different number.

| Preparation system | Read-only device inventory | What to check |
| --- | --- | --- |
| Windows PowerShell | `Get-Disk \| Select-Object Number,FriendlyName,SerialNumber,UniqueId,BusType,Size,IsBoot,IsSystem` | Match the physical USB; do not choose a system or boot disk. |
| macOS Terminal | `diskutil list external physical`, then `diskutil info /dev/diskN` | Replace `N` with the inspected USB's current whole-disk number; confirm external, physical storage and capacity. |
| Linux terminal | `lsblk --paths --bytes --output PATH,TYPE,TRAN,SIZE,MODEL,SERIAL,WWN,MOUNTPOINTS` | Match the USB's whole disk and its `/dev/disk/by-id/` identity; never choose a partition or the system disk. |

An agent performing the write must obtain the maintainer's selection of that exact physical device before writing.
These instructions do not pre-authorize erasing any connected device.

## Write and validate on Windows, macOS, or Linux

1. Open balenaEtcher. On macOS choose its download for your Mac's Intel or Apple Silicon processor; the ISO remains
   the same x86-64 Atlaso image. On Windows/Linux choose the matching host application.
2. Choose **Flash from file** and select the verified, reconstructed Atlaso `.iso`.
3. Choose **Select target**. Match the USB against the physical identity and capacity you inspected above.
   Select exactly that one USB. Review the destructive warning before continuing.
4. Choose **Flash!** and approve the operating system's requested disk access. Keep final validation enabled.
   Wait for both writing and validation to complete successfully. A write without successful validation is incomplete.
5. Safely eject the USB. On macOS, choose **Ignore** if macOS offers to initialize an unreadable disk after writing.
   On Windows, cancel any offer to format a newly exposed partition. Do not initialize, format, resize, or repair it.

Write the ISO as a raw disk image. Do not copy the `.iso` file onto a formatted USB, extract its files, or select
an ISO/file-copy mode in another writer. The raw image preserves the EFI partition and the signed payload bytes.
It does not need a preformatted FAT32 or NTFS drive. The ISO may exceed FAT32's 4 GiB single-file limit because it is
written directly to the device, rather than stored as a file on FAT32. Its small EFI filesystem contains only boot
assets; the offline payload remains in ISO9660 level 3.

## Boot and install

1. Insert the USB into the target computer. Use its firmware's one-time boot menu and select the **UEFI** USB entry.
   Keep Secure Boot disabled. Start with a directly connected USB port rather than an external hub.
2. Let the installer authenticate its local payload. Missing, corrupt, disconnected, or ambiguous source media must
   stop installation. It must not download replacement installation packages from the network.
3. Follow [Choose disks and layout](physical-installation.md#choose-disks-and-layout). Select the intended internal
   disk or disks and review their identities and complete proposed layout. The source USB and other USB storage are
   excluded from installation targets. Disks you do not select must remain unchanged.
4. At **Erase selected disks?**, confirm **Yes** only for the disks whose contents may be erased. The default is **No**.
   Complete the installer's concealed password prompts. No appliance web UI or separate USB installer is needed.
5. Remove the USB when installation completes, then boot from the installed internal disk.
6. Complete the existing tty1 management-network setup. Verify the installed payload identity and the host-facing
   `/openapi.json` endpoint as described in the [physical installation guide](physical-installation.md).

## If writing or booting fails

Do not install from media that failed validation. Reverify the downloaded installation release, recheck the exact
USB identity, and write the complete image again. Try another suitable USB drive or directly connected port.

If firmware does not list a UEFI USB entry, confirm UEFI mode and Secure Boot settings, then check that the release
actually contains the USB-capable image layout. Renaming an optical-only `.iso` to `.img` does not add USB boot support.
If the installer reports ambiguous media, power off and remove duplicate installer drives before retrying.

If an installation stops after destructive confirmation, the selected internal disks may be partially installed.
Power off, restore backups if required, and review the exact disks again before reinstalling. Keep the source and all
unselected disks unchanged. Report the ISO checksum, hardware/controller identities, writer/version and observed failure;
do not include account passwords or other secrets.

VM USB-controller results and physical USB 2/3, SATA/NVMe results are separate acceptance evidence. Neither a successful
writer validation nor a virtual CD/DVD boot proves physical USB installation compatibility.
