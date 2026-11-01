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
  validation enabled, or one of the alternatives below. Etcher remains the primary workflow on Windows, macOS,
  and Linux. Platform-specific Atlaso acceptance results must still be recorded for each writer and mode.
- An x86-64 target computer with UEFI firmware, Secure Boot disabled, a supported internal SATA/NVMe disk, and a
  hardware-backed Ethernet adapter. Installation does not require a connected Ethernet cable or Internet access.
  Photon must support the actual USB, storage, and Ethernet controllers.
- Backups of any data on the USB and the internal disks you intend to replace.

Keep the ISO on a different physical device from the USB you are about to overwrite. The image's disk map uses
512-byte logical sectors; use a USB reporting that logical sector size and enough capacity for the complete ISO.

| Host | Primary graphical method | Alternative graphical method | Native command-line method |
| --- | --- | --- | --- |
| Windows | balenaEtcher | Rufus 4.15 in DD mode | — |
| Linux | balenaEtcher | USBImager 1.0.10 with Verify enabled | GNU `dd`, followed by `cmp`. |
| macOS, Intel or Apple Silicon | balenaEtcher | USBImager 1.0.10 with Verify enabled | `diskutil` and BSD `dd`, followed by SHA-256 readback. |

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

## Alternative on Windows: Rufus

Use [Rufus 4.15](https://rufus.ie/en/), the stable version selected for these instructions, in raw **DD Image mode**.
The [Rufus FAQ](https://github.com/pbatard/rufus/wiki/FAQ#list-of-rufus-advanced-features-and-cheat-modes) documents
the **Alt+I** shortcut for disabling ISO extraction and forcing DD writing.

1. In **Device**, select the USB whose physical identity and capacity you checked above.
2. Use **SELECT** to choose the verified, reconstructed Atlaso ISO.
3. Choose **START**. If Rufus offers **ISO Image mode** or **DD Image mode**, select **DD Image mode**.
   To force raw writing, cancel before writing, press **Alt+I** to disable ISO image support, then reselect the image.
   Confirm the log reports ISO support disabled. If raw writing is unavailable or the image is rejected, stop and use
   Etcher; do not fall back to file extraction, bootloader downloads, or a different partition scheme.
4. Recheck the selected device and approve erasing only that USB. Wait for **READY** without errors.
5. Independently compare the written USB with the ISO using the Windows command in
   [USB image layout and readback](../reference/installation-iso.md#usb-image-layout-and-readback).
   **READY** alone is not evidence that every written byte was read back successfully.
6. Safely eject the USB. Cancel any Windows offer to format it.

## Alternative graphical writer on Linux and macOS: USBImager

[USBImager 1.0.10](https://gitlab.com/bztsrc/usbimager#usbimager) is an MIT-licensed raw-image writer. Its project
provides Linux builds and links Intel/Apple Silicon macOS builds. Choose the normal version with **Verify**, rather
than a simplified write-only build. Follow the project's platform installation instructions and normal OS approval
process; keep its default system-disk filtering enabled.

1. Use **...** to select the complete verified Atlaso `.iso`.
2. Select the intended physical USB in the device list, checking its identity and capacity again.
3. Enable **Verify**, then choose **Write** and approve erasing that USB.
4. Wait for writing and comparison to finish without errors, then safely eject the USB.

The project's [writing instructions](https://gitlab.com/bztsrc/usbimager#writing-image-file-to-device) describe
readback comparison. These are candidate Atlaso workflows; native writer and installation acceptance remains pending.

## Native Linux method: GNU dd and cmp

This method uses GNU coreutils, GNU diffutils, and util-linux, commonly supplied by Linux distributions. It writes a
whole device directly. Check the exact physical USB first, unmount every mounted partition shown by `lsblk` with
`sudo umount <exact-mounted-partition>`, and stop if it is a system disk, swap device, or otherwise in use.

Set these values in the same terminal, replacing both placeholders with the verified ISO and inspected whole-disk
identity. A `/dev/disk/by-id/` link ending in `-part1` identifies a partition and must not be used.

```bash
image='/absolute/path/atlaso.iso'
usb='/dev/disk/by-id/<EXACT-USB-ID>'
lsblk --paths --bytes --output PATH,TYPE,TRAN,SIZE,LOG-SEC,MODEL,SERIAL,WWN,MOUNTPOINTS "$usb"
stat -c %s "$image"
```

Compare the image size with the USB capacity, confirm 512-byte logical sectors, and review the USB's physical identity.
Only then run the destructive write and read-only comparison:

```bash
(
  set -eu
  [ -f "$image" ]
  [ -b "$usb" ]
  bytes=$(stat -c %s "$image")
  [ "$bytes" -gt 0 ]
  [ "$((bytes % 512))" -eq 0 ]
  [ "$(lsblk -dn -o TYPE "$usb")" = disk ]
  [ "$(sudo blockdev --getss "$usb")" -eq 512 ]
  [ "$(sudo blockdev --getsize64 "$usb")" -ge "$bytes" ]
  sudo dd if="$image" of="$usb" bs=4M conv=fsync status=progress
  sync
  sudo cmp -n "$bytes" "$image" "$usb"
  printf '%s\n' 'USB image bytes verified; safely eject the USB.'
)
```

`conv=fsync` flushes the write. `cmp` compares exactly the ISO length, so extra USB capacity is ignored; exit status
zero with no difference reported is required. A mismatch, short read, write error, or permission failure stops this
subshell before the success message. Eject through the desktop's safe-removal control before unplugging.
See the [GNU dd manual](https://www.gnu.org/s/coreutils/manual/html_node/dd-invocation.html) and
[GNU cmp options](https://www.gnu.org/software/diffutils/manual/html_node/cmp-Options.html).

## Native macOS method: diskutil and BSD dd

Use the macOS-supplied commands; GNU-specific `status=progress` and `conv=fsync` are not used here. First run
`diskutil list external physical`, then `diskutil info /dev/diskN` for the independently identified USB.
Confirm it is the intended external physical device, has 512-byte logical sectors, and has enough capacity.
Use the whole disk, never a partition such as `/dev/diskNs1`. Close applications using its volumes.

Set the verified ISO and inspected disk in Terminal. `diskN` is a placeholder, not a device selection:

```bash
image='/absolute/path/atlaso.iso'
usb='/dev/diskN'
diskutil info "$usb"
stat -f %z "$image"
```

After reviewing that exact physical identity and capacity, run:

```bash
(
  set -eu
  set -o pipefail
  disk_number=${usb#/dev/disk}
  case "$disk_number" in ''|*[!0-9]*) printf '%s\n' 'Select an inspected whole disk first.' >&2; exit 1 ;; esac
  [ -f "$image" ]
  bytes=$(stat -f %z "$image")
  [ "$bytes" -gt 0 ]
  [ "$((bytes % 512))" -eq 0 ]
  raw_usb="/dev/rdisk${disk_number}"
  expected=$(shasum -a 256 "$image" | awk '{print $1}')
  diskutil unmountDisk "$usb"
  sudo dd if="$image" of="$raw_usb" bs=4m
  sync
  diskutil unmountDisk "$usb"
  actual=$(sudo head -c "$bytes" "$raw_usb" | shasum -a 256 | awk '{print $1}')
  [ "$actual" = "$expected" ]
  printf '%s\n' 'USB image bytes verified.'
  diskutil eject "$usb"
)
```

The raw `/dev/rdiskN` selector uses the same inspected disk number. The readback hashes exactly the image's byte count
and may take several minutes. Errors or a checksum mismatch stop the subshell before success/ejection.
If macOS offers to initialize the written disk, choose **Ignore**. Leave it unmounted until verification finishes.
Apple's [BSD dd manual](https://github.com/apple-oss-distributions/file_cmds/blob/main/dd/dd.1) documents block sizes;
its [head manual](https://github.com/apple-oss-distributions/text_cmds/blob/main/head/head.1) documents bounded reads.
No Homebrew installation, ISO conversion, or Disk Utility erase/restore operation is required.

These command-line and graphical alternatives preserve the same ISO bytes. None establishes Atlaso hardware support
until its exact writer/version, image checksum and native USB boot/install results have been recorded under #1069.

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
