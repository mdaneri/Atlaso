---
title: Windows image-build WSL environment
description: Provision, select, update, recover, and remove the isolated WSL host used by Atlaso image builds.
audience:
  - contributor
  - maintainer
status: current
---

# Windows image-build WSL environment

Atlaso's Windows image wrappers build Inventory Linux inside an explicitly selected WSL distribution. The supported
default is the disposable `Atlaso-Build` distribution. This isolates Buildroot host packages and native-Linux build
storage from a contributor's general-purpose distribution.

## Prerequisite and safety boundary

Install and initialize WSL 2 before using the Atlaso setup command. Atlaso does not enable Windows features, run
`wsl --install`, elevate, accept licenses, or reboot Windows. An unavailable or incomplete WSL installation stops with
an error before Atlaso downloads or imports a distribution.

Ordinary Inventory Linux and Photon build commands never create, update, remove, or change the default WSL
distribution. If their selected distribution is missing, they print the explicit setup command and stop.

## Provision Atlaso-Build

From the repository root in PowerShell 7, run:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/common/Initialize-AtlasoBuildWslDistribution.ps1
```

The command:

1. Confirms that WSL is already functional.
2. Downloads the Ubuntu Base archive pinned in `image/inventory-linux/wsl-build-contract.json`, unless the verified
   archive is already in the user-local download cache.
3. Verifies the compressed archive's SHA-256 digest, expands it to a temporary tar archive, imports that tar as WSL 2
   under `%LOCALAPPDATA%\Atlaso\WSL\Atlaso-Build`, and removes the temporary tar.
4. Installs the recorded Buildroot host-package contract and creates the non-root `atlaso-build` user.
5. Records the base digest, contract version, build user, and installed package versions under
   `/var/lib/atlaso-build`.
6. Restores the previous default WSL distribution if the import changed it.

Rerunning the command is supported. It recognizes only an Atlaso-owned distribution with the expected base-image
marker, then reapplies the package contract and readiness checks. It does not modify an unrelated distribution that
happens to use the `Atlaso-Build` name. A failed provisioning run preserves an already imported, Atlaso-owned
distribution so the command can be rerun after the reported package or network problem is corrected.

Use `-BaseImagePath <path>` to supply the exact pinned archive from an approved mirror or offline transfer. Use
`-InstallLocation <path>` only when the default user-local WSL storage location is unsuitable.

## Build with the selected distribution

The Inventory Linux wrapper selects `Atlaso-Build` by default. Photon wrappers do not build or embed Inventory Linux:

```powershell
pwsh -File scripts/windows/common/Build-AtlasoInventoryLinux.ps1
```

To use an existing compatible distribution without provisioning `Atlaso-Build`, pass its registered WSL name to the
same entry point:

```powershell
pwsh -File scripts/windows/common/Build-AtlasoInventoryLinux.ps1 `
  -WslDistribution Ubuntu-24.04
```

Atlaso uses that one distribution for path conversion, prerequisite checks, cache discovery, locking, and build
execution. A user-selected distribution must
provide the commands listed in `wsl-build-contract.json`, run builds as a non-root default user, and provide
case-sensitive native Linux storage. Atlaso validates it but does not install packages into it.

## Storage and concurrency

Buildroot downloads and mutable work trees stay in the selected Linux filesystem under:

```text
${XDG_CACHE_HOME:-$HOME/.cache}/atlaso/inventory-linux/<repository-key>
```

The repository key is derived from the Windows repository path. Different WSL distributions have separate filesystems,
and different repository paths receive separate work trees. A `flock` file next to each work tree serializes concurrent
builds for the same repository and distribution. A checkout-keyed Windows mutex also serializes the complete build and
final-output verification across different selected distributions that target the same checkout. The Linux-only child
`PATH` excludes imported Windows paths.

Final verified `bzImage`, `rootfs.cpio.gz`, `manifest.json`, and `legal-info` output still lands under
`image/inventory-linux/output` in the selected repository checkout. The Inventory Linux build probes that final output
filesystem before copying artifacts. Native Linux filesystems retain normalized artifact modes and source legal-info
metadata; Windows DrvFS output uses byte-exact file copies and recursive legal-info synchronization without requesting
unsupported POSIX modes or timestamps. The wrapper does not change WSL mount configuration to publish those files.

## Update, export, restore, or recreate

After pulling a change to `wsl-build-contract.json`, rerun the setup command. A package-contract change is applied in
place and its resolved package versions are recorded. A pinned base-image change requires deliberate recreation;
Atlaso will not replace or unregister the old distribution automatically.

Before recreation, export anything that must be retained:

```powershell
wsl --terminate Atlaso-Build
wsl --export Atlaso-Build C:\Backups\Atlaso-Build.tar
```

To restore that export later under the managed name, first confirm that no distribution with that name is registered,
then run:

```powershell
wsl --import Atlaso-Build C:\WSL\Atlaso-Build-Restored C:\Backups\Atlaso-Build.tar --version 2
```

The exported distribution retains its Atlaso ownership and contract markers. Rerun the setup command after import to
validate and refresh the package contract. Confirm the user's preferred default with `wsl --list --verbose`; set it
explicitly with `wsl --set-default <name>` if a manual import changed it.

To discard and recreate the dedicated environment, export it if needed, then explicitly remove and reprovision it:

```powershell
wsl --terminate Atlaso-Build
wsl --unregister Atlaso-Build
pwsh -File scripts/windows/common/Initialize-AtlasoBuildWslDistribution.ps1
```

`wsl --unregister` permanently deletes that distribution's Linux filesystem. The setup and build wrappers never run
that command.

## Troubleshoot

- **WSL required or incomplete:** install or repair WSL separately, confirm `wsl --status` and `wsl --list --verbose`
  succeed, then retry. Atlaso will not change Windows to fix WSL.
- **No Linux distributions:** run the explicit Atlaso setup command. It works when WSL is available even if the list is
  empty.
- **Requested distribution missing:** check the exact registered name with `wsl --list --verbose`, correct
  `-WslDistribution`, or provision `Atlaso-Build`.
- **Distribution stuck:** run `wsl --terminate <name>`, then retry. Do not unregister it unless deliberate recreation is
  intended.
- **Missing host command:** rerun Atlaso setup for `Atlaso-Build`. For another distribution, install the documented
  prerequisites yourself and rerun the build.
- **Contract or base mismatch:** rerun setup for a contract-only change. Export and recreate the distribution for a
  pinned base mismatch.
- **Invalid build storage:** clear a whitespace-bearing `XDG_CACHE_HOME` override and use case-sensitive storage inside
  the Linux filesystem, not `/mnt/c`.
- **Final-output permission failure:** pull a revision with DrvFS-aware final artifact copying, remove any output from the
  failed run, and retry. Do not package a directory left by `install: setting permissions ... Operation not permitted`;
  the kernel might be new while the initramfs and manifest are older.

Distribution selection does not replace output verification. A successful release build must still validate manifest
digests for `bzImage` and `rootfs.cpio.gz` and retain Buildroot legal metadata.
