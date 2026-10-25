---
title: Offline installation ISO build and verification
description: Prepare, verify, and release the planned signed Atlaso installation ISO.
audience:
  - contributor
  - maintainer
status: roadmap
---

# Offline installation ISO build and verification

This reference records the build and release path for
[issue #542](https://github.com/mdaneri/Atlaso/issues/542). A development ISO completed a disconnected Auto
installation in VMware at source commit
`960621fdd0e6c1babcc707e2ca0ca2896539876e`; reboot and installed-system acceptance remain in progress. Physical
SATA/NVMe and wired-Ethernet acceptance remains outstanding. This VM result does not establish physical-platform
support or complete issue acceptance.

The installation image reuses the pinned Photon 5.0 ISO and Photon installer 2.2. Remastering preserves the source EFI
boot image and native installer flow. The Atlaso deployment source comes from an immutable Git archive at the
selected full commit. The signed software release, its exact application wheel, locked CPython wheelhouse, shared
provisioning inputs, PowerCLI modules, trust material, notices, firmware, and a signed offline Photon RPM repository
are embedded and inventoried. Dependency closure is resolved during authorized ISO preparation; installation does
not use network package repositories. The boot package selection includes Photon’s native `initramfs` package and
its resolved dependencies. Installation requires the kernel and initrd selected by Photon’s GRUB environment to
exist before applying chosen credentials or reporting completion.

The shared boot-branding installer handles both native Photon kernel paths. The root-only Auto layout uses
`/boot/$photon_linux` and points GRUB at `/boot/grub2/themes/atlaso/theme.txt`; a Custom layout with a separate `/boot`
uses `/$photon_linux` and `/grub2/themes/atlaso/theme.txt`. Theme files remain under `/boot/grub2/themes/atlaso` in
both layouts. Custom layouts must use ext4 for the boot filesystem; see [Choose disks and layout](../getting-started/physical-installation.md#choose-disks-and-layout).

Use the existing VMware build and lifecycle process for admitted Photon builders and VM validation. Do not create a
parallel Hyper-V or KVM image pipeline. Capture RPM dependencies during preparation on the authorized Photon builder;
do not restart or repurpose a consumed template to produce capture inputs. `capture-rpms` requires an absent absolute
output directory. Task workspaces, temporary content, and validation output must stay under a configured permitted
root. Receipt resource ownership and source/task identity before creating disposable roots, as required by the
[completed-task cleanup policy](../contribute/completed-task-cleanup.md). Keep release signing inside the protected
hosted workflow.

## Prepare inputs

Use the full source commit and exact software version being prepared. Select an absent destination for each newly
created output. Begin from authorized builder preparation state and capture the resolved, signed Photon RPM closure
and required firmware:

```text
python scripts/build_installation_iso.py capture-rpms --output <absent-absolute-directory>
```

Prepare the candidate from that closure, the exact signed software payload, and the PowerCLI modules accepted by the
existing `Validate` mode of `image/common/powershell/provision-powercli.ps1`:

```text
python scripts/build_installation_iso.py prepare --commit <FULL-SOURCE-SHA> --version <X.Y.Z> --payload <absent-directory> --software <verified-software-directory> --rpms <captured-rpm-directory> --powercli <validated-powercli-directory>
```

The preparation stage binds the source files to the selected commit and records the software, RPM, firmware, and
PowerCLI inventories. Keep its unsigned candidate in the private task workspace; it is not a release artifact. For
controlled transfer, package the candidate and split oversized input archives into an existing empty destination
directory:

```text
python scripts/build_installation_iso.py pack-inputs --payload <candidate-directory> --output <absent-archive.tar.gz>
python scripts/build_installation_iso.py split-inputs --archive <input-archive.tar.gz> --output <existing-empty-directory>
```

Input packaging does not grant signing authority. The protected `installation-prerelease.yml` workflow independently
validates the candidate, signs it, assembles the ISO, and stages the signed installation assets in the existing hidden
`installation-vX.Y.Z-rc.N` draft. This staging run leaves the release as a draft. Installation artifacts remain
separate from software-update and virtualization release assets. The signed release index covers the ISO manifest
and assets; phase one requires Secure Boot disabled. ARM support is a possible second phase and is not included in
the x86-64 release contract.

## Development-only VMware test image

The existing PR builder accepts `-CaptureInstallationRpms` to download the resolved Photon RPM closure and installed
PowerCLI modules alongside its output. This option is rejected for release builders. Capture staging uses `/var/tmp`
so it does not consume the guest's `/tmp` memory filesystem during shared provisioning. Independently validate all
captured inputs before assembly; capturing files alone does not establish a successful appliance build.

PowerCLI input can also be prepared with the existing locked module installer in a receipted task directory:

```powershell
pwsh -NoProfile -File image/common/powershell/provision-powercli.ps1 `
  -Mode Install -ModuleRoot <TASK-OWNED-POWERCLI-DIRECTORY>
```

For installer work on a pull-request commit, use the explicit development builder. It requires a clean checkout at the
exact PR `HEAD`; the separately supplied software directory must be a signed main release, with its version and
main-reachable source commit passed independently. Reuse the already captured Photon RPM directory, validated
PowerCLI modules, pinned Photon 5.0 source ISO, and verified software release. Put all paths under the configured,
receipted task roots, and select absent payload and ISO destinations plus an existing empty private scratch directory:

```powershell
python scripts/build_development_installation_iso.py `
  --commit <PR-HEAD-SHA> `
  --software-version <MAIN-RELEASE-VERSION> `
  --software-commit <MAIN-RELEASE-SHA> `
  --software <VERIFIED-MAIN-RELEASE-DIRECTORY> `
  --rpms <CAPTURED-PHOTON-RPM-DIRECTORY> `
  --powercli <VALIDATED-POWERCLI-DIRECTORY> `
  --payload <ABSENT-DEVELOPMENT-PAYLOAD-DIRECTORY> `
  --scratch <EXISTING-EMPTY-PRIVATE-DIRECTORY> `
  --source-iso <PINNED-PHOTON-5.0-ISO> `
  --output <ABSENT-DEVELOPMENT-ISO-PATH>
```

This builder uses the distinct `atlaso-installation-development-public-test` key identity. Its deterministic Ed25519
fixture seed is public test data (`bytes(range(32))`, bytes `00` through `1f`); it is not a credential or release
authority and is never stored as a secret. The production signer and default production verifier continue to require
the production key identity. Production finalization runs only from `main`, uses its checked-out workflow tools, and
retains the protected signing environment and main-release admission checks. The development initrd accepts the test
identity only when its explicit development
marker is present. The resulting image is for VMware testing only: it uses the serial installer console on `ttyS0`,
is not publishable as an Atlaso release, and does not establish production or physical-hardware acceptance.

Boot-time signature verification reuses the `cryptography` package already included in the pinned Photon initrd;
that initrd removes the OpenSSL command-line executable. The downloadable verifier retains its existing OpenSSL path.

RPM repository generation explicitly uses gzip metadata so the pinned Photon initrd can read it, regardless of the
build host’s default compression format. Repository configuration uses UTF-8 with LF line endings for Photon TDNF.

The VMware harness creates an isolated EFI VM with no network adapters, two blank SCSI disks, and a private serial
console. Its VMX configuration uses UTF-8 to preserve non-ASCII worktree, ISO, and output paths.
Hash the generated ISO and use the exact owning pull request number. `Probe` checks that the native Photon disk
selection screen appears, and `Cancel` checks cancellation before disk writes. `Auto` exercises the single-disk Auto
installation path. Reboot, persistence, and Appliance Update checks remain separate follow-up tests:

```powershell
$isoSha256 = (Get-FileHash -LiteralPath <DEVELOPMENT-ISO-PATH> -Algorithm SHA256).Hash.ToLowerInvariant()
.\scripts\windows\vmware\invoke-installation-iso-test.ps1 `
  -IsoPath <DEVELOPMENT-ISO-PATH> `
  -IsoSha256 $isoSha256 `
  -OutputDirectory <ABSENT-VM-OUTPUT-DIRECTORY> `
  -PullRequestNumber <OWNING-PR-NUMBER> `
  -Scenario Probe
```

Run `-Scenario Cancel` and `-Scenario Auto` in separate receipt-bound VM roots, following the VMware lifecycle
procedure for each. `Auto` obtains administrator and root credentials through the existing supported Atlaso
credential bridge and sends them only to concealed installer prompts; do not put passwords in command lines or logs.
`CancelReview` selects the target but cancels at the planned-layout review before erasure consent. `Insufficient`
selects the fixture's four-GiB disk and requires the exact capacity refusal for that disk before consent. Both
scenarios use no credentials and compare both disks with their pre-boot baselines after stopping the VM.
Creation records a separate disk-baseline receipt before first boot. Retain both original receipt paths and their
creation-time hashes from the console driver's ownership output. The console runner automatically verifies disks
within its process deadline. To repeat verification afterward:

```powershell
.\scripts\windows\vmware\test-installation-iso.ps1 -Mode Verify `
  -OutputDirectory <EXACT-VM-OUTPUT-DIRECTORY> -PullRequestNumber <OWNING-PR-NUMBER> `
  -OriginalReceiptPath <ORIGINAL-RECEIPT> -OriginalReceiptSha256 <ORIGINAL-RECEIPT-SHA256> `
  -BaselineReceiptPath <BASELINE-RECEIPT> -BaselineReceiptSha256 <BASELINE-RECEIPT-SHA256>
```

Use `-Scenario AutoReboot` in a fresh VM root to install, stop, disconnect the installation CD drive, and boot the
installed system. This development image enables the standard password-protected `serial-getty@ttyS0` service only
after verifying the development signing identity, non-production marker, and VMware platform. It also invokes the
shared boot-branding helper's explicit development option to add GRUB serial output and the `ttyS0` kernel console.
Production images keep their existing boot console and do not enable this test login service. The runner rechecks
its private pipe peer before sending either chosen password
to ordinary Linux login; it records only fixed success checkpoints, never the console stream.

The `BootInstalled` harness mode reuses original VM and disk-baseline admission, stopped-provider checks, logical
disk comparison, and source pins. It requires the original isolated EFI device configuration, publishes an immutable
`installation-boot` transition receipt before editing the VMX through its retained writer, disables only the existing
CD drive, verifies readback, and starts the same VM. It preserves disk paths, network isolation, cleanup identity,
and private serial endpoint. Retain the reported transition path and creation-time SHA-256 alongside the original
selectors. After this transition, repeat `-Mode Verify` with `-BootReceiptPath` and `-BootReceiptSha256` as well as
the original and baseline selectors. Verification refuses disconnected media without the bound transition receipt.
On interruption, preserve the VM and receipts; do not recreate the VM, reconnect media, or reconstruct ownership
from current files. A partially written or ambiguous configuration requires maintainer recovery.

Verification stops only the identity-checked VM, preserves its artifacts, and compares the unselected disk with its
pre-boot baseline using `qemu-img compare`. Add `-VerifyTarget` after cancellation to compare the target disk too.
The development `Probe` and `Cancel` scenarios passed earlier. A disconnected `Auto` installation also completed in
the receipt-bound VM for source commit `960621fdd0e6c1babcc707e2ca0ca2896539876e`. After stopping the VM,
receipt-bound verification confirmed the unselected disk's logical contents matched its pre-boot baseline. Reboot with
the installation media removed, login with the chosen installed credentials, fresh machine identities, payload
equality, the host-facing `/openapi.json`, Appliance Update success and rollback persistence, and physical acceptance
remain outstanding. A serial-enabled boot attempt exposed a missing initramfs package. After adding its resolved RPM
closure, the corrected development image completed disconnected installation and booted without media through systemd
to the root login/password prompts. Shell-identity verification timed out, so installed-credential acceptance remains
open. The receipt-bound post-reboot comparison confirmed the unselected disk was unchanged. The console runner accepts
Photon's root prompt with or without a hostname and still requires a separate account-identity challenge.
The capacity-refusal and planned-layout cancellation scenarios passed with both fixture disks unchanged.
Do not infer reboot or persistence results from a completed installation run.

Publication is a separate, explicit workflow dispatch after the exact ISO has been validated. The maintainer supplies
`publish=true` and `validated_iso_sha256` for the ISO whose disconnected UEFI installation, reboot, Appliance Update
success and rollback persistence, and unselected-disk preservation were tested. The workflow requires that checksum
to match the signed draft index before publishing, then downloads and verifies the published assets again. The
development ISO has completed its disconnected Auto installation and the unselected-disk comparison. Reboot,
installed-credential login, and Appliance Update checks have not yet been recorded, so this result does not establish
full installer acceptance or authorize publication. Do not publish or describe the installer as validated before the
remaining acceptance evidence exists.

## Verify a release

Get the public verification key from an independently trusted Atlaso repository checkout. Do not trust a copy of the
key obtained only from the release assets being verified. Use Python 3.11 or newer with OpenSSL available. The
verifier first checks the signed installation artifact index against the selected version and full source commit,
then checks each asset’s size and SHA-256 checksum. When the ISO is split, it verifies every ordered part and the
reconstructed ISO.

From a source checkout, run:

```text
python scripts/verify_installation_iso.py --assets <release-assets-directory> --trust-key image/common/update-trust/atlaso-release-2026-01.pem --version <X.Y.Z> --commit <FULL-SOURCE-SHA> --scratch <existing-private-directory> [--output <absent-iso-path>]
```

The release also contains `verify-installation.pyz`, which accepts the same options and requires Python 3.11 or newer
and OpenSSL. For example:

```text
python verify-installation.pyz --assets <release-assets-directory> --trust-key <independently-trusted-public-key.pem> --version <X.Y.Z> --commit <FULL-SOURCE-SHA> --scratch <existing-private-directory> [--output <absent-iso-path>]
```

`--scratch` must name an existing private directory. Omit `--output` to verify assets without reconstruction; when
requested, the ISO destination must be absent. Compare the reported version and source commit with the release you
intended to use before writing the verified ISO to removable media.

## Acceptance status

The generated release index reports physical hardware acceptance as pending until SATA/NVMe and wired-Ethernet results
are recorded. Native VM evidence alone does not establish physical support or complete issue #542. The development
VMware path supports receipt-bound blank-disk ISO and installer-console tests. Probe, Cancel, and one disconnected
Auto installation have passed; reboot, installed-credential login, and the disconnected update/rollback scenarios
remain outstanding. Do not describe the installer as validated or claim physical support while these gates are
outstanding. Secure Boot is disabled for phase one; this reference makes no Secure Boot or ARM support claim.

For disk selection, concealed initial credentials, first-boot networking, and recovery guidance, see
[Physical installation](../getting-started/physical-installation.md).
