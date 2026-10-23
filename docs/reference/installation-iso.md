---
title: Offline installation ISO build and verification
description: Prepare, verify, and release the planned signed Atlaso installation ISO.
audience:
  - contributor
  - maintainer
status: roadmap
---

# Offline installation ISO build and verification

This reference records the planned build and release path for
[issue #542](https://github.com/mdaneri/Atlaso/issues/542). ISO assembly and native VM acceptance are still in
progress. Physical SATA/NVMe and wired-Ethernet acceptance remains outstanding. The steps below do not establish that
an ISO, VM installation, or physical platform has passed acceptance.

The installation image reuses the pinned Photon 5.0 ISO and Photon installer 2.2. Remastering preserves the source EFI
boot image and native installer flow. The Atlaso deployment source comes from an immutable Git archive at the
selected full commit. The signed software release, its exact application wheel, locked CPython wheelhouse, shared
provisioning inputs, PowerCLI modules, trust material, notices, firmware, and a signed offline Photon RPM repository
are embedded and inventoried. Dependency closure is resolved during authorized ISO preparation; installation does
not use network package repositories.

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

Publication is a separate, explicit workflow dispatch after the exact ISO has been validated. The maintainer supplies
`publish=true` and `validated_iso_sha256` for the ISO whose disconnected UEFI installation, reboot, Appliance Update
success and rollback persistence, and unselected-disk preservation were tested. The workflow requires that checksum
to match the signed draft index before publishing, then downloads and verifies the published assets again. The required
blank-install-ISO and installer-console VMware smoke test has not yet been recorded, so no ISO checksum currently
establishes installer acceptance. Do not publish or describe the installer as validated before the acceptance
evidence exists.

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
are recorded. Native VM evidence alone does not establish physical support or complete issue #542. The supported
VMware path still lacks a blank-disk install-ISO boot and installer-console smoke test; native installer acceptance
and the disconnected installation/update/rollback scenarios remain outstanding. Do not describe the installer as
validated or claim physical support while these gates are outstanding. Secure Boot is disabled for phase one; this
reference makes no Secure Boot or ARM support claim.

For disk selection, concealed initial credentials, first-boot networking, and recovery guidance, see
[Physical installation](../getting-started/physical-installation.md).
