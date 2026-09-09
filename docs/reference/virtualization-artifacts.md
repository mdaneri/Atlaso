---
title: Portable virtualization artifacts
description: Deploy one verified Atlaso OVA on VMware, Proxmox VE, or KVM, or import its converted Hyper-V ZIP.
audience:
  - operator
  - contributor
status: current
---

# Portable virtualization artifacts

## Windows capacity admission

`export-ovf.ps1 -Prerelease` checks free storage before it creates staging directories, retrieves credentials,
downloads software, builds, exports, or mutates a VM. Read-only GitHub metadata and retained-artifact verification
run first. The check resolves each destination to its actual Windows volume and calculates the largest remaining
simultaneous allocation on that volume. Paths sharing a volume compete for the same free bytes; sequential VMware
and Hyper-V smoke imports are not added together. Every summary identifies the paths, volume, free bytes, required
bytes, components, and any shortfall.

The conservative planning estimates below are additional physical storage, in GiB. They are not the virtual
capacity of the two empty 500 GiB data disks. Existing files already consume the reported free space and do not
receive speculative cleanup credits.

Source reconstruction checks the aggregate declared size of selected archive members before extracting any payload.
The 16 GiB limit includes the signed manifest and signature plus a 1 MiB reserve for the generated source identity;
compressed download sizes alone do not establish this expansion bound. Oversized bundles are rejected and preserved.

| Component | Additional estimate | Lifetime |
| --- | ---: | --- |
| Signed software downloads | 2 | Source verification; larger or unknown GitHub asset sizes fail admission |
| Reconstructed verified source | 16, or verified retained tree length | Source through staging |
| Builder payload disks | 64 | Build through staging; includes the 40 + 20 GiB zero-fill high-water mark |
| Builder compaction and memory | 64 | Build only |
| Source snapshot, source copies, ISO and credential staging | Source estimate + 8 | Build only |
| Verified ISO cache | 4 | Build through staging |
| OVF/OVA outputs and staged OVA copy | 8 | Export through staging |
| Export before asset-size admission | 60 | Export only |
| Hyper-V ZIP | 2 | Conversion through staging |
| Conversion extraction and VHDX scratch | 68 | Conversion only |
| VMware smoke import, growth, validation and memory | 84 | VMware smoke only |
| Hyper-V extraction, copies, growth and VMRS | 36 | Hyper-V smoke only |
| Candidate copies and metadata | 8 | Candidate staging |
| Operational headroom | 2 per volume | Every admission |

These estimates cover the canonical four-disk pipeline, including payload zero filling and compaction, not an
arbitrary workload inside a diagnostic guest. For a new build with every path on one volume, the current conservative
peak plus headroom is 180 GiB. A verified retained template omits new builder allocations; a verified candidate
omits build, export, conversion, and smoke allocations. Retained source, template provenance, powered-off state, and
candidate bytes must pass their existing validation before the smaller resume plan is admitted. An invalid retained
operation is preserved and rejected, never relocated automatically.
When the source tree is already verified, only its temporary reconstruction copy is budgeted during source verification;
that copy is removed before later stages. A newly created source tree remains allocated through candidate staging.

The workflow repeats admission before each heavy stage using the remaining plan. Hyper-V conversion discounts validated
completed VHDX bytes from subsequent conversion checks while retaining the ZIP output budget. Direct OVF export,
Hyper-V conversion and smoke entry points also check capacity; the standalone packaged Hyper-V importer uses actual
VHDX file lengths
for disk copies, checks again before each copy and VM creation/start, and separately budgets the observed 4 GiB VMRS
allocation, 16 GiB guest growth, and 2 GiB metadata/headroom. Thus 4 GiB alone is not the total required free space.
Capacity checks do not reserve space against concurrent processes. Later provider allocation errors retain their
original diagnostic and the existing exact-identity cleanup safeguards.

On refusal, free space through an ownership-verified cleanup procedure or choose a supported output location.
`-StagingRoot` moves new prerelease staging and its builder only; it does not move checkout-local caches, OVF output,
conversion output, or smoke roots. Use a checkout on an adequately sized volume for those outputs, and use
`-DestinationRoot` for a standalone Hyper-V import. Do not move or delete a retained operation to evade admission.
Keep the completed source template powered off and preserve its provenance plus valid OVA/ZIP evidence for retry.

## Disposable VMware console diagnostics

For a fresh diagnostic import with a securely retrievable console password, rerun the normal prerelease command
with an explicit bounded window, for example:

```powershell
.\scripts\windows\vmware\export-ovf.ps1 -Prerelease `
    -ManagementSwitch 'Atlaso-Mgmt' -ServiceSwitch 'Atlaso-Services' `
    -SmokeConsoleMinutes 15
```

The window accepts 1 through 30 minutes. Omission runs ordinary release smoke. The installed 1Password plugin and
unlocked, authorized desktop integration are required for concealed-variable publication. Existing checkout-local
Environment selection and DPAPI-protected service-account configuration continue to authenticate the image builder;
Environment publication uses the plugin because the SDK Environment interface is read-only. The workflow never
overwrites `DEFAULT_ADMIN_PASSWORD`, `DEFAULT_ROOT_PASSWORD`, or another run's credential.

Before starting the exact fresh `Atlaso-Ova-Console-<run>` VM, the bounded helper generates a unique password and
stores it as concealed `ATLASO_SMOKE_CONSOLE_<full-run-id>` in the verified **Atlaso** Environment. The terminal prints
only that variable name, the exact VM path, and the non-secret handoff record. Open **1Password > Developer > Atlaso**,
select that variable, and reveal it privately in 1Password. Use account **root** on that VM's local console; the same
temporary password also belongs to its bootstrap **admin** account. Retrieval is independent of guest networking and
SSH. Root SSH remains disabled. Never copy the value into a command line, task report, screenshot, or `.env` file.

The diagnostic window starts after power-on. At expiry, or ordinary interruption, the existing identity-verified
smoke cleanup runs. Diagnostic runs always stop before successful smoke evidence or publication, even if the guest
appears healthy; rerun ordinary smoke against a fresh import after troubleshooting. Source templates stay powered off
and exported image bytes remain unchanged. A retained successful candidate is preserved and rejects diagnostic mode.

`smoke-console-<run-id>.json` in the retained operation records the exact run, VM directory, variable, and retirement
state without a password. The local credential exchange contains current-user DPAPI ciphertext only and is removed
after handoff. A successful exact VM cleanup retires the credential by destroying its only guest identity. Its
concealed 1Password record remains available as history: the current Environment plugin has no variable-deletion
operation. After verifying the handoff is retired and its exact VM is absent, the operator may remove that one obsolete
variable in 1Password. Do not append a duplicate variable as a supposed password rotation.

If the host or controller is killed, or cleanup cannot verify ownership, retain the VM and its concealed credential
for recovery. The recorded window is no longer an enforced deadline after controller termination; do not claim the
guest was stopped or that its password was revoked. Perform the documented exact-VM cleanup with the recorded VMX
and expected name, independently verify provider and filesystem absence, and only then retire the matching variable.
Never identify a cleanup target from its display name alone. An incomplete diagnostic run is never release evidence.

## Canonical artifact lifecycle

Atlaso builds and validates one appliance template with VMware Workstation. A release publishes that template as the
canonical OVA for VMware, Proxmox VE, and KVM, plus one Hyper-V ZIP converted from the same OVA payload. The import
helpers normalize target-specific VM configuration without changing the source OVA.

The lifecycle is **verify published software → construct the complete template → verify and shut down → export →
test disposable imports**. The published application wheel and complete CPython 3.14 wheelhouse are installed during
construction. After final shutdown and compaction, the source template never restarts for software installation,
provider selection, customization, or export preparation. Export and smoke tests revalidate its final hashes.

| Platform | Completed template | Deployed first boot |
| --- | --- | --- |
| VMware | Installed `open-vm-tools` | Retain and enable VMware Tools |
| KVM/QEMU/Proxmox | QEMU agent RPM and complete verified offline dependencies | Install locally and enable the agent |
| Hyper-V | Photon Hyper-V RPMs and complete verified offline dependencies | Install locally and enable required daemons |

All tools survive construction, final Photon updates, cleanup, and export. Only deployed appliances select a provider
and remove unused packages. The selector installs from the verified local RPM closures, verifies required services,
and commits selection before retryable staging cleanup. A failed detection, install, or service check blocks application
readiness. See [first boot guest-agent selection](#first-boot-guest-agent-selection) for the transaction behavior.

The guest-neutral Photon provisioner installs Atlaso's system-wide PowerShell profile in the canonical root reported
by the reviewed package layout. Current images use `/usr/share/powershell`; the older
`/opt/microsoft/powershell/7` root remains an explicitly supported compatibility layout. VMware builds and derived
Hyper-V artifacts fail closed when the executable resolves elsewhere, when the profile ancestry is not root-owned and
non-writable, or when the destination is a symlink. Protected artifact verification accepts exactly one of those two
profile locations and requires the admitted Atlaso bytes with mode `0644`.
When a package update moves the executable between those layouts, provisioning and wheel deployment remove the
inactive copy only after proving its canonical root-owned directory chain, exact Atlaso bytes, ownership, and mode.
Unexpected inactive content or a symlink fails closed instead of being removed or followed.

Virtualization has its own immutable Release namespace. A maintainer's existing Windows workstation creates and smokes
`virtualization-vX.Y.Z-rc.N`; a protected GitHub-hosted job signs and publishes it. Manual stable promotion runs that
exact prerelease OVA on Proxmox and KVM before publishing the unchanged OVA and Hyper-V bytes as
`virtualization-vX.Y.Z`. The software/update `vX.Y.Z` Release is the required source of the embedded wheel and CPython
3.14 wheelhouse, but never contains virtualization assets.

Successful `main` CI automatically publishes the 90-day `atlaso-wheel-vX.Y.Z-<full-sha>` Actions artifact with its
commit/version/digest and CI/publisher identity. The separately protected **Publish appliance release** workflow then
consumes and records that exact automatic-main wheel handoff, adds the offline CPython 3.14 wheelhouse, signs the
bundle, publishes `vX.Y.Z`, and advances `development`. Only after that software Release exists may the
separate manual virtualization producer consume it. The automatic wheel path has no signing material, Release/tag or
Pages write, channel, self-hosted runner, or virtualization access, and it cannot queue an OVA, Hyper-V, Proxmox, KVM,
or virtualization smoke job. If the handoff expires, protected **Replay Python wheel** admission from `main` accepts
only the exact commit and successful source CI run ID and attempt. It validates that evidence without target checkout,
then a completed-run handoff lets **Publish Python wheel** revalidate and rebuild without gaining virtualization
authority. If the software Release already exists, its signed assets are reused only after the replay wheel matches the
bundled wheel byte for byte, so recovery cannot change the immutable source Release consumed by virtualization.

The maintainer workstation is a trusted release producer. An optional explicitly approved ephemeral Windows runner is
trusted for the same single release while it is online. Neither receives the signing key. The protected hosted
finalizer performs the independent checks below as defense in depth and retains exclusive signing and publication
authority, but it is not a reproducible Photon image builder and does not claim to prove an entire root filesystem safe
against a compromised producer. A producer compromise is therefore a release-security incident that requires stopping
publication, rotating affected credentials, and rebuilding from a known-good trusted workstation.

The producer cannot attribute a mixed live checkout to a later commit. The canonical VMware wrapper admits one clean
commit, materializes an invocation-owned snapshot, removes the build identity's write access for the child lifetime,
runs its bounded child, exact HCL template, and every Packer source from that tree, and
records the snapshot inventory digest in schema-v3 VMX provenance. OVA export requires that exact binding; Hyper-V is
derived only from the validated OVA and therefore inherits it. Protected finalization still verifies the signed
software-source sidecar, privileged assets, artifact bytes, and publication identity independently. Those checks are
defense in depth around the source-bound producer output, not a replacement for the snapshot boundary.

Published-software verification runs with Python's `-B` option before source ACL protection and again before Packer
admission. Imports cannot create bytecode in the admitted snapshot, including when the caller sets a Python cache
prefix; no `PYTHONDONTWRITEBYTECODE` workaround is required. The complete file inventory remains authoritative.
An inventory mismatch still blocks construction: preserve the failure evidence and investigate changed or added files
instead of excluding caches or accepting a new baseline.

Schema-v3 also carries `template_contract`: schema version `1`, state `uninitialized`, and the exact verified
`software_source` identity. That identity binds the software tag, version, source commit, manifest and bundle digests,
application-wheel path and digest, and `cp314` ABI. It is copied into OVA provenance and required during retained
template reuse, candidate validation, and protected publication. Protected read-only disk inspection additionally
checks the guest-tool inventories and absence of consumed provider selection, OVF customization, HTTPS initialization,
machine IDs, SSH host keys, and application identity. Provenance alone cannot replace those disk checks.

Older schema-v3 templates without this contract, previously booted templates, changed disks, mismatched software, and
incomplete retained candidates are preserved and rejected with rebuild instructions. Never retrofit them by starting
them or rewriting their provenance. Existing published release bytes remain immutable.

The shared machine contract is UEFI with Secure Boot disabled, four virtual CPUs, 4096 MiB RAM, two NICs, one SCSI
controller, and four ordered disks:

1. 40 GiB Photon OS at SCSI slot 0;
2. 20 GiB Atlaso system content at SCSI slot 1;
3. 500 GiB VCF Offline Depot at SCSI slot 2; and
4. 500 GiB VCF Backups at SCSI slot 3.

The canonical VMware OVF declaration emitted by Atlaso's supported OVF Tool is
`vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="false"`. The validator also recognizes the older
`uefi.secureBoot.enabled` spelling for compatible artifacts, but every present supported declaration must explicitly
evaluate to false. A missing, enabled, malformed, or conflicting declaration blocks export and import. Export validates
the normalized descriptor's complete machine contract before writing provenance that records `secure_boot: false`.

Before either virtualization index is signed, the protected GitHub-hosted finalizer opens the OVA-validated
system-content VMDK read-only with libguestfs. It resolves the active CPython 3.14 environment, requires every hashed
member installed from the Atlaso wheel and complete signed wheelhouse to match, and rejects unexpected active files
except bounded inert pip metadata. Both image provisioning and release deployment disable bytecode compilation and
remove retained package bytecode; the protected finalizer rejects every active `.pyc` file rather than trusting
producer-generated compilation. Every shipped systemd unit that executes the active virtualenv also sets
`PYTHONDONTWRITEBYTECODE=1`, including the root console and first-boot customization services, so post-deployment
restarts cannot recreate bytecode before signing. The image retains the exact Photon RPM closure that owns the
interpreter and
standard library. The finalizer authenticates every retained RPM against the Photon package keys pinned in the admitted
Atlaso commit, requires its exact name, epoch, version, release, architecture, and SHA-256 digest to remain present in
the current official Photon 5.0 release or updates repository metadata, extracts those signed payloads on the hosted
runner, and requires `/usr/bin/python3.14` plus the complete
`/usr/lib/python3.14` tree in the guest to match byte for byte. The pinned keys originate from Photon OS's
`photon-repos` package sources; updating them requires an explicit reviewed source change. It also requires the active
virtualenv Python link to resolve only to that authenticated CPython 3.14 interpreter and every Atlaso console script to
match its signed-wheel entry point and canonical pip launcher. The finalizer opens both payload disks and compares every
Atlaso-provisioned privileged helper, service unit, drop-in,
console setting, vault profile, complete PowerShell global profile, and boot-branding asset with its exact bytes from the
admitted software-release commit. The installer places that profile in the supported PowerShell runtime home discovered
from the resolved `pwsh` executable, including the Photon package locations `/opt/microsoft/powershell/7` and
`/usr/share/powershell`. The producer replaces that global profile with the canonical Atlaso import instead
of preserving workstation-controlled commands, and safely retires a proven Atlaso copy from the inactive supported
layout so exactly one global profile remains. Before comparing bytes, the finalizer also requires each privileged
file and trust key to be a root-owned regular file with its exact declared mode; every ancestor must be a root-owned
directory without group or other write access.
It also requires the installed update-trust directory to contain exactly that commit's public PEM set, rejecting both
altered files and injected trust keys. Producer-authored provenance and smoke evidence cannot substitute for these
independent payload checks. The
same boundary uses `qemu-img compare` to require both Hyper-V payload VHDX disks to
expose the same guest-visible bytes as the admitted OVA VMDKs and both 500 GiB Hyper-V data disks to match an
independent all-zero sparse reference.
The protected index signer also requires the exact versioned OVA name and the canonical OVF, manifest, provenance, and
two payload-VMDK names; suffix-compatible aliases are not publishable assets. The complete Hyper-V archive-name set
must equal exactly `{atlaso-v<version>-hyperv-x86_64.zip}` before the finalizer validates evidence, builds or signs an
index, or changes publication state. Missing, additional, wrong-version, case-variant, and path-variant suffix matches
fail closed. Stable promotion independently enforces the same invariant from the signed prerelease index before it can
publish the unchanged bytes.

The OVA contains files for the two payload disks. Its two 500 GiB data disks are fileless declarations. Import helpers
retain fileless disks when the platform creates them, create only missing data disks, and reject reordered or
conflicting disks.

## Verify release assets

Download the release into a new directory, then obtain the trusted public key from the immutable source tag. The
release key ID is `atlaso-release-2026-01`; its SHA-256 fingerprint is
`b0bb5614342c4f432a01c53fc4c9aae54c1eeffb12806539a92babbcda74b58e`. This example verifies the detached Ed25519
signature, expected version, and every indexed asset before import:

```bash
TAG=virtualization-vX.Y.Z
ASSET_ROOT="atlaso-$TAG"
mkdir -- "$ASSET_ROOT"
gh release download "$TAG" --repo mdaneri/Atlaso --dir "$ASSET_ROOT"
curl --fail --location --output "$ASSET_ROOT/atlaso-release-2026-01.pem" \
  "https://raw.githubusercontent.com/mdaneri/Atlaso/$TAG/image/common/update-trust/atlaso-release-2026-01.pem"
printf '%s  %s\n' \
  'b0bb5614342c4f432a01c53fc4c9aae54c1eeffb12806539a92babbcda74b58e' \
  "$ASSET_ROOT/atlaso-release-2026-01.pem" | sha256sum --check --strict
jq -e --arg version "${TAG#virtualization-v}" --arg tag "$TAG" '
  .schema_version == 2 and .kind == "atlaso-virtualization-artifacts" and
  .classification == "stable" and .release_tag == $tag and
  .source_software_tag == ("v" + $version) and
  .version == $version and .signing_key_id == "atlaso-release-2026-01" and
  (.source_release_manifest_sha256 | test("^[0-9a-f]{64}$")) and
  (.application_wheel_sha256 | test("^[0-9a-f]{64}$")) and
  (.source_commit | test("^[0-9a-f]{40}$")) and
  (.assets | type == "array" and length > 0 and
    all(.[]; (.name | test("^[A-Za-z0-9][A-Za-z0-9._-]*$")) and
      (.size | type == "number") and (.sha256 | test("^[0-9a-f]{64}$"))) and
    ([.[].name] | length == (unique | length)))
' "$ASSET_ROOT/virtualization-artifact-index.json" >/dev/null
jq -e '
  .schema_version == 1 and .algorithm == "ed25519" and
  .key_id == "atlaso-release-2026-01" and (.signature | type == "string")
' "$ASSET_ROOT/virtualization-artifact-index.json.sig" >/dev/null
jq -r .signature "$ASSET_ROOT/virtualization-artifact-index.json.sig" |
  base64 --decode >"$ASSET_ROOT/virtualization-artifact-index.raw.sig"
openssl pkeyutl -verify -pubin -rawin \
  -inkey "$ASSET_ROOT/atlaso-release-2026-01.pem" \
  -in "$ASSET_ROOT/virtualization-artifact-index.json" \
  -sigfile "$ASSET_ROOT/virtualization-artifact-index.raw.sig"
while IFS=$'\t' read -r digest size name; do
  test "$(stat --format='%s' "$ASSET_ROOT/$name")" -eq "$size"
  printf '%s  %s\n' "$digest" "$name"
done < <(jq -r '.assets[] | [.sha256, .size, .name] | @tsv' \
  "$ASSET_ROOT/virtualization-artifact-index.json") |
  (cd "$ASSET_ROOT" && sha256sum --check --strict)
rm -- "$ASSET_ROOT/virtualization-artifact-index.raw.sig"
```

Run the verification from a trusted administrative workstation with OpenSSL 3, `jq`, GNU coreutils, and GitHub CLI.
The standard tools authenticate the signed index before trusting its asset records; no downloaded verifier executes
before that trust boundary. Keep the verified OVA immutable and available until deployment validation succeeds. Do not
import any asset if key fingerprint, signature, version, size, or asset hash verification fails.

Every helper runs `validate_ova.py` before changing hypervisor state. Validation requires the manifest, source commit,
version, payload hashes and roles, fixed capacities, and complete machine topology to agree. An unexpected archive
member, symbolic link, unsafe path, missing provenance record, or changed payload blocks the import.

## Deploy on VMware

Import the OVA directly in VMware Workstation or another compatible VMware OVF deployment environment. Map the first
NIC to the management network and the second NIC to the services network. Do not change the disk controller, slots, or
capacities.

VMware deployment continues through OVF-property customization. The first-boot selector retains `open-vm-tools`,
discards the unused offline QEMU and Hyper-V RPM payloads, and records success before Atlaso services start.
Supply a unique FQDN, Atlaso administrator password, and root password in the OVF deployment properties. The release
image contains no usable build or deployment credential and no reusable SSH host key.
Packer schedules final build-account removal in a detached root-owned unit so the SSH communicator exits first. That
unit verifies the build account, home directory, passwordless sudo authorization, and build-only helper are absent;
any failed verification leaves the VM powered on and blocks export.

## Import on Proxmox VE

The Proxmox VE node needs `qm`, `pvesm`, `qemu-img`, `jq`, Python 3, and access to the selected storage and bridges. Copy
the OVA, `import-atlaso-proxmox.sh`, and `validate_ova.py` into one ordinary directory, then run:

```bash
chmod 0755 import-atlaso-proxmox.sh
./import-atlaso-proxmox.sh atlaso-vX.Y.Z.ova 240 local-lvm vmbr0 vmbr1
```

Arguments are the OVA, an unused VM ID, destination storage, management bridge, and optional services bridge. The
helper uses the platform OVF/OVA importer, then enforces q35, OVMF without pre-enrolled Secure Boot keys, four CPUs,
4096 MiB RAM, one shared virtio SCSI controller, two NICs, QEMU guest-agent support, boot from SCSI slot 0, and the
four-disk contract. It
extracts the manifest-verified OVF member into a private temporary directory for `qm importovf`; the downloaded OVA is
never rewritten.

Do not reuse a VM ID or pre-create matching destination volumes. A failed invocation destroys only the VM ID and
unreferenced storage that it created after all preflight checks passed.

## Import on KVM with virt-v2v

The KVM host needs `virt-v2v`, `virsh`, `qemu-img`, `jq`, Python 3, q35-compatible OVMF firmware, one active storage
pool, and two existing libvirt networks. Copy the OVA, `import-atlaso-kvm.sh`, `validate_ova.py`, and
`normalize_libvirt.py` into one ordinary directory, then run:

```bash
chmod 0755 import-atlaso-kvm.sh
sudo ./import-atlaso-kvm.sh atlaso-vX.Y.Z.ova atlaso default atlaso-management atlaso-services
```

Arguments are the OVA, an unused domain name, active storage pool, management network, and optional services network.
The helper imports with `virt-v2v -i ova`, creates only missing 500 GiB data volumes, verifies the resulting disk order
and capacities, and normalizes the inactive libvirt definition. The resulting domain remains shut off for inspection.

The helper serializes each pool/domain namespace and rejects an existing domain or storage volume with the exact
literal `<domain-name>-` prefix. Dots remain valid in domain names and do not match other characters when storage
ownership is checked.
Rollback removes only the domain and matching volumes created after that locked preflight, including partial
`virt-v2v` volumes left before a domain definition exists.

## Import on Hyper-V

Download and extract `atlaso-v<version>-hyperv-x86_64.zip` into a new ordinary directory on the Hyper-V host. Open an
elevated PowerShell 7.4 or newer (`pwsh`) session and run:

```powershell
pwsh -File .\Import-Atlaso.ps1 `
  -Name Atlaso `
  -ManagementSwitch 'Management' `
  -ServiceSwitch 'Services' `
  -DestinationRoot 'D:\Hyper-V\Atlaso' `
  -Start
```

The importer verifies its manifest and checksums before creating state. It copies four dynamic VHDX disks into a new
destination, creates a Generation 2 VM with Secure Boot off, attaches two selected switches and the four ordered SCSI
disks, and applies the shared CPU and memory contract. Existing VM names, destinations, unsafe paths, malformed
manifests, checksum failures, and conflicting topology are rejected. Failure cleanup removes only resources recorded
as created by that invocation.

Choose a short `DestinationRoot`: the importer creates `<DestinationRoot>\<Name>` once and passes its parent to
`New-VM`, which appends the name itself. Before creating directories or copying disks, admission checks disk paths,
UUID-based configuration/state files under `Virtual Machines`, snapshot paths, and a 64-character provider filename
reserve for Smart Paging against a conservative **240-character full-path budget**. This is an Atlaso safety budget,
not a promise that Windows long-path support changes Hyper-V limits. A Windows host reproduction accepted a
190-character VM directory but rejected 195 characters with Smart Paging error `0x800700CE`; configuration files added
another 59 characters. Shorten the selected destination or VM name when admission reports an over-budget path.

Hyper-V smoke uses `<OutputRoot>\.hv-<128-bit compact identifier>\p` for extraction and places the imported VM beside
`p`. Its preflight checks ZIP member paths and reserves the larger provider layout used by older ZIP importers before
extracting anything. `OutputRoot` must remain beneath the checkout's `artifacts\virtualization-smoke` directory. It
never moves retained operations, falls back to an OS temporary directory, or changes host policy to fit a path.
An import failure retains the original exception together with any importer and smoke cleanup diagnostics. If no exact
created VM identity was returned, files remain for investigation even when a later inventory contains no matching VM.
Existing root, descendant, reparse-point, and exact-VM cleanup checks remain mandatory.

### Hyper-V conversion and ZIP size

The Hyper-V ZIP artifact is built from the validated OVA payload and keeps raw payload-to-VHDX ordering, two dynamic
payload VHDX files, 2 MiB VHDX blocks, two 500 GiB data disks, and the same four-slot SCSI topology as the OVA.
The final archive creation uses .NET `System.IO.Compression.ZipArchive` in streaming create mode and retains ZIP64 support.
This avoids buffering multi-GiB disk members in memory.

Raw VHDX file length can exceed 2 GiB and still be valid. The release asset limit applies to the final ZIP:

- **empty VHDX members** are rejected before disk inspection and archive creation;
- a **non-empty final Hyper-V ZIP of 2,147,483,648 bytes or more** is rejected as an oversized publish candidate.

Export and protected publication also cap the combined uncompressed package at 8 GiB to bound extraction space.
Protected validation retains the separate 1 MiB metadata-member limit, exact package inventory, checksums, source
binding, disk topology, and guest-visible byte comparisons. A raw disk crossing 2 GiB alone does not fail publication.

When a check fails, keep the completed source template powered off:

- if a raw VHDX is empty, investigate the converter output and revalidate the source OVA before
  retrying;
- if only the final ZIP is oversized, review candidate evidence and rebuild from a validated source after reducing
  content where supported by policy.

For diagnostics, capture and retain:

- reported converter version, dynamic subformat, and block size;
- reported virtual capacity and raw byte length for each VHDX;
- ZIP member `uncompressed_bytes` and `compressed_bytes`;
- final archive byte size.

At final import time or release troubleshooting, use PowerShell 7.4+ (`pwsh`) and `Expand-Archive` for zip inspection;
raw extraction and import paths may need more temporary space than the downloaded ZIP size.

## First boot guest-agent selection

Atlaso retains its checksum-pinned QEMU guest-agent build. Photon 5.0's published `qemu` build disables the guest
agent, so installing that emulator package does not supply the required `qemu-ga` daemon. Atlaso builds only the agent
RPM from the pinned upstream source and stages its complete Photon dependency closure; it does not add the full
emulator to the appliance. See the [Photon QEMU specification](https://github.com/vmware/photon/blob/5.0/SPECS/qemu/qemu.spec)
and the checked-in `image/common/guest-agents` build inputs.

The image carries locked offline RPM closures under `/var/lib/atlaso/first-boot-packages`. A provider-neutral service
runs before data-disk initialization, networking handoff, nginx, Atlaso, and the worker. It does not use a network
repository. Both the canonical VMware producer and its derived Hyper-V artifact therefore inherit the same shared
provisioning checks: the physical bootstrap release must match both compatibility links, and QEMU's offline-agent build
uses a private root-owned HOME/cache sandbox rather than the Packer communicator user's home.

- VMware retains and enables `open-vm-tools`.
- KVM, QEMU, and Proxmox remove VMware Tools, install the verified local QEMU guest-agent closure, and enable its
  service.
- Hyper-V removes VMware Tools, installs the verified local Photon Hyper-V closure, and enables its required daemons.
- Bare metal removes VMware Tools and all virtual guest-agent payloads, then continues without an agent.
- Unknown or contradictory platform evidence blocks appliance startup for diagnosis.

The bare-metal selector branch applies only when the canonical portable four-disk set is attached with its declared
SCSI layout; it uses the explicit system-content, Depot, and Backups identities at slots 1, 2, and 3. It does not select,
partition, or adopt arbitrary physical disks. The separate offline installation ISO tracked in #542 owns interactive
target selection and the physical-hardware disk-safety contract.

Successful selection proves that only the expected agent is installed, then securely removes the RPM staging tree,
checksum manifest, package-manager cache, and runtime scratch directory. Failure leaves the verified persistent RPM
closure available for automatic retry while the Atlaso front door and application remain stopped.
Production cleanup is fixed to the Atlaso staging, runtime, marker, and TDNF cache paths. The selector rejects path
overrides unless an isolated test invocation also supplies one ordinary mode-`0700` test root owned by the expected
test identity; every overridden cleanup target must be a strict, non-overlapping descendant with canonical,
non-symlink ancestry, no mount anywhere in the explicit test root, and no multiply linked regular file. The selector
revalidates those boundaries, ownership, and
permissions immediately before every cleanup attempt, including a retry after the durable success marker exists.
Test-override cleanup pins the validated isolated-root identity, opens every target ancestor relative to that descriptor,
and atomically renames staging, runtime, and package-cache artifacts to randomized siblings before recreating an empty
cache. It never recursively traverses or erases same-identity paths, so a root or ancestor replacement cannot redirect
cleanup and a mount added after validation fails closed; the test harness owns eventual cleanup of retained artifacts.
Production retains secure erasure on its fixed paths.
The selector's success marker is the only first-boot transaction commit. It is stored under the root-only
`/var/lib/atlaso-privileged/guest-agent` boundary, whose ownership and mode are revalidated before the marker is trusted.
An interruption before that commit reruns
identity initialization, generates a fresh credential set, and republishes its matching one-time envelope before
networking. The retry never exposes a password whose corresponding host state was replaced.

VMware continues into OVF-property customization. Hyper-V, KVM, and Proxmox use DHCP-first defaults and do not wait for
VMware metadata. Use the appliance console to complete initial networking when DHCP is unavailable.

DHCP-first images admit management SSH and HTTP/HTTPS over IPv4 only through the deployed management interface
(`eth0`). IPv6 management admission requires explicit deployment configuration.
The temporary VMware builder subnet is not retained as a source restriction. An explicitly supplied
`ATLASO_MGMT_SOURCE_CIDR` remains an additional source restriction on that interface; static builds otherwise derive
it from the final configured management network. Services interfaces remain outside this management admission.
Fresh appliance initialization retains these
source and address-family restrictions in the **Bootstrap management** Source Group assigned to management admission,
including physical and VLAN interfaces flagged for management UI, so normal Firewall Apply preserves them.
Editing a flagged listener's Source Group overrides that listener only; other listeners retain their shared default.
Console IPv6 correction uses the shared Network Objects transaction lock before reading desired state, preserving
concurrent operator saves. It updates the address family of an untouched bootstrap group before Apply; an operator-saved
Source Group remains authoritative. Operators can subsequently edit that Source Group or its assignment;
startup does not replace saved choices or migrate existing appliances.
When validating a portable image, use a management subnet different from the builder's and verify SSH plus
`/openapi.json` both on initial boot and after reboot. Existing exported images need a rebuilt artifact to receive
this provisioning correction; changing an appliance software version alone does not replace their initial firewall.

Before networking, every cloned appliance generates a new machine ID, OpenSSH host-key set, application secrets, and
high-entropy administrator and root passwords. VMware replaces the generated passwords with its required OVF values
and publishes the regenerated Ed25519 public host key through VMware guest-info for authenticated automation. KVM and
Proxmox expose a root-only one-time envelope on tmpfs at `/run/atlaso/first-boot-access.json`, readable through the QEMU
guest agent or from the local console. Hyper-V publishes the same envelope under KVP key `atlaso.first_boot_access`.
The local console keeps the envelope on a dedicated first-time initialization screen until an operator presses Enter
to acknowledge that every value was recorded; acknowledgement removes only the console's tmpfs copy. Retrieve the
envelope only from the authenticated hypervisor control plane or the physically controlled console, pin its SSH host
key before connecting, and rotate both passwords immediately. The first reboot removes any remaining runtime file and
Atlaso's Hyper-V KVP record while preserving unrelated KVP data.

Signed appliance updates preserve the disk policy already proven for the installed generation. Portable artifacts use
the shared four-disk policy recorded by the verified first-boot provider marker. Older VMware appliances retain their
existing four-disk controller identities, while older three-disk Hyper-V appliances retain their Depot and Backups
slots and are never reinterpreted as the new four-disk layout. These compatibility policies support updates only; the
retired Hyper-V template-build and lifecycle environment is not restored.

The protected smoke jobs retrieve each booted VM's regenerated Ed25519 public host key and unique credential through
its authenticated hypervisor metadata channel before SSH authentication. They reject an unknown or changed host and
never use trust-on-first-use host-key acceptance. Artifact provenance intentionally contains no reusable host identity.

Protected virtualization admission, finalization, and publication jobs configure Python without requesting the
built-in `setup-python` pip cache. Their read-only or otherwise narrowly scoped Actions permissions are not widened for
cache saving; exact hash-locked release-tool installation and every signing, attestation, immutable-asset, and isolated
smoke boundary remain authoritative.

Each smoke also captures both provider-side NIC identities before probing the guest. Hyper-V binds the address to the
named **Management** adapter and its exact switch, KVM and Proxmox match QEMU guest-agent interface data to the
management MAC from the ordered provider topology, and VMware resolves `ethernet0` only through its mapped management
vmnet and exact MAC. On a clean Windows runner, the VMware smoke uses the exact management MAC to obtain DHCP lease
candidates and sends an interface-scoped probe to populate neighbor evidence; a lease is never accepted without the
matching management-vmnet neighbor entry. Services-first enumeration cannot choose the probe target. Missing, duplicate,
mismatched, or
changing management MAC/address evidence fails the smoke run before the SSH or `/openapi.json` result is accepted, and
the same binding is revalidated after reboot.

VMware SSH admission requires a currently `Reachable` management neighbor. Cached `Stale`, `Delay`, and `Probe`
entries are probe candidates only; expired, malformed, or unbounded DHCP leases are excluded. Each failed SSH
transport attempt returns to the Windows wrapper for another identity check under the same 15-minute phase deadline.
The wrapper handles the child retry status explicitly even when PowerShell native-error promotion is enabled, and
preserves the caller's preference; other nonzero child results remain terminal.
Unanswered ICMP probes also preserve that preference and continue to refreshed neighbor evaluation; ICMP success
alone never admits an address.
Loss of MAC-bound address ownership receives at most a 20-second neighbor refresh window before an explicit identity
failure. A changed address is never silently substituted, including during initial boot. Correct the reported network
condition and start a new disposable smoke attempt. Host-key or authentication rejection is terminal.

Progress identifies the provider, initial or post-reboot phase, VMX, management MAC/vmnet/host interface, target and
elapsed/remaining SSH wait. Child progress uses standard error so the initial TLS fingerprint remains the sole standard
output result. `Transfer Completed` from OVF Tool proves only import completion; guest disk/service/OpenAPI checks and
post-reboot validation must still pass. The original stale-address report did not establish what moved the guest address;
the fixed-host retry loop and admission of cached neighbor state are independently reproducible from the smoke helpers.

## Validate and recover

After first boot, verify all of the following before adopting the VM:

- the expected guest agent is installed and active and foreign agents are absent;
- `/var/lib/atlaso/first-boot-packages` no longer exists;
- both NICs and four ordered disks are present;
- the Depot and Backups data disks are mounted at their documented paths; and
- `https://<management-address>/openapi.json` returns the Atlaso API document.

Reboot the VM and repeat the readiness and disk checks. An assigned address or a running VM alone is not application
readiness.

If guest-agent selection fails, inspect its service status and journal from the console. Preserve the RPM staging tree,
correct only the reported image or platform conflict, and restart the selector. Do not manually enable Atlaso or nginx
while the selector is failed. For an import-time failure, keep the original release assets, remove only the target VM
and storage owned by that import attempt, correct the host prerequisite, and run the helper again.

## Protected release runners

The primary Windows producer is a maintainer workstation, not a permanent GitHub runner. From a clean attached branch
or detached checkout at the successful software-release SHA, run:

```powershell
python -m pip install --require-hashes --requirement requirements-virtualization-smoke.lock

./scripts/windows/vmware/export-ovf.ps1 -Prerelease
```

The command verifies and extracts the exact published software bundle, installs it while building the canonical
VMware template, exports that checked powered-off template directly, derives
Hyper-V from that OVA, runs both Windows smokes, creates the annotated tag before the draft Release, uploads without
clobbering, and waits for the exact newly dispatched hosted-finalizer run to succeed before verifying publication.
The intermediate VMware builder uses a deterministic version-and-source-commit identity and records that identity in
its output manifest and schema-v3 provenance. The exporter consumes that exact proven VMX while retaining the canonical
`atlaso-vX.Y.Z` OVA/product and release filenames; release output never inherits a pull-request number.
Its credential bridge, sensitive source snapshot, Packer workspace, cleanup state, and builder-address release handoff
remain beneath the exact checkout-local `.atlaso-local/photon-image-build-state` root. Snapshot admission preserves
and revalidates whether that exact source checkout was attached to its original branch or detached at the release SHA.
The non-task-owned address
allocation lock and ledger remain per-user and host-shared so parallel worktrees cannot choose the same address; no
task-owned output or sensitive state falls back to a Windows profile, temporary directory, or `LocalApplicationData`.
Use `-CandidateOnly` to stop after candidate production and smoke; otherwise the command continues through tag creation,
draft upload, and protected hosted finalization. The standard
producer defaults `StagingRoot` to `<checkout>\artifacts\virtualization-release`, uses the exact Hyper-V switches
`Atlaso Management` and `Atlaso Services`, resolves the pinned Atlaso 1Password Environment through the checkout-local
selector file, prefers the checkout-local current-user DPAPI service-account token before desktop discovery, and
discovers a standard Windows x64 CPython 3.14 runtime. The retained `-StagingRoot`, `-ManagementSwitch`,
`-ServiceSwitch`, `-OnePasswordEnvironmentId`, `-OnePasswordServiceAccountTokenFile`, `-OnePasswordAccount`, and
`-OnePasswordPython` parameters remain authoritative overrides.
The resolved credential selectors are forwarded unchanged to the fresh image build. The producer performs no
post-build address discovery or SSH wheel deployment on the source template.
The image-builder handoff uses named parameters and deliberately leaves both `SecureString` credential parameters
unbound so the reviewed 1Password defaults remain authoritative.

For production-path acceptance without creating a virtualization tag or Release, use the matching signed software
release from its clean source checkout:

```powershell
./scripts/windows/vmware/export-ovf.ps1 -Prerelease -CandidateOnly
```

Before merge, validate development construction and deployment using PR-owned test VMs. Protected candidate production
still requires the matching successful `main` software release; do not weaken that binding to test a feature branch.
Both Windows smokes import separate disposable VMware and Hyper-V VMs, verify offline provider initialization,
unique identity, cleanup, services and host-facing `/openapi.json`, then reboot and recheck persistent readiness.
The source stays powered off and its VMX and payload hashes must remain unchanged after export and smoke completion.
These Windows checks establish candidate acceptance. Actual KVM and Proxmox tests remain mandatory for stable promotion.

New builders live directly at `<StagingRoot>\<rc-tag>\<builder-name>\<builder-name>.vmx`; the redundant `vmware-build`
directory is omitted. Canonical names, ownership manifests, output claims, and provenance are unchanged. A retained
legacy output, sibling manifest, or claim keeps its original `vmware-build` layout. If both layouts contain state,
preflight stops for explicit recovery; it never moves, deletes, or adopts that state automatically.

Before credential selection or release downloads, new build preflight checks generated VMX, sidecar, disk, UUID memory,
and lock paths against a conservative 240-character budget. VMware Workstation can fail creating lock directories even
with Windows long-path support enabled. The error identifies the generated path and recommends a shorter absolute
`-StagingRoot`; direct Photon builds recommend a shorter `-OutputDirectory` parent while retaining the canonical
builder leaf. Existing candidate verification and publication retries do not require a new builder path. Preserve
retained operations when selecting a different staging root; do not manually delete locks or rename owned builders.

Preflight prints the synchronized version and selected tag, staging root, switch names, and selector-source labels
before creating staging directories or starting build activity. It never prints Environment IDs, account values,
credentials, credential material, or secret-bearing paths. If the resolved staging root contains exactly one valid
current-version `rc.N` operation, the producer resumes it after validating any corresponding remote tag and Release.
With no retained operation it inventories remote tags and all GitHub Releases, deduplicates canonical ordinals, and
selects `rc.1` or one greater than the maximum. Multiple retained operations fail closed as ambiguous. The selection is
frozen for the invocation: a later collision never advances automatically and remains subject to non-force tag
creation, `--verify-tag`, no-clobber upload, exact-commit, and byte-idempotency guards.

Keep `StagingRoot` until stable verification; cleanup is a separate explicit operator action. Every retry reconstructs
and byte-validates the complete cached software source against freshly downloaded signed Release assets. A complete
retained candidate is independently
revalidated and reused byte-for-byte; only an absent candidate enters the image-build, OVA-export, and Hyper-V
conversion path. Pre-verification network downloads are invocation-temporary and never reused after interruption.
Repeat the same `-Prerelease -CandidateOnly` command to reuse an exact valid candidate, or omit `-CandidateOnly` only
when publication is intended. If verification rejects retained software, template, or candidate state, preserve that
operation for diagnosis and rebuild under a new explicitly selected owned staging root. A running source, unprovable
power state, consumed initialization marker, or incompatible contract cannot be repaired by starting or SSH-deploying
to the template. See the
[Photon image guide](https://github.com/mdaneri/Atlaso/blob/main/image/vmware-workstation/README.md#completed-template-lifecycle)
for the explicit verified software input and construction checks.
Before signing, the hosted finalizer requires the OVA provenance's software tag, manifest, bundle, application-wheel, and
Python-ABI fields to exactly match the verified software-source sidecar. A retry after only one signed-index file was
uploaded reconstructs the deterministic pair, verifies the retained byte without clobbering it, and uploads only the
missing counterpart.

Stable promotion never rebuilds:

```powershell
./scripts/windows/vmware/export-ovf.ps1 -Release `
  -FromPrerelease virtualization-vX.Y.Z-rc.1 `
  -ProxmoxRunnerLabel atlaso-proxmox-virtualization-vX-Y-Z-rc-1 `
  -KvmRunnerLabel atlaso-kvm-virtualization-vX-Y-Z-rc-1
```

Bring the uniquely labelled Proxmox and KVM `--ephemeral` runners online only for that approved promotion, then destroy
or sanitize them after the job. They receive read-only Actions/contents permissions, no signing secret, and no
write-capable token. Define the repository variables named by `.github/workflows/virtualization-stable.yml` for storage
and networks. The workstation waits for the exact promotion run it dispatched, rather than accepting an older stable
Release with the same version. Stable promotions are serialized repository-wide so two release candidates cannot race
one immutable stable tag. Signing and Release writes occur only in the protected GitHub-hosted finalizer. If stable
publication completed but its final live verification did not, an exact retry detects the published stable Release
during admission and verifies its signed index, source binding, attestations, and byte identity with the selected
prerelease directly on GitHub-hosted Linux. It does not schedule Proxmox or KVM again, rebuild the signed index, or
modify the immutable Release.
If an unpublished stable draft already contains both signed-index assets, the protected finalizer validates their
signature, release identity, source binding, and complete asset set, then resumes with those exact retained bytes even
when current `main` would render a different index. A draft containing only one index asset fails closed. After
confirming that the draft is unpublished and the retained file is the sole incomplete index asset, a maintainer may
rerun **Promote stable virtualization release** with `recover_incomplete_index` enabled; only that explicit protected
recovery deletes the incomplete file and reconstructs the pair. Ordinary retries never delete or replace draft assets.
For the optional ephemeral-Windows workflow, also define `ATLASO_ONEPASSWORD_ENVIRONMENT_ID`,
`ATLASO_ONEPASSWORD_ACCOUNT`, and `ATLASO_ONEPASSWORD_PYTHON` as repository variables. They are non-secret selectors;
the disposable runner must still complete its local 1Password authorization and receives no signing key.

The workstation requires PowerShell 7.4 or newer, VMware Workstation, Packer, OVF Tool, Hyper-V, `qemu-img`, and two
operator-owned virtual switches. The Proxmox and KVM runners require the host tools listed in their import sections.
The optional Windows producer workflow performs the same CPython 3.14 smoke-runtime installation before candidate
production. The generated, seven-day, hash-verified smoke lock is separate from
`requirements-onepassword-deploy.lock`: the latter belongs to the bounded standard Windows x64 CPython 3.14 1Password
credential bridge and includes SDK dependencies the smoke helper neither imports nor needs.
Every smoke identity and storage
namespace is invocation-scoped: VMware generates a disposable per-run password, Proxmox serializes each VMID import,
passes it to OVF Tool through a runner-only temporary configuration file instead of process arguments, and deletes that
file immediately after import. Proxmox serializes each VMID import, and cleanup failures fail the active smoke job
instead of allowing publication with retained provider state. VMware cleanup binds the root, VMX, provider aliases,
and every remaining descendant to captured Windows file identities; Proxmox and KVM require successful inventories to
prove absence. KVM serializes the global domain name and its selected pool namespace independently; Proxmox importer
rollback requires a final inventory proving its fixed VMID absent. Hyper-V
cleanup removes only a VM whose exact ID was captured after successful import; an indeterminate import preserves files
for diagnosis rather than claiming a later name match. KVM rollback preserves every imported volume unless a successful
libvirt inventory proves that the exact domain is absent. Every smoke identity and storage namespace must be dedicated to
the release invocation so cleanup can remain limited to resources created by that invocation. Stable publication waits
for both Linux platform smokes and refuses an asset at or above the repository's existing 2 GiB limit rather than
producing multipart output. Raw VHDX members are validated separately for format and capacity before the final ZIP
size check.

As an optional alternative, **Produce virtualization candidate on ephemeral Windows** runs the same producer with
`-CandidateOnly` on a temporary Windows runner whose exact release-specific label is
`atlaso-windows-virtualization-vX-Y-Z-rc-N`. The Windows job has read-only repository authority
and no signing material. A GitHub-hosted job alone creates the annotated tag and draft, then calls the same protected
hosted prerelease finalizer. Keep that runner offline except for an approved default-branch dispatch and destroy or
sanitize it after its single `--ephemeral` job. If a retry finds a complete existing draft, hosted admission validates
its exact candidate asset inventory and routes it directly back to protected finalization; it never schedules a fresh
ephemeral Windows build whose timestamp-bearing bytes could conflict with the retained draft. An incomplete or
unexpected draft fails closed for explicit operator recovery.

The disposable VMware smoke import explicitly binds its adapters to the selected existing VMnets.
Cleanup uses the shared Workstation inventory and running-VM checks before removing only the owned import.
If initial network-identity capture fails, cleanup retains the last verified VMX identity to stop the owned import.
After shutdown, cleanup verifies the captured directory inventory and VMX contents before accepting a replacement
VMX; only shutdown-status flags may change. Unexpected replacements or added files are preserved and fail cleanup.
The protected read-only verifier checks offline-package names, entry types, sizes, and the 256-entry limit
(including directories) before exporting the guest-tool tree, then rechecks the archive inventory.
The local smoke import supplies its OVF environment through the shared Workstation serializer,
with credentials confined to the protected disposable VM directory until first-boot cleanup.
The smoke check allows 21 minutes after SSH becomes available for the 20-minute storage initialization
window plus application readiness, with a 22-minute outer SSH-command timeout;
a readiness timeout reports service states and still fails acceptance.
