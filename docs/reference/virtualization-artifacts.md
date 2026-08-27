---
title: Portable virtualization artifacts
description: Deploy one verified Atlaso OVA on VMware, Proxmox VE, or KVM, or import its converted Hyper-V ZIP.
audience:
  - operator
  - contributor
status: current
---

# Portable virtualization artifacts

Atlaso builds and validates one appliance template with VMware Workstation. A release publishes that template as the
canonical OVA for VMware, Proxmox VE, and KVM, plus one Hyper-V ZIP converted from the same OVA payload. The import
helpers normalize target-specific VM configuration without changing the source OVA.

The shared machine contract is UEFI with Secure Boot disabled, four virtual CPUs, 4096 MiB RAM, two NICs, one SCSI
controller, and four ordered disks:

1. 40 GiB Photon OS at SCSI slot 0;
2. 20 GiB Atlaso system content at SCSI slot 1;
3. 500 GiB VCF Offline Depot at SCSI slot 2; and
4. 500 GiB VCF Backups at SCSI slot 3.

The OVA contains files for the two payload disks. Its two 500 GiB data disks are fileless declarations. Import helpers
retain fileless disks when the platform creates them, create only missing data disks, and reject reordered or
conflicting disks.

## Verify release assets

Download the release into a new directory, then obtain the trusted public key from the immutable source tag. The
release key ID is `atlaso-release-2026-01`; its SHA-256 fingerprint is
`b0bb5614342c4f432a01c53fc4c9aae54c1eeffb12806539a92babbcda74b58e`. This example verifies the detached Ed25519
signature, expected version, and every indexed asset before import:

```bash
TAG=vX.Y.Z
ASSET_ROOT="atlaso-$TAG"
mkdir -- "$ASSET_ROOT"
gh release download "$TAG" --repo mdaneri/Atlaso --dir "$ASSET_ROOT"
curl --fail --location --output "$ASSET_ROOT/atlaso-release-2026-01.pem" \
  "https://raw.githubusercontent.com/mdaneri/Atlaso/$TAG/image/common/update-trust/atlaso-release-2026-01.pem"
printf '%s  %s\n' \
  'b0bb5614342c4f432a01c53fc4c9aae54c1eeffb12806539a92babbcda74b58e' \
  "$ASSET_ROOT/atlaso-release-2026-01.pem" | sha256sum --check --strict
jq -e --arg version "${TAG#v}" '
  .schema_version == 1 and .kind == "atlaso-virtualization-artifacts" and
  .version == $version and .signing_key_id == "atlaso-release-2026-01" and
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

The helper serializes each pool/domain namespace and rejects an existing domain or matching storage namespace.
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

## First boot guest-agent selection

The image carries locked offline RPM closures under `/var/lib/atlaso/first-boot-packages`. A provider-neutral service
runs before data-disk initialization, networking handoff, nginx, Atlaso, and the worker. It does not use a network
repository.

- VMware retains and enables `open-vm-tools`.
- KVM, QEMU, and Proxmox remove VMware Tools, install the verified local QEMU guest-agent closure, and enable its
  service.
- Hyper-V removes VMware Tools, installs the verified local Photon Hyper-V closure, and enables its required daemons.
- Bare metal removes VMware Tools and all virtual guest-agent payloads, then continues without an agent.
- Unknown or contradictory platform evidence blocks appliance startup for diagnosis.

Successful selection proves that only the expected agent is installed, then securely removes the RPM staging tree,
checksum manifest, package-manager cache, and runtime scratch directory. Failure leaves the verified persistent RPM
closure available for automatic retry while the Atlaso front door and application remain stopped.
The selector's success marker is the only first-boot transaction commit. It is stored under the root-only
`/var/lib/atlaso-privileged/guest-agent` boundary, whose ownership and mode are revalidated before the marker is trusted.
An interruption before that commit reruns
identity initialization, generates a fresh credential set, and republishes its matching one-time envelope before
networking. The retry never exposes a password whose corresponding host state was replaced.

VMware continues into OVF-property customization. Hyper-V, KVM, and Proxmox use DHCP-first defaults and do not wait for
VMware metadata. Use the appliance console to complete initial networking when DHCP is unavailable.

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

Virtualization release jobs run only for the exact protected-main commit selected by the release workflow. The runner
fleet must provide the dedicated `atlaso-vmware`, `atlaso-proxmox`, `atlaso-kvm`, and `atlaso-hyperv` labels; do not
attach those labels to general-purpose or fork-accessible runners. Build credentials are disposable values generated
inside the protected build job and are scrubbed before export. Define the repository variables named by
`.github/workflows/release.yml` for VMware vmnets, Proxmox storage and bridges, KVM storage and networks, Hyper-V
switches, and bounded test destinations.

The VMware build runner requires Workstation, Packer, OVF Tool, and the existing Photon build prerequisites. The
Proxmox and KVM runners require the same host tools listed in their import sections. The Hyper-V runner requires
PowerShell 7.4 or newer, Hyper-V, `qemu-img`, and two operator-owned virtual switches. Every smoke identity and storage
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
CI so cleanup can remain limited to resources created by that invocation. Release
publication waits for all four platform smoke tests and refuses an asset at or above the repository's existing 2 GiB
limit rather than producing multipart output.
