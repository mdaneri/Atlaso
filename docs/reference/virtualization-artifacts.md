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

Download the OVA, its manifest, the signed artifact index, and the import helper for the target platform from the same
release. Verify the signed index according to the release instructions before importing an appliance. Keep the OVA
immutable and available until deployment validation succeeds.

Every helper runs `validate_ova.py` before changing hypervisor state. Validation requires the manifest, source commit,
version, payload hashes and roles, fixed capacities, and complete machine topology to agree. An unexpected archive
member, symbolic link, unsafe path, missing provenance record, or changed payload blocks the import.

## Deploy on VMware

Import the OVA directly in VMware Workstation or another compatible VMware OVF deployment environment. Map the first
NIC to the management network and the second NIC to the services network. Do not change the disk controller, slots, or
capacities.

VMware deployment continues through OVF-property customization. The first-boot selector retains `open-vm-tools`,
discards the unused offline QEMU and Hyper-V RPM payloads, and records success before Atlaso services start.

## Import on Proxmox VE

The Proxmox VE node needs `qm`, `pvesm`, `qemu-img`, `jq`, Python 3, and access to the selected storage and bridges. Copy
the OVA, `import-atlaso-proxmox.sh`, and `validate_ova.py` into one ordinary directory, then run:

```bash
chmod 0755 import-atlaso-proxmox.sh
./import-atlaso-proxmox.sh atlaso-vX.Y.Z.ova 240 local-lvm vmbr0 vmbr1
```

Arguments are the OVA, an unused VM ID, destination storage, management bridge, and optional services bridge. The
helper uses the platform OVF/OVA importer, then enforces q35, OVMF without pre-enrolled Secure Boot keys, four CPUs,
4096 MiB RAM, virtio SCSI, two NICs, QEMU guest-agent support, boot from SCSI slot 0, and the four-disk contract. It
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

The helper rejects an existing domain or matching storage namespace. Rollback can remove only the domain and volumes
created by that invocation.

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

VMware continues into OVF-property customization. Hyper-V, KVM, and Proxmox use DHCP-first defaults and do not wait for
VMware metadata. Use the appliance console to complete initial networking when DHCP is unavailable.

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
attach those labels to general-purpose or fork-accessible runners. Configure the `appliance-release` environment with
the protected build and smoke credentials, and define the repository variables named by `.github/workflows/release.yml`
for VMware vmnets, Proxmox storage and bridges, KVM storage and networks, Hyper-V switches, smoke identities, and
bounded test destinations.

The VMware build runner requires Workstation, Packer, OVF Tool, and the existing Photon build prerequisites. The
Proxmox and KVM runners require the same host tools listed in their import sections. The Hyper-V runner requires
PowerShell 7.4 or newer, Hyper-V, `qemu-img`, and two operator-owned virtual switches. Every smoke identity and storage
namespace must be dedicated to CI so cleanup can remain limited to resources created by that invocation. Release
publication waits for all four platform smoke tests and refuses an asset at or above the repository's existing 2 GiB
limit rather than producing multipart output.
