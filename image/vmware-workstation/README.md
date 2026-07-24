# LabFoundry Photon OS VMware Workstation Image

The base image includes Python `vcf-sdk==9.1.0.0` and system-wide
`VCF.PowerCLI==9.1.0.25380678`. Provisioning fails if PowerCLI cannot import or
`Connect-VIServer` is unavailable to the unprivileged bootstrap administrator.
Provisioning also disables and verifies PowerCLI CEIP participation at
`AllUsers` scope; Appliance Settings can change that central preference after
deployment without product-specific prompts.
The system module tree remains root-owned and writable only by root, while
every local `/usr/bin/pwsh` user can read and import its modules. Set
`LABFOUNDRY_POWERCLI_MODULE_SOURCE` to a pre-staged module directory for offline
image builds; otherwise PSGallery is used.

This target builds a Photon OS 5.0 VMware Workstation VMX/VMDK appliance with
the same LabFoundry control plane provisioning used by the Hyper-V image.
Fresh appliances enable the integrated CA on deployed-VM first boot, serve the
management console/API over CA-backed HTTPS/443, and keep management HTTP/80
redirect-only. ESXi PXE remains the only served HTTP payload.

## Prerequisites

- VMware Workstation Pro with `vmrun.exe` available under
  `C:\Program Files\VMware\VMware Workstation`.
- VMware Workstation's bundled OVF Tool with `ovftool.exe` available under
  `C:\Program Files\VMware\VMware Workstation\OVFTool` when exporting OVF/OVA artifacts.
- Packer `>= 1.10`.
- `qemu-img` when preparing the tiny Alpine lifecycle client VMDK.
- Photon OS 5.0 ISO URL and checksum.

The template uses the Packer VMware Desktop plugin:

```hcl
source = "github.com/vmware/vmware"
```

Run `packer init` from this directory before validating or building.

## Build

Use the wrapper instead of raw `packer build`; it creates the remastered Photon
ISO with `photon-ks.json` and the LabFoundry GRUB auto-install entry.
The original Photon source ISO is shared with the Hyper-V image path under
`image/common/source`; only the target-specific remastered kickstart ISO is
written under this image directory.
Workstation builds show the VMware console by default so boot/install progress
is visible; pass `-Headless` for unattended runs.

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/build-photon-image.ps1 `
  -IsoUrl "https://packages.vmware.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso" `
  -IsoChecksum "sha512:<checksum>"
```

Before `packer build -force` replaces the Workstation output directory, the
wrapper checks for an existing output VMX and unregisters it with
`vmrun -T ws unregister`. The `vmrun.exe` path is resolved through the same
Workstation discovery path used by the rest of the VMware scripts, and the
cleanup is scoped to this image target's configured output directory.

For lifecycle/demo images that should use real appliance adapters:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/build-photon-image.ps1 `
  -IsoUrl "<photon-iso-url-or-path>" `
  -IsoChecksum "<packer-checksum>" `
  -EnableRealSystemAdapters
```

The built VMX keeps the first adapter on `-VmnetName` as management-only and
adds a second `vmxnet3` adapter on `-ServiceVmnetName` for service traffic. The
service network defaults to Workstation's built-in host-only `VMnet1`.
The Packer builder VM contains only the 40 GB Photon OS disk. The OVF export
step declares the appliance data disks without adding large blank VMDK payloads
to the reusable builder image.

## Networking

The default Workstation builder and lifecycle scripts expect:

- management: `VMnet8`, with the LabFoundry appliance address assigned by
  DHCP by default
- services: `VMnet1`
- SiteA: `VMnet2`
- WAN/SiteB: `VMnet3`
- trunk-like validation segment: `VMnet4`

Validate the current Workstation network inventory with:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/prepare-networks.ps1 `
  -PlanOnly
```

The Workstation management subnet intentionally stays separate from the Hyper-V
lab subnet. The build wrapper reads the selected VMware network before
rendering Packer variables. For NAT/host-only vmnets it uses
`vmrun -T ws listHostNetworks`; for bridged `vmnet0` it falls back to the active
Windows IPv4 interface, or the interface named by `-BridgedInterfaceAlias`.
Unless overridden, it chooses host offset `.30` for the temporary Photon
builder SSH address and uses DHCP for the final appliance management address.
For NAT vmnets, the wrapper points the temporary builder at the VMware NAT
gateway DNS proxy, normally host offset `.2`, instead of copying unrelated host
DNS servers into the Photon kickstart. Pass `-BuilderStaticIp`,
`-BuilderStaticGateway`, and `-BuilderStaticDns` together only when a different
builder address plan is intentional. Pass `-FinalMgmtAddress` and
`-FinalMgmtGateway` only when a static final management address is intentional.
Pass `-ServiceVmnetName` only when the second appliance NIC should attach to a
different Workstation network.

Create or adjust missing lifecycle vmnets in VMware Virtual Network Editor. The
scripts intentionally do not rewrite global Workstation vmnet configuration
because `vnetlib.exe` behavior is version-sensitive and can affect unrelated
VMs.

## Local Wheel Deploy

After a code change that does not require rebuilding the Photon image, deploy a
fresh LabFoundry wheel to a running VMware test appliance with:

```powershell
.\scripts\windows\vmware\deploy-wheel.ps1 -IpAddress 192.168.167.10
```

When the IP should be resolved from VMware Tools, pass the VMX path as a named
argument:

```powershell
.\scripts\windows\vmware\deploy-wheel.ps1 `
  -VmxPath "image\vmware-workstation\test-vms\LabFoundry-VMware\LabFoundry-VMware.vmx"
```

Do not pipe the VMX path or put the `.vmx` path on a line by itself; PowerShell
will try to run that file and report a pipeline/document execution error. The
helper builds `python -m pip wheel . -w dist`, uploads the newest
`labfoundry-*.whl` with `scp`, installs it into `/opt/labfoundry/.venv`,
syncs `scripts/appliance/labfoundry-helper` to
`/opt/labfoundry/bin/labfoundry-helper`, synchronizes every checked-in public
release key from `image/common/update-trust` into
`/etc/labfoundry/update-trust.d`, restores virtualenv permissions, restarts
`labfoundry.service`, and verifies `/openapi.json` from inside the guest and
from the Windows host. The helper and trust-key syncs are required because
those root-owned files live outside the Python virtualenv and are not updated
by `pip install`. If the app takes longer to become reachable after restart,
pass `-ReadinessTimeoutSeconds 120`.

`deploy-wheel.ps1` remains a development-only live-patching path. Production
Appliance Update uses signed GitHub release bundles, retained ABI-specific
wheelhouses, `/opt/labfoundry/releases/<version>`, and transactional rollback;
it does not use this direct wheel deployment path.
Manual and scheduled checks/installations retain one parent task with separate
LabFoundry Release, PowerShell Modules, and Photon OS child steps so failures
and skipped Photon work remain independently visible.
The Packer build explicitly stages `image/common/update-trust` and fails when
no valid public release key is available.

## OVF / OVA Export

After a VMware image build, export a deployable OVF folder and OVA archive:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/export-ovf.ps1 `
  -SourceVmxPath image/vmware-workstation/output/labfoundry-photon-vmware-workstation/LabFoundry-Photon-Builder-VMware.vmx `
  -Name LabFoundry-Photon `
  -Force
```

The export script runs OVF Tool, adds LabFoundry vApp properties and appliance
network mappings to the OVF descriptor, regenerates the manifest, and packages
the folder as an OVA unless `-NoOva` is passed. The descriptor declares a
500 GiB empty VCF Offline Depot disk and a 500 GiB empty VCF Backups disk;
ESXi creates both disks during deployment, while the OVA carries only the OS
VMDK payload. The exporter refuses to package an image unless the descriptor
contains the OS and both empty data disks. It identifies the guest as VMware
Photon OS, uses VMware Paravirtual SCSI for all three disks, and removes the
build-time CD-ROM device. On first boot, `labfoundry-data-disks.service`
formats the two blank disks as ext4, labels them `LABFOUNDRY_DEPOT` and
`LABFOUNDRY_BKUP`, writes their UUIDs to `/etc/fstab`, and mounts them at
`/mnt/labfoundry-vcf-offline-depot` and `/mnt/labfoundry-vcf-backups`. The
descriptor exposes two network mappings for vSphere/ESXi import:
`LabFoundry Management Network` for
the first adapter, which remains management-only as `eth0`, and
`LabFoundry Services Network` for the second adapter used by DNS, DHCP, CA,
depot, PXE, KMS, and other LabFoundry-managed services. The OVF properties are
intended for vSphere/ESXi import:

| Category | Property | Required | Description |
| --- | --- | --- | --- |
| Management network | `labfoundry.cidr` | no | Static management IPv4 CIDR for `eth0`, for example `192.168.10.10/24`; blank uses DHCPv4. |
| Management network | `labfoundry.gateway` | no | Required with a static IPv4 CIDR and invalid without one. |
| Management network | `labfoundry.ipv6_enabled` | no | Boolean, default `false`. Enables management IPv6. |
| Management network | `labfoundry.ipv6_cidr` | no | Blank while IPv6 is enabled uses RA/SLAAC; a value selects static IPv6. |
| Management network | `labfoundry.ipv6_gateway` | no | Optional with a static IPv6 CIDR; accepts an on-link global address or link-local address. |
| Management network | `labfoundry.dns_servers` | no | Optional resolver IPs separated by commas, spaces, or new lines. Blank DHCP deployments keep lease-provided DNS. |
| Appliance identity | `labfoundry.fqdn` | yes | Appliance FQDN applied to Photon OS and LabFoundry desired state. |
| Initial credentials | `labfoundry.admin_password` | yes | Initial LabFoundry web `admin` password. |
| Initial credentials | `labfoundry.root_password` | yes | Photon root console password. Root SSH remains disabled by default. |
| Initial credentials | `labfoundry.root_ssh_enabled` | no | Boolean, default `false`. Enables root password SSH immediately on first boot. |

On first boot from an OVF/OVA deployment, `labfoundry-vmware-ovf-customize`
reads those properties through VMware Tools before LabFoundry starts. A blank
IPv4 CIDR writes `DHCP=ipv4`; a supplied CIDR and gateway configure static IPv4.
IPv6 can be disabled, automatic through RA/SLAAC, or static. The customizer also
writes family-correct firewall access, resolver overrides when supplied,
hostname, root password, optional root SSH state, and bootstrap admin password
once, then records a redacted marker
under `/var/lib/labfoundry`.
Passwords are consumed as deployment inputs and are not printed in the marker or
customization log.

The OVF descriptor stores these as unqualified property IDs inside the
`labfoundry` product class. ESXi qualifies them once in the guest OVF environment
as `labfoundry.<property>`; do not repeat the class prefix in each property ID.

## Lifecycle

Run the Workstation lifecycle wrapper after building an appliance VM:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/invoke-lifecycle-test.ps1
```

The wrapper writes evidence under
`test-results/vmware-workstation-lifecycle/<timestamp>`. Unless
`-ApplianceIPAddress` is passed, it waits for VMware Tools to report the DHCP
management address and records it in `discovered-appliance.json` before running
HTTP and SSH probes. It keeps the Python appliance assertions shared with the
Hyper-V lifecycle runner.

Pass `-PlanOnly` to print the selected VMX, client VMDK, vmnets, and result path
without creating VMs.

## Boot A Test Appliance

Create and start a normal Workstation test appliance from the latest built VMX:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/create-labfoundry-test-vm.ps1 `
  -Redeploy `
  -ResetDataDisks `
  -WaitForIp `
  -TrustRootCa
```

The wrapper creates fresh Depot and Backups data VMDKs when needed, and
`-ResetDataDisks` removes those data VMDKs before recreating them. Pass
`-IncludeLabNetworkAdapters` only after `VMnet2`, `VMnet3`, and `VMnet4` exist
for the SiteA, WAN/SiteB, and trunk-like lifecycle networks.
`-TrustRootCa` downloads the freshly deployed appliance root CA, removes stale
LabFoundry root CAs from the current-user Trusted Root store, and trusts the new
root so Edge and the Codex integrated browser accept the first-boot HTTPS cert.
The root CA is generated by `labfoundry-bootstrap-https.service` on each
deployed VM's first boot, not baked into the reusable Packer-built VMX.
The wrapper waits up to five minutes by default for the first-boot CA endpoint,
retrying transient connection and service-readiness failures. Pass
`-TimeoutSeconds <seconds>` to adjust both IP discovery and CA readiness waits.
After the VM starts, the wrapper prints a connection summary with the HTTPS
console URL, Swagger URL, OpenAPI URL, root certificate URL, and
`ssh admin@<appliance-ip>` command.

The VM's first virtual terminal runs the LabFoundry recovery console; tty2 and
later terminals retain Photon login prompts. Its normal 80x30 layout includes
boot and runtime state for the appliance services, including Firewall desired
state. F3 and F4 each require a fresh Photon root password before opening `top`
or an audited root Bash session. Exiting either process restores and physically
redraws the appliance screen. Installed VMs use a 640x480 LabFoundry GRUB theme
with the official Photon OS logo; wheel deployment can synchronize the boot
branding but never reboots the appliance automatically. See
[Local appliance console](../../docs/appliance-console.md).

### Windows DNS for lab FQDNs

When browsing or testing lab services from the Windows host, use the
LabFoundry DNS listener as the resolver for the appliance-managed lab domain.
The namespace should match the DNS/DHCP domain configured in LabFoundry, and
the name server should be the appliance DNS listen address on the lab network.
For example, if the lab domain is `labfoundry.internal` and DNS listens on
`192.168.87.200`, run PowerShell as Administrator:

```powershell
# Remove existing NRPT rules for labfoundry.internal
Get-DnsClientNrptRule |
  Where-Object { $_.Namespace -eq ".labfoundry.internal" } |
  Remove-DnsClientNrptRule -Force

# Add the correct rule
Add-DnsClientNrptRule `
  -Namespace ".labfoundry.internal" `
  -NameServers "192.168.87.200"

# Clear Windows DNS cache
Clear-DnsClientCache
```

Verify the active NRPT rule:

```powershell
Get-DnsClientNrptRule |
  Where-Object { $_.Namespace -eq ".labfoundry.internal" }
```

Then test name resolution and browse with the service FQDN:

```powershell
Resolve-DnsName depot.labfoundry.internal
```

Open Edge with the FQDN, for example
`http://depot.labfoundry.internal/`. If Edge still reports
`DNS_PROBE_FINISHED_NXDOMAIN`, open `edge://net-internals/#dns` and click
`Clear host cache`.

On first boot, `labfoundry-data-disks.service` formats blank attached data
VMDKs, labels them as `LABFOUNDRY_DEPOT` and `LABFOUNDRY_BKUP`, writes
`/etc/fstab`, and mounts them at `/mnt/labfoundry-vcf-offline-depot` and
`/mnt/labfoundry-vcf-backups` before the LabFoundry control plane starts.

## Fidelity Notes

Workstation vmnets are isolated layer-2 segments. They are useful for appliance
management, SiteA, WAN, and trunk-like separation, but they do not expose the
same explicit Hyper-V access/trunk port VLAN controls. Treat the Workstation
lifecycle as parity for appliance behavior and host/client integration where the
vmnet topology can represent it; keep Hyper-V as the authoritative VLAN
access/trunk acceptance path until a Workstation VLAN-specific client strategy
is validated.
