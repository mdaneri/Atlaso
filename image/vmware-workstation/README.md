# Atlaso Photon OS VMware Workstation Image

The base image includes Python `vcf-sdk==9.1.0.0` and system-wide `VCF.PowerCLI==9.1.0.25380678`. Provisioning fails if
PowerCLI cannot import or `Connect-VIServer` is unavailable to the unprivileged bootstrap administrator. Provisioning
also disables and verifies PowerCLI CEIP participation at `AllUsers` scope; Appliance Settings can change that central
preference after deployment without product-specific prompts. The system module tree remains root-owned and writable
only by root, while every local `/usr/bin/pwsh` user can read and import its modules. Set
`ATLASO_POWERCLI_MODULE_SOURCE` to a pre-staged module directory for offline image builds; otherwise PSGallery is used.
Before a PSGallery install, the shared provisioner expands Photon's build-time `/tmp` tmpfs to 4 GiB so PowerCLI's
dependency extraction does not exhaust the default memory-backed temporary filesystem. The deployed appliance returns
to Photon's normal `/tmp` sizing after reboot.

This target builds a Photon OS 5.0 VMware Workstation VMX/VMDK appliance with the same Atlaso control plane provisioning
used by the Hyper-V image. Fresh appliances enable the integrated CA on deployed-VM first boot, serve the management
console/API over CA-backed HTTPS/443, and keep management HTTP/80 redirect-only. Network Boot remains the only served HTTP
payload.

## Prerequisites

- PowerShell 7.x (`pwsh`). Windows PowerShell 5.1 (`powershell.exe`) is not supported.
- WSL 2 installed and initialized before provisioning the default `Atlaso-Build` image-build distribution. See
  [Windows image-build WSL environment](../../docs/contribute/windows-image-build-wsl.md).
- VMware Workstation Pro with `vmrun.exe` available under `C:\Program Files\VMware\VMware Workstation`.
- VMware Workstation's bundled OVF Tool with `ovftool.exe` available under
  `C:\Program Files\VMware\VMware Workstation\OVFTool` when exporting OVF/OVA artifacts.
- Packer `>= 1.10`.
- `qemu-img` when preparing the tiny Alpine lifecycle client VMDK.
- Photon OS 5.0 ISO URL and checksum.
- At least 70 GiB free on the filesystem holding the Packer output. Final zero-filling temporarily expands both sparse
  payload VMDKs before compaction reclaims the zeroed blocks.

The template uses the Packer VMware Desktop plugin:

```hcl
source = "github.com/vmware/vmware"
```

Run `packer init` from this directory before validating or building.

From the repository root, `python scripts/check_deployment_assets.py --mode packer` performs that initialization plus
formatting and full wrapper-equivalent validation for both the VMware Workstation and Hyper-V templates. Canonical CI
runs the same protected inventory on its Windows Packer runner.

## Build

Use the wrapper instead of raw `packer build`; it creates the remastered Photon ISO with `photon-ks.json` and the Atlaso
GRUB auto-install entry. The original Photon source ISO is shared with the Hyper-V image path under
`image/common/source`; only the target-specific remastered kickstart ISO is written under this image directory.
`New-AtlasoPhotonKickstart` in `scripts/windows/common/Atlaso.PhotonImage.psm1` is the only kickstart source for both
providers. The focused image tests invoke that generator, parse the VMware and Hyper-V JSON outputs, and validate their
shared installer contract plus provider-specific packages and guest-service commands.
Workstation builds show the VMware console by default so boot/install progress is visible; pass `-Headless` for
unattended runs. The shared provisioner stages `pyproject.toml` with `scripts/version.py`, parses `[project].version` as
TOML, and requires the repository's strict `X.Y.Z` release format before it creates
`/opt/atlaso/releases/bootstrap-<version>`. If that metadata is missing, unreadable, malformed, or invalid, the build
log reports the specific version-policy error. The remastered kickstart disables `sshd.socket` and enables
`sshd.service`. Photon must not enable both conflicting units: the normal daemon provides deterministic
password-authenticated SSH for Packer after the installed-system boot. The Photon root/build password remains separate
from the Atlaso web bootstrap administrator password. The shared wrapper encodes that build credential before every
kickstart or Packer shell boundary and decodes it only to standard input, so apostrophes and common PowerShell or POSIX
shell metacharacters remain credential data instead of executable syntax. The template also stages
`requirements-appliance.lock` with the
application source so bootstrap dependency installation retains hash verification instead of falling back to unpinned
packages. It stages the third-party notice generator, vendored-component inventory, and Inventory Linux README used by
that inventory as mandatory build inputs rather than skipping notice generation when any input is missing. The shared
PowerShell profile is staged with the other common
image assets so provisioning can install the interactive `Get-AtlasoVault` helper. Notice lock verification inventories
only top-level virtual-environment distributions and ignores package-internal vendored metadata. Long TDNF operations
emit compact 30-second heartbeats with elapsed time and cache size instead of streaming terminal progress redraws
through Packer. Successful operations report their duration, while failures retain the TDNF exit status and replay a
normalized, bounded output tail.

Packer also stages the shared udev disk-identity rule and the VMware data-disk policy. The shared provisioner validates
and installs both from the staged source tree before the application sync populates `/opt/atlaso`, so this early
disk-safety setup never depends on files that have not been copied yet.

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/build-photon-image.ps1 `
  -IsoUrl "https://packages.vmware.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso" `
  -IsoChecksum "sha512:<checksum>"
```

The wrapper does not build or embed Inventory Linux. New templates leave it uninstalled so an administrator can use
**Download latest** to retrieve the signed independent release when needed. Contributors building Inventory Linux
itself use `scripts/windows/common/Build-AtlasoInventoryLinux.ps1` and its `-WslDistribution <name>` option.

Before `packer build -force` replaces the Workstation output directory, the wrapper checks for an existing output VMX
and unregisters it with `vmrun -T ws unregister`. The `vmrun.exe` path is resolved through the same Workstation
discovery path used by the rest of the VMware scripts, and the cleanup is scoped to this image target's configured
output directory.

For lifecycle/demo images that should use real appliance adapters:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/build-photon-image.ps1 `
  -IsoUrl "<photon-iso-url-or-path>" `
  -IsoChecksum "<packer-checksum>" `
  -EnableRealSystemAdapters
```

The built VMX keeps the first adapter on `-VmnetName` as management-only and adds a second `vmxnet3` adapter on
`-ServiceVmnetName` for service traffic. The service network defaults to Workstation's built-in host-only `VMnet1`. The
Packer creates a 40 GiB Photon OS disk and a sparse 20 GiB Atlaso system-content disk. Provisioning formats the second
disk as `ATLASO_SYSTEM`, mounts it by UUID, and places `/opt/atlaso` plus the appliance-wide PowerShell modules there.
The two 500 GiB application data disks remain empty OVF declarations, so the reusable builder contains no large blank
data-disk payloads. The build removes `python3-devel` after compatibility validation, clears build caches and staged
sources, zero-fills free blocks on both payload filesystems while retaining a 512 MiB safety reserve, deletes the fill
files, requests TRIM, and lets Packer compact both payload VMDKs. Zero-filling makes compaction deterministic even when
the VMware virtual disks do not advertise discard. After a successful build, the wrapper writes
a provenance JSON file beside the VMX containing the exact source commit, tracked-source state, and SHA-256 hashes and
sizes for the VMX and both VMDKs.

## Networking

The default Workstation builder and lifecycle scripts expect:

- management: `VMnet8`, with the Atlaso appliance address assigned by DHCP by default
- services: `VMnet1`
- SiteA: `VMnet2`
- WAN/SiteB: `VMnet3`
- trunk-like validation segment: `VMnet4`

Validate the current Workstation network inventory with:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/prepare-networks.ps1 `
  -PlanOnly
```

The Workstation management subnet intentionally stays separate from the Hyper-V lab subnet. The build wrapper reads the
selected VMware network before rendering Packer variables. For NAT/host-only vmnets it uses
`vmrun -T ws listHostNetworks`; for bridged `vmnet0` it falls back to the active Windows IPv4 interface, or the
interface named by `-BridgedInterfaceAlias`. Unless overridden, it chooses host offset `.30` for the temporary Photon
builder SSH address and uses DHCP for the final appliance management address. For NAT vmnets, the wrapper points the
temporary builder at the VMware NAT gateway DNS proxy, normally host offset `.2`, instead of copying unrelated host DNS
servers into the Photon kickstart. Pass `-BuilderStaticIp`, `-BuilderStaticGateway`, and `-BuilderStaticDns` together
only when a different builder address plan is intentional. Pass `-FinalMgmtAddress` and `-FinalMgmtGateway` only when a
static final management address is intentional. Pass `-ServiceVmnetName` only when the second appliance NIC should
attach to a different Workstation network.

Create or adjust missing lifecycle vmnets in VMware Virtual Network Editor. The scripts intentionally do not rewrite
global Workstation vmnet configuration because `vnetlib.exe` behavior is version-sensitive and can affect unrelated VMs.

## Local Wheel Deploy

After a code change that does not require rebuilding the Photon image, deploy a fresh Atlaso wheel to a running VMware
test appliance with:

```powershell
.\scripts\windows\vmware\deploy-wheel.ps1 -IpAddress 192.168.167.10
```

For the password-backed path, first authenticate the local 1Password integration, verify that exactly one Environment
named `Atlaso` exists, and confirm that it contains the concealed `DEFAULT_ADMIN_PASSWORD` variable without reading its
value. Copy that Environment's opaque ID from 1Password and pass only the ID to the supported Windows bridge:

```powershell
.\scripts\windows\vmware\deploy-wheel.ps1 `
  -IpAddress 192.168.167.10 `
  -OnePasswordEnvironmentId '<atlaso-environment-id>'
```

The bridge requires a 1Password CLI build that supports `op run --environment`; it starts the deployment script as the
single bounded child process and keeps the concealed value in that process environment and the existing password-backed
SSH stdin channel. It fails closed when the CLI, authorization, exact Environment, or variable is unavailable. Do not
set `DEFAULT_ADMIN_PASSWORD`, pass a password argument, create a local `.env` file, or use the retired
`ATLASO_DEPLOY_SSH_PASSWORD` fallback. Password-backed Paramiko connections load the user's SSH known-hosts database
and reject unknown host keys; approve the VM host key through the normal verified SSH workflow before deployment.

When the IP should be resolved from VMware Tools, pass the VMX path as a named argument:

```powershell
.\scripts\windows\vmware\deploy-wheel.ps1 `
  -VmxPath "image\vmware-workstation\test-vms\Atlaso-VMware\Atlaso-VMware.vmx"
```

Do not pipe the VMX path or put the `.vmx` path on a line by itself; PowerShell will try to run that file and report a
pipeline/document execution error. The helper builds `python -m pip wheel . -w dist`, uploads the newest `atlaso-*.whl`
with `scp`, installs it into `/opt/atlaso/.venv`, syncs `scripts/appliance/atlaso-helper` to
`/opt/atlaso/bin/atlaso-helper`, installs the VMware `atlaso.service` unit with its pre-start factory-reset recovery
hook, synchronizes every checked-in public release key from `image/common/update-trust` into
`/etc/atlaso/update-trust.d`, builds and installs the locally verified Inventory Linux package, restores virtualenv
permissions, restarts `atlaso.service`, and verifies `/openapi.json`
from inside the guest and from the Windows host. The helper and trust-key syncs are required because those root-owned
files live outside the Python virtualenv and are not updated by `pip install`. Build Inventory Linux first or pass
`-SkipInventoryLinuxSync` only for a code-only deployment that intentionally leaves the appliance package unchanged.
If the app takes longer to become reachable after restart, pass `-ReadinessTimeoutSeconds 120`.

`deploy-wheel.ps1` remains a development-only live-patching path. Production Appliance Update uses signed GitHub release
bundles, retained ABI-specific wheelhouses, `/opt/atlaso/releases/<version>`, and transactional rollback; it does not
use this direct wheel deployment path. Manual and scheduled checks/installations retain one parent task with separate
Atlaso Release, PowerShell Modules, and Photon OS child steps so failures and skipped Photon work remain independently
visible. The Packer build explicitly stages `image/common/update-trust` and fails when no valid public release key is
available.

The `atlaso.service` pre-start hook asks the constrained helper to resume a durable
`/var/lib/atlaso-privileged/factory-reset/request.json` marker before uvicorn starts. A reset interrupted by power loss
therefore
returns to the validated factory transaction before exposing the management control plane; an appliance without a
marker takes the no-op path.

## OVF / OVA Export

After a VMware image build, export a deployable OVF folder and OVA archive:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/export-ovf.ps1 `
  -SourceVmxPath image/vmware-workstation/output/atlaso-photon-vmware-workstation/Atlaso-Photon-Builder-VMware.vmx `
  -Name Atlaso-Photon `
  -Force
```

The export script runs OVF Tool, adds Atlaso vApp properties and appliance network mappings to the OVF descriptor,
regenerates the manifest, and packages the folder as an OVA unless `-NoOva` is passed. The descriptor preserves the OS
and Atlaso system-content VMDKs, then declares a 500 GiB empty VCF Offline Depot disk and a 500 GiB empty VCF Backups
disk. ESXi creates the latter two disks during deployment without payload files. The exporter requires exactly four
ordered disks, requires file-backed payloads for the first two, uses VMware Paravirtual SCSI, and removes the build-time
CD-ROM device. On first boot, the independent Atlaso `tty1` console and OVF management-network validation start before
data-disk discovery. After networking validates, `atlaso-data-disks.service` ignores the formatted system-content disk
and requires the two data disks at SCSI units 2 and 3 to expose topology-derived `atlaso-path-*` identities and exact
500 GiB capacities. It completes an all-disk preflight before formatting either disk and fails closed for any missing,
extra, reordered, ambiguous, or mismatched device. Verified blank disks become ext4 volumes labeled
`ATLASO_DEPOT` and `ATLASO_BKUP`; correctly labeled ext4 disks are never reformatted. The service writes their UUIDs to
`/etc/fstab` and mounts them at `/mnt/atlaso-vcf-offline-depot` and `/mnt/atlaso-vcf-backups`. The descriptor exposes
those fixed volumes while allowing only positively identified Atlaso-managed ESX Storage disks after initialization;
claimed existing ext4 whole disks require UUID-backed fstab persistence and a root-owned Atlaso claim.
The descriptor exposes two network mappings for
vSphere/ESXi import: `Atlaso Management Network` for the first adapter, which remains management-only as `eth0`, and
`Atlaso Services Network` for the second adapter used by DNS, DHCP, CA, depot, PXE, KMS, and other Atlaso-managed
services.

To upload the deployable OVF package to an existing GitHub Release, authenticate GitHub CLI and pass the release tag:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/export-ovf.ps1 `
  -Release
```

Release mode derives `v<version>` from the synchronized repository metadata, requires that tag to identify the clean
checked-out commit, resolves the destination GitHub repository from the current checkout, and replaces the generated
local OVF output before publishing. That implicit replacement applies only when `-OutputDirectory` is omitted and the
target is the canonical `image/vmware-workstation/ovf/<Name>` destination. An explicitly supplied existing destination,
including that same canonical path, requires `-Force`. Recursive replacement is always limited to a strict descendant
of `image/vmware-workstation/ovf`; filesystem, repository, image, VMware image, OVF-root, external, and reparse-point
targets are refused even with `-Force`. A new external destination may receive an export because no existing tree is
removed, but rerunning against it requires choosing a repository-owned output destination instead.

Every OVF asset is checked against GitHub's less-than-2-GiB per-asset boundary before upload. The descriptor, manifest,
and both payload VMDKs are uploaded as one set. A retry verifies every existing asset byte-for-byte and refuses partial
or different assets instead of overwriting them. The OVA is also uploaded when it fits; an oversized OVA is omitted
with a warning because it combines both otherwise deployable VMDKs into one archive. Publication also requires a clean
checkout whose `HEAD` is the locally available annotated release tag, a byte-matching build provenance record, and a
destination-repository tag resolving to the same commit. Release recovery parses the OVF and revalidates the two
file-backed payload disks plus the two empty 500 GiB data disks before accepting existing assets.

The OVF properties are intended for vSphere/ESXi import:

| Category            | Property                  | Required | Description                                                                                                      |
| ------------------- | ------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| Management network  | `atlaso.cidr`             | no       | Static management IPv4 CIDR for `eth0`, for example `192.168.10.10/24`; blank uses DHCPv4.                       |
| Management network  | `atlaso.gateway`          | no       | Required with static IPv4; must be on-link for the CIDR and differ from the management address.                  |
| Management network  | `atlaso.ipv6_enabled`     | no       | Boolean, default `false`. Enables management IPv6.                                                               |
| Management network  | `atlaso.ipv6_cidr`        | no       | Blank while IPv6 is enabled uses RA/SLAAC; a value selects static IPv6.                                          |
| Management network  | `atlaso.ipv6_gateway`     | no       | Optional with static IPv6; accepts an on-link or link-local address that differs from the management address.    |
| Management network  | `atlaso.dns_servers`      | no       | Optional resolver IPs separated by commas, spaces, or new lines. Blank DHCP deployments keep lease-provided DNS. |
| Appliance identity  | `atlaso.fqdn`             | yes      | Appliance FQDN applied to Photon OS and Atlaso desired state.                                                    |
| Initial credentials | `atlaso.admin_password`   | yes      | Initial Atlaso web `admin` password.                                                                             |
| Initial credentials | `atlaso.root_password`    | yes      | Photon root console password. Root SSH remains disabled by default.                                              |
| Initial credentials | `atlaso.root_ssh_enabled` | no       | Boolean, default `false`. Enables root password SSH immediately on first boot.                                   |

On first boot from an OVF/OVA deployment, `atlaso-vmware-ovf-customize` reads those properties through VMware Tools
before Atlaso starts. A blank IPv4 CIDR writes `DHCP=ipv4`; a supplied CIDR and gateway configure static IPv4. IPv6 can
be disabled, automatic through RA/SLAAC, or static. The customizer also writes family-correct firewall access, resolver
overrides when supplied, hostname, root password, optional root SSH state, and bootstrap admin password once, then
records a redacted marker under `/var/lib/atlaso`. Passwords are consumed as deployment inputs and are not printed in
the marker or customization log. After all first-boot configuration succeeds, the customizer writes a redacted pending
marker, clears the consumed OVF environment through VMware Tools, and atomically promotes the pending file to the
applied marker. This removes raw-clone credentials from the host-side `guestinfo.ovfEnv` VMX setting while keeping a
power interruption between scrub and promotion recoverable on the next boot. A failed scrub remains unmarked and is
retried from pending success with the initialization lock held and the network-review handshake cleared. Cleanup writes
an explicit empty string through `vmware-rpctool` or `vmtoolsd`; a cleanup failure never returns to DHCP review because
the management state already applied. VMware Tools can read the cleared value back as the exact `""` sentinel; Atlaso
normalizes that representation to answered-empty before confirmation. Mutation failures identify only a bounded,
non-secret initialization layer in
the customization log. The pending file and its parent directory are synchronized before the external credential scrub;
all preceding host filesystem mutations are synchronized before pending success is recorded, and the applied-marker
promotion synchronizes the directory again. The early tty1 console is restarted after clone-specific appliance secret
rotation and before the initialization lock is removed, so it cannot retain baked keys in process memory. If a raw clone
accidentally reuses a disk whose applied marker already exists, the customizer
does not reapply the injected credentials, but it does clear the injected OVF environment before its marker early exit so
those plaintext values cannot remain in the cloned VMX. Inconclusive VMware RPC reads are retried rather than treated as
proof of an empty property. Applied-marker cleanup also requires 30 consecutive successful empty reads before unlocking
tty1, so delayed clone properties are scrubbed. Raw-clone injection carries a non-secret deployment identifier; if a
source was interrupted with only a pending marker, a different injected identifier invalidates that stale pending state
before the clone applies its own properties. A nonempty ID-less OVF environment is also applied instead of promoting
pending source state, so
release OVA redeployment remains safe. Pending recovery requires 30 consecutive successful empty guestinfo reads, and
applies properties that appear during that confirmation window. Use only pristine, never-booted image outputs as clone
sources.

When VMware Tools answers successfully but returns no envelope, the customizer requires 30 consecutive empty reads
before classifying the boot as non-OVF. It writes the durable
`/var/lib/atlaso/vmware-no-ovf-initialization.applied` marker, removes any initialization/review handshake, logs
**No OVF deployment properties supplied; using image defaults.**, and lets the ordinary console and appliance services
continue. An unanswered Tools channel never contributes to that confirmation. Malformed XML, present-but-incomplete
properties, and invalid properties remain fail-closed. The marker makes reboot idempotent, but a later nonempty envelope
durably replaces the non-OVF classification and enters the normal OVF validation/customization path.

The customizer validates IPv4, IPv6, gateway, and DNS relationships before any host mutation. Interface and gateway
addresses must be usable unicast values rather than unspecified, loopback, multicast, or reserved addresses. If
validation fails, the
Atlaso `tty1` console displays **First-time initialization — Network configuration requires review**, prepopulates only
non-secret OVF values, and accepts a corrected network configuration. Networkd, data-disk initialization, HTTPS
bootstrap, and Atlaso remain held until the correction passes the same shared validation and applies successfully. The
applied marker is absent until success, so another console correction remains possible without redeploying the OVA.
A root-owned lock staged in the VMware image disables ordinary privileged tty1 actions until the deployment root
password applies. Non-network properties validate before network recovery is offered, and a later boot clears stale
handshake files when the applied marker proves customization finished.

If an administrator later corrects management networking from the tty1 console, Atlaso explicitly regenerates Network
and Firewall state from the corrected CIDR, retries an unfinished first-boot HTTPS bootstrap, applies Appliance
Settings, validates nginx, restores nginx and Atlaso when needed, and proves stable loopback readiness for the applied
HTTP-only or HTTPS management mode before the console reports success. Check
`https://<management-address>/openapi.json` when HTTPS is enabled or `http://<management-address>/openapi.json` in
HTTP-only mode.

The OVF descriptor stores these as unqualified property IDs inside the `atlaso` product class. ESXi qualifies them once
in the guest OVF environment as `atlaso.<property>`; do not repeat the class prefix in each property ID.

## Lifecycle

Run the Workstation lifecycle wrapper after building an appliance VM:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/invoke-lifecycle-test.ps1
```

The wrapper writes evidence under `test-results/vmware-workstation-lifecycle/<timestamp>`. Unless `-ApplianceIPAddress`
is passed, it waits for VMware Tools to report the DHCP management address and records it in `discovered-appliance.json`
before running HTTP and SSH probes. It keeps the Python appliance assertions shared with the Hyper-V lifecycle runner.

Pass `-PlanOnly` to print the selected VMX, client VMDK, vmnets, and result path without creating VMs.

## Boot A Test Appliance

Create and start a normal Workstation test appliance from the latest built VMX:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/create-atlaso-test-vm.ps1 `
  -Redeploy `
  -ResetDataDisks `
  -WaitForIp `
  -TrustRootCa
```

The wrapper requires the cloned Photon OS and Atlaso system-content VMDKs at SCSI units 0 and 1, then creates fresh
Depot and Backups data VMDKs at units 2 and 3 when needed. `-ResetDataDisks` removes those data VMDKs before recreating
them only when their canonical paths are strict, non-reparse-point descendants of the selected VM output directory.
Both creation-size arguments accept only `500GB`; an explicitly reused data VMDK must also expose an exact 500 GiB
virtual capacity in its descriptor or deployment stops before cloning the target VM.
`-Redeploy` requires the exact named VMX and exactly one well-formed, matching `displayName`; a missing, malformed,
duplicate, or mismatched target preserves the
directory and returns an actionable failure. Cleanup checks the running and registered Workstation inventories by
Windows filesystem identity, stops and unregisters only when needed, verifies both transitions, and preserves all
artifacts if an inventory path is malformed or cannot be resolved, or if `vmrun` fails or returns unverifiable state.
Pass `-IncludeLabNetworkAdapters` only after `VMnet2`, `VMnet3`, and `VMnet4` exist for the
SiteA, WAN/SiteB, and trunk-like lifecycle networks. `-TrustRootCa` downloads the freshly deployed appliance root CA,
removes stale Atlaso root CAs from the current-user Trusted Root store, and trusts the new root so Edge and the Codex
integrated browser accept the first-boot HTTPS cert. The root CA is generated by `atlaso-bootstrap-https.service` on
each deployed VM's first boot, not baked into the reusable Packer-built VMX. The wrapper waits up to five minutes by
default for the first-boot CA endpoint, retrying transient connection and service-readiness failures. Pass
`-TimeoutSeconds <seconds>` to adjust both IP discovery and CA readiness waits. Partial downloads are removed
best-effort between retries through .NET file APIs, including when the current user's temporary directory contains a
dotted profile name or a valid DOS 8.3 short-path representation. Cleanup cannot replace the original readiness error
or stop the retry loop. After the VM starts, the wrapper prints a connection summary with the HTTPS console URL,
Swagger URL, OpenAPI URL, root certificate URL, and `ssh admin@<appliance-ip>` command.

Both this wrapper and the Workstation lifecycle runner inject a complete `guestinfo.ovfEnv` document into a raw cloned
VMX before power-on. The default document selects IPv4 DHCP, leaves resolver overrides blank, keeps IPv6 and root SSH
disabled, and supplies the required appliance identity and first-boot credentials. This gives raw Workstation clones the
same fail-closed initialization contract as an OVA deployment instead of leaving the customizer waiting for properties
that only an OVF deployment normally supplies. A generated non-secret deployment identifier distinguishes each raw
clone attempt during pending-marker crash recovery. Use `-FirstBootFqdn`, `-AdminPassword`, and `-RootPassword` to
override the normal test-VM values; the lifecycle wrapper uses its existing admin-password input. Password values are written
only to the guestinfo-backed VMX setting until successful first-boot consumption clears it; they are never printed in
plan, result, or connection-summary output. Raw-clone credential overrides must be at least 12 characters and cannot
contain leading, trailing, XML control, or non-XML characters that would change during OVF attribute parsing.

The VM's first virtual terminal runs the Atlaso recovery console; tty2 and later terminals retain Photon login prompts.
Its normal 80x30 layout includes boot and runtime state for the appliance services, including Firewall desired state. F3
and F4 each require a fresh Photon root password before opening `top` or an audited root Bash session. Exiting either
process restores and physically redraws the appliance screen. Installed VMs use a 640x480 Atlaso GRUB theme with the
official Photon OS logo; wheel deployment can synchronize the boot branding but never reboots the appliance
automatically. See [Local appliance console](../../docs/appliance-console.md).

### Windows DNS for lab FQDNs

When browsing or testing lab services from the Windows host, use the Atlaso DNS listener as the resolver for the
appliance-managed lab domain. The namespace should match the DNS/DHCP domain configured in Atlaso, and the name server
should be the appliance DNS listen address on the lab network. For example, if the lab domain is `atlaso.internal` and
DNS listens on `192.168.87.200`, run PowerShell as Administrator:

```powershell
# Remove existing NRPT rules for atlaso.internal
Get-DnsClientNrptRule |
  Where-Object { $_.Namespace -eq ".atlaso.internal" } |
  Remove-DnsClientNrptRule -Force

# Add the correct rule
Add-DnsClientNrptRule `
  -Namespace ".atlaso.internal" `
  -NameServers "192.168.87.200"

# Clear Windows DNS cache
Clear-DnsClientCache
```

Verify the active NRPT rule:

```powershell
Get-DnsClientNrptRule |
  Where-Object { $_.Namespace -eq ".atlaso.internal" }
```

Then test name resolution and browse with the service FQDN:

```powershell
Resolve-DnsName depot.atlaso.internal
```

Open Edge with the FQDN, for example `http://depot.atlaso.internal/`. If Edge still reports
`DNS_PROBE_FINISHED_NXDOMAIN`, open `edge://net-internals/#dns` and click `Clear host cache`.

On first boot, `atlaso-data-disks.service` verifies the fixed SCSI units, stable topology identities, exact 500 GiB
capacities, and exact platform disk set before formatting the assigned blank VMDKs. It fails before `mkfs` on missing,
extra, reordered, ambiguous, or mismatched disks. Correctly labeled ext4 volumes remain untouched; both volumes are
mounted by UUID at `/mnt/atlaso-vcf-offline-depot` and `/mnt/atlaso-vcf-backups` before the control plane starts. Once
both are initialized, only positively identified Atlaso-managed ESX Storage disks may join the platform disk set.
Disk-preflight failure blocks nginx, the HTTPS bootstrap, Atlaso control plane, and worker.

## Fidelity Notes

Workstation vmnets are isolated layer-2 segments. They are useful for appliance management, SiteA, WAN, and trunk-like
separation, but they do not expose the same explicit Hyper-V access/trunk port VLAN controls. Treat the Workstation
lifecycle as parity for appliance behavior and host/client integration where the vmnet topology can represent it; keep
Hyper-V as the authoritative VLAN access/trunk acceptance path until a Workstation VLAN-specific client strategy is
validated.
