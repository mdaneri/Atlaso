---
title: VMware Workstation Lifecycle Testing
description: Run and interpret the Atlaso VMware Workstation lifecycle interoperability suite.
audience:
  - contributor
  - maintainer
status: current
---

# VMware Workstation Lifecycle Testing

The shared lifecycle host-state checks verify that first-boot appliances retain `vcf-sdk==9.1.0.0`,
`VCF.PowerCLI==9.1.0.25380678`, and `Connect-VIServer` after the wheel-only test deployment. The PowerCLI import and
command check run directly as the unprivileged appliance SSH user rather than through sudo.

For a wheel-only deployment to the canonical test VM, use `scripts/windows/vmware/deploy-wheel.ps1` with the secure
Windows 1Password handoff documented in the [full technical reference](full-technical-reference.md). Authenticate the
local integration, verify the unique `Atlaso` Environment and concealed `DEFAULT_ADMIN_PASSWORD` variable by name,
then pass only its opaque Environment ID through `-OnePasswordEnvironmentId`. The handoff requires the supported
`op run --environment` capability and provisions the value only into the bounded Paramiko deployment child, preserves
SSH known-host verification, and fails closed when authorization or any required Environment input is unavailable.
Key-backed Windows
transfers keep `scp` sources and destinations separate and cross the PowerShell login shell through a secret-free
base64 `sh -lc` wrapper. Password-backed SSH supports one password-only keyboard-interactive challenge, rejects OTP/MFA
prompts, and uses a separate deployment timeout from the readiness allowance with a non-PTY
`sudo -S` handoff. Do not pass a password argument, create a local `.env` file, or use the retired
`ATLASO_DEPLOY_SSH_PASSWORD` fallback. The PowerShell parent performs local build and input preparation without the
credential, then invokes the Paramiko helper directly as `op run --environment <id> -- <python> ...`; `op` supplies
`DEFAULT_ADMIN_PASSWORD` only to that bounded child, which removes it from its process environment immediately after
capture. The child starts Python with `-I -S` and an explicit dependency path so startup hooks and inherited
`PYTHONPATH` cannot observe the variable. An interactive `op run` shell is not a supported substitute for the exact
Environment handoff.

Atlaso can run a VMware Workstation lifecycle lab alongside the Hyper-V lab. The Workstation path uses VMX/VMDK
artifacts and `vmrun.exe`, then delegates appliance behavior checks to the shared Python lifecycle runner.

Run all Windows commands in PowerShell 7.x (`pwsh`). Windows PowerShell 5.1 (`powershell.exe`) is not supported.
The single-command wrapper enforces that runtime, resolves the installed `pwsh` application, and launches its lifecycle
child in PowerShell 7 so the default cleanup path cannot fall back to Windows PowerShell 5.1. A missing `pwsh`
installation fails before any lifecycle VM is created.

Appliance VMX files set `disk.EnableUUID = "TRUE"` so Photon exposes stable `/dev/disk/by-id` identities. ESX Storage
blank-disk claims depend on those identities and reject transient `/dev/sdX` names.

## Topology

The default lifecycle lab creates isolated VM directories under:

```text
test-results/vmware-workstation-lifecycle/<timestamp>/vms
```

The appliance VMX is copied from the selected Workstation image output. Client VMs use an Alpine cloud VMDK prepared
from the same upstream QCOW2 source as the Hyper-V lifecycle client. The payload and SHA-512 metadata are cached only as
a verified pair: corrupt entries are removed on an ordinary rerun, downloads stay in unique partial files until
validation succeeds, and promotion is scoped to the exact expected cache files. The default Alpine artifact uses the
versioned `v3.24` release URL and a repository-pinned SHA-512 digest; custom images must pass their own
`-ExpectedSha512` pin.

Default vmnets:

- `VMnet8` for management, with the appliance address assigned by DHCP by default
- `VMnet2` for SiteA
- `VMnet3` for WAN/SiteB
- `VMnet4` for trunk-like validation

Check the current Workstation host network inventory with:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/prepare-networks.ps1 `
  -PlanOnly
```

If vmnets are missing, adjust them in VMware Virtual Network Editor before running the interop test. The image build
wrapper reads the selected management vmnet before rendering Packer variables; for bridged `vmnet0`, it uses the active
Windows IPv4 interface or the interface named by `-BridgedInterfaceAlias`.

The Workstation management subnet must remain separate from the Hyper-V management subnet. Unless overridden, the build
wrapper chooses `.30` in that subnet for temporary builder SSH, then leaves final appliance management on DHCP and
discovers the runtime address through VMware Tools.

## Build The Appliance

Build the Workstation appliance with:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/build-photon-image.ps1 `
  -IsoUrl "<photon-iso-url-or-path>" `
  -IsoChecksum "<packer-checksum>" `
  -EnableRealSystemAdapters
```

The wrapper shares Photon ISO remastering, kickstart rendering, checksum validation, and Packer var-file generation with
the Hyper-V build wrapper. Both wrappers use `image/common/source` for the original Photon ISO download cache so the
source ISO is not duplicated under each target. The Workstation image installs `open-vm-tools`; the Hyper-V image keeps
the `hyper-v` package and Hyper-V guest daemons. The Workstation build wrapper opens a visible VMware console by
default. Use `-Headless` only when an unattended build is preferred.

## Single-Command Run

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/invoke-lifecycle-test.ps1
```

The wrapper selects the newest appliance VMX under `image/vmware-workstation/output`, prepares the tiny Alpine client
VMDK when needed, creates a unique `AtlasoWorkstationLifecycle-*` lab, runs the initial lifecycle scenario, and by
default runs the restored backup/restore pass. Pass `-SkipBackupRestoreTest` only when the older single-pass behavior is
intended. Unless `-ApplianceIPAddress` is passed, the wrapper waits for VMware Tools to report the appliance's DHCP
management IPv4 address and derives the appliance URL from that discovered address.

Tiny-client preparation exits nonzero and emits no prepared-image JSON when `qemu-img` conversion or inspection fails.
If the current run created an incomplete or unverified VMDK, the wrapper removes that exact output before returning the
failure so a later lifecycle run cannot accept it as prepared.

Before it powers on the raw appliance clone, the runner injects the complete Atlaso first-boot OVF environment that a
normal ESXi or Workstation OVF deployment would provide. The lifecycle lab uses IPv4 DHCP with blank DNS overrides,
disabled IPv6, a generated lab FQDN, and the existing lifecycle admin-password input for both required
first-boot credential properties. Each injection also carries a generated non-secret deployment identifier so an
interrupted source VM's pending state cannot be mistaken for the new clone's attempt. The value is stored only in the
clone's guestinfo-backed VMX setting and is excluded from plan and result artifacts. Invalid identity or password inputs
fail before the runner creates the lab directories. Root SSH remains disabled for the default `admin` appliance SSH user;
selecting `-ApplianceSshUser root` explicitly enables it in the same first-boot document.
After customization, appliance guest operations use that applied admin password while `-SshPassword` remains dedicated
to the client VMs, so callers may continue to supply different appliance and client credentials.

For focused deployed OIDC acceptance independent of the full service-network topology, pass `-OidcOnly`. The wrapper
still clones the selected appliance, installs the exact branch wheel, proves appliance readiness, and runs the OIDC
Authorization Code acceptance check. It skips unrelated multi-NIC service configuration, client VM creation and probes,
and the backup/restore pass.

Useful commands:

```powershell
# Print selected paths and topology without creating VMs.
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/invoke-lifecycle-test.ps1 `
  -PlanOnly

# Validate Workstation vmnet inventory.
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/invoke-lifecycle-test.ps1 `
  -PrepareNetworksOnly

# Stop and remove existing AtlasoWorkstationLifecycle* VMs.
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/invoke-lifecycle-test.ps1 `
  -CleanupVmsOnly
```

## Cleanup Safety

Workstation cleanup removes a VM directory only after validating that every target VMX is inside the exact
non-reparse-point artifact root. It reads checked running and registered VM inventories, resolves each canonical absolute
VMX to its Windows volume and file identity, stops a listed running VM, unregisters a listed registration, and confirms
that each transition completed before deleting files. Filesystem aliases such as DOS 8.3 or mapped-drive forms therefore
cannot make a running or registered target appear unrelated. Already-stopped and already-unregistered VMs remain
idempotent cleanup cases. A nonzero command, malformed (including asymmetrically quoted paths or nonnumeric and
separator/whitespace-corrupted registration keys) or unresolvable inventory,
target still listed after an apparently successful transition, or missing VMX preserves the artifact directory and
makes the command fail. Registration inventory reads are terminating, so access denial or an incomplete I/O read cannot
be interpreted as an empty or partial registered-VM set. VMX identity reads use the same terminating contract, preventing
a partial file from validating one displayed name while unread content remains unresolved. Cleanup also requires the
Workstation `inventory.vmls` snapshot to contain only well-formed `vmlistN.config` entries whose VMX filesystem
identities can be resolved. The independent `index.count` and `indexN.id` search index must describe the same complete
VMX identity set, so a header-only or partially rewritten snapshot fails closed. VMware Workstation does not expose a
registered-VM listing through `vmrun`, so cleanup does not invoke the unsupported `listRegisteredVM` command. After the
final recursive VMX-set scan, cleanup refreshes the
checked `vmrun list` running inventory and the Workstation registration file as its last safety gate before deletion.
When lifecycle
execution and cleanup both fail, the final error reports the original scenario failure together with the cleanup failure
and preserved path.

The read-only Workstation registration inventory may reside beneath a redirected `%APPDATA%` junction or symbolic link.
The non-reparse-point requirement remains enforced on the artifact root that cleanup recursively deletes.
Recursive deletion errors are terminating, and cleanup reports success only after confirming that the artifact root is
absent.

The Photon image builder applies the same inventory checks to the exact resolved `-OutputDirectory`. Absolute custom
output directories remain supported even when they are outside the Packer directory; cleanup binds deletion to that
exact configured path and will not accept a sibling or parent path instead.

The normal test-VM `-Redeploy` path also requires the exact named VMX and exactly one well-formed, matching
`displayName`; missing, duplicate, malformed, or conflicting assignments preserve the existing directory.
`-ResetDataDisks` accepts only strict canonical
descendants of the selected VM output, so sibling-prefix and reparse-point paths are refused.

## Normal Test VM

For a normal Workstation appliance VM, separate from the lifecycle lab, use:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/create-atlaso-test-vm.ps1 `
  -Redeploy `
  -ResetDataDisks `
  -WaitForIp `
  -TrustRootCa
```

That is the Workstation counterpart to `scripts/windows/hyperv/create-atlaso-test-vm.ps1`. It defaults to the management
vmnet only; pass `-IncludeLabNetworkAdapters` after creating the SiteA, WAN/SiteB, and trunk-like vmnets.
The wrapper injects the same complete DHCP-first OVF environment before power-on; use `-FirstBootFqdn`,
`-AdminPassword`, and `-RootPassword` when the default local test identity or credentials are not appropriate.
Credential overrides must be at least 12 characters, contain no leading, trailing, tab, carriage-return, or newline
whitespace, and contain only XML-representable characters so the OVF value round-trips unchanged.
`-TrustRootCa` waits for the first-boot CA endpoint, removes partial downloads best-effort between retries, validates the
self-signed Atlaso root CA, and imports it into the current-user Trusted Root store. The temporary-file cleanup remains
idempotent for missing files and safely handles dotted user-profile directories and valid DOS 8.3 short paths, so a
cleanup race or path alias cannot stop the readiness retry loop. Use `-TimeoutSeconds` to change the IP and CA waits.

## Fidelity Boundary

For ESX Storage appliance acceptance, attach an extra blank VMDK to the normal Workstation test appliance, initialize it
only through global `esx_storage` apply, and apply the matching DNS/DHCP and Firewall units. Record the job ID,
`/dev/disk/by-id` fingerprint, UUID mount, generated A/AAAA names, `exportfs -v`, TCP/111/2049/20048 sockets, nftables
family rules, and persistence after appliance reboot. Workstation proves real Photon disk/NFS/DNS/firewall behavior; the
Hyper-V/ESX 9 lifecycle remains authoritative for IPv4 and IPv6 VMkernel mounts and datastore I/O.

VMware Workstation vmnets provide isolated layer-2 segments, but they do not match Hyper-V's explicit access/trunk VLAN
port model. The Workstation lifecycle therefore validates the appliance workflow, management reachability, service apply
behavior, tty1 console ownership with tty2 left available for normal login, backup/restore portability, and host/client
integration where separate vmnets are equivalent. Keep Hyper-V lifecycle results as the authoritative acceptance
evidence for VLAN access/trunk behavior until a Workstation-specific tagged-client strategy is added and proven.
