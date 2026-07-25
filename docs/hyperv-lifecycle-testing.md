# Hyper-V Lifecycle Testing

Atlaso lifecycle interop tests use a separate Hyper-V lab set. They must not
reuse or destroy the normal `Atlaso` test appliance VM.

## Topology

The default lifecycle lab creates these VMs:

- `AtlasoLifecycle-Appliance`
- `AtlasoLifecycle-ClientA`
- `AtlasoLifecycle-ClientB`

The appliance attaches to `Atlaso-Mgmt`, `Atlaso-SiteA`,
`Atlaso-Trunk`, and `Atlaso-SiteB`. Client A attaches to its SSH
management switch, SiteA, an access VLAN on the trunk switch, and a dedicated
Atlaso management test NIC used only for the CA request path. Client B
attaches to a management switch plus the WAN-test switch.

The default SiteA test network is tagged VLAN 12 on appliance interface
`eth1.12` with gateway `192.168.12.1/24`. The separate trunk validation network
uses VLAN 50 on `eth2.50` with gateway `192.168.60.1/24`. These defaults match
the current appliance image state and avoid changing a physical parent that
already owns VLAN children.

The lifecycle script creates differencing disks under
`test-results/hyperv-lifecycle/<timestamp>/disks`, using the supplied appliance
and client VHDX files as read-only parents. It also creates per-client NoCloud
seed ISOs under `test-results/hyperv-lifecycle/<timestamp>/seed` so the client
VMs boot with SSH access and the test NIC DHCP refresh helper.

The default client parent image path is:

```text
image/hyperv/clients/alpine-cloud/atlaso-tiny-linux-client.vhdx
```

Prepare or refresh that image with:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/prepare-tiny-linux-client.ps1
```

The preparation script downloads Alpine's official UEFI cloud-init QCOW2 image,
verifies the `.sha512` checksum, and converts it to a dynamic Hyper-V VHDX with
`qemu-img`. The lifecycle script uses `pycdlib` to build the NoCloud seed ISOs;
if it is missing, the script installs it with `python -m pip install pycdlib`.

## Single-Command Run

Run from an elevated PowerShell session:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/invoke-lifecycle-test.ps1
```

The wrapper prepares the Alpine client VHDX if needed, selects the newest
appliance VHDX under `image/hyperv/output`, creates a unique lifecycle lab name,
runs the full interop scenario, prints a human-readable summary to the console,
writes `result.json`, and removes the VMs it created after the test. By
default, a successful first pass exports a settings backup, redeploys the
appliance VM from the parent VHDX, restores the backup on the fresh appliance,
applies the restored desired state, and reruns the host/client checks. The
restored pass also compares the pre-restore and post-restore Client A CA
certificate serial number and SHA-256 fingerprint, then exports the restored
settings state and compares the archived root CA plus CA-managed certificate
fingerprints against the original backup. Backup/restore portability fails
loudly when certificate identity changes. Pass `-SkipBackupRestoreTest` for the
older single-pass lifecycle run, and pass `-KeepVms` only when you want to
inspect a failed lab. Default two-pass runs write `initial/result.json`,
`restored/result.json`, `settings-backup.json`, and
`restored/restored-settings-backup.json` under the timestamped result directory.

The wrapper defaults the Atlaso admin and SSH passwords to the local Hyper-V
lab password. The VCF Backup SFTP test password defaults to a separate
policy-compliant value because Local Users enforces the appliance password
policy before OS sync. Override them with `-AdminPassword`, `-SshPassword`, and
`-VcfBackupPassword` when testing a different image.

The lifecycle web probe defaults to `https://<ApplianceIPAddress>`. Fresh
appliance images install nginx with CA-backed management HTTPS/443 and
redirect public HTTP/80 to HTTPS; override the probe with `-ApplianceUrl` only
when testing a different management front door.

Useful single-purpose commands:

```powershell
# Create or repair the Atlaso Hyper-V switches and management NAT only.
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/invoke-lifecycle-test.ps1 `
  -PrepareNetworksOnly

# Remove only AtlasoLifecycle* VMs; keep Hyper-V switches and NAT.
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/invoke-lifecycle-test.ps1 `
  -CleanupVmsOnly

# Remove Atlaso switches and management NAT; refuses if VMs are attached.
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/invoke-lifecycle-test.ps1 `
  -CleanupNetworksOnly
```

Pass `-CleanupNetworksAfterTest` to remove the switches/NAT after a successful
test as well as the VMs. Network cleanup is intentionally opt-in because the
normal `Atlaso` VM can also be attached to the shared Atlaso switches.

Use `-PlanOnly` first to print the VM names, VHDX parents, and result path
without creating or modifying VMs. Use `-ApplianceVhdxPath` when you want a
specific appliance image instead of the newest discovered VHDX.

## Low-Level Run

The wrapper delegates to `scripts/windows/hyperv/run-lifecycle-test.ps1`. That
lower-level script is still available when you need explicit control over every
input:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/run-lifecycle-test.ps1 `
  -ApplianceVhdxPath image/hyperv/output/atlaso-photon-hyperv/"Virtual Hard Disks"/Atlaso-Photon-Builder.vhdx `
  -AdminPassword '<bootstrap-admin-password>' `
  -SshPassword '<bootstrap-admin-password>' `
  -CleanupCreatedLab
```

The default path uses password SSH for both appliance and client probes. The
default appliance SSH user is `admin` because root SSH is disabled by default on
fresh appliance images. Appliance host-state probes log in as `admin` and run the
existing Linux checks through `sudo sh -lc`; pass `-ApplianceSshUser root` only
for images where Appliance Settings has enabled root SSH. The default client SSH
user is `alpine`. Key-based client auth is still available by passing an
existing `-SshKeyPath`; the matching `.pub` file is injected into both client
VMs. The scripts do not generate SSH keys automatically. When using Plink, the
Hyper-V script discovers and pins the appliance and client SSH host keys for the
test run so rebuilt VMs can safely reuse the same lab IPs without depending on
PuTTY's cached host key state.

The low-level script only cleans up when `-CleanupCreatedLab` is present. That
flag removes only VM names created during the current run that start with the
lifecycle lab prefix. Both scripts refuse to use reserved names such as
`Atlaso` and `Atlaso-Photon-Builder`.

## What It Validates

The lifecycle runner records structured evidence in
`test-results/hyperv-lifecycle/<timestamp>/result.json`:

- appliance boot, SSH, `atlaso.service`, `/openapi.json`, and dashboard API
- physical interface refresh, access NICs, trunk NIC, and VLAN desired state
- tty1 Atlaso console service ownership, masked tty1 getty, untouched tty2 getty template, installed console executable, and non-isolated recovery state
- DNS and DHCP desired state plus dnsmasq host-state checks
- first-boot `vcf-sdk` plus unprivileged appliance-user VCF PowerCLI
  version/import checks, including `Connect-VIServer` without sudo
- firewall settings, NAT, WAN policy, nftables, routes, and `tc` state
- WAN impairment evidence through a route-bound netem policy and a live
  `tc qdisc` assertion on the appliance WAN interface
- deterministic WAN packet-loss evidence by temporarily applying 100% loss,
  proving Client A cannot ping Client B across the WAN path, restoring the
  normal 25ms/5ms/0% loss policy, and proving the ping recovers
- CA enablement, root CA generation/download metadata, Client A CSR request
  submission over its lifecycle management test NIC, global `ca` appliance
  apply, issued certificate download from Client A, runner-side certificate
  signature/subject validation, and CA files under `/etc/atlaso`
- CA-backed management HTTPS desired state, the global `appliance_settings`
  apply unit, HTTP-to-HTTPS redirect behavior on the management front door, and
  HTTPS `/openapi.json` reachability with the locally issued appliance
  certificate
- passwordless admin web-terminal desired state on management plus the selected
  SiteA interface, applied OpenSSH user-CA trust, a ready terminal page and
  one-use ticket on both listeners, and proof that the extra listener returns
  404 for `/dashboard`
- VCF Backups SFTP desired state, `vcf-backup` Local Users password staging and
  OS sync, global `vcf_backups` appliance apply, OpenSSH drop-in host state, and
  a client-side SFTP probe from Client A to the SiteA appliance address
- VCF Offline Depot desired state, selected `vcf-depot` Local Users password
  staging, browser-session login, curl and wget Basic-auth artifact downloads,
  and password rotation proven through Local Users apply without reapplying the
  depot service
- ESX Storage with an attached blank VHDX, job-scoped format confirmation, ext4 UUID mount, generated A and AAAA targets, IPv4 and IPv6 storage VMkernel paths, NFS 3 and NFS 4.1 mounts, create/read/delete probes for every protocol/family pair, one dual-stack share, and appliance/ESX reboot persistence evidence
- client-side DNS/DHCP/routing probes when client SSH addresses are available
- settings backup export, appliance redeploy, settings restore, restored
  desired-state apply, downloaded Client A certificate comparison, and restored
  CA archive certificate comparison unless `-SkipBackupRestoreTest` is used

The runner submits only global `/appliance-apply` units. It does not call
service-specific apply routes.

ESX Storage acceptance records the global job IDs, stable disk identity and fingerprint, generated family names, direct A/AAAA answers, `exportfs -v`, listening TCP sockets, nftables `ip saddr`/`ip6 saddr` rules, ESX datastore listings, and post-reboot data probes. IPv4 and IPv6 must both pass before the feature PR is ready.

## Dry-Run Boundary

First-boot images may still have `ATLASO_DRY_RUN_SYSTEM_ADAPTERS=true`.
That is useful for control-plane smoke testing, but a real lifecycle interop run
should use an appliance image built with `-EnableRealSystemAdapters`. If a
deliberate dry-run pass is needed, pass `-AllowDryRunApply`; otherwise the
runner fails when an apply job reports dry-run.

## Test Roadmap

Keep the test stack split by ownership:

- PowerShell and Hyper-V orchestration tests should move into Pester. The
  intended entry point is `Invoke-Pester tests/pester/HyperVLifecycle.Tests.ps1`.
  Pester should cover wrapper parameter sets, plan-only output, VHDX discovery,
  switch/NAT preparation, VM cleanup safety, reserved VM protections, and mocked
  Hyper-V cmdlet behavior.
- Python appliance and guest assertions must remain pytest-covered. The
  `scripts/interop/lifecycle_test.py` runner owns HTTP/API flows, global
  `/appliance-apply`, result JSON evidence, SSH probes, DNS/DHCP checks,
  firewall/routing/NAT assertions, and client-side connectivity checks.

Use Pester tags for destructive or host-mutating scenarios. Normal Pester tests
should mock Hyper-V cmdlets; real VM-creating runs should be explicit integration
tests.
