---
title: Certificate handoff address-control procedure
description: Trusted-host VMware procedure for certificate address handoff acceptance.
audience:
  - maintainer
status: current
---

# Certificate handoff address-control procedure

This procedure defines a trusted-host acceptance path for certificate address handoff on an ISO-installed appliance.
It uses one task-owned Workstation appliance and one task-owned Linux peer attached to the same dedicated private LAN
segment. The maintainer trusts the Windows Workstation host administrator to account for that host's VMs and to avoid
changing the test topology during acceptance. The evidence supports a controlled lab result; it is not proof against
the trusted host administrator or another administrator able to reconfigure Workstation.

The appliance's test interface has no adapter outside this segment, and the segment has no bridge, NAT, host adapter,
or routed connection to another network. The peer's other adapter, when used to reach the appliance through pinned SSH,
stays on a separate management network; do not bridge or route it into the test segment. Only the appliance and peer
may have adapters on the test segment. A different LAN member, VMX binding, source, certificate pin, receipt, or
reservation invalidates the run.

The acceptance cases below cover the existing fixture: one dedicated IPv4 management interface, `eth0`, with IPv6
disabled and an explicitly configured static baseline. They do not establish Access-management acceptance for #852 or
support for other interface roles or address families.

## Trusted host and admission

The trusted-host boundary is the human maintainer with authority over the Workstation host, its VM inventory, VMX
files, LAN segment registration, and test task. That maintainer can authorize the test, observe the host state, and
keep other host operators from changing the topology during the run. Acceptance assumes this administrator follows
the recorded procedure. It does not claim an independent hypervisor control plane or protection from that administrator.

This procedure covers the current native scenario only: one IPv4 dedicated-management interface named eth0, with IPv6
disabled. It does not establish acceptance for another interface, role, address family, or access-management
configuration.

Before the first appliance configuration change, establish all of the following:

- The lab is authorized, isolated, and tied to the exact repository, issue, pull request, reviewed source commit, and
  original task identity. Bind the exact ISO appliance VMX and root identity to immutable original creation-intent
  and ownership receipts. Preserve original appliance receipts, paths, and SHA-256 digests in durable evidence
  outside every disposable VM directory.
- Before any appliance SSH readback or mutation, capture its public SSH host-key fingerprint through the authorized
  console of the exact admitted VM, independently matched to its original VMX, root identity, and ownership receipt.
  Record that fingerprint, its observation source/time, and receipt binding in the durable evidence. Require strict
  matching to this recorded pin for every appliance SSH connection, including connections after an address change.
  Do not establish trust from the candidate endpoint alone or automatically accept a new or changed host key.
  If this pin cannot be established, use only that independently verified VM console for guest observations; record
  the console identity and transport choice before mutation. If neither path is verified, refuse the test.
- The appliance adapter and candidate interface are the intended ones. Record the VMX adapter-to-LAN mapping, the
  observed appliance MAC and interface, the candidate IPv4 address and prefix, gateway, and the prior static
  management configuration.
- The Linux peer is a task-owned resource. Bind its original creation and source-disk identity,
  private-LAN adapter, address, and pinned SSH host-key fingerprint. Record the original peer creation-receipt path
and digest, selected source-disk path and digest, and public SSH key fingerprint used for admission. Never put a
private key, password, token, authenticated URL, or other secret in evidence.
- The test LAN is a newly created, task-owned Workstation LAN segment. Bind its ID and name to its original creation
  receipt and SHA-256. Read back both appliance and peer VMX adapter assignments, including the segment ID and MAC.
  Inventory Workstation VMs and task VM roots known to the host; verify that exactly these two VM identities reference
  the segment. Check the appliance and peer adapters are connected, and verify the appliance has no other connected
  adapter. Record the inventory and adapter readbacks with observation time. The host administrator attests that this
  inventory covers the host's VM locations and prevents untracked host operators from adding a member during the run.
  Vacant inventory slots and stale missing VMX paths are counted separately; every existing registration and running
  VM is still checked. A vacant slot must contain an exactly empty path, and duplicate slot indexes are refused.
- Select and record an unused private candidate address and a distinct peer address. Reserve the candidate for the
  admitted appliance MAC in the peer's bounded DHCP configuration, or record the equivalent fixed-address plan. The
  peer's DHCP service binds only to its test-segment adapter and leases only the admitted appliance MAC. Verify the
  running configuration and current lease from the pinned peer. Do not treat an unresponsive address, VMware Tools
  address, or a lease alone as proof that a machine is attached to the segment.
- The appliance's original HTTPS certificate identity, trusted public CA digest, interface fields, route, and DNS
  baseline are captured through the normal authenticated Atlaso interface. Keep only public certificate material and
  sanitized observations.
- Capture the source and installed-runtime facts described in the
  [ISO bootstrap procedure](#bootstrap-the-iso-static-baseline) before changing desired state. The original route
  probe must prove routing intent absent, with the required route,
  rule, NAT, port-forward, WAN-policy, and route-role interface counts at zero and routing/WAN settings disabled.
  The installed helper, wheel, appliance SSH host key, ISO VM ownership, and source commits must match their pinned
  inspection receipts. The initial static Apply must complete successfully before running either address scenario.

This procedure records the host administrator's bounded inventory and topology checks under an explicit trusted-host
assumption. It does not infer an adversarial guarantee from VMware Tools or DHCP. Keep the test segment free of
bridges, NAT, host adapters, and routes to other networks. Recheck the VM inventory, each adapter's LAN assignment,
the address reservation, and current lease before and after every Apply transition. Watch for host and guest power,
VMX, adapter, segment, route, or source changes throughout the run. If any check fails, changes, or cannot be repeated,
stop before another Apply, preserve state, and invalidate the run; re-admit from the original receipts before retry.

## Maintainer evidence record

Keep one append-only lab record in the maintainer-approved durable evidence location, outside the removable lab root.
Record the task, issue, PR, repository, source commit, appliance and peer identities, LAN identity, address plan,
original receipt digests, public CA digest, appliance and peer SSH host-key fingerprints or the verified appliance
console binding, trusted-host inventory source, and each observation and action in order. Preserve the original
bytes of creation receipts; calculate and record their SHA-256 digests before use. Do not edit, relabel, or recreate
receipts from another task.

The trusted-host address-proof producer binds each run to its current task and PR, ISO appliance, peer, LAN creation
receipt, source/runtime digests, public CA, SSH pins, address plan, and time-stamped topology observations. Receipts
from the earlier PR #871 independent-control path remain bound to that task. The trusted-host mode is explicit and
must not weaken legacy independent-control admission.

When the reviewed harness advances after lab creation, retain the original receipt bytes and creation source in
`resource_source_commit`; `source_commit` identifies the currently reviewed harness. Admission requires the creation
source to remain an ancestor of that harness. Never change a receipt's source to match a later head.
The peer fixture and LAN retain their own creation source; their source need not equal the original ISO appliance's
independently admitted creation source. Legacy independent-control admission still requires matching VM sources.
Trusted-host inventory admission verifies the original peer fixture's digest, task, VM and LAN selectors before using
its LAN creation source, and requires that source to remain an ancestor of the reviewed harness.

## Prepare the ISO appliance adapter

For a new fixture, create and install the appliance through `invoke-installation-iso-test.ps1` with
`-Scenario AutoReboot` and `-InspectInstalled`. For the existing manually installed ISO appliance, verify its
installation with `-Scenario BootInstalled -InspectInstalled` and the original creation and disk-baseline selectors.
Preserve the original creation, disk-baseline, installed-boot, and public identity evidence. The installed inspection
binds the image's software/source identity and the appliance SSH host-key pin to that original VM. Do not substitute
the ordinary lifecycle `-CertificateOnly` clone.

The installed inspection must be complete before the native plan is prepared. It identifies the ISO's original
resource source, the installed software source and wheel, and the appliance SSH host-key fingerprint. Preserve these
values separately from the current reviewed harness commit. The original resource source commit remains the immutable
source recorded when the VM was created; the current harness source identifies the later reviewed code and must
descend from that resource source. Never rewrite original ISO receipts to make their source match a newer harness.

A development ISO can contain a newer installer source and an older signed application wheel. The helper comes from
the installer source, while `deployed_commit` continues to identify the signed wheel. Before credential access, admission
reads the original checksum-pinned ISO, verifies its helper against the media inventory and exact installer Git source,
and binds the software source and wheel digest to the installed inspection. Native readback must match that helper;
bootstrap runtime evidence records `helper_source_commit` separately. Neither source is relabelled to satisfy admission.

The certificate peer seed suppresses cloud-init's optional SSH-key console helper; its explicit public-key marker remains
available for console pinning. It persists the provisioned network and host keys before seed removal, restricts later
datasource discovery to NoCloud and None, and preserves the peer's original instance history. Recheck the original SSH
pin and native readiness after the seed-removal restart; never reseed to clear a provisioning failure.

After creating the task-owned peer and LAN through their admitted owning paths, stop the ISO appliance gracefully.
Use its exact preserved selectors to attach its existing adapter to that segment; the command refuses an active VM,
extra adapters, an unknown MAC, or mismatched original evidence:

```powershell
& ./scripts/windows/vmware/test-installation-iso.ps1 -Mode RewirePrivateLan `
  -Worktree $worktree -OutputDirectory $applianceRoot -PullRequestNumber $pr `
  -OriginalReceiptPath $originalPath -OriginalReceiptSha256 $originalSha256 `
  -BaselineReceiptPath $baselinePath -BaselineReceiptSha256 $baselineSha256 `
  -BootReceiptPath $bootPath -BootReceiptSha256 $bootSha256 `
  -PrivateLanSegmentName $segmentName -PrivateLanSegmentId $segmentId `
  -PrivateLanSegmentReceiptPath $segmentReceiptPath `
  -PrivateLanSegmentReceiptSha256 $segmentReceiptSha256 -Confirm:$false
```

Retain the returned `PrivateLanRewireReceiptPath` and `PrivateLanRewireReceiptSha256`. Subsequent `AdmitConsole`,
`ResumeInstalled`, and `Cleanup` operations take those values as `-RewireReceiptPath` and `-RewireReceiptSha256`,
together with the original boot and segment selectors. This transition changes only the original adapter's attachment
and connected state, preserving its generated MAC and all original ownership records.

## Bootstrap the ISO static baseline

### Create an offline peer for a fresh ISO fixture

`scripts/windows/vmware/create-certificate-peer.ps1` prepares a new peer for this ISO workflow without entering the
legacy PR-871 clone scenario. Complete its code review before VM use. It creates an offline peer and a new owned LAN;
it never starts, rewires, or adopts the appliance. The original ISO intent, ownership and installed-boot receipts must
already belong to the same task and PR. Keep that appliance stopped while its ordinary VMX is pinned for admission.

Use an independently admitted Alpine source prepared with `prepare-tiny-linux-client.ps1` in a new originally receipted
task root, without `-Force`. Preserve its original JSON result outside that root as `peer_source_preparation`. The factory
authenticates the QCOW2 against the repository's pinned release digest, requires a standalone monolithic sparse VMDK,
and uses `qemu-img compare` to prove the VMDK's logical contents match that QCOW2. The supplied VMDK SHA-256 and the
public-key file SHA-256 are independent selectors; no existing disk becomes cleanup-owned. An ordinary file pin excludes
writes and replacement through copying. Host disk admission reserves the full sparse-disk maximum plus 2 GiB, and
creation requires 2 GiB free RAM.

Prepare a public JSON plan under the task's originally receipted inputs root. Replace every example selector with the
exact original value; the factory never discovers or relabels another task's receipts:

```json
{
  "schema": 1,
  "trust_model": "trusted-host",
  "repository": "mdaneri/Atlaso",
  "pr": 123,
  "task_id": "exact-current-task-id",
  "source_commit": "FULL_REVIEWED_HEAD_SHA",
  "appliance_vmx": "ABSOLUTE_ORIGINAL_ISO_VMX",
  "appliance_mac": "00:50:56:20:30:40",
  "appliance_intent": {"path": "ABSOLUTE_ORIGINAL_INTENT", "sha256": "ORIGINAL_SHA256"},
  "appliance_ownership": {"path": "ABSOLUTE_ORIGINAL_OWNERSHIP", "sha256": "ORIGINAL_SHA256"},
  "appliance_installed_boot": {"path": "ABSOLUTE_ORIGINAL_BOOT", "sha256": "ORIGINAL_SHA256"},
  "peer_source_preparation": {"path": "ABSOLUTE_ORIGINAL_SOURCE_RESULT", "sha256": "ORIGINAL_SHA256"},
  "peer_vmdk_sha256": "INDEPENDENTLY_VERIFIED_SOURCE_DISK_SHA256",
  "peer_public_key_path": "ABSOLUTE_EXISTING_ED25519_PUBLIC_KEY",
  "peer_public_key_sha256": "INDEPENDENTLY_VERIFIED_PUBLIC_FILE_SHA256",
  "server_cidr": "192.168.77.1/24",
  "lease_address": "192.168.77.10",
  "management_addresses": ["192.168.77.10", "192.168.77.30", "192.168.77.40"],
  "management_vmnet": "vmnet3",
  "peer_user": "alpine",
  "peer_hostname": "atlaso-pr-123-certificate-peer"
}
```

The three private addresses are the admitted DHCP, static baseline and static candidate. Select an existing separate
management VMnet; no host network is created or changed. The existing selected public key must be available in the SSH
agent before creation. No private key or password enters the plan, seed or factory process arguments.

From the clean reviewed task checkout, first inspect without creating resources:

```powershell
& ./scripts/windows/vmware/create-certificate-peer.ps1 -Mode Plan -Plan $peerPlan -PythonPath $nativePython
# After checking the projection, source and capacity, close the Workstation UI normally.
& ./scripts/windows/vmware/create-certificate-peer.ps1 -Mode Create -Plan $peerPlan `
    -PythonPath $nativePython -QemuImgPath $qemuImg -Confirm:$false
```

Create independently verifies the open same-repository PR head, source bytes, original ISO bindings, public key and
source disks before mutation. Preserve the emitted original intent/directory/VM, LAN and prepared-fixture selectors in
the task inventory. Records live outside the peer removal root. A failure preserves its original receipts and any
partial output; an existing destination is refused, never adopted or replaced. The seed publishes the public SSH host
key to the VMX-bound serial file, uses a task-unique NoCloud instance, constrains local SSH tunnels to the three addresses,
and configures only the peer's genuinely synchronized Chrony service to serve time on its private interface.

Creation is not readiness or native acceptance. Admit the original VMX and serial endpoint before starting the new peer,
then capture and pin its actual public host key before SSH. Follow the existing two-member topology, seed retirement,
clock, private-LAN rewire and bootstrap procedures above. Do not accept a network-discovered host key or infer appliance
address control from the seed. The prepared fixture's state remains `offline-prepared-not-native-acceptance`.

Use `-Mode Inspect` with `-OriginalReceiptPath` and `-OriginalReceiptSha256` for receipt-bound readback. Once the peer is
no longer needed and its consumers are inactive, the same selectors with `-Mode Cleanup -VmrunPath $vmrun` invoke the
existing checked VM remover for this exact peer only. Its source plan and original appliance/source references must
remain available. If creation stopped before the VMX existed, `-Mode CleanupPrepared` uses the original preparation
directory receipt selectors and the existing empty-directory remover. It refuses nonempty output; a VMX without its
original VM receipt remains preserved for maintainer recovery. Keep the LAN receipt separately; remove that segment
through its existing owning procedure only after
every appliance/peer reference is absent. Never use peer cleanup to remove the appliance, source disk or evidence.

Prepare the one task-owned Linux peer on the dedicated management VMnet and test LAN. Its test-LAN adapter runs DHCP
only for the admitted appliance MAC; its control adapter remains on the separate management VMnet. When generating
the peer's NoCloud seed with `scripts/interop/create_certificate_peer_seed_iso.py`, enable
`--publish-host-key-to-serial` and supply a task-unique `--instance-id`. This option enables VMware Tools on the peer
and publishes a fixed public Ed25519 host-key marker to its VMX-bound serial file. Read and record that exact marker
from the admitted peer VMX/serial endpoint, bind the instance ID and observation to the original peer receipt, and
pin the host key before any SSH connection. Do not establish peer SSH trust from a network scan, DNS, or an
unverified first connection. The seed's `--public-key` is the public key selected for this task's peer SSH identity;
never stage its private half in the seed or receipts.

For the trusted-host verifier, supply `--management-address` once for each admitted appliance address: the DHCP lease,
static baseline, and static candidate. The seed then permits local SSH channels only to those addresses on ports 22
and 443, verifies the effective SSH policy, and keeps remote forwarding and gateway listeners disabled. For the
example plan these addresses are `192.168.77.10`, `192.168.77.30`, and `192.168.77.40`. This SSH byte transport does not
enable kernel IP forwarding or bridging. Before the first address-changing Apply, the verifier evaluates the effective
SSH policy for its authenticated user and source and refuses missing destinations, unrestricted forwarding, or extra
destinations.

For the normal `peer_transport.authentication_mode: "agent"` selection, or when that selection is omitted, unlock the
SSH agent and approve the selected key for the task's Python runtime before starting unattended inspection. The key
must match the public key admitted for this peer. The bounded child receives no peer private-key value in agent mode;
the bridge clears inherited native credential values before supplying the selected credentials.

Install the task's isolated Python runtime from `requirements-onepassword-deploy.lock`, which includes both the SSH
transport (`paramiko`) and ISO reader (`pycdlib`). Both certificate inspectors refuse a runtime missing either package
before retrieving credentials or creating their source snapshot. Development dependencies are not required.
If a read-only address observation exits with code 2, the wrapper reports a fixed allowlisted failure category when
available, such as `peer_connection_failed` or `appliance_authentication_failed`. Unexpected output remains
`unclassified_proof_failure`; child stdout, stderr and remote error text are never included in the diagnostic.
Preserve the failed run and diagnose that boundary before retrying; an authentication preflight does not prove the
later observation succeeded or authorize replaying Apply.

The ordinary credential policy remains the default. A task-only peer SSH key protected with current-user Windows
DPAPI is an optional exception only when the maintainer has explicitly approved that key and its lab lifetime. Before
creating it, preserve the original approval receipt and bind it to this task, repository, PR, exact peer ownership, and
the peer SSH purpose. Create a dedicated Ed25519 key through the approved credential workflow; preserve the original
key-creation receipt and digest, and bind its public key and fingerprint to the same peer identity and seed. Keep the
private key available to the bounded host-side credential bridge only as DPAPI ciphertext. Do not place ciphertext
or plaintext private-key material in the seed, guest, VM directory, receipts, logs, or public evidence reports. Keep
ciphertext in its separately restricted host credential artifact; plans contain only its path and digest. The explicit
`peer_transport.authentication_mode` is `dpapi-task-key`, with pinned `peer_key`, `peer_key_authorization`, and
`peer_key_creation` references. Admission checks the approval and creation bindings before credential access.
Do not substitute an agent's personal key or fall back to another SSH identity if the approved task key is unavailable
or rejected; stop and reconcile the approved key and its receipts.

### Initialize a fresh appliance fixture

A manual ISO installation can still have pending first-run DNS/DHCP and NTP settings. Establish the fixture baseline
before the certificate bootstrap; its protected handoff bundle must not absorb those independent changes.
This preparation reuses the existing non-grid **Appliance Settings**, **DNS**, and **NTP and NTS** forms and normal
**Appliance Apply** review.
The initializer follows the Settings form's original ID across tabs, including external controls, so changing the
fixture resolver preserves the existing HTTPS, SSH, terminal, and service DNS settings. Ambiguous form IDs or selected
password controls stop preparation before submission.

Keep one real clock authority on the peer. For an Alpine peer already synchronized by Chrony, the seed's optional
`--serve-ntp` uses its existing upstream configuration and admits only the private peer and the three appliance
addresses on UDP 123. The IPv4 server binds to the peer's private address; IPv6 serving is confined to loopback.
It refuses competing time controllers, synthetic local-clock sources, or an unsynchronized peer. It does not select
new upstream sources. For an existing admitted peer, stage the same public configuration and installer returned by
`certificate_peer_time.peer_time_files` over its pinned SSH session; preserve the original config and task-bound
before/after records. Keep the original VM, host keys, interfaces and DHCP configuration. Do not reseed or create a
second peer for this step. The verifier requires both recent genuine synchronization and a real, nonce-matched NTP reply.
Chrony's [`bindaddress` and `allow` directives](https://chrony-project.org/doc/4.8/chrony.conf.html)
define this serving scope.

Add this explicit initialization intent to the existing receipt-bound plan, using its admitted peer address:

```json
"fixture_initialization": {
  "peer_time_address": "192.168.77.1",
  "resolver_address": "192.168.77.1",
  "disable_dns_server": true,
  "disable_ntp_server": true
}
```

Using the reviewed Git-blob entrypoint and the same original resource references, run `-InitializeFixture` first.
Review `fixture-initialization-inspection.json`, which contains public form fingerprints, original interface and TLS
facts, and genuine peer-time observations. Tokens and private-material selectors remain in memory. Bind that immutable
inspection's path and SHA-256 in a new plan reference named `fixture_initialization_inspection`, then run the entrypoint
with `-InitializeFixture -ExecuteInitialization` and that execution plan.

The explicit execution disables the fixture's DNS and NTP server roles, sets stable resolver/upstream values to the
peer, and selects an NTP client with only the real private peer enabled as its time source. Other successful form
controls and the factory upstream rows are preserved. It submits only the reviewed initialization roots: Appliance
Settings, Network, CA, Firewall, Public Services, DNS/DHCP and NTP. A required disabled WAN/NAT replay is allowed only
with the original routing-absence proof; independent pending work is refused.

For the ordinary CA rotation cases, optionally add `"web_terminal_enabled": false` or
`"web_terminal_enabled": true` to `fixture_initialization`. The value must be a JSON Boolean.
This explicit choice uses the existing Settings form and initial Apply to prepare either no Web Terminal
listener or only the mandatory `eth0` management listener. The inspection binds the choice, and execution
verifies its applied readback. Omitting the field preserves the existing terminal settings. Use a fresh,
originally receipted fixture for each selected baseline; never rerun initialization to change a completed case.

Require a successful task, clean Apply state, unchanged DHCP management interface, original CA and payload pins,
continued routing absence, a synchronized NTP client with no competing controller, and the private peer selected in
native `ntpq` readback. This preparation does not establish certificate acceptance. DNS verification records the
configured resolver and upstream values through the later address transitions.
The initialization journals precede desired edits and Apply submission. An unknown task outcome requires reconciliation
from those records; never rerun it or overwrite the evidence. Then continue with the static bootstrap below.

### Deploy the reviewed app wheel before private-LAN preparation

A development ISO has separate software identities: its signed original app wheel and its installer/helper source.
To test a newer CA fix, retain both original identities and add a separate deployment receipt for the actual running
PR wheel. Do this on a fresh originally receipted appliance, before its private-LAN rewire and fixture initialization.
Use the [separately admitted host-only procedure](installation-iso.md#inspect-a-separately-admitted-host-only-connection)
first. Preserve its disconnected account/content checks, original VM, disk-baseline and installed-boot receipts,
stopped unselected-disk verification, exact VMX backup and console network inspection. The selected existing host-only
vmnet must have DHCP; both default routes must remain absent.

The immutable public deployment plan retains `task_id`, positive `pr`, `trust_model: "trusted-host"`, the reviewed
`source_commit` and identical `deployed_commit`, and the original appliance `mac`. Bind original receipt paths and
SHA-256 digests under `appliance_intent`, `appliance_ownership`, `appliance_disk_baseline`,
`appliance_installed_boot` and `installed_inspection`. Add `deployment_network_inspection` for the original console
network report and `deployment_network_binding` with its native `vmnet`, `subnet` and integer `prefixlen`.
Native admission retains the original appliance's canonical name and collision suffix. Keep the original VM identity
when the reviewed harness advances; never rename it to fit a later invocation.

Before the stopped host-only configuration transition, publish `host_only_transition` as a path/digest reference to
an immutable public record. Its schema is `1`, kind is `certificate-iso-host-only-transition`, and it binds the exact
task, repository, PR, source, `vmx_path`, selected `vmnet`, original `ownership` and `boot` references, and original
`backup_path`/`backup_sha256`. Record `boot_configuration_sha256` from the original boot receipt and literal
`stopped_vm_verified: true` and `unselected_disk_unchanged: true` only after their owning checks succeed. The backup
captures the actual stopped VMX, including permitted VMware runtime fields; preserve its bytes independently of the
boot transition's configuration digest. Missing pre-transition evidence prevents deployment; never reconstruct it
from the later connected VM.

Load the new owner from the exact reviewed Git commit, as with the certificate inspector:

```powershell
$relative = 'scripts/windows/vmware/deploy-certificate-iso-wheel.ps1'
$bytes = @(& git -C $repoRoot show "${reviewedCommit}:$relative")
if ($LASTEXITCODE -ne 0) { throw 'Reviewed deployment owner is unavailable.' }
$deployOwner = [scriptblock]::Create(($bytes -join "`n"))
& $deployOwner -RepositoryRoot $repoRoot -ReviewedSourceCommit $reviewedCommit `
    -Plan $deploymentPlan -PythonPath $pythonPath -EnvironmentId $environmentId `
    -RuntimeDependencyDirectory $originalSignedCp314Wheelhouse
# Inspect the public original-media/network report before the explicit deployment.
& $deployOwner -RepositoryRoot $repoRoot -ReviewedSourceCommit $reviewedCommit `
    -Plan $deploymentPlan -PythonPath $pythonPath -EnvironmentId $environmentId `
    -RuntimeDependencyDirectory $originalSignedCp314Wheelhouse -Execute
```

Use a prepared, originally owned isolated Python environment beneath this worktree's `test-results` with the locked
native inspector and wheel-build dependencies, including the build backend's `packaging` parser. The runtime and
immutable Git archive stay pinned through every
consumer. The owner creates and receipts a fresh artifact root before use, builds one wheel from that archive, and
requires its dependency declarations to match the original signed app except requirements whose entire marker is
`extra == "dev"`. The deployer installs only the bare wheel with `--no-deps`; it never selects the development extra.
Runtime changes, other extras, broader marker expressions and malformed requirements remain refusals. The complete
offline cp314 wheelhouse must
match the original ISO's release inventory. Native VM admission uses the separately pinned canonical checkout owner
and its complete checkout/parsed-code validation; the wheel builder and deployment child use the immutable archive
from that same reviewed commit. The existing direct deployer keeps its bootstrap, deployment-lock and
Appliance Update guards. It verifies the original console-observed SSH key before authentication, uses one private
remote staging directory, verifies every uploaded file, and retains the original helper and console/boot assets.
This exclusive mode-0700 staging directory lives under `/var/tmp`, preserving the same verified wheel archive across
the private-LAN handoff reboot for subsequent payload measurements. `/tmp` staging is refused for this workflow.

The original-fixture claim is exclusive across output directories. Process ownership is published while the child
is suspended, before credential access or guest mutation. Success requires a quiescent process job, unchanged source
guards and native VM/network binding, exact active wheel payload and original public machine/helper/assets identity.
Preserve `deployment.json` separately and bind its path/digest as `iso_wheel_deployment` in the later certificate plan.
Keep `installed_inspection` unchanged: it continues to describe the original signed software. Subsequent certificate
admission measures the active PR wheel again before and after rotation.

On failure or an unknown outcome, preserve the fixture, exclusive claim and all process/intent records. Reconcile
those records before any recovery; another output directory never permits redeployment. After success, stop the VM,
restore and verify the original backed-up adapter declaration through the owning procedure, then use the existing
private-LAN rewire. The host-only phase grants no host route, NAT or bridge to the private certificate LAN.

### Recover a terminal initial NTP synchronization timeout

If the initializer failed only because the selected NTP client did not synchronize within its 60-second guard,
preserve its result and task ID. Read the existing task and native clock/routing observations first. An active or
unknown task, another failed component, changed management interface or TLS identity, unrelated pending work, or
different DNS/NTP desired settings prevents this recovery. The NTP synchronization guard and safe rollback remain
unchanged; a listening service or a small measured clock offset does not establish a healthy controller.

Create a fresh, originally receipted output namespace and retain the original failed result as the plan reference
`fixture_initialization_failure` with its original path and SHA-256. Using the same reviewed Git-blob wrapper, run
`-RecoverFixture` without execution. Review `fixture-recovery-inspection.json`: only NTP may be pending, the other
initializer components must have succeeded, and Public Services must have been skipped. Desired state must already
select only the admitted private peer as an NTP client, with DNS and NTP/NTS server roles disabled. Normal Apply review
must select exactly NTP and Public Services for this new task.

Bind that inspection as `fixture_recovery_inspection`, then use `-RecoverFixture -ExecuteRecovery`. This submits a
distinct two-unit recovery through normal Appliance Apply, without saving forms or replaying the initializer's other
components. Before submission, an immutable `fixture-ntp-recovery-claim.json` beside the original failure claims its
single recovery attempt across output namespaces. An existing claim requires reconciliation; a new output directory
cannot authorize another submission. The original failed result remains unchanged. Require task success, clean Apply
state, the original interface/CA/payload/routing identities, and genuine exclusive NTP-client synchronization with the
private peer selected in native `ntpq` readback. Preserve the new task's journals and `fixture-recovery-result.json`
alongside the original failure. A failed or unknown recovery blocks bootstrap.

After the original ISO adapter is rewired and the trusted-host topology is admitted, use the reviewed Git-blob
`scripts/windows/vmware/inspect-certificate-peer.ps1` entrypoint described in the
[VMware lifecycle certificate workflow](vmware-workstation-lifecycle-testing.md#single-command-run). Do not invoke
the mutable checkout copy directly. The plan uses the original ISO intent, ownership, boot, and private-LAN
transition references, the installed inspection, and the original peer/LAN receipts. Keep its public CA certificate
file separately pinned to the public CA read through the appliance's pinned SSH session. The bootstrap rejects a
private key or CA digest mismatch. It first obtains a CA-validated TLS handshake through the peer and then uses the
observed certificate name with the normal full CA and hostname validation for UI requests.

Run the wrapper with `-Bootstrap` first to inspect the source route snapshot, active `atlaso.service`, installed
helper and wheel, original desired fields, served TLS identity, DNS, and topology without editing the UI. Review
`inspection-result.json` in the existing task-owned evidence directory. Confirm the current-address value is the peer's
admitted lease, and the selected interface, original MAC, public CA, resource source ancestry, installed inspection,
and two-member topology all match the original receipts.

The bootstrap sends its reviewed Python probes as encoded, single-line commands to the installed application
interpreter, matching the ISO inspector. It does not rely on the guest login shell to preserve multiline Python quoting.

With the same reviewed entrypoint and plan, invoke it with `-Bootstrap -ExecuteBootstrap` to establish the first
static baseline.
This explicit option edits Physical Interfaces through the existing authenticated UI, preserving unrelated
desired fields while setting eth0 to static 192.168.77.30/24, no gateway, and IPv6 disabled with blank IPv6
fields. It submits only the validated protected Apply bundle selected by the server review, then waits for the
terminal task and verifies the desired fields, TLS identity, `/openapi.json`, clean Apply state, route snapshot,
installed wheel/helper identity, and trusted-host topology. Use the addresses from the admitted plan when the lab
uses a different approved baseline subnet; do not copy the example address into another lab.

For a fresh ordinary CA case that must retain DHCP, select `"scenario": "ordinary-ca-rotation"` and
`"ordinary_ca_baseline_mode": "dhcp"` in its immutable plan. Keep `current_address` equal to the original peer fixture's
fixed lease. The same bootstrap inspection/execution commands then observe the clean existing DHCP configuration;
they submit no interface edit or Apply task. Success publishes `dhcp-baseline-observation.json` and a separate proof
plan with phase `iso-dhcp-baseline-observed`, preserving the original MAC lease, connected route, absence of default
routes, TLS identity and deployed payload. Do not substitute this observation for a static rewire receipt.

Run each static/DHCP and Web Terminal disabled/enabled combination on a fresh original fixture. Ordinary rotation
requires the running app to match the current reviewed source. DHCP admission checks the original lease and native
address owner both before and after CA rotation; an extra address, changed lease owner, default route or changed
deployed payload prevents success. The static baseline address remains distinct from the predeclared handoff candidate
and DHCP lease; it need not appear in the candidate-only address list.

Bootstrap inspection and execution require a clean applied baseline before editing the interface. The controlled
interface edit can also change Atlaso-owned DNS records while local DNS is disabled. In that case the trusted-host
harness explicitly includes the changed **DNS/DHCP (dnsmasq)** unit in the same reviewed handoff; disabled DNS does
not receive the server's automatic generated-record dependency. It saves no DNS forms and preserves the admitted
DNS settings. Pre-existing DNS changes and unrelated pending components still stop admission. Address restoration
uses the same reviewed scope and must leave no pending units.

Task polling and restoration try only the predeclared original and candidate origins. A private-channel refusal at
the retired origin permits trying the other admitted origin while following the same submitted task and deadline;
it never submits again. Inactive peer transport, changed SSH trust, out-of-scope destinations, and topology failures
still stop the run. A failed observer result stays preserved even if later read-only reconciliation finds a successful
task; reconcile the recorded state before planning another attempt.

Using the verified in-memory `$entrypoint` and receipt-bound paths from the linked workflow:

```powershell
& $entrypoint -RepositoryRoot $repoRoot -ReviewedSourceCommit $reviewedCommit `
    -Plan $plan -AddressEvidence $addressEvidence -RuntimeEvidence $runtimeEvidence `
    -EnvironmentId $environmentId -PythonPath $pythonPath -Bootstrap
# Review inspection-result.json before this explicit configuration transition.
& $entrypoint -RepositoryRoot $repoRoot -ReviewedSourceCommit $reviewedCommit `
    -Plan $plan -AddressEvidence $addressEvidence -RuntimeEvidence $runtimeEvidence `
    -EnvironmentId $environmentId -PythonPath $pythonPath -Bootstrap -ExecuteBootstrap
```

The wrapper uses the existing bounded 1Password credential bridge; it does not put plaintext passwords on the
command line or in evidence. Select a task-owned native-test Python environment with the locked credential and SSH
dependencies. A larger development environment can exceed the protected code-inventory bound; use the smaller admitted
environment rather than increasing or bypassing that bound. Execute mode re-admits the original inputs and writes
source, bootstrap-runtime, original-state, management-rewire-intent, mutation-started, apply-submitted, rewired-runtime,
proof-plan, and
bootstrap-result records in the task-owned evidence directory. It does not overwrite inspection-result.json. A sticky
topology failure, including failure to stop the watcher, prevents a successful terminal result or a usable proof plan.
The source phase is `before-certificate-validation`; do not label it as `before-lifecycle-deployment` or synthesize
missing route evidence. Do not retry an execution in a directory with execution records. If an Apply result is unknown,
preserve the journal and lab and do not resubmit. Reconcile through the supported UI recovery workflow, then plan a
separately named attempt with new evidence paths. A failed or incomplete bootstrap cannot authorize either address
scenario.

The native plan explicitly selects `trust_model: "trusted-host"` and `trusted_host.host_administrator_trusted: true`.
Its `trusted_host` block records the exact `vmrun_path`, `inventory_path`, `preferences_path`, `segment_name`,
`segment_id`, original `segment_receipt` path/hash, appliance and peer VMX paths, private adapter indices/MACs, and
the peer control adapter's index, connection type, VMnet, and MAC. The producer inspects the union of registered and
running VMs; a running VM omitted from the saved inventory still enters membership checks. Both admitted lab VMs must
be running. The scenario samples host topology in the background and rechecks it around authenticated HTTP operations.
Any observed drift remains a failure even if the original topology is later restored.

For the dedicated-management baseline route, the producer reads `ip -j -4 route show table 100` and requires the
exact connected prefix, `eth0`, preferred source, and on-link scope without a gateway. Keep this query unfiltered by
device: iproute2 can omit `dev` when `dev eth0` is already a query filter. A main-table route alone does not prove the
management routing-domain baseline.

## Run and accept ordinary CA rotation

For a CA-only management certificate change, use the same reviewed
`inspect-certificate-handoff.ps1` entrypoint and full trusted-host admission with
`scenario: "ordinary-ca-rotation"`. The immutable plan must name the original
issued `management_certificate_id`, set `expected_web_terminal` to an explicit
Boolean, and bind `interface: "eth0"` and its original MAC. Its peer baseline
address must match the appliance's clean applied static IPv4 configuration.
This case does not establish DHCP-address acceptance.

Run inspection before execution. Keep the original ISO, appliance, peer, LAN,
installed source/helper, address evidence, public CA and SSH trust receipts.
The runner records original public certificate and configuration evidence before
using **Certificate requests → Revoke certificate → Replace** for this disposable
appliance's `appliance:https` certificate. It then reviews only CA changes and
requires unchanged Appliance Settings and Public Services to replay after CA.
Unrelated pending edits or missing dependencies refuse submission.
The inventory read reconciles the replacement to `issued` before Apply. The runner
pins that successor's inventory/public-PEM fingerprint and requires the same leaf
after activation.

Acceptance requires the same admitted task to succeed without dry-run results,
a clean applied baseline, unchanged management address/MAC/configuration and Web
Terminal state, and an unchanged root certificate matching the receipt-pinned
CA. The replacement inventory fingerprint, authenticated public certificate PEM
and strictly verified peer TLS leaf must all match and differ from the original
leaf. Run separate cases with Web Terminal disabled and enabled on the sole
management interface; apply each intended baseline before preparing its plan.

Revocation retains certificate history and cannot be undone. On failure, retain
the fixture and original evidence for diagnosis; never automatically restore,
retry or resubmit this scenario. The existing static-address and DHCP-rejection
scenarios keep their separate restoration requirements.

## Run and accept the static-address case

Protected handoff validation checks the staged candidate certificate's format, configured paths, and key pair without
requiring it to authenticate the old listener addresses. The transaction preserves and verifies the old TLS path with
its snapshotted certificate, then validates the candidate leaf against every actual candidate address before publishing
that listener. An ordinary Appliance Settings certificate change still requires coverage of its retained listeners.
This separation also applies to DHCP: an unknown lease does not waive certificate validation after acquisition.

Use the standard Atlaso [Network configuration](../operate/networking.md) pages and [Appliance
Apply](../operate/appliance-apply.md) workflow for the admitted source. Match the reviewed native submission boundary:
submit only units selected and validated by Apply review from the protected Network, CA, Firewall, Appliance Settings,
and Public Services set, plus the generated DNS changes described above. Do not include unrelated pending units.
Do not use a local helper, direct database edit, ad
hoc API caller, or a script that bypasses that workflow. Keep the appliance on its recorded static management
baseline while establishing the peer control path. Before changing it, record the host inventory, exact appliance
and peer LAN membership, adapter bindings, addresses, peer reservation, CA, and trust pins.

After the ISO bootstrap completed successfully and admission is rechecked, open **Physical Interfaces** and set the
selected management interface to the approved
candidate static IPv4 address, prefix, and gateway. Review pending changes and submit the protected **Network** Apply
bundle with **Submit appliance changes**. Include every dependency selected by the review; do not submit Network alone
when the review requires a protected bundle. Record the Apply
task identity, status, and sanitized failure details if any. Acceptance requires all of these observations:

- Apply reaches succeeded through the supported workflow.
- The candidate address serves the appliance over HTTPS with a chain validated by the admitted public CA and an IP
  subject alternative name matching the candidate address. Verify /openapi.json at that address.
- Readback shows the intended interface still has the admitted MAC and exact candidate static fields. Route and DNS
  state match the approved plan and captured baseline.
- After candidate readiness and final cutover, verify retirement of the original address using the native checks
  below. Candidate reachability and saved desired fields alone do not prove retirement.
- The served public TLS identity is captured before and after the handoff. Report the actual certificate fingerprint
  and address coverage; do not claim observation of transient nginx certificate generations that were not directly
  observed.
- The trusted-host administrator rechecks the two-member segment inventory, appliance adapter, peer reservation, and
  active lease after the transition. Record the observation time; changed membership invalidates the run.

Then restore the exact original static desired fields using the same editor and Apply review. Require the previous
task to be terminal. If review returns units, submit its valid protected bundle, record the restoration task, and
verify that Apply succeeds. If review returns no units, submit nothing and record a no-op restoration with no task
ID. In either case, verify a clean applied baseline, the original address and route, the original DNS baseline, and
HTTPS /openapi.json at the original address. The restoration may reissue the management certificate:
validate its chain against the admitted public CA and confirm its IP subject alternative name covers the original
address. Record the actual restored fingerprint and whether it differs from the original; exact fingerprint equality
is not a static-restoration requirement. Recheck both SSH trust pins (or the admitted appliance console binding),
the two-member LAN inventory, peer reservation, and active lease. Acceptance is
incomplete until both candidate and restored state are observed and the candidate address is retired using the
native checks below.

## Run and accept the DHCP-rejection case

Run this case only from a proven static management baseline and only when the authoritative DHCP plan identifies a
candidate lease that is not covered by the selected management certificate. Before mutation, record the exact
expected DHCP IPv4 address and bind it to the original appliance MAC, peer reservation, trusted-host address evidence,
and task/VM/LAN identities. Recheck that same reservation before Apply; do not infer the expected address
from a later acquired lease. Verify certificate selection and its fingerprint against the live appliance:https
certificate before the test. After saving the DHCP desired state but
before submitting Apply, verify again that the enabled appliance:https inventory row has the same ID and fingerprint
captured at admission. Validate its public chain with the admitted CA and confirm that it does not cover the expected
acquired address. The trusted host keeps the LAN inventory stable and rechecks the peer reservation throughout.

Download the desired public leaf from the certificate's authenticated `certificate.pem` protocol download endpoint.
This download remains outside `/ui/management`;
the certificate inventory page stays under the management UI. Export no private key. Verify the downloaded public
certificate's actual chain and IP coverage with OpenSSL before accepting the negative-case prerequisite.

On **Physical Interfaces**, request DHCP for the selected management interface. Review pending changes and submit the
protected **Network** Apply bundle with **Submit appliance changes**, including every dependency selected by review.
The expected outcome is rejection at the certificate prerequisite after the acquired address is known, with
the management handoff rolled back. A failed task by itself is not acceptance. Record and verify all of the following:

- The Apply task reports failed at the certificate prerequisite and explicitly identifies the acquired IPv4 address.
  That address must equal the exact expected DHCP address admitted and recorded before mutation, and the task must
  identify it as outside the selected certificate's IP address coverage. Missing or different acquired-address
  evidence fails acceptance, even if the unexpected address is also uncovered and rollback succeeds. Preserve that
  failure and reconcile under the supported recovery workflow; do not relabel the reservation or proof afterward.
- The task reports that the management handoff was rolled back. HTTPS remains reachable at the original management
  address, /openapi.json succeeds, and the served TLS identity exactly equals the captured original identity.
- Readback confirms that no partial candidate management state remains applied. The original interface, route, DNS,
  and certificate baselines remain intact, and the certificate inventory still identifies the same selected public
  leaf. Verify that the acquired DHCP candidate is retired using the native checks below.
- The trusted-host administrator records that the admitted appliance and peer remained the only LAN members and that
  the expected-address reservation stayed unchanged through acquisition and rollback.

Finally, restore the saved original static desired fields through **Physical Interfaces**, then open Apply review
with the failed handoff task terminal. If review returns units, submit its valid protected bundle, record this
restoration task separately, and require success. If review returns no units because the desired fields already
match the rolled-back applied baseline, do not submit a second Apply: record a no-op restoration with no task ID.
In both branches, require no pending units or active task and verify the original saved and applied fields, route,
DNS, and HTTPS endpoint; validate the served
certificate chain against the admitted public CA and confirm the certificate IP subject alternative name covers the
original address. Record the actual restored fingerprint, including any change from the captured fingerprint.
Recheck that the DHCP candidate remains retired after this restoration.
The expected certificate rejection and the successful restoration are distinct acceptance observations.

## Verify retired addresses natively

For each retirement check, retain time-stamped guest and private-peer observations under the same task-owned segment
and trusted-host inventory. Before each SSH readback, recheck the appliance host-key fingerprint against its
pre-mutation, VM-bound pin;
refuse a missing or changed pin without collecting acceptance observations or accepting replacement trust. For the
console alternative, recheck the console's binding to the original VMX and VM root identity. Use only the admitted
transport for read-only `ip -j -4 addr show` and route/listener inspection. Verify the retired address is absent from
every guest interface, not merely from saved desired state,
and that no active management listener or owned handoff route still binds that address. Native `ss` endpoints can
include an interface suffix such as `%lo`; compare the address itself so that suffix neither invalidates an unrelated
loopback listener nor conceals a binding to the retired address. Record the actual native
observations after the terminal Apply result; a pending task or unavailable observation cannot establish retirement.

From the admitted private peer, attempt a direct TCP connection to the retired IPv4 address on the configured
management HTTPS port with a bounded timeout, while verifying that the active address remains reachable over the
same path. Do not use DNS, proxy fallback, or a hostname that could select another address. Any accepted connection
at the retired address fails retirement, even when TLS certificate validation or authentication subsequently fails.
A TLS mismatch, HTTP denial, or failed ping alone is not evidence that the listener is gone. Peer connection failure
must agree with native address/listener absence; if peer routing, transport, or the host inventory check is uncertain,
preserve the lab and report acceptance incomplete rather than treating a timeout as proof.

When a live authenticated SSH peer has not returned its TCP channel-open outcome within the normal eight-second
probe deadline, the retirement observer may make one further read-only observation with a 150-second channel wait.
OpenSSH waits for the peer kernel's connect outcome; Linux's default SYN retry horizon can reach
[131 seconds](https://docs.kernel.org/networking/ip-sysctl.html).
A single 200-second monotonic budget reserves the full selected channel wait and eight seconds for the active-path
probe before each observation and TCP attempt. Existing native-command deadlines and the bounded child still apply.
Before the extended probe it repeats native address, listener, route and rule absence checks and requires positive
TCP acceptance at the active address from the first observation. It checks the active address after each retired
probe and repeats native absence after an explicit refusal before accepting retirement. Only an explicit connect-failed
reply proves nonacceptance; expiry of either channel wait remains unknown. Administrative denial, lost authentication,
other transport errors, persistent pending outcomes, budget exhaustion, reappearing native ownership or an accepted
retired connection still fail. Evidence retains each outcome, selected wait and elapsed time. This window does not
replay Apply or change the eight-second authentication deadline or the 60-second NTP guard.

## Hand off lab resources for cleanup

After successful acceptance or a recorded terminal failure disposition, preserve the acceptance or failure record,
original ownership receipts and their independently
recorded digests outside every removable VM, lab, and result root. Hand off a bounded inventory of the appliance VM,
peer VM, private LAN segment, DHCP/address reservations, lifecycle result and other
artifact roots, helper processes, and recovery state. Bind each exact path or provider identity to its original
ownership manifest, task, repository, source, and PR; record the verified restoration result or explicitly record
that restoration was not verified and the disposable lab was abandoned. Never report an abandoned run as acceptance.
Explicitly record any
required retention with its resource, owner, reason, and retry condition, including a downstream diagnosis need.

Once evidence is preserved, the PR is terminal, and no review, diagnosis, retry, deployment, release, or maintainer
activity needs the lab, follow [completed task resource
cleanup](vmware-workstation-lifecycle-testing.md#completed-task-resource-cleanup)
and its [supported removal entry points](vmware-workstation-lifecycle-testing.md#supported-removal-entry-points).
Use the exact owned lifecycle VM cleanup path; release each owned LAN segment through its
[LAN-segment procedure](vmware-workstation-lifecycle-testing.md#release-task-owned-lan-segments). VM removal alone
neither releases reservations and controls nor removes the result root. Release each associated resource through its
supported owning tool, then release the exact quiescent artifact root only after preserving evidence and verifying
its ownership and containment. Record host readback that the two VMs no longer reference the LAN segment and that the
owned reservation, segment registration, and other task resources are absent.

If the approved task-only DPAPI peer key was used, include its exact host-side ciphertext artifact and any bounded
credential staging state in the same task cleanup handoff. After no diagnosis, retry, or recovery needs the key, remove
only those receipt-bound artifacts through their supported owner and verify that they are absent. Preserve the public
approval and key-creation receipts with the lab evidence; they contain no private-key material. Do not delete or alter
shared 1Password items, other keys, or unreceipted host credentials as part of lab cleanup.

Retained, shared, differently owned, unsupported, or ambiguously owned resources must be preserved and reported with
the blocking condition. Do not substitute broad provider cleanup or recursive deletion, and do not mark the lab
cleanup complete while retention or release gates remain unresolved. Branch/worktree completion separately follows
the [completed-task cleanup policy](../contribute/completed-task-cleanup.md).

## Failure handling and limits

If any admission fact is missing, stale, or ambiguous, make no appliance change and preserve the VM, peer, LAN,
receipts, and evidence for maintainer review. If an Apply result or rollback is uncertain, do not resubmit the
operation or clean up the lab while diagnosis,
recovery, or retry still needs its state. Preserve the state, task output, original rollback inputs, and sanitized
observations; reconcile
using the supported Atlaso workflow under the same trusted-host inventory and address plan. If the original state
cannot be verified, stop and escalate to the maintainer who controls the lab.

Failed or interrupted admission and acceptance may retain resources only while diagnosis, recovery, or retry needs
them. Once maintainer review ends, record the disposition: a controlled retry, explicit resource retention, or
abandonment of the disposable lab. For abandonment, preserve failure and recovery evidence outside removal roots,
record that acceptance/restoration is unverified where applicable, and use the same
[cleanup handoff](#hand-off-lab-resources-for-cleanup) after its terminal-PR, inactivity, ownership, and quiescence
gates pass. Do not restart Apply just to make an abandoned lab eligible for teardown. If recovery activity, ownership,
a supported cleanup capability, or another release gate remains uncertain, record the exact blocked resource, owner,
reason, and retry condition and preserve it; uncertainty is neither cleanup authorization nor indefinite unrecorded
retention. A terminal failed run does not waive any branch/worktree completion gate.

The trusted-host bootstrap and proof wrappers admit the original ISO and peer receipt kinds for the current task and
PR, then repeat inventory, reservation, identity, and trust checks before obtaining guest credentials. Receipts from
the older PR #871 independent-control path remain bound to that task and cannot be relabeled. Use the
[VMware lifecycle certificate section](vmware-workstation-lifecycle-testing.md#single-command-run) for the reviewed
Git-blob entrypoint and bounded credential wrapper workflow.
