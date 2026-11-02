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

With the same reviewed entrypoint and plan, invoke it with `-Bootstrap -ExecuteBootstrap` to establish the first
static baseline.
This explicit option edits Physical Interfaces through the existing authenticated UI, preserving unrelated
desired fields while setting eth0 to static 192.168.77.30/24, no gateway, and IPv6 disabled with blank IPv6
fields. It submits only the validated protected Apply bundle selected by the server review, then waits for the
terminal task and verifies the desired fields, TLS identity, `/openapi.json`, clean Apply state, route snapshot,
installed wheel/helper identity, and trusted-host topology. Use the addresses from the admitted plan when the lab
uses a different approved baseline subnet; do not copy the example address into another lab.

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
The source phase is `before-certificate-validation`; do not label it as `before-lifecycle-deployment` or synthesize missing
route evidence. Do not retry an execution in a directory with execution records. If an Apply result is unknown,
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

## Run and accept the static-address case

Use the standard Atlaso [Network configuration](../operate/networking.md) pages and [Appliance
Apply](../operate/appliance-apply.md) workflow for the admitted source. Match the reviewed native submission boundary:
submit only units selected and validated by Apply review from the protected Network, CA, Firewall, Appliance Settings,
and Public Services set. Do not include unrelated pending units. Do not use a local helper, direct database edit, ad
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
and that no active management listener or owned handoff route still binds that address. Record the actual native
observations after the terminal Apply result; a pending task or unavailable observation cannot establish retirement.

From the admitted private peer, attempt a direct TCP connection to the retired IPv4 address on the configured
management HTTPS port with a bounded timeout, while verifying that the active address remains reachable over the
same path. Do not use DNS, proxy fallback, or a hostname that could select another address. Any accepted connection
at the retired address fails retirement, even when TLS certificate validation or authentication subsequently fails.
A TLS mismatch, HTTP denial, or failed ping alone is not evidence that the listener is gone. Peer connection failure
must agree with native address/listener absence; if peer routing, transport, or the host inventory check is uncertain,
preserve the lab and report acceptance incomplete rather than treating a timeout as proof.

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
