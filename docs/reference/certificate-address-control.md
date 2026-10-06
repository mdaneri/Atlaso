---
title: Certificate handoff address-control procedure
description: Human-maintainer acceptance procedure for certificate handoff when native address proof is unavailable.
audience:
  - maintainer
status: current
---

# Certificate handoff address-control procedure

This procedure defines a human-maintainer acceptance path for a certificate handoff lab while the current Atlaso
VMware Workstation producer cannot produce machine-admissible proof that a candidate management address is exclusively
controlled. It permits a
maintainer to collect reviewable lab evidence through Atlaso's supported interface and Appliance Apply workflow. It
does not make that evidence admissible to `certificate_handoff_native.py` or unlock either credentialed wrapper.

The acceptance cases below cover the existing fixture: one dedicated IPv4 management interface, `eth0`, with IPv6
disabled and an explicitly configured static baseline. They do not establish Access-management acceptance for #852 or
support for other interface roles or address families.

## Authority and admission

The maintainer directing the lab must independently establish and enforce exclusive admission to the private LAN for
the full interval from the first ownership observation through the final rollback verification. The maintainer must
have authority over both the candidate address and the LAN admission boundary. A second qualified operator or an
authoritative system outside the test VM and its peer must attest the observations and enforcement. Select a control
that actually fences membership and prevents conflicting use of the candidate address, then record its configured
rule and independent readback for the exact VM, peer, LAN, and address. An operator statement, signed or otherwise,
without observable enforcement and readback is not proof. A receipt written by the test runner, an agent, or the VM
owner alone is not independent proof.

This procedure covers the current native scenario only: one IPv4 dedicated-management interface named eth0, with IPv6
disabled. It does not establish acceptance for another interface, role, address family, or access-management
configuration.

Before any appliance configuration change, establish all of the following:

- The applied baseline is complete and clean: the initial Apply has completed, there are no pending desired-state
  units, and no Appliance Apply task is pending, running, or otherwise active. The original source probe proves
  routing intent absent with the required route, rule, NAT, port-forward, WAN-policy, and route-role interface counts
  at zero and routing/WAN settings disabled. Bind that original source receipt by digest to the exact task, appliance
  VM, and source commit.
- The deployed runtime is bound to that same source and VM. Bind the exact helper and wheel SHA-256 values from the
  runtime receipt to the plan and deployed source commit. Independently verify the helper digest against the reviewed
  source; retain the verified built-wheel digest from the admitted runtime record.

- The lab is authorized, isolated, and tied to the exact repository, issue, pull request, reviewed source commit, and
  original task identity. Bind the exact appliance VMX and VM root identity to its immutable original creation-intent
  and ownership receipts. Record the original receipt paths and SHA-256 digests in durable evidence outside any
  disposable VM directory.
- The appliance adapter and candidate interface are the intended ones. Record the VMX adapter-to-LAN mapping, the
  observed appliance MAC and interface, the candidate IPv4 address and prefix, gateway, and the prior static
  management configuration.
- The peer is independently admitted as a task-owned resource. Bind its original creation and source-disk identity,
  private-LAN adapter, address, and pinned SSH host-key fingerprint. Record the original peer creation-receipt path
and digest, selected source-disk path and digest, and public SSH key fingerprint used for admission. Never put a
private key, password, token, authenticated URL, or other secret in evidence.
- The private LAN identity is bound to its original creation or authoritative inventory record and original digest.
  Record its provider identity and the enforcing attachment boundary. Prove that every attached endpoint is accounted
  for and that no other endpoint can join or claim the candidate address during the operation.
- An authoritative reservation or equivalent enforcement prevents other claimants from using the candidate address.
  The source must be independent of the guest's address report and peer configuration. Retain the source record,
  operator identity, observation time, and a digest or verifiable reference.
- The appliance's original HTTPS certificate identity, trusted public CA digest, interface fields, route, and DNS
  baseline are captured through the normal authenticated Atlaso interface. Keep only public certificate material and
  sanitized observations.

An address that does not answer ARP or ICMP is not thereby unused. A quiet DHCP lease table, MAC-derived address,
VMware Tools address, guest route, or vmrun inventory does not prove exclusive current LAN membership or exclude
another claimant. Do not proceed if the independent source cannot account for all attachments, enforce admission,
reserve the address, or observe those facts continuously. The [VMware Workstation
API](https://developer.broadcom.com/xapis/vmware-workstation-pro-api/latest/)
documents per-VM adapters and IP information, networks, DHCP MAC settings, and VM identities and paths; those
observations alone do not establish an enforced exclusive attachment or exclude a static-address claimant. Any
platform mechanism used must be demonstrated on the actual lab. A switch port fence, controlled virtual-switch
membership, or authoritative reservation service are examples of required capabilities, not claims that a
particular installation provides them.

Keep the independent admission control active from the initial observation through both the test and restoration.
Recheck the attachment inventory, reservation, and claimant state before each Apply and after each address transition.
Stop before another change if any check is unavailable or differs. Any membership, reservation, peer trust, VM,
source,
route, or candidate-address drift invalidates the evidence. If the control boundary is interrupted, the VM reboots,
the relevant task/source binding changes, or a verification interval is missed, treat the proof as stale and do not
resume from the old receipt. Re-admit from original evidence before any new mutation.

## Maintainer evidence record

Keep one append-only lab record in the maintainer-approved durable evidence location, outside the removable lab root.
Record the task, issue, PR, repository, source commit, appliance and peer identities, LAN identity, address plan,
original receipt digests, public CA digest, peer SSH host-key fingerprint, independent authority and source, and each
observation and action in order. Preserve the original bytes of creation receipts; calculate and independently record
their SHA-256 digests before use. Do not edit, relabel, or recreate them to match a later task or pull request.

The record is manually collected maintainer acceptance evidence. It is not a controlled native receipt, regardless of
whether it is structured as JSON or signed. Current native admission binds VM ownership to PR #871 and requires an
original address-proof receipt with exact task, VM, peer, LAN, CA, and runtime bindings. A manually authored record,
an old PR #871 receipt, or a receipt with its PR/task fields rewritten cannot satisfy those checks. A future native
producer must obtain each new task and PR identity from its owning admission path, bind the original receipts and
independent address authority itself, and enforce the required live checks through rollback. Do not use the current
credentialed wrappers for a new task until that producer is implemented and admitted by the native path.

## Run and accept the static-address case

Use the standard Atlaso [Network configuration](../operate/networking.md) pages and [Appliance
Apply](../operate/appliance-apply.md) workflow for the admitted source. Match the reviewed native submission boundary:
submit only units selected and validated by Apply review from the protected Network, CA, Firewall, Appliance Settings,
and Public Services set. Do not include unrelated pending units. Do not use a local helper, direct database edit, ad
hoc API caller, or a script that bypasses that workflow. Keep the appliance on its
recorded static management baseline while establishing the peer control path and independent address fence.

After admission is rechecked, open **Physical Interfaces** and set the selected management interface to the approved
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
- The independent authority rechecks exclusive LAN membership, claimant absence, and reservation enforcement at the
  candidate address after the transition.

Then restore the exact original static desired fields using the same editor and Apply review. Require the previous
task to be terminal. If review returns units, submit its valid protected bundle, record the restoration task, and
verify that Apply succeeds. If review returns no units, submit nothing and record a no-op restoration with no task
ID. In either case, verify a clean applied baseline, the original address and route, the original DNS baseline, and
HTTPS /openapi.json at the original address. The restoration may reissue the management certificate:
validate its chain against the admitted public CA and confirm its IP subject alternative name covers the original
address. Record the actual restored fingerprint and whether it differs from the original; exact fingerprint equality
is not a static-restoration requirement. Recheck the peer trust pin and independent LAN fence. Acceptance is
incomplete until both candidate and restored state are observed and the candidate address is retired using the
native checks below.

## Run and accept the DHCP-rejection case

Run this case only from a proven static management baseline and only when the authoritative DHCP plan identifies a
candidate lease that is not covered by the selected management certificate. Verify certificate selection and its
fingerprint against the live appliance:https certificate before the test. After saving the DHCP desired state but
before submitting Apply, verify again that the enabled appliance:https inventory row has the same ID and fingerprint
captured at admission. Validate its public chain with the admitted CA and confirm that it does not cover the expected
acquired address. The independent reservation and LAN admission controls remain active throughout.

On **Physical Interfaces**, request DHCP for the selected management interface. Review pending changes and submit the
protected **Network** Apply bundle with **Submit appliance changes**, including every dependency selected by review.
The expected outcome is rejection at the certificate prerequisite after the acquired address is known, with
the management handoff rolled back. A failed task by itself is not acceptance. Record and verify all of the following:

- The Apply task reports failed at the certificate prerequisite and identifies the acquired candidate address as
  outside the selected certificate's IP address coverage.
- The task reports that the management handoff was rolled back. HTTPS remains reachable at the original management
  address, /openapi.json succeeds, and the served TLS identity exactly equals the captured original identity.
- Readback confirms that no partial candidate management state remains applied. The original interface, route, DNS,
  and certificate baselines remain intact, and the certificate inventory still identifies the same selected public
  leaf. Verify that the acquired DHCP candidate is retired using the native checks below.
- The independent authority confirms the address reservation and exclusive LAN membership remained enforced through
  acquisition and rollback.

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

For each retirement check, retain time-stamped guest and private-peer observations under the same independent LAN
fence. Use the pinned appliance SSH or authorized local console for read-only `ip -j -4 addr show` and route/listener
inspection. Verify the retired address is absent from every guest interface, not merely from saved desired state,
and that no active management listener or owned handoff route still binds that address. Record the actual native
observations after the terminal Apply result; a pending task or unavailable observation cannot establish retirement.

From the admitted private peer, attempt a direct TCP connection to the retired IPv4 address on the configured
management HTTPS port with a bounded timeout, while verifying that the active address remains reachable over the
same path. Do not use DNS, proxy fallback, or a hostname that could select another address. Any accepted connection
at the retired address fails retirement, even when TLS certificate validation or authentication subsequently fails.
A TLS mismatch, HTTP denial, or failed ping alone is not evidence that the listener is gone. Peer connection failure
must agree with native address/listener absence; if peer routing, transport, or the independent fence is uncertain,
preserve the lab and report acceptance incomplete rather than treating a timeout as proof.

## Failure handling and limits

If any admission fact is missing, stale, or ambiguous, make no appliance change and preserve the VM, peer, LAN,
receipts, and evidence for maintainer review. If an Apply result or rollback is uncertain, do not resubmit the
operation
or clean up the lab. Preserve the state, task output, original rollback inputs, and sanitized observations; reconcile
using the supported Atlaso workflow under the same independent address fence. If the original state cannot be
verified, stop and escalate to the maintainer who controls the lab.

Manual acceptance is useful for a maintainer-directed lab decision only. It does not authorize automated certificate
handoff, replace machine-admissible address proof, or permit broader infrastructure mutation. Existing
inspect-certificate-peer.ps1 and inspect-certificate-handoff.ps1 wrappers remain usable only after a supported
producer supplies receipts that pass the native admission checks for the exact task and PR. See the
[VMware lifecycle certificate section](vmware-workstation-lifecycle-testing.md#single-command-run)
for the current producer and wrapper limitations.
