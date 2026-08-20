---
title: Apply appliance changes
description: Review, submit, monitor, and verify desired-state changes on the Atlaso appliance.
audience:
  - operator
status: current
---

# Apply appliance changes

Use Appliance Apply after editing Atlaso settings to enforce selected desired state on the Photon appliance. The review
is global: one submission can apply related changes from several service pages in a controlled order.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Review appliance changes dialog with selected valid units and one unit needing attention.](../assets/screenshots/appliance-review-modal-desktop.webp)

*Figure: Appliance change review with valid and invalid desired-state units.*

<!-- END GENERATED INTERFACE OVERVIEW -->

!!! important
    Editing and applying are separate actions. Autosave updates Atlaso's desired state; it does not change Photon
    services. Host changes begin only after an administrator selects valid units and chooses **Submit appliance
    changes**.

## Before you begin

You need:

- an administrator account with permission to apply appliance changes;
- saved desired-state changes on one or more service or settings pages;
- validation errors resolved for every unit you intend to submit; and
- no other Appliance Apply task pending or running.

If a change can interrupt management access, use the local appliance console or VMware console as a recovery path
before submitting it.

## Understand the workflow

```mermaid
flowchart LR
    A[Edit desired state] --> B[Review pending units]
    B --> C{Unit valid?}
    C -- No --> D[Return to its settings page]
    D --> B
    C -- Yes --> E[Inspect summary and diff]
    E --> F[Submit selected units]
    F --> G[Monitor component tasks]
    G --> H[Verify appliance state]
```

Atlaso groups related settings into apply units. For example, DNS and DHCP share one `DNS/DHCP (dnsmasq)` unit because
they use the same generated configuration and service reload. A change can affect several units; Web Terminal listener
changes commonly require **Appliance Settings**, **Public Services**, and **Firewall** together.

## Review pending changes

1. Finish editing the desired state on the relevant service pages.
2. Open **Review appliance changes** from the lower-left sidebar card or a page-level pending-change action.
3. Read the status of every changed unit:

   | Status | Meaning | What to do |
   | --- | --- | --- |
   | **valid** | The desired state passes current validation. | Inspect it and keep it selected if it belongs in this run. |
   | **needs attention** | Atlaso found an error that prevents submission. | Open the unit's page, correct the error, and review again. |
   | Warning | The unit is valid but has an operational caution. | Read the warning and confirm the effect before submission. |

4. Expand each selected unit and inspect its summary and rendered difference.
5. Clear the checkbox for a valid unit that should remain pending for a later run.

Valid changed units are selected by default. Invalid units are not submitted. Unselected units remain in the pending
count after the task starts.

!!! warning
    Review all related units together when one feature crosses service boundaries. Submitting only part of a related
    change can leave the new behavior unavailable until the remaining units are applied.

## Submit and monitor

1. Confirm that the selection contains only the units intended for this run.
2. Choose **Submit appliance changes**.
3. Keep the task dialog open while the master task and its component rows progress.
4. Open a component row to inspect its bounded, redacted result.
5. Wait for the master task to reach a terminal state. The dialog, lower-left sidebar badge, pending count, and global
   write lock update automatically; a page reload is not required.

If another session starts a new Apply immediately after the current master finishes, the monitor completes the current
task's terminal refresh before following the newer task.

Components run sequentially. If one component fails, Atlaso stops the sequence and marks the remaining components
**skipped**. Other write operations are locked while the master task is pending or running; read-only pages, task
inspection, authentication actions, and safe cancellation remain available.

A management-path change is the exception to independent component execution: if any of Certificate Authority,
Network, Firewall, Appliance Settings, or Public Services is submitted while such a Network change is pending, Atlaso
selects all five together and runs them as one recoverable handoff. The task
keeps every previous configured or runtime global address, public port, HTTP/HTTPS listener, and snapshotted TLS
certificate active until consecutive bounded checks on the applicable old and candidate public ports prove the Atlaso
loopback upstream, candidate nginx listener, and host-facing `/openapi.json` are ready.
The same transaction moves the management resolver to the candidate interface and persists its directives in the
effective dedicated or flagged-access physical/VLAN networkd file. Atlaso writes those directives again after the final
Network install so a later networkd restart or appliance reboot retains them. If either resolver apply fails, rollback
restores the previous networkd resolver directives and per-link runtime state before the old path readiness check.
Every candidate that requests DHCP or SLAAC must acquire and pass readiness on that address family; another static or
dynamic listener cannot mask a missing lease or router-advertised address. When the same Apply disables the firewall,
the transition retains the previous filtering policy with minimal candidate listener admission until readiness. When
the same Apply enables filtering from an open state, the transition remains open until readiness. In both directions,
the candidate firewall state applies only while retiring the old path.
If rollback started from a state with no Atlaso firewall config or service, it disables and stops any candidate service,
removes the candidate unit/config through the snapshot restore, reloads systemd, and explicitly flushes nftables back
to the previous open policy.
On failure, each bundled
component records the same failing layer
and rollback result. The handoff applies only the management front-door portion of Appliance Settings; unrelated
Appliance Settings differences remain pending for a later Apply instead of being folded into the network transaction.
An active appliance without a last-applied Network baseline cannot safely identify its previous management path, so
Atlaso blocks Network apply without host mutation until a known-good settings archive restores that baseline or a
maintainer completes local-console recovery.
Desired-state edits saved from another session while readiness checks run are not folded into the successful task.
Atlaso commits baselines from the exact submitted snapshots, so those newer edits remain pending for a later review.
Atlaso records durable application-commit proof separately from the retained helper marker. After a restart it retries
rollback unless that proof exists; only a proven database commit selects idempotent helper acknowledgement.

Safe cancellation does not interrupt the component already running. Every helper or adapter command in that component
continues to completion. After the component returns, Atlaso skips the remaining components and releases the mutation
lock when the master task becomes terminal.

When a real Appliance Settings component reaches its planned management-service restart, the dialog shows **Applying
management settings; Atlaso is reconnecting to task status.** This neutral state keeps the last known task progress and
global lock visible. Leave the dialog open: Atlaso retries every two seconds, clears the notice when the front door
returns, and follows the same master task to its terminal state without a page reload. The bounded reconnect interval
uses the remaining server-owned restart window reported with each task response. A browser opened or resumed after the
scheduled restart therefore cannot start a fresh grace interval, and clock differences between the browser and appliance
do not change the boundary. For a settings-only apply, the completed master remains visible and keeps appliance changes
locked only until that restart window ends.

If that reconnect exceeds the bounded grace window, or a status failure is not part of the planned restart, the dialog
instead shows **Live task status is temporarily unavailable** with a link-free instruction to open **Tasks** in another
tab if the problem persists. Atlaso continues retrying and retains the last known task and lock until an authoritative
response arrives. Use Tasks to inspect the master task and verify appliance connectivity before deciding whether to
reload the affected page.

## Verify the result

Do not treat a submitted task as proof that the appliance changed successfully.

1. Confirm that the master task is **succeeded**.
2. Confirm that every selected component is **succeeded**, not **failed** or **skipped**.
3. Return to the affected service page and confirm its pending indicator cleared.
4. Verify the resulting runtime behavior from the relevant service guide.

When enabling local DNS, apply **DNS/DHCP (dnsmasq)** before the subsequent Appliance Settings resolver change. Atlaso
keeps the last-applied external or DHCP resolver active until the DNS/DHCP unit is applied, so an unapplied local-DNS
selection cannot redirect the appliance to loopback prematurely.

Examples include checking service health, resolving a managed DNS name, reaching the intended listener, or confirming
the installed configuration from the appliance console. Use the service-specific verification procedure rather than
relying only on a green UI status.

In development, adapters normally run in dry-run mode. A successful dry-run proves that Atlaso validated and recorded
the command intent; it does not prove that Photon services changed.

## Recover from a failed apply

1. Open the failed component and read its validation, error, and redacted command output.
2. Correct the desired state on the owning service page.
3. Review the pending units again. Units that succeeded earlier keep their updated baselines; failed and skipped units
   remain pending when their desired state still differs.
4. Submit only the units required for the corrected run.

If Atlaso restarts during an ordinary apply, startup fails the running child and master task, skips pending children,
and releases the global lock. For an interrupted management handoff, the privileged helper first stops and verifies any
surviving apply process, restores the captured previous runtime state, and records the recovery result.
The same path runs immediately after a helper wait timeout because the fixed apply service can outlive its waiting
process. Recovery uses a separate fixed service identity; before retrying, the helper stops and verifies any surviving
recovery service so two rollback attempts cannot mutate the same network state concurrently.
The helper retains that rollback state until Atlaso durably commits the bundled component results and baselines. If a
restart occurs after that database commit, startup idempotently acknowledges the committed candidate instead of falsely
claiming a rollback. A failed task whose helper acknowledgement or rollback is not proven retains the global Apply lock
until startup or immediate exception recovery reconciles that state, even when an older task payload lacks the newer
pending marker. Review the task before resubmitting.

If a selected unit changed after submission but before execution, Atlaso fails closed and asks for a new review. This
prevents a queued task from applying state that the administrator did not inspect.

## Safety boundaries

- `/ui/management/appliance-apply` is the only desired-state host-mutation workflow.
- Only one Appliance Apply master can be pending or running.
- Photon mutations use constrained `atlaso-helper` actions; the web process does not receive broad root access.
- Previews, diffs, task results, logs, and audit details redact sensitive-looking values.
- Secret-bearing Local Users, Certificate Authority, and Managed LDAP inputs use mode `0600` only during their helper
  execution window. Both the control plane and helper remove them on terminal outcomes, and startup removes stale
  inputs after interruption.
- Read-only Local Users status uses an isolated short-lived input and cannot overwrite a pending apply payload.
- A successful component updates only that component's last-applied baseline.
- Fresh-appliance baseline initialization records comparison metadata only; it does not run helper commands.

## Complete technical contents

No original section was removed. The [Appliance Apply technical reference](../reference/appliance-apply-technical.md)
is divided into these scannable groups:

| Reference group | Contents |
| --- | --- |
| [Workflow and execution model](../reference/appliance-apply-technical.md#workflow-and-execution-model) | Backend routes, global locking, helper boundaries, and apply-unit ownership. |
| [Appliance and network units](../reference/appliance-apply-technical.md#appliance-and-network-units) | Users, inventory, networking, routing, and DNS/DHCP. |
| [Infrastructure and security units](../reference/appliance-apply-technical.md#infrastructure-and-security-units) | PXE, storage, firewall, backups, certificates, and KMS/KMIP. |
| [Appliance settings and operations](../reference/appliance-apply-technical.md#appliance-settings-and-operations) | NTPsec, appliance settings, logs, power, tasks, and VCF Offline Depot. |
| [State, results, and interface contracts](../reference/appliance-apply-technical.md#state-results-and-interface-contracts) | Baselines, diffs, job results, recovery, and UI expectations. |
