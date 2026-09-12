---
title: Tasks
description: Follow Atlaso jobs from submission through terminal result and sanitized execution evidence.
audience:
  - operator
  - maintainer
status: current
---

# Tasks

Open **Tasks** to follow appliance apply, update, automation, and service operations. Each row represents one auditable
job with its type, state, timestamps, and result.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Tasks page in the clean-appliance desktop viewport.](../assets/screenshots/tasks-clean-desktop.webp)

*Figure: Tasks in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Follow a task

1. Locate the highlighted task after submitting an operation.
2. Open its detail view to inspect ordered steps, selected units, validation, and result.
3. Wait for a terminal state: succeeded, failed, skipped, or cancelled.
4. For appliance apply, confirm that selected and skipped units match the review submission.

When you open several task logs in quick succession, the last task selected owns the log dialog. Atlaso cancels the
older request where possible and ignores any stale success or error that arrives after the newer selection or after the
dialog was closed.

Pending and running tasks are not proof that appliance state changed. Treat only a successful terminal result plus the
service-specific verification as success.

During a real Appliance Update installation, nginx temporarily replaces ordinary management and public browser pages
with the update-only status surface. That page is a bounded projection of this same parent/child hierarchy, including
the exact task ID, ordered Photon OS, PowerShell Modules, and Atlaso Release children that were selected, their states,
and parent progress. It intentionally omits logs, commands, credentials, source locations, and detailed errors. A
terminal page is not yet proof that ordinary UIs can reopen: Atlaso first reconciles release/finalizer evidence, any
scheduled worker restart, nginx reload, and browser-listener health. If the appliance reboots during that interval, the
same durable task identity remains on the status page until restoration is proven.

VCF Offline Depot downloads use the same task type for profile-row starts and Automation starts. Their result records
identify the profile, trigger, optional schedule, planned time, and sanitized task log. A scheduled VCFDT overlap is a
terminal **skipped** task linked to the already-active profile download, Software Depot ID task, or VCF Offline Depot
Appliance Apply; a failed execution-time prerequisite is a terminal **failed** task. Neither outcome implies depot
content changed, and neither is replayed automatically.

## Diagnose a failure

Read the failed step and sanitized task log, then correlate its identifier with [Operational logs](logs.md) and the
[Audit log](audit-log.md). Correct desired state in the owning page and submit a new task. Do not edit task history or
fabricate a successful result.

## Cancellation and execution ownership

Tasks and the API expose the same backend-owned `can_cancel`, `cancel_reason`, and `cancel_confirmation` fields.
The task detail shows the reason even when cancellation is unavailable. A stale browser action cannot override the
backend policy. An accepted request records `cancel_requested_at` and `cancel_requested_by`; running work keeps its
active status until its owner verifies the stop and cleanup. `cancel_completed_at` and `cancel_outcome` record the
final disposition. `cleanup-required` remains active and blocks worker admission while recovery needs attention.
A media failure racing an accepted cancellation confirms the stop once rollback and upload cleanup succeed;
only unresolved cleanup retains that queue hold. Startup recovery also requires proof that no unresolved swap journal,
replacement tree, or staging directory remains. Malformed recovery evidence retains the request and queue hold
until recovery succeeds. Embedded Appliance Update actions use the current caller's permissions.
Do not interpret a cancellation request as proof that a local process or a remote operation stopped.

| Task owner | Queued cancellation | Running cancellation |
| --- | --- | --- |
| Appliance Update check | Reserved before worker claim | Current bounded check finishes and cleans credentials; remaining checks skipped |
| Appliance Update installation or source synchronization | Reserved before worker claim | Unavailable; existing update/recovery owner must finish |
| Appliance Apply | Cancelled before its atomic execution claim; apply lock released | Current component and cleanup finish; remaining components skipped; applied changes remain |
| Network Boot media download/upload | Reserved before claim; owned upload removed | Transfer/extraction checkpoint, then staged filesystem rollback and upload cleanup |
| Network Boot media deletion | Reserved before worker claim | Unavailable once destructive deletion starts |
| Managed script | Reserved before worker claim | Unavailable because script side effects have no generic rollback contract |
| VCF depot download | Reserved before claim; queued profile status restored | Unavailable until the VCFDT owner finishes |
| Diagnostic bundle | Reserved before worker claim | Unavailable; bounded collector descendant shutdown is not verified |
| VCF software identity replacement | Unavailable | Unavailable; identity operation owner must finish |
| Remote SDDC deployment, depot target configuration, or CA trust | Unavailable | Unavailable; stopping a watcher does not stop or undo remote work |
| Manual placeholder | Cancelled before execution | Unavailable |
| Other/unregistered task types | Unavailable | Unavailable until an explicit safe owner contract is registered |

An update check request can wait up to six minutes for the current helper's deadline and credential cleanup. Media
cancellation checks before each transfer attempt and after each 1 MiB read. A network operation can wait up to its
300-second socket timeout (including each bounded redirect); extraction commands have 60-second deadlines.
Cancellation does not
interrupt filesystem publication halfway through. Failed cleanup retains active ownership and the request for
recovery. Worker restart
revalidates task-owned update units or restores interrupted media swaps before confirming cancellation.
Web startup confirms accepted queued Apply cancellations before classifying other interrupted Apply jobs.
Paired Firewall/NAT publication finishes as one transaction; a request after its final work preserves completion.

Completed child results remain intact. A verified parent stop skips children that never started. If completion wins
the race, Atlaso preserves success or failure and records `completion-won`; repeated requests never rewrite that result.
The API requires `admin:all`; browser administrators can request supported cancellations, while service administrators
are limited to supported Network Boot media tasks. Child rows cannot independently cancel their parent's operation.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Tasks

![Atlaso task detail dialog for a failed appliance apply.](../assets/screenshots/tasks-apply-failed-detail-desktop.webp)

*Figure: Failed appliance apply task with redacted operator detail.*

![Atlaso task detail dialog showing a successful DNS appliance apply.](../assets/screenshots/tasks-apply-succeeded-detail-desktop.webp)

*Figure: Successful appliance apply task with verified dnsmasq output.*

![Atlaso task log showing successful dnsmasq validation, apply, and reload.](../assets/screenshots/tasks-apply-succeeded-log-desktop.webp)

*Figure: Successful appliance apply log with captured commands and audit events.*

![Atlaso Tasks page in the clean-appliance responsive viewport.](../assets/screenshots/tasks-clean-responsive.webp)

*Figure: Tasks in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
