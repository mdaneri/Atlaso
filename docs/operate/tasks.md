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
