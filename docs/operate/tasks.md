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

Pending and running tasks are not proof that appliance state changed. Treat only a successful terminal result plus the
service-specific verification as success.

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
