---
title: Operate Atlaso
description: Run the appliance, review desired state, inspect tasks, and maintain runtime health.
audience:
  - operator
status: current
---

# Operate Atlaso

Use these guides for day-to-day appliance work:

- [Dashboard](dashboard.md) — read-only operational attention and setup readiness.
- [Primary navigation](navigation.md) — collapse sidebar sections while keeping the current page and pending changes
  available.
- [Monitor](monitor.md) — runtime CPU, memory, network, disk-activity, and interface health.
- [Operational logs](logs.md) and [Audit log](audit-log.md) — correlate runtime evidence and operator actions.
- [Tasks](tasks.md) — follow submitted operations to a verified terminal result.
- [Appliance Apply](appliance-apply.md) — review and submit selected desired-state changes.
- [Appliance settings](appliance-settings.md) — manage appliance-wide identity and access desired state.
- [Network configuration](networking.md) — physical interfaces, VLANs, routing, and WAN desired state.
- [Local appliance console](appliance-console.md) — local status and recovery access.
- [Appliance Update](appliance-update.md) — signed Atlaso, PowerShell, and Photon update streams.
- [Backup and restore](backup-restore.md) — protect and recover Atlaso settings.
- [Automation](automation.md) — schedules, executions, and immutable managed scripts.
- [Use the Atlaso API](api.md) — create scoped tokens, call `/api/v1`, and interpret errors and apply boundaries.
- [Web Terminal](web-terminal.md) — constrained browser terminal sessions.

Editing desired state and enforcing it are separate actions. Routine forms autosave safely; host mutation occurs only
after deliberate review and submission through the global apply workflow.
