---
title: Automation
description: Schedule supported tasks and manage immutable automation scripts safely.
audience:
  - operator
status: current
---

# Automation

Atlaso's core scheduler runs in the separate persistent `atlaso-worker.service`. The web process creates task and
schedule records; the worker claims pending work and writes the normal task, audit, result, and error history. It
supports:

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Automation page in the clean-appliance desktop viewport.](../assets/screenshots/automation-clean-desktop.webp)

*Figure: Automation in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

- Appliance Update checks and installs with selected update streams.
- Enabled VCF Offline Depot download profiles. The worker rechecks the profile immediately before execution, so a
  profile disabled after queueing fails closed instead of starting a download.
- Explicitly enabled immutable managed-script revisions.

Schedules use either a one-time local date/time or a standard five-field cron expression
(`minute hour day month weekday`) with an IANA timezone such as `UTC` or `America/Los_Angeles`. Execution timestamps are
stored in UTC. Missed runs and overlaps are not replayed: the scheduler advances to the next time and does not queue a
second active task for the same schedule.

Schedules can be edited, enabled or disabled, run immediately, and deleted. **Run now** creates a normal queued task
with a `manual_schedule` trigger and does not change the next calculated recurring run. The Automation table shows the
latest task state; full execution output remains on the Tasks page.

The Automation workspace uses three tabs:

- **Schedules** fills the available workspace with the schedule grid. The standard State control enables or disables a
  schedule directly. Run now, Edit, and Delete live in the row context menu rather than consuming columns.
- **Executions** lists every task queued by a schedule, including succeeded and failed runs, and links each row to the
  associated Tasks detail view.
- **Managed Scripts** provides the immutable script-revision grid and source editor.

Adding or editing a schedule opens the five-step wizard: schedule identity and task type, task-specific inputs, timing,
enabled state, and review. The second step changes with the selected task: update streams, a VCF Offline Depot profile,
or an enabled managed-script revision and its parameters. The timing step includes an hourly/daily/weekly/monthly cron
builder with a generated summary; advanced operators can choose Custom for a standard five-field expression. The same
wizard is used for edits.

## Managed scripts

Creating or editing a script always creates a new immutable, disabled revision. An administrator must review and enable
a particular revision before it can be run manually or selected by a schedule. Schedules remain pinned to that exact
revision; disabling it makes execution fail closed.

Managed-script rows edit name, description, interpreter, timeout, and state in the grid. Source is opened through the
compact source action in a nearly full-window CodeMirror modal, which also imports `.sh`, `.bash`, `.py`, `.ps1`, or
`.txt` files up to 1 MiB. An edit that changes revision-owned fields creates a new disabled immutable revision; it never
rewrites historical source. When a script has at least two revisions, selecting its revision cell opens a
near-full-window, two-column comparison. Base and comparison selectors list every immutable revision with its creation
date and state, so operators can compare any two revisions. The viewer aligns corresponding rows, shows original line
numbers, collapses long unchanged runs, colors removals and additions, and uses a Prism grammar selected from the script
interpreter.

**Run latest revision** opens a confirmation modal instead of immediately creating a task. The modal names the exact
revision and interpreter and accepts the same literal parameter syntax used by schedules. Schedule and manual-run
parameters are entered as one logical command line. Bash and Python use backslash line continuation and POSIX-style
literal argument parsing; PowerShell uses the backtick continuation marker and PowerShell-style quoting. Atlaso passes
the resulting argument vector directly to the selected script without a second shell-expansion pass. Parameters are
bounded, stored with the schedule and task history, and must not contain secrets.

Atlaso prevents disabling a revision used by an enabled schedule and prevents deleting a script while any schedule
references one of its revisions. The operator must disable, edit, or delete those schedules first. Script deletion
removes its stored revisions but preserves existing task history.

Interpreters are allowlisted to Bash, system Python, and PowerShell. The helper runs scripts as the dedicated
`atlaso-automation` account in a transient systemd unit with:

- no sudo or root identity;
- `NoNewPrivileges=yes`;
- a private temporary directory and protected home directories;
- a read-only system filesystem except for `/var/lib/atlaso/automation/runs`;
- the revision's configured timeout, capped at 24 hours.

Scripts receive no Atlaso credentials by default. A schedule or manual run may select one named VCF/ESX password vault.
Atlaso stages that vault as a transient systemd credential and provides `atlaso-vault get --key <key>` to Bash/Python
and `Get-AtlasoVault -Key <key>` to PowerShell. The helper fails outside the scoped process and exact injected values are
redacted from captured output. Output is bounded in task history. Script definitions and schedules are included in
settings archives, but restored revisions and schedules are always disabled and vault contents are never exported. See
[Vaults](../services/vaults.md) for the complete key, scope, and recovery contract.

## Service operations

```bash
systemctl status atlaso-worker --no-pager
journalctl -u atlaso-worker -n 120 --no-pager
```

If the worker restarts during a task, that task is marked failed and is not silently replayed. A queued task that was
never claimed remains pending.

## Task history and output

Scheduled work always creates normal Atlaso Jobs, so it appears in both the Automation **Executions** tab and `/tasks`.
The Tasks grid uses backend-owned filtering and pagination. Status and state are fixed lists; Task / Component is an
autocomplete list built from recorded job types and component labels while still accepting a custom job id, task, or
component fragment.

Task detail keeps the complete redacted result payload for audit and diagnosis, but **Console output** shows only the
managed process stdout and stderr. The helper execution envelope is removed from that console view, stdout keeps the
normal terminal colors, and stderr is shown separately in red. Result and log previews keep copy/open controls overlaid
in the corner without reserving blank text rows.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Automation

![Atlaso Automation page in the clean-appliance responsive viewport.](../assets/screenshots/automation-clean-responsive.webp)

*Figure: Automation in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
