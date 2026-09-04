---
title: Recover a retained 1Password credential bridge
description: Inspect and safely reset an exact retained Windows credential bridge without deleting its ownership marker.
audience:
  - operator
  - maintainer
status: current
---

# Recover a retained 1Password credential bridge

Use the supported recovery command when a Windows VMware workflow reports retained 1Password credential-bridge
cleanup. The command operates only on the fixed marker in the checkout from which it is run. It never retrieves a
credential or opens the 1Password SDK.

## Inspect retained state

Run inspection from the same Atlaso checkout that reported the blocker:

```powershell
pwsh -NoProfile -File `
  .\scripts\windows\vmware\reset-atlaso-onepassword-credential-bridge.ps1 `
  -Inspect
```

The report contains only these sanitized fields:

- marker phase and Windows boot relation;
- recorded controller and child state;
- named-job and bridge-root state;
- the safe next action and a fixed blocker code.

Inspection does not terminate a process, remove a directory, rewrite the marker, authorize 1Password, or retrieve an
Environment variable. `-WhatIf -TerminateOwnedProcess` previews the explicitly authorized active-job path with the same
boundary.

## Reset proven-inactive state

If inspection reports that the recorded controller is absent and the child/job are inactive, run:

```powershell
pwsh -NoProfile -File `
  .\scripts\windows\vmware\reset-atlaso-onepassword-credential-bridge.ps1
```

PowerShell prompts before this high-impact reset. Review the inspection result and confirm only when the reported
ownership state matches the intended bridge. Unattended automation may pass `-Confirm:$false` only after performing
and evaluating the same inspection.

The command revalidates the schema, current checkout marker, boot identity, the durably recorded creation-time
temporary parent and its filesystem identity, exact bridge-root namespace and filesystem identity, reparse-free
ancestry, controller and child PID/start identities, job name, and ownership phase before it
changes state. It removes only the exact identity-matching bridge root, flushes its parent directory, durably advances
the marker through `root-absent` and `retired`, removes the marker, and flushes the marker directory. A missing marker,
an already completed terminal phase, and a repeated reset are successful no-ops.

The reset does not depend on the invoking shell's current `TEMP` or `TMP`; use the same checkout even when those
environment variables changed after the interrupted workflow.

## Terminate an exact owned job

If inspection reports `JobState: active-owned` and `Action: rerun-with-terminate-owned-process`, authorize termination
of only the recorded job:

```powershell
pwsh -NoProfile -File `
  .\scripts\windows\vmware\reset-atlaso-onepassword-credential-bridge.ps1 `
  -TerminateOwnedProcess
```

This path also presents the high-impact confirmation prompt before terminating the exact job or removing retained
state.

Immediately before termination, recovery reopens the exact `Local\Atlaso-OnePassword-<32-hex>` job, verifies the
recorded child PID/start identity and membership, and captures every active job member. It terminates the job as one
ownership boundary, proves the job has no active members, and proves the recorded child and every captured process are
inactive before removing the bridge root.

Recovery never terminates the recorded VMware controller because the controller is outside the authoritative job. If
it is still active, allow the original workflow to exit and inspect again.

## Resolve a blocked reset

No process or file is changed when ownership is ambiguous:

- A reused controller or child PID is never terminated.
- An active child without its exact job is never terminated.
- A job with an unrecorded active descendant is never terminated.
- A current-boot legacy marker cannot use same-boot reset because it has no process-ownership evidence.

For those process-evidence blockers, restart Windows and rerun the original VMware workflow. A changed boot proves the
legacy process tree inactive and lets the existing compatibility recovery retire an otherwise valid legacy marker.

A malformed marker, inaccessible identity, reparse point, replaced root, changed marker or marker-directory identity,
or a terminal marker paired with a present root requires maintainer investigation. Preserve the marker and root while
investigating. Error output intentionally omits marker contents, process identifiers, job names, filesystem paths,
1Password Environment or account identifiers, authenticated URLs, arguments, and credential material.

Never delete or rename the marker manually. The marker is the durable evidence that prevents recovery from targeting
an unrelated process, job, or directory.

## Verify recovery

Run inspection again. A completed reset reports `MarkerState: absent`, `Action: already-reset`, and `Result:
inspection`. Then rerun the original VMware command from the same checkout. Credential preparation should proceed
without the retained-cleanup blocker; any new 1Password authorization or package-source failure is a separate preflight
result and does not justify deleting recovery state.
