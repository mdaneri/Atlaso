---
title: Offline installation ISO refresh workflow
description: Admit Photon input changes, build development media, and validate it through one receipt-bound workflow.
audience:
  - contributor
  - maintainer
status: current
---

# Offline installation ISO refresh workflow

Use the native VMware refresh workflow to detect Photon package and runtime-profile drift before capture or ISO
assembly, then build and validate one development image against its exact inputs. The production signing and release
path remains the protected hosted workflow described in
[Offline installation ISO build and verification](installation-iso.md).

## Prerequisites

- Run on the supported Windows host with VMware Workstation and the repository's locked Python 3.14
  environment.
- The default plan selects Windows-native `rpm`, `rpmkeys`, and `createrepo_c` from `PATH`. On Windows,
  operators will usually need to select an already configured WSL distribution where `/usr/bin/python3`,
  `rpm`, `rpmkeys`, and `createrepo_c` are available. Configure and verify that distribution separately
  before using it; the selector does not install or configure WSL or its packages.
- Use a clean Atlaso task worktree at the exact installer source commit. For native Photon capture, that
  source must be committed and have an owning pull request so the canonical builder can admit it.
- Select the exact signed Atlaso software directory and pinned Photon source ISO. Record their version,
  source commit, full paths, and SHA-256 identities separately from installer source and output media.
- Resolve the supported Codex `git-worktree-root`. Keep durable task evidence there, outside the task
  worktree and every disposable output root.
- Meet the driver's reported free-space gates on every volume it uses. Capture requires 120 GiB and a new
  two-disk installer VM requires 74 GiB. The driver refuses insufficient capacity; do not lower a gate to
  continue.

Create the immutable plan from the active caller. The existing evidence directory must be outside the worktree;
the ignored output parent must already exist. The generator reads the actual task ID and exact checked-out commit:

```powershell
python -B scripts/refresh_installation_iso.py create-plan `
  --plan <EXISTING-DURABLE-DIRECTORY>/plan.json `
  --software <VERIFIED-SIGNED-SOFTWARE-DIRECTORY> `
  --software-version <X.Y.Z> --software-commit <SIGNED-MAIN-COMMIT> `
  --source-iso <PINNED-PHOTON-ISO> --pull-request-number <OWNING-PR> `
  --output-root <ABSENT-WORKTREE-TEST-RESULT-ROOT> `
  --protected-file <EXISTING-PROTECTED-INPUT>
```

For a fresh capture, the plan generator selects an `iso-inputs-<operation_id>` directory beside the durable
evidence directory. These inputs are retained as reusable source material after
task-worktree cleanup, with their original ownership and capture receipt. They are not disposable VM
artifacts. Use explicit `--rpms` and `--powercli` paths only when selecting previously captured inputs and
provide their original `--capture-receipt` and `--capture-receipt-sha256` selectors. The capture root must
be outside the task worktree and remain under the configured durable worktree root.

To select an independently configured WSL distribution, add
`--native-distribution AlmaLinux-10`. Use the exact existing distribution name; leave the option unset
when the required native tools are already available on Windows `PATH`. Plans store this selector as
`native_distribution`, which is either `null` or one exact distribution name. The selector only chooses
the pre-existing tool environment; it is not evidence that the native tool pipeline has run successfully.
Use the phase's recorded result and evidence to assess each actual run.

When drift reports `requires_review`, `compare` can produce a bounded old-versus-new RPM diagnostic:

```powershell
pwsh -NoProfile -File scripts/windows/vmware/invoke-installation-refresh.ps1 `
  -Plan <ABSOLUTE-DURABLE-PLAN-PATH> -Phase compare `
  -PythonPath <EXISTING-LOCKED-PYTHON-3.14> `
  -OldRpm <OLD-RPM-PATH> -NewRpm <NEW-RPM-PATH>
```

This report is diagnostic only; it never approves changed package behavior or advances an unknown profile.

For reuse, supply the retained RPM and PowerCLI paths plus both `--capture-receipt` and
`--capture-receipt-sha256` from the original successful operation. The native phase entry point is:

```powershell
pwsh -NoProfile -File scripts/windows/vmware/invoke-installation-refresh.ps1 `
  -Plan <ABSOLUTE-DURABLE-PLAN-PATH> `
  -Phase Initialize `
  -PythonPath <EXISTING-LOCKED-PYTHON-3.14>
```

Use the same plan and Python path for `Status` and each lowercase phase: `drift`, `capture`, `admit`,
`build`, `readback`, `install`, `verify`, `cleanup`, and `protected`. Run one phase at a time and wait for
its recorded terminal result before requesting another. `Status` reads the current operation; pending means
the consumer has not reached a proven terminal state.

## Plan identity and paths

`Initialize` admits the exact plan once and binds it to the current caller's task identity. Do not type,
replace, or override `task_id`; do not reuse another task's plan. The generated plan follows this schema:

```json
{
  "schema": 1,
  "operation_id": "0123456789abcdef0123456789abcdef",
  "task_id": "01234567-89ab-cdef-0123-456789abcdef",
  "installer_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "software": {
    "path": "E:\\.codex\\worktree\\inputs\\software",
    "version": "0.9.469",
    "source_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "source_iso": "E:\\.codex\\worktree\\inputs\\photon-5.0.iso",
  "rpms": "E:\\.codex\\worktree\\.evidence\\iso-inputs-0123456789abcdef0123456789abcdef\\rpms",
  "powercli": "E:\\.codex\\worktree\\.evidence\\iso-inputs-0123456789abcdef0123456789abcdef\\powercli",
  "output_root": "E:\\.codex\\worktree\\task\\Atlaso\\test-results\\ir1",
  "pull_request_number": 1234,
  "native_distribution": null,
  "protected_files": [
    {"path": "E:\\.codex\\worktree\\inputs\\photon-profile.json", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
  ],
  "capture_receipt": null
}
```

The UUID and hashes above are examples only. Use the plan generated for the active caller. Paths must be
canonical absolute local paths; URI and UNC paths are refused. The output root must be a new strict
descendant of the task worktree under ignored `test-results/` (for example, `test-results/ir1`). It must not
overlap software, source ISO, RPM or PowerCLI inputs, or protected files. With `capture_receipt: null`,
the RPM and PowerCLI destinations must be separate new directories under the configured durable
worktree root and outside the task worktree. The canonical capture adapter creates them under its original
operation-specific input root before extraction. Original creation records bind output and archive
roots before use; extraction rejects existing destinations and retains directory pins while writing their
contents. Task cleanup removes disposable operation output but retains captured source inputs under their
original owner and receipt.

For reusable inputs, preserve the original `capture-inputs.json` and its original root-creation receipt
outside all removal roots. Reuse is eligible only when the canonical source-compatibility digest and
complete inventory still match. The current official package metadata, full signed RPM set, runtime
profile, and complete RPM transaction are admitted again for each operation. A directory name or a later
snapshot does not establish capture ownership. Do not adopt receipts, caches, media, VMs, or exhausted
validation budgets from another task.

## Run the phases

1. **Initialize, then drift.** Inspect the complete selected package/runtime-profile set against current
   official Photon metadata before capture. The bounded report identifies package name,
   epoch/version/release, architecture and digest. The optional `compare` phase reports bounded native
   metadata and scriptlet differences for selected old/new packages. A same-behavior digest change still
   requires review; unknown runtime behavior requires an explicit
   reviewed source update and a new operation. The report never updates an accepted profile or bypasses
   package authentication.
2. **Capture when requested.** If drift reports `requires_capture`, run `capture`. The canonical VMware
   builder captures the full resolved RPM closure and PowerCLI inputs into the newly receipted durable
   roots outside the task worktree. Those inputs remain available for later receipt-bound reuse.
   Preserve the complete result and any failed builder artifacts for the owning cleanup path. Do not
   restart or repurpose a failed or completed builder. The canonical build wrapper's `-CleanupOnly` path
   handles its exact retained sensitive staging, not the builder VM or all reservations. Keep failed
   resources for their owning diagnosis and cleanup procedure.
3. **Admit.** Run `admit` after drift and, when required, capture. It repeats early drift admission and
   verifies current official package metadata, signatures, every selected identity, full RPM closure and
   transaction, and the reviewed runtime-profile digests. Assembly and installed content inspection retain
   the complete firmware and native module-index checks. A changed or unknown
   profile refuses the workflow until reviewed source and new-source admission are provided.
4. **Build development media.** Run `build` to prepare the payload and assemble the development-only
   image from the exact installer commit, signed-software identity, admitted Photon input, PowerCLI
   modules, and pinned source ISO. This path does not sign or publish a production ISO.
5. **Read back the ISO.** Run `readback` to authenticate the embedded development manifest and compare the
   full file inventory and bytes against the admitted inputs. Confirm the nested signed software manifest
   and wheel identity as well as the outer ISO digest. Partial or pending readback cannot admit
   installation.
6. **Install and reboot.** Run `install` for the canonical `AutoReboot` VMware scenario with installed
   application and full content inspection enabled. The native harness obtains account credentials only
   through its supported bounded credential bridge. Never place passwords in the plan, command line,
   environment, logs, or screenshots.
7. **Verify, then clean up.** `verify` uses the original VM and disk-baseline receipt selectors to
   independently check the appliance and protected unselected disk. `cleanup` is admitted only after
   successful verification and uses the receipt-bound VMware cleanup procedure. It also releases a successful
   capture builder through the canonical provider-aware artifact remover. A failed or interrupted
   installation remains retained for diagnosis; this workflow does not authorize cleanup of failed
   validation resources.
8. **Check protected state.** `protected` verifies the explicitly listed protected files against their
   admitted digests and original filesystem identities. This check covers those files only; it does not
   establish absence of unrelated
   provider registrations, builder VMs, reservations, or external resources. Reconcile each resource with
   its canonical inventory and owning cleanup tool before task handoff.

Each phase has one immutable original start intent, fixed timeout, and source/task/operation binding. Do
not repeat a phase after success, failure, interruption, or ambiguous status, and do not extend its
deadline. A new operation requires a new operation ID, absent output roots, and original creation
receipts. Preserve failed evidence and report exact passed, failed, reused, and pending stages.

The validation scope is VMware development media and its stated native install, reboot, account, and
content checks. It does not establish physical hardware, Update/rollback, certificate-address, USB, or
production release acceptance. Do not replace installed helpers, change host networking, capture a
credentialed console, or publish/sign development media.

## Focused validation for code changes

Run focused tests `tests/test_installation_refresh_plan.py`,
`tests/test_installation_refresh_receipt.py`, `tests/test_installation_refresh_drift.py`, and
`tests/test_installation_readback.py`, `tests/test_installation_refresh.py`, and
`tests/test_installation_refresh_runner.py`, plus the recorded PowerShell driver checks. Do not substitute the
exhausted #542 strict-documentation attempt budget or claim another task's validation evidence.
