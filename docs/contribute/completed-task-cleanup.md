---
title: Completed task cleanup command
description: Preview and reconcile owned task resources, Git refs, worktrees, and completion titles.
audience:
  - contributor
  - maintainer
status: current
---

# Completed task cleanup command

Use `scripts/cleanup-completed-task.ps1` from the primary checkout for eligible completed ordinary tasks.
It requires Python 3.14, Git, authenticated GitHub CLI, and a live cleanup controller with supported Codex task tools.
Generated-directory release additionally requires Windows. The controller supplies fresh task evidence through
stdin; the command independently checks GitHub, Git, configuration, and filesystem state. No private Codex database,
rollout editing, guessed server endpoint, administrative bypass, or execution-policy override is used.

## Prepare durable ownership evidence

The originating task records resources as they are created. Its `cleanup-ready` handoff must survive outside its
worktree and every resource being removed, beneath the configured `desktop.git-worktree-root` or another explicitly
permitted durable controller surface. This command currently accepts its evidence directory beneath that configured
root only. Read the exact supported Codex `config.toml`; never infer a worktree root from an existing path.
The supplied configuration must be the active `CODEX_HOME/config.toml` (the standard user Codex directory when
`CODEX_HOME` is unset), not a replacement supplied by the cleanup handoff.

Provide a UTF-8 JSON handoff with these schema-1 fields:

| Field | Required evidence |
| --- | --- |
| `schema` | Integer `1`. |
| `task_id`, `description` | Exact Codex task identity and short description without traceability segments. |
| `repository` | Exact public same-repository GitHub `owner/name`. |
| `primary_checkout`, `worktree` | Absolute paths independently verified against Git registration. |
| `worktree_identity` | `[st_dev, st_ino]` recorded with Python `Path.stat()` when the task worktree was created. |
| `branch`, `head`, `merge`, `pr` | Exact owned branch, full PR head SHA, squash SHA, and positive PR number. |
| `issues` | Every closing issue number returned by GitHub for this PR. |
| `resources` | Complete bounded inventory, or explicit `[]` with independently verified empty-inventory evidence. |

A resource has `id`, `kind`, `task_id`, `source_commit`, and its exact provider/path identity and original ownership
manifest. Supported kinds are `generated_tree`, `vm`, `lifecycle`, `artifact`, `reservation`, `credential_bridge`,
`process`, and `configuration`. Specialized kinds require an existing supported owning tool; a kind name does not
prove that capability. Preserve unsupported, retained, shared, permanent, user-created, active, or ambiguously owned
resources and report the missing evidence or owning cleanup capability.
The recorded creation `source_commit` must be the PR head or one of its ancestors; retain original resource identity
when validation ran before later review commits.

For `generated_tree`, include an absolute `path` strictly beneath the task worktree and `root_identity`, the identity
array from `WindowsFiles().snapshot(path)["."]["identity"]` in `scripts.completed_task_files`. Record this at creation,
with task ownership; a cleanup-time snapshot alone cannot establish ownership. The command captures and reports every
ordinary entry at preview/execution time. It rejects tracked files, reparse points, hard-linked files, nested Git
repositories, and Git/credential-recovery roots. It pins ancestors and deletes matching objects through Windows
handles; changed objects or new children stop removal and preserve remaining entries. Partial releases require a fresh
inspection on retry. Never retrofit ownership merely because a directory is called `node_modules` or `site`.

Primary-checkout restoration, private advisory cleanup, non-task-owned branch/checkout exceptions, multi-PR tasks, and
issue-less Dependabot tasks retain their existing policy workflows. This entry point refuses unsupported eligibility
instead of relaxing their gates. Do not use its directory removal primitive for those exceptions.

## Preview and execute

From the verified primary checkout, supply absolute paths in these PowerShell variables:

```powershell
pwsh -NoProfile -File scripts/cleanup-completed-task.ps1 -Handoff $handoff -Evidence $evidence -Config $config
```

Omitting `-Execute` is a read-only preview. It does not fetch, create evidence files, release resources, mutate refs,
remove worktrees, or rename tasks. Read the proposed exact entries/refs and any refusal. Execute with the same inputs:

```powershell
pwsh -NoProfile -File scripts/cleanup-completed-task.ps1 -Handoff $handoff -Evidence $evidence -Config $config -Execute
```

Execution revalidates every transition; a saved preview is never authorization. The terminal order is
`validation_resources_released`, `remote_branch_absent`, `worktree_removed`, then `task_title_done`.
Remote deletion uses an atomic expected-SHA lease and verifies absence. Worktree removal uses non-forced
`git worktree remove`. The exact unreferenced local ref is separately removed with an old-SHA compare-and-swap and
verified absent. Remaining ignored files block resource completion before branch removal.

## Live controller protocol

Run the command with bidirectional stdin/stdout, such as an agent-controlled terminal session. Each stdout JSON line
with `kind: "controller_request"` contains a unique `id`, `operation`, and `payload`. The controller performs fresh
supported-tool reads for that request, then writes exactly one JSON line to stdin:

```json
{"id":"the-current-request-id","result":{"handoff_sha256":"the-requested-digest"}}
```

That minimal example illustrates framing only; each operation requires the complete result below. Responses are
bounded to 256 KiB and 120 seconds. A mismatched nonce, missing field, error, EOF, or timeout refuses the transition.
Never pipe a saved response sequence into execution. The bridge is a trusted controller boundary, not authentication
against a malicious operator who can write stdin or edit the program. Keep the originating task idle and unpinned for
the entire reconciliation; a maintainer restarting it must stop cleanup first. Fresh snapshots do not provide a
cross-application atomic activity lock.

### Task inspection

For `task.inspect`, use supported `list_threads` and `read_thread` controls, paging as necessary. Independently bind
the handoff to the originating task's recorded creation/cleanup evidence; the handoff's claims alone are insufficient.
Inspect other owners, current pin/activity state, every linked PR/issue, review disposition, maintainer holds, resource
inventory and ownership manifests, completed chained post-merge workflows, and downstream needs. Do not equate idle
with cleanup-ready, an absent resource with ownership, or an empty workflow response with completion.

Return `handoff_sha256`, nonempty durable sanitized `evidence_refs`, and each of these fields as literal `true` only
after verification: `identity_verified`, `exclusive_ownership_verified`, `idle`, `unpinned`, `holds_clear`,
`downstream_clear`, `inventory_verified`, `post_merge_complete`, `reviews_complete`, and `supported_tools_used`.
For an empty inventory, also return `inventory_empty_verified: true` after explicitly verifying
`validation_resource_inventory_empty`.
Missing capabilities must return a refusal. This is the controller's independent evidence attestation; the script
does not infer semantic ownership or maintainer intent from task titles.

### Resource inspection and owning tools

For `resource.inspect`, independently check the exact resource/provider, manifest, process/boot identity where
applicable, and surviving reservations/claims/recovery state. Return literal booleans `ownership_verified`, `inactive`,
`retained`, `supported_cleanup`, `evidence_preserved`, and `absent`. Preserve durable sanitized evidence outside every
removal root. For no resources, task inspection must explicitly verify `validation_resource_inventory_empty`.

For `resource.release`, call only the resource's existing supported owning tool with exact identity arguments:
`remove-atlaso-vm.ps1`, `remove-lifecycle-vms.ps1`/`-CleanupVmsOnly`, or the documented
`Remove-AtlasoWorkstationArtifactRoot` path with independent strict-descendant checks, as appropriate. Reservations,
credential bridges, processes, and configuration require their own documented recovery/cleanup entry points. Do not
substitute broad deletion or stop unrelated processes. Return `success: true` only after that tool succeeds. The script
requests another independent `resource.inspect`; release acknowledgement alone cannot complete the resource gate.
Generated trees are removed by this command and still receive independent absence readback.

### Completion title

For `task.title`, use supported `set_thread_title` with the exact supplied title, then `read_thread` to retrieve the
persisted title. Return `persisted_readback: true` and `observed_title`. The script uses `completed_task_title.py` to
format and verify all linked identifiers and the single Done suffix. Do not archive the task. If mutable title controls
are actually unavailable, return `capability: "unavailable"` and concrete `capability_evidence`; record the documented
not-applicable exception without claiming a visible Done suffix. A denied or failed available control is a failure,
not an unavailable capability.

## Failure and interrupted recovery

Exit zero means a successful preview or completed execution; inspect the JSON `status` to distinguish them. Exit one
and `status: "refused"` give an actionable `retry_condition` and completed gates. Durable JSON evidence records bind
each transition and prepared generated-tree inventory to the original handoff digest. Preserve the original handoff
and controller evidence references alongside these records. Never use a journal's claimed gate to skip live checks.

An absent worktree with absent registration may resume exact matching local-ref cleanup. A fully removed branch and
worktree may retry title-only completion without repeating destructive operations. A path absent while registration
remains, changed ref, failed resource release, or stale title keeps the task actionable. Reconcile that exact condition
through supported tools, then rerun. Successful earlier deletion cannot be rolled back by the command.

Execution guards still apply. A tool refusal such as “blocked by policy” is evidence of an execution refusal, not proof
of a specific Atlaso policy breach. Record the exact rejected operation on the controller's durable evidence surface,
preserve remaining resources, and report the stated reason without inventing one. Do not retry through a different
shell, bypass flag, or ad hoc deletion. A refusal that prevents the command from starting cannot be caught by its code;
the controller must record it. Never mark Done after a failed or ambiguous gate.
