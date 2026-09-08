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
Git's worktree inventory and common directory identify the primary checkout before worktree-root configuration is read.
A primary-checkout target is directed to its restoration workflow even when that configuration is unavailable or unsafe.
For non-primary targets, a `desktop` value that is not a TOML table produces a structured refusal directing configuration
repair; a later configuration rewrite preserves already recorded cleanup gates in the refusal result.
Generated-directory release additionally requires Windows. The controller supplies fresh task evidence through
stdin; the command independently checks GitHub, Git, configuration, and filesystem state. No private Codex database,
rollout editing, guessed server endpoint, administrative bypass, or execution-policy override is used.

## Prepare durable ownership evidence

The originating task records resources as they are created. Its `cleanup-ready` handoff must survive outside its
worktree and every resource being removed, beneath the configured `desktop.git-worktree-root` or another explicitly
permitted durable controller surface. This command currently accepts its handoff and evidence directory beneath that configured
root only. Read the exact supported Codex `config.toml`; never infer a worktree root from an existing path.
The supplied configuration must be the active `CODEX_HOME/config.toml` (the standard user Codex directory when
`CODEX_HOME` is unset), not a replacement supplied by the cleanup handoff.

Provide a UTF-8 JSON handoff with these schema-1 fields:

| Field | Required evidence |
| --- | --- |
| `schema` | Integer `1`. |
| `task_id`, `description` | Exact Codex task identity and short string description without traceability segments; title formatting is validated before resource release. |
| `task_title` | Exact current title recorded by the originating task in the cleanup-ready handoff. |
| `repository` | Exact public same-repository GitHub `owner/name`. |
| `primary_checkout`, `worktree` | Absolute paths independently verified against Git registration. |
| `worktree_identity` | `[st_dev, st_ino]` recorded with Python `Path.stat()` when the task worktree was created. |
| `branch`, `head`, `merge`, `pr` | Exact owned branch, full PR head SHA, squash SHA, and positive PR number. |
| `issues` | Every closing issue number returned by GitHub for this PR. |
| `resources` | Complete bounded inventory, or explicit `[]` with independently verified empty-inventory evidence. |

A resource requires `id`, `kind`, `task_id`, `source_commit`, matching `repository` and `pr`, and at least one exact
`path` or `provider_id`. Its required `ownership_manifest` contains an absolute `path` and the original file's
`sha256`; preserve that manifest outside the worktree and every removal root. The command verifies the manifest bytes,
while the controller independently verifies its provenance and binding to the resource. Specialized resources also
require the exact supported `cleanup_tool`. Every resource identity is checked before any resource is released.
Supported kinds are `generated_tree`, `vm`, `lifecycle`, `artifact`, `reservation`, `credential_bridge`,
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
bounded to 256 KiB and 120 seconds. A non-object JSON response, mismatched nonce, missing field, error, EOF, or timeout
refuses the transition with a structured result that retains the completed gates.
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
Return a nonempty `post_merge_runs` list for the complete applicable post-merge chain. Each entry contains exactly
`id`, `run_attempt`, `workflow_id`, `head_sha`, and `event`, bound through the source CI and downstream handoffs.
The command independently reads each run and requires matching identity and successful completion. Include applicable
manual recovery runs, but exclude unrelated manual dispatches merely sharing the merge SHA. Preserve the chain's
applicability evidence in `evidence_refs`; run selection must not omit failed or pending required work.
For an empty inventory, also return `inventory_empty_verified: true` after explicitly verifying
`validation_resource_inventory_empty`.
Also return the exact supported-tool `observed_title`. It must match the handoff's `task_title`; a title-only retry
may also observe the canonical completed title only after the worktree and both refs are independently absent.
Missing capabilities must return a refusal. This is the controller's independent evidence attestation; the script
does not infer semantic ownership or maintainer intent from task titles.

### Resource inspection and owning tools

The entire inventory passes schema, unique-ID, task/source ownership, and source-ancestry preflight before any resource
can be released. This includes entries whose release gates were recovered; duplicate IDs cannot reuse an earlier gate.
Ownership manifests must also remain beneath the configured durable root. A removal scope cannot contain another
inventoried resource's path; reconcile overlapping ownership through the existing owning tools before using this command.
All resources' complete removal scopes are inspected before the first release, including provider-only resources and
auxiliary paths. Intersecting scopes or later scope changes block release and require ownership reconciliation.

For `resource.inspect`, independently check the exact resource/provider, manifest, process/boot identity where
applicable, and surviving reservations/claims/recovery state. Return literal booleans `ownership_verified`, `inactive`,
`retained`, `supported_cleanup`, `evidence_preserved`, and `absent`. Preserve durable sanitized evidence outside every
removal root. For no resources, task inspection must explicitly verify `validation_resource_inventory_empty`.
For specialized resources, also return `removal_scopes`: every absolute filesystem path the owning tool will remove,
including derived parent directories, disks, and auxiliary roots. An explicit empty list is valid only for a provider
operation with no filesystem removal. Scopes must lie beneath the configured root and cannot contain either checkout,
the handoff, configuration, evidence directory, or any ownership manifest. The command repeats this inspection before
release and passes the validated scopes to `resource.release`; the controller must bind the owning-tool invocation to
those exact scopes and refuse if its operation would remove anything beyond them.

For `resource.release`, call only the resource's existing supported owning tool with exact identity arguments:
`remove-atlaso-vm.ps1`, `remove-lifecycle-vms.ps1`/`-CleanupVmsOnly`, or the documented
`Remove-AtlasoWorkstationArtifactRoot` path with independent strict-descendant checks, as appropriate. Reservations,
credential bridges, processes, and configuration require their own documented recovery/cleanup entry points. Do not
substitute broad deletion or stop unrelated processes. Return `success: true` only after that tool succeeds. The script
requests another independent `resource.inspect`; release acknowledgement alone cannot complete the resource gate.
Generated trees are removed by this command and still receive independent absence readback.
Before recording the aggregate resource-release gate, the command reinspects every resource, including whether its
durable evidence survived release. Later eligibility
checks repeat that aggregate readback and require completed remote/local ref gates to remain absent, even if a
recreated ref points to the original SHA. Reappearance blocks completion and preserves the recreated resource/ref.

### Completion title

For `task.title`, use supported `set_thread_title` with the exact supplied title, then `read_thread` to retrieve the
persisted title. Return `persisted_readback: true` and `observed_title`. The script uses `completed_task_title.py` to
format and verify all linked identifiers and the single Done suffix. Do not archive the task. If mutable title controls
are actually unavailable, return `capability: "unavailable"` and concrete `capability_evidence`; record the documented
not-applicable exception without claiming a visible Done suffix. A denied or failed available control is a failure,
not an unavailable capability.

## Failure and interrupted recovery

All GitHub CLI evidence reads explicitly select `github.com`, independently of `GH_HOST`. The handoff must be an
ordinary file beneath the configured worktree root and outside the target worktree; an arbitrary external or temporary
path is not an approved durable handoff surface.

Exit zero means a successful preview or completed execution; inspect the JSON `status` to distinguish them. Exit one
and `status: "refused"` give an actionable `retry_condition` and completed gates. Durable JSON evidence records bind
each transition and prepared generated-tree inventory to the original handoff digest. Preserve the original handoff
and controller evidence references alongside these records. Never use a journal's claimed gate to skip live checks.
Each fresh invocation recovers the matching monotonic journal history and rechecks the continued absence of completed
resources and refs. Reappearance refuses cleanup rather than authorizing a second deletion. Gates enter the reported
completed list only after the prospective record has been flushed, fsynced, and published. An interrupted `.pending`
record or conflicting history requires independent evidence reconciliation before another invocation can proceed.
Every eligibility check also verifies all effective Git push URLs; a separate fork push URL or extra destination blocks
cleanup even when the fetch URL names the correct repository.
Symbolic task refs, including dangling refs, block cleanup. Local deletion never dereferences the task ref. Index
`assume-unchanged` and `skip-worktree` flags also block cleanup because they can hide edits from Git's cleanliness checks.
Large controller evidence and snapshots are stored as bounded, hashed `.evidence` files; cumulative journals contain
their references and remain within the same 64 MiB recovery limit. Preserve both file types. A retry verifies referenced
payloads before continuing, and prepared transition records are persisted before destructive owning-tool or Git actions.
Journal and payload publication uses Windows `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`, or a rename followed by a
parent-directory fsync on POSIX. A gate is reported only after that publication succeeds; file-content fsync alone is
insufficient. See the [Windows move contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).
Each missing evidence-directory component is first created under a pending sibling name and durably published through
the same parent before journals are written. A surviving `.atlaso-cleanup-directory.pending` sibling blocks retry until
independently reconciled. POSIX retries also fsync the parent of an existing evidence directory.
Windows inputs reject trailing-dot/space, reserved-device, and short-name aliases before containment checks. An absent
remote `main` produces a structured refusal, including any already recorded gates.

An absent worktree with absent registration may resume exact matching local-ref cleanup. A fully removed branch and
worktree may retry title-only completion without repeating destructive operations. A path absent while registration
remains, changed ref, failed resource release, or stale title keeps the task actionable. Reconcile that exact condition
through supported tools, then rerun. Successful earlier deletion cannot be rolled back by the command.
The title-capability exception preserves its capability evidence and still records the literal `task_title_done` gate.
After the title response, resource and Git/worktree absence are checked again before that terminal gate is recorded.
Reappearance leaves cleanup refused and the recreated object preserved, even if the title readback itself succeeded.
Handoff inputs must be regular single-link files no larger than 256 KiB; validation precedes the bounded payload read.
Ownership manifests use the same bounded reader. Windows pins no-follow file and ancestor handles during the read;
POSIX uses a nonblocking no-follow open. Both verify regular single-link identity and recheck size after reading.
Generated-tree deletion repeats resource-specific ownership, inactivity, retention, capability, and evidence checks
after task eligibility reconciliation, immediately before recording its prepared gate and removing the checked tree.
Recovered journals and blobs use the same regular-file reader with the 64 MiB evidence limit. Before final ref/worktree
removal, every remaining directory must be a parent of tracked source; empty ignored or untracked directories require
inventory reconciliation and owning-tool release because Git's cleanliness checks do not report them.

Execution guards still apply. A tool refusal such as “blocked by policy” is evidence of an execution refusal, not proof
of a specific Atlaso policy breach. Record the exact rejected operation on the controller's durable evidence surface,
preserve remaining resources, and report the stated reason without inventing one. Do not retry through a different
shell, bypass flag, or ad hoc deletion. A refusal that prevents the command from starting cannot be caught by its code;
the controller must record it. Never mark Done after a failed or ambiguous gate.
