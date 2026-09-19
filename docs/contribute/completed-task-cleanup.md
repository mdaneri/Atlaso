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
The PowerShell entry point uses isolated Python startup with site initialization disabled and binds the `scripts`
package directly to its checked-in script directory, ignoring inherited Python paths and startup hooks.
Git's worktree inventory and common directory identify the primary checkout before worktree-root configuration is read.
The inventory uses NUL-delimited porcelain so Unicode and other supported path characters are preserved verbatim.
A primary-checkout target is directed to its restoration workflow even when that configuration is unavailable or unsafe.
For non-primary targets, a `desktop` value that is not a TOML table produces a structured refusal directing configuration
repair; a later configuration rewrite preserves already recorded cleanup gates in the refusal result.
The active configuration uses the pinned regular-file reader with a 1 MiB limit before TOML parsing.
Child commands stream stdout and stderr through a combined 4 MiB cap with a 90-second execution timeout. Excess output
terminates the child and produces a sanitized refusal; inspect the tool directly before retrying.
Windows children enter a non-breakaway job before the command is authorized to start; POSIX children enter a new
process group. Completion and refusal paths terminate remaining descendants and verify quiescence. Failure to establish
or verify containment refuses the operation and requires helper reconciliation before retry.
Child environments discard inherited `GIT_*` overrides except the credential prompt helper `GIT_ASKPASS`, then explicitly
disable optional Git locks. Repository, index, object-store, namespace, and injected configuration overrides therefore
cannot redirect inspection or deletion away from the checked worktree. Normal on-disk Git configuration still applies.
Every Git child explicitly sets `core.fsmonitor=false`, including cleanliness checks and worktree removal, so a stale
monitor response cannot hide tracked edits from the cleanup gates.
Git children also force `core.trustctime=true` and `core.checkStat=default` so on-disk configuration cannot suppress
ctime and other normal stat comparisons for tracked files, including same-size edits with a preserved mtime.
Because filesystem timestamps can still collide, cleanup independently hashes every tracked regular file against its
index blob before trusting cleanliness. Built-in Git checkout normalization applies, while custom content filters and
unsupported tracked entries require independent reconciliation. Hash mismatches preserve the worktree.
Specialized resources receive a new eligibility and scope inspection after the complete scope scan, immediately before
their prepared-release gate and owning-tool invocation.
POSIX Git children also force `core.fileMode=true` so executable-bit-only edits remain visible even when repository
configuration disables mode tracking. Windows retains its native file-mode behavior.
Closing issue references must name this same repository through their canonical GitHub issue URLs. A matching issue
number in another repository cannot satisfy the local closure gate.
Before worktree removal, filesystem enumeration admits only tracked source files and the root worktree `.git` file.
Nested `.git` metadata and other Git-invisible files require inventory reconciliation before cleanup can continue.
Execution holds an exclusive per-task operating-system lock from before eligibility through the final result, and
reloads durable gates after acquiring it. A concurrent controller refuses immediately and may retry after the owner exits.
The lock hashes a canonical GitHub repository, exact task ID, and PR identity, independently of handoff whitespace,
key ordering, or evidence location. Evidence journals retain their original raw-byte handoff digest binding.
On POSIX, recovery flushes the evidence directory before trusting visible journals: a previous rename may have
succeeded while its directory flush failed. A repeated flush failure refuses recovery without accepting those gates.
Windows uses a named mutex; POSIX keeps a single-link `.atlaso-cleanup-<digest>.lock` coordination file beneath the configured
root and releases its advisory lock on exit. Preserve that inode to prevent split ownership. Preview remains read-only.
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

Treat a task-created VMware LAN segment as a separate `configuration` resource with its exact `provider_id`, original
creation commit, and preserved receipt path/hash in `ownership_manifest`. Use
`cleanup_tool: "Remove-AtlasoWorkstationLanSegment"`; never inventory the entire shared preferences file as a removable
resource. Its provider registration has no filesystem removal scope (`removal_scopes: []`). Complete the
[receipt-bound LAN segment release](../reference/vmware-workstation-lifecycle-testing.md#release-task-owned-lan-segments)
after VM removal and before releasing lifecycle result roots. Independently verify the receipt's task/PR/source binding,
complete configured VM search roots, absent adapter references, and absent exact provider registration on each readback.
The owning operation retains creation evidence and changes only the selected provider records. Open Workstation UI,
active VMware processes, references, ambiguous ownership, or recovery residue keep `validation_resources_released`
blocked. Preserve legacy segments without receipts and report the exact missing ownership evidence; VM absence alone
never authorizes their deletion.

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
Fetch and push URLs must use the exact GitHub HTTPS repository URL. SSH origins are refused because local SSH commands
and host configuration can redirect transport independently of Git's reported URL; configure HTTPS before retrying.
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
After the title response, full task/GitHub eligibility and resource/Git/worktree absence are checked again before that
terminal gate is recorded, including holds, task/downstream activity, issue closure, and post-merge workflow state.
Reappearance leaves cleanup refused and the recreated object preserved, even if the title readback itself succeeded.
Resource ancestry verification is durably recorded against the exact handoff before release. A recovered released-resource
gate uses that evidence, so title-only retries do not require squash-merged task objects that Git maintenance has pruned.
Handoff inputs must be regular single-link files no larger than 256 KiB; validation precedes the bounded payload read.
Ownership manifests use the same bounded reader. Windows pins no-follow file and ancestor handles during the read;
POSIX uses a nonblocking no-follow open. Both verify regular single-link identity and recheck size after reading.
Generated-tree deletion repeats resource-specific ownership, inactivity, retention, capability, and evidence checks
after task eligibility reconciliation, immediately before recording its prepared gate and removing the checked tree.
Generated snapshots reject `.git` entries and bare-repository structures (`HEAD`, `objects`, and `refs` or `packed-refs`)
at any depth. These repositories require separate inventory and their owning cleanup workflow.
Nested `.atlaso-local` credential/recovery directories are also preserved for their owning cleanup workflow.
Recovered journals and blobs use the same regular-file reader with the 64 MiB evidence limit. Before final ref/worktree
removal, every remaining directory must be a parent of tracked source; empty ignored or untracked directories require
inventory reconciliation and owning-tool release because Git's cleanliness checks do not report them.

Execution guards still apply. A tool refusal such as “blocked by policy” is evidence of an execution refusal, not proof
of a specific Atlaso policy breach. Record the exact rejected operation on the controller's durable evidence surface,
preserve remaining resources, and report the stated reason without inventing one. Do not retry through a different
shell, bypass flag, or ad hoc deletion. A refusal that prevents the command from starting cannot be caught by its code;
the controller must record it. Never mark Done after a failed or ambiguous gate.

## Completed Task Cleanup

Agents and the primary-checkout cleanup controller must use `scripts/cleanup-completed-task.ps1` for eligible
completed ordinary task worktrees. Run `pwsh -NoProfile -File scripts/cleanup-completed-task.ps1` with absolute
`-Handoff`, `-Evidence`, and `-Config` inputs: omit `-Execute` for read-only preview, then add it for execution with
fresh live controller evidence. Follow the [command and bridge contract](completed-task-cleanup.md).
Never replace a failed or refused command with ad hoc deletion; preserve remaining resources and report its exact
retry condition. Unsupported policy exceptions retain their existing safeguards and require the documented controller
workflow; this command does not waive ownership, resource-release, terminal-order, or title-readback gates.

An ordinary implementation task becomes cleanup-ready only after its pull request is merged, the merge commit is
reachable from current `origin/main`, the linked issue is closed, applicable post-merge workflows are complete, and no
review, deployment, release, or maintainer activity remains. Private remediation uses `advisory_cleanup_ready` instead
of the nonexistent public-issue gate: an explicitly authorized advisory administrator must have merged the private
pull request through its draft advisory, the resulting commit must be reachable from current `origin/main`, required
advisory-side review and recorded local validation must be complete, coordinated release and disclosure activity must
be finished, and the advisory must require no further task activity. Before becoming idle, a worktree-backed
originating task must send a `cleanup-ready` handoff to a cleanup controller running from the repository's primary
checkout. The handoff must name
the repository, task identifier and current title, pull-request number, task-owned branch, absolute worktree path,
pull-request head SHA, and merge commit SHA. A handoff is evidence to revalidate, never authority to skip a gate.

The primary-checkout controller must wait until the originating task is idle and unpinned, then independently re-fetch
task, GitHub, and Git worktree state. First identify and verify whether the task uses the repository's primary checkout.
Only for a non-primary target, independently read the supported Codex `git-worktree-root` setting at cleanup time and
fail closed if it cannot resolve one exact safe root; a guessed or fallback path is never ownership evidence. It must
verify the exact merged pull request and completed post-merge activity, then determine remote-branch ownership and local
checkout/worktree ownership independently. Require exclusive task
ownership before a destructive step or establish the external ownership required by the corresponding non-destructive
exception below. Require a closed linked issue for ordinary work or privately revalidate every
`advisory_cleanup_ready` criterion against the corresponding advisory record. Only a non-primary target must be
a registered, clean, unlocked, non-reparse-point worktree beneath the resolved Codex worktree root. Never remove the primary
checkout, a user-created or permanent worktree, or a worktree whose ownership or state is ambiguous. A squash-merged
pull-request head need not be an ancestor of `main` only when the worktree HEAD equals the recorded pull-request head
SHA and the recorded merge commit is reachable from current `origin/main`.

If cleanup discovers a task worktree outside the configured root, preserve its state and obtain maintainer direction;
never move or delete it automatically.

Passing tests does not permit indefinite retention of disposable validation infrastructure. Inventory resources as
they are created in a bounded `validation_resource_inventory`, binding each resource to its task, repository, source
commit, PR when present, exact path or provider identity, and existing ownership manifest. Names alone never prove
ownership. Include PR-numbered test VMs, lifecycle VMs, local and PR builders, disposable clones, address reservations,
output claims, task-created disks and temporary networks, artifact/test roots, helper processes, credential-bridge
recovery state, locks, and external test resources.

The originating task releases these resources through existing supported cleanup paths once required validation
evidence is preserved, the PR is terminal, and no review, deployment, release, diagnosis, retry, or maintainer activity
needs the environment. Failed or interrupted validation may retain resources only while diagnosis or retry needs them.
This resource gate does not waive the existing merge, issue, post-merge, or private-remediation prerequisites for
branch/worktree cleanup. Earlier per-operation sensitive-material cleanup and recovery remain mandatory.

Use `remove-atlaso-vm.ps1` with the exact VMX and expected name after independently verifying ownership; use
`remove-lifecycle-vms.ps1` or the lifecycle wrapper's `-CleanupVmsOnly` for the exact PR-owned lab. These VM-only paths
retain the result root; after preserving evidence and verifying ownership and quiescence, release that exact root with
`Remove-AtlasoWorkstationArtifactRoot` using its exact configured-root binding as documented in the lifecycle guide.
First use `Assert-AtlasoStrictDescendantPath` against independently configured permitted and canonical lifecycle roots;
derive the expected lab path separately from validated task/PR identity, never from the candidate manifest path.
Preserve existing identity, filesystem, shared-disk, provider-state, process-termination, and recovery safeguards.
Release associated resources through their owning tools; VM removal alone does not prove reservations, claims,
or recovery state released.
Never delete shared, reusable, permanent, user-created, differently owned, or ambiguous resources.

The cleanup-ready handoff includes the inventory and durable, sanitized `validation_resource_release_evidence`:
the cleanup entry point and result, exact resource identities, and verified absence of each disposable resource,
VM registration and path, reservation, claim, process, lock, and temporary root. Preserve required validation and
ownership evidence outside every root scheduled for deletion, on a permitted durable task/controller evidence surface.
The primary-checkout controller independently reads back the exact resource states before recording
`validation_resources_released` and before branch/worktree cleanup. For no resources, require an explicitly verified
`validation_resource_inventory_empty` statement; missing evidence is never proof of absence. If another owner must
perform teardown, hand off this bounded inventory and require the same ownership checks and independent readback.

Record explicit maintainer retention or a proven active downstream need as `validation_resource_retention`, with
the exact resource, owner, reason, and retry condition. Any unresolved retention, failure, unsupported cleanup path,
or ambiguous ownership records `validation_resource_cleanup_blocked`, preserves uncertain resources and recovery
evidence, and keeps the task actionable. Do not delete the branch/worktree or mark Done to hide a blocked resource gate.
Track missing cleanup capabilities separately; never substitute ad hoc deletion or broad VMware inventory cleanup.

For ordinary public tasks, enforce `task_title_done` with `scripts/completed_task_title.py` after all prior gates pass.
Supply every linked issue and PR from verified task/GitHub evidence, not from a potentially truncated current title;
use repeated `--issue` and `--pr` arguments and a short `--description` without traceability or completion segments.
For an issue-less GitHub-managed Dependabot PR, independently verify the documented dependency-update exception and
pass `--dependabot`; preserve every PR number and any linked issue that does exist. Ordinary tasks still require issues.
The formatter puts all identifiers first, trims only the description to a conservative 60 UTF-16-unit budget, and
retains exactly one " · Done" suffix. If the identifiers alone do not fit, keep completion blocked for maintainer
direction; never drop an issue or PR. Use supported task-title controls to set the exact generated title, then read
the persisted title through a supported task read tool and rerun the same formatter inputs with `--observed-title`.
Record `task_title_readback_verified` only when verification succeeds. A rename acknowledgement alone is insufficient.
A stale, truncated, missing, or duplicated completion marker blocks Done and requires an idempotent title-only retry
after revalidating earlier gates. Do not repeat destructive cleanup on a title retry. If title controls are unavailable,
retain the existing capability-evidence exception. Private remediation keeps its sanitized title and private evidence;
never pass advisory identifiers to this public formatter, and still require exact supported-tool title readback.

Terminal order:

1. `validation_resources_released`
2. `remote_branch_absent`
3. `worktree_removed`
4. `task_title_done`

For ordinary `remote_branch_absent`, delete only the exact task-owned branch from its same-repository GitHub remote.
If the ref exists, require it to equal the pull-request head SHA and delete it with an atomic expected-SHA lease such as
`--force-with-lease=refs/heads/BRANCH:HEAD_SHA`; a lease rejection or unsupported atomic guard blocks cleanup. Then
verify the remote ref is absent.
For private remediation, satisfy `advisory_remote_branch_absent` only on private surfaces: bind the exact temporary
private fork, private pull request, branch, task, and recorded head SHA through the advisory; if the ref exists, require
it to equal that head and use the same atomic expected-SHA lease before deleting only the ref and privately verifying
absence. An already absent ref satisfies the gate only after the same private identity and merge evidence are verified.
Never delete the temporary fork, change
advisory state, or enable repository-wide automatic branch deletion. For `worktree_removed`, first verify that the exact
local task branch is absent or still equals the recorded pull-request head and is referenced only by the target
worktree. Use `git worktree remove`, prune only stale worktree metadata for the affected repository, and verify both the
path and registration are absent. Then require the local branch to be unreferenced by every registered worktree, delete
only that exact ref when present, and verify `local_task_branch_absent` before recording `worktree_removed`. A retry
interrupted after the path and registration disappeared but before local-ref deletion may enter
`worktree_removal_resume` only when the path and registration remain absent. The
worktree removal remote branch gate is either verified absent or recorded not applicable through
`non_task_owned_remote_branch_preserved`, and the same task ownership,
pull-request head, and merge evidence prove that the exact unreferenced local branch is safely deletable or already
absent.
For a task running in the primary checkout, the initial path requires a clean checkout still at the recorded task head;
fetch current `origin/main`, switch to local `main` without force, fast-forward it exactly to `origin/main`, and verify
the resulting HEAD. A retry interrupted after that switch may enter `primary_checkout_resume` only when the checkout is
clean on local `main` and a fresh fetch and non-forced fast-forward makes it equal current `origin/main`. The
primary checkout remote branch gate is either verified absent or recorded not applicable through
`non_task_owned_remote_branch_preserved`; the local task branch must still equal the recorded pull-request head while
checked out nowhere or already be absent under the same task ownership and merge evidence. Delete the exact local task
branch when it remains, record `primary_checkout_restored`, then record worktree removal as not applicable and never
remove the checkout.
For `task_title_done`, use supported task-title controls to append the exact suffix " · Done" once, preserving the
description and issue/pull-request traceability. Keep the completed task unarchived unless a maintainer separately
requests archival. Only when the runtime exposes no supported mutable task-title control,
record `task_title_done` as verified not applicable with the capability evidence; do not append or claim a visible Done
suffix, and do not block otherwise-complete cleanup on the unavailable control.

For an existing ordinary pull request, evaluate remote and local ownership separately after independently verifying the
exact merge, reachable merge commit, closed linked issue, and completed post-merge activity. When the remote branch is
non-task-owned, preserve it, record `non_task_owned_remote_branch_preserved`, and record `remote_branch_absent` as
verified not applicable; this does not exempt a task-owned local worktree from normal removal. When the local checkout
or worktree is non-task-owned, preserve it and its local refs and metadata, record
`non_task_owned_checkout_preserved`, and record `worktree_removed` as verified not applicable; this does not exempt a
task-owned remote branch from normal deletion. Apply these decisions in terminal order. Ambiguous ownership blocks the
affected transition and the Done suffix.

Any failed or ambiguous gate blocks `task_title_done`; leave the task actionable and report the exact retry condition.
The daily Codex cleanup automation is the reconciliation backstop for missed handoffs and partially completed terminal
transitions, but it must apply the same checks and ordering. Private vulnerability remediation additionally follows
`SECURITY.md`: keep titles, handoffs, controller output, advisory identity, and temporary-fork remote operations
sanitized and private; block rather than expose or guess when private state cannot be verified; and do not treat an
advisory merge as lifecycle completion while coordinated release, disclosure, or authorized advisory-state work remains.
