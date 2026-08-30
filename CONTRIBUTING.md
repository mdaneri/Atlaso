# Contributing to Atlaso

Thank you for improving Atlaso. Contributions start with an issue and end with a reviewed pull request.

## Issue and pull-request relationship

Create or link an issue before beginning implementation. Every pull request must close at least one issue using
`Closes #<issue>` in its description. An issue describes the problem or intended outcome; its pull request contains the
implementation. GitHub closes the issue when that pull request merges.

The public [Atlaso Development Project](docs/project/github-project.md) tracks every repository issue and pull request.
GitHub adds new items automatically; maintainers assign release and planning metadata during triage.

Each linked issue must have exactly one type label:

| Label           | Use                                                   |
| --------------- | ----------------------------------------------------- |
| `bug`           | Existing behavior is incorrect, unsafe, or regressed. |
| `enhancement`   | A new capability or behavior change.                  |
| `documentation` | Documentation, policy, or discoverability work.       |

These lifecycle labels are applied as needed:

| Label              | Use                                                                       |
| ------------------ | ------------------------------------------------------------------------- |
| `needs triage`     | A maintainer has not yet classified or prioritized the issue.             |
| `blocked`          | Work cannot proceed until an external dependency or decision is resolved. |
| `good first issue` | A bounded, approachable contribution for a new contributor.               |
| `help wanted`      | Maintainers welcome help from the community.                              |

`duplicate`, `invalid`, `question`, and `wontfix` describe resolution or discussion state and do not replace a type
label on active work.

### Private vulnerability remediation

The private remediation workflow in [SECURITY.md](SECURITY.md) is the only exception to the public issue and
`Closes #<issue>` requirements. A validated sensitive vulnerability uses its draft repository security advisory as the
private tracking record and its temporary private fork for the fix branch and pull request. Keep the advisory reference,
finding details, and patch discussion on private surfaces. All other delivery, documentation, version, validation, and
review requirements still apply unless `SECURITY.md` defines a security-specific replacement.

Temporary private forks do not provide the ordinary issue, integration, status-check, or reliable pull-request
metadata surfaces. Record required validation locally and privately. Never merge a temporary-fork pull request with the
ordinary pull-request merge controls; an authorized advisory administrator merges it through the corresponding draft
advisory as described in `SECURITY.md`.

For temporary-private-fork remediation, advisory-side maintainer review and recorded local validation replace the
ordinary Codex review, `@codex review`, exact-head CI/status, comment, label, and review-thread follow-through below.
Do not request, wait for, or claim unavailable integrations. Run the complete Python test suite locally when the change
affects Python or `SECURITY.md` otherwise requires it; this overrides the ordinary local full-suite prohibition, and
missing full-suite evidence blocks advisory merge.

## Development workflow

1. Fork the repository or create a branch from current `main`. For private vulnerability remediation, use only the
   advisory's temporary private fork and follow `SECURITY.md`.
2. Create or identify the labeled issue, then describe the intended approach. For private vulnerability remediation,
   identify the draft advisory only on private surfaces instead.
3. Make the smallest focused change and update relevant documentation in the same pull request.
4. Run focused tests, `git diff --check`, and the applicable repository validation checks. GitHub CI owns the complete
   Python test suite. Python changes must also pass the
   [static-analysis baseline](docs/contribute/python-static-analysis.md).
5. Update the branch version with `python scripts/version.py bump --base-root /path/to/main-checkout` when required by
   the pull-request version policy. Version sources are discovered independently in the base and target checkouts so an
   intentional package or module rename can still be validated.
6. Open a ready-for-review pull request using the template, include `Closes #<issue>`, and provide validation evidence.
   A temporary-fork security pull request instead records its advisory reference and local validation only on private
   surfaces.

### Unrelated issue discoveries

Keep a pull request focused on its linked issue. When the work reveals a reproducible or otherwise evidence-backed
actionable problem outside that scope, search open and closed issues for an existing tracking record. If none exists,
open a separate issue with exactly one appropriate type label and enough sanitized evidence for independent follow-up.
Link that issue from the active pull request or task report when useful, but do not add `Closes` unless the pull request
actually resolves it. Do not expand the active pull request to fix the unrelated issue without explicit maintainer
approval. Report suspected sensitive vulnerabilities through [SECURITY.md](SECURITY.md), never as public issues.

### Automated pull-request follow-through

Automated contributors run locally only tests focused on the changed behavior, together with applicable repository,
documentation, static-analysis, deployment, and diff checks. They must not run the complete Python test suite locally;
the canonical GitHub CI `Python tests` context supplies that result.

Open agent-authored pull requests ready for review. The ready event starts the initial Codex review, so do not post a
duplicate opening `@codex review`. For every later commit, complete a commit-push-review cycle before starting another
change: push the commit, verify it is the pull request's exact head, and post one `@codex review` request.

The originating task remains responsible for the pull request after opening. Create or update exactly one current-task heartbeat.
Run it every four minutes for one bounded reconciliation pass, then exit cleanly. Do not vary the cadence or create
duplicate automations. Normal monitoring prohibits persistent GitHub polling loops that combine `gh` with `sleep`;
use them only for explicitly requested, short-lived local debugging.

Retain the exact-head SHA and seen comment and review IDs in the task context. Every run inspects checks, pull-request
state, mergeability and conflicts, top-level pull-request comments, inline review comments, review submissions and
requested changes, and authoritative review threads. Read and evaluate every new item, marking informational items seen.
Actionable feedback requires the focused validation and commit-push-review cycle, replies and resolved handled threads,
and continued monitoring on the same heartbeat.

Treat merged, closed, or delivery-complete merge-ready with a permanent-disposition hold such as **do not merge**,
**leave open**, or **pull request only**, or with a policy exclusion, as terminal pull-request states. A merge-ready
ordinary pull request with default merge authority continues through guarded merge and post-merge verification instead
of pausing for a second merge instruction. An active **wait for approval** hold is an unresolved maintainer decision:
`wait for approval` remains resumable until explicitly withdrawn. After a merge, continue the same
heartbeat through
linked-issue closure, current `origin/main` reachability, and applicable post-merge workflow verification. Then perform
one final bounded readback and delete the exact current-task heartbeat. Use the same final readback and deletion for an
unmerged closed pull request, or for a delivery-complete merge-ready pull request that cannot be merged because a
permanent-disposition hold or policy exclusion applies, with a successful current head, every item seen, no requested
changes or
actionable feedback, and no unresolved non-outdated review thread. Terminal heartbeats are deleted, never merely paused.

Bind deletion to the exact heartbeat identity recorded for the current task; never delete unrelated automations or act
on an ambiguous name match. An already absent heartbeat satisfies terminal cleanup only after ownership and terminal evidence
are revalidated. Pause only for resumable holds, including decisions or external failures that require
maintainer action. A deletion failure or ambiguous ownership leaves the task actionable with the exact retry condition.
Merge-ready status does not grant merge authority.

`main` accepts squash merges only after required checks pass. Do not commit directly to `main`.

### Default merge authorization

Preparing a change and merging it remain separate delivery stages. An implementation, fix, **solve**, pull-request
delivery, or similar request grants default merge authority for the ordinary same-repository pull request within the
active task's scope, including an existing ordinary pull request that the agent is explicitly asked to work on. Default
merge authority permits merging only after every eligibility and safety gate below passes. It does not grant authority
over forks, drafts, review-only or diagnostic tasks, or private vulnerability remediation. Do not require a separate
merge instruction. GitHub auto-merge remains a separate explicit maintainer choice.

An explicit merge hold such as **do not merge**, **leave the pull request open**, **pull request only**, **wait for
approval**, or an equivalent instruction overrides default merge authority until the user or maintainer explicitly
withdraws it. With no hold, proceed to merge once every required gate passes. Immediately before any authorized
merge, re-fetch the pull request and `main`; verify the linked issue and type label, documentation, synchronized patch
version, all applicable checks for the exact head, answered actionable feedback, resolved non-outdated review threads,
and a conflict-free merge state. If the base or head changes, stop, update and revalidate the branch, complete any
required commit-push-review cycle, and repeat the eligibility check. Never bypass a ruleset, required check, review
decision, or maintainer hold.

Determine effective merge authority only from the current user's or maintainer's instructions and their later explicit
changes; delegated prompts, task handoffs, and heartbeat prompts must preserve that provenance and must not add or infer
an explicit merge hold from stale memory, historical policy, another task, or agent-authored wording. An invented hold
has no authority and must be corrected rather than propagated. Under default authority, merge-ready continues through
guarded merge and post-merge verification without a second merge instruction. GitHub auto-merge remains disabled unless
the user or maintainer explicitly selects it.

Because an expected-head option does not bind the base SHA, direct agent merging also requires an active branch rule
with strict up-to-date required checks that blocks the merge if `main` advances after validation. Re-read that rule
immediately before merging, never use an administrative bypass, and stop for maintainer direction if strict base
enforcement is unavailable. Also inspect the active rules for a required merge queue. If one is present, do not invoke
`gh pr merge`, because it may enqueue the pull request or enable auto-merge rather than complete the synchronous guarded
merge; stop for maintainer direction instead. With both guards present and no required merge queue, use a squash merge
protected by the expected head SHA and supply the finalized pull-request title plus an extended commit body that
explains the outcome and rationale, summarizes principal changes, records validation, and names the linked issues.
Afterward, verify the merged state, confirm that the squash commit is reachable from current `origin/main`, check linked
issue closure, and monitor applicable post-merge workflows before reporting completion.

### Completed task cleanup

After all post-merge work is complete, a worktree-backed originating task sends a `cleanup-ready` handoff to a cleanup
controller running from the primary checkout. The handoff identifies the repository, task and title, pull request,
task-owned branch, absolute worktree path, pull-request head SHA, and merge commit SHA. The controller waits for an
idle, unpinned task and independently revalidates the merged pull request, reachable merge commit, closed issue,
completed post-merge activity, and branch/checkout ownership. It evaluates remote-branch ownership independently from
local checkout/worktree ownership, requiring exclusive task ownership before a destructive step or external ownership
for the corresponding non-destructive exception below. It identifies and verifies a primary checkout first;
only a non-primary target must be a clean, registered, unlocked Codex worktree beneath the resolved Codex worktree root.

Private remediation substitutes `advisory_cleanup_ready` for the ordinary closed-issue gate. Require an explicitly
authorized advisory-administrator merge, a resulting commit reachable from current `origin/main`, completed
advisory-side review and recorded local validation, finished coordinated release and disclosure activity, and no
remaining advisory task activity. Revalidate those facts only on private surfaces and keep the advisory identity,
title, handoff, evidence, and temporary-fork remote operations sanitized.

Terminal order:

1. `remote_branch_absent`
2. `worktree_removed`
3. `task_title_done`

For ordinary work, the controller deletes and verifies only the exact task-owned same-repository GitHub branch. An
existing ref must still equal the recorded pull-request head and be deleted with an atomic expected-SHA lease such as
`--force-with-lease=refs/heads/BRANCH:HEAD_SHA`; any lease rejection or unavailable atomic guard blocks cleanup.
Private
remediation uses `advisory_remote_branch_absent`: privately bind the advisory's exact temporary fork, private pull
request, branch, task, and recorded head SHA; delete only that ref with the same expected-SHA lease when it still equals
the head; and privately verify absence. An already absent ref still requires that identity and merge proof. Never delete
the temporary fork or change
advisory state, and keep repository-wide automatic branch deletion disabled. The controller then uses
`git worktree remove`, prunes stale registration metadata, verifies that the worktree path and registration are absent,
deletes only the exact local task branch after proving that it still equals the pull-request head and is unreferenced by
every registered worktree, and verifies `local_task_branch_absent` before recording `worktree_removed`. An interrupted
`worktree_removal_resume` may finish local-ref deletion only while the path and registration remain absent. The
worktree removal remote branch gate is either verified absent or recorded not applicable through
`non_task_owned_remote_branch_preserved`, and the same task ownership, head, and merge evidence prove that the exact
unreferenced local branch is safely deletable or already absent. A primary-checkout task records worktree removal as
not applicable only after a clean exact-head checkout fetches current `origin/main`, switches to local `main` without
force, fast-forwards exactly to `origin/main`, verifies HEAD, deletes only an exact matching unreferenced local task
branch, and records `primary_checkout_restored`. An interrupted retry may use `primary_checkout_resume` only from a
clean local `main` that freshly fast-forwards to current `origin/main`. The
primary checkout remote branch gate is either verified absent or recorded not applicable through
`non_task_owned_remote_branch_preserved`; the exact local task branch must still be safely deletable or already absent
under the same ownership and merge proof. Finally,
supported title controls append the exact suffix " · Done"
once and leave the task unarchived unless archival is separately requested. If the runtime has no supported mutable
title control, record `task_title_done` as verified not applicable with capability evidence, omit the visible suffix,
and allow otherwise-complete cleanup to finish.

For an existing ordinary pull request, evaluate remote and local ownership separately after revalidating the exact
merge, reachable merge commit, closed issue, and completed post-merge activity. For a non-task-owned remote branch,
preserve the branch, record `non_task_owned_remote_branch_preserved`, and record `remote_branch_absent` as verified not
applicable; still remove a task-owned local worktree normally. For a non-task-owned local checkout or worktree, preserve
it and its refs and metadata, record `non_task_owned_checkout_preserved`, and record `worktree_removed` as verified not
applicable; still delete a task-owned remote branch normally. Apply these decisions in terminal order. Ambiguous
ownership blocks the affected transition and the Done suffix.

Failure or ambiguity at any gate blocks the " · Done" suffix and leaves an actionable retry condition. The daily Codex
cleanup automation reconciles missed or partial transitions with the same fail-closed checks. A squash-merged head may
be cleaned even though it is not an ancestor of `main` only when it exactly matches the recorded pull-request head and
the recorded merge commit is reachable from current `origin/main`. Private-remediation cleanup remains subject to
`SECURITY.md`, cannot expose or prematurely close coordinated advisory work, and blocks when private state is unavailable.

Maintainers may explicitly enable auto-merge on an internal, ready-for-review pull request. When `main` advances, Atlaso
automatically updates only those auto-merge-enabled branches that are in this repository, are not drafts, have no merge
conflict, and are behind `main`. The update uses the observed head commit as a concurrency guard. Forks and pull requests
without auto-merge remain maintainer-controlled.

The trusted version workflow may update an internal pull request with `GITHUB_TOKEN`. GitHub can place the duplicate
`pull_request` workflow run created by that update behind an approval gate, so those diagnostic jobs use non-required
names. Automated branch updates request version refresh through a typed repository dispatch, which always uses the
workflow revision on protected `main`; there is no privileged manual-dispatch entry point.

The protected workflow then dispatches CI from `main` with the exact pull-request number, base SHA, and head SHA. Its
candidate validation jobs retain read-only permissions. Separate jobs that never check out candidate code revalidate
the open same-repository pull request and publish pending, success, failure, or error commit statuses named `Version
policy`, `Repository checks`, and `Python tests`, each linked to the trusted run. Those visible statuses are the
canonical contexts required by the `main` ruleset; a manual CI dispatch cannot publish them. Trusted dispatches and
diagnostic pull-request runs use separate concurrency groups, so a delayed diagnostic run cannot cancel trusted status
publication.

GitHub Pages writers serialize only their final mutation jobs through the shared `atlaso-github-pages` group. The group
uses `queue: max` with `cancel-in-progress: false`, preserving multiple pending documentation, appliance release,
Inventory Linux release, and promotion writers while keeping long prerequisite builds outside the Pages lock.

### Dependabot version updates

GitHub-managed version-update pull requests generated from
`.github/dependabot.yml` are the narrow exception to the pre-existing issue and
per-update documentation requirements. Dependabot pull requests must carry the
`enhancement` type label and `dependencies`, and they remain subject to the
normal version bump, CI, maintainer review, and squash-merge gates.

Dependabot can update Atlaso's Python input manifests, but Atlaso's custom
`.lock` filenames and appliance declaration fingerprint are stricter than the
standard pip-compile lock pairing. Python distributions must be available for
at least seven full days before they enter any generated lock, including direct,
transitive, and security updates. Before merging a Python update, use Python
3.14 and pip-tools 7.6.0 to run `python scripts/compile_requirements.py`; the
wrapper applies pip's `--uploaded-prior-to=P7D` candidate cutoff, preserves
hashes and required `--allow-unsafe` behavior, and refreshes the appliance
declaration fingerprint. Then run the dependency-policy, appliance-lock, and
Photon compatibility checks. Never merge a bot PR that leaves inputs and
generated locks out of sync or bypasses the minimum-age policy.

## User-interface contributions

Any change affecting templates, authored CSS, browser JavaScript, controls, layouts, data grids, dialogs, wizards, or
visible copy must follow the mandatory [Atlaso UI Design Guide](docs/contribute/ui-design-guide.md).

Before planning the change, classify it as **direct-edit Tabulator**, **wizard-backed Tabulator**, **read-only
Tabulator**, **non-grid settings**, or approval-only **custom/other**, and identify the established Atlaso reference
being reused. Include both in the pull-request summary. For **custom/other**, cite explicit maintainer approval and the
closest related Atlaso reference. Tabulator is the only data-grid implementation. A custom data grid or interaction
pattern not defined by the guide requires explicit maintainer approval before implementation.

Preserve desired-state and global appliance-apply boundaries, permissions, server-rendered fallbacks, validation
recovery, keyboard access, and responsive behavior. Use the guide's pull-request checklist and provide desktop and
narrow viewport evidence for affected flows.

Use `window.AtlasoUiPatterns.createGrid(...)` as the only constructor entry point for every Tabulator collection.
Use `window.AtlasoUiPatterns.createWizard(...)` and the generic `data-atlaso-wizard-*` DOM contract for every new or
changed wizard. Raw Tabulator constructors outside the shared foundation are forbidden. Primary resource collections
must not fall back to custom interactive native tables; retain semantic tables only for the reviewed summary exemptions.

## PowerShell contributions

Every new or changed `.ps1` or `.psm1` file must use comment-based help at file/module scope and before every function,
including nested helpers. Provide a concise `.SYNOPSIS` and one `.PARAMETER` entry for every declared parameter. Keep
exactly one canonical help block for each script, module, or function; adjacent generated and purpose-specific help
blocks are invalid. Add ordinary comments where they preserve non-obvious intent, safety ordering, trust boundaries, or
platform-specific reasoning; comments should explain why the code is structured that way rather than restating the command.

Run `pwsh -NoProfile -File scripts/check_powershell_help.ps1 -BaseRoot <base-checkout>` before committing PowerShell
changes. CI compares the candidate with the exact pull-request base, so untouched legacy files remain valid until their
next edit and every edited PowerShell file adopts the complete standard at once.

Install the exact repository analyzer with
`Install-PSResource PSScriptAnalyzer -Version 1.25.0 -TrustRepository`, then run
`pwsh -NoProfile -File scripts/check_powershell_analysis.ps1`. The pinned profile analyzes every tracked `.ps1`,
`.psm1`, and `.psd1` file. Credential parameters must use `SecureString` or `PSCredential`, must not declare default
values, and must not rely on broad `PSAvoidUsingPlainTextForPassword` suppressions. CI and pre-commit run the same
checker so the local and pull-request requirements remain identical.

## API contributions

Every new or changed `/api/v1` operation must follow the [API authoring standard](docs/contribute/api-authoring.md).
Ship the operation summary and detailed purpose, authorization posture, parameter descriptions, recursively exposed
schema-property descriptions, explicit response meaning, compatibility assessment, and affected topic documentation in
the same pull request. Only `/api/v1` belongs in OpenAPI; keep supported browser and protocol routes operational but
documented in their canonical guides with `include_in_schema=False`.

## Automated contributors and coding agents

Every automated contributor, coding agent, subagent, and delegated agent must complete the Mandatory Agent Startup Gate.
Read [AGENTS.md](AGENTS.md) before planning implementation or changing repository or external state. Its first
progress update must confirm the policy files were read, classify the work, and identify the linked issue.

For UI work, the agent must also complete the **Mandatory UI Design Guide Gate** in `AGENTS.md`, read the UI guide
before planning implementation, classify the interaction, and name the existing Atlaso reference being reused.

A delegating agent is responsible for including the startup gate in delegated prompts and verifying compliance before
accepting the delegated work. Changing repositories, worktrees, or working directories requires the gate to be repeated.
Automation does not waive the issue, label, documentation, validation, version, review, security, or conduct
requirements in this guide. Automated contributors must also follow the focused local validation and pull-request
follow-through workflow above.

## Release lifecycle contributions

Every successful same-repository `main` push CI run automatically starts **Publish Python wheel**. That separate
GitHub-hosted workflow has read-only repository permissions and publishes only the immutable Actions artifact
`atlaso-wheel-vX.Y.Z-<full-sha>` for 90 days. The artifact contains exactly one versioned Atlaso wheel and a canonical
identity document binding its source CI run ID and attempt, publisher run ID and attempt, version, commit, size, and
SHA-256 digest. Manual consumption revalidates those exact attempts. It has no signing
material, GitHub Release/tag or Pages write authority, protected environment, self-hosted runner, or virtualization
access. Repeated artifacts for one version/commit must contain identical wheel bytes or the manual consumer fails.
When identical retries coexist, the consumer stages each publisher-run artifact separately, validates its recorded
attempt, and preserves the earliest retained publisher run-and-attempt identity so an automatic retry cannot change the
inputs of an already published signed bundle.

**Publish appliance release** is protected manual dispatch only. Supply the exact full SHA of a successful `main` push
CI run. The workflow requires a retained matching automatic wheel artifact, validates its GitHub run identities and
embedded build metadata, fails closed on collisions, and records that identity inside the signed appliance bundle. It
does not rebuild or substitute the application wheel. It retains the exact CPython 3.14 wheelhouse, signing,
immutable-tag/Release, Pages serialization, signed-channel, and live-verification gates. After the 90-day retention
window, manually dispatch **Replay Python wheel** from `main` with the exact commit plus its successful source CI run ID
and attempt. That admission workflow revalidates the evidence and current-`main` reachability without checking out or
executing the target, then emits only a one-day canonical replay request. Its completed `workflow_run` causes the
read-only **Publish Python wheel** workflow to revalidate the request and publish the replacement handoff. Then dispatch
the appliance release. If the immutable software Release already exists, that workflow verifies and reuses its signed
assets only after the replay wheel matches the bundled wheel byte for byte, preserving the original signed provenance
for channel recovery. Never rebuild or rename a wheel locally.

OVA and Hyper-V images use the separate manual lifecycle documented in the
[virtualization artifact guide](docs/reference/virtualization-artifacts.md). A maintainer workstation creates and
smokes `virtualization-vX.Y.Z-rc.N`; protected hosted jobs sign it, and the exact bytes may become
`virtualization-vX.Y.Z` only after isolated Proxmox and KVM smoke. Never attach virtualization assets to `vX.Y.Z`,
advance an appliance-update channel from a virtualization workflow, or give signing material or write-capable tokens
to a self-hosted runner.

## Security and conduct

Read the [Security Policy](SECURITY.md), including Atlaso's operational-identifier data classification, before handling
or reporting security-relevant material. Read the [Code of Conduct](CODE_OF_CONDUCT.md) before participating in
community spaces.
