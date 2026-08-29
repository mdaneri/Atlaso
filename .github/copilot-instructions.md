# Atlaso coding-agent instructions

Before planning implementation or changing repository or external state, read the root `AGENTS.md` completely. Then read
`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md`.

Complete the **Mandatory Agent Startup Gate** defined in `AGENTS.md`: confirm the policy files were read in the first
progress update, classify the work, and identify the linked GitHub issue. Repeat the gate after changing repositories,
worktrees, or working directories. For private vulnerability remediation, confirm a private advisory is linked without
putting its identifier or finding details on public surfaces.

For changes affecting templates, authored CSS, browser JavaScript, controls, layouts, data grids, dialogs, wizards, or
visible copy, also complete the **Mandatory UI Design Guide Gate** in `AGENTS.md` and read
`docs/contribute/ui-design-guide.md`
before planning implementation. Classify the interaction and name the existing Atlaso reference being reused.
Approval-only `custom/other` work must cite explicit maintainer approval and the closest related Atlaso reference.
New Tabulators must use `window.AtlasoUiPatterns.createGrid(...)`; every new or changed wizard must use
`window.AtlasoUiPatterns.createWizard(...)` and the generic `data-atlaso-wizard-*` DOM contract.

`AGENTS.md` and `CONTRIBUTING.md` are authoritative. In particular:

- create or link the labeled issue before implementation;
- update relevant documentation and validation in the same change;
- regenerate Python locks only through `python scripts/compile_requirements.py` so every package satisfies the
  seven-day upload-time cutoff;
- run locally only focused tests and applicable checks; the complete Python test suite belongs to GitHub CI;
- open pull requests ready for review without a duplicate opening `@codex review`, then request one `@codex review`
  after every later commit is pushed as the exact head;
- keep the task active with exactly one current-task heartbeat running every four minutes; each run must perform one
  bounded reconciliation and exit, and persistent GitHub polling loops that combine `gh` with `sleep` are forbidden
  outside explicitly requested short-lived debugging;
- retain the exact-head SHA and seen comment and review IDs in task context; every run must read and evaluate new
  top-level pull-request comments, inline review comments, review submissions and requested changes, exact-head checks,
  mergeability and conflicts, and authoritative review threads;
- treat merged, closed, or merge-ready as terminal states; keep the same heartbeat after actionable feedback and its
  focused commit-push-review cycle, and after a merge keep it running through linked-issue closure and
  current `origin/main` reachability, plus applicable post-merge workflow verification; then
  perform one final bounded readback and delete the exact current-task heartbeat; use the same final readback and
  deletion for an unmerged closed pull request or a
  delivery-complete merge-ready successful current head only when every item is seen and no actionable feedback or
  unresolved non-outdated review thread remains;
- bind deletion to the exact current-task heartbeat identity; never delete unrelated automations or use an ambiguous
  name match; accept an already absent heartbeat only after ownership and terminal evidence are revalidated; pause only
  for resumable holds such as unresolved maintainer decisions or external failures;
  a deletion failure or ambiguous ownership leaves the task actionable with the exact retry condition;
- apply the **Default merge authorization** policy to ordinary same-repository pull requests within the active task's
  scope: implementation, fix, solve, delivery, and similar requests grant default merge authority, including for an
  existing ordinary pull request the agent is explicitly asked to work on; do not require a separate merge instruction;
  preserve an explicit merge hold until the user or maintainer withdraws it, require strict up-to-date required checks
  to bind the validated base, also guard the head SHA, never use an administrative bypass, fail closed instead of
  invoking `gh pr merge` when a merge queue is required, and keep GitHub auto-merge as a separate explicit maintainer
  choice;
- after an authorized merge and all remaining activity, send the primary-checkout controller a `cleanup-ready` handoff
  and require the ordered terminal states `remote_branch_absent`, `worktree_removed`, and `task_title_done`; delete only
  the task-owned GitHub branch with an atomic expected-SHA lease such as
  `--force-with-lease=refs/heads/BRANCH:HEAD_SHA`, fail closed on a lease rejection or unavailable atomic guard,
  never remove the primary checkout, and append the exact suffix " · Done" once only after every cleanup gate succeeds.
  If no supported mutable task-title control exists,
  record `task_title_done` as verified not applicable with capability evidence, omit the visible suffix, and do not block
  otherwise-complete cleanup;

  For an existing ordinary pull request, evaluate remote-branch ownership separately from local checkout/worktree
  ownership after merge and lifecycle verification. Preserve a non-task-owned remote branch, record
  `non_task_owned_remote_branch_preserved`, and mark only `remote_branch_absent` not applicable. Preserve a
  non-task-owned checkout or worktree and its local refs and metadata, record `non_task_owned_checkout_preserved`, and
  mark only `worktree_removed` not applicable. Clean up every task-owned side normally and keep terminal order;
  ambiguous ownership blocks the affected transition and `task_title_done`.

  For a non-primary worktree, record `worktree_removed` only after `git worktree remove`, stale-registration pruning,
  path and registration absence, deletion of the exact unreferenced local task branch that still equals the recorded
  head, and verified `local_task_branch_absent`. An interrupted `worktree_removal_resume` may finish that local-ref
  deletion only when the path and registration remain absent. The
  worktree removal remote branch gate is either verified absent or recorded not applicable through
  `non_task_owned_remote_branch_preserved`, and the same ownership, head, and merge
  evidence still proves the exact local branch safely deletable or already absent.

  A primary-checkout task must restore the clean checkout to current `origin/main`, verify HEAD, delete only the exact
  unreferenced local task branch, and record `primary_checkout_restored` before worktree removal becomes not applicable.
  An interrupted `primary_checkout_resume` is valid only from clean local `main` freshly fast-forwarded to current
  `origin/main`. The primary checkout remote branch gate is either verified absent or recorded not applicable through
  `non_task_owned_remote_branch_preserved`; the exact local task branch must still be safely deletable or already
  absent.

  Terminal order:

  1. `remote_branch_absent`
  2. `worktree_removed`
  3. `task_title_done`

  Private remediation requires privately verified `advisory_cleanup_ready` in place of a closed public issue; keep the
  advisory identity, title, handoff, evidence, and temporary-fork operations sanitized, and retain the task through
  coordinated release, disclosure, and authorized advisory-state activity. Fulfill the first terminal state through
  `advisory_remote_branch_absent` by privately binding and deleting only the exact temporary-fork ref at the recorded
  private-pull-request head with the same atomic expected-SHA lease; never delete the fork or change advisory state.
- keep each pull request within its linked scope; search for an existing issue and open a separately typed, sanitized
  issue when an evidence-backed unrelated problem has no tracking record, while routing suspected vulnerabilities
  through `SECURITY.md` instead of a public issue;
- use `Closes #<issue>` in the pull request;
- follow the security and conduct policies; and
- never commit directly to `main`.

The private vulnerability remediation workflow in `SECURITY.md` is the only exception to the public issue, repository
branch, and `Closes #<issue>` requirements. Keep all advisory references and vulnerability details private. For a
temporary private fork, advisory-side maintainer review and recorded local validation replace the ordinary Codex review,
`@codex review`, exact-head CI/status, comment, label, and review-thread follow-through above. Do not request, wait for,
or claim unavailable integrations. Run the complete Python test suite locally when required by `SECURITY.md`; this
overrides the ordinary local full-suite prohibition, and missing full-suite evidence blocks advisory merge. Never use
ordinary pull-request merge controls or `gh pr merge`, and do not change advisory state without explicit maintainer
authorization.

Subagents and delegated agents must complete the same gate. A delegating agent must include the requirement in its
prompt and verify compliance before using delegated work.
