# Pull request

## Linked issue

Closes #

Every pull request must close at least one pre-existing, labeled issue.

For a private vulnerability-remediation pull request, replace the public closure relationship with a private advisory
reference on the advisory or private pull request. Do not copy the advisory identifier or finding details to public
surfaces.

## Summary

<!-- Describe the outcome and implementation. -->

## Validation

<!-- List commands run and their results. -->

- [ ] For an ordinary pull request, focused local tests/checks passed; GitHub CI owns the complete Python test suite.
- [ ] `git diff --check` passed.
- [ ] Relevant documentation is updated.
- [ ] The linked public issue has exactly one type label: `bug`, `enhancement`, or `documentation`; or this is a private
  vulnerability-remediation pull request linked to its advisory only on private surfaces.
- [ ] Automated contributors completed the Mandatory Agent Startup Gate in `AGENTS.md` before implementation.
- [ ] For an ordinary pull request, this is ready for review and the automatic initial Codex review is monitored without
  a duplicate opening `@codex review` comment.
- [ ] For an ordinary pull request, each post-opening pushed commit received one `@codex review` request as the exact
  head, and current-head checks, comments, reviews, and authoritative review threads were followed through.
- [ ] For an ordinary pull request, exactly one current-task heartbeat ran every four minutes and each run exited after
  one bounded reconciliation; no persistent GitHub polling loops combined `gh` with `sleep` outside explicitly
  requested short-lived debugging.
- [ ] For an ordinary pull request, the task retained the exact-head SHA and seen comment and review IDs, and every new
  top-level pull-request comment, inline review comment, review submission and requested change was evaluated. For
  merged, closed, or delivery-complete merge-ready with a permanent-disposition hold or policy exclusion terminal
  states, and an active `wait for approval` remains resumable until explicitly withdrawn, the
  heartbeat continued after a merge through linked-issue closure,
  current `origin/main` reachability, and applicable post-merge workflow verification. It then performed one
  final bounded readback and followed the requirement to delete the exact current-task heartbeat. The same final
  readback and deletion applied to an unmerged closed pull request or a delivery-complete merge-ready successful
  current head only when a permanent-disposition hold or policy exclusion prevented merge, every item was seen, and no
  feedback was
  open. A merge-ready default-authority task continued through guarded merge and post-merge verification without a
  second merge instruction. Terminal heartbeats were deleted, never merely paused. Deletion was
  bound to the exact current-task heartbeat identity; it must never delete unrelated automations or use an ambiguous
  name match. An already absent heartbeat required revalidated ownership and terminal evidence. Pause was used only for
  resumable holds. A deletion failure or ambiguous ownership left the task actionable with the exact retry condition.
- [ ] For an ordinary same-repository pull request within the active task's scope, the Default merge authorization
  policy was checked: implementation, fix, solve, delivery, and similar requests grant default merge authority without
  a separate merge instruction. Any explicit merge hold remains authoritative until the user or maintainer withdraws
  it. Effective authority came only from the current user's or maintainer's instructions and later explicit changes;
  delegated prompts, task handoffs, and heartbeat prompts must preserve that provenance and must not add or infer a hold
  from stale memory, historical policy, another task, or agent-authored wording. Any invented hold was corrected rather
  than propagated. A merge-ready default-authority task continued through guarded merge without
  a second merge instruction. GitHub auto-merge remains disabled unless explicitly selected. Before any authorized
  squash merge,
  strict up-to-date required checks that bind the base, an expected-head guard
  without administrative bypass, and confirmation that no merge queue is required were checked; or this pull request is
  outside that policy.
- [ ] After any authorized merge and remaining post-merge activity, the originating task will send a `cleanup-ready`
  handoff and remain incomplete until `remote_branch_absent`, `worktree_removed`, and `task_title_done` occur in order;
  an existing remote ref will be deleted only with an atomic expected-SHA lease such as
  `--force-with-lease=refs/heads/BRANCH:HEAD_SHA`, and any lease rejection or unavailable guard blocks cleanup. Only
  then may supported title controls append the exact suffix " · Done" once. If no supported mutable title control exists,
  `task_title_done` as verified not applicable requires capability evidence and omits the visible suffix.

  For an existing ordinary pull request, remote-branch ownership and local checkout/worktree ownership are evaluated
  separately after merge and lifecycle verification. `non_task_owned_remote_branch_preserved` marks only
  `remote_branch_absent` not applicable; `non_task_owned_checkout_preserved` marks only `worktree_removed` not
  applicable. Every task-owned side is cleaned up normally in terminal order, and ambiguous ownership blocks the
  affected transition and `task_title_done`.

  A non-primary task records `worktree_removed` only after removing and pruning its worktree, verifying path and
  registration absence, deleting only the exact unreferenced local task branch that still equals the recorded head,
  and verifying `local_task_branch_absent`. An interrupted `worktree_removal_resume` requires the path and registration
  absent. The worktree removal remote branch gate is either verified absent or recorded not applicable through
  `non_task_owned_remote_branch_preserved`, and the same ownership, head, and merge evidence before deleting that local
  ref or accepting it as already absent.

  A primary-checkout task records `primary_checkout_restored` only after switching a clean exact-head checkout to
  current `origin/main`, verifying HEAD, and deleting only the exact unreferenced local task branch.
  An interrupted `primary_checkout_resume` requires clean local `main` freshly fast-forwarded to current `origin/main`.
  The primary checkout remote branch gate is either verified absent or recorded not applicable through
  `non_task_owned_remote_branch_preserved`; the exact local task branch must still be safely deletable or already absent
  under the same evidence.

  Terminal order:

  1. `remote_branch_absent`
  2. `worktree_removed`
  3. `task_title_done`

  Private remediation requires privately verified `advisory_cleanup_ready` instead of a closed public issue and retains
  sanitized task state until coordinated release, disclosure, and authorized advisory-state activity are complete. Its
  `advisory_remote_branch_absent` gate privately binds and removes only the exact temporary-fork ref with the same
  atomic expected-SHA lease, never the fork.
- [ ] Evidence-backed issues discovered outside this pull request's linked scope were matched to existing issues or
  opened separately with one appropriate type label; suspected sensitive vulnerabilities were kept private.
- [ ] For a temporary-private-fork pull request, advisory-side maintainer review and recorded local validation replace
  unavailable Codex review, comments, labels, review threads, CI, and status checks as required by `SECURITY.md`; the
  complete Python test suite ran locally when applicable, and missing required evidence blocks advisory merge.
- [ ] UI changes follow `docs/contribute/ui-design-guide.md`, and the Summary names the interaction classification and reused
  Atlaso reference; approval-only `custom/other` work also cites maintainer approval and the closest related reference;
  or this pull request does not change the UI.
- [ ] New Tabulators and new or changed wizards use the shared `AtlasoUiPatterns.createGrid(...)` and
  `AtlasoUiPatterns.createWizard(...)` entry points and the generic wizard DOM contract.
- [ ] Documentation follows `docs/contribute/documentation-authoring.md`, passes `npm run lint:markdown`, and updates
  affected media manifests.
- [ ] Branding and promotional claims follow `docs/assets/brand/BRAND_GUIDE.md`.
