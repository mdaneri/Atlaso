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
- keep the task active to monitor exact-head checks, comments, reviews, and authoritative review threads through a
  successful current head with no unresolved actionable feedback;
- apply the **Explicit merge authorization** policy to ordinary agent-authored internal pull requests: implementation,
  fix, solve, delivery, and similar requests authorize a ready pull request but do not authorize merging it; require an
  explicit merge instruction for that pull request and otherwise leave it open after every delivery gate passes;
  preserve explicit holds, require strict up-to-date required checks to bind the validated base, also guard the head
  SHA, never use an administrative bypass, fail closed instead of invoking `gh pr merge` when a merge queue is required,
  and keep GitHub auto-merge as a separate explicit maintainer choice;
- after an authorized merge and all remaining activity, send the primary-checkout controller a `cleanup-ready` handoff
  and require the ordered terminal states `remote_branch_absent`, `worktree_removed`, and `task_title_done`; delete only
  the task-owned GitHub branch, never remove the primary checkout, and append the exact suffix " · Done" once only after
  every cleanup gate succeeds.

  Terminal order:

  1. `remote_branch_absent`
  2. `worktree_removed`
  3. `task_title_done`

  Private remediation requires privately verified `advisory_cleanup_ready` in place of a closed public issue; keep the
  advisory identity, title, handoff, evidence, and temporary-fork operations sanitized, and retain the task through
  coordinated release, disclosure, and authorized advisory-state activity.
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
