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
- use `Closes #<issue>` in the pull request;
- follow the security and conduct policies; and
- never commit directly to `main`.

The private vulnerability remediation workflow in `SECURITY.md` is the only exception to the public issue, repository
branch, and `Closes #<issue>` requirements. Keep all advisory references and vulnerability details private, and retain
the remaining local validation and review requirements. Temporary private forks have no CI or status checks; never use
ordinary pull-request merge controls or `gh pr merge`, and do not change advisory state without explicit maintainer
authorization.

Subagents and delegated agents must complete the same gate. A delegating agent must include the requirement in its
prompt and verify compliance before using delegated work.
