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
- [ ] For an agent-authored internal pull request, the Explicit merge authorization policy was checked: an implementation
  or delivery request alone was not treated as an explicit merge instruction, and the pull request remains open without
  one. Before any authorized squash merge, explicit holds, strict up-to-date required checks that bind the base, an
  expected-head guard without administrative bypass, and confirmation that no merge queue is required were checked; or
  this pull request is outside that policy.
- [ ] After any authorized merge and remaining post-merge activity, the originating task will send a `cleanup-ready`
  handoff and remain incomplete until `remote_branch_absent`, `worktree_removed`, and `task_title_done` occur in order;
  only then may supported title controls append the exact suffix " · Done" once. If no supported mutable title control
  exists, `task_title_done` as verified not applicable requires capability evidence and omits the visible suffix.

  Terminal order:

  1. `remote_branch_absent`
  2. `worktree_removed`
  3. `task_title_done`

  Private remediation requires privately verified `advisory_cleanup_ready` instead of a closed public issue and retains
  sanitized task state until coordinated release, disclosure, and authorized advisory-state activity are complete. Its
  `advisory_remote_branch_absent` gate privately binds and removes only the exact temporary-fork ref, never the fork.
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
