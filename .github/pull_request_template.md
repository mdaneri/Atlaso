# Pull request

## Linked issue

Closes #

Every pull request must close at least one pre-existing, labeled issue.

## Summary

<!-- Describe the outcome and implementation. -->

## Validation

<!-- List commands run and their results. -->

- [ ] Focused local tests/checks passed; GitHub CI owns the complete Python test suite.
- [ ] `git diff --check` passed.
- [ ] Relevant documentation is updated.
- [ ] The linked issue has exactly one type label: `bug`, `enhancement`, or `documentation`.
- [ ] Automated contributors completed the Mandatory Agent Startup Gate in `AGENTS.md` before implementation.
- [ ] This pull request is ready for review; the automatic initial Codex review is monitored without a duplicate opening
  `@codex review` comment.
- [ ] Each post-opening pushed commit received one `@codex review` request as the exact head, and current-head checks,
  comments, reviews, and authoritative review threads were followed through.
- [ ] UI changes follow `docs/contribute/ui-design-guide.md`, and the Summary names the interaction classification and reused
  Atlaso reference; approval-only `custom/other` work also cites maintainer approval and the closest related reference;
  or this pull request does not change the UI.
- [ ] New Tabulators and new or changed wizards use the shared `AtlasoUiPatterns.createGrid(...)` and
  `AtlasoUiPatterns.createWizard(...)` entry points and the generic wizard DOM contract.
- [ ] Documentation follows `docs/contribute/documentation-authoring.md`, passes `npm run lint:markdown`, and updates
  affected media manifests.
- [ ] Branding and promotional claims follow `docs/assets/brand/BRAND_GUIDE.md`.
