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

- [ ] Focused tests/checks passed.
- [ ] `git diff --check` passed.
- [ ] Relevant documentation is updated.
- [ ] The linked public issue has exactly one type label: `bug`, `enhancement`, or `documentation`; or this is a private
  vulnerability-remediation pull request linked to its advisory only on private surfaces.
- [ ] Automated contributors completed the Mandatory Agent Startup Gate in `AGENTS.md` before implementation.
- [ ] UI changes follow `docs/contribute/ui-design-guide.md`, and the Summary names the interaction classification and reused
  Atlaso reference; approval-only `custom/other` work also cites maintainer approval and the closest related reference;
  or this pull request does not change the UI.
- [ ] New Tabulators and new or changed wizards use the shared `AtlasoUiPatterns.createGrid(...)` and
  `AtlasoUiPatterns.createWizard(...)` entry points and the generic wizard DOM contract.
- [ ] Documentation follows `docs/contribute/documentation-authoring.md`, passes `npm run lint:markdown`, and updates
  affected media manifests.
- [ ] Branding and promotional claims follow `docs/assets/brand/BRAND_GUIDE.md`.
