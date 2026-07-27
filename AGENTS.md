# Atlaso Agent Notes

## Mandatory Agent Startup Gate

Before planning implementation or changing repository or external state, read this file completely, then read
[CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md). Treat all
four documents as mandatory instructions. In the first progress update, confirm that the policy files were read,
classify the work as `bug`, `enhancement`, `documentation`, or security-sensitive work, and identify the linked GitHub
issue.

Repeat this gate whenever the repository, worktree, or working directory changes, or when a policy file changes. A
delegating agent must include the gate in every delegated prompt and verify completion before using delegated work. Stop
for maintainer direction if a policy is missing, conflicting, or unclear.

## Mandatory UI Design Guide Gate

Before planning or implementing any user-interface change, read the
[Atlaso UI Design Guide](docs/contribute/ui-design-guide.md) completely, classify the interaction as
`direct-edit Tabulator`, `wizard`, `read-only semantic table`, or `custom/other`, and name the reused Atlaso reference.
`custom/other` work requires explicit maintainer approval. Confirm this gate in the first progress update.

All new Tabulator collections must use `window.AtlasoUiPatterns.createGrid(...)`, and every new or changed wizard must
use `window.AtlasoUiPatterns.createWizard(...)` with the generic `data-atlaso-wizard-*` DOM contract. Existing raw
Tabulator constructors are temporary issue #117 migration sites; do not copy or extend them.

## Repository Delivery Workflow

[CONTRIBUTING.md](CONTRIBUTING.md) is canonical. Every change requires a linked GitHub issue with exactly one type
label, documentation in the same change, the next patch version, validation, and a pull request containing
`Closes #<issue>`. Never commit directly to `main`.

GitHub-managed version-update pull requests from `.github/dependabot.yml` are the only exception to the pre-existing
issue and per-update documentation requirements. They still require the `enhancement` and `dependencies` labels, the
normal version, CI, review, and squash-merge gates, and synchronized generated locks. See
[Detailed agent policies](docs/contribute/agent-policies.md) for the complete dependency-update contract.

Use `python scripts/version.py bump` or `.\scripts\version.ps1` to increment and synchronize the current patch version.
When an explicit target is required, pass the current version or exact next patch through `--version X.Y.Z` to Python or
`-Version X.Y.Z` to PowerShell. Explicit targets cannot skip a patch or change the major or minor version. Never update
individual version sources manually.

## Documentation and branding

Markdown is the canonical documentation source. Follow the
[documentation authoring guide](docs/contribute/documentation-authoring.md), keep `npm run lint:markdown` clean, and
update affected pages and media manifests whenever behavior or UI changes. Follow the
[Atlaso Brand Kit](docs/assets/brand/BRAND_GUIDE.md) for documentation, screenshots, video, and promotional claims.

## Canonical implementation policies

Read [Detailed agent policies](docs/contribute/agent-policies.md) before appliance, UI, networking, service, image,
deployment, or live-VM work. Its subsystem contracts remain mandatory. Use the documentation index to locate the closest
current operator or contributor guide before making a change.

The following cross-cutting boundaries always apply:

- `/appliance-apply` is the only desired-state host-mutation workflow.
- Privileged appliance operations go through `atlaso-helper` and constrained sudoers rules.
- Keep development system adapters in dry-run mode unless a reviewed apply unit explicitly promotes real mutation.
- VMware Workstation is the default live appliance target; use Hyper-V lifecycle coverage for exact VLAN behavior.
- Validate live appliance readiness through `/openapi.json`, not VMware Tools IP discovery or service color alone.
- OIDC clients use explicit validated identity sources and emit only granted, explicitly mapped claims; see the detailed
  agent policies and canonical OIDC service guide. Administration keeps generated client IDs immutable, shows secrets
  once, validates the issuer against the applied Management HTTPS certificate, preserves retired-key overlap, and
  exports only public relying-party metadata.
- Never expose credentials, authenticated URLs, private keys, raw secrets, or secret-bearing commands in UI, jobs,
  audits, logs, documentation, screenshots, or video.
- Browser navigation to a globally disabled Web Terminal must render the authenticated Atlaso unavailable-state page;
  reserve JSON and protocol errors for ticket, API, and WebSocket consumers.
