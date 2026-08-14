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

### Automated pull-request follow-through

Automated contributors run locally only tests focused on the changed behavior, together with applicable repository,
documentation, static-analysis, deployment, and diff checks. They must not run the complete Python test suite locally;
the canonical GitHub CI `Python tests` context supplies that result.

Open agent-authored pull requests ready for review. The ready event starts the initial Codex review, so do not post a
duplicate opening `@codex review`. For every later commit, complete a commit-push-review cycle before starting another
change: push the commit, verify it is the pull request's exact head, and post one `@codex review` request.

The originating task remains responsible for the pull request after opening. Monitor all exact-head checks, comments,
reviews, and authoritative review threads. Address actionable feedback, reply and resolve handled threads, and repeat
focused validation plus the commit-push-review cycle after every fix. Completion requires successful current-head
checks and no unanswered actionable comment or unresolved non-outdated review thread. Escalate decisions or external
failures that require maintainer action.

`main` accepts squash merges only after required checks pass. Do not commit directly to `main`.

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

## Security and conduct

Read the [Security Policy](SECURITY.md), including Atlaso's operational-identifier data classification, before handling
or reporting security-relevant material. Read the [Code of Conduct](CODE_OF_CONDUCT.md) before participating in
community spaces.
