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

## Development workflow

Automated contributors begin with [AGENTS.md](AGENTS.md) and its conditional routes. Read only the applicable
procedures before planning or performing the operation; [progressive policy](docs/contribute/progressive-policy.md)
explains ownership and measurement. Private vulnerability remediation follows [SECURITY.md](SECURITY.md).

1. Link the correctly typed issue, keep the change scoped, and work on a branch from current `main`.
2. Update relevant documentation with the smallest focused implementation.
3. Run focused tests plus applicable repository, documentation, and static checks, and `git diff --check`.
   The complete Python test suite belongs to GitHub CI except where the private security workflow requires it locally.
4. Synchronize the next patch using `python scripts/version.py bump` or `scripts/version.ps1`; never edit individual
   version sources. Explicit targets may be only the current version or exact next patch, never skip a patch or change
   major/minor. With an available base checkout use `--base-root` to enforce exactly one patch above the PR base.
5. Open a ready pull request with `Closes #<issue>` and validation evidence, following
   [PR review and delivery](docs/contribute/pr-workflow.md). Never commit directly to `main`.

### Conditional contribution standards

| Operation | Read before doing it |
| --- | --- |
| Worktree preparation, delegation, unrelated discoveries | [Agent workflow](docs/contribute/agent-workflow.md) |
| Review, PR follow-through, merge | [PR workflow](docs/contribute/pr-workflow.md) |
| Resource release or completed-task cleanup | [Cleanup](docs/contribute/completed-task-cleanup.md) |
| UI changes | [UI design guide](docs/contribute/ui-design-guide.md) |
| API or route changes | [API authoring](docs/contribute/api-authoring.md) and [router architecture](docs/contribute/router-architecture.md) |
| Python changes | [Static analysis](docs/contribute/python-static-analysis.md) |
| PowerShell changes | [PowerShell authoring](docs/contribute/powershell-authoring.md) |
| Documentation or media | [Documentation authoring](docs/contribute/documentation-authoring.md) |
| Dependency updates, including Dependabot | [Dependency management](docs/contribute/dependency-management.md) |
| Release, trusted CI, signing, publishing, Pages | [Release policy](docs/contribute/release-policy.md) |
| Sensitive information or suspected vulnerabilities | [Security policy](SECURITY.md) |
| Community participation | [Code of conduct](CODE_OF_CONDUCT.md) |

### Maintainer override / break-glass

This section is the canonical maintainer override policy. A human maintainer may use GitHub's ruleset or administrative
bypass only as an explicit break-glass action when the protected workflow cannot safely or reasonably complete, such as
broken required checks, repository-policy repair, emergency security remediation, or infrastructure failure. Ordinary
delivery continues to use the protected pull-request workflow.

Automated contributors, coding agents, delegated agents, workflows, and other automation must never use or request a
ruleset or administrative bypass. The human-maintainer break-glass authority cannot be delegated to automation. It does
not change default merge authority, waive a maintainer hold, or authorize GitHub auto-merge.

Before using the bypass, the human maintainer must verify the exact commit and intended change and complete as much
applicable validation as circumstances allow. Record the reason, exact commit, actor, validation performed, and any
unavailable or intentionally overridden gate on an appropriate audit surface such as the pull request, issue, or commit.
When public recording would disclose sensitive security information, use the private advisory or another appropriate
private security surface instead.

This break-glass authority does not replace or broaden the private-vulnerability workflow in `SECURITY.md`. Advisory
state changes and advisory merges still require the explicit authorization and private validation defined there.
