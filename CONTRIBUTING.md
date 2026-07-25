# Contributing to Atlaso

Thank you for improving Atlaso. Contributions start with an issue and end
with a reviewed pull request.

## Issue and pull-request relationship

Create or link an issue before beginning implementation. Every pull request
must close at least one issue using `Closes #<issue>` in its description. An
issue describes the problem or intended outcome; its pull request contains the
implementation. GitHub closes the issue when that pull request merges.

Each linked issue must have exactly one type label:

| Label | Use |
| --- | --- |
| `bug` | Existing behavior is incorrect, unsafe, or regressed. |
| `enhancement` | A new capability or behavior change. |
| `documentation` | Documentation, policy, or discoverability work. |

These lifecycle labels are applied as needed:

| Label | Use |
| --- | --- |
| `needs triage` | A maintainer has not yet classified or prioritized the issue. |
| `blocked` | Work cannot proceed until an external dependency or decision is resolved. |
| `good first issue` | A bounded, approachable contribution for a new contributor. |
| `help wanted` | Maintainers welcome help from the community. |

`duplicate`, `invalid`, `question`, and `wontfix` describe resolution or
discussion state and do not replace a type label on active work.

## Development workflow

1. Fork the repository or create a branch from current `main`.
2. Create or identify the labeled issue, then describe the intended approach.
3. Make the smallest focused change and update relevant documentation in the
   same pull request.
4. Run focused tests, `git diff --check`, and the repository validation checks.
5. Update the branch version with `python scripts/version.py bump --base-root
   /path/to/main-checkout` when required by the pull-request version policy.
   Version sources are discovered independently in the base and target
   checkouts so an intentional package or module rename can still be validated.
6. Open a pull request using the template, include `Closes #<issue>`, and
   provide validation evidence.

`main` accepts squash merges only after required checks pass. Do not commit
directly to `main`.

## Automated contributors and coding agents

Every automated contributor, coding agent, subagent, and delegated agent must
complete the **Mandatory Agent Startup Gate** in [AGENTS.md](AGENTS.md) before
planning implementation or changing repository or external state. Its first
progress update must confirm the policy files were read, classify the work, and
identify the linked issue.

A delegating agent is responsible for including the startup gate in delegated
prompts and verifying compliance before accepting the delegated work. Changing
repositories, worktrees, or working directories requires the gate to be
repeated. Automation does not waive the issue, label, documentation, validation,
version, review, security, or conduct requirements in this guide.

## Security and conduct

Read the [Security Policy](SECURITY.md) before reporting a vulnerability. Read
the [Code of Conduct](CODE_OF_CONDUCT.md) before participating in community
spaces.
