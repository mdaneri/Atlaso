---
title: Agent worktree and delegation workflow
description: Conditional worktree, title, scope, and delegation requirements.
audience:
  - contributor
  - maintainer
status: current
---

# Agent worktree and delegation workflow

Read before preparing implementation, selecting a worktree, or delegating work.

## Worktree preparation

Before creating, selecting, delegating into, or reporting an agent-owned implementation worktree, read the supported
Codex configuration and resolve the exact configured `git-worktree-root`. Use only that configured root for the
worktree. Never guess, infer, synthesize, or silently fall back to a repository sibling, user profile, temporary
directory, drive, or other conventional path. A repository policy must not hard-code a host drive: the supported Codex
setting is authoritative. If the setting is missing, ambiguous, inaccessible, unsafe, or unavailable through a
supported interface, stop before repository, build, or external mutation and request maintainer direction.

Agent-authored implementation work must use a dedicated clean worktree beneath that resolved root on its task-owned
branch. Do not make implementation edits in the repository's primary checkout; reserve that checkout for
synchronization, coordination, and completed-task cleanup. Keep task-owned temporary roots, staging, build outputs,
logs, reservation state, and generated artifacts beneath the configured worktree root or another explicit
maintainer-configured permitted root; do not silently inherit `GetTempPath()`, `LocalAppData`, or another OS-default
location. If no supported permitted location is available, stop before mutation. Create or select the task worktree
before applying implementation changes, and repeat the Mandatory Agent Startup Gate there before planning or mutation.
If an existing task is outside the configured root or another required task-owned mutable path is outside every
permitted root, preserve its state: do not move or delete it automatically, and report the exact conflict for
maintainer-directed migration or cleanup. If a safe dedicated worktree cannot be established, stop for maintainer
direction instead of continuing in the primary checkout.

Credential access is conditional: before copying or using worktree credentials, read the
[credential reuse procedure](../reference/vmware-workstation-lifecycle-testing.md#reuse-primary-checkout-configuration-in-a-task-worktree).
An ordinary task that does not use credentials need not seed credential files.

## Validation resource preparation

Before creating disposable test, dependency, cache, build, or log roots, read the
[ownership evidence section](completed-task-cleanup.md#prepare-durable-ownership-evidence), record the original
identity and task/source binding at creation, and preserve the manifest outside every removal root. Choose only roots
supported by an existing owning cleanup tool; the generated-tree command requires a strict descendant of the task
worktree. A permitted root alone does not prove cleanup support. Keep durable handoff/evidence outside disposable
roots. Load the full cleanup procedure before release. Never retrofit missing creation evidence at cleanup time.

## Codex Task Title Traceability

### Supported title controls

When the current Codex runtime exposes supported task-title controls, use them after identifying or creating the linked
GitHub issue to rename the current task to `Short description · Issue #<issue>`. After opening or discovering the pull
request, rename it again to `Short description · Issue #<issue> · PR #<pr>`. Keep the short description concise and
stable, and omit only a segment whose identifier does not exist yet. When one task spans multiple items, list every
identifier in its segment, for example `Short description · Issues #123, #124 · PRs #456, #457`.

For private vulnerability remediation, use only a sanitized short description in the task title. Do not place advisory
identifiers, affected features, or patch details in titles.

### Unsupported title controls

When supported task-title controls are unavailable, or the runtime does not have a mutable Codex task, continue without
blocking on the rename. Do not invent or depend on an undocumented CLI fallback.

### Schema-constrained reporting

Include every linked issue and pull-request identifier in the first progress update and final response only when those
reporting surfaces accept free-form traceability metadata. When a required output schema does not permit extra metadata,
follow the schema and do not block solely to add the identifiers.

## Sol and Luna Delegation

The project-scoped `luna_worker` in `.codex/agents/luna-worker.toml` selects `gpt-6-luna` at high reasoning effort.
GPT-6 Sol High is the lead; GPT-6 Luna High is the default worker for scoped implementation, investigation, tests,
documentation, and parallel tasks. Sol owns architecture, difficult debugging, integration, security, final review,
validation, and delivery.

Escalate to Sol after repeated Luna failures or when the task needs architectural reasoning, non-obvious interactions
across services, authentication or security, database/schema migration, or broader networking/routing/DHCP/DNS
reasoning. Luna returns its evidence and the open decision to Sol.
Every delegated prompt must state the exact scope, owned files, expected result, relevant checks, the Mandatory Agent
Startup Gate, and the exact resolved Codex worktree root and permitted task-state roots. The delegating agent must
verify the delegated worktree and task-owned mutable paths against those roots before relying on the result. UI prompts
must also include the Mandatory UI Design Guide Gate, interaction classification, and reused Atlaso reference. Luna
must not commit, push, change GitHub state, or delegate further.

Run multiple Luna workers only for independent tasks with non-overlapping
file ownership. Sol must inspect and integrate every returned diff before
relying on it.

If Luna is unavailable, rate-limited, its usage allowance is exhausted,
or the worker cannot be started because of capacity/runtime limitations,
Sol performs the work directly. Sol does not repeatedly retry Luna after a
quota or rate-limit failure and never substitutes an unapproved model.
Report the fallback once for the current task.

### Unrelated issue discoveries

Keep each pull request limited to its linked issue scope. When work reveals a reproducible or otherwise evidence-backed
actionable problem outside that scope, search open and closed issues for an existing tracking record. If none exists,
open a separate issue with exactly one appropriate type label and enough sanitized evidence for independent follow-up.
Link the new or existing issue from the active pull request or task report when useful, but do not add `Closes` unless
the active pull request actually resolves it. Do not expand the pull request to fix the unrelated issue without explicit
maintainer approval. Route suspected sensitive vulnerabilities through
[SECURITY.md](https://github.com/mdaneri/Atlaso/blob/main/SECURITY.md) instead of a public issue.
