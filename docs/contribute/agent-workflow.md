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

Before creating, selecting, delegating into, or reporting an implementation worktree, read the supported Codex configuration
and resolve its exact `git-worktree-root`; use only that root. Never guess, infer, synthesize, or silently fall back
to conventional paths or hard-code a host drive. Missing, ambiguous, inaccessible, unsafe, or unsupported configuration
requires maintainer direction before repository, build, or external mutation.

Implementation requires a dedicated clean worktree on a task-owned branch beneath that root. Reserve the primary
checkout for synchronization, coordination, and completed-task cleanup. Keep all task-owned temporary roots, staging,
builds, logs, reservations, and artifacts beneath that root or another explicit maintainer-configured permitted root;
never inherit `GetTempPath()`, `LocalAppData`, or OS defaults. Repeat the Mandatory Agent Startup Gate in the task
worktree before planning or mutation. If a worktree or mutable path is outside its permitted roots, preserve its state;
report the exact conflict for maintainer-directed migration or cleanup without automatically moving or deleting it.
Without a safe worktree or supported state location, stop before mutation; never implement in the primary checkout.

Before copying or using worktree credentials, read the
[credential reuse procedure](../reference/vmware-workstation-lifecycle-testing.md#reuse-primary-checkout-configuration-in-a-task-worktree).
An ordinary task that does not use credentials need not seed credential files.

## Validation resource preparation

Before creating disposable test, dependency, cache, build, or log roots, read the
[ownership evidence section](completed-task-cleanup.md#prepare-durable-ownership-evidence), record the original
identity and task/source binding at creation, and preserve the manifest outside every removal root. Choose only roots
supported by an existing owning cleanup tool; the generated-tree command requires a strict descendant of the task
worktree. A permitted root alone does not prove cleanup support. Keep durable handoff/evidence outside disposable
roots. Load the full cleanup procedure before release. Never retrofit missing creation evidence at cleanup time.

## Resource-scoped VMware coordination

Coordinate only overlapping operations on a specific VM, network, address allocation, credential/staging transaction,
or host-wide setting. Sharing a VMware host alone requires no coordination: independent task-owned labs may proceed
concurrently. Co-location never requires host-wide exclusivity, all-other-PR acknowledgements, zero running VMs, or
blanket PowerShell/Python pauses.

Record the exact shared resource or global operation, affected owners, unsafe overlap, bounded paused operations,
eligible independent work, and explicit release condition. Prefer supported atomic allocators/transaction locks to
entire-test-duration holds. Source, tests, read-only work, and disjoint VM/network operations remain eligible under
their own guards. Never stop unrelated VMs/processes or infer access to another owner's resources.

Generated delegation, handoffs, and heartbeat instructions must preserve the conflict record, scope, and release
condition. Recheck on resumption; never broaden a pause to the host or unrelated PRs without a new conflict explanation.
Preserve task/source ownership, original receipts, fresh scoped admission, capacity checks, credential custody,
collision protection, and native acceptance. Never bypass a guard for concurrency; report the blocked operation and
separately track proposed guard fixes. See [lifecycle examples and current limitations](../reference/vmware-workstation-lifecycle-testing.md#resource-scoped-coordination).

## Codex Task Title Traceability

### Supported title controls

Use supported task-title controls after identifying the issue: `Short description · Issue #<issue>`; after identifying
the PR: `Short description · Issue #<issue> · PR #<pr>`. Keep the description concise and stable; omit only nonexistent
identifiers and include every linked issue/PR for multi-item tasks. Private remediation titles contain only a sanitized
description, never advisory identifiers, affected features, or patch details.

### Unsupported title controls

Without supported controls or a mutable task, continue without renaming; never invent an undocumented CLI fallback.

### Schema-constrained reporting

Include every linked issue/PR in the first update and final response when free-form metadata is allowed. Otherwise
follow the required schema without blocking solely to add identifiers.

## Sol and Luna Delegation

The project `luna_worker` (`.codex/agents/luna-worker.toml`) selects `gpt-6-luna` at high reasoning effort. GPT-6 Sol High
leads; GPT-6 Luna High defaults to scoped implementation, investigation, tests, documentation, and parallel work.
Sol owns architecture, difficult debugging, integration, security, final review, validation, and delivery.

Luna returns evidence and open decisions to Sol after repeated failures or for architectural/cross-service reasoning,
authentication/security, database/schema migration, or broader networking/routing/DHCP/DNS work.
Delegated prompts require exact scope, owned files, expected result, checks, Mandatory Agent Startup Gate, resolved
Codex worktree root, and permitted task-state roots. Verify delegated worktree/mutable-path containment before relying
on results. UI prompts also require the Mandatory UI Design Guide Gate, interaction classification, and reused Atlaso
reference. Luna must not commit, push, change GitHub state, or delegate further.

Use multiple workers only for independent tasks with non-overlapping file ownership. Sol inspects and integrates every
returned diff. If Luna is unavailable, rate-limited, quota-exhausted, or cannot start due to capacity/runtime limits,
Sol works directly, reports fallback once, avoids repeated quota/rate-limit retries, and
never substitutes an unapproved model.

### Unrelated issue discoveries

Keep PRs scoped to linked issues. For reproducible or otherwise evidence-backed unrelated actionable problems, search
open and closed issues; absent a match, open a separate issue with exactly one appropriate type label and sanitized
evidence for independent follow-up. Link tracking when useful; add `Closes` only for issues the PR resolves. Fixing an
unrelated issue in the same PR requires explicit maintainer approval. Suspected sensitive vulnerabilities follow
[SECURITY.md](https://github.com/mdaneri/Atlaso/blob/main/SECURITY.md) instead of a public issue.
