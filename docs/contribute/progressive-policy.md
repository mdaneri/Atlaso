---
title: Progressive agent policy
description: Load a small core and operation-specific safety contracts with measurable context budgets.
audience:
  - contributor
  - maintainer
status: current
---

# Progressive agent policy

The mandatory core is `AGENTS.md` plus `CONTRIBUTING.md`. The root route table selects additional policy before the
relevant operation; it does not require traversing every link. Policy remains mandatory when its trigger applies.
Re-evaluate routes when scope, worktree, or policy changes, but reuse unchanged instructions already read in the task.

## Canonical ownership

| Contract | Owner |
| --- | --- |
| Startup, always-applicable boundaries, route triggers | Root `AGENTS.md` |
| Issue/type relationship, normal patch workflow, human break-glass | Root `CONTRIBUTING.md` |
| Worktree/state roots, titles, delegation, unrelated discovery | [Agent workflow](agent-workflow.md) |
| Comprehensive review, waiting, authority, guarded merge, post-merge verification | [PR workflow](pr-workflow.md) |
| Secret custody and worktree reuse entry point | [Credential policy](credential-policy.md) |
| Classification and private remediation | Root `SECURITY.md` |
| Resource ownership, release, terminal ordering, cleanup command | [Completed-task cleanup](completed-task-cleanup.md) |
| Trusted CI, Pages, signing and release publication | [Release policy](release-policy.md) |
| Domain-specific implementation constraints | Matching section of [subsystem policies](agent-policies.md) and linked operator procedure |

The PR template and Copilot instructions link to these contracts. Do not copy their normative workflow into more
entry points. Extend the owning section and focused checks instead. Existing specialized subsystem detail remains
available; moving it out of the root does not relax its requirements.

## Selecting routes

- An ordinary Python fix reads the core, implementation route, and Python standard; load subsystem sections affected
  by its behavior. Documentation changes also load the documentation standard. A routine patch-version bump follows
  CONTRIBUTING and does not require every release/publication procedure.
- A UI fix additionally loads the UI guide before planning, classifies the interaction, and names the reused reference.
- A reviewer loads the complete-review contract even without implementation. Analyze the whole change before
  publishing; an unchanged head is not a reason to run another speculative review.
- A deployment loads infrastructure, credentials, and relevant subsystem procedures before retrieving credentials or
  mutating a VM. Record disposable resources when created; load cleanup before releasing them.
- Suspected sensitive findings route to SECURITY before a public issue, review, or report. Private authorization and
  local-validation exceptions remain intact.
- Ordinary PR waiting uses one fifteen-minute heartbeat only while asynchronous work remains. Reconcile immediately
  when already awake for a push, user input, or guarded transition. Read changed feedback, not unchanged code.

## Preserved safety

The loading boundary does not change secret custody, private advisory authorization, exact worktree/resource
ownership, credential containment, release signatures/provenance, immutable publication, protected status publishing,
or infrastructure rollback requirements. Guarded merges still require current evidence, strict base enforcement,
expected-head protection, no bypass and no implicit merge queue or auto-merge. Explicit holds remain authoritative.
Cleanup retains independent evidence and resource release before branch, worktree, and completion-title transitions.

## Measurement and validation

Baseline commit `a21d9fd64a6df545d48fc3b600a8edf0ab6e8894` required four complete startup files:

| File | Words | UTF-8 bytes, LF normalized |
| --- | ---: | ---: |
| AGENTS.md | 14,953 | 112,906 |
| CONTRIBUTING.md | 5,209 | 39,617 |
| CODE_OF_CONDUCT.md | 612 | 4,456 |
| SECURITY.md | 815 | 5,997 |
| Total | 21,589 | 162,976 |

`scripts/check_repo.py` enforces the root budget and combined ordinary pre-implementation route budget against this
fixed baseline. Measure actual LF-normalized UTF-8 bytes and whitespace-separated words; these are not billed tokens.
Count core and required route documents, including transitive required reads, once each. Keep ordinary
pre-implementation policy at or below 20% of baseline. Report review/delivery and high-risk route costs separately;
never hide mandatory reads behind a new filename to claim savings.

Focused tests check routing and canonical ownership, missing/hidden operative requirements, terminal ordering,
merge-authority provenance, and the comprehensive-review contract. Markers and structured checks detect policy
regressions; they do not prove arbitrary natural-language equivalence or actual agent compliance. Retain existing
runtime safety tests rather than replacing them with prose checks.

The fifteen-minute cadence reduces unchanged waiting wakeups from fifteen to four per hour (about 73%). Startup
reduction is not an equal promise of total credit savings: implementation, verification, specialized work, caching,
and model reasoning still affect usage. No local-model worker or provider change is part of this change.
