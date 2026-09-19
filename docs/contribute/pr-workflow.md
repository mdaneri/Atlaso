---
title: Pull-request review and delivery
description: Complete reviews, bounded waiting, and guarded ordinary pull-request delivery.
audience:
  - contributor
  - maintainer
status: current
---

# Pull-request review and delivery

Read this policy before reviewing, opening, monitoring, or merging an ordinary pull request.
For a suspected vulnerability or temporary private fork, load [SECURITY.md](https://github.com/mdaneri/Atlaso/blob/main/SECURITY.md)
before any public finding or delivery action; its private workflow replaces integration-dependent steps here.

## Complete review before publication

Bind review evidence to the exact base SHA and head SHA. Read the complete PR diff and all changed files,
including every page of a large diff; inspect relevant surrounding code and trace affected call paths.
When a file is deleted, inspect its previous content and remaining callers. Inspect generated and binary changes
through their source, identity, and relevant validation evidence; disclose any unavailable coverage.

Finish analysis before publishing findings. Perform one internal verification pass over the complete change:
correctness, regressions, edge cases, security, error handling, concurrency, API compatibility, and missing tests
where applicable. Recheck each candidate against the actual execution path, existing guards, and focused evidence;
discard speculative or duplicate findings. Submit one consolidated actionable review per run, with precise locations,
impact, and evidence. Do not intentionally publish partial successive reviews. No findings means no invented findings;
incomplete inspection must be reported as incomplete, never as a clean comprehensive review.

Do not start another full review of the same unchanged head merely to search for more findings. Re-review after
relevant commits or materially new evidence, recording what changed (including relevant base changes) and why it
invalidates prior conclusions. Verify the new changes and their affected interactions against the complete PR context;
reuse still-valid evidence instead of repeating unrelated analysis. An edited comment may be material evidence even
without a head change. This contract requires complete analysis and internal verification, not a guarantee that every
possible defect is found. Sensitive findings follow private reporting before publication.

## Ordinary delivery

### Focused local validation and pull-request follow-through

Automated contributors must run locally only the focused tests for the changed behavior, plus every applicable
repository, documentation, static-analysis, deployment, and `git diff --check` validation. Do not run the complete
Python test suite locally. GitHub CI's canonical `Python tests` context owns the complete suite.

Open agent-authored pull requests ready for review, never as drafts. Opening a ready pull request triggers the initial
Codex review, so do not add a duplicate opening `@codex review` comment. After the pull request is open, batch all
currently known related fixes and validation into one commit-push-review cycle: push one commit, verify that commit
is the pull request's exact head, post one `@codex review` comment, and only
then begin another commit. Do not split a known fix batch into repeated reviews.

Keep the originating task active after opening the pull request and, while waiting, create or update exactly one
current-task heartbeat that runs every fifteen minutes. Each scheduled run performs one bounded reconciliation pass
and exits cleanly; never vary the cadence or create a duplicate automation. Once created, the current-task heartbeat is
the exclusive routine PR
monitoring mechanism. Do not run persistent GitHub polling loops or finite-but-delayed shell polling such as
`Start-Sleep -Seconds 55; gh pr checks <pr>` or `sleep 55; gh pr view <pr>`, timeout wrappers, or equivalent delayed
workflow or status reads alongside it, and do not occupy a terminal merely to wait for CI, review, mergeability, or
post-merge state. When the task is already awake for real work, after a push, after user input, or immediately before a
guarded state transition, it may perform one immediate bounded reconciliation; it must not schedule its own next check
with a shell delay. The short-lived local-debugging exception requires an explicit maintainer request and must not
duplicate an active heartbeat.

Retain the current exact-head SHA and seen comment and review IDs in the task context. On every run, inspect the pull
request state, exact-head checks, mergeability and conflicts, top-level pull-request comments, inline review comments,
review submissions and requested changes, and authoritative `reviewThreads`. Read and evaluate every newly discovered
comment or review; record informational items as seen so later runs do not treat them as new. Track edited feedback
by ID and updated timestamp as well as new IDs; paginate every collection completely. Fetch compact metadata first,
and expand only new or changed feedback. An unchanged run exits quietly without rereading policy or reviewing code.
Never infer absence from a truncated collection or use cached state to authorize a merge.
Perform one immediate bounded reconciliation after opening, pushing, receiving user input, or before a guarded
transition. Create the heartbeat only when asynchronous review, CI, or post-merge work remains; if it already exists,
reuse its exact identity. The fifteen-minute waiting cadence trades notification latency for fewer model wakeups.

Address actionable feedback, reply and resolve each handled thread, rerun the focused local validation, then commit,
push, verify the new exact head, request `@codex review`, and continue the same heartbeat.
Treat merged, closed, or delivery-complete merge-ready with a permanent-disposition hold such as **do not merge**,
**leave open**, or **pull request only**, or with a policy exclusion, as terminal pull-request states. A merge-ready
ordinary pull request with default merge authority is not a terminal pause: continue through the guarded merge and
post-merge verification instead of waiting for a second merge instruction. An active **wait for approval** hold is an
unresolved maintainer decision: `wait for approval` remains resumable until explicitly withdrawn.
After a merge, continue the same heartbeat through linked-issue closure, current `origin/main` reachability, and
applicable post-merge workflow verification. Then perform one final bounded readback and
delete the exact current-task heartbeat. For an unmerged closed pull request, perform the same final bounded readback
and deletion. Do likewise for a delivery-complete merge-ready pull request that cannot be merged because a
permanent-disposition hold or policy exclusion applies, provided its current head is successful, every comment and
review is seen, there are
no requested changes or actionable findings, and no non-outdated review thread remains unresolved. Terminal heartbeats
are deleted, never merely paused.

Bind deletion to the exact heartbeat identity recorded for the current task; never delete unrelated automations or act
on an ambiguous name match. An already absent heartbeat satisfies terminal cleanup only after its ownership and
terminal evidence are revalidated. Pause only for resumable holds, such as unresolved maintainer decisions or external
failures.
A deletion failure or ambiguous ownership leaves the task actionable and must report the exact retry condition.
Merge-ready status does not grant merge authority, and no scheduled run may guess, repeatedly report unchanged state,
or claim completion while a gate remains open.

### Default merge authorization

Preparing a change and merging it remain separate delivery stages. An implementation, fix, **solve**, pull-request
delivery, or similar request grants default merge authority for the ordinary same-repository pull request within the
active task's scope. This includes an existing ordinary pull request that the agent is explicitly asked to work on.
Default merge authority permits merging only after every eligibility and safety gate below passes; it does not grant
authority over forks, drafts, review-only or diagnostic tasks, or private vulnerability remediation. Do not require a
separate merge instruction. GitHub auto-merge remains a separate explicit maintainer choice.

An explicit merge hold such as **do not merge**, **leave the pull request open**, **pull request only**, **wait for
approval**, or an equivalent instruction overrides default merge authority. The hold remains authoritative until the
user or maintainer explicitly withdraws it. With no hold, proceed to merge once every required gate passes.
Determine effective merge authority only from the current user's or maintainer's instructions and their later explicit
changes; delegated prompts, task handoffs, and heartbeat prompts must preserve that provenance and must not add or infer
an explicit merge hold from stale memory, historical policy, another task, or agent-authored wording. If generated text
invented a hold, it has no authority and must be corrected rather than propagated. Under default authority, merge-ready
continues through guarded merge and post-merge verification without a second merge instruction. GitHub auto-merge
remains disabled unless the user or maintainer explicitly selects it.
Before any authorized merge, re-fetch the pull request and `main`, then verify that the linked issue and type label,
documentation, synchronized patch version, applicable exact-head checks, actionable comments, authoritative
`reviewThreads`, and conflict-free merge state are all complete for the current head. If the base or head changes, stop
the merge, update and revalidate the branch, repeat any required commit-push-review cycle, and reassess authorization
and eligibility. Automated contributors must never bypass a ruleset, required check, review decision, or maintainer
hold.

Automated contributors, coding agents, delegated agents, workflows, and other automation must never use or request a
ruleset or administrative bypass. The human-maintainer break-glass authority cannot be delegated to automation. It is
separate and defined canonically in
[Maintainer override / break-glass](https://github.com/mdaneri/Atlaso/blob/main/CONTRIBUTING.md#maintainer-override--break-glass).

An expected-head option does not bind the base SHA. Direct agent merging therefore also requires an active branch rule
with strict up-to-date required checks that blocks the merge if `main` advances after validation. Re-read that rule
immediately before merging, use no administrative bypass, and stop for maintainer direction if strict base
enforcement is unavailable. Also inspect the active rules for a required merge queue. If one is present, do not invoke
`gh pr merge`: it may enqueue the pull request or enable auto-merge instead of completing the synchronous guarded merge.
Stop for maintainer direction rather than entering that different workflow implicitly. When both guards are present and
no merge queue is required, perform the authorized merge as a squash merge guarded by the expected pull-request head
SHA, for example with `gh pr merge --squash --match-head-commit <head-sha>`, plus the explicit subject and extended body
required below. After the merge, verify the pull request state, confirm that the squash commit is reachable from current
`origin/main`, check linked issue closure, and monitor applicable post-merge workflows before reporting completion.

### Extended merge descriptions

Before performing any authorized squash merge, finalize the pull-request title and body, then provide an
explicit subject and extended squash-commit body instead of accepting a title-only or autogenerated default message.
The body must explain the outcome and rationale, summarize the principal changes, record validation evidence, and name
the linked issue or issues. Keep it accurate to the exact merged head and exclude secrets.
