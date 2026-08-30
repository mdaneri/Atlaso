# Atlaso Agent Notes

## Mandatory Agent Startup Gate

Before planning implementation or changing repository or external state, read this file completely, then read
[CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md). Treat all
four documents as mandatory instructions. In the first progress update, confirm that the policy files were read,
classify the work as `bug`, `enhancement`, `documentation`, or security-sensitive work, and identify the linked GitHub
issue. For private vulnerability remediation, confirm that a private advisory is linked without disclosing its
identifier or finding details on public surfaces.

Repeat this gate whenever the repository, worktree, or working directory changes, or when a policy file changes. A
delegating agent must include the gate in every delegated prompt and verify completion before using delegated work. Stop
for maintainer direction if a policy is missing, conflicting, or unclear.

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

## Sol and Spark Delegation

Atlaso defines the project-scoped `spark_worker` in `.codex/agents/spark-worker.toml` with
`gpt-5.3-codex-spark` at medium reasoning effort. The primary Sol agent should delegate small, fully specified work to
that worker when doing so materially improves speed or keeps noisy exploration and validation out of the primary
context. Suitable work includes localized edits, repository searches, mechanical refactoring, isolated unit tests,
Ruff or mypy cleanup, documentation and docstrings, and narrowly scoped UI tweaks whose interaction and reference are
already decided.

Sol retains architecture and design decisions, ambiguous or difficult debugging, cross-component and integration
work, security-sensitive changes, task decomposition, review of every delegated result, final validation, and delivery.
Every delegated prompt must state the exact scope, owned files, expected result, relevant checks, and the Mandatory
Agent Startup Gate. UI prompts must also include the Mandatory UI Design Guide Gate, interaction classification, and
reused Atlaso reference. Spark must not commit, push, change GitHub state, or delegate further.

Run multiple Spark workers only for independent tasks with non-overlapping
file ownership. Sol must inspect and integrate every returned diff before
relying on it.

If Spark is unavailable, rate-limited, its usage allowance is exhausted,
or the worker cannot be started because of capacity/runtime limitations,
Sol performs the work directly. Sol does not repeatedly retry Spark after a
quota or rate-limit failure and never substitutes another model.
Report the fallback once for the current task.

## Mandatory UI Design Guide Gate

Before planning or implementing any user-interface change, read the
[Atlaso UI Design Guide](docs/contribute/ui-design-guide.md) completely, classify the interaction as
`direct-edit Tabulator`, `wizard-backed Tabulator`, `read-only Tabulator`, `non-grid settings`, or `custom/other`, and
name the reused Atlaso reference.
`custom/other` work requires explicit maintainer approval. Confirm this gate in the first progress update.

All Tabulator collections must use `window.AtlasoUiPatterns.createGrid(...)`, and every new or changed wizard must use
`window.AtlasoUiPatterns.createWizard(...)` with the generic `data-atlaso-wizard-*` DOM contract. Raw Tabulator
constructors outside the shared foundation are forbidden.

## Repository Delivery Workflow

[CONTRIBUTING.md](CONTRIBUTING.md) is canonical. Every change requires a linked GitHub issue with exactly one type
label, documentation in the same change, the next patch version, validation, and a pull request containing
`Closes #<issue>`. Never commit directly to `main`.

Agent-authored implementation work must use a dedicated clean sibling worktree on its task-owned branch. Do not make
implementation edits in the repository's primary checkout; reserve that checkout for synchronization, coordination,
and completed-task cleanup. Create or select the task worktree before applying implementation changes, and repeat the
Mandatory Agent Startup Gate there before planning or mutation. If a safe dedicated worktree cannot be established,
stop for maintainer direction instead of continuing in the primary checkout.

### Unrelated issue discoveries

Keep each pull request limited to its linked issue scope. When work reveals a reproducible or otherwise evidence-backed
actionable problem outside that scope, search open and closed issues for an existing tracking record. If none exists,
open a separate issue with exactly one appropriate type label and enough sanitized evidence for independent follow-up.
Link the new or existing issue from the active pull request or task report when useful, but do not add `Closes` unless
the active pull request actually resolves it. Do not expand the pull request to fix the unrelated issue without explicit
maintainer approval. Route suspected sensitive vulnerabilities through [SECURITY.md](SECURITY.md) instead of a public
issue.

The private vulnerability remediation workflow in [SECURITY.md](SECURITY.md) is the only exception to the public issue,
repository branch, and `Closes #<issue>` requirements. Use the draft advisory as the private tracking record, push the
fix branch only to its temporary private fork, and keep all advisory references and vulnerability details private. The
remaining documentation, version, local validation, and review requirements still apply.

Temporary private forks have no integration or status-check coverage and may not support ordinary issue, label, or
comment workflows. Record all required validation privately and locally. Never use ordinary pull-request merge controls
or `gh pr merge`; only an explicitly authorized advisory administrator may merge through the corresponding draft
advisory workflow.

For temporary-private-fork remediation, the advisory-side maintainer review and recorded local validation required by
`SECURITY.md` replace the Codex review, `@codex review`, exact-head CI/status, comment, label, and review-thread
follow-through requirements below. Do not request, wait for, or claim unavailable integrations. Run the complete Python
test suite locally when required by `SECURITY.md`; this overrides the ordinary prohibition below, and missing full-suite
evidence blocks advisory merge.

GitHub-managed version-update pull requests from `.github/dependabot.yml` are the only exception to the pre-existing
issue and per-update documentation requirements. They still require the `enhancement` and `dependencies` labels, the
normal version, CI, review, and squash-merge gates, and synchronized generated locks. See
[Detailed agent policies](docs/contribute/agent-policies.md) for the complete dependency-update contract.
Every Python lock must be generated through `python scripts/compile_requirements.py`, which excludes distributions
uploaded less than seven full days ago. Do not bypass the upload-time cutoff for direct, transitive, or security updates.

Trusted version refresh dispatches CI from protected `main` with the exact PR number, base SHA, and head SHA. Candidate
validation jobs remain read-only. Only separate no-checkout jobs may publish the canonical `Version policy`, `Repository
checks`, and `Python tests` commit statuses after revalidating the open same-repository PR and exact head/base. Preserve
the bot-only publication gate, visible run links, diagnostic names for bot-triggered `pull_request` jobs, and the active
ruleset contexts. Keep trusted dispatch and diagnostic pull-request runs in separate concurrency groups so diagnostic
work cannot cancel the trusted publisher. Never dispatch a candidate workflow revision with status-write permission.

Every workflow job that mutates `gh-pages` must use the shared `atlaso-github-pages` concurrency group with `queue: max`
and `cancel-in-progress: false`. Keep long prerequisite builds outside that job-level lock; acquire it before reading the
current Pages branch and retain it through the guarded publication push. Do not weaken existing signature, immutable
tag/release, monotonic-channel, or byte-idempotency checks when narrowing the lock scope.
Every Pages writer must also fail closed unless the shipped default `stable` manifest and signature exist in its final
tree. Appliance release and promotion workflows must re-fetch the published signed pointer and immutable release
manifest, verify the named trust key, and confirm CPython 3.14 compatibility after publication.

Use `python scripts/version.py bump` or `.\scripts\version.ps1` to increment and synchronize the current patch version.
When an explicit target is required, pass the current version or exact next patch through `--version X.Y.Z` to Python or
`-Version X.Y.Z` to PowerShell. Explicit targets cannot skip a patch or change the major or minor version. Never update
individual version sources manually.

### Focused local validation and pull-request follow-through

Automated contributors must run locally only the focused tests for the changed behavior, plus every applicable
repository, documentation, static-analysis, deployment, and `git diff --check` validation. Do not run the complete
Python test suite locally. GitHub CI's canonical `Python tests` context owns the complete suite.

Open agent-authored pull requests ready for review, never as drafts. Opening a ready pull request triggers the initial
Codex review, so do not add a duplicate opening `@codex review` comment. After the pull request is open, use one
commit-push-review cycle for every subsequent branch change: push one commit, verify that commit is the pull request's
exact head, post one `@codex review` comment, and only then begin another commit.

Keep the originating task active after opening the pull request and create or update exactly one current-task heartbeat
that runs every four minutes. Each scheduled run performs one bounded reconciliation pass and exits cleanly; never vary
the cadence or create a duplicate automation. Normal monitoring forbids persistent GitHub polling loops that combine
`gh` with `sleep`. Use them only for short-lived local debugging when continuous polling is explicitly requested.

Retain the current exact-head SHA and seen comment and review IDs in the task context. On every run, inspect the pull
request state, exact-head checks, mergeability and conflicts, top-level pull-request comments, inline review comments,
review submissions and requested changes, and authoritative `reviewThreads`. Read and evaluate every newly discovered
comment or review; record informational items as seen so later runs do not treat them as new.

Address actionable feedback, reply and resolve each handled thread, rerun the focused local validation, then commit,
push, verify the new exact head, request `@codex review`, and continue the same heartbeat.
Treat merged, closed, or merge-ready as terminal pull-request states.
After a merge, continue the same heartbeat through linked-issue closure, current `origin/main` reachability, and
applicable post-merge workflow verification. Then perform one final bounded readback and
delete the exact current-task heartbeat. For an unmerged closed pull request, perform the same final bounded readback
and deletion. Do likewise for a
delivery-complete merge-ready pull request with a successful current head, every comment and review seen, no requested
changes or actionable feedback, and no unresolved non-outdated review thread.

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
Before any authorized merge, re-fetch the pull request and `main`, then verify that the linked issue and type label,
documentation, synchronized patch version, applicable exact-head checks, actionable comments, authoritative
`reviewThreads`, and conflict-free merge state are all complete for the current head. If the base or head changes, stop
the merge, update and revalidate the branch, repeat any required commit-push-review cycle, and reassess authorization
and eligibility. Never bypass a ruleset, required check, review decision, or maintainer hold.

An expected-head option does not bind the base SHA. Direct agent merging therefore also requires an active branch rule
with strict up-to-date required checks that blocks the merge if `main` advances after validation. Re-read that rule
immediately before merging, never use an administrative bypass, and stop for maintainer direction if strict base
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

## Completed Task Cleanup

An ordinary implementation task becomes cleanup-ready only after its pull request is merged, the merge commit is
reachable from current `origin/main`, the linked issue is closed, applicable post-merge workflows are complete, and no
review, deployment, release, or maintainer activity remains. Private remediation uses `advisory_cleanup_ready` instead
of the nonexistent public-issue gate: an explicitly authorized advisory administrator must have merged the private
pull request through its draft advisory, the resulting commit must be reachable from current `origin/main`, required
advisory-side review and recorded local validation must be complete, coordinated release and disclosure activity must
be finished, and the advisory must require no further task activity. Before becoming idle, a worktree-backed
originating task must send a `cleanup-ready` handoff to a cleanup controller running from the repository's primary
checkout. The handoff must name
the repository, task identifier and current title, pull-request number, task-owned branch, absolute worktree path,
pull-request head SHA, and merge commit SHA. A handoff is evidence to revalidate, never authority to skip a gate.

The primary-checkout controller must wait until the originating task is idle and unpinned, then independently re-fetch
task, GitHub, and Git worktree state. It must verify the exact merged pull request and completed post-merge activity,
then determine remote-branch ownership and local checkout/worktree ownership independently. Require exclusive task
ownership before a destructive step or establish the external ownership required by the corresponding non-destructive
exception below. Require a closed linked issue for ordinary work or privately revalidate every
`advisory_cleanup_ready` criterion against the corresponding advisory record. Determine first whether
the task uses the repository's primary checkout and verify that identity separately. Only a non-primary target must be
a registered, clean, unlocked, non-reparse-point worktree beneath the resolved Codex worktree root. Never remove the primary
checkout, a user-created or permanent worktree, or a worktree whose ownership or state is ambiguous. A squash-merged
pull-request head need not be an ancestor of `main` only when the worktree HEAD equals the recorded pull-request head
SHA and the recorded merge commit is reachable from current `origin/main`.

Terminal order:

1. `remote_branch_absent`
2. `worktree_removed`
3. `task_title_done`

For ordinary `remote_branch_absent`, delete only the exact task-owned branch from its same-repository GitHub remote.
If the ref exists, require it to equal the pull-request head SHA and delete it with an atomic expected-SHA lease such as
`--force-with-lease=refs/heads/BRANCH:HEAD_SHA`; a lease rejection or unsupported atomic guard blocks cleanup. Then
verify the remote ref is absent.
For private remediation, satisfy `advisory_remote_branch_absent` only on private surfaces: bind the exact temporary
private fork, private pull request, branch, task, and recorded head SHA through the advisory; if the ref exists, require
it to equal that head and use the same atomic expected-SHA lease before deleting only the ref and privately verifying
absence. An already absent ref satisfies the gate only after the same private identity and merge evidence are verified.
Never delete the temporary fork, change
advisory state, or enable repository-wide automatic branch deletion. For `worktree_removed`, first verify that the exact
local task branch is absent or still equals the recorded pull-request head and is referenced only by the target
worktree. Use `git worktree remove`, prune only stale worktree metadata for the affected repository, and verify both the
path and registration are absent. Then require the local branch to be unreferenced by every registered worktree, delete
only that exact ref when present, and verify `local_task_branch_absent` before recording `worktree_removed`. A retry
interrupted after the path and registration disappeared but before local-ref deletion may enter
`worktree_removal_resume` only when the path and registration remain absent. The
worktree removal remote branch gate is either verified absent or recorded not applicable through
`non_task_owned_remote_branch_preserved`, and the same task ownership,
pull-request head, and merge evidence prove that the exact unreferenced local branch is safely deletable or already
absent.
For a task running in the primary checkout, the initial path requires a clean checkout still at the recorded task head;
fetch current `origin/main`, switch to local `main` without force, fast-forward it exactly to `origin/main`, and verify
the resulting HEAD. A retry interrupted after that switch may enter `primary_checkout_resume` only when the checkout is
clean on local `main` and a fresh fetch and non-forced fast-forward makes it equal current `origin/main`. The
primary checkout remote branch gate is either verified absent or recorded not applicable through
`non_task_owned_remote_branch_preserved`; the local task branch must still equal the recorded pull-request head while
checked out nowhere or already be absent under the same task ownership and merge evidence. Delete the exact local task
branch when it remains, record `primary_checkout_restored`, then record worktree removal as not applicable and never
remove the checkout.
For `task_title_done`, use supported task-title controls to append the exact suffix " · Done" once, preserving the
description and issue/pull-request traceability. Keep the completed task unarchived unless a maintainer separately
requests archival. Only when the runtime exposes no supported mutable task-title control,
record `task_title_done` as verified not applicable with the capability evidence; do not append or claim a visible Done
suffix, and do not block otherwise-complete cleanup on the unavailable control.

For an existing ordinary pull request, evaluate remote and local ownership separately after independently verifying the
exact merge, reachable merge commit, closed linked issue, and completed post-merge activity. When the remote branch is
non-task-owned, preserve it, record `non_task_owned_remote_branch_preserved`, and record `remote_branch_absent` as
verified not applicable; this does not exempt a task-owned local worktree from normal removal. When the local checkout
or worktree is non-task-owned, preserve it and its local refs and metadata, record
`non_task_owned_checkout_preserved`, and record `worktree_removed` as verified not applicable; this does not exempt a
task-owned remote branch from normal deletion. Apply these decisions in terminal order. Ambiguous ownership blocks the
affected transition and the Done suffix.

Any failed or ambiguous gate blocks `task_title_done`; leave the task actionable and report the exact retry condition.
The daily Codex cleanup automation is the reconciliation backstop for missed handoffs and partially completed terminal
transitions, but it must apply the same checks and ordering. Private vulnerability remediation additionally follows
`SECURITY.md`: keep titles, handoffs, controller output, advisory identity, and temporary-fork remote operations
sanitized and private; block rather than expose or guess when private state cannot be verified; and do not treat an
advisory merge as lifecycle completion while coordinated release, disclosure, or authorized advisory-state work remains.

## Documentation and branding

Markdown is the canonical documentation source. Follow the
[documentation authoring guide](docs/contribute/documentation-authoring.md), keep `npm run lint:markdown` clean, and
update affected pages and media manifests whenever behavior or UI changes. Follow the
[Atlaso Brand Kit](docs/assets/brand/BRAND_GUIDE.md) for documentation, screenshots, video, and promotional claims.

Every new or changed PowerShell script or module must provide comment-based help at file/module scope and for every
function, including nested helpers. Include a concise `.SYNOPSIS`, document every declared parameter with `.PARAMETER`,
and keep exactly one canonical help block per script, module, or function; never stack a generated help block beside the
purpose-specific block. Add rationale comments for non-obvious safety ordering, trust boundaries, and platform
behavior. Run
`scripts/check_powershell_help.ps1` against the base checkout; the incremental gate requires complete compliance for
each touched PowerShell file without forcing unrelated legacy rewrites. Install PSScriptAnalyzer `1.25.0` and run
`scripts/check_powershell_analysis.ps1`; every tracked PowerShell source must pass the repository profile. Real password
parameters must use `SecureString` or `PSCredential`, declare no default, and never use a broad
`PSAvoidUsingPlainTextForPassword` suppression.

Every new or changed `/api/v1` operation must follow the
[API authoring standard](docs/contribute/api-authoring.md), including operation, authorization, parameter,
schema-property, response, compatibility, enforcement-test, and topic-documentation requirements. Keep supported
non-`/api/v1` browser and protocol routes out of OpenAPI and documented in their canonical guides.
Route ownership and staged domain extraction must also follow the
[router architecture](docs/contribute/router-architecture.md): retain the stable UI/API facades, deterministic
registries, dependency direction, exact route inventory, and normalized OpenAPI contract.
Physical-interface and VLAN transport handlers and tests belong to their domain router modules; keep facade imports
compatible. Physical-interface transports must delegate typed desired-state changes to the domain service, which owns
the interface, dependent-row, and audit transaction; retain the lower-level reconciliation helper only as a documented
compatibility seam for callers that already own a wider transaction.

## Canonical implementation policies

Read [Detailed agent policies](docs/contribute/agent-policies.md) before appliance, UI, networking, service, image,
deployment, or live-VM work. Its subsystem contracts remain mandatory. Use the documentation index to locate the closest
current operator or contributor guide before making a change.

The following cross-cutting boundaries always apply:

- Canonical human browser surfaces belong to `/ui/management` or `/ui/public`; `/` is only the requested-interface
  dispatcher. Keep API, OpenAPI, OIDC, CA-download, PXE, `/PROD/`, registry, static, and other machine/protocol routes at
  their stable paths. A URL prefix never replaces listener, authentication, authorization, CSRF, or session enforcement.
  Resolve management requested-interface eligibility from the last-applied Network binding plus observed addresses,
  never from unapplied desired role, address, or exposure edits. Reject a desired-state mutation that removes the final
  complete management candidate, while admitting a complete explicit access-management replacement to the protected
  management handoff. Keep `/ui/public` independently governed throughout pending, failed, and reverted edits.
  Safe legacy `GET`/`HEAD` bookmarks may redirect only after destination eligibility is proven; bridge legacy mutations
  internally and never replay them through `307`/`308`. Route-inventory coverage must fail for an undeclared human UI
  route. Scope management browser caching to `/ui/management/` and keep public UI caching disabled.
- Authenticated primary navigation renders only non-empty groups after server-side permission filtering. Each group is
  an accessible disclosure with a native button, accurate `aria-expanded` and `aria-controls`, and a visible chevron.
  First use starts every authorized group expanded; browser-local state restores inactive-group choices, while the
  current page's group always opens without overwriting its saved choice. One compact two-state symbol control expands or
  collapses only the rendered groups, uses `<<` to collapse and `>>` to expand, and updates its accessible name and
  tooltip to describe its next action. It persists through the same per-group state. Keep the global
  **Review appliance changes** card outside the disclosures
  and preserve coherent groups at desktop, two-column narrow, and single-column mobile widths.
- `/ui/management/appliance-apply` is the only ordinary desired-state host-mutation workflow. The dedicated confirmed
  factory-reset transaction is the sole exception: it preflights and activates every factory apply unit, atomically
  replaces the database, records durable recovery state, invalidates sessions, and must finish with zero pending units.
- A management address, gateway, role, interface, VLAN, management VLAN MTU, or flagged-access listener change must
  use one recoverable
  handoff across Certificate Authority, Network, Firewall, Appliance Settings, and Public Services. Submitting any one
  of those dependent units while such a Network change is pending must force all five into the handoff. Evaluate this
  after every cross-unit dependency expands so an indirectly selected protected unit cannot bypass it. Keep the previous
  known-good configured and observed global addresses, public port, protocol, and snapshotted TLS identity active until
  consecutive bounded Atlaso loopback,
  candidate nginx, and host-facing `/openapi.json` checks pass. Never expose a candidate nginx front door before its
  Atlaso upstream is healthy. Validate management and Public Services TLS references against the bundled Certificate
  Authority payload before relying on deployed files. Move the persistent and runtime management resolver to the
  candidate interface inside the transaction, persist its directives in the effective dedicated or flagged-access
  networkd file both before readiness and after the final Network regeneration, and restore the
  previous resolver state with the network snapshot on rollback. On success, include the applied resolver mode,
  servers, and local-DNS state in the Appliance Settings baseline completion so those executed changes do not remain
  falsely pending. Persist every static dedicated-management connected prefix as an on-link route in table `100`
  beside its source rule and default route; an address and working outbound gateway do not prove that same-subnet
  host-facing replies will survive reboot. Derive loopback/local-DNS resolver mode only from the
  last-applied DNS/DHCP baseline; leave an unapplied DNS enablement pending instead of activating loopback early. When
  disabling applied local DNS, force Appliance Settings ahead of DNS/DHCP so the resolver leaves loopback before the
  listener stops. Retire the old path only
  after readiness succeeds; retain the durable rollback marker until Atlaso commits the bundled task state and baselines
  and explicitly acknowledges that commit. Record separate durable application-commit proof before selecting
  acknowledgement during startup; an incomplete pre-commit rollback must retry recovery instead. A matching durable
  commit receipt must retry rollback-marker and backup cleanup before acknowledgement succeeds. Sync every backup file
  and its backup directory before publishing the marker. Sync every final candidate runtime file and affected directory
  before entering the application-commit phase. Retain the global apply lock while recovery or acknowledgement
  is pending, including when startup cannot prove either outcome from a legacy or incomplete task payload. A pending
  task plus explicit successful no-transaction recovery proves the privileged handoff never began and releases the
  lock. On failure,
  timeout, indeterminate helper return, interruption, or startup recovery, first stop and verify any surviving
  fixed-identity apply helper; serialize every retry under a separate fixed-identity recovery unit and stop and verify
  any surviving recovery unit before starting another. Then restore every captured runtime
  file and link, durably sync every restored file and affected parent directory before clearing rollback state,
  reconfigure pre-existing candidate links, remove candidate-only VLANs, fail closed without host
  mutation when an active appliance has no known-good Network baseline, restore a previously absent firewall by
  disabling its candidate service and flushing the candidate ruleset, keep the old path reachable, and record a
  truthful non-secret failing layer. Probe old and candidate listeners on their configured public ports. Require every
  dynamic candidate listener to acquire and probe each requested DHCP
  or SLAAC address family before retirement. Preserve the previous firewall policy plus minimal candidate admission when
  firewall state changes in either direction; include the configured management public port in both transitional and
  final filtered rulesets without dropping the candidate rule's source predicates, and apply the enabled or disabled
  candidate ruleset only after readiness. Commit
  baselines only from the exact staged snapshots, and leave desired-state edits made during readiness pending. A
  flagged-access candidate must remove a stale dedicated `00-atlaso-mgmt.network` file when that file is not part of the
  candidate configuration. Retain a flagged-management VLAN's trunk parent for link rollback without treating the
  parent's addresses as management listeners or readiness targets.
- Every effective management listener admits ordinary bootstrap-administrator SSH on TCP/22 as well as the management
  HTTP/HTTPS ports. This includes flagged access physical interfaces and VLANs, with the same Source Group predicate in
  desired previews and old/candidate/final handoff rules. Never infer root SSH enablement from firewall admission, and
  never open TCP/22 merely because an unflagged access network exists.
- Physical-interface desired-state updates from the API and UI use one atomic domain service. Capture the previous
  IPv4 and IPv6 CIDRs before mutation, refresh dependent service, ESX Storage, Web Terminal, DHCP, and Network Boot
  bindings before one commit, include child VLAN dependencies when their parent becomes unavailable, roll back every
  row when reconciliation fails, rebase reservations and their app-owned DNS records only when one updated DHCP scope
  is unambiguous, ignore inactive legacy DHCP binding fields when real scopes exist, and audit the dependent units that
  changed.
- When a static physical interface changes from management to access, capture valid IPv4 and IPv6 gateways before
  clearing the management-only fields and stage enabled canonical family defaults on the converted target in the same
  transaction. Reuse an equivalent route, reject a conflicting family default with complete rollback, never invent a
  missing gateway, mark and audit Network, Routes & WAN Simulation, and Appliance Settings, and keep host mutation in
  the protected handoff. If the migrated route is absent from the applied WAN baseline, select WAN into that handoff,
  validate candidate and rollback configs, and restore prior WAN runtime before old-path recovery succeeds.
- Converting the dedicated management interface from DHCP to static must discover a usable DHCP-protocol IPv4 default
  route on that exact interface, review its observed address/prefix and on-link gateway together, and preserve the
  gateway in desired state. An absent or intentionally cleared gateway must warn that off-subnet connectivity will be
  unavailable; shared gateway validation, global Apply, baseline commit, and rollback remain authoritative.
- Keep **Static Routes** separate from **Routing Permissions** in operator language. Static Routes choose destination,
  gateway, target interface/VLAN, and metric in the lab route table; Routing Permissions authorize forwarding between
  interface/VLAN networks, with route-role paths generated automatically and Access networks requiring explicit rules.
  The Static Route wizard must make **Default route** mutually exclusive with **Destination CIDR**, require an explicit
  IPv4 or IPv6 family plus a same-family next-hop gateway for defaults, persist canonical `0.0.0.0/0` or `::/0`, and
  allow only one default per family. Destination-specific routes keep a required CIDR and optional gateway for directly
  connected paths; API callers may continue to submit canonical `/0` CIDRs.
  Static Routes, Routing Permissions, NAT Rules, and WAN Policies are wizard-backed Tabulator collections. Add launches
  from the bottom row; edit launches from row double-click or the context menu; generated routing permissions remain
  read-only; and ordinary persisted **Enabled** state remains directly editable without host mutation.
- Network Objects Source Groups use a full-height compact wizard-backed Tabulator. The add-row native button opens on
  one click or native keyboard activation, while row double-click remains edit-only. The Entries step exposes an
  exclusive **Any source** switch that persists canonical `entries: ["any"]`; explicit addresses, CIDRs, and stable
  nested-group references use the shared tag editor with server-owned per-entry validation, non-color status text,
  canonical submission, and a truthful line-separated textarea fallback. Keep built-in **Any** read-only.
- Physical and VLAN interfaces share exactly `management`, `access`, `route`, and `unused` roles. Reject retired or
  unknown values on new UI, API, desired-state, and helper inputs. Upgrade and settings-archive compatibility may map
  only retired `services` and `storage` values to `access` while preserving every other interface field.
- Keep ordinary `/ui/management/appliance-apply/status` polling on the non-reconciling desired-state projection.
  Prevent overlapping browser polls, suspend them while hidden, back off when idle, and refresh promptly after successful
  mutations and Apply completion. Retain the tracked master task until a valid terminal task response is rendered, retry
  transient status and terminal-reconciliation failures at the active cadence, and never let an older active response
  replace a terminal result. Current real Appliance Settings apply must prove the desired Atlaso loopback upstream before
  publishing nginx, reload nginx without restarting the active Atlaso worker, require consecutive guest-local front-door
  readiness, and restore the previous nginx/systemd files on activation or readiness failure. Retain bounded reconnect
  handling only for server-marked legacy task records; unexpected or out-of-window failures must show the observable
  availability warning. Reconcile a retained task and run its completion refresh before accepting a different session's
  newer active task. Full review, validation, and submission must still reconcile current host observations.
- Privileged appliance operations go through `atlaso-helper` and constrained sudoers rules.
- VCF Offline Depot settings and download-profile applies preserve the registered VCFDT software depot ID. Generate an
  ID only when none exists or an administrator explicitly confirms **Refresh software depot ID** through global apply;
  preserve the old ID when generation itself fails, but invalidate it if generation succeeds and canonical readback
  fails because VCFDT may already have replaced its runtime identity. Once generation succeeds, remove both staged and
  runtime Broadcom credentials because neither remains valid for the replacement identity. Keep Broadcom credential replacement,
  application properties, Software Depot ID review, and the explicit refresh handoff in the shared VCFDT configuration
  wizard; its ordinary transactional save never refreshes an existing ID. Stage VCFDT package add/update through its
  shared two-step package wizard. Resetting VCFDT staging always clears the package, credentials, application properties,
  generated metadata, and profile enablement together.
- VCF Offline Depot download admission deduplicates the same profile atomically while allowing distinct profiles to
  queue in FIFO order. Exactly one VCFDT operation may execute at a time. Software Depot ID replacement and Appliance
  Apply containing VCF Offline Depot remain exclusive across the entire queued/running download set and may start only
  after it drains. Revalidate mutable prerequisites when each queued download is claimed. Manual Start feedback uses the
  shared accessible transient grid status/error pattern. The selected profile's Schedule action opens the shared
  four-step contextual Automation wizard (Schedule, Timing, State, Review) in place with task type and profile bound
  server-side; preserve Automation's generic five-step wizard.
- Keep development system adapters in dry-run mode unless a reviewed apply unit explicitly promotes real mutation.
- VMware Workstation is the canonical image-build and live appliance target. Treat Hyper-V, KVM, and Proxmox VE only as
  portable artifacts exported from the validated VMware template; do not add provider-specific appliance build or
  lifecycle stacks. Preserve the documented two-NIC, four-SCSI-disk import contract and validate target compatibility
  without presenting it as canonical lifecycle evidence.
- VMware Workstation recursive cleanup is authoritative only for an exact non-reparse-point Atlaso artifact root
  containing every expected VMX. Test-VM redeploy fails closed when its named VMX is missing or has another display
  name, and data-disk reset accepts only strict path-component descendants of that VM output. Capture immutable root,
  descendant, and target identities before provider operations; a new or replaced entry or root blocks recursive
  deletion. Use checked `vmrun` running output to stop an exact target, matching filesystem aliases by identity, and
  verify it is inactive. Current Workstation automation has no unregister-only operation, so use checked
  `vmrun deleteVM` only for a well-formed exact in-scope registration and verify that the VMX is absent. Immediately
  before each provider deletion, repeat the target identity and identity-aware running check, confirm the exact scoped
  registration, and verify the recursive VMX set still contains only validated targets.
  Before `deleteVM`, detach every VMDK device whose resolved path is outside the exact removal root so provider deletion
  cannot erase a reused depot, backup, or other shared disk. Replace the detached VMX atomically while retaining its
  displaced backup. Restore that backup only when the protected identity and content still match; preserve a concurrent
  replacement and an actionable recovery copy instead of overwriting either.
  Do not require global `inventory.vmls` consistency for normal Atlaso cleanup. Unrelated stale, malformed, missing,
  duplicate, or inconsistent Workstation library entries must not block an exact Atlaso root. Reserve inventory mutation
  for a well-formed Atlaso-scoped registration whose VMX is already missing. With the Workstation UI closed, validate
  that each selected `vmlistN` ID owns exactly one config path, recheck the scoped VMX remains absent, and hold a
  write-excluding handle from the final byte comparison through atomic replacement and rollback. Remove only the
  selected library and matching index records; leave unrelated registrations in place and do not require them to
  resolve. Preflight failures preserve all artifacts; provider deletion, postcondition, rollback, or recursive-removal
  failures preserve the remaining artifacts and return failure. When checked `deleteVM` legitimately removes the
  complete validated artifact root, keep scoped registration and running-state verification, require the exact root to
  remain absent through the final gates, and let the initiating redeploy continue without a second filesystem deletion.
- VLAN Interfaces use the shared wizard-backed Tabulator with the ESX Storage interaction. Keep every persisted field,
  including Admin Up, out of inline editing and review the complete VLAN record in the add/edit wizard. New VLANs
  default to Admin Up; edits preserve saved state; a missing-parent VLAN may remain saved only while disabled. Saving
  changes desired state only, and global Appliance Apply owns host enforcement.
- VMware OVF first boot and the Atlaso tty1 console share one management-network validation contract. Reject off-link,
  equal-address, incomplete, and malformed gateway relationships before host mutation. Start the console independently
  of management networking and before data-disk initialization; on validation failure, show a recoverable non-secret
  network-review state, retain deployment secrets only in the waiting customizer, and keep privileged tty1 actions
  locked until the deployment root password applies. Validate non-network OVF fields before offering network-only
  correction, keep the waiting customizer alive across post-validation apply failures, make review cleanup recover from
  interruption after marker creation, and write applied state only after successful correction and customization.
  Preserve whether VMware Tools answered: after 30 consecutive answered-empty reads, classify the boot as non-OVF,
  record durable image-default completion, clear the initialization/review handshake, and unlock the ordinary console.
  Never classify unanswered, malformed, present-but-incomplete, or invalid properties as non-OVF, and allow a later
  real envelope to replace the non-OVF marker and enter the full validation/customization path. Clear consumed
  `guestinfo.ovfEnv` with an explicit empty value. Once pending success is durable, retry credential scrub and marker
  promotion directly with the review handshake cleared; never route finalization failure back to network correction.
- VCF Helper VCF Installer imports use the destination `OvfManager.ParseDescriptor` contract and a complete reviewed
  property mapping. Direct standalone ESXi imports bind deterministically to the endpoint's single host. Before power-on
  or DNS, trust, and depot follow-up, verify that the exact imported VM retained every mapped vApp property and a
  supported OVF environment transport; remove only that task-created VM if verification fails, and report cleanup
  failure as a partial deployment. Sanitize parser and import warnings against all submitted property values.
- VMware release images use separate compacted Photon OS and required Atlaso system-content payload VMDKs, followed by
  empty 500 GiB depot and backup disks. Preserve `/opt/atlaso` and appliance-wide PowerShell modules on the UUID-mounted
  system-content disk, size-gate individual OVF release assets below 2 GiB, and publish the aggregate OVA only when it
  independently fits that limit. OVF export may recursively replace only a strict, non-reparse-point descendant of the
  repository OVF output root. `-Release` and `-Prerelease` provide implicit replacement only for the canonical derived
  destination; an explicitly supplied existing destination still requires `-Force`, which never widens the approved
  deletion boundary. Low-level OVF export never changes GitHub. Manual virtualization orchestration through
  `-Prerelease` may create only the exact annotated `virtualization-vX.Y.Z-rc.N` tag and hidden draft after both Windows
  smokes pass; it never publishes or reclassifies that draft. Only the protected hosted finalizer may sign, attest, and
  publish the prerelease.
- The maintainer workstation and any explicitly approved ephemeral Windows alternative are trusted virtualization
  producers while building a release. They receive no signing key, and the protected hosted finalizer independently
  verifies software-source binding, selected privileged assets, provenance, exact virtualization bytes, and publication
  state as defense in depth; it is not a reproducible Photon image builder and does not claim to authenticate the entire
  root filesystem against a compromised producer. Keep public-repository Windows runners offline except for the approved
  release, bind them to one release-specific label, and destroy or sanitize them immediately afterward.
- First-boot depot and backup initialization requires the root-owned image policy, exact platform SCSI identities,
  topology-derived `atlaso-path-*` links, and exact 500 GiB capacities. Complete an all-disk preflight before `mkfs` and
  fail closed for missing, extra, reordered, ambiguous, read-only, in-use, or identity/capacity-mismatched disks.
  Resolve the root filesystem through its complete block-device dependency chain, require exactly one physical backing
  disk, and exclude only that resolved disk from the candidate set; mapper path layout must never fabricate a disk path.
  Existing correctly labeled ext4 disks remain UUID-mounted and must never be reformatted. After both fixed disks are
  initialized, admit additional disks only when they satisfy the root-owned managed ESX Storage identity, UUID, mount,
  and fstab contract. Atlaso-formatted disks retain their `lf-<hash>` label; claimed existing ext4 disks additionally
  require an exact root-owned allowlist record. Make data-disk success a hard systemd requirement for nginx, the HTTPS
  bootstrap, control plane, and worker so a failed preflight cannot fall through to root-filesystem-backed mount paths.
- Every successful same-repository `main` push CI run automatically publishes the 90-day Actions artifact
  `atlaso-wheel-vX.Y.Z-<full-sha>` from GitHub-hosted Linux. Bind its single versioned wheel to canonical source-CI,
  publisher-run IDs and attempts, repository, version, full-commit, UTC build-time, size, and SHA-256 identity. Manual
  consumption must query and verify each recorded GitHub run attempt. Give the automatic path read-only
  repository authority and no signing key, protected environment, tag/Release or Pages write, channel promotion,
  self-hosted label, or virtualization access. A successful automatic-main wheel handoff then starts the separately
  protected **Publish appliance release** workflow, which consumes and records the exact wheel without rebuilding or
  substituting it, publishes the signed `vX.Y.Z` software bundle, and advances `development` while retaining all
  CPython 3.14 wheelhouse, signing, immutable publication, Pages, and live-verification gates. Manual exact-SHA dispatch
  remains the recovery entry point. Authenticate the existing `development` pointer under the shared Pages lock and
  refuse to replace it with an older semantic version. Byte-identical automatic
  retries are valid, but the consumer must stage them by publisher run plus artifact ID, validate every recorded attempt,
  and preserve the earliest retained publisher run-and-attempt identity so a later retry cannot change signed bundle
  inputs. Divergent collisions fail closed. For an expired handoff, allow only the protected **Replay Python wheel**
  manual admission workflow from `main` with the exact commit plus successful source CI run ID and attempt. It must
  revalidate that attempt and current-`main` reachability without checkout or target-code execution, then publish only
  one canonical one-day replay-request artifact. **Publish Python wheel** may consume that request only through its
  completed `workflow_run`, revalidate the request and source CI evidence, and build inside the same read-only
  wheel-only trust boundary. When an immutable software Release already exists, recovery must verify and reuse its
  signed assets, and require the replayed application wheel bytes to match the wheel inside that bundle; never rebuild
  the Release with the replay publisher identity.
- Inventory Linux is an independently versioned Atlaso release package; full images leave it uninstalled so an
  administrator downloads a signed release on demand. Supported VMware wheel deployment synchronizes it unless
  explicitly skipped. Publish it only through the protected manual Inventory
  Linux release workflow for an exact successful `main` CI SHA. Every workflow build is a final immutable
  `inventory-linux-v<version>` release and signed Pages pointer; never attach it to an appliance release or introduce
  development, preview, or staging channels.
- VMware wheel deployment validates `RemoteDirectory` before build or upload as an absolute POSIX path containing only
  ASCII letters, digits, `/`, `.`, `_`, and `-`, with no `.` or `..` components. Keep key/agent authentication and the
  supported Windows 1Password SDK password bridge on this shared path contract, and serialize every key-backed
  remote shell argument explicitly. The bridge must bind the exact verified `Atlaso` Environment's concealed
  `DEFAULT_ADMIN_PASSWORD` variable only inside the bounded deployment child, bound desktop authorization and
  Environment retrieval to the deployment timeout, stage its complete runtime from the generated seven-day
  hash-verified deployment lock with an explicit SDK-supported CPython 3.10 through 3.13 interpreter, install it with
  index access disabled, preserve known-host verification, and fail
  closed for missing SDK support, desktop authorization, Environment, variable, masking, or redaction. Never use a
  password argument,
  local `.env`, caller-provided `DEFAULT_ADMIN_PASSWORD`, or the retired `ATLASO_DEPLOY_SSH_PASSWORD` fallback.
- Every task-owned VMware test VM used for pull-request validation derives its identity from the exact positive
  pull-request number through `Atlaso-PR-<number>-<purpose>[-<collision-safe-suffix>]`. Sanitize the short purpose and
  optional suffix through the shared VMware identity helper. Keep the VMware `displayName`, canonical output or
  lifecycle-lab directory, VMX filename where applicable, result/log identity, and reported absolute VMX evidence
  consistent with that name. Use a collision-safe suffix for multiple VMs owned by one pull request without removing
  the `PR-<number>` segment. Before reuse, redeploy, or cleanup, require the expected canonical name, exact VMX path,
  matching `displayName`, and lifecycle ownership manifest; any mismatch fails before mutation. Never automatically
  rename, reuse, redeploy, or delete a generic, issue-only, or differently owned VM. Atlaso does not support a
  provisional shared/live VM path: wait for the pull-request number, and collect acceptance evidence only from the
  resulting PR-numbered VM.
- The normal `create-atlaso-test-vm.ps1` Workstation wrapper provisions an existing Ed25519 public key for the bootstrap
  administrator and a separate test-only passwordless-sudo drop-in by default. Resolve the default only from the current
  Windows user's `.ssh/id_ed25519.pub`, permit an explicit public-key path or explicit skip, and fail before cleanup or
  creation for missing, malformed, non-Ed25519, multiline, or conflicting input. Never generate, copy, or expose a
  private key. When that test-only property is present, publish only the VM's public Ed25519 SSH host key through a
  separate VMware guest-info value. Read, wire-validate, and fingerprint that host-derived value before displaying it
  for explicit `known_hosts` verification; never substitute unauthenticated `ssh-keyscan` output.
  For each omitted `-AdminPassword` or `-RootPassword`, retrieve only the corresponding exact concealed
  `DEFAULT_ADMIN_PASSWORD` or `DEFAULT_ROOT_PASSWORD` from that same verified Environment through the supported bounded
  Windows 1Password SDK pattern. Each explicit `SecureString` remains authoritative for its credential. Keep plaintext
  out of the PowerShell parent, arguments, caller-controlled environment, logs, output, markers, evidence,
  documentation, and GitHub surfaces; use current-user DPAPI between bounded children. Reject caller environment
  fallbacks, repository defaults, local `.env` files, and interactive password prompts. Credential failure must precede
  network preparation, cleanup, disk reset, and cloning, while `-WhatIf` remains credential-free.
  The VMware Photon image wrapper reuses this exact pinned Environment selector and bounded SDK/DPAPI foundation for
  omitted `-SshPassword` and `-BootstrapAdminPassword`, mapped respectively to concealed `DEFAULT_ROOT_PASSWORD` and
  `DEFAULT_ADMIN_PASSWORD`. Explicit `SecureString` values remain independently authoritative. Complete credential
  preflight and task-owned bridge cleanup before network discovery or preparation, output cleanup, ISO remastering,
  Packer initialization, or other image mutation; retain exact-byte validation and all sensitive ISO/Packer-variable
  cleanup. Run the complete plaintext-consuming image workflow in a separately bounded PowerShell child; the parent
  may pass only current-user DPAPI ciphertext. Place every plaintext kickstart, remastered ISO, and Packer variable
  artifact inside the exact task-owned child root, and require the parent to remove and verify that root after ordinary
  exit or whole-tree termination so a killed child cannot bypass sensitive cleanup. If whole-tree termination is
  unproven, retain the exact root plus a non-secret cleanup marker, block same-boot reuse, and permit exact-root cleanup
  only after a changed Windows boot identity proves the prior tree inactive; remove the marker only after root absence
  is verified. Apply the same boot-bound recovery ownership to the shared SDK credential bridge. Durably publish each
  marker with write-through file and rename semantics before starting a child that can consume plaintext, then durably
  transition through root absence and a non-actionable retired tombstone before deleting the marker.
  The wrapper also owns the sole development-root exception to per-appliance CA generation: require the exact `Atlaso`
  1Password Environment's concealed `ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY`, validate it against the checked-in public
  `Atlaso Development Root CA` before mutation, pin and verify the exact Environment ID by SHA-256 before invoking `op`,
  bound and whole-tree-terminate every `op`/secret-child invocation and every post-staging VMware operation, and pass
  the signer only through a separately
  scrubbed normal-wrapper guest-info value. First boot must stage it mode `0600`, prove guest-info scrub, encrypt it with
  the VM-unique secrets key, remove staging even when encrypted import fails, and issue a unique HTTPS leaf. Commit a
  durable non-secret cleanup marker through a Windows write-through atomic rename before staging. Bind it to a
  non-secret VMX identity that survives VMware's legitimate power-on file replacement. Expose its marker path to
  rollback only after durable publication succeeds. A pre-publication failure before any
  secret child starts must preserve the original actionable error and remove only invocation-owned artifacts. Before
  launching rollback removal, durably bind the exact stopped VMX identity, quarantine path, and boot-bound child phase;
  first reconcile any exact identity-bound destination left by a completed rename whose caller reference was not
  published. If reconciliation is ambiguous or fallback publication fails, preserve the VM artifacts and do not start
  a removal child. Actual child-active or unproven state remains fail-closed across same-boot reruns.
  After encrypted import proof,
  stop the exact VM, prove the powered-off VMX signer assignment absent, restart it, and prove runtime guest-info remains
  empty before retiring the marker. Later normal-wrapper invocations must retry its exact identity-bound stop, VMX
  scrub, artifact removal, and data-disk restoration before
  1Password preflight or any new mutation. Persist
  boot-bound child-active phases before staging, VM start, and artifact removal. An unproven child-tree termination must
  preserve the VM and VMX, or keep reused disks quarantined during removal, until a Windows host restart makes cleanup
  safe. Persist the stopped/scrubbed phase before artifact removal so a retry can resume restoration from an absent
  artifact root. Before persisting rollback state, reject configured data disks that repeat the same descriptor,
  hard-linked alias, or shared extent by filesystem identity. Before deleting a completed marker, write-through
  transition it to a non-actionable tombstone so a
  post-crash directory-entry resurrection cannot trigger cleanup of a successful VM.
  Default waiting must verify the
  exact
  checked-in fingerprint; Windows trust
  remains explicit and idempotent. Reject `-NoStart`, preserve root SSH as disabled, and do not extend either development
  authority to lifecycle VMs, Hyper-V, reusable images, or exported OVF/OVA deployments. Rotate the repository PEM and
  concealed Environment key together after compromise of any in-scope test VM.
  Before reporting a started clone ready or printing connection endpoints, bind VMware Tools' management IPv4 result to
  the exact running VMX, its `ethernet0` MAC, the injected hostname, and a Windows neighbor entry for that MAC. Compare
  the address with every running Workstation VM and fail closed with the conflicting VMX, MAC, and address when another
  guest reports it or the host-facing neighbor maps elsewhere. Never continue SSH or HTTPS validation through an
  ambiguous address and never modify the user's SSH `known_hosts` automatically during recovery.
- Inventory Linux reports use bounded schema v2 while accepting and normalizing legacy v1. Keep sysfs authoritative for
  device enumeration, use metadata tools only for structured enrichment/readable names, retain JSON in the existing
  report column, enforce the 256 KiB boundary, and never submit raw command output. Its five-minute local console
  countdown starts only after successful submission; pause/resume must preserve
  the remaining time and audited remote reboot remains authoritative.
- Render inventory reports as escaped semantic sections with explicit legacy
  not-reported states. Wake-on-LAN uses the server-owned discovered/reference
  MAC, deduplicated effective IPv4 Network Boot broadcasts, one audited UDP/9
  send with no retries, and no claim that the host powered on. Keep discovered
  hosts live-refreshed while visible, expose ESXi assignment details by
  normalized reported MAC, and use the shared grid/wizard foundations for Host
  Reference variables and ESX installer ISO intake. Never delete an assigned
  discovered host directly: remove its ESXi Host Reference first, retaining the
  discovery record by default and removing its commands, sessions, reports,
  and host row only through the explicit associated-discovery option. Keep
  Host Reference association IDs synchronized during live discovery refresh,
  and reject associated-discovery cleanup while another Host Reference still
  owns any reported MAC for that discovery. Serialize every Host Reference
  write, settings-archive restore, and factory reset with inventory report
  mutation, direct discovery deletion, associated-discovery cleanup, and
  automatic capacity pruning so every assignment snapshot remains valid
  through commit.
  Protect assigned discoveries and
  all of their retained reports from automatic capacity pruning; reject new
  report admission as retryable when live or assigned state alone fills either
  global storage limit. Expose the same retain-or-clean-up lifecycle through
  the scoped `/api/v1` Host Reference deletion operation.
- Windows Inventory Linux and Photon builds select the dedicated `Atlaso-Build` WSL distribution by default. WSL is a
  pre-existing host prerequisite: ordinary builds must never install or configure WSL, create a missing distribution,
  change the default distribution, elevate, reboot, or remove a distribution. Keep the pinned setup contract, explicit
  distribution selection, native-Linux cache, Linux-only child `PATH`, per-repository `flock`, and checkout-wide output
  serialization described in the canonical contributor guide.
- Image download caches accept only checksum-verified payloads. Validate existing entries before reuse, remove only the
  exact expected corrupt payload and checksum metadata, download into unique same-directory partial files, and promote
  them only after pinned verification. Failed or interrupted downloads must not become accepted durable cache entries,
  and an ordinary rerun must recover without a force flag or manual cache surgery.
- Treat Packer HCL, systemd units/manager drop-ins, and sudoers fragments as protected deployment assets. Keep them in
  the checked-in inventory, run `scripts/check_deployment_assets.py` through pre-commit where native tools are
  available, pin every required Packer plugin to one reviewed exact version, and run `packer init` plus
  `scripts/check_packer_plugins.py` before either supported wrapper validates or builds. Canonical CI must perform the
  same exact-resolution check before full Packer validation and require native Linux systemd/sudoers validation. Pass
  the read-only GitHub Actions token to Packer only through `PACKER_GITHUB_API_TOKEN` on the canonical validation step
  for protected events and same-repository pull requests. Keep fork validation tokenless, checkout credentials
  unpersisted, and token material out of output, files, caches, and artifacts.
- Default VMware Workstation GUI image builds must start or reuse a responsive Workstation UI in a process separate from
  Packer before the synchronous `vmrun` start transition. Bind bounded sanitized startup diagnostics to the expected
  VMX filesystem identity, provider inventory, exact running state, and configured builder TCP/22 endpoint until SSH
  provisioning begins. Remove raw Packer debug-log environment variables from the monitored child because they bypass
  redaction. On timeout, terminate only the Packer process tree and honor `-PackerOnError cleanup` through the checked
  exact-root cleanup; preserve exact artifacts for other failure selections. Never print connection credentials or VMX
  contents, and do not mask a start-handoff failure with an arbitrary delay.
- Before any canonical VMware Photon builder starts, atomically reserve one temporary static IPv4 address from the
  configured per-host pool. Parse the selected vmnet's exact `vmnetdhcp.conf` subnet, reject a pool or explicit address
  that overlaps a VMware DHCP range or fixed address, and exclude observed non-ICMP use. Serialize the durable ledger
  across Atlaso worktrees, bind each entry to the exact task worktree, source commit, branch, owner process, Windows
  boot identity, output root, VM name, and VMX path, and retain it while that exact VM remains active or recovery
  evidence is ambiguous. A dead owner cannot release its reservation during the same Windows boot because a surviving
  descendant could still start the VM. Permit stale recovery only after a changed host-boot identity proves that tree
  gone and the exact VM and address are inactive. Release normally only after inactive-VM completion. The completed
  appliance still uses management DHCP by default.
- Validate live appliance readiness through `/openapi.json`, not VMware Tools IP discovery or service color alone.
- A successful tty1 management-network correction must explicitly apply Network and Firewall from the corrected state,
  retry unfinished first-boot HTTPS before applying Appliance Settings, validate nginx before reload, ensure nginx and
  Atlaso are enabled/running, and require stable loopback readiness matching the applied HTTP-only or HTTPS management
  mode before the console reports success. Keep this recovery idempotent and preserve an actionable failing-layer
  message.
- Keep configured Appliance Update source tabs read-only. Create and edit Photon, PowerShell, and signed Atlaso sources
  through the shared reviewed source wizard, with **Edit repository** beside the destructive action. Wizard submission
  saves desired runtime-maintenance state only; package-client changes still require the explicit audited
  **Synchronize repositories** task.
- Persist bounded per-stream Appliance Update availability with separate latest-attempt and successful-confirmation
  evidence. Disable an unsynchronized Photon or PowerShell stream with an accessible **Repository setup required**
  reason and a direct path to the matching Update Sources context and audited **Synchronize repositories** action.
  Reject blocked streams server-side for both checks and installations while preserving independent ready streams.
  Refresh readiness promptly after synchronization, order browser responses so stale data cannot overwrite the new
  state, replace an obsolete prerequisite failure with **Check required** after success, and retain actionable
  non-secret failure guidance after a failed sync. Require fresh successful non-stale checks, at least one confirmed
  update, and valid prerequisites for manual installation. Keep scheduled check-before-apply independent. Render the
  authenticated global indicator from sanitized no-store browser state, poll it only while visible and after terminal
  update tasks, create or update exactly one control for a positive confirmed count, remove every live control
  completely from visual and accessibility trees at zero current confirmed updates, preserve only valid last-known
  positive state through transient, structurally invalid, or noncanonical polling failures, require `up_to_date`
  confirmations to carry zero changes, and clear only successfully installed streams. Optional signed release summaries
  must be bounded commit subjects and release links must be credential-free HTTPS of at most 2,048 characters.
- A signed Atlaso Release update succeeds only after durable candidate activation is proven: `current`, the compatibility
  virtualenv, signed receipt, finalizer, internal OpenAPI version, nginx management-front-door version, maintenance
  cleanup, nginx validation/reload, and required service state must agree. Restart the worker under a provisional
  finalizer and prove its new PID, candidate version, release root, and job identity before writing definitive success;
  retain maintenance through every rollback-capable stage and durably record `activation_committed` before opening the
  management front door. Once committed, preserve the candidate and retry cleanup, host-facing proof, and definitive
  finalization forward; never restore the database snapshot after operator writes can be admitted. After reboot,
  recreate the matching volatile gate from durable committed evidence, let pre-start admit the gated candidate without
  requiring its own worker to be active, and complete forward activation only after that worker publishes exact job,
  version, release-root, current-boot, PID, and process-start identity.
  Persist the bounded rollback manifest before switching the active link, persist restart-pending evidence before the
  volatile runtime gate, and keep recovery behind that gate until the definitive write completes. Worker pre-start must
  distinguish the live helper by boot, PID, and process-start identity and roll back stale provisional evidence before
  admitting the worker after a host restart. Reboot forward recovery must use one stable per-job systemd unit and replace
  the prior-boot owner with that helper's exact live identity before admitting the candidate worker. While that exact
  helper remains live, extend the candidate worker's gate
  wait so a timeout cannot restart through a restored legacy unit before definitive rollback evidence. Flush every
  database and installed-asset rollback backup plus its directory entries before publishing the durable manifest.
  A missing database backup makes rollback incomplete, and restore every installed asset independently so one failure
  cannot prevent later restores. Refresh the manifest after the ESX allowlist backup is added and
  before claim migration mutates its allowlist or database, so both restore together. An already-active release completes
  from exact readiness evidence without scheduling an
  unverified service restart. A matching definitive success or healthy rollback may clear or supersede an orphaned gate;
  incomplete rollback must retain maintenance and the gate. Atlaso and nginx service pre-start guards must recreate the
  volatile maintenance hold from durable provisional evidence before either service can start after reboot. Reboot
  rollback must keep that hold and a provisional finalizer through candidate-version child, parent, log, and audit
  bookkeeping; only then may it open and prove the front door and publish definitive healthy-rollback evidence.
  Rollback must preserve and verify the already-running worker
  until the definitive rollback write; never start a restored legacy worker inside the transaction. After recovery
  bookkeeping, a candidate worker must exit for systemd to start the restored release. Before publishing any incomplete
  rollback, retain provisional owner evidence and stop and verify the caller inactive, including when the gate exists.
  Then resume only untouched pending update children when the restored worker can preserve terminal child results,
  including a mixed terminal/pending set after a second worker restart, without rerunning terminal children. When a
  rollback restores an older worker without that capability, leave untouched children explicitly skipped and the
  parent failed so the restored worker cannot rerun the rejected release. Gate timeout exits worker startup for systemd
  retry, and the surviving helper removes staged source
  credentials before restarting the caller. Definitive finalizers retain sanitized helper commands, and recovery uses
  the ordinary child, parent, terminal task-log, and audit completion path. Any post-switch failure before the durable
  activation commit restores the previous release, assets, database, and nginx-ready front door with
  `rolled_back=true`; failures after that commit remain fail-closed and recover forward. Worker startup must reject a success
  finalizer that disagrees with the durable active release or running version. Lifecycle coverage proves both successful
  activation and rollback before and after audited appliance reboots; never reboot automatically as part of installation.
- Boot ShredOS only from the verified stable ISO's allowlisted `/boot/bzImage` kernel through iPXE. Do not restore raw
  disk-image SAN boot or add unattended erase arguments.
- OIDC clients use explicit validated identity sources and emit only granted, explicitly mapped claims; see the detailed
  agent policies and canonical OIDC service guide. Administration keeps generated client IDs immutable, shows secrets
  once, validates the issuer against the applied Management HTTPS certificate, preserves retired-key overlap, and
  exports only public relying-party metadata.
- IP addresses, MAC addresses, hostnames, and account names are non-sensitive operational identifiers by themselves.
  Passwords, tokens, authenticated URLs, session material, private keys, password hashes, credential verifiers, and
  other secret-bearing data remain sensitive; content-integrity hashes of non-secret material and one-way
  change-detection hashes of encrypted-at-rest ciphertext do not. Treat an identifier as sensitive when it is embedded
  in or paired with authentication or cryptographic material.
- Use the installed 1Password plugin and the exact `Atlaso` Environment as the required agent-facing integration for
  every user password and for every newly created user or key secret, including passwords, tokens, API keys, and private
  keys. Authenticate through the plugin, verify the named Environment before access, and store secret values there as
  concealed variables. For supported Windows
  subprocess use, bind that exact Environment by its opaque ID through the supported 1Password SDK inside the bounded
  child process; never read the value into agent-visible output. Never fall back to chat, repository files, local
  `.env` files, shell arguments, jobs,
  audits, logs, screenshots, or documentation; if the 1Password plugin or the `Atlaso` Environment is unavailable, stop
  and request maintainer direction.
  DEFAULT_ROOT_PASSWORD contains the default root password for any new deployed environment.
  DEFAULT_ADMIN_PASSWORD contains the default admin password for any new deployed environment.
- Never expose credentials, authenticated URLs, private keys, raw secrets, or secret-bearing commands in UI, jobs,
  audits, logs, documentation, screenshots, or video.
- The appliance-native vSphere Key Provider targets only VCF 9.1 and implements the checked-in bounded KMIP contract.
  Keep it experimental until the live acceptance and recovery gate promotes that contract to observed. Provider UUIDs
  are isolated key namespaces; multiple provider-scoped vCenters use canonical public certificates and appliance-wide
  unique exact fingerprints. Never generate or expose vCenter client private keys or management key CRUD. Authenticated
  status exposes nullable redacted lifecycle counts and unavailable evidence is never zero. LDAP organizations never
  select a provider. Do not restore a general-purpose KMIP backend.
- Keep secret-bearing Local Users, Certificate Authority, and Managed LDAP apply inputs mode `0600` and present only
  for the constrained helper execution window. Remove them on success, validation or apply failure, and startup
  recovery; read-only Local Users status must use a separate short-lived file.
- Preflight every settings archive section, required row field, relationship, and enabled VLAN or static-route target
  before clearing desired state. A failed restore must roll back database changes and preserve separately staged LDAP
  recovery metadata and in-memory bytes. Clear staged recovery material only after a successful restore commit or
  factory reset commit.
- Complete factory reset must replace every control-plane database record with factory/bootstrap records, invalidate
  all sessions and credentials, activate coherent core defaults while disabling optional services, and preserve depot,
  backup, and managed ESX Storage payload paths. Persist a non-secret recovery marker before database replacement,
  make resume idempotent across interruption or reboot, validate all generated runtime configuration before activation,
  scrub transient staging plus retained VCF Backup authorized keys and Web Terminal signing material, and leave all 16
  desired/applied baselines equal with no follow-up Apply workflow. Also remove retained KMIP operational state and
  Atlaso-synchronized package-source credentials and registrations, fsyncing credential-bearing repository removal
  before the recovery marker advances. Require explicit keep-or-change choices for both
  the bootstrap administrator and root passwords, validate changes against the packaged factory Local Users policy,
  and give each request its own protected staging file so failed admission removes only that request's secret. Keep
  submitted values out of the database, marker, jobs, audits, logs, and UI responses. Keep the recovery marker pending
  until Atlaso, worker, nginx, and stable management OpenAPI readiness are verified after restart. Run every real
  Bind the privileged runner and finalizer to the admitted root-owned state directory through a pinned, no-follow
  descriptor beneath the root-owned `/var/lib/atlaso-privileged` parent so the service account cannot rename the state
  during detached dispatch or redirect recovery state and credential access. Run
  every real mutating helper and nested account mutation in an exact UUID-named `atlaso-helper-action-*` transient
  service. After
  stopping Atlaso callers, reset must stop and verify those services, cancel and verify any pre-existing fixed-name
  management restart timer and service, and reverify the callers are inactive before inventorying delayed
  update-restart units. After transient automation units are quiescent, durably clear their bounded managed-script and
  run staging directories through symlink-resistant paths before reset activation continues. Also durably clear the
  bounded Managed LDAP recovery-export directory so interrupted plaintext account archives cannot survive reset.
  Before runtime activation, stop SSH admission and terminate and verify every root or Atlaso-managed operating-system
  login session. Repeat that bounded termination after retained authorization keys are scrubbed, then restore and
  verify factory SSH policy through the readiness handoff.
- Keep internal CA custody and managed service-certificate deployment available without a public CA listen interface.
  Interface selection owns portal publication only. Every selected NTS server apply includes the CA unit and executes
  it before NTP/NTS validation so runtime certificate material is present even when the CA baseline is current. Turning
  NTS server mode off removes its `ntp:nts` CA record and deployed certificate, key, and cookie material during apply
  without changing per-upstream NTS client flags. The one-time `ntp_nts_restoration_v1` reconciliation may re-enable
  only the canonical Cloudflare and Netnod default rows; it must not change operator-created sources or enable server
  mode.
- Require TLS 1.2 or newer for the KMS compatibility listener and pre-authentication certificate-fingerprint probes.
  Preserve explicit certificate-fingerprint confirmation as the trust decision for VCF Automation and vSphere probes.
- Vault passwords are the narrow exception for an explicit administrator eye reveal: keep them masked by default,
  CSRF-protect and audit reveals without values, disable caching, and automatically hide the value again.
- Use the locally bundled `window.AtlasoMonaco` integration for code or configuration editing. ESXi Kickstarts use the
  dedicated Kickstart language and derive vault scope only from exact source markers; never restore an explicit
  Kickstart-to-vault selector or expose resolved values in browser state or completion metadata. Dynamic Kickstart
  retrieval requires a cryptographically random pending boot claim plus an administrator-entered one-time code shown
  by the intended host console. Only that exact claim may receive a short-lived, atomic single-use boot capability
  bound to the applied host, full Kickstart revision, listener, and generated attempt. Store only claim, code, and
  capability verifiers, never treat a MAC address as authentication, and never expose capability paths in management
  UI/API, audit, job, problem, or log data. The exact pending boot protocol response may carry only its own claim.
- Browser navigation to a globally disabled Web Terminal must render the authenticated Atlaso unavailable-state page;
  reserve JSON and protocol errors for ticket, API, and WebSocket consumers.
- Browser inactivity is server-authoritative across management, public, and protocol browser planes. Evaluate the
  configured 5-to-1,440-minute timeout before protected handlers; refresh only for deliberate navigation, submitted
  actions, or the CSRF-protected activity heartbeat, never static assets or passive polling. Terminal expiry clears
  identity and CSRF state, emits only sanitized account/session-class/reason audit context, returns `401` to fetch/API
  consumers, and routes human navigation to the same-plane login notice. A later policy increase must never resurrect
  an expired session.
- New API-token issuance uses the current 1-to-365-day maximum from Appliance Settings. Omitted expiry means exactly
  that lifetime from server issuance time; explicit expiry must be timezone-aware, future, and no later than the
  maximum. Preserve every existing token's absolute expiry when policy changes, and show the configured lifetime plus
  absolute expiry in the shared token wizard review.
- Classify Web Terminal management page, ticket, and WebSocket eligibility from the last-applied Network binding,
  including flagged access physical and VLAN listeners. Pending desired edits must not reclassify the applied listener;
  handoff commit moves all three surfaces, rollback retains the old listener, and explicit extra listeners stay public.
- VCF Offline Depot login return targets must be reconstructed beneath the server-owned `/PROD` prefix after strict
  relative-path validation. Unsupported or malformed destinations fall back to `/PROD/`; never redirect a successful
  depot login to an authority, scheme, traversal path, or browser-equivalent backslash form supplied by the request.
- When local DNS points the management resolver to loopback, recover empty DNS service upstreams from the exact
  management interface's systemd-networkd DHCP lease. Reject loopback, unscoped IPv6 link-local, duplicate, malformed,
  and other-interface lease values, preserve explicit upstream precedence, and fail both desired-state and helper
  validation when DHCP fallback is required but unavailable.
- Derive every factory-owned service hostname from the domain portion of the canonical appliance FQDN. Reconcile fresh
  seed, OVF first boot, appliance-domain changes, settings restore, factory reset, and existing development state through
  one registry. Migrate only the packaged default or the exact prior factory domain, preserve customized hostnames and
  operator-owned DNS rows, remove stale exact-marker app-owned A/AAAA/CNAME aliases on conflict, and keep coupled issuer,
  certificate, endpoint, and Appliance Apply desired state coherent.
