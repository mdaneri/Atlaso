---
title: Detailed agent policies
description: Canonical subsystem contracts and implementation constraints for automated contributors.
audience:
  - contributor
  - maintainer
status: current
---

# Detailed agent policies

## Mandatory Agent Startup Gate

- These instructions apply to every agent, subagent, delegated agent, automated contributor, and resumed task.
- Before planning implementation or changing repository or external state, read the root `AGENTS.md` completely, then
  read [CONTRIBUTING.md](https://github.com/mdaneri/Atlaso/blob/main/CONTRIBUTING.md),
  [CODE_OF_CONDUCT.md](https://github.com/mdaneri/Atlaso/blob/main/CODE_OF_CONDUCT.md), and
  [SECURITY.md](https://github.com/mdaneri/Atlaso/blob/main/SECURITY.md). Treat all four documents as mandatory
  instructions, not optional reference material.
- In the first progress update, confirm that the policy files were read, classify the work as `bug`, `enhancement`,
  `documentation`, or security-sensitive work, and identify the linked GitHub issue. For private vulnerability
  remediation, confirm that a private advisory is linked without disclosing its identifier or finding details on public
  surfaces. Read-only inspection needed to identify the repository, applicable instructions, issue, or private tracking
  record is allowed before that confirmation.
- Repeat this startup gate whenever the repository, worktree, or working directory changes, or when any of the policy
  files changes during the task.
- A delegating agent must include this startup gate in every delegated prompt and verify that the delegated agent
  completed it before accepting or using its work. Delegation never bypasses repository policy.
- If a policy is unavailable, conflicting, or unclear, stop before implementation and ask for maintainer direction.
  Never silently bypass a policy.

## Mandatory UI Design Guide Gate

- Any change affecting templates, authored CSS, browser JavaScript, controls, layouts, data grids, dialogs, wizards, or
  visible copy must read the [Atlaso UI Design Guide](ui-design-guide.md) before planning implementation.
- In the first progress update for UI work, confirm that the guide was read, classify the interaction as
  `direct-edit Tabulator`, `wizard-backed Tabulator`, `read-only Tabulator`, `non-grid settings`, or approval-only
  `custom/other`, and name the existing Atlaso reference being reused. For `custom/other`, cite the explicit maintainer
  approval and name the closest related Atlaso reference.
- Tabulator is the only data-grid implementation. Custom data grids and interaction patterns not defined by the guide
  require explicit maintainer approval before implementation.
- Construct every Tabulator through `window.AtlasoUiPatterns.createGrid(...)`. Build every new or changed wizard
  through `window.AtlasoUiPatterns.createWizard(...)` and the generic `data-atlaso-wizard-*` DOM contract. Raw
  Tabulator constructors outside the shared foundation are forbidden.
- A delegating agent must include this UI gate in every UI-related delegated prompt and verify that the delegated agent
  read the guide, classified the interaction, identified the reused or closest related reference, and cited maintainer
  approval for `custom/other` before accepting or using its work.
- Repeat this gate when the guide changes during a task. If the guide is unavailable, conflicting, or unclear, stop
  before UI implementation and ask for maintainer direction.

## Repository Delivery Workflow

- [CONTRIBUTING.md](https://github.com/mdaneri/Atlaso/blob/main/CONTRIBUTING.md) is the canonical delivery workflow.
  Every repository change requires a GitHub
  issue created or linked before implementation begins, exactly one applicable type label, relevant documentation
  updated in the same change, and a pull request linked with `Closes #<issue>`. Do not commit changes directly to
  `main`.
- Keep every pull request within its linked issue scope. When a reproducible or otherwise evidence-backed actionable
  problem outside that scope is discovered, search open and closed issues for an existing record. If none exists, open
  a separate issue with exactly one appropriate type label and sanitized evidence. Link it when useful, but do not add
  `Closes` unless the active pull request resolves it, and do not expand the pull request without explicit maintainer
  approval. Route suspected sensitive vulnerabilities through `SECURITY.md`, never a public issue.
- The private vulnerability remediation workflow in
  [SECURITY.md](https://github.com/mdaneri/Atlaso/blob/main/SECURITY.md) is the only exception to the public issue,
  repository branch, and `Closes #<issue>` requirements. Use the draft advisory as the private tracking record, create
  the fix branch from the current default branch, push only to the advisory's temporary private fork, and open the
  private pull request there. Keep advisory identifiers, cross-references, finding details, and patch discussion on
  private surfaces. Complete and record every required validation locally because integrations and status checks cannot
  access temporary private forks. Treat the temporary private fork as a GitHub workspace repository where ordinary
  Issues cannot be enabled and pull-request labels or comments may be unavailable or forbidden. An otherwise mergeable
  pull request may show `UNSTABLE` solely because checks are absent; never substitute that state for local validation.
  Advisory-side maintainer review and recorded local validation replace ordinary Codex review, `@codex review`,
  exact-head CI/status, comment, label, and review-thread follow-through. Do not request, wait for, or claim unavailable
  integrations. Run the complete Python test suite locally when the change affects Python or `SECURITY.md` otherwise
  requires it. This overrides the ordinary automated-contributor prohibition, and missing full-suite evidence blocks
  advisory merge.
  Do not use ordinary pull-request merge controls or `gh pr merge`. An explicitly authorized advisory administrator
  must use **Security > Advisories > This advisory is ready to be merged > Merge pull request(s)**. GitHub merges all
  open pull requests in the temporary fork together, permits only one pull request targeting `main`, and applies the
  patch to the public `main` branch while the advisory may remain draft. Publishing is a separate explicit action.
  Merge only for an authorized coordinated release and disclosure, and do not otherwise change advisory state without
  explicit maintainer authorization. `SECURITY.md` is canonical for the complete security-specific workflow.
- Trusted version refresh must dispatch the CI definition from protected `main` with the exact pull-request number, base
  SHA, and head SHA. Keep candidate validation jobs read-only. Publish the canonical `Version policy`, `Repository
  checks`, and `Python tests` commit statuses only from bot-gated jobs that never check out candidate code and that
  revalidate the open same-repository PR plus exact head/base before publishing pending or final results. Keep every
  status linked to its trusted run, retain diagnostic names for bot-triggered `pull_request` jobs, and keep trusted and
  diagnostic events in separate concurrency groups so diagnostic work cannot cancel trusted publication. Never grant
  candidate workflow revisions status-write permission.

### Focused local validation and pull-request follow-through

- This section governs ordinary pull requests. Temporary-private-fork remediation uses the security-specific
  replacement in the Repository Delivery Workflow above.

- Run locally only tests focused on the changed behavior, plus every applicable repository, documentation,
  static-analysis, deployment, and `git diff --check` validation. Do not run the complete Python test suite locally;
  GitHub CI's canonical `Python tests` context owns that complete suite.
- Open every agent-authored pull request ready for review. The ready event triggers the initial Codex review, so do not
  post a duplicate opening `@codex review` comment.
- After the pull request is open, use a separate commit-push-review cycle for every later branch change. Push one
  commit, verify that it is the pull request's exact head, post one `@codex review` request, and only then begin another
  commit.
- Keep the originating task active while GitHub evaluates the pull request. Monitor every check for the current exact
  head and inspect pull-request comments, reviews, and authoritative `reviewThreads`.
- Address actionable feedback, reply and resolve each handled thread, rerun focused local validation, then commit,
  push, request `@codex review`, and restart monitoring for the new exact head. Completion requires successful
  current-head checks with no unanswered actionable comment or unresolved non-outdated review thread. Escalate genuine
  maintainer decisions or external failures rather than guessing or reporting completion.

### Explicit merge authorization

- Preparing a change and merging it are separate authorities. An implementation, fix, **solve**, pull-request delivery,
  or similar request authorizes preparation and publication of a ready-for-review pull request but does not authorize
  merging it.
- Require an explicit merge instruction for the ordinary same-repository pull request authored and owned by the active
  task. The instruction may be part of the original request or a later direction. Without one, leave the pull request
  open after delivery and follow-through are complete. Do not infer merge authority for human-authored pull requests,
  forks, drafts, review-only or diagnostic tasks, or private vulnerability remediation. GitHub auto-merge remains a
  separate explicit maintainer choice.
- Treat **do not merge**, **leave the pull request open**, **pull request only**, **wait for approval**, and equivalent
  instructions as holds until explicitly withdrawn and the merge is authorized.
- Immediately before an authorized merge, re-fetch the pull request and `main`, then verify the linked issue and type label,
  documentation, synchronized patch version, all applicable exact-head checks, answered actionable feedback, resolved
  non-outdated `reviewThreads`, and conflict-free merge state. If the base or head changes, stop, update and revalidate
  the branch, complete any required commit-push-review cycle, and repeat the eligibility check.
- An expected-head option does not bind the base SHA. Direct agent merging therefore requires an active branch rule with
  strict up-to-date required checks that blocks the merge if `main` advances after validation. Re-read the rule
  immediately before merging, never use an administrative bypass, and stop for maintainer direction when strict base
  enforcement is unavailable.
- Inspect the active rules for a required merge queue. If one is present, do not invoke `gh pr merge`, because it may
  enqueue the pull request or enable auto-merge rather than complete a synchronous guarded merge. Stop for maintainer
  direction instead of entering that workflow implicitly.
- With both base and head guards present and no required merge queue, perform only a squash merge guarded by the expected
  head SHA. Supply the finalized pull-request title as the subject and an extended body describing the outcome,
  rationale, principal changes, validation, and linked issues. Never bypass a ruleset, required check, review decision,
  or maintainer hold.
- After merging, verify the pull request state, confirm that the squash commit is reachable from current `origin/main`,
  check linked issue closure, and monitor applicable post-merge workflows before reporting completion.

## API authoring

- Follow the [API authoring standard](api-authoring.md) for every new or changed `/api/v1` operation.
- Keep route-local summaries, detailed purpose and authorization, effect boundaries, parameter descriptions, explicit
  response meaning, and Pydantic schema-property descriptions synchronized with behavior.
- Only `/api/v1` belongs in OpenAPI. Preserve supported browser and service-protocol routes at runtime with
  `include_in_schema=False` and document them in their canonical guides.
- Update the operator API guide and affected topic documentation, preserve compatible operation IDs and shapes, and run
  `tests/test_openapi_contract.py` so new routes automatically enter the enforcement surface.
- Follow the [router architecture](router-architecture.md) for route ownership, facade aggregation, deterministic
  registration, dependency direction, domain test placement, route inventory, and normalized OpenAPI compatibility.
- GitHub-managed version-update pull requests generated from `.github/dependabot.yml` are the only exception to the
  pre-existing issue and per-update documentation requirements. They must carry the `enhancement` type label plus
  `dependencies`, remain subject to the normal version, CI, review, and squash-merge gates, and must not weaken
  Atlaso's generated-lock or release boundaries. Before merging a Python update, regenerate every affected `.lock`
  file through `python scripts/compile_requirements.py` with Python 3.14 and pip-tools 7.6.0. The wrapper must retain
  pip's `--uploaded-prior-to=P7D` cutoff for every direct, transitive, and security update, preserve hashes and required
  `--allow-unsafe` behavior, refresh the appliance declaration fingerprint, and run the dependency-policy, lock, and
  Photon compatibility checks. Do not admit a Python distribution uploaded less than seven full days ago.

## Data Classification And Redaction

- IP addresses, MAC addresses, hostnames, and account names are non-sensitive operational identifiers when they appear
  by themselves. Their presence alone is not a reason to suppress a useful operational log or audit record.
- Passwords, tokens, authenticated URLs, session material, private keys, password hashes, credential verifiers, and
  other secret-bearing data are sensitive and must remain out of public issues, pull requests, previews, baselines,
  tasks, logs, audits, screenshots, test output, and final responses. Content-integrity hashes of non-secret material
  and one-way change-detection hashes of encrypted-at-rest ciphertext are not sensitive by themselves.
- Treat an operational identifier as sensitive when it is embedded in or paired with authentication or cryptographic
  material. Review the complete context before recording, rendering, or sharing it.
- This classification does not relax authentication, authorization, access control, least-privilege, or an operator's
  site or organization handling requirements. Preserve those controls even when a value is not sensitive by itself.

## UI Defaults

- Every configurable setting should include an adjacent `i` help control using the `.field-label` and `.help-icon`
  pattern.
- The help text should explain what the setting changes, where it applies, and any safety boundary such as dry-run or
  interface binding.
- Keep the help inline and compact: use hover/focus tooltips for short explanations instead of adding persistent
  instructional text to the page.
- Text-edit form controls, including text, number, password, select, and textarea controls, should use the standard
  Atlaso sans font and compact app control sizing unless the field is intentionally a monospace config/code preview.
  Check computed styles when Tailwind/runtime defaults may override form-control CSS.
- Prefer consistent control types: switch controls for binary settings, selects/list editors for short enumerations,
  inputs for exact free-form values, textareas for multiline config, tabs for mutually exclusive editing modes, and
  Tabulator for editable data grids.
- Give server-rendered tab controls literal initial `aria-selected` values and let the shared tab script update them
  after restoring persisted state. For authored CSS, pair supported WebKit compatibility properties with their standard
  declarations and avoid nonessential scroll styling that has no cross-browser fallback.

## Appliance Configuration UX

- Use the DNS page as the default pattern for configurable appliance services where applicable.
- Place configurable service settings in the right-side rail, matching the DNS page. Keep the service's primary
  resources or workflow in the main column and place service validation below the settings in that rail; collapse
  responsively without changing their order.
- Treat forms as desired-state editors. Settings should autosave on change with `data-autosave-form`, a small
  `.autosave-status` message, and the existing CSRF/session protections. Avoid visible "Save" buttons for routine
  desired-state settings when autosave is safe.
- Keep enforcement separate from editing. Applying changes to the appliance should be a deliberate task action after the
  user is done, not part of every field change.
- Do not add service-specific apply cards or service-specific apply submit routes. Applying is a global appliance
  workflow owned by `/ui/management/appliance-apply`.
- In service right-side rails, show a compact `Pending Appliance Changes` card first, then the service-specific
  `Validation` card. The pending card opens the shared appliance-review modal; the validation card owns only
  valid/needs-attention state, validation messages, warnings, and compact rendered config preview actions.
- Top-of-page pending banners should be scoped to the current page's changed apply unit only. The sidebar apply card
  remains the global pending-unit indicator.
- The shared appliance-review modal should list changed apply units, check changed valid units by default, show compact
  summaries, show rendered config diffs/previews, allow users to unselect units, and submit one `appliance-apply` job.
  Do not restore a standalone appliance-apply page; direct GET requests redirect to Dashboard and open the modal.
- Apply actions should create one global job/task that captures selected units, skipped changed units, current desired
  state summaries, rendered config previews/diffs, validation results, adapter commands, dry-run status, and audit
  event.
- Label the global submit action around the user's intent, such as `Submit appliance changes`, and explain that the task
  validates and applies selected desired state through Atlaso adapters.
- Fresh Photon appliance startup may initialize the factory desired-state baseline automatically when no baseline,
  appliance-apply job, or non-auth operator audit event exists. This is comparison metadata only and must not run helper
  commands or mutate host services.
- Keep dry-run boundaries visible. In development, applying should record command intent through adapters instead of
  mutating host services directly.
- Appliance Settings owns appliance FQDN, OS hostname, appliance resolver mode/servers, management UI HTTPS preference,
  and root SSH login preference. NTPsec owns appliance time service behavior. DNS/DHCP owns rendered DNS records and
  dnsmasq reload, not appliance resolver, hostname, or NTP enforcement.
- Use validation panels to show whether desired state is ready to apply, including warnings and rendered config
  previews. Keep full rendered configs out of side rails; use the shared compact preview action row and global preview
  modal, while preserving hidden source selectors so autosave refresh code can update the latest text.
- When autosave changes affect validation or preview output, update the validation card in-place without shifting the
  page with large `Saved` alerts. Use compact autosave status text near the edited form.
- Use compact Tabulator grids for editable record sets. Rows should autosave on edit, place new-record rows at the
  bottom, include a clear `+ Add record here` affordance, and expose destructive actions through a context/menu action
  rather than inline clutter. New-record placeholder rows should show and enable only the required identity field until
  that value is filled; default/generated cells stay visually blank and locked to avoid implying a complete row exists.
- Use tab groups when two editing modes solve the same job. Do not show single-record forms, bulk import, and raw/config
  editors all at once if tabs can make the workflow clearer.
- Use tag editors for one-or-more selections such as interfaces, addresses, networks, domains, or labels. Tag editors
  should allow typed custom values and a `+` menu for known existing options.
- Use domain- or scope-specific tabs for resources that naturally belong under a parent, such as DNS records under
  zones. Each tab should keep edits scoped to that parent.
- When DNS authoritative mode is enabled, every managed forward domain is a dnsmasq `auth-zone` using the shared primary
  nameserver, SOA administrator, timers, TTL, and server-managed monotonic serial. Generate SOA and NS records plus
  A/AAAA nameserver glue from selected DNS listen addresses; keep those structural records read-only, accept only
  matching structural metadata during zone-file import, and reject conflicting operator records. Authoritative mode does
  not make generated reverse zones authoritative, and reverse-zone cards start as collapsed native disclosures on every
  page load.
- Preserve active tab context after autosave, record creation, deletion, or import whenever possible.
- Prefer explicit status language over generic button text. Avoid labels such as `Save DNS` or `Apply` when the action
  really means "save desired state", "review appliance changes", "submit appliance changes", "import into this domain",
  or "apply zone file".
- Destructive UI actions such as deleting a domain, scope, record set, backup, token, or appliance-owned config should
  require the shared modal confirmation pattern (`data-confirm-modal`) instead of a browser confirm or immediate submit.
  The modal copy should name the object, explain what will be removed, and mention whether the appliance is affected
  immediately or only after global appliance apply.

## Dashboard Operations UX

- Keep `/ui/management/dashboard` as an adaptive, read-only operations command center. Preserve the application shell
  and send
  mutating work to existing workflows instead of adding dashboard-side apply, restart, or service actions.
- Build the initial HTML and `/ui/management/dashboard/data` response from the same private snapshot builder. Keep
  `/api/v1/dashboard`
  and its public schema independent and backward compatible.
- Prioritize dashboard attention items as invalid changed apply units, unresolved failed tasks from the last 24 hours,
  unhealthy enabled services, then missing or unexpectedly down configured physical interfaces. Later successful
  appliance applies resolve an earlier appliance-apply failure for dashboard attention only when they cover every unit
  that did not succeed in the failed task; an unrelated successful apply does not clear it. Preserve the failed tasks
  and audit events as history. Disabled optional services and unused interfaces are not exceptions.
- Keep valid pending changes separate from invalid changed units. Open changes in the shared appliance-review modal, and
  link tasks to `/ui/management/tasks`, service exceptions to `/ui/management/services`, and interface exceptions to
  `/ui/management/physical-interfaces`.
- Fresh appliances remain in setup readiness until management networking is healthy and one global appliance-apply task
  has succeeded. Show management discovery, addressing/link state, Appliance Settings validity, desired-state validity,
  and first-apply readiness while that mode is active.
- Merge recent tasks and audit events chronologically without rendering task results, command output, raw errors, or
  audit detail. Dashboard refresh runs every 30 seconds only while visible, refreshes immediately on visibility return,
  and preserves the last successful snapshot with a stale marker after failure.

## Monitor Operations UX

- Keep `/ui/management/monitor` read-only and focused on appliance runtime health: CPU, memory pressure, network throughput,
  unique-device disk activity, interface state, and virtual-machine context.
- Do not restore per-mount capacity presentation on the Monitor page, including the top-level Disks metric, Disk Usage
  chart, or capacity table. Filesystem usage may remain in monitor samples and APIs for compatibility and other
  consumers, but it is intentionally omitted from this page because the mount-level view was not operationally useful.
- Count disk activity once per underlying device even when the same filesystem is visible through multiple mount or
  bind-mount paths. Preserve the aggregate-versus-detail hierarchy so appliance totals remain visually distinct from
  per-CPU, per-interface, and per-device series.
- Keep chart expansion, series selection, and time-range controls consistent across the remaining charts.
  Full-screen-only zoom must not change the selected history range.

## Photon OS Appliance Deployment

- Default live appliance testing should use VMware Workstation. VMware Workstation is installed by default at
  `C:\Program Files\VMware\VMware Workstation`; use `vmrun.exe` there with the helpers under `scripts/windows/vmware/`.
- The first real OS appliance target is Photon OS 5.0. Keep Hyper-V image-build work under `image/hyperv/`. VMware
  Workstation work lives under `image/vmware-workstation/` and should share Photon image-build/provisioning code with
  Hyper-V whenever possible.
- Before a VMware Workstation image rebuild force-replaces the configured output directory, unregister any existing
  output VMX with `vmrun -T ws unregister` through the same Workstation/vmrun discovery path used by the rest of the
  VMware scripts. Keep this cleanup scoped to the configured image output directory.
- Workstation test-VM and lifecycle cleanup may recursively remove only an exact, non-reparse-point artifact root that
  contains every validated target VMX. A named redeploy with no matching VMX fails closed, and data-disk reset paths
  must be strict path-component descendants of that VM output rather than sibling-prefix matches. Query the checked
  `vmrun` running inventory and Workstation registration inventory, stop and unregister only when needed, then verify
  the target is absent from both before removing files. Any nonzero or malformed `vmrun` result or unreadable
  registration inventory preserves the artifacts and must propagate as a cleanup failure; lifecycle cleanup must retain
  the original scenario failure alongside that cleanup evidence.
- Keep VMware release images on two compacted payload VMDKs: the Photon OS disk and a required UUID-mounted
  `ATLASO_SYSTEM` disk containing `/opt/atlaso` and appliance-wide PowerShell modules. OVF export must preserve both
  payload files, add only the empty depot and backup definitions, preflight every GitHub asset below 2 GiB, and omit an
  oversized aggregate OVA rather than publishing an unusable release asset. Recursive OVF output replacement is limited
  to strict, non-reparse-point descendants of `image/vmware-workstation/ovf`; repository, image, output, filesystem, and
  external roots are never removal targets. Release mode implicitly replaces only its canonical derived destination.
  Every explicitly supplied existing destination requires `-Force`, and `-Force` does not expand the deletion boundary.
- Remove only proven build-only packages after runtime and Photon compatibility checks. Preserve all appliance
  capabilities, clean package/download caches and staged build sources, zero-fill both payload filesystems with a
  bounded free-space reserve, remove the fill files, request TRIM, and emit bounded before/after footprint evidence
  before Packer compaction.
- The Hyper-V image is automated with Packer, Photon kickstart JSON, an ISO-embedded GRUB auto-install entry, and
  provisioning scripts. Do not replace it with manual-only install steps unless the automation path is also kept
  current.
- Photon appliance provisioning should run `tdnf -y makecache` and `tdnf -y update` before installing Atlaso so the
  image lands on the current Photon 5.0 package stream.
- Both Photon Packer templates must stage `requirements-appliance.lock` into `/tmp/atlaso-src` before shared
  provisioning syncs the application under `/opt/atlaso`. Keep bootstrap dependency installation hash-locked and fail
  the image when the staged lock is missing; do not fall back to unpinned dependency resolution.
- Both Photon Packer templates must also stage `scripts/generate_third_party_notices.py` and
  `scripts/third_party_notices.json`. Treat third-party notice generation as mandatory and fail the image when its
  generator, inventory, referenced notice, installed top-level Python distribution metadata, or Photon RPM inventory is
  missing or invalid; ignore nested package-internal vendored metadata during installed-environment lock verification,
  and do not skip notice generation to complete a build.
- Run long TDNF operations in shared Photon provisioning through `scripts/run_tdnf_with_progress.py`. Keep its compact
  30-second Packer heartbeats with elapsed time and TDNF cache size, capture raw transaction output instead of streaming
  terminal redraws, preserve the child exit status, and replay only a normalized bounded output tail on failure.
- Photon 5.0 GA started at Python 3.11, but Atlaso targets the updated Photon 5.0 package stream; on June 21, 2026 live
  repo metadata showed `python3` as `3.14.5-2.ph5`. Keep Atlaso at `requires-python >=3.14,<3.15`, publish only the
  `cp314` appliance wheelhouse, and run `python scripts/check_photon_compatibility.py` before treating Photon
  compatibility as healthy.
- System-wide PowerShell modules live under `/usr/local/share/powershell/Modules`. Keep that tree root-owned and
  non-writable by group/other while making directories traversable and module content readable to every local
  `/usr/bin/pwsh` user. Normalize those permissions after image provisioning copies or installs modules and after each
  Appliance Update module install, and verify VCF PowerCLI plus `Connect-VIServer` from the unprivileged bootstrap
  administrator's PowerShell session.
- The appliance installs Atlaso under `/opt/atlaso`, stores environment in `/etc/atlaso/atlaso.env`, stores durable
  state in `/var/lib/atlaso`, writes local logs under `/var/log/atlaso`, and preserves fixed service mounts under
  `/mnt/atlaso-vcf-*`.
- Appliance provisioning must set `ATLASO_SECRETS_KEY` in `/etc/atlaso/atlaso.env`. Atlaso uses it to encrypt CA root
  and leaf private keys in the database; preserving it is required for settings-backup portability.
- Keep the image-build OS/root password separate from the Atlaso web bootstrap password. Packer exposes `ssh_password`
  for build-time SSH/root use and `bootstrap_admin_password` for the initial `admin` web login; never substitute one for
  the other.
- Photon kickstart must disable `sshd.socket` and enable the normal `sshd.service` for deterministic Packer SSH. Do not
  enable both conflicting units: socket activation can accept port 22 without completing the Packer handshake on a fresh
  image.
- Product-owned helper binaries should live under `/opt/atlaso/bin`; do not put Atlaso-owned helpers in
  `/usr/local/sbin` for Photon appliance images.
- The appliance systemd unit is `atlaso.service` and should run uvicorn from the provisioned virtual environment as the
  `atlaso` service user.
- Photon appliance firewall ownership is nftables-first. Provisioning installs nftables and loads
  `atlaso-firewall.service`; do not add a Atlaso iptables apply path.
- Photon Hyper-V images should mask `systemd-ssh-generator` because Atlaso uses normal TCP SSH and does not rely on
  automatic SSH-over-AF_VSOCK sockets. This prevents noisy `Failed to query local AF_VSOCK CID` console messages on
  current systemd/Hyper-V combinations.
- Keep `ATLASO_DRY_RUN_SYSTEM_ADAPTERS=true` for first-boot appliance images. Promote real host mutation one apply unit
  at a time after validation, preview, job capture, and rollback behavior are reviewed.
- Privileged appliance enforcement must go through `atlaso-helper` and constrained sudoers entries. Do not give the
  control plane broad shell, root, or package-manager access.
- Real mutating helper actions run through `systemd-run` from inside `atlaso-helper` when
  `ATLASO_HELPER_USE_SYSTEMD_RUN=1` is set. This escapes the `atlaso.service` read-only `/etc` mount namespace without
  giving the web control plane broad shell/root access. Keep that environment variable in `atlaso.service` and preserve
  it in the Atlaso sudoers rule.
- The global `/ui/management/appliance-apply` workflow remains the only host-mutation workflow. Do not add
  service-specific apply
  routes, service-specific apply jobs, or direct helper calls from desired-state edit forms.
- Appliance Update is runtime maintenance, not desired-state drift. Keep it separate from
  `/ui/management/appliance-apply`, stage
  `/var/lib/atlaso/apply/appliance-update/atlaso-update.json`, and run Photon OS, PowerShell module, and signed Atlaso
  release work only through `atlaso-helper appliance-update`. Do not restore the retired Python Libraries or independent
  wheel streams.
- Represent every manual or scheduled Appliance Update check/install as one parent job with ordered `JobStep` children
  for the selected Atlaso Release, PowerShell Modules, and Photon OS streams. Checks run every selected child for
  complete diagnostics. Installs preserve release, PowerShell, then Photon ordering; Photon is explicitly skipped when
  an earlier selected stream fails. After a definitive release worker handoff, resume only untouched pending children
  and never rerun a child that had started. Keep child output, compatibility evidence, and errors independent, and
  derive the parent outcome from all selected children. Give privileged PowerShell update work the root-owned
  persistent home `/var/lib/atlaso/powershell`; do not point it at the service's read-only `/root` view.
- Submit manual Appliance Update checks and installations asynchronously from Update Streams. Refresh only the embedded
  shared Tasks grid, highlight the newly created task, and keep both task actions disabled until the active Appliance
  Update task reaches a terminal state; do not restore a separate submission-result card.
- Appliance Update sources are repository-style desired runtime-maintenance configuration. Support multiple named
  Photon, PowerShell, and HTTPS Atlaso release sources, using secondary signed Atlaso channels as failover sources. Keep
  repository tabs inside collapsible ecosystem sections and managed PowerShell modules in their own one-tab-per-module
  editor. Each configured source tab is a read-only detail view with identity first, location or discovered runtime data
  second, binary repository behavior in one consistent group, and synchronization state in a separated footer. Place
  **Edit repository** beside the destructive action and use the same shared reviewed source wizard for creation and
  editing. The built-in Photon row must show effective values discovered from `/etc/yum.repos.d`. Source
  credentials remain encrypted at rest and move to `atlaso-helper appliance-update` only through a separate mode-0600
  transient staging file; never place credentials, authenticated URLs, or secret-bearing commands in manifests, jobs,
  audits, or helper output. Source wizard submissions save desired state only; writing Photon or PowerShell package-client
  configuration requires the explicit audited **Synchronize repositories** task through
  `atlaso-helper appliance-update`; signed Atlaso sources never configure pip.
- Keep the staged Appliance Update manifest in a compact Validation card at the bottom of the detail rail and open its
  full JSON through the shared preview modal; do not render the full manifest inline in Update Streams.
- Atlaso releases must come from signed v2 channel pointers and immutable signed release manifests verified by named
  Ed25519 public keys under `/etc/atlaso/update-trust.d`. Install the exact ABI wheelhouse offline with
  `PIP_CONFIG_FILE=/dev/null`, `--no-index`, and hash verification under `/opt/atlaso/releases/<version>`, switch
  `/opt/atlaso/current` atomically, and preserve `/opt/atlaso/.venv` as a compatibility symlink. Restore the previous
  release, helper/systemd files, and SQLite snapshot on failure. Inspect Photon transactions before mutation, use the
  Photon-supported `tdnf repoquery python3` form and select the highest advertised minor ABI, reject unsupported
  candidate Python ABIs, reconstruct from the retained wheelhouse after supported ABI changes, and do not claim
  automatic RPM rollback or reboot.
- Do not write a successful Atlaso Release finalizer until durable activation is proven. Flush the active switch and
  installed assets, remove maintenance mode only through final nginx validation and reload, restart the worker into the
  candidate release under a provisional finalizer, require its new systemd PID to publish the matching job, version, and
  release root, and keep restarted worker recovery behind a runtime gate until the definitive finalizer write completes.
  Require nginx plus web, worker, and console service state, and require the signed receipt, `current`, compatibility
  virtualenv, internal OpenAPI version, nginx management-front-door OpenAPI version, and candidate version to agree. Any
  failure after the switch must restore the previous release, helper/systemd assets, SQLite snapshot, and working nginx
  front door, write
  `rolled_back=true` with a sanitized failing layer, and fail both release child and parent. Worker startup must reject
  a success finalizer that disagrees with the durable active release or running version. Signed-release lifecycle
  coverage must prove the candidate and a healthy rollback both before and after audited appliance reboots; installation
  itself must not reboot automatically.
- Release publication recovery must use the protected **Publish appliance release** manual dispatch with the exact
  successful `main` push CI SHA. Atlaso starts a new signed update lineage at `v0.9.18`; do not publish or consume a
  retired-product bridge. Preserve tag/release commit and asset-byte idempotency checks. A rerun after tag/release
  publication must verify the existing asset bytes before retrying channel advancement. The VMware export helper may
  append one complete OVF asset set to that exact release without overwriting; recovery must validate its manifest, two
  payload VMDKs, four-disk descriptor topology, optional byte-equivalent OVA, and per-asset size boundary. Require a
  byte-bound build provenance record for the exact clean source commit and resolve the destination repository's tag to
  that commit before upload. Annotated tag creation must
  supply its own non-secret GitHub Actions bot identity rather than depend on runner-global Git configuration.
- Keep the GitHub Pages root as a static, dependency-free informational release-repository page generated by the
  publication workflow. Signed updater documents remain under `/updates`; the landing page must not become part of the
  appliance trust contract or introduce JavaScript, external assets, secrets, or unsigned release-selection behavior.
- Treat the signed `stable` channel as a required Pages invariant because it is the shipped Appliance Update default.
  Every workflow that writes `gh-pages` must refuse to publish a final tree without both stable pointer files. Release
  and promotion workflows must then re-fetch the live pointer, detached signature, immutable release manifest, and its
  signature; verify the named checked-in key, channel-to-release identity, and CPython 3.14 compatibility before
  reporting publication success.
- Durable automation runs in the separate `atlaso-worker.service`; the web process creates schedules and queued jobs but
  does not execute them inline. Keep schedule task types allowlisted to Appliance Update check/install, VCF Offline
  Depot downloads, and enabled immutable managed-script revisions. Revalidate mutable dependencies when the worker
  claims a job, including rejecting VCF Offline Depot downloads whose profile was disabled after queueing. Skip
  missed/overlapping runs instead of replaying them, preserve schedule-to-task execution history, and mark an in-flight
  job failed if the worker restarts.
- Keep the Automation workspace as three full-space tabs: Schedules, Executions, and Managed Scripts. Add/edit schedules
  use the five-step wizard (identity/type, type-specific configuration, timing, state, review); timing uses the friendly
  cron builder with Custom as the advanced five-field escape hatch. Schedule State is directly editable with the
  standard enable/disable control, while Run now, Edit, and Delete belong in the row context menu. Executions must link
  every scheduled job to `/ui/management/tasks`.
- Keep the generic Automation add/edit wizard at five steps. A selected VCF Offline Depot row instead opens the shared
  `createWizard(...)` schedule form in place with exactly Schedule, Timing, State, and Review. The server fixes both
  `vcf_depot_download` and the path-selected profile ID; do not render task-type or profile selectors in this contextual
  flow, navigate away from the depot page, or fork schedule validation and persistence behavior.
- Managed scripts are immutable revisions executed as the unprivileged `atlaso-automation` account through the
  constrained helper and transient systemd units. Creation uses the shared four-step wizard for identity, runtime,
  initial source, and review, and stores revision 1 disabled. Grid edits to revision-owned fields create a new disabled
  revision. Existing-script source editing uses the large Monaco Editor modal with local-file import. The revision cell
  opens a near-full-window, two-column comparison when at least two revisions exist; use the light Atlaso modal style,
  list every revision with its creation date and state in base/comparison selectors, keep corresponding rows and line
  numbers aligned, collapse long unchanged runs, color additions/removals, and use a Prism grammar selected from the
  interpreter. Manual execution is labeled **Run latest revision**, opens a parameter modal before creating the task,
  and uses the same literal argument syntax as schedules: backslash continuation for Bash/Python and backtick
  continuation for PowerShell. Never evaluate arguments through a second shell and never accept secrets as parameters.
- VCF/ESX password vaults are admin-only and encrypted with the appliance secrets key. A managed-script job carries
  the selected vault ID plus its non-reusable scope fingerprint; the worker must verify both before decryption. Stage
  decrypted values under `/run`, pass them through systemd `LoadCredential`, remove them after
  execution, and keep `atlaso-vault` fail-closed outside that credential context. PowerShell receives
  `Get-AtlasoVault`; Bash/Python use `atlaso-vault`. Redact exact values from helper and worker output.
- Vault entries may carry at most nine credential-free HTTP, HTTPS, SSH, or SFTP URIs. Kickstart markers address them
  by one-based position. HTTP and HTTPS row actions may open a new browser tab. SSH and SFTP row actions require an
  applied Web Terminal, explicit SHA-256 host-key confirmation, a short-lived one-use launch, and a second host-key
  check before server-side password authentication. Never place the password or an authenticated URI in browser launch
  state, response, audit events, or logs.
- Packer is a Windows-host prerequisite for the Photon image path; Hyper-V and `qemu-img` may already be available
  locally but should still be checked in handoff notes.

## Photon VM Debugging Notes

- The Hyper-V management NAT appliance address used during the first Photon bring-up was `192.168.49.1`; verify the
  actual current address before assuming it with `scripts/windows/hyperv/get-atlaso-vm-ip.ps1`, Hyper-V Manager, or SSH.
- Current live test appliance access for this lab: web UI `https://192.168.49.1/` with `admin` / `VMware01!`; SSH with
  `root` / `VMware01!`. These are local lab test credentials only, not production secrets. If connectivity fails, verify
  the VM IP first because Hyper-V NAT addresses can drift.
- Use the running Photon VM for real functionality checks after appliance-impacting changes: validate local tests first,
  then install/test on the VM when behavior depends on Photon, Hyper-V NICs, systemd, nftables, dnsmasq, resolver state,
  or `/ui/management/appliance-apply`.
- Hyper-V lifecycle interop tests must use a completely separate VM set from the normal `Atlaso` test appliance. Prefer
  `scripts/windows/hyperv/invoke-lifecycle-test.ps1` for one-command runs; it prepares the tiny Linux client image,
  picks the latest appliance VHDX, runs the test, validates backup/restore by redeploying the appliance and comparing
  pre/post restore client certificate identity plus restored CA archive fingerprints, and cleans up created lifecycle
  VMs by default. Use `-SkipBackupRestoreTest` only when the older single-pass run is intentionally needed, use
  `-KeepVms` only for debugging, and use `-PrepareNetworksOnly`, `-CleanupVmsOnly`, and `-CleanupNetworksOnly` for
  explicit Hyper-V lab maintenance. Network cleanup must remain opt-in and refuse removal while VMs are attached to
  Atlaso switches.
- VMware Workstation lifecycle interop tests use VMX/VMDK artifacts and `vmrun.exe` through
  `scripts/windows/vmware/invoke-lifecycle-test.ps1`. Keep Workstation lifecycle VMs under
  `test-results/vmware-workstation-lifecycle/`, keep Workstation management on a subnet separate from Hyper-V such as
  the default `192.168.167.0/24`, validate vmnet topology with `scripts/windows/vmware/prepare-networks.ps1`, and keep
  Hyper-V lifecycle evidence authoritative for exact access/trunk VLAN behavior because Workstation vmnets are isolated
  layer-2 segments rather than Hyper-V-style VLAN port policies.
- Any newly implemented appliance feature that affects deployed behavior must be added to the Hyper-V lifecycle coverage
  and validated through the lifecycle test before the feature is treated as complete. Keep the feature's local/unit
  tests in place, but use the lifecycle run as the interop acceptance check for Photon, Hyper-V networking, service
  apply behavior, and client-observable results.
- For the default VMware test appliance, resolve the current IP with `scripts/windows/vmware/get-atlaso-vm-ip.ps1` and
  check web reachability with `Invoke-WebRequest https://<vmware-ip>/openapi.json -SkipCertificateCheck`. Use the
  bootstrap `admin` account for SSH connections and run privileged checks through password-backed `sudo`; do not assume
  root SSH is enabled on VMware test appliances. Check SSH/service state with `systemctl status atlaso --no-pager`,
  `journalctl -u atlaso -n 120 --no-pager`, and relevant real-state commands such as `nft list ruleset`,
  `resolvectl query <name>`, `getent hosts <name>`, `ip link`, `systemctl status ntpd --no-pager`, or
  `systemctl status systemd-timesyncd --no-pager`.
- When the appliance web UI is unreachable, separate network reachability from service reachability: use host-side
  `Test-Connection <ip>` for ICMP, `Test-NetConnection <ip> -Port 8000` for the web service, and in-guest
  `systemctl status atlaso --no-pager` plus `journalctl -u atlaso -n 120 --no-pager`.
- ICMP can be intentionally blocked by nftables while SSH and TCP/8000 still work. Do not treat failed ping as proof
  that the VM is down; check TCP ports and Hyper-V console before changing networking.
- For VMware live appliance patching, prefer `scripts/windows/vmware/deploy-wheel.ps1`; it builds a local wheel, uploads
  it with `scp`, installs it into `/opt/atlaso/.venv`, syncs `scripts/appliance/atlaso-helper` to
  `/opt/atlaso/bin/atlaso-helper`, provisions every checked-in public release key under `/etc/atlaso/update-trust.d`,
  restores venv permissions, restarts `atlaso.service`, and verifies guest plus host `/openapi.json` with a readiness
  retry. The default deploy also builds and installs the independently versioned Inventory Linux package; use
  `-SkipInventoryLinuxSync` only for a code-only patch that intentionally preserves existing boot media. Packer image
  definitions must explicitly stage `image/common/update-trust`, and provisioning must fail rather
  than build an appliance with no valid public release key. Use `-IpAddress <appliance-ip>` when the VM IP is known, or
  `-VmxPath "<path-to-vmx>"` for VMware discovery; do not pipe the VMX path or put the `.vmx` path on a separate line
  because PowerShell will try to execute it. If uvicorn needs longer after reinstall, pass
  `-ReadinessTimeoutSeconds 120`. Use `-SkipHelperSync` only when the appliance helper is intentionally unchanged.
- The wheel helper's `RemoteDirectory` is one shared pre-upload contract for key/agent and password-backed SSH. Accept
  only absolute POSIX paths composed of ASCII letters, digits, `/`, `.`, `_`, and `-`, reject `.` and `..` components,
  whitespace, shell metacharacters, and control characters before local build work, and serialize every key-backed
  remote command argument with the shared POSIX quoting helper. Do not depend on `scp` version-specific remote quoting.
- For manual live appliance patching, build a local wheel with `python -m pip wheel . -w dist`, copy only the Atlaso
  wheel to the VM, install it with `/opt/atlaso/.venv/bin/python -m pip install --force-reinstall --no-deps`, then
  restore venv readability for the `atlaso` service user with directory `0755`, file `0644`, and executable bits under
  `.venv/bin`.
- After installing a live wheel, restart with `systemctl restart atlaso` and verify both `systemctl is-active atlaso`
  and internal `curl http://127.0.0.1:8000/openapi.json` from inside the guest, then verify the host-facing console/API
  with `Invoke-WebRequest https://<ip>/openapi.json -SkipCertificateCheck` from Windows.
- If `atlaso.service` fails with `status=203/EXEC`, check execute permissions on `/opt/atlaso/.venv/bin/python` for the
  `atlaso` user. If it fails importing static/templates, confirm package assets are included in the wheel and that
  `base.html` static query strings changed after JS/CSS edits.
- Real firewall apply stages rendered nftables config under `/var/lib/atlaso/apply/firewall/atlaso.nft` as the `atlaso`
  service user before invoking the root helper. Keep `/var/lib/atlaso/apply` and its firewall child owned by
  `atlaso:atlaso`; root-owned staging files cause `/ui/management/appliance-apply` to fail before a job is recorded.
  Atlaso-managed
  service allow rules are generated from enabled service listener desired state, including management, DNS, DHCP, KMS,
  VCF Backup, VCF Offline Depot, and VCF Private Registry. Atlaso-managed routing rules allow route-role network pairs
  and explicit access routing permissions, while always dropping management-to-lab and lab-to-management forwarding.
  Managed DNS/service listener rules default to the built-in `Any` group; operators can create, rename, remove, and
  assign firewall groups containing `any`, CIDRs, addresses, or other groups when rule sources or destinations need
  narrower access. DHCP bootstrap rules are interface-bound UDP/67 for IPv4 zones and UDP/547 for IPv6 zones and should
  not be group-filtered. Changing a DHCP scope interface, service listener, or routing permission should make the
  Firewall apply unit move the generated rule to that same bind target.
- Validate actual firewall state with `nft list ruleset`, not only the UI preview. The helper should run
  `nft -c -f <staged file>` before apply; syntax errors such as placing `tcp` before `ip saddr` must fail validation and
  be fixed in the renderer.
- `atlaso-firewall.service` is a oneshot persistence service. It should be installed with
  `systemctl enable --now atlaso-firewall.service`; `enabled` plus `inactive` means it was not started after
  writing/enabling.
- Real DNS/DHCP apply stages rendered dnsmasq config under `/var/lib/atlaso/apply/dnsmasq/atlaso.conf` as the `atlaso`
  service user before invoking the root helper. The helper validates with `dnsmasq --test`, installs
  `/etc/atlaso/dnsmasq.d/atlaso.conf`, manages the Atlaso dnsmasq systemd drop-in, enables `dnsmasq`, and
  reloads/restarts the service. DNSSEC validation renders `dnssec` plus a Atlaso-managed trust-anchor include under the
  dnsmasq apply directory; the helper must verify installed dnsmasq DNSSEC support and copy package-provided trust
  anchors before `dnsmasq --test`. Rebind protection renders `stop-dns-rebind` plus explicit `rebind-domain-ok`
  exemptions, and query logging uses `log-queries=extra` only as a temporary troubleshooting setting because query names
  may be sensitive. Operator DNS records support A, AAAA, CNAME, TXT, SRV, MX, CAA, and explicit PTR, while A/AAAA still
  generate PTR answers through dnsmasq `host-record`. Authoritative mode renders every managed forward zone through one
  interface-bound `auth-server` plus shared SOA policy and generated NS/glue; dnsmasq treats those selected listeners as
  authoritative-only, while loopback and other non-authoritative listeners retain PTR and upstream-recursive behavior.
  When Appliance Settings resolver mode is DHCP and DNS upstreams are empty, use the management interface's observed
  DHCP DNS servers as dnsmasq forwarder fallback. If local DNS makes resolvectl loopback-only, resolve the exact
  management interface ifindex and read only its systemd-networkd lease through the constrained helper; filter loopback,
  unscoped IPv6 link-local, duplicate, malformed, and other-interface values, preserve explicit upstream precedence,
  and fail control-plane plus helper validation when DHCP fallback is required but unavailable. When converting the
  management DHCP lease to static, copy those observed DNS servers into Appliance Settings external DNS and DNS service
  upstreams if those settings were relying on DHCP. DHCP lease readback must use the allowlisted helper path for
  `/var/lib/atlaso/dnsmasq/dhcp.leases`, not
  arbitrary file reads. Validate actual DNS with direct queries against both the selected authoritative listener and a
  non-authoritative recursive listener such as appliance loopback, plus in-guest `getent hosts <name>` for
  appliance-local resolution, not only the UI preview.
- Real ESXi PXE apply stages JSON under `/var/lib/atlaso/apply/esxi-pxe/atlaso-esxi-pxe.json` as the `atlaso` service
  user before invoking the root helper. Kickstart source content lives in the database and is edited through the
  built-in Monaco Editor; generated files under `/var/lib/atlaso/pxe/http/esxi/ks/<id>.cfg` are derived runtime
  copies only. Saving a Kickstart must not write runtime files. Installer ISO choices are discovered from
  `/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST`, the VCFDT ESX host component folder; Atlaso may create that folder
  and upload additional operator-provided `.iso` files there. Host PXE definitions can reference both a database
  Kickstart and selected installer ISO path. Global `esxi_pxe` apply writes enabled Kickstarts, removes stale generated
  numeric `.cfg` files, writes HTTP `boot.ipxe` even without host profiles, validates selected ISO paths stay under the
  ESX_HOST folder, updates rendered/applied timestamps, and redacts root passwords, tokens, keys, licenses, and other
  secret-looking values from previews, diffs, jobs, logs, audit events, and final responses.
- Kickstart vault access is declared only through exact
  `{{vault.<vaultname>.<key>.<username|password|uri1..uri9>}}` markers. Saving and request-time rendering must validate
  every named vault, key, and subkey, resolve only those exact values, and fail closed without exposing secret values.
- Code and configuration editors use the locally bundled `window.AtlasoMonaco` integration with synchronized textarea
  form sources. Do not add another editor package, parallel initializer, or incompatible rendered attribute.
- Photon image provisioning must upload `third_party/ipxe` into the Packer source tree and stage bundled `undionly.kpxe`
  and `snponly.efi` under `/var/lib/atlaso/pxe/bootloaders`; fail the image build rather than silently producing an
  appliance where ESXi PXE validation cannot find first-stage boot files.
- Network Boot retains the `esxi_pxe` apply/helper identifiers. Its generic
  `/pxe/boot.ipxe` menu, Inventory Linux, and optional verified maintenance
  environments activate only through that global apply unit.
- Keep Inventory Linux reproducible and read-only: pin Buildroot source and
  digest, run from initramfs, collect only bounded hardware metadata, and never
  add filesystem mounts, block writes, a remote shell, or arbitrary commands.
- Publish Inventory Linux only through the protected **Publish Inventory Linux release** manual dispatch with the exact
  SHA of a successful `main` push CI run. Derive its `X.Y.Z+revision` version from the built package, sign deterministic
  release metadata with the Atlaso Ed25519 release key, and publish an immutable final
  `inventory-linux-v<version>` release without making it the repository-wide latest release. The matching versioned
  Pages metadata and `/updates/inventory-linux/latest/` pointer must advance monotonically in the same commit while
  preserving documentation and appliance-update content. Existing tags, assets, or Pages metadata must be
  byte-identical on a rerun; fail closed on collisions. Do not attach Inventory Linux packages to ordinary appliance
  releases and do not add development, preview, or staging channels for Inventory Linux.
- Serialize every `gh-pages` mutation job through `atlaso-github-pages` with `queue: max` and
  `cancel-in-progress: false` so overlapping writers wait instead of replacing pending work. Build Inventory Linux and
  other long-lived prerequisites before acquiring that job-level lock; retain the lock from the fresh Pages checkout
  through the guarded push without weakening signature, immutable-release, monotonic-pointer, or byte-idempotency gates.
- Inventory report schema v2 uses sysfs as the authoritative source for bounded
  CPU/DIMM, NIC, disk/controller, PCI/USB, and system identity data. Continue to
  accept v1 and normalize it into retained v2 JSON without a database migration,
  enforce collection/string limits plus the 256 KiB report boundary, and use
  pciutils/pci.ids only to enrich readable names rather than submitting raw
  command output. Start the local five-minute reboot countdown only after a
  successful report; pause/resume preserves remaining time, local immediate
  reboot stays explicit, and acknowledged audited remote reboot is authoritative.
- Render retained inventory as escaped semantic report sections with explicit
  legacy not-reported states. Print only the selected report and export a
  self-contained no-cache JSON attachment with host identity, metadata, and the
  unchanged normalized payload. Discovered-host removal must transactionally
  delete its commands, sessions, reports, and host row while retaining separate
  ESXi desired state.
- Wake-on-LAN is an immediate audited UDP/9 magic-packet send for discovered
  hosts and saved ESXi Host References. Use only the server-owned MAC, deduplicate
  IPv4 broadcasts derived from effective Network Boot DHCP zones, perform no
  retries, and never represent packet send as proof that a host woke.
- Windows Inventory Linux and Photon builds use `Atlaso-Build` unless the caller explicitly selects another compatible
  WSL distribution. Treat WSL itself as a pre-existing prerequisite: no ordinary build or Atlaso setup path may enable
  Windows features, install WSL, elevate, reboot, change the default distribution, or remove an existing distribution.
  Keep the dedicated base archive and host-package contract pinned and recorded. Use the same explicit distribution for
  path conversion, readiness checks, native-Linux cache discovery, per-repository `flock`, and build execution. Hold a
  checkout-wide host lock through final artifact verification so different distributions cannot write the shared output
  concurrently. See [Windows image-build WSL environment](windows-image-build-wsl.md).
- `pxe-media-sync` may populate immutable verified cache versions, but must not
  alter active menu state. Fixed upstreams, HTTPS limits, pinned verification,
  allowlisted extraction, and atomic installation are mandatory.
- Permit distinct download jobs to queue behind the single FIFO worker and
  reject only an active duplicate for the same environment and download source.
  Enforce that admission atomically in the database across concurrent web
  workers, returning `409 Conflict` to competing requests. Preserve the stricter
  upload staging and cleanup guards.
- Preserve generic `read:pxe` and `write:pxe` isolation from legacy
  `read:esxi-pxe`. Never place inventory bearer tokens in URLs, logs, audits,
  jobs, or browser state; store only hashes and bind each session to one
  submitted host identity.
- Real VCF Backup apply stages the rendered OpenSSH drop-in under
  `/var/lib/atlaso/apply/vcf-backups/atlaso-vcf-backups-sshd.conf` as the `atlaso` service user before invoking the root
  helper. Provisioning leaves the default `vcf-backup` OS account absent until Local Users apply creates it; the VCF
  Backup helper validates the Atlaso-rendered `Match User` config and selected OS user, installs
  `/etc/ssh/sshd_config.d/atlaso-vcf-backups.conf`, prepares `/mnt/atlaso-vcf-backups/backups`, validates `sshd`, and
  restarts `sshd`. Firewall apply owns the selected interface/port allow rule.
- Real Appliance Settings apply stages JSON under `/var/lib/atlaso/apply/appliance-settings/atlaso-settings.json` as the
  `atlaso` service user before invoking the root helper. The helper validates resolver mode, management interface/IP,
  root SSH preference, and management nginx fields; sets the OS hostname to the appliance FQDN; local DNS mode sets
  management resolver DNS to `127.0.0.1` and `Domains=~.`; external DNS mode uses configured resolver servers and
  removes the catch-all domain; root SSH apply writes `/etc/ssh/sshd_config.d/atlaso-root-login.conf`, validates `sshd`,
  and restarts `sshd`; and management front door apply writes `/etc/nginx/conf.d/atlaso.conf`,
  `/etc/atlaso/nginx/sites.d/management.conf`, and a `atlaso.service` loopback override. Fresh appliances run
  `atlaso-bootstrap-https.service` on deployed-VM first boot to generate the integrated root CA and CA-managed
  `appliance:https` certificate; the root CA must not be baked into reusable images. Nginx redirects public HTTP/80 to
  HTTPS/443 and reverse-proxies HTTPS to uvicorn on `127.0.0.1:8000`. Appliance FQDN or management IP changes should
  reissue the managed leaf certificate automatically; root CA replacement remains an explicit rotation workflow. When
  HTTPS is disabled or factory reset is applied, nginx serves public HTTP/80 as a plain reverse proxy to the same
  loopback upstream and does not expose a management HTTPS listener. The helper reloads nginx/systemd, then schedules a
  short delayed `atlaso.service` restart so the apply job can be recorded.
- The web terminal is off by default, requires management HTTPS, and always includes management when enabled. Configure
  additional addressed interfaces with the shared tag editor; keep the management tag locked and reject missing,
  disabled, trunk-only, unused, or addressless selections. Additional selected addresses receive only login/logout,
  terminal, WebSocket, and static-asset nginx routes plus Firewall-owned TCP/443. Never expose dashboard or API routes
  on those listeners.
- Web SSH authorization is an explicit per-local-user checkbox, default off except for the newly provisioned bootstrap
  administrator. Require the user to be enabled with an interactive shell and an applied Photon password. Enforce the
  permission on the terminal page, ticket creation, WebSocket attachment, and public-terminal login; do not infer access
  from a Atlaso role.
- The management terminal lives under Operations. A terminal opened on an additional selected interface must extend
  `public_portal_base.html`, use the Public Services login/sign-out experience, and must not render the admin
  application shell. The terminal connects automatically and keeps one bounded server-side shell per authorized user so
  reloads and short WebSocket interruptions reattach to the same working directory and buffered output. A second browser
  must confirm takeover; takeover moves the existing shell and disconnects the old attachment instead of starting or
  ending the shell. Treat `Ctrl-D` and the `exit` command as intentional shell termination, then retain the transcript
  in a disconnected state with an in-terminal reconnect action.
- Keep terminal copy and transcript-download actions as compact icons inside the terminal's top-right corner.
  Disconnected terminals use the lighter terminal background; session-moved and reconnect messages are terminal
  overlays, while copy/download success uses the shared transient notification behavior above the footer.
- Use a root-owned Ed25519 OpenSSH user CA, one-use browser tickets, ephemeral keys, loopback-only 60-second
  certificates, pinned local host keys, and bounded idle/lifetime/input/output limits. Never expose the CA private key,
  allow root certificates, forwarding, X11, agent use, user RC, or passwordless `sudo`.
- Real NTPsec apply stages `/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf` as the `atlaso` service user before invoking the
  root helper. NTPsec owns appliance time service behavior; Appliance Settings no longer owns the NTP client. Fresh
  desired state uses the structured upstream grid with NTS-enabled `time.cloudflare.com` and `nts.netnod.se` rows,
  including descriptions. Per-upstream NTS client mode renders `nts` on source lines; NTS server mode renders
  `nts enable`, the CA-managed certificate chain and key, and persistent cookie storage under `/var/lib/ntp/nts-keys`.
  The renderer ignores every interface before explicitly listening on selected addresses, uses restrictive client rules
  that still permit time service, and maps minimum sources to `tos minsane`. Firewall apply owns TCP/4460 NTS-KE access
  in addition to UDP/123. The helper requires Photon `ntpsec`, installs `/etc/ntp.conf`, grants the NTS key `root:ntp`
  mode `0640`, disables competing daemons, enables/restarts `ntpd.service`, and exposes bounded source health through
  `ntpq -pn`, `ntpq -c rv`, and `ntpq -c ntsinfo`. When NTS server mode is disabled, NTP apply removes the managed
  server certificate/key and cookie directory without clearing authenticated client sources. The one-time
  `ntp_nts_restoration_v1` reconciliation re-enables and normalizes only canonical Cloudflare and Netnod default rows,
  records a value-free system audit, leaves custom sources unchanged, and never enables NTS server mode.
- NTPsec NTS controls must reflect the installed `ntpd` feature set. Detect capability through the allowlisted
  `atlaso-helper ntpd capabilities` path; when NTS is unavailable, disable the server switch and upstream NTS editors,
  normalize saved NTS state off, reject NTS enable attempts, and keep ordinary NTP behavior available. A temporarily
  unknown probe must preserve desired NTS state while blocking unsafe NTP apply. Do not imply that packaged/default
  upstream choices guarantee local NTS support.
- Appliance Settings and Web Terminal autosave own no NTP/NTS fields. Enabling or editing Web Terminal must not change
  upstream NTS flags, NTS server state, `ntp:nts` certificate ownership, rendered NTP configuration, or NTP apply
  selection.
- The Logs page fixed source set is Atlaso App, KMS, NTPsec, Nginx, DNS, DHCP, TFTP, and Audit Events. DNS, DHCP, and
  TFTP must remain classified views of one allowlisted `dnsmasq.service` journal read, with `dnsmasq-dhcp` and
  `dnsmasq-tftp` lines routed to their protocol tabs and base/service lines routed to DNS. Keep logs read-only and
  redacted, auto-refresh every five seconds, and offer 100/200/500-line tail selection. Apply the shared log syntax
  highlighting to timestamps, severity levels, components, identifiers, addresses, and redaction markers both on initial
  render and after refresh. Keep source details in tab hover tooltips instead of repeated panel headings, disable
  unavailable source tabs, and move away from an active tab if its source becomes unavailable. NTPsec, Nginx, and
  dnsmasq journal reads must use their allowlisted helper actions. Do not restore the retired VCFDT Logs tab without a
  new explicit requirement.
- The Tasks grid owns backend filtering and pagination. Keep Status and State as fixed list filters; build Task /
  Component choices from recorded job types and component labels while allowing a custom fragment. Leaf jobs must not
  show a tree expander. Task detail modals retain wrapped, syntax-highlighted redacted JSON payloads for auditing, but
  Console output must remove the helper action envelope and show only process stdout/stderr with stderr in red. Keep
  result, console, and log previews constrained within the modal and viewport, overlay copy/open controls without
  reserving blank text rows, and do not style read-only payloads as form controls.
- The authenticated account menu owns About, username-aware sign out, and admin-only Reboot/Shutdown actions. Power
  actions must use the shared confirmation modal, create and commit an auditable task before helper invocation, and
  schedule the real host action through the constrained helper with a delay that lets task/audit persistence finish.
  Fail closed if delayed scheduling is unavailable; never execute an immediate fallback power action.
- Real CA apply stages JSON under `/var/lib/atlaso/apply/ca/atlaso-ca.json` as the `atlaso` service user before invoking
  the root helper. The helper validates the staged CA/certificate payload, writes public CA bundles and service
  certificate/key files under `/etc/atlaso`, and must not print private keys in stdout, stderr, previews, jobs, docs, or
  final responses. CA custody and managed certificate deployment do not require a public listen interface. Selecting a
  CA interface is the explicit publication boundary for the portal, DNS, firewall, and public-service configuration.
  The public CA portal defaults to `ca.atlaso.internal`: `/ui/public/ca` shows public trust material and
  `/ui/public/ca/requests` is the authenticated certificate request/revocation workflow. Do not put Certificate
  Requests in the primary Atlaso sidebar; link it from CA-associated surfaces instead. Every selected NTS server apply
  automatically includes the CA material unit and preserves CA-before-NTP execution order, even when the CA baseline
  appears current.
- Real internal `kms` apply stages strict JSON and the public-only trust bundle at fixed paths under
  `/var/lib/atlaso/apply/kms`. vSphere Key Providers can be activated only when CA desired state is enabled and healthy;
  `/ui/management/vsphere-key-providers` derives IPv4 and IPv6 listen addresses, creates app-owned DNS records, and
  auto-ensures only the shared KMS server CA row. The only backend is `atlaso-kmip`; expose no backend or
  server-certificate selector.
  Keep hostname near the top of the DNS-style settings rail, stack listen interfaces and derived addresses, and keep
  port compact. The helper validates exact JSON, fixed paths, ownership, modes, symlink resistance, CA-managed server
  identity, provider UUIDs, globally unique exact fingerprints, and resource limits. It installs
  `/etc/atlaso/kmip/server.json` and `/etc/atlaso/kmip/client-trust.pem` and manages the hardened unprivileged service.
  The trust bundle contains only the internal CA public root and imported public vCenter certificates. Never generate,
  accept, export, or expose a vCenter client private key or plaintext operational key material.
- The Python `atlaso-kmip` service implements only the candidate VCF 9.1 contract in
  `atlaso/app/kmip/contracts/vcf_9_1.json`; keep the implementation experimental until issue #172 records the live
  VCF 9.1 acceptance and recovery evidence required to promote the contract to `observed`. A provider UUID defines an
  isolated key namespace and may trust multiple provider-scoped vCenters; every exact certificate fingerprint maps to
  one provider appliance-wide. LDAP organizations do not select providers. Generate only AES-256 keys, wrap
  operational keys with AES-256-GCM under a KEK protected by
  `ATLASO_SECRETS_KEY`, and never expose plaintext keys outside the authorized KMIP `Get` response. Reject operations,
  objects, algorithms, formats, and attributes outside the contract. Interop traces contain metadata only and must pass
  `scripts/kmip/validate_interop_trace.py`; raw TTLV and secret-bearing fields are forbidden. Recovery uses a separate
  passphrase-encrypted bundle in issue #172.
- Real VCF Offline Depot apply stages nginx config under
  `/var/lib/atlaso/apply/vcf-offline-depot/atlaso-vcf-offline-depot.conf` as the `atlaso` service user before invoking
  the root helper. Uploading `vcf-download-tool-*.tar.gz` uses a shared two-step package wizard and remains desired-state
  only: validate/store the package and clear
  stale generated metadata, but do not extract, create runtime folders, invoke VCFDT, or generate a software depot ID
  from the upload route. Global `vcf_offline_depot` apply must validate the staged nginx site, run `stage-tool` to
  extract the archive under `/opt/atlaso/vcf-download-tool/extracted`, expose
  `/opt/atlaso/vcf-download-tool/vcf-download-tool` as the stable executable wrapper, record the tool version using
  `--version`, and apply `application-prodv2.properties`. It must preserve an existing software depot ID during ordinary
  settings and download-profile applies. Generate an ID only when none is recorded or the operator explicitly submits
  the software depot ID refresh action; then read the persisted identity back with
  `vcf-download-tool configuration get --software-depot-id`, store only one unambiguous canonical readback value, sync
  intent, and apply HTTPS. Preserve the old ID when generation itself fails. If generation succeeds but canonical
  readback fails, invalidate the stored ID because VCFDT may already have replaced its runtime identity. The helper must
  remove both runtime credential files immediately after the generation command succeeds, and Atlaso must remove both
  staged credential records when the result contains a new canonical ID or identity-invalidated marker. Preserve both
  credential locations when generation itself fails before changing the identity. The helper
  validates CA-managed
  `vcf_offline_depot:https` cert/key paths, server name/listener uniqueness, document root, auth mode, selected local
  HTTP user, and static-file directives, then installs or removes `/etc/atlaso/nginx/sites.d/vcf-offline-depot.conf`,
  writes `/etc/atlaso/nginx/htpasswd/vcf-offline-depot.htpasswd` from the applied Photon password hash when
  authentication is required, and reloads nginx. The non-grid settings rail exposes one VCFDT configuration summary;
  its five-step shared `createWizard(...)` flow starts with the current Software Depot ID and refresh intent, then
  covers a standard select-based, presence-only Broadcom credential choice, a conditional upload-or-paste step,
  `application-prodv2.properties`, and review. Credential and
  application-properties changes must use one transactional desired-state save. The wizard must never preload stored
  credential values, must prefer an uploaded credential file over pasted text, and must return only presence flags,
  safe display names, the version parsed from the validated staged archive name, properties metadata,
  validation/previews, and Software Depot ID metadata. Credential choices are state-aware: omit Keep when none is
  staged, use Replace only for present inputs, require choosing which absent input to use, and hide the credential-input
  step when Keep is selected. The bundled Monaco application-properties editor must remain writable, synchronize its
  source textarea, and avoid a wrapping label that can steal pointer focus from the editor. If refresh is selected,
  hide the credential and properties steps so the rail contains only Software Depot ID and Review, without resaving
  unchanged configuration; Review is the explicit confirmation boundary and must create a dedicated
  `vcf-depot-software-id` task, not call the helper directly or route identity generation through global Appliance
  Apply. When no ID exists, generation is selected and cannot be cleared. Review immediately dispatches the dedicated
  task and opens the ordinary Tasks workflow. Its safe child operations stage the VCFDT tool, apply application
  properties and the CEIP prerequisite, then generate/read back the identity. The task succeeds only after a non-empty
  ID is persisted, and refresh additionally requires a different ID. It must not validate, sync,
  or apply nginx, update the VCF Offline Depot apply baseline, or open the global Appliance Apply monitor.
  Identity tasks, profile-download tasks, and Appliance Apply tasks containing `vcf_offline_depot` must share one
  admission boundary. Distinct profile downloads may be pending together in FIFO order, with an atomic database-backed
  unique guard deduplicating the same profile across manual and scheduled callers. Exactly one VCFDT operation may be
  running. Software Depot ID tasks and Appliance Apply containing `vcf_offline_depot` remain exclusive across both
  queued and running downloads, so their admission must wait until the profile-download queue drains and their own
  pending/running state must block new downloads. Software Depot ID identity tasks are non-cancellable from admission
  onward because a claim race or already-running helper may have replaced the runtime identity. Startup recovery for an
  interrupted running identity task must perform a read-only canonical VCFDT
  ID readback before finalizing the task: persist a changed runtime ID and clear obsolete credentials, or invalidate
  the stored ID and credentials when runtime identity cannot be verified.
  Resetting VCFDT staging is one destructive confirmation that always clears the staged package, both Broadcom
  credentials, saved application properties, generated identity/version metadata, and profile enablement; it must not
  offer a partial configuration-preservation mode.
  Review must state that both staged credentials are removed after identity replacement. The settings-rail Depot ID
  ready state uses the shared clipboard action with accessible labeling and transient completion feedback.
  Tool staging and Software Depot ID generation must not depend on the HTTPS service-enabled toggle. Ordinary wizard
  saves must preserve an existing ID.
  Manual
  VCFDT command generation
  should use `/var/lib/atlaso/vcfDownloadTool/active-tool` token and activation-code file paths, write telemetry and ESX
  disabled-platform config without exposing secret contents, and model patch-only separately from upgrade-only. Download
  tokens and activation codes can be preserved together or replaced one at a time in the VCFDT configuration wizard;
  files or pasted text still become the runtime credential files used by VCFDT and existing storage keys remain as compatibility
  aliases. Metadata profiles appear first by default, followed by binaries and ESX with deterministic name/ID
  tie-breaking; user sorting may reorder them while the shared add row remains pinned last.
  Manual profile starts create `vcf-depot-download` background jobs that write runtime credential files under
  `/var/lib/atlaso/vcfDownloadTool/active-tool/secrets`, run VCFDT as the `atlaso` service user, and update job/profile
  status from the process exit code; missing profile credentials should disable only the profile Start button and must
  not block applying or disabling the depot service. Enabled VCF Offline Depot profiles are selectable in the real
  Automation scheduler and execute as the same durable `vcf-depot-download` jobs as manual starts. The application
  must admit both paths through one atomic database-backed per-profile guard, queue distinct profiles in deterministic
  FIFO order, claim no more than one VCFDT runtime operation, revalidate tool/profile/credential prerequisites at claim,
  record same-profile or exclusive-operation scheduled collisions as skipped Jobs, and preserve terminal
  task/log/audit evidence. Startup recovery fails only interrupted running downloads and retains never-claimed pending
  downloads. Manual Start success and failure use the standard accessible bottom-right transient grid status/error
  foundation rather than a depot-specific inline message, while durable task, audit, and log evidence remains intact.
  Disabling a profile or resetting the tool disables attached schedules without re-enabling them later;
  profile deletion is blocked while any schedule references it. Schedule configuration stores only the stable integer
  `profile_id` and never credentials, authenticated URLs, generated commands, or secret-bearing output. The application
  properties editor in the shared VCFDT configuration wizard saves desired-state text and syncs Monaco Editor before
  submit; global apply writes the runtime properties used by the active tool. Depot private keys, HTTP user
  passwords/hashes, and VCFDT credential contents must
  remain path references or presence flags only; never print key contents, token values, activation-code values, private
  keys, passwords, or password hashes in previews, jobs, logs, docs, or final responses.
- When testing real apply from the UI, select only the intended apply unit. Existing appliances that predate factory
  baseline initialization may still list units without a last-applied baseline as changed; unselect unrelated units
  before submitting.
- Check the latest appliance apply job directly when behavior is unclear: query `Job` rows in the appliance SQLite
  database or inspect the rendered job JSON in the UI. A failed job can still leave host state unchanged if helper
  validation failed before apply.

## ESX Storage

- Real ESX Storage apply stages JSON under `/var/lib/atlaso/apply/esx-storage/atlaso-esx-storage.json`. IPv4 and IPv6
  are equal v1 requirements: one share may enable either or both on one selected interface/VLAN, and each enabled family
  requires its own listener, generated A/AAAA target name, VMkernel client allowlist, ESX command, and nftables rule.
- Keep datastore enablement editable through the standard boolean grid icon and a dedicated State step after Clients in
  the add/edit wizard. Put enabled-share mount guidance in the dedicated Connection Instructions tab, render equivalent
  family-specific ESXCLI and PowerCLI commands with compact copy actions, and preserve the active ESX Storage tab across
  reloads.
- Blank disks require stable `/dev/disk/by-id` identity plus job/manifest/device-bound `FORMAT <volume-name>`
  authorization and immediate helper revalidation before whole-device ext4 formatting. Mount by UUID under
  `/mnt/atlaso-esx-storage`, bind shares under `/srv/atlaso/esx-storage`, preserve formatted data on later failure, and
  never add wipe/reformat/data-delete behavior.
- Existing mounted ext4 sources must be writable whole disks with stable `/dev/disk/by-id` identity, no partitions or
  holders, an active UUID-matching mount, and an exact UUID-backed `/etc/fstab` entry. Real apply records each accepted
  source in root-owned `/etc/atlaso/esx-storage-disks.conf`; first-boot disk verification admits no unclaimed extra disk.
- Nginx, the HTTPS bootstrap, Atlaso control plane, and worker require successful `atlaso-data-disks.service` completion.
  Ordering without a hard systemd dependency is insufficient because precreated mount directories could otherwise
  accept writes on the Photon root filesystem after a disk-safety failure or expose a misleading front door.
- Apply only through global `/ui/management/appliance-apply`. Settings backup and restore include volume/share desired
  state but never
  format authorization. iSCSI remains a separate kernel/target-stack feasibility issue.

## Network And Service Binding

- Physical Interfaces are for untagged/access networks. VLAN Interfaces are only for tagged VLAN networks on physical
  parent interfaces marked as trunk.
- VLAN Interfaces use a wizard-backed Tabulator that reuses the ESX Storage interaction. The collection is read-only:
  add and edit must review parent, VLAN ID, derived name, addressing, MTU, role, and Admin Up together through the shared
  wizard. This is the approved exception to the ordinary inline-Enabled rule. New VLANs default to Admin Up; edits
  preserve the saved value. A missing-parent VLAN may remain saved only while disabled and must move to an available
  trunk before enablement. Saving remains desired-state-only and global `/ui/management/appliance-apply` owns network
  enforcement.
- Physical Interfaces automatically refresh observed Photon/Hyper-V NIC inventory on appliance startup and may also
  refresh it manually from the page, but host inventory is read-only context; desired-state edits remain separate and
  enforcement still goes through `/ui/management/appliance-apply`.
- Host NIC reconciliation must match observed adapters by MAC address before Linux interface name. When a host NIC
  disappears, mark the missing physical interface inert, set dependent VLANs disabled/admin down where modeled, remove
  the missing interface and derived IP addresses from service listeners, disable services left without any listener, and
  log/audit the cleanup so operators are not trapped behind invalid appliance-apply state.
- Real network apply is Photon `systemd-networkd` backed. It may install Atlaso-owned `.network`/`.netdev` files under
  `/etc/systemd/network/`, reload networkd, reconfigure non-management links, create/update desired VLAN links, and
  delete VLAN links explicitly derived from successful Atlaso network apply history. The appliance image's default
  management networkd file should match only `eth0`, not `eth*`/`en*`, and Atlaso should retire Photon catchall network
  defaults such as `50-static-en.network` and `99-dhcp-en.network`. The default desired state keeps management on `eth0`,
  but an operator may assign the single dedicated management role to another physical interface or use only flagged
  access listeners. Do not blindly reconfigure a dedicated management link without reachability safeguards. When one
  exists, management uses its own policy-routing table and must never forward traffic from or to access/route networks;
  non-management lab routes use the lab route table.
- Do not offer trunk physical interfaces as direct service bind targets. Service bind selectors should include access
  physical interfaces with an IPv4 or IPv6 CIDR and enabled VLAN interfaces with an IPv4 or IPv6 CIDR.
- When a service bind target is selected, derive IPv4 and IPv6 listen addresses from the selected interface or VLAN
  CIDRs. Do not ask the user to enter separate bind IPs unless the service genuinely supports unrelated explicit listen
  addresses.
- If a VLAN has dependent state, protect parent interface mode changes that would invalidate it. A physical interface
  with VLAN children should not be silently changed from trunk to access.
- Validate required network creation fields before saving. For VLANs, do not persist a new VLAN row unless the parent,
  VLAN ID, at least one valid IPv4 or IPv6 CIDR, MTU from 576 through 9000, and a supported role are present. Reject a
  duplicate parent/VLAN ID pair and reject enablement when the parent is missing or not an available trunk.
- Keep the validation/config preview current after any network or service change that affects rendered appliance state.

## Public Services Front Door

- Management-role interface addresses dispatch `/` to `/ui/management`; all authenticated management pages and their
  browser-only support/action endpoints stay under that canonical root.
- A management-role physical interface exposes the management UI inherently and has no exposure flag. Access-role,
  access-mode physical interfaces and enabled access-role VLANs may set `access_management_ui_enabled`. They remain
  ordinary access interfaces for routing, service selectors, public UI, and public services. Allow at most one dedicated
  management role, allow multiple flagged access listeners, and reject state with neither an effective dedicated role
  nor an active flagged access listener. A management-to-access conversion enables the flag atomically; an
  access-to-management conversion clears it.
- Non-management interface addresses dispatch `/` to an unauthenticated public service directory at `/ui/public`
  scoped to the called IP/host. The page must list only enabled public services whose desired listen addresses include
  that IP, and must show
  a minimal `No public services on this interface` state when none match.
- When web terminal access is enabled for the called non-management interface, include a `Web Terminal` service tile
  linked to that address's HTTPS `/ui/public/terminal` route. Do not show the tile on unselected interfaces, and do not
  invent an interface DNS name for the Name/IP toggle.
- App-owned public pages must also be IP-scoped: CA `/ui/public/ca`, certificate requests
  `/ui/public/ca/requests`, and Web Terminal `/ui/public/terminal`. Keep CA downloads
  `/ca/downloads/root-ca.pem` and `/ca/downloads/ca-bundle.pem`, ESXi PXE `/pxe/esxi/`, VCF Offline Depot `/PROD/`,
  and VCF Private Registry canonical URLs outside `/ui` as stable machine/protocol contracts.
- An unflagged public listener must return not found for `/ui/management` without rendering login behavior or the
  management shell. A flagged access listener cohosts both planes: `/` prefers `/ui/management`, the authenticated
  management shell offers a Public services link, and `/ui/public` remains available. A dedicated management listener
  must not publish `/ui/public`. Safe eligible root-level browser bookmarks use temporary
  same-host redirects. Legacy mutations bridge internally to canonical handlers and must never use replaying redirects.
- Do not add `/registry` reverse proxying in the public-services site. Registry DNS and canonical registry URLs remain
  service-owned.
- Public Services apply stages `/var/lib/atlaso/apply/public-services/atlaso-public-services.conf` as the `atlaso`
  service user before invoking the root helper. The helper installs `/etc/atlaso/nginx/sites.d/public-services.conf`,
  reloads nginx, and keeps management nginx config separate.
- The generated public-services nginx config should create HTTP server blocks only for ESXi PXE service IPs, redirect
  `/pxe/esxi` to `/pxe/esxi/`, proxy dynamic PXE requests to the app, serve PXE static content through a narrow nginx
  alias, and avoid exposing public portal, CA, request, depot, management, broad depot roots, registry, or unrelated
  service paths over HTTP.
- VCF Offline Depot `/PROD/` is exposed through the depot service-owned HTTPS site, not the generated public-services
  HTTP site. In authenticated mode, app-owned directory browsing routes redirect unauthenticated users to `/PROD/login`,
  while static artifact locations use the same `vcf-depot` htpasswd file generated from the applied Photon OS account.
  Local Users apply must run before exposing the depot with authentication.
- Public portal/user pages should extend `public_portal_base.html` so they share the compact Atlaso header and bottom
  appliance footnote. The brand mark links to `/ui/public`, the header action is contextual `Login` or `Sign out`, footer
  metadata should link Swagger `/api/docs` rather than the raw OpenAPI document, and the Python version should link to
  the official Python site. Public service cards should default to service hostnames, use the configured service
  scheme/port, and provide a Name/IP toggle stored as the `atlaso_public_address_mode` cookie. CA fingerprint controls
  should use compact monospace text with a copy icon. Do not apply this public shell to the authenticated admin portal.
- Styled app-owned directory browsing should wrap depot indexes instead of exposing raw nginx autoindex pages when the
  user navigates from the public portal.
- The management manifest starts within `/ui/management`, and its service worker may intercept only
  `/ui/management/` navigation plus shared immutable assets. Keep public UI caching disabled and never intercept API,
  OIDC, CA download, PXE, depot, registry, or other protocol requests.

## DNS And DHCP

- DNS domains are first-class zones. Represent domains as tabs, include a `+ Domain` tab/action, and keep records, hosts
  import, and zone-file editing inside the selected domain.
- DNS defaults should include the zone derived from the appliance FQDN and an app-owned A/AAAA record for the appliance
  hostname pointing at the management IP. Factory reset should keep only that core appliance DNS record, not demo DNS
  records.
- DNS records belong under their domain. Store and edit relative hostnames inside a zone; render fully qualified names
  only where useful for preview, API output, or validation context.
- Always consider reverse zones for A and AAAA records. DNS record grids should expose reverse/PTR status so missing
  reverse coverage is visible.
- Support at least A, AAAA, and CNAME records in DNS record editing. A is IPv4, AAAA is IPv6, and CNAME is an alias
  target; use selects instead of free-text inputs for short record-type enumerations.
- Avoid `.local` for VMware Cloud Foundation labs. Warn when a user enters `.local`, recommend `.internal`, and mention
  that `.local` is reserved for multicast DNS/link-local naming by RFC 6762 and listed as a special-use domain by RFC
  6761\. Treat `.internal` as Atlaso's recommended private-use internal suffix; do not claim an IETF RFC reserves it
  unless the app copy cites a current authoritative source.
- Use `atlaso.internal` as the sample/default internal domain.
- DHCP should be modeled as IP zones/scopes, not one global range. Each IP zone owns its interface, gateway, prefix,
  lease range, DNS servers, NTP servers, domain suffix, and per-zone options.
- DHCP IP zones may be IPv4 or IPv6. IPv4 zones may bind only to access physical interfaces or enabled VLAN interfaces
  with an IPv4 CIDR; IPv6 zones require a matching IPv6 CIDR. Do not allow trunk physical interfaces, missing
  interfaces, or addressless interfaces as DHCP bind targets. Render IPv6 zones through dnsmasq DHCPv6/RA syntax and
  keep ESXi PXE boot-zone selection IPv4-only until DHCPv6 bootfile-url support is explicitly implemented.
- DHCP also needs global options. Keep global options and per-zone options distinct in the UI.
- DHCP reservations should use DNS names. If a matching A or AAAA record is missing, ask for the FQDN and create the DNS
  record from the reservation IP rather than storing a disconnected hostname.
- DHCP domain fields should suggest current managed DNS domains.
- DHCP should expose actual leases in a separate tab or panel from desired state.
- Physical interface grid actions may enable or disable non-management interfaces with shared modal confirmation.
  Management interfaces cannot be disabled. When a management interface uses DHCP, expose a convert-to-static action for
  observed IPv4/IPv6 lease addresses and preserve DHCP-provided DNS into Appliance Settings and DNS service fallback as
  described above.

## Users, Auth, And Roles

- Keep local Users separate from authentication provider settings. LDAP is an authentication source, not the local user
  list.
- Users need roles because Atlaso is expected to support OIDC. LDAP/OIDC integrations should support group-to-role
  mapping.
- Organization-bound OIDC clients authenticate only against their configured enabled managed LDAP organization and
  must not render an organization selector. Unbound clients require an explicit server-validated `Local` or enabled
  managed LDAP organization choice; never infer a source from an ambiguous username or accept a raw organization ID
  from a form.
- OIDC external groups come only from explicit local-role or managed-LDAP-group mappings. Organization defaults apply
  first and a compatible client mapping replaces the default for the same source. Enforce case-insensitive uniqueness
  of effective names per client and identity organization, resolve enabled direct and nested LDAP membership through
  the cycle-safe graph, and never emit LDAP DNs, server details, or unmapped group names.
- Filter OIDC identity claims by granted scope: `openid` carries required protocol claims, `profile` adds username,
  display name, and organization, `email` adds email with `email_verified=false`, and `groups` adds mapped external
  names. Authorization and UserInfo must revalidate current client, source, organization, user, and group state; the
  existing short JWT lifetime is the only bound on already-issued tokens.
- Managed LDAP organizations follow the DNS-zone interaction pattern: organization tabs include a `+ Organization`
  creation tab, while users and groups are compact editable Tabulator grids with bottom add rows and context-menu
  actions. Synthetic lab-directory generation asks for user and group counts, invents complete profile and membership
  data, and displays compliant generated passwords once without persisting or auditing them.
- Users can hold multiple roles. Store normalized role sets in `roles_json`, keep `role` as the primary compatibility
  value, evaluate permissions as the union of selected roles, and use a multi-select grid/list editor instead of
  comma-separated free text where possible.
- Default local users should be created by seed logic when needed. The VCF Backup SFTP service has a default local user
  named `vcf-backup`, and the VCF Offline Depot HTTP service has a default local user named `vcf-depot`; keep them
  visible under Users and selectable by their services.
- Local Users owns Photon OS account synchronization through the global `/ui/management/appliance-apply` unit
  `local_users`. It stages
  `/var/lib/atlaso/apply/local-users/atlaso-users.json`, creates or updates enabled users under `/var/lib/atlaso/users`
  with their desired shell, removes disabled or removed managed users with `userdel -r`, and applies staged unlock
  requests through `passwd -u` plus `faillock --reset`.
- Local user password rules are configurable desired state on Users. Enforce them on create/reset before staging a
  Photon OS password, and apply the desired rule to Photon PAM/pwquality through the Local Users apply unit.
- Photon image provisioning installs Photon's `powershell` package and creates the bootstrap admin OS account under
  `/var/lib/atlaso/users` with `/usr/bin/pwsh` and the bootstrap admin password, so the default admin has a real Photon
  account before first apply.
- Photon image provisioning grants the bootstrap admin normal password-backed sudo through
  `/etc/sudoers.d/atlaso-bootstrap-admin` for local recovery and debugging. Keep the `atlaso` service account
  constrained to `atlaso-helper`.
- Atlaso does not store local user passwords in the database. Set/reset values are held only in process memory until a
  real Local Users apply sends them to Photon OS; a restart before apply requires the operator to set/reset the password
  again. Never render plaintext passwords, password hashes, or pending password values in previews, jobs, logs, widgets,
  docs, or final responses.
- Existing users without a pending OS password cannot have their OS password recovered by Atlaso; show/reset them as
  `password not staged; reset to sync`.
- Never expose secrets in final responses, logs, widgets, or rendered previews beyond intentionally generated one-time
  credentials already displayed by the app.

## VCF Backups

- VCF Backups is an SFTP endpoint backed by local Atlaso users. The selected SFTP user must come from Users.
- The default VCF Backup user is `vcf-backup`. Keep it disabled while VCF Backups desired state is off; operators
  set/reset its Photon OS password before exposure.
- When VCF Backup desired state is disabled, keep the default `vcf-backup` user disabled so the next Local Users apply
  removes the Photon OS account.
- Apply the Local Users unit before VCF Backups when the selected SFTP user is new, renamed, disabled/enabled, has a
  pending password, changes default shell, or has an unlock request.
- VCF Backup listen targets must include access physical interfaces with IPs and VLAN interfaces with IPs; exclude trunk
  physical interfaces.
- The VCF-facing remote directory should be short and stable: `/backups`.
- The appliance backup storage is a fixed appliance volume mount, currently `/mnt/atlaso-vcf-backups`; do not make this
  a routine UI-configurable field.
- The VCF Backup config preview should make the host-side volume and VCF remote directory clear, and OpenSSH should use
  `ForceCommand internal-sftp -d /backups` when chroot is enabled.
- VCF Backup OpenSSH enforcement should remain a user-scoped `Match User` drop-in; do not make it a broad global `sshd`
  port/listen-address rewrite.

## VCF Helper

- VCF Helper lives under VCF Workflows at `/ui/management/vcf-helper`. Keep deployment component sets versioned;
  current targets are
  `VCF 9.1` with all 17 catalog components and `VVF 9.1` with `vc01`, `ops01`, `vsp01`, `fleetlcm`, `shared01`, and
  `license`.
- Domain choices must come from managed DNS zones. Prefix and suffix are optional hostname fragments; normalize them
  consistently and validate every generated FQDN before writing any records.
- Starting address input is one IPv4 or IPv6 CIDR. IPv4 creates A records and IPv6 creates AAAA records. Allocate
  sequential usable addresses inside that network, skip occupied DNS addresses of the selected family, and also skip
  IPv4 DHCP reservation addresses.
- Treat generation as one transaction. Existing FQDNs are skipped without modification, and insufficient address
  capacity or any validation error must create no records. Return created and skipped rows with assigned or existing
  A/AAAA addresses in fetch responses.
- Keep component descriptions role-specific, such as `vCenter` and `VCF Automation`. Store helper ownership separately
  in structured DNS record metadata with source `vcf_helper` and the component hostname; do not replace role
  descriptions with a generic generated-by label.
- Deletion must require shared modal confirmation and remove only matching helper-owned A/AAAA records for the selected
  deployment, prefix, suffix, and domain. Preserve unrelated/manual records. Legacy records without metadata may be
  removed only when their description exactly matches the expected component description.
- The FQDN modal stays open after creation so assigned addresses remain reviewable. When every displayed FQDN has an A
  or AAAA address, replace the create action with `Done` and hide `Cancel`. Enable deletion only when at least one
  displayed FQDN has an associated address.
- Keep the modal compact and free of horizontal overflow. Deployment, prefix, and suffix controls should remain short,
  the IP/prefix control should have more width for IPv6 CIDRs, and edge help tooltips must open inward or downward so
  their complete text remains inside the modal.
- VCF Helper edits DNS desired state only. Runtime enforcement remains owned by the global `DNS/DHCP (dnsmasq)`
  Appliance Apply unit; do not add a VCF Helper apply route or invoke `dnsmasq` directly.
- Maintain the operator contract in `docs/services/vcf-helper.md` and focused `tests/test_ui.py` coverage whenever
  catalogs, allocation, ownership, deletion, modal state, or API responses change.

## VCF Offline Depot

- VCF Offline Depot is a static HTTP(S) depot endpoint backed by nginx and the fixed appliance volume mount
  `/mnt/atlaso-vcf-offline-depot`.
- The default VCF Offline Depot HTTP user is `vcf-depot`. Keep it visible in Users, selectable by the depot service, and
  disabled while VCF Offline Depot desired state is off.
- Apply Local Users before VCF Offline Depot when the selected HTTP user is new, renamed, disabled/enabled, has a
  pending password, changes default shell, or has an unlock request.
- Default depot access is authenticated. The `Unauthenticated access` switch is an explicit desired-state exception for
  isolated open mirrors.
- The depot helper reads the applied Photon OS password hash from `/etc/shadow` and writes nginx htpasswd material under
  `/etc/atlaso/nginx/htpasswd/`; Atlaso must not store or render plaintext passwords or password hashes.
- `/PROD/` is the canonical depot path, `/PROD` redirects to `/PROD/`, and the depot service-owned HTTPS site must
  follow the configured auth setting and htpasswd file.
- Successful browser login may return only to `/PROD` or a validated path beneath `/PROD/`. Reconstruct the destination
  from the server-owned depot prefix, reject scheme, authority, traversal, control-character, fragment, repeated-slash,
  and browser-equivalent backslash forms, and fall back to `/PROD/` for every unsupported target.

## VCF Private Registry

- VCF Private Registry is a Harbor-backed appliance service for staging VCF Supervisor Service bundles in a private OCI
  registry.
- The registry listen targets must follow the same service binding rule as VCF Backups: access physical interfaces with
  IPs and VLAN interfaces with IPs; exclude trunk physical interfaces.
- The default registry hostname is `registry.atlaso.internal`, and the default Harbor project is
  `vcf-supervisor-services`.
- The registry storage path is a fixed appliance volume mount, currently `/mnt/atlaso-vcf-registry`; do not make this a
  routine UI-configurable field.
- The registry CA bundle should come from the local Atlaso CA when CA is enabled. When the local CA is disabled, require
  an uploaded PEM CA bundle and stage it through global appliance apply; do not expose a routine free-form CA bundle
  path editor.
- Bundle relocation should be modeled as desired state and previewed as `imgpkg copy` command intent. Development
  appliance apply jobs must record Harbor and relocation command intent through adapters instead of pushing images or
  mutating host services directly.
- Do not render Harbor admin passwords, robot account tokens, or registry credentials in config previews, job results,
  logs, widgets, or final responses.

## Routing And WAN

- Routes & WAN Simulation owns static route desired state, IPv4 outbound masquerade NAT rules, and interface/VLAN-level
  `tc/netem` latency/error simulation.
- Label path entries **Static Routes** and forwarding authorization **Routing Permissions**. Keep Static Routes,
  explicit Routing Permissions, NAT Rules, and WAN Policies as wizard-backed Tabulator collections using the ESX
  Storage reference. Add launches from the bottom row; edit launches from row double-click or its context action;
  generated route-role permissions remain read-only; and ordinary persisted Enabled state remains directly editable.
- All Routing/WAN host mutation must go through the global `/ui/management/appliance-apply` `wan` unit. Do not add
  route-specific,
  NAT-specific, or WAN-policy-specific apply routes or direct helper calls from edit forms.
- The real apply path stages `/var/lib/atlaso/apply/wan/atlaso-wan.conf`; `atlaso-helper wan validate|apply` validates
  targets, routes, NAT rules, and netem values before running `ip route`, `nft`, `sysctl`, and `tc`.
- WAN impairment mode is v1 interface/VLAN-level only. Do not expose a route-specific WAN mode until it is fully
  implemented in the helper; track that design in `docs/project/routing-wan-roadmap.md`.
- Atlaso has no `wan` interface role and must not infer NAT or internet connectivity from an interface role.
- Physical and VLAN interfaces share exactly four roles: `management`, `access`, `route`, and `unused`. New UI, API,
  desired-state, and helper inputs reject retired or unknown roles. Bounded upgrade and settings-archive compatibility
  maps only the retired `services` and `storage` values to `access` without changing any other interface state.
  `Routes & WAN Simulation` is the explicit routing/NAT/loss workflow, not an interface classification.
- NAT v1 is explicit IPv4 masquerade only. Do not add destination NAT, port forwarding, automatic broad NAT, or
  non-reviewable NAT inferred only from interface role. Route-role networks may forward to other route-role networks by
  default; access networks require explicit routing rules; management is never a route, NAT, or routing-permission
  target.
- NAT outbound targets must be access physical interfaces with an IPv4 CIDR or enabled VLAN interfaces with an IPv4
  CIDR. IPv6-only interfaces are not valid NAT outbound targets. NAT is explicit desired state and remains reviewed
  through global apply; it is not inferred from an interface role.
- Validate live Routing/WAN state with `ip route`, `tc qdisc show`, `nft list ruleset`, and `sysctl net.ipv4.ip_forward`
  after applying on Photon.

## Database And Verification

- This project is still in MVP scaffold mode. When model/schema changes make the development SQLite database stale,
  prefer deleting/reseeding `data/atlaso.db` over adding migrations, unless the user explicitly asks for migrations.
- Do not delete the DB for data-only seed/default updates if a focused in-place update is safer and the schema did not
  change.
- Backup / Restore owns desired-state settings archives. Do not include audit events, jobs, API tokens, password hashes,
  uploaded secret bodies, or runtime history in those archives. The separate passphrase-encrypted LDAP directory
  recovery export/import is an explicit special case that also lives on Backup / Restore; it preserves slapcat password
  hashes, remains outside the settings archive, and stages import for global LDAP apply. Restore and factory reset must
  leave service status rows stopped, disabled, and `unconfigured`; host mutation still belongs only to the global
  `/ui/management/appliance-apply` workflow. Factory reset must reseed only core defaults and must not recreate demo
  VLANs, trunk-only
  parent NIC posture, routes, NAT rules, WAN policies, DHCP scopes/reservations, firewall rules, CA requests, vSphere
  providers/trusted vCenters, depot download profiles, or service listener bindings, including after service restart.
  The only DNS record factory reset should reseed is the app-owned appliance FQDN record pointed at the management IP.
  After factory reset, only `eth0` should be desired admin up; other physical NICs should be desired admin down until
  an operator enables them. Disabled service settings should have blank listen interfaces and addresses until an
  operator selects a valid bind target.
- Settings archives must not include vault entries. Restore and factory reset clear vaults and the unused legacy
  Kickstart-binding compatibility table; operators reimport or recreate vault contents afterward.
- Validate every supplied settings archive collection, row object, nested revision, required field, relationship, and
  enabled VLAN or static-route target before deleting desired state. Restore owns rollback for every failure after
  mutation begins and must retain both the database row and in-memory bytes for any separately staged LDAP recovery
  import. Remove that staged recovery material only after the settings restore or factory reset database commit succeeds.
- Documentation updates are required for every major product, architecture, workflow, safety-boundary, or
  operator-experience change. In the same change, update `README.md`, `AGENTS.md`, and any topic-specific file under
  `docs/` whose behavior or operator guidance is affected; do not treat the work as complete while those documents
  describe the old behavior.
- Before committing branch work, run `python scripts/check_repo.py` or install the local hook with `pre-commit install`
  so changed Python, Jinja/HTML, Markdown, CSS, JavaScript, JSON, TOML, YAML, PowerShell, and SVG files get
  syntax/content checks. The hook is a fast pre-commit guard and does not replace focused tests.
- Before finalizing UI/backend changes, run focused tests for the touched area when available. Do not run the complete
  Python test suite locally; GitHub CI owns it. Also run `python -m compileall atlaso` after broad
  Python/template-adjacent changes.
- Before finalizing appliance deployment changes, also run `python scripts/check_photon_compatibility.py`. If image
  build files changed and Packer is available, run `packer fmt` and `packer validate` from the changed image target
  directories such as `image/hyperv/` and `image/vmware-workstation/`.
- Restart the local uvicorn server after template/static/route changes so the in-app browser sees the new code. Bump the
  static asset query string in `base.html` after CSS or JS changes.
