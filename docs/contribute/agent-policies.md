---
title: Detailed agent policies
description: Conditional subsystem contracts and implementation constraints for automated contributors.
audience:
  - contributor
  - maintainer
status: current
---

# Detailed agent policies

Load only the named sections relevant to the task and its affected call paths. This is a conditional subsystem
reference, not a startup prerequisite. Cross-domain changes load every affected section. When scope is unclear,
inspect the section headings first and resolve applicability before changing behavior.

Workflow ownership lives in [the progressive policy guide](progressive-policy.md); startup is defined only in
[AGENTS.md](https://github.com/mdaneri/Atlaso/blob/main/AGENTS.md). The former root implementation boundaries are
preserved with their affected subsystem below. Keep new requirements at their topic owner, not in the root router.

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
- Real Appliance Settings apply must prove the configured Atlaso loopback `/openapi.json` upstream before publishing a
  management nginx candidate, write and daemon-reload the durable loopback drop-in without restarting the active Atlaso
  worker, then require consecutive guest-local front-door readiness on the applied management address and public port.
  Snapshot the existing nginx site/include/main configuration and service drop-in before mutation; an activation or
  readiness failure restores those exact files, validates and reloads nginx, reloads systemd, and reports rollback failure
  truthfully. Current helpers do not emit management-restart context. The shared monitor may retain the bounded neutral
  reconnecting behavior only for complete server-owned transition metadata from an older task record; missing,
  unexpected, or out-of-window status failures retain the actionable availability warning and active retry cadence.
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
  A main-column desktop record grid may expand to the remaining viewport height when it recalculates from its actual
  position on window and panel resize, keeps a practical minimum, and returns to the compact bounded CSS height for
  narrow, hidden, or zero-width layouts. Preserve grid-contained horizontal overflow and identical empty, single-row,
  many-row, and bottom-add-row behavior.
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

### Preserved implementation boundaries

- Authenticated primary navigation renders only non-empty groups after server-side permission filtering. Each group is
  an accessible disclosure with a native button, accurate `aria-expanded` and `aria-controls`, and a visible chevron.
  First use starts every authorized group expanded; browser-local state restores inactive-group choices, while the
  current page's group always opens without overwriting its saved choice. One compact two-state symbol control expands or
  collapses only the rendered groups, uses `<<` to collapse and `>>` to expand, and updates its accessible name and
  tooltip to describe its next action. It persists through the same per-group state. Keep the global
  **Review appliance changes** card outside the disclosures
  and preserve coherent groups at desktop, two-column narrow, and single-column mobile widths.
- Privileged appliance operations go through `atlaso-helper` and constrained sudoers rules.
- Keep development system adapters in dry-run mode unless a reviewed apply unit explicitly promotes real mutation.
- ESXi boot authorization must consume the exact successful real-Apply manifest from the dedicated encrypted runtime
  record, never a redacted display preview. Keep ciphertext out of Apply baselines and portable settings exports;
  publish the runtime record transactionally after successful activation, including factory reset, and preserve it
  across failed and dry-run applies. Bind hidden desired edits to the submitted snapshot with the ESXi-specific keyed
  marker. Corrupt protected evidence must fail closed without legacy fallback. Keep incomplete runtime state selectable
  for real Apply, explain recovery in the existing Validation rail, and require a fresh host boot attempt afterward.
  Reuse one request-local manifest index and revision check across management diagnostics. Preserve standalone IP,
  MAC, and host UUID identifiers without adding UUID as an authorization requirement. See [ESXi Network Boot](../services/ipxe.md).
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
- Virtualenv launchers must survive both release staging moves, and every named readiness service must report active rather
  than relying on systemctl's any-active exit status. Recovery must admit every first-boot asset installed by the release.
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
- Maintenance retains the Backup / Restore route and groups LDAP, Backup, Reset, and Diagnostics in shared tabs.
  Diagnostic bundles are administrator-only, bounded observational captures through the shared grid and reviewed wizard;
  the recovery CLI must remain independent of web, worker, writable database, and application startup. Default to a
  30-minute window, minimal evidence, detailed logs off, and hostname/username anonymization off. When selected, assign
  consistent per-bundle aliases only after reserving all collected source identities; never export their mapping or
  internal markers. Preserve IP and MAC addresses. Exclude secrets, arbitrary files, free-form logs, environments, and
  command lines regardless of privacy selection. Privileged reads use only fixed helper source allowlists and bounded
  projections; never accept arbitrary commands or paths. Recompute integrity metadata over final exported bytes and
  report unavailable, truncated, or failed evidence truthfully. Publish private archives with current authorization,
  mode `0600`, non-cacheable downloads, cancellation, manual deletion of retained expired bundles, and 24-hour managed
  retention. CLI archives remain operator-owned. Factory reset must safely clear the dedicated spool before replacing
  retention records. Collection never applies configuration, restarts services, repairs state, or uploads evidence.
  Keep the [operator guide](../operate/diagnostics.md) and
  [collector contract](diagnostic-collectors.md) aligned with these boundaries.
- Preflight every settings archive section, required row field, relationship, and enabled VLAN or static-route target
  before clearing desired state. A failed restore must roll back database changes and preserve separately staged LDAP
  recovery metadata and in-memory bytes. Clear staged recovery material only after a successful restore commit or
  factory reset commit.
- Complete factory reset must replace every control-plane database record with factory/bootstrap records, invalidate
  all sessions and credentials, activate coherent core defaults while disabling optional services, and preserve depot,
  backup, and managed ESX Storage payload paths. Persist a non-secret recovery marker before database replacement,
  make resume idempotent across interruption or reboot, validate all generated runtime configuration before activation,
  scrub transient staging plus retained VCF Backup authorized keys and Web Terminal signing material, and leave all 17
  desired/applied baselines equal with no follow-up Apply workflow. Also remove retained KMIP operational state and
  Atlaso-synchronized package-source staging and registrations, fsyncing repository removal
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
- Use the locally bundled `window.AtlasoMonaco` integration for code or configuration editing. ESXi Kickstarts use the
  dedicated Kickstart language and derive vault scope only from exact source markers; never restore an explicit
  Kickstart-to-vault selector or expose resolved values in browser state or completion metadata. Dynamic Kickstart
  retrieval requires a cryptographically random boot claim. The applied **Require console authorization** policy is
  off by default; enabling it additionally requires an administrator-entered one-time code shown by the intended host
  console. Desired policy edits take effect only after successful Apply; legacy snapshots retain approval until then.
  Only that exact claim may receive a short-lived, atomic single-use boot capability
  bound to the applied host, full Kickstart revision, listener, and generated attempt. Store only claim, code, and
  capability verifiers. Automatic mode admits assigned applied hosts without console authentication; never represent
  a MAC address as proof of identity, and never expose capability paths in management
  UI/API, audit, job, problem, or log data. The exact pending boot protocol response may carry only its own claim.
- Browser navigation to a globally disabled Web Terminal must render the authenticated Atlaso unavailable-state page;
  reserve JSON and protocol errors for ticket, API, and WebSocket consumers.

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

- Canonical image builds and live appliance testing use VMware Workstation. VMware Workstation is installed by default at
  `C:\Program Files\VMware\VMware Workstation`; use `vmrun.exe` there with the helpers under `scripts/windows/vmware/`.
- The Photon OS 5.0 canonical template lives under `image/vmware-workstation/`. Hyper-V, KVM, and Proxmox VE are
  portable artifacts exported from its validated payload and must not grow independent image-build or lifecycle stacks.
  Keep guest-neutral provisioning and disk identity assets under `image/common/`.
- Before a VMware Workstation image rebuild force-replaces the configured output directory, route any existing output
  VMX through the checked cleanup module. Current Workstation automation has no unregister-only operation: `vmrun`
  rejects unregister, VIX reports it unsupported, and `vmrest` exposes only credentialed destructive deletion. After
  every fail-closed preflight succeeds, use checked local `vmrun deleteVM` for a registered target. Keep this cleanup
  scoped to the configured image output directory.
- Workstation test-VM and lifecycle cleanup may recursively remove only an exact, non-reparse-point Atlaso artifact root
  containing every validated target VMX. A named redeploy with no matching VMX fails closed, and data-disk reset paths
  must be strict path-component descendants of that VM output rather than sibling-prefix matches. Capture immutable
  root, descendant, and target identities before provider operations; a new or replaced entry or root blocks recursive
  removal. Query checked `vmrun` running output, match an exact target or filesystem alias by identity, stop through
  checked `vmrun` when needed, and verify inactivity. Use checked `vmrun deleteVM` only for a well-formed exact in-scope
  registration. A successful cleanup-owned stop may admit an atomic VMX rewrite only when every assignment except
  validated `cleanShutdown`/`softPowerOff` booleans remains unchanged. Bind the stopped identity and hash under a read
  lock while retaining every other root/descendant identity; reject all other replacements. Verify the exact in-scope
  registration and verify the target VMX is absent. Immediately before each deletion, repeat the target identity and
  identity-aware running check, confirm the scoped registration, and verify the recursive VMX set contains only the
  validated surviving targets.
  Detach every VMDK device whose resolved path is outside the exact removal root before `deleteVM`, because provider
  deletion must never remove reused depot, backup, or other shared disks. Atomically replace the VMX while retaining the
  displaced backup. Restore that backup only when the detached identity and content still match; preserve a concurrent
  replacement and an actionable recovery copy instead of overwriting either.
  Normal Atlaso deletion must not require global `inventory.vmls` consistency. Unrelated stale, malformed, missing,
  duplicate, or inconsistent Workstation library entries cannot block cleanup of an exact Atlaso-owned root. Reserve
  inventory mutation for a well-formed Atlaso-scoped registration whose VMX is already missing. With the Workstation UI
  closed, validate only that each selected `vmlistN` ID owns one config path, recheck the scoped VMX remains absent, and
  hold a write-excluding handle from the final byte comparison through atomic replacement and rollback. Remove only the
  selected library and matching index records; leave unrelated registrations in place and do not require them to
  resolve. A preflight failure preserves all artifacts. A nonzero or malformed command result, scoped inventory read or
  repair failure, provider deletion failure, failed postcondition, or recursive-removal failure must propagate as a
  cleanup failure and preserve the remaining artifacts; lifecycle cleanup must retain the original
  scenario failure alongside that cleanup evidence.
  If checked `deleteVM` removes the complete validated artifact root, retain the scoped running and registration gates,
  require the exact root to remain absent throughout them, and allow the initiating redeploy to continue only after
  those checks succeed.
- For the default visible VMware image build, start or reuse a responsive Workstation UI in a separate process before
  Packer enters the synchronous `vmrun` GUI start transition. Keep startup monitoring bounded until SSH provisioning,
  bind every diagnostic to the expected VMX filesystem identity and exact provider inventory, and distinguish VM
  creation, provider responsiveness, running state, configured builder TCP/22, start handoff, and SSH authentication.
  Sanitize Packer output and remove raw debug-log environment variables from the monitored child. For
  `-PackerOnError cleanup`, make Packer retain the exact failed VMX and route ordinary nonzero exits, startup timeouts,
  monitor interruptions, and the outer whole-image deadline through checked exact-root cleanup only after the outer
  Windows job proves zero Packer, plugin, and provider processes remain. Release the builder address only after
  process-tree termination, exact-provider inactivity, and artifact removal are proven; otherwise retain the remaining
  artifacts, reservation, and combined failure evidence. Preserve the exact artifacts for other selections. Never
  expose connection credentials or VMX contents, and never substitute an arbitrary delay for a diagnosed start
  transition.
- Keep VMware release images on two compacted payload VMDKs: the Photon OS disk and a required UUID-mounted
  `ATLASO_SYSTEM` disk containing `/opt/atlaso` and appliance-wide PowerShell modules. OVF export must preserve both
  payload files, add only the empty depot and backup definitions, preflight every GitHub asset below 2 GiB, and omit an
  oversized aggregate OVA rather than publishing an unusable release asset. Recursive OVF output replacement is limited
  to strict, non-reparse-point descendants of `image/vmware-workstation/ovf`; repository, image, output, filesystem, and
  external roots are never removal targets. Stable and prerelease publication modes implicitly replace only the
  canonical derived destination. Every explicitly supplied existing destination requires `-Force`, and `-Force` does
  not expand the deletion boundary. Low-level OVF export never changes GitHub. Manual virtualization orchestration
  through `-Prerelease` may create only the exact annotated `virtualization-vX.Y.Z-rc.N` tag and hidden draft after
  VMware and Hyper-V smoke pass; it never publishes or reclassifies that draft. Only the protected hosted finalizer may
  sign, attest, and publish the prerelease.
- Remove only proven build-only packages after runtime and Photon compatibility checks. Preserve all appliance
  capabilities, clean package/download caches and staged build sources, zero-fill both payload filesystems with a
  bounded free-space reserve, remove the fill files, request TRIM, and emit bounded before/after footprint evidence
  before Packer compaction.
- Atlaso's platform services exclusively own appliance first boot; cloud-init metadata is unsupported. Remove Photon's
  incidental `cloud-init` package immediately after the initial OS update and before subsequent systemd daemon reloads.
  Final package-state verification must reject both the package and leftover generator, unit, or configuration paths.
- The VMware image is automated with Packer, Photon kickstart JSON, an ISO-embedded GRUB auto-install entry, and
  provisioning scripts. Portable target exporters must consume the validated role-bound VMware provenance instead of
  recreating installation steps.
- Before any Workstation, ISO, Packer, output, or image mutation, require a completely clean source
  checkout and admit one exact commit. Archive that commit into the invocation-owned build root, remove the build
  identity's write access for the complete child lifetime, launch the bounded child from the snapshot, and make every
  Packer file and shell source plus the exact HCL template consume only that tree through a separate disposable Packer
  working directory. Bind schema-v3 VMX provenance to the commit plus a deterministic full-snapshot
  file-count and SHA-256 inventory, and revalidate it before Packer and provenance emission. Reject dirty, ambiguous,
  changed, legacy-unbound, or unreproducible source state. Hyper-V and protected virtualization publication inherit
  this boundary only through the validated OVA; downstream signature and signed-software-source verification remain
  mandatory defense in depth.
- Photon appliance provisioning should run `tdnf -y makecache` and `tdnf -y update` before installing Atlaso so the
  image lands on the current Photon 5.0 package stream.
- The Photon Packer template must stage `requirements-appliance.lock` into `/tmp/atlaso-src` before shared
  provisioning syncs the application under `/opt/atlaso`. Keep bootstrap dependency installation hash-locked and fail
  the image when the staged lock is missing; do not fall back to unpinned dependency resolution.
- The Photon Packer template must also stage `scripts/generate_third_party_notices.py` and
  `scripts/third_party_notices.json`. Treat third-party notice generation as mandatory and fail the image when its
  generator, inventory, referenced notice, installed top-level Python distribution metadata, or Photon RPM inventory is
  missing or invalid; ignore nested package-internal vendored metadata during installed-environment lock verification,
  and do not skip notice generation to complete a build.
- Run long TDNF operations in shared Photon provisioning through `scripts/run_tdnf_with_progress.py`. Keep its compact
  30-second Packer heartbeats with elapsed time and TDNF cache size, capture raw transaction output instead of streaming
  terminal redraws, preserve every nonzero child exit status, promote a zero-status transcript that reports a TDNF
  error or disabled repository to exit status 1, and replay only a normalized bounded output tail on failure.
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
- The canonical image masks `systemd-ssh-generator` because Atlaso uses normal TCP SSH and does not rely on automatic
  SSH-over-AF_VSOCK sockets. Preserve that state in portable conversions.
- Keep `ATLASO_DRY_RUN_SYSTEM_ADAPTERS=true` for first-boot appliance images. Promote real host mutation one apply unit
  at a time after validation, preview, job capture, and rollback behavior are reviewed.
- Privileged appliance enforcement must go through `atlaso-helper` and constrained sudoers entries. Do not give the
  control plane broad shell, root, or package-manager access.
- Real mutating helper actions run through `systemd-run` from inside `atlaso-helper` when
  `ATLASO_HELPER_USE_SYSTEMD_RUN=1` is set. This escapes the `atlaso.service` read-only `/etc` mount namespace without
  giving the web control plane broad shell/root access. Keep that environment variable in `atlaso.service` and preserve
  it in the Atlaso sudoers rule. Give every real helper action and nested account mutation an exact 32-hex-identity
  `atlaso-helper-action-*` transient service. Ordinary actions use a fresh UUID. A single-stream Appliance Update apply
  derives the same collision-resistant identity from its durable task and stream so startup recovery can stop and verify
  only that surviving helper before terminalizing the child. Complete factory reset stops and verifies the whole bounded
  family after stopping Atlaso callers and before inventorying delayed update restarts.
- The global `/ui/management/appliance-apply` workflow remains the only ordinary host-mutation workflow. The dedicated
  complete factory-reset transaction is the sole recovery exception; it validates and activates all factory units and
  establishes matching baselines without an operator-created Apply task. Do not add
  service-specific apply
  routes, service-specific apply jobs, or direct helper calls from desired-state edit forms.
- Appliance Update is runtime maintenance, not desired-state drift. Keep it separate from
  `/ui/management/appliance-apply`, stage
  `/var/lib/atlaso/apply/appliance-update/atlaso-update.json`, and run Photon OS, PowerShell module, and signed Atlaso
  release work only through `atlaso-helper appliance-update`. Do not restore the retired Python Libraries or independent
  wheel streams.
- Represent every manual or scheduled Appliance Update check/install as one parent job with ordered `JobStep` children
  for the selected Atlaso Release, PowerShell Modules, and Photon OS streams. Checks run every selected child for
  complete diagnostics. New installs preserve Photon OS, PowerShell Modules, then Atlaso Release ordering and skip every
  later selected stream after the first installation failure. Persist the exact order and a random status-transaction
  identity before the parent becomes visible. Legacy in-flight tasks retain their recorded release-first order; never
  reorder an already-created hierarchy. A current-protocol worker interrupted safely between children requeues only the
  untouched pending suffix and never reruns a child that started. Release-last owns the only selected release worker
  handoff, so no pending post-release child remains and a proven candidate worker restart suppresses the older delayed
  Photon restart. If rollback restores an older worker without terminal-child capability, explicitly skip untouched
  children and fail the parent rather than requeueing terminal work. Keep child output, compatibility evidence, and
  errors independent, and
  derive the parent outcome from all selected children. Give privileged PowerShell update work the root-owned
  persistent home `/var/lib/atlaso-privileged/powershell`; do not point it at the service's read-only `/root` view.
- Before any real installation child starts, atomically publish a root-owned, no-store update-only browser surface from
  the exact durable parent/child hierarchy and prove HTTP 503 on every applied management and public browser listener.
  While its runtime marker exists, nginx must serve the bounded self-contained page without Atlaso, authentication,
  sessions, JavaScript, or ordinary static assets; the canonical browser prefixes, `/` dispatcher, and legacy human
  bookmarks must not reach the control plane. Machine and protocol route paths remain unchanged and may return the same
  maintenance 503 while their upstream is unavailable; they must not return 502. Store the durable snapshot and
  monotonic restoration state beneath the root-only privileged state directory, publish only the sanitized HTML in
  `/run`, reject symlinks, non-root ownership, stale/cross-task identities, malformed hierarchy, and non-install tasks,
  and use no-follow atomic replacement plus file and directory sync. Recreate a nonterminal or terminal-pending hold in
  nginx pre-start after reboot. Corrupt evidence must serve a generic no-detail recovery 503 and block worker admission,
  not prevent nginx from starting. Restore ordinary UIs only after the parent is terminal, every selected child is
  terminal, any started release has definitive finalizer/update-info/current-link/signed-receipt/worker/service evidence,
  and any scheduled Photon worker restart has completed in the new worker process. Persist successful hold activation
  only after listener proof so an initial publication rollback cannot recreate a never-active marker. Bind restart
  completion to the exact task and current worker identity, and retry missing completion evidence through a bounded,
  durable, rate-limited dispatch budget whose initial grace begins at the persisted restart dispatch timestamp, never at
  the long-lived worker process start. Persist `pending` before removing the marker and `restored` only after nginx
  reload and listener proof; startup and the worker must retry an interrupted restoration idempotently.
- Submit manual Appliance Update checks and installations asynchronously from Update Streams. Refresh only the embedded
  shared Tasks grid, highlight the newly created task, and keep both task actions disabled until the active Appliance
  Update task reaches a terminal state; do not restore a separate submission-result card.
- Persist bounded per-stream check state under `appliance_update.availability.v1`, separating the latest attempt from
  the latest successful confirmation. Retain a prior confirmed update after a failed recheck, but make configuration
  fingerprint mismatches stale and exclude them from global indication and manual installation. Disable an
  unsynchronized Photon or PowerShell stream with an accessible **Repository setup required** reason and a direct path
  to its Update Sources context and audited **Synchronize repositories** action. Reject blocked stream identifiers
  server-side for checks and installations while preserving independent ready streams. Refresh readiness promptly after
  synchronization, prevent older browser responses from overwriting a newer state, replace an obsolete prerequisite
  failure with **Check required** after success, and retain actionable non-secret failure guidance after a failed sync.
  Admit a manual check whenever at least one ready stream is selected and no Appliance Update task is active. Require
  every selected manual-install stream to have a successful, current latest attempt, require at least one confirmed
  update, enforce package-client prerequisites, and apply the same gate server-side. Scheduled installs retain
  check-before-apply.
- Render the authenticated topbar **Update available** link from server state and refresh its sanitized, browser-only,
  no-store projection every 60 seconds only while visible, after visibility returns, and after terminal update tasks.
  Render no live control when the current confirmed count is zero, create or update exactly one control for a positive
  count, and remove it again on a confirmed transition to zero so no focusable, visual, tooltip, badge, or screen-reader
  zero state remains. A transient, structurally invalid, or noncanonical polling response may preserve only a valid
  last-known positive control. Exclude that route from OpenAPI and never expose commands, credentials, or raw helper
  output. Require every browser-polled `up_to_date` confirmation to carry zero changes. Clear confirmations only for
  successfully installed streams.
- Appliance Update sources are repository-style desired runtime-maintenance configuration. Support multiple named
  Photon, PowerShell, and HTTPS Atlaso release sources, using secondary signed Atlaso channels as failover sources. Keep
  repository tabs inside collapsible ecosystem sections and managed PowerShell modules in their own one-tab-per-module
  editor. Each configured source tab is a read-only detail view with identity first, location or discovered runtime data
  second, binary repository behavior in one consistent group, and synchronization state in a separated footer. Place
  **Edit repository** beside the destructive action and use the same shared reviewed source wizard for creation and
  editing. The built-in Photon row must show effective values discovered from `/etc/yum.repos.d`. Source
  credentials remain encrypted at rest and move to `atlaso-helper appliance-update` only through a separate mode-0600
  transient staging file. Keep synchronized managed Photon repository files credential-free; authenticated TDNF calls
  use a root-only repository view in volatile `/run` storage that is removed after each command. Never place credentials,
  authenticated URLs, or secret-bearing commands in durable package-client configuration, manifests, jobs, command
  arguments, audits, or helper output. Source wizard submissions save desired state only; writing Photon or PowerShell
  package-client configuration requires the explicit audited **Synchronize repositories** task through
  `atlaso-helper appliance-update`; signed Atlaso sources never configure pip.
- Keep the staged Appliance Update manifest in a compact Validation card at the bottom of the detail rail and open its
  full JSON through the shared preview modal; do not render the full manifest inline in Update Streams.
- Treat `/etc/atlaso/update-info` only as durable updater transaction and recovery evidence. Do not synthesize it for a
  source checkout, development wheel, fresh packaged appliance, or read-only check. Project normal absence as neutral
  **Not recorded**, evidence bound to the latest applied stream of the latest qualifying real task as **Available**, and
  an expected-but-missing,
  unreadable, malformed, stale, or finalizer-inconsistent record as **Needs attention** with non-secret remediation.
  Keep this projection read-only and
  independent from activation, receipt, finalizer, rollback, recovery, and reboot-persistence enforcement.
- Atlaso releases must come from signed v2 channel pointers and immutable signed release manifests verified by named
  Ed25519 public keys under `/etc/atlaso/update-trust.d`. Optional release `summary` and `release_notes_url` fields
  remain backward compatible; bound the summary to one line derived from the release commit subject and accept only
  credential-free HTTPS notes URLs of at most 2,048 characters. Install the exact ABI wheelhouse offline with
  `PIP_CONFIG_FILE=/dev/null`, `--no-index`, and hash verification under `/opt/atlaso/releases/<version>`, switch
  `/opt/atlaso/current` atomically, and preserve `/opt/atlaso/.venv` as a compatibility symlink. Restore the previous
  release, helper/systemd files, and SQLite snapshot on failure. Inspect Photon transactions before mutation, use the
  Photon-supported `tdnf repoquery python3` form and select the highest advertised minor ABI, reject unsupported
  candidate Python ABIs, reconstruct from the retained wheelhouse after supported ABI changes, and do not claim
  automatic RPM rollback or reboot.
- Do not write a successful Atlaso Release finalizer until durable activation is proven. Flush the active switch and
  installed assets, restart the worker into the
  candidate release under a provisional finalizer, require its new systemd PID to publish the matching job, version, and
  release root, persist a bounded rollback manifest before switching the active link, and persist restart-pending
  evidence before establishing the volatile runtime gate. Keep recovery blocked until the definitive finalizer write
  completes. Retain maintenance through every rollback-capable stage, then durably record `activation_committed` before
  validating, reloading, and opening nginx. Failures after that commit must preserve the candidate and retry forward;
  never restore the database snapshot after the front door can admit operator writes. Worker pre-start must distinguish
  a live helper by boot, PID, and process-start identity. Stale committed evidence after reboot must recreate its
  volatile gate, schedule one stable per-job root-owned completion unit, durably replace the prior-boot owner with that
  helper's exact live identity, and admit the gated candidate without requiring the not-yet-started worker; definitive
  completion then requires that worker's exact published job, version, release-root, current-boot,
  PID, and process-start identity. Stale provisional
  evidence after a host restart must make Atlaso and nginx service pre-start guards recreate maintenance from the
  durable provisional finalizer before either service starts, then restore and verify the previous release before the
  worker is admitted. Flush the
  database and every installed-asset rollback backup plus its directory entries before publishing the durable recovery
  manifest. Missing database backup bytes make rollback incomplete. Restore installed assets independently so one
  failure cannot prevent later destinations from being attempted. While the exact recorded helper remains live, extend
  the candidate worker's runtime-gate wait so timeout cannot restart it through a restored legacy unit before the
  definitive rollback write. Refresh the manifest after adding the ESX allowlist backup and before mutating its claims
  or database, so both rollback together. Reboot recovery must retain the candidate environment after restoring the
  previous runtime, execute the exact release task's child, parent, terminal-log, and audit bookkeeping through that
  candidate as the
  Atlaso service account while maintenance and provisional rollback evidence remain held, using the restored database
  schema directly without candidate schema creation or startup reconciliation. Only after that bookkeeping
  may recovery remove maintenance, prove the host-facing previous version, publish definitive healthy-rollback evidence,
  remove the candidate, and admit the restored worker. A failed candidate bookkeeping handoff
  must retain the candidate, maintenance response, and runtime gate for retry.
  An already-active release must complete from exact readiness evidence without an unverified delayed service restart.
  A matching definitive success or healthy rollback may clear or supersede an orphaned runtime gate. Incomplete rollback
  must retain both maintenance and that gate so queued mutations cannot resume against inconsistent state. Rollback must
  preserve and verify the already-running worker until the definitive rollback write; it must never start a restored
  legacy worker inside the transaction. After recovery bookkeeping, a candidate worker must exit so systemd starts the
  restored release without executing pending children itself. Before publishing any incomplete rollback, retain the
  provisional owner evidence and stop and verify exact `ActiveState=inactive`, including when the runtime gate exists.
  A failed status query is not inactive proof: retry from the live helper without returning to the caller. Retain the
  candidate directory through candidate-version bookkeeping and restored-worker handoff, including incomplete retries.
  A gate timeout must exit worker startup for systemd retry, never enter the ordinary work loop. Remove and durably flush
  staged source credentials from the surviving helper before it restarts the calling worker. Require nginx plus web,
  worker, and console service state, and require the signed receipt, `current`, compatibility
  virtualenv, internal OpenAPI version, nginx management-front-door OpenAPI version, and candidate version to agree.
  Definitive finalizers must retain sanitized helper command evidence; startup recovery must pass that evidence through
  the ordinary child completion, parent completion, terminal task-log, and audit bookkeeping. Any
  failure after the switch but before `activation_committed` must restore the previous release, helper/systemd assets,
  SQLite snapshot, and working nginx front door. Runtime rollback must verify and flush the restored release internally
  while maintenance remains held, durably write `rolled_back=true` with a sanitized failing layer so the snapshot cannot
  be replayed, and only then remove maintenance, prove the host-facing previous version, and persist that host-facing
  evidence. A failed final front-door probe or evidence write must restore maintenance without making the snapshot
  eligible for replay. Fail both release child and parent. After a verified healthy
  rollback, preserve the terminal failed release child and requeue untouched children without rerunning it. Requeue a
  mixed terminal/pending set after another worker restart while preserving every terminal result; for legacy
  release-first tasks retain their recorded compatibility behavior, while current release-last tasks skip the untouched
  suffix after any earlier failure.
  Worker startup must reject
  a success finalizer that disagrees with the durable active release or running version. On the first transition from
  the legacy updater, recognize only its bounded successful service-health or no-change finalizer shape and reconcile
  it from the exact active links, signed receipt identity, and running candidate version; do not reinterpret missing
  current-protocol fields alone as a failed update. Signed-release lifecycle
  coverage must prove the candidate and a healthy rollback both before and after audited appliance reboots; installation
  itself must not reboot automatically.
- Every successful same-repository `main` push CI run automatically starts **Publish Python wheel** on GitHub-hosted
  Linux. Keep it read-only and bounded to one 90-day Actions artifact named
  `atlaso-wheel-vX.Y.Z-<full-sha>`, containing exactly the versioned wheel and canonical identity document. Bind the
  source CI and publisher run IDs and attempts, repository, version, full commit, UTC commit build time, filename, size,
  and SHA-256. Later consumers must use the attempt-specific GitHub run endpoints and verify each recorded attempt.
  Give this path no appliance signing material, protected environment, contents write, tag/Release or `gh-pages`
  mutation, channel promotion, self-hosted label, or virtualization access. Automatic retries may publish another
  artifact for the same identity only when the wheel bytes remain identical; a later consumer must compare all retained
  candidates, stage them by publisher run plus artifact ID, validate every recorded publisher attempt, fail closed on
  divergence, and preserve the earliest retained publisher run-and-attempt handoff so a later identical retry cannot
  change signed bundle inputs. Provide manual retention recovery only through the protected **Replay Python wheel**
  workflow revision on `main`. It must accept an exact commit plus source CI run ID and attempt, revalidate that exact
  attempt as successful same-repository `main` push CI for the commit, and require the commit to remain reachable from
  current `main` without checkout or target-code execution. Publish only one canonical one-day replay-request artifact.
  The wheel publisher must consume that request only through its completed `workflow_run`, revalidate it and the source
  CI evidence, and retain the same read-only wheel-only trust boundary.
- Every successful automatic-main wheel handoff starts the protected **Publish appliance release** workflow. Require
  and revalidate the retained handoff, including its
  successful source CI identity and embedded wheel version/commit/time, and record `wheel-identity.json` inside the
  signed bundle. Never rebuild or substitute the application wheel in this workflow. If the 90-day artifact expired,
  dispatch **Replay Python wheel** from protected `main` with the exact commit and successful source CI run ID and
  attempt; the two-stage replay must revalidate that evidence before publishing the replacement handoff. If an
  immutable software Release already exists, verify and reuse its signed assets only when the replay wheel is
  byte-identical to the wheel inside that bundle; do not rebuild it with a new publisher identity. Atlaso starts a new
  signed update
  lineage at `v0.9.18`; do not publish or consume a retired-product bridge. Preserve tag/release commit and asset-byte
  idempotency checks. A rerun after tag/release publication must verify the existing asset bytes before retrying channel
  advancement. Keep the protected GitHub-hosted workflow limited to the signed software/update bundle, immutable
  `vX.Y.Z` Release, and `development` channel. Retain exact-successful-main-SHA manual dispatch for idempotent recovery;
  authenticate the existing pointer under the shared Pages lock and refuse semantic-version downgrades so historical
  CI reruns and replayed handoffs cannot move `development` backward.
  Resolve retained wheel candidates and verify any existing immutable Release in an unlocked, read-only prerequisite
  job. Pass those bounded verified inputs through the current workflow run, and acquire the shared Pages lock only for
  the protected signing, Release publication, channel mutation, and live publication verification stages.
- Virtualization publication is separate. A clean Windows workstation consumes the exact signed `vX.Y.Z` bundle,
  installs its exact application wheel and complete hash-verified offline CPython 3.14 wheelhouse during template
  construction without rebuilding them. Preserve installed VMware Tools, both verified offline QEMU/Hyper-V RPM
  closures, and untouched deployment initialization through final updates, cleanup, shutdown, and compaction. Never
  restart a completed template for installation, provider selection, customization, or export preparation. Prove the
  exact source powered off before hashing and export; recheck its VMX and payload hashes after export and disposable
  imported-VM smoke tests. Require the schema-v3 completed-template contract and exact verified software identity during
  retained reuse, candidate acceptance, and protected publication. Preserve and reject legacy, incomplete, or consumed
  templates with rebuild instructions; never boot or rewrite their provenance to retrofit them. The producer exports
  and smokes the OVA and
  derived Hyper-V ZIP, and creates an automatically selected annotated `virtualization-vX.Y.Z-rc.N` draft. Preflight
  resumes exactly one retained current-version staging operation or selects one greater than the maximum canonical
  ordinal inventoried across remote tags and every GitHub Release. It freezes that identity before mutation and reports
  only sanitized selector-source labels. Multiple retained operations and mismatched remote identity fail closed. A
  protected hosted job
  revalidates, signs, attests, and publishes that prerelease. Stable `virtualization-vX.Y.Z` promotion reuses the exact
  prerelease bytes and requires actual Proxmox and KVM smoke on uniquely labelled ephemeral runners. Self-hosted jobs
  receive neither signing secrets nor write-capable tokens. Virtualization workflows must never modify `vX.Y.Z`,
  signed appliance manifests or channels, `gh-pages`, or protected virtualization state. Existing tags, Releases, and
  assets are byte-idempotent resume points only; any identity or byte collision after selection fails closed, and tooling
  never advances to a replacement `rc.N` during the invocation.
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
- Packer and VMware Workstation are Windows-host prerequisites for the Photon image path. `qemu-img` is required only
  when converting the canonical OVA payload disks into the portable Hyper-V ZIP. KVM and Proxmox VE consume the
  unchanged OVA and use their native target storage formats during import. Record the applicable host prerequisites in
  artifact handoff notes.
- Release image builds must generate disposable credentials inside the protected job, scrub every credential hash,
  application secret, machine ID, and SSH host key before export, and remove the build account before shutdown. Packer
  retains its SSH communicator while polling for poweroff, so schedule build-account removal only from a detached
  root-owned context that captures the disposable account's non-root numeric UID, gives only that UID bounded graceful
  and forced termination windows, and verifies its session is gone before deletion. Verify the account, home, sudo
  authorization, and build-only finalizer are absent before powering off so any failure blocks export. Every
  deployment regenerates identity before networking. Never bind a template SSH host key into OVA or converted-artifact
  provenance; retrieve the regenerated public key and one-time credential only through the authenticated hypervisor
  metadata channel or local console.
- Pin every Photon image Packer plugin to one reviewed exact `X.Y.Z` version. The supported Windows wrapper must run
  `packer init` and `scripts/check_packer_plugins.py` before validation or build, and canonical Packer CI must perform
  the same resolution check between initialization and validation. A range constraint or a selected binary whose
  filename does not match the exact required version fails closed. Plugin updates are explicit dependency changes that
  update the affected template, relevant image documentation, tests, and the normal Atlaso patch version together.

### Preserved implementation boundaries

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
  cleanup's narrow shutdown rewrite admission only after its own successful stop: preserve every VMX assignment except
  validated `cleanShutdown`/`softPowerOff` booleans, bind the stopped identity and hash under a read lock, and retain all
  other root/descendant identities. No other replacement is admitted. Use checked
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
- VMware release images use separate compacted Photon OS and required Atlaso system-content payload VMDKs, followed by
  empty 500 GiB depot and backup disks. Preserve `/opt/atlaso` and appliance-wide PowerShell modules on the UUID-mounted
  system-content disk, size-gate individual OVF release assets below 2 GiB, and publish the aggregate OVA only when it
  independently fits that limit. OVF export may recursively replace only a strict, non-reparse-point descendant of the
  repository OVF output root. `-Release` and `-Prerelease` provide implicit replacement only for the canonical derived
  destination; an explicitly supplied existing destination still requires `-Force`, which never widens the approved
  deletion boundary. Low-level OVF export never changes GitHub. Manual virtualization orchestration through
  `-Prerelease` derives and freezes one exact annotated `virtualization-vX.Y.Z-rc.N` tag after preflight. It resumes the
  single retained current-version staging operation, or selects one greater than the maximum canonical ordinal found
  across remote tags and all Releases. Multiple retained operations, mismatched remote identity, and later collisions
  fail closed without advancing to another ordinal. The producer may create only that tag and hidden draft after both
  Windows smokes pass; it never publishes or reclassifies that draft. Only the protected hosted finalizer may sign,
  attest, and publish the prerelease.
- The maintainer workstation and any explicitly approved ephemeral Windows alternative are trusted virtualization
  producers. Install the exact signed software wheel and complete hash-verified offline CPython 3.14 wheelhouse during
  template construction. Preserve installed VMware Tools, both offline QEMU/Hyper-V RPM closures, and untouched
  deployment initialization through final updates, cleanup, shutdown, and compaction. Never restart a completed source
  template for software installation, provider selection, customization, or export preparation. Require powered-off
  identity and final VMX/payload hashes before export and recheck them after export and disposable-import smokes.
  Only the ownership-verified successful builder may atomically remove empty ordinary lock directories using
  no-follow deletion handles. Nonempty directories, lock files, and reparse points fail closed. Recheck power state
  and require no surviving lock entries before provenance. Export and retained-template admission remain read-only
  and reject every lock entry, including empty directories.
  Require the schema-v3 completed-template contract and exact verified software identity for retained reuse, candidate
  acceptance, and protected publication. Preserve and reject legacy or consumed templates with rebuild instructions;
  never retrofit them by booting or rewriting provenance. Published releases remain immutable.
- The maintainer workstation and any explicitly approved ephemeral Windows alternative are trusted virtualization
  producers while building a release. They receive no signing key, and the protected hosted finalizer independently
  verifies software-source binding, selected privileged assets, provenance, exact virtualization bytes, and publication
  state as defense in depth; it is not a reproducible Photon image builder and does not claim to authenticate the entire
  root filesystem against a compromised producer. Keep public-repository Windows runners offline except for the approved
  release, bind them to one release-specific label, and destroy or sanitize them immediately afterward.
  Before evidence validation, index construction, signing, attestation, or publication, require the complete
  suffix-matching Hyper-V archive-name set to equal exactly the single version-derived canonical filename. Stable
  promotion must independently enforce the same signed asset-set invariant before reusing those bytes.
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
  administrator downloads a signed release on demand. VMware wheel deployment must never build, package, upload,
  validate, or install Inventory Linux. Publish it only through the protected manual Inventory
  Linux release workflow for an exact successful `main` CI SHA. Every workflow build is a final immutable
  `inventory-linux-v<version>` release and signed Pages pointer; never attach it to an appliance release or introduce
  development, preview, or staging channels.
- VMware wheel deployment validates `RemoteDirectory` before build or upload as an absolute POSIX path containing only
  ASCII letters, digits, `/`, `.`, `_`, and `-`, with no `.` or `..` components. Keep key/agent authentication and the
  supported Windows 1Password SDK password bridge on this shared path contract, and serialize every key-backed
  remote shell argument explicitly. The bridge must bind the exact verified `Atlaso` Environment's concealed
  `DEFAULT_ADMIN_PASSWORD` variable only inside the bounded deployment child, bind 1Password authorization and
  Environment retrieval to the deployment timeout, stage its complete runtime from the generated seven-day
  hash-verified deployment lock with standard GIL-enabled Windows x64 CPython 3.14. Verify the exact immutable
  compatibility-wheel URL, filename, size, SHA-256, and GitHub release host chain before credentials or VMware
  activity; install it with
  index access disabled, preserve known-host verification, and fail
  closed for missing SDK support, authorization, Environment, variable, masking, or redaction. Prefer the
  checkout-local current-user DPAPI service-account token, retain explicit-account desktop authorization as fallback,
  and never use a password or token argument, plaintext token file, local `.env`, caller-provided
  `OP_SERVICE_ACCOUNT_TOKEN` or `DEFAULT_ADMIN_PASSWORD`, or the retired `ATLASO_DEPLOY_SSH_PASSWORD` fallback.
- Every task-owned VMware test VM used for pull-request validation derives its identity from the exact positive
  pull-request number through `Atlaso-PR-<number>-<purpose>[-<collision-safe-suffix>]`. Sanitize the short purpose and
  optional suffix through the shared VMware identity helper. Keep the VMware `displayName`, canonical output or
  lifecycle-lab directory, VMX filename where applicable, result/log identity, and reported absolute VMX evidence
  consistent with that name. Use a collision-safe suffix for multiple VMs owned by one pull request without removing
  the `PR-<number>` segment. Before reuse, redeploy, or cleanup, require the expected canonical name, exact VMX path,
  matching `displayName`, and lifecycle ownership manifest; any mismatch fails before mutation. Never automatically
  rename, reuse, redeploy, or delete a generic, issue-only, or differently owned VM. The normal test-VM wrapper may use
  `-LocalBuilder` before a pull request exists, deriving
  `Atlaso-Local-<12-character-source-commit>-<purpose>[-<collision-safe-suffix>]` from one clean checked-out branch.
  This is an exploratory local VM, not acceptance evidence. Lifecycle labs remain PR-only, and acceptance evidence must
  come from the resulting PR-numbered VM after the pull request exists.
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
  Prefer the checkout-local current-user DPAPI service-account token and retain explicit `-OnePasswordAccount` desktop
  authorization as fallback. Decrypt the token only inside a bounded child, expose it only to the immediate SDK or
  `op run` process, and remove the SDK environment copy immediately after client initialization. Reject plaintext token
  files and caller-provided `OP_SERVICE_ACCOUNT_TOKEN`.
  The VMware Photon image wrapper reuses this exact pinned Environment selector and bounded SDK/DPAPI foundation for
  omitted `-SshPassword` and `-BootstrapAdminPassword`, mapped respectively to concealed `DEFAULT_ROOT_PASSWORD` and
  `DEFAULT_ADMIN_PASSWORD`. Explicit `SecureString` values remain independently authoritative. Complete credential
  preflight and task-owned bridge cleanup before network discovery or preparation, output cleanup, ISO remastering,
  Packer initialization, or other image mutation; retain exact-byte validation and all sensitive ISO/Packer-variable
  cleanup. Resolve `PipGlobalIndex` and `PipGlobalIndexUrl` once as one credential-free HTTPS pair before credential
  preparation, require both or neither, and propagate the exact resolved semantics to both the host-side hash-locked
  SDK dependency download and the guest Photon build. A partial or explicit pair must never inherit or fall back to
  public PyPI. Keep the host configuration and parent-to-child transport out of arguments and process listings, and
  classify dependency failures only through bounded caller-scoped sanitized diagnostics; the generic process runner
  must not emit arbitrary child streams. Run the complete plaintext-consuming image workflow in a separately bounded
  PowerShell child; the parent
  may pass only current-user DPAPI ciphertext. Place every plaintext kickstart, remastered ISO, and Packer variable
  artifact inside the exact task-owned child root, and require the parent to remove and verify that root after ordinary
  exit or whole-tree termination so a killed child cannot bypass sensitive cleanup. If whole-tree termination is
  unproven, retain the exact root plus a non-secret cleanup marker. Before resuming the suspended child, durably bind
  the prior controller, unique named Windows job, and child PID/start identity. Same-boot recovery may terminate only
  that exact job after the prior controller is absent and must prove every owned process gone before exact-root cleanup.
  PID reuse, identity drift, a surviving descendant without the recorded root, or incomplete termination remains
  fail-closed; legacy and ambiguous markers require a changed Windows boot identity. Remove the marker only after root
  absence is verified. Apply the same boot-bound recovery ownership to the shared SDK credential bridge. Durably
  publish each
  marker with write-through file and rename semantics before starting a child that can consume plaintext, then durably
  transition through root absence and a non-actionable retired tombstone before deleting the marker.
  The wrapper also owns the sole development-root exception to per-appliance CA generation: require the exact `Atlaso`
  1Password Environment's concealed `ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY`, validate it against the checked-in public
  `Atlaso Development Root CA` before mutation, pin and verify the exact Environment ID by SHA-256 before invoking `op`,
  bound and whole-tree-terminate every `op`/secret-child invocation and every post-staging VMware operation, and pass
  the signer only through a separately
  scrubbed normal-wrapper guest-info value. Encode canonical PKCS#8 DER once so the complete assignment remains below
  VMware's 4,096-character VMX line boundary. First boot must reconstruct standard PKCS#8 PEM, stage it mode `0600`,
  prove guest-info scrub, encrypt it with
  the VM-unique secrets key, remove staging even when encrypted import fails, and issue a unique HTTPS leaf. Commit
  guest-agent provider selection before potentially long offline-closure cleanup, and retain that cleanup as a
  mandatory 15-minute data-disk pre-start gate so VMware signer scrub can proceed concurrently without admitting
  appliance readiness early. Cleanup mode must erase only the offline closure; retain portable KVM and Hyper-V
  first-boot access until the next boot. Publish only bounded fixed non-secret first-boot stage identifiers for host
  timeout diagnostics.
  Commit a
  durable non-secret cleanup marker through a Windows write-through atomic rename before staging. Bind it to a
  non-secret VMX identity that survives VMware's legitimate power-on file replacement. Expose its marker path to
  rollback only after durable publication succeeds. A pre-publication failure before any
  secret child starts must preserve the original actionable error and remove only invocation-owned artifacts. Before
  launching rollback removal, durably bind the exact stopped VMX identity, quarantine path, and boot-bound child phase;
  first reconcile any exact identity-bound destination left by a completed rename whose caller reference was not
  published. If reconciliation is ambiguous or fallback publication fails, preserve the VM artifacts and do not start
  a removal child. Actual child-active or unproven state remains fail-closed across same-boot reruns.
  After encrypted import proof,
  gracefully stop the exact VM within a bounded deadline, prove the powered-off VMX signer assignment absent, restart
  it, and prove runtime guest-info remains empty before retiring the marker. Never substitute a hard power-off on this
  successful-import path; preserve the retryable marker if graceful shutdown cannot be proven. Later normal-wrapper
  invocations must retry its exact identity-bound stop, VMX
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
- Windows Inventory Linux and Photon builds select the dedicated `Atlaso-Build` WSL distribution by default. WSL is a
  pre-existing host prerequisite: ordinary builds must never install or configure WSL, create a missing distribution,
  change the default distribution, elevate, reboot, or remove a distribution. Keep the pinned setup contract, explicit
  distribution selection, native-Linux cache, Linux-only child `PATH`, per-repository `flock`, and checkout-wide output
  serialization described in the canonical contributor guide.
- Image download caches accept only checksum-verified payloads. Validate existing entries before reuse, remove only the
  exact expected corrupt payload and checksum metadata, download into unique same-directory partial files, and promote
  them only after pinned verification. Failed or interrupted downloads must not become accepted durable cache entries,
  and an ordinary rerun must recover without a force flag or manual cache surgery.
- Before the VMware Photon wrapper performs any Workstation, ISO, Packer, output, or image mutation,
  require a completely clean source checkout and admit one exact commit. Archive that commit into the invocation-owned
  build root, remove the build identity's write access for the complete child lifetime, launch the bounded child from
  the snapshot, and make every Packer file and shell source plus the exact HCL template consume only that tree through
  a separate disposable Packer working directory. Bind schema-v3 VMX provenance to the commit plus a
  deterministic full-snapshot file-count and SHA-256 inventory, and revalidate it before Packer and provenance
  emission. Reject dirty, ambiguous, changed, legacy-unbound, or unreproducible source state. Hyper-V and protected
  virtualization publication inherit this boundary only through the validated OVA; their downstream signature and
  software-source checks remain mandatory defense in depth.
- Atlaso does not support cloud-init metadata. Remove Photon's incidental `cloud-init` package immediately after the
  initial OS update, before any later systemd daemon reload, and fail final image verification if the package or its
  generator, service, or configuration paths remain. Keep first-boot ownership in Atlaso's platform services.
- Treat Packer HCL, systemd units/manager drop-ins, and sudoers fragments as protected deployment assets. Keep them in
  the checked-in inventory, run `scripts/check_deployment_assets.py` through pre-commit where native tools are
  available, pin every required Packer plugin to one reviewed exact version, and run `packer init` plus
  `scripts/check_packer_plugins.py` before either supported wrapper validates or builds. Canonical CI must perform the
  same exact-resolution check before full Packer validation and require native Linux systemd/sudoers validation. Pass
  the read-only GitHub Actions token to Packer only through `PACKER_GITHUB_API_TOKEN` on the canonical validation step
  for protected events and same-repository pull requests. Keep fork validation tokenless, checkout credentials
  unpersisted, and token material out of output, files, caches, and artifacts.
- Default VMware Workstation GUI image builds must repair only exact missing Atlaso registrations inside the configured
  output scope while the Workstation UI is closed, then start or reuse a responsive Workstation UI in a process separate
  from Packer before the synchronous `vmrun` start transition. Keep full artifact cleanup after network preflight, and
  retain the exact close-the-UI refusal when scoped repair is required. Bind bounded sanitized startup diagnostics to
  the expected
  VMX filesystem identity, provider inventory, exact running state, and configured builder TCP/22 endpoint until SSH
  provisioning begins. Remove raw Packer debug-log environment variables from the monitored child because they bypass
  redaction. On timeout, terminate only the Packer process tree and honor `-PackerOnError cleanup` through the checked
  exact-root cleanup; preserve exact artifacts for other failure selections. Never print connection credentials or VMX
  contents, and do not mask a start-handoff failure with an arbitrary delay.
- Before new credential retrieval, enforce the shared 240-character generated VMware path budget, including UUID memory
  files and lock directories. Prerelease preflight must check before source downloads; use the compact
  direct-under-operation builder layout for new outputs, preserve retained legacy layout and ownership state, and
  reject ambiguous layouts without moving or deleting artifacts.
- Before any canonical VMware Photon builder starts, atomically reserve one temporary static IPv4 address from the
  configured per-host pool. Parse the selected vmnet's exact `vmnetdhcp.conf` subnet, reject a pool or explicit address
  that overlaps a VMware DHCP range or fixed address, and exclude observed non-ICMP use. Serialize the durable ledger
  across Atlaso worktrees, bind each entry to the exact task worktree, source commit, branch, owner process, Windows
  boot identity, output root, VM name, and VMX path, and retain it while that exact VM remains active or recovery
  evidence is ambiguous. A dead owner alone cannot release its reservation during the same Windows boot because a surviving
  descendant could still start the VM. Permit stale recovery after either a valid controlling-parent termination
  receipt or a changed host-boot identity proves that tree gone, and the exact VM is inactive. Release checks must
  reject current host-interface assignments, running-VM address use, non-stale neighbor evidence, and unavailable
  provider observations. Stale-only neighbor-cache evidence may allow release of that completed reservation without
  asserting ownership of the cached MAC: every subsequent allocation must independently exclude the cached address,
  including explicit address requests. Never flush the neighbor cache to make an address eligible. Keep the
  non-secret release handoff outside temporary credential
  storage, never recover it while its exact owner process remains active, retry it after a preserved VM stops, and
  delete it only after exact ledger release succeeds. Never replay a dead same-boot owner's handoff unless the
  controlling parent proved complete process-tree termination, either in the current invocation or through its
  durable exact-allocation termination receipt. A later caller must verify that receipt and the original controller
  is inactive before rechecking VM and address state. Missing legacy proof still requires a host-restart boundary. Publish
  recoverable release intent before ledger admission, then publish both records with write-through replacement plus
  directory metadata synchronization. Release
  normally only after inactive-VM completion. Exclude every IPv4 address on the selected bridged host interface, and never
  let skipped topology preparation bypass read-only DHCP-state discovery. The completed appliance still uses management
  DHCP by default.
- Every task-owned Photon/Packer VMware builder requires the exact open same-repository pull request whose head branch
  and commit equal the checkout. Derive one canonical
  `Atlaso-PR-<number>-Photon-Builder-VMware[-<collision-safe-suffix>]` identity through the shared builder helper and
  keep it identical across Packer `vm_name`, Workstation `displayName`, output directory, VMX filename/path, address
  reservation, startup diagnostics, ownership manifest, provenance, cleanup scope, and reported evidence. Multiple
  builders for one pull request retain the PR segment and use sanitized suffixes. Explicit local/test builds use
  `-LocalBuilder` without a pull request and derive
  `Atlaso-Local-<12-character-source-commit>-Photon-Builder-VMware[-<collision-safe-suffix>]` from one clean checked-out
  branch. They retain the same snapshot, output, ownership, cleanup, reservation, and schema-v3 provenance controls;
  provenance records `builder_identity.kind` as `local`. Protected release and publication paths must reject local/test
  provenance. Protected release builders instead
  use the deterministic version-and-commit identity produced by that helper, optionally extended by workflow run ID,
  only after independently proving the exact reachable protected-main commit, immutable software-release tag, complete
  non-draft release asset set, and successful main push CI.
  Require the sibling ownership manifest before replacing a retained output. A task manifest may advance to a newer
  exact head only when repository, pull request, branch, canonical name, and suffix still match; retained reuse requires
  the exact commit. Require schema-v3 builder provenance before clone or export. Never rename, adopt, reuse, redeploy,
  or delete a legacy generic or differently owned builder.
  OVF export requires an explicit proven source VMX; exported product identity, deployed-appliance names, and immutable
  release asset names remain canonical and never inherit a transient pull-request number.
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
- Keep synchronized managed Photon repository files credential-free. For authenticated TDNF checks and installations,
  construct a root-only repository view in volatile `/run` storage, pass only its non-secret path to TDNF, and remove
  that view when each command exits. Never place Photon repository credentials in durable package-client configuration
  or command arguments.

## Photon VM Debugging Notes

- Task-owned Photon/Packer VMware builders use the exact open same-repository pull request whose head branch and commit
  match the checkout. The shared builder-identity helper derives
  `Atlaso-PR-<number>-Photon-Builder-VMware[-<collision-safe-suffix>]`; the same exact value owns Packer `vm_name`,
  Workstation `displayName`, the output-directory leaf, VMX filename/path, temporary-address reservation, startup
  diagnostics, sibling ownership manifest, schema-v3 provenance, cleanup target, and reported evidence. A second
  builder for one pull request uses a sanitized suffix without losing the PR segment. Explicit local/test builds use
  `-LocalBuilder`, require one clean checked-out branch, and derive
  `Atlaso-Local-<12-character-source-commit>-Photon-Builder-VMware[-<collision-safe-suffix>]` without querying a pull
  request. They retain the same immutable snapshot, output claim, ownership manifest, cleanup, reservation, and
  schema-v3 provenance controls; `builder_identity.kind` is `local`. Protected virtualization release and publication
  paths require release-builder provenance and reject local/test artifacts. Protected release builders use
  the helper's deterministic version-and-commit identity, optionally extended by workflow run ID, only after the wrapper
  independently proves the exact reachable protected-main commit, immutable software-release tag, complete non-draft
  release asset set, and successful main push CI. Reject missing,
  malformed, closed, fork-owned, branch-mismatched, commit-mismatched, ambiguous, generic, and differently owned
  identities before provider or target-filesystem mutation. Normalize trailing directory separators before deriving the
  sibling manifest and claim paths. A retained task output is replaceable only when its sibling manifest proves the same
  repository, pull request, branch, canonical name, and suffix; after checked cleanup, advance
  the manifest to the newly verified head. Retained reuse still requires the exact source commit. Hold an OS-enforced
  exclusive sibling-file claim from ownership admission through cleanup, Packer completion, and provenance publication
  so concurrent builders cannot adopt or mutate the same canonical output. After proven child-tree termination, the
  visible parent must hold the same exclusive output claim across its retained manifest and VMX checks, Workstation
  inventory repair, and UI launch, then release it before starting the isolated child. The bounded parent may perform
  timeout cleanup only when the child durably recorded its cleanup claim, including for an
  initially absent output. Every claimant must durably replace the sibling claim's invocation generation while holding
  it; the parent must then revalidate identity, reacquire the claim, and require the child's exact generation before
  cleanup so an intervening completed or failed build blocks deletion. Clone and export
  require exact builder provenance. Low-level OVF export accepts only an explicit proven source VMX. Never propagate
  transient PR identity into OVF/OVA product naming, deployed-appliance names, canonical release filenames, or
  immutable release assets. Before manifest or OVA generation, normalize and read back both the OVF `VirtualSystem`
  identifier and its `Name` as the requested canonical product name.

- Every task-owned VMware test VM used for pull-request validation has one canonical identity:
  `Atlaso-PR-<number>-<purpose>[-<collision-safe-suffix>]`. Require the exact positive pull-request number and sanitize
  the short purpose and optional suffix through `Atlaso.VmwareTestIdentity.psm1`. The same identity owns the Workstation
  `displayName`, normal output or lifecycle-lab directory, VMX filename where applicable, result/log directory, and
  absolute VMX evidence reported with validation. Multiple VMs for one pull request use distinct collision-safe
  suffixes while retaining the exact `PR-<number>` segment. Reuse, redeploy, and cleanup must rederive the expected
  identity and fail before mutation unless the exact directory, VMX path, `displayName`, and lifecycle ownership
  manifest agree. Never rename, adopt, reuse, redeploy, or remove a generic, issue-only, or differently owned VM
  automatically. Before a pull request exists, the normal test-VM wrapper may select `-LocalBuilder` and derive
  `Atlaso-Local-<12-character-source-commit>-<purpose>[-<collision-safe-suffix>]` from one clean checked-out branch.
  It retains the same exact directory, VMX, `displayName`, redeploy, and cleanup checks. This local VM is exploratory:
  lifecycle labs remain PR-only, and acceptance evidence must be collected from the PR-numbered VM after the pull
  request exists.
- Use the running VMware Photon VM for real functionality checks after appliance-impacting changes: validate focused
  local tests first, then install and test on the VM when behavior depends on Photon NICs, systemd, nftables, dnsmasq,
  resolver state, or `/ui/management/appliance-apply`.
- VMware Workstation lifecycle interop tests use VMX/VMDK artifacts and `vmrun.exe` through
  `scripts/windows/vmware/invoke-lifecycle-test.ps1`. Keep Workstation lifecycle VMs under
  `test-results/vmware-workstation-lifecycle/`, validate vmnet topology with
  `scripts/windows/vmware/prepare-networks.ps1`, and record any upstream tagged-trunk configuration needed by the test.
- Any newly implemented appliance feature that affects deployed behavior must be added to the VMware lifecycle coverage
  and validated through the lifecycle test before the feature is treated as complete. Keep the feature's local/unit
  tests in place, but use the lifecycle run as the interop acceptance check for Photon, virtual networking, service
  apply behavior, and client-observable results.
- For the default VMware test appliance, resolve the current IP with `scripts/windows/vmware/get-atlaso-vm-ip.ps1` and
  check web reachability with `Invoke-WebRequest https://<vmware-ip>/openapi.json -SkipCertificateCheck`. Use the
  bootstrap `admin` account for SSH connections. The normal `create-atlaso-test-vm.ps1` wrapper installs the current
  Windows user's existing `.ssh/id_ed25519.pub` and a separate test-only passwordless-sudo rule unless explicitly
  skipped, so key/agent-backed privileged checks use `sudo -n`; it must not generate a key or extend this authority to
  lifecycle or exported appliances. After startup, it reads the VM's public Ed25519 host key from test-only VMware
  guest-info, validates and fingerprints it, and prints it for explicit `known_hosts` verification; never substitute
  unauthenticated `ssh-keyscan` output. Root SSH remains disabled. Check SSH/service state with
  `systemctl status atlaso --no-pager`,
  `journalctl -u atlaso -n 120 --no-pager`, and relevant real-state commands such as `nft list ruleset`,
  `resolvectl query <name>`, `getent hosts <name>`, `ip link`, `systemctl status ntpd --no-pager`, or
  `systemctl status systemd-timesyncd --no-pager`.
- When the appliance web UI is unreachable, separate network reachability from service reachability: use host-side
  `Test-Connection <ip>` for ICMP, `Test-NetConnection <ip> -Port 8000` for the web service, and in-guest
  `systemctl status atlaso --no-pager` plus `journalctl -u atlaso -n 120 --no-pager`.
- ICMP can be intentionally blocked by nftables while SSH and HTTPS still work. Do not treat failed ping as proof
  that the VM is down; check TCP ports and the VMware console before changing networking.
- For VMware live appliance patching, prefer `scripts/windows/vmware/deploy-wheel.ps1`; it builds a local wheel, uploads
  it with `scp`, installs it into `/opt/atlaso/.venv`, syncs `scripts/appliance/atlaso-helper` to
  `/opt/atlaso/bin/atlaso-helper`, provisions every checked-in public release key under `/etc/atlaso/update-trust.d`,
  restores venv permissions, restarts `atlaso.service`, and verifies guest plus host `/openapi.json` with a readiness
  retry. It never builds, packages, uploads, validates, or installs the independently versioned Inventory Linux
  package; administrators manage that boot media through its signed release and installation workflow. Packer image
  definitions must explicitly stage `image/common/update-trust`, and provisioning must fail rather
  than build an appliance with no valid public release key. Use `-IpAddress <appliance-ip>` when the VM IP is known, or
  `-VmxPath "<path-to-vmx>"` for VMware discovery; do not pipe the VMX path or put the `.vmx` path on a separate line
  because PowerShell will try to execute it. For password-backed Windows deployment, verify exactly one `Atlaso`
  Environment and the concealed `DEFAULT_ADMIN_PASSWORD` variable by name, then pass its opaque ID with
  `-OnePasswordEnvironmentId`. Prefer the checkout-local current-user DPAPI service-account token; an explicit
  `-OnePasswordServiceAccountTokenFile` takes precedence, while `-OnePasswordAccount` retains desktop authorization.
  Use only standard GIL-enabled Windows x64 CPython 3.14, discovered automatically or supplied
  with `-OnePasswordPython`. Verify the immutable Atlaso compatibility-wheel manifest and release asset before any
  credential or VMware activity. The script must use the supported 1Password SDK integration, stage the SDK, Paramiko,
  and their transitive dependencies from the generated seven-day hash-verified deployment lock, install only from that
  offline wheel set, and fail closed when SDK preparation, authorization, Environment access, the unique
  variable, or masking is unavailable. Never pass a password
  or token argument, create a plaintext token file or local `.env`, set `OP_SERVICE_ACCOUNT_TOKEN` or
  `DEFAULT_ADMIN_PASSWORD` in the caller, or use the retired
  `ATLASO_DEPLOY_SSH_PASSWORD` fallback. The parent must perform local build and input preparation without the
  credential, then invoke one bounded Python child that retrieves `DEFAULT_ADMIN_PASSWORD` through the SDK and uses it
  directly for Paramiko without placing the password in the environment. Decrypt a service-account token only in the
  bounded launcher, expose it only to the immediate SDK process, and remove its environment copy immediately after
  client initialization. Start Python with `-I -S` and prepend only its explicit
  dependency path; caller-controlled child command-line values, startup hooks, and inherited `PYTHONPATH` must not
  observe or authorize password consumption. Password-backed Paramiko
  must load system known hosts and reject unknown keys; accept only one non-echoing account-password prompt and reject
  OTP/MFA or verification-code wording. Keep the password-backed remote-command timeout separate from the readiness
  timeout so a long but progressing deployment is not cut off by the post-restart readiness allowance.
  If uvicorn needs longer after reinstall, pass `-ReadinessTimeoutSeconds 120`. Use `-SkipHelperSync` only when the
  appliance helper is intentionally unchanged.
- The wheel helper's `RemoteDirectory` is one shared pre-upload contract for key/agent and password-backed SSH. Accept
  only absolute POSIX paths composed of ASCII letters, digits, `/`, `.`, `_`, and `-`, reject `.` and `..` components,
  whitespace, shell metacharacters, and control characters before local build work, and serialize every key-backed
  remote command argument with the shared POSIX quoting helper. On Windows, preserve separate `scp` source/destination
  arguments and cross a PowerShell login shell with one `sh -lc` argument containing a secret-free base64 command.
  Password-backed Paramiko must support password-only keyboard-interactive authentication, reject unexpected prompts,
  verify system known hosts, drain non-PTY stdout and stderr concurrently, and hand `sudo -S -p ''` a non-PTY password
  line before closing stdin. Do not depend on `scp` version-specific remote quoting.
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
  Managed DNS/service listener rules default to the built-in `Any` Source Group. Source Group writes belong to the
  canonical Network Objects router/service while retaining `firewall.managed_source_groups`, stable IDs, nested
  references, archive shape, and Firewall/WAN apply semantics. Keep **Any** visible and read-only; reject deletion while
  a nested group, operator Firewall rule, managed assignment, or NAT rule still references the object. Firewall and NAT
  wizard handoffs must use an allowlisted return token, tab-local draft storage, fresh server-rendered choices, and
  focus restoration. Legacy safe reads redirect only after management authorization; legacy writes invoke the same
  mutation handler and use a non-replaying `303`. DHCP bootstrap rules are interface-bound UDP/67 for IPv4 zones and
  UDP/547 for IPv6 zones and should
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
  reloads/restarts the service. When authoritative mode is enabled, it also extracts, validates, installs, and manages
  the isolated authoritative configuration and service described below. DNSSEC validation renders `dnssec` plus a
  Atlaso-managed trust-anchor include under the
  dnsmasq apply directory; the helper must verify installed dnsmasq DNSSEC support and copy package-provided trust
  anchors before `dnsmasq --test`. Rebind protection renders `stop-dns-rebind` plus explicit `rebind-domain-ok`
  exemptions, and query logging uses `log-queries=extra` only as a temporary troubleshooting setting because query names
  may be sensitive. Operator DNS records support A, AAAA, CNAME, TXT, SRV, MX, CAA, and explicit PTR, while A/AAAA still
  generate PTR answers through dnsmasq `host-record`. Authoritative mode uses an isolated dnsmasq backend on
  `127.0.0.1:5353`, with an address-qualified `auth-server` and every managed forward zone rendered with shared SOA
  policy and generated NS/glue. Each authoritative zone includes its managed DHCP subnets and the addresses of
  explicit A/AAAA records and generated glue; dnsmasq serves host-file addresses only within those subnets. The
  ordinary dnsmasq service forwards managed domains to that backend so selected
  service listeners preserve authoritative positive and negative answers while retaining PTR and upstream-recursive
  behavior within the existing listener and firewall boundaries. The client-facing cache must be disabled in
  authoritative mode because cached forwarded answers lose their AA flag. Apply, rollback, and reboot policy must manage
  both dnsmasq services as one DNS/DHCP unit. Generated nameserver glue must retain recursive PTR answers, and live DHCP
  names in managed-suffix DHCP scopes must be synchronized into the authoritative backend, retain DHCP lease UI/API
  visibility and reverse lookup, and be reconciled against active leases before backend startup. DNS health must require
  that backend while either desired or last-applied DNS configuration is authoritative.
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
- Store the exact successful ESXi activation manifest in its dedicated encrypted runtime record, outside Apply
  baselines and portable settings exports. Real Apply and factory reset publish that record in the same database
  transaction as their completion metadata; failures and dry runs cannot replace it. Bind hidden input changes with
  the ESXi-specific keyed snapshot marker before shared Apply projection. Never authorize from redacted previews or
  fall back when a protected record is unreadable. Recovery requires real Apply and a fresh client boot attempt;
  report it in the existing Validation rail using one request-local manifest index and shared revision checks.
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
- Treat image download cache existence as insufficient proof of validity. Verify cached payloads against pinned metadata
  before reuse; invalidate only the exact expected corrupt payload and checksum files; use unique same-directory partial
  files; and promote only verified content. A failed or interrupted transfer must not become an accepted durable cache
  entry, and ordinary retry must reacquire corrupt content without requiring a force flag or manual deletion.
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
  `appliance:https` certificate; the root CA must not be baked into reusable images. The sole exception is the normal
  VMware test wrapper's checked-in public `Atlaso Development Root CA`: require its matching concealed private key from
  the exact `Atlaso` 1Password Environment, retry credential-independent pending signer cleanup before resolving new
  Environment configuration, load an omitted ID only from the checkout-local, Git-ignored
  `.atlaso-local/onepassword-environment-id` file, pin and verify that ID by SHA-256, require an Environments-enabled beta
  CLI before invoking `op`, and cryptographically verify the retrieved signer against the checked-in certificate before
  mutation. For each omitted normal-wrapper `-AdminPassword` or `-RootPassword`, use the supported bounded Windows
  1Password SDK pattern to retrieve only the corresponding exact, unique, concealed `DEFAULT_ADMIN_PASSWORD` or
  `DEFAULT_ROOT_PASSWORD` from that same verified Environment. Preserve each explicit `SecureString` independently.
  Prefer the checkout-local current-user DPAPI service-account token before desktop discovery. An explicit token file
  takes precedence over an explicit account; without a token, resolve exactly one local 1Password CLI account. Select
  standard GIL-enabled Windows x64 CPython 3.14 registered with the Windows launcher. Accept current Python Install Manager
  bracketed architecture selectors while retaining legacy launcher and vendor-tagged registrations. Reject Python
  3.10 through 3.13, x86, ARM64, free-threaded `3.14t`, malformed entries, and missing executables without
  masking a lower compatible runtime. Explicit selectors remain authoritative. Without a token, zero or multiple
  desktop accounts and a missing
  compatible runtime must fail before mutation.
  Keep plaintext out of the PowerShell parent, arguments, caller-controlled environment, logs, output, markers,
  evidence, documentation, and GitHub surfaces by exchanging only current-user DPAPI ciphertext between bounded
  children. Store a service-account token only as current-user DPAPI ciphertext with access limited to that user and
  SYSTEM. Never accept caller environment variables, repository defaults, plaintext token files, local `.env` files, or
  interactive password prompts. Fail before network preparation, cleanup, disk reset, or cloning, and keep `-WhatIf`
  credential-free. Bound
  each secret child and post-staging VMware operation and require proven complete process-tree termination before
  mutating the VM or VMX during rollback. Persist boot-bound child-active phases for staging, VM start, and artifact
  removal. If termination is unproven, preserve the VM and VMX, or keep reused disks quarantined during removal, until
  a Windows host restart proves the child tree is gone. Validate the
  key before host mutation, use only canonical base64 PKCS#8 DER in the separately scrubbed test-wrapper guest-info path
  so its complete VMX assignment stays below 4,096 characters, reconstruct standard PKCS#8 PEM for staging, encrypt it
  with each
  VM's unique secrets key, scrub plaintext staging when import fails, and issue a unique HTTPS leaf. Commit guest-agent
  provider selection before potentially long offline-closure cleanup, and keep that cleanup as a mandatory data-disk
  15-minute pre-start gate so VMware signer scrub can run concurrently without admitting appliance readiness early.
  Reserve additional data-disk unit time for formatting and mounting after the full cleanup deadline, and retain enough
  host import-proof time for cleanup, disk preparation, and bootstrap startup.
  Cleanup mode erases only the offline closure and must retain portable KVM and Hyper-V first-boot access until the next
  boot. Host timeout diagnostics may consume only bounded fixed non-secret first-boot stage identifiers. Commit a durable
  non-secret cleanup marker through a Windows write-through atomic rename before staging and bind it to a non-secret
  VMX identity that survives VMware's legitimate power-on file replacement. After encrypted import proof, stop the
  exact VM only through a bounded graceful shutdown, prove the powered-off VMX signer assignment absent, restart it,
  and prove runtime guest-info remains empty before retiring the marker. Never fall back to hard power-off on the
  successful-import path; retain the retryable marker when graceful shutdown is unproven. Later normal-wrapper
  invocations must retry its exact identity-bound stop, VMX scrub,
  artifact removal, and data-disk restoration before
  1Password preflight or any new mutation. Persist the
  stopped/scrubbed phase before artifact removal so a retry can safely resume restoration from an absent artifact root.
  The VMware Photon image wrapper uses that same pinned selector and bounded SDK/DPAPI credential foundation. For each
  omitted `-SshPassword` or `-BootstrapAdminPassword`, retrieve only the exact concealed `DEFAULT_ROOT_PASSWORD` or
  `DEFAULT_ADMIN_PASSWORD`, while preserving each explicit `SecureString` independently. Complete Environment,
  account, SDK, uniqueness, concealment, value, and cleanup preflight before network discovery or preparation, output
  cleanup, ISO remastering, Packer initialization, or any other image mutation. Keep plaintext out of the PowerShell
  parent, arguments, caller environment, durable files, output, logs, Packer diagnostics, and provenance, and preserve
  exact-byte validation plus sensitive kickstart, ISO, and Packer-variable cleanup. Resolve `PipGlobalIndex` and
  `PipGlobalIndexUrl` once as a complete credential-free HTTPS pair before the SDK or image network paths run. Require
  both or neither, apply the exact pair to the private host-side pip configuration and guest Photon build, and forbid
  partial-default or public-PyPI fallback. Transport the pair to the isolated image child through the protected bundle,
  not process arguments. A dependency failure may expose only an allowlisted bounded category derived from captured
  stdout and stderr or a no-detail fallback; keep the generic bounded runner non-disclosing. Run the complete
  plaintext-consuming image workflow in a separately bounded PowerShell child; the parent may pass only current-user
  DPAPI ciphertext. Place every plaintext kickstart, remastered ISO, and Packer variable artifact inside the exact
  task-owned child root, and require the parent to remove and verify that root after ordinary exit or whole-tree
  termination so a killed child cannot bypass sensitive cleanup. Run boot-bound cleanup-marker and pending-reservation
  recovery before validating the identity for a new task or release build, because a closed or advanced PR must not
  strand prior sensitive state. If whole-tree termination is unproven, retain the exact root plus a non-secret cleanup
  marker. Before resuming the suspended child, durably bind the prior controller, unique named Windows job, and child
  PID/start identity. Same-boot recovery may terminate only that exact job after proving the prior controller absent,
  and must prove every owned process gone before exact-root cleanup. PID reuse, identity drift, a surviving descendant
  without the recorded root, or incomplete termination remains fail-closed; legacy and ambiguous markers require a
  changed Windows boot identity. Remove the marker only after root absence is verified. Apply
  the same boot-bound recovery ownership to the shared SDK credential bridge. Durably publish each marker with
  write-through file and rename semantics before starting a child that can consume plaintext, then durably transition
  through root absence and a non-actionable retired tombstone before deleting the marker.
  Before persisting rollback state, reject configured data disks that repeat the same descriptor, hard-linked alias, or
  shared extent by filesystem identity. Before deleting a completed marker, write-through transition it to a
  non-actionable tombstone so a post-crash
  directory-entry resurrection cannot trigger cleanup of a successful VM.
  Keep lifecycle, Hyper-V, reusable-image, and exported-appliance paths outside that trust domain. Default wrapper wait
  verifies the exact public fingerprint; Windows trust is explicit and idempotent, `-NoStart` is forbidden, and
  certificate/key rotation is one coordinated repository-and-Environment update. Nginx redirects public HTTP/80 to
  HTTPS/443 and reverse-proxies HTTPS to uvicorn on `127.0.0.1:8000`. Appliance FQDN or management IP changes should
  reissue the managed leaf certificate automatically; root CA replacement remains an explicit rotation workflow. When
  HTTPS is disabled or the dedicated complete factory-reset transaction is applied, nginx serves public HTTP/80 as a
  plain reverse proxy to the same loopback upstream and does not expose a management HTTPS listener. Before nginx
  activation, the helper requires consecutive success from the configured loopback `/openapi.json`; after reload it
  requires the loopback and guest-local address/public-port front door to remain healthy. It daemon-reloads the durable
  service drop-in without restarting Atlaso. Persist and sync root-only backups plus a recovery marker beneath the
  root-owned `/var/lib/atlaso-privileged` boundary before candidate mutation; use no-follow descriptor-relative reads
  and reject unsafe ownership, modes, links, or file types during recovery. Sync every final candidate file and parent
  directory before committing readiness. Record a durable terminal phase before backup or marker cleanup after either
  candidate readiness or completed rollback; cleanup failure must retain terminal proof and retry cleanup without
  restoring files. Run recovery before Atlaso startup. Protected management handoff and factory-reset admission must
  reconcile retained ordinary front-door state before their wider snapshots or mutations begin. Candidate activation,
  readiness, or interruption failure restores the exact previous nginx site/include/main files and service drop-in,
  then validates and reloads the restored front door; incomplete prepared-state recovery blocks startup.
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
  The public CA portal factory hostname is `ca.<appliance-domain>`: `/ui/public/ca` shows public trust material and
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
- Physical Interfaces automatically refresh observed Photon NIC inventory on appliance startup and may also
  refresh it manually from the page, but host inventory is read-only context; desired-state edits remain separate and
  enforcement still goes through `/ui/management/appliance-apply`.
- When the dedicated management interface uses IPv4 DHCP, its direct-edit grid discovers a usable DHCP-protocol default
  route on that exact host interface. DHCP-to-static conversion reviews the observed CIDR and on-link gateway together
  before saving both as desired state. No observed gateway remains an explicit supported isolation choice with an
  off-subnet-connectivity warning, and clearing a configured gateway requires the same warning.
- Host NIC reconciliation must match observed adapters by MAC address before Linux interface name. When a host NIC
  disappears, mark the missing physical interface inert, set dependent VLANs disabled/admin down where modeled, remove
  the missing interface and derived IP addresses from service listeners, disable services left without any listener, and
  log/audit the cleanup so operators are not trapped behind invalid appliance-apply state.
  Preserve NAT ingress and egress selections when a target disappears. Report enabled affected rules as invalid for
  explicit administrator review; never silently drop ingress members, infer replacements, or disable the saved rule.
- Real network apply is Photon `systemd-networkd` backed. It may install Atlaso-owned `.network`/`.netdev` files under
  `/etc/systemd/network/`, reload networkd, reconfigure non-management links, create/update desired VLAN links, and
  delete VLAN links explicitly derived from successful Atlaso network apply history. The appliance image's default
  management networkd file should match only `eth0`, not `eth*`/`en*`, and Atlaso should retire Photon catchall network
  defaults such as `50-static-en.network` and `99-dhcp-en.network`. The default desired state keeps management on `eth0`,
  but an operator may assign the single dedicated management role to another physical interface or use only flagged
  access listeners. Do not blindly reconfigure a dedicated management link without reachability safeguards. When one
  exists, management uses its own policy-routing table and must never forward traffic from or to access/route networks.
  Persist each static dedicated-management connected prefix as an on-link route in table `100` before its source rule
  can select that table, together with the family-matching default route. Address persistence and outbound gateway
  reachability alone are insufficient because a missing connected route sends same-subnet replies through the gateway
  after reboot. Non-management lab routes use the lab route table.
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
- A static management-to-access physical-interface mutation captures valid IPv4 and IPv6 gateways before clearing
  management-only fields and stages enabled canonical defaults for the converted access target in the same transaction.
  Reuse equivalent routes, reject conflicting family defaults with complete rollback, warn without inventing missing
  gateways, audit both Network and Routing & WAN, and mark Appliance Settings dependent. A migrated route not
  present in the last-applied WAN baseline selects WAN into the existing protected management handoff with a validated
  rollback config; it does not create another host-mutation path.

### Preserved implementation boundaries

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
  unavailable; shared gateway validation, global Apply, baseline commit, and rollback remain authoritative. During a
  protected handoff, revalidate the candidate address after resolver and DNS activation and before binding nginx;
  networkd can briefly withdraw a DHCP-to-static address while IPv4 conflict detection restarts. Preserve observed
  DHCP DNS from the prospective effective listener when the same desired-state edit enables its Access role, flag, or
  admin state, without changing the persisted interface before validation.
- Keep **Static Routes** separate from **Routing Permissions** in operator language. Static Routes choose destination,
  gateway, target interface/VLAN, and metric in the lab route table; Routing Permissions authorize forwarding between
  interface/VLAN networks, with route-role paths generated automatically and Access networks requiring explicit rules.
  The Static Route wizard must make **Default route** mutually exclusive with **Destination CIDR**, require an explicit
  IPv4 or IPv6 family plus a same-family next-hop gateway for defaults, persist canonical `0.0.0.0/0` or `::/0`, and
  allow only one default per family. Destination-specific routes keep a required CIDR and optional gateway for directly
  connected paths; API callers may continue to submit canonical `/0` CIDRs.
  Static Routes, Routing Permissions, and WAN Policies belong to Routing & WAN; source NAT and port forwarding belong to
  Traffic Publishing. Source NAT supports IPv4/IPv6 masquerade or fixed SNAT. Port forwarding owns exact dual-stack
  listener mappings and read-only generated Firewall admissions; its Firewall/NAT publication and baselines are paired.
  All five are
  wizard-backed Tabulator collections. Add launches
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
- VLAN Interfaces use the shared wizard-backed Tabulator with the ESX Storage interaction. Keep every persisted field,
  including Admin Up, out of inline editing and review the complete VLAN record in the add/edit wizard. New VLANs
  default to Admin Up; edits preserve saved state; a missing-parent VLAN may remain saved only while disabled. Saving
  changes desired state only, and global Appliance Apply owns host enforcement.
- Classify Web Terminal management page, ticket, and WebSocket eligibility from the last-applied Network binding,
  including flagged access physical and VLAN listeners. Pending desired edits must not reclassify the applied listener;
  handoff commit moves all three surfaces, rollback retains the old listener, and explicit extra listeners stay public.
- When local DNS points the management resolver to loopback, recover empty DNS service upstreams from the exact
  management interface's systemd-networkd DHCP lease. Reject loopback, unscoped IPv6 link-local, duplicate, malformed,
  and other-interface lease values, preserve explicit upstream precedence, and fail both desired-state and helper
  validation when DHCP fallback is required but unavailable.
- Derive every factory-owned service hostname from the domain portion of the canonical appliance FQDN. Reconcile fresh
  seed, OVF first boot, appliance-domain changes, settings restore, factory reset, and existing development state through
  one registry. Migrate only the packaged default or the exact prior factory domain, preserve customized hostnames and
  operator-owned DNS rows, remove stale exact-marker app-owned A/AAAA/CNAME aliases on conflict, and keep coupled issuer,
  certificate, endpoint, and Appliance Apply desired state coherent.

## Public Services Front Door

- Management-role interface addresses dispatch `/` to `/ui/management`; all authenticated management pages and their
  browser-only support/action endpoints stay under that canonical root.
- A management-role physical interface exposes the management UI inherently and has no exposure flag. Access-role,
  access-mode physical interfaces and enabled access-role VLANs may set `access_management_ui_enabled`. They remain
  ordinary access interfaces for routing, service selectors, public UI, and public services. Allow at most one dedicated
  management role, allow multiple flagged access listeners, and reject state with neither an effective dedicated role
  nor an active flagged access listener. A management-to-access conversion enables the flag atomically; an
  access-to-management conversion clears it.
- Firewall generation treats dedicated and flagged access management listeners as the same administrative reachability
  boundary for TCP/22, TCP/80, and TCP/443. Preserve the selected Source Group predicate through UI/API previews and
  protected-handoff old, candidate, final, and rollback rules. Do not admit TCP/22 on an unflagged access network, and
  do not couple this listener admission to the separate root-SSH policy.
- Non-management interface addresses dispatch `/` to an unauthenticated public service directory at `/ui/public`
  scoped to the called IP/host. The page must list only enabled public services whose desired listen addresses include
  that IP, and must show
  a minimal `No public services on this interface` state when none match.
- When web terminal access is enabled for the called non-management interface, include a `Web Terminal` service tile
  linked to that address's HTTPS `/ui/public/terminal` route. Do not show the tile on unselected interfaces, and do not
  invent an interface DNS name for the Name/IP toggle.
- Resolve Web Terminal management page, ticket, and WebSocket eligibility from the last-applied Network binding,
  including flagged access physical and VLAN listeners. Pending desired edits do not reclassify the active listener;
  successful handoff commit moves it, rollback retains it, and explicit additional terminal listeners remain public.
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
  reloads nginx, and keeps management nginx config separate. During a protected handoff, the Public Services site owns
  flagged Access management sockets on HTTPS port 443; the dedicated management site publishes those Access addresses
  itself for HTTP or a different HTTPS port. The sites must not bind the same socket twice at final publication.
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

### Preserved implementation boundaries

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
  child process; never read the value into agent-visible output. A service-account token may be stored only as
  current-user DPAPI ciphertext in the Git-ignored checkout-local path, with current-user-and-SYSTEM access, and may be
  decrypted only inside a bounded child. Never fall back to chat, plaintext repository files, local `.env` files,
  shell arguments, jobs,
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
- Domain choices must come from managed DNS zones. Prefix and suffix are optional defaulting fragments. Keep one
  editable reviewed hostname label per selected catalog component; pattern changes update untouched defaults, catalog
  changes preserve deliberate overrides for retained components, and clearing the pattern restores catalog hostnames.
  Keep compact rows free of redundant visible input labels while providing each hostname input an accessible component-
  specific name. Require an explicit non-mutating Populate step that displays planned allocations and enables creation
  only for the exact signed, time-limited actor, input revision, and allocation plan; any deployment, domain, address,
  pattern, or hostname change must clear that revision and require Populate again. Recompute current DNS and DHCP
  availability at creation and reject drift from the signed allocation instead of silently changing reviewed results.
  Submit the exact component-keyed mapping to creation and deletion, reject missing, duplicate, unknown, out-of-catalog,
  empty, or malformed entries, and derive and validate every FQDN on the server before writing any records.
- VCF Installer OVA deployment must treat the destination `OvfManager.ParseDescriptor` result as authoritative for
  deployable properties, defaults, deployment options, warnings, and errors. Pass the complete reviewed property
  mapping to `CreateImportSpec`; sanitize warnings against every submitted value. Bind a direct `HostAgent` connection
  to its one host while preserving vCenter automatic placement unless a host was selected. Before power-on or follow-up
  DNS, trust, or depot work, verify every reviewed property through the target's supported OVF transport. Direct ESXi
  discards `vAppConfig` during import: install a bounded, escaped `guestinfo.ovfEnv` document on the exact powered-off
  imported VM, using the generated import specification's qualified class/id/instance keys, reviewed values (including
  empty values), and non-editable defaults. Require the descriptor's `com.vmware.guestInfo` transport and fresh complete
  XML/value readback; reject missing, duplicated, malformed, or changed properties. Keep vCenter's vApp-property and
  declared-transport verification. Installation or verification failure must remove only the exact task-created VM;
  cleanup failure remains a truthful partial deployment. Never expose serialized XML or property values in diagnostics.
- Starting address input is one IPv4 or IPv6 CIDR. IPv4 creates A records and IPv6 creates AAAA records. Allocate
  sequential usable addresses inside that network, skip occupied DNS addresses of the selected family, and also skip
  IPv4 DHCP reservation addresses.
- Treat generation as one transaction. Existing FQDNs are skipped without modification, and insufficient address
  capacity or any validation error must create no records. Return created and skipped rows with assigned or existing
  A/AAAA addresses in fetch responses.
- Keep component descriptions role-specific, such as `vCenter` and `VCF Automation`. Store helper ownership separately
  in structured DNS record metadata with source `vcf_helper`, the immutable catalog component key, and the reviewed
  generated host label; do not replace role descriptions with a generic generated-by label.
- Deletion must require shared modal confirmation and remove only A/AAAA records proven helper-owned for the exact
  submitted component and reviewed hostname mapping. Preserve unrelated, manual, mismatched, and legacy
  description-only records even when their names or descriptions match the current catalog.
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

### Preserved implementation boundaries

- VCF Helper VCF Installer imports use the destination `OvfManager.ParseDescriptor` contract and a complete reviewed
  property mapping. Direct standalone ESXi imports bind deterministically to the endpoint's single host. Before power-on
  or DNS, trust, and depot follow-up, verify every reviewed value through the target's OVF transport. Direct ESXi
  requires a bounded, escaped `guestinfo.ovfEnv` document using the generated import specification's qualified
  class/id/instance keys and appliance defaults, followed by fresh exact-value readback. Do not require ESXi to retain
  `vAppConfig`, which it discards during import. Preserve vCenter's vApp property and declared-transport verification.
  Remove only that task-created VM if installation or verification fails, and report cleanup failure as a partial
  deployment. Never log the environment XML or values. Sanitize parser and import warnings against all submitted values.

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

### Preserved implementation boundaries

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
- VCF Offline Depot login return targets must be reconstructed beneath the server-owned `/PROD` prefix after strict
  relative-path validation. Unsupported or malformed destinations fall back to `/PROD/`; never redirect a successful
  depot login to an authority, scheme, traversal path, or browser-equivalent backslash form supplied by the request.

## VCF Private Registry

- VCF Private Registry is a Harbor-backed appliance service for staging VCF Supervisor Service bundles in a private OCI
  registry.
- The registry listen targets must follow the same service binding rule as VCF Backups: access physical interfaces with
  IPs and VLAN interfaces with IPs; exclude trunk physical interfaces.
- The factory registry hostname is `registry.<appliance-domain>`, and the default Harbor project is
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

- Routing & WAN owns static route desired state, forwarding, and interface/VLAN-level
  `tc/netem` latency/error simulation.
- Persist the global Routing, NAT, and WAN Simulation switches as safe settings. Fresh install and factory reset are
  off; legacy Routing/WAN settings derive once from effective enabled rows. Explicit legacy NAT intent migrates to the
  canonical Traffic Publishing setting. Keep every route, permission, NAT rule, WAN
  policy, and assignment saved while its feature is off. Routing gates lab routes, rules, and IPv4/IPv6 forwarding;
  NAT is effective only with Routing; WAN Simulation is independent. Management reachability remains outside the lab
  Routing switch.
- Label path entries **Static Routes** and forwarding authorization **Routing Permissions**. Keep Static Routes,
  explicit Routing Permissions, and WAN Policies on Routing & WAN, with Source NAT on Traffic Publishing.
  All four remain wizard-backed Tabulator collections using the ESX
  Storage reference. Add launches from the bottom row; edit launches from row double-click or its context action;
  generated route-role permissions remain read-only; and ordinary persisted Enabled state remains directly editable.
- Keep **Default route** mutually exclusive with **Destination CIDR** in the Static Route wizard. Default mode requires
  an explicit IPv4 or IPv6 family and a same-family next-hop gateway that is on-link for the selected target (or IPv6
  link-local), persists canonical `0.0.0.0/0` or `::/0`, and
  permits only one default per family. Destination-specific routes require a CIDR and may omit the gateway when directly
  connected. Preserve `/api/v1/routes` compatibility for callers that submit canonical `/0` CIDRs, and enforce the
  contract in browser validation, UI/API transports, desired-state validation, settings restore, and the WAN helper.
- Routing/WAN host mutation uses global `/ui/management/appliance-apply` `wan`; source NAT uses its separate `nat` unit.
  Do not add route-specific,
  NAT-specific, or WAN-policy-specific apply routes or direct helper calls from edit forms.
- The real apply path stages `/var/lib/atlaso/apply/wan/atlaso-wan.conf`; `atlaso-helper wan validate|apply` validates
  targets, routes, and netem values before running `ip route`, `sysctl`, and `tc`. Traffic Publishing stages its own NAT
  input and owns nftables translation.
- WAN impairment mode is v1 interface/VLAN-level only. Do not expose a route-specific WAN mode until it is fully
  implemented in the helper; track that design in `docs/project/routing-wan-roadmap.md`.
- Atlaso has no `wan` interface role and must not infer NAT or internet connectivity from an interface role.
- Physical and VLAN interfaces share exactly four roles: `management`, `access`, `route`, and `unused`. New UI, API,
  desired-state, and helper inputs reject retired or unknown roles. Bounded upgrade and settings-archive compatibility
  maps only the retired `services` and `storage` values to `access` without changing any other interface state.
  `Routing & WAN` and `Traffic Publishing` are explicit routing, translation, and loss workflows, not interface classes.
- Traffic Publishing supports explicit IPv4/IPv6 masquerade, fixed SNAT to a same-family assigned egress address,
  and managed destination NAT with exact listener, source, equal-length port mapping, and reviewed reply mode.
  Port forwards require Routing and paired Firewall/NAT validation, publication, rollback, and baseline recording.
  Generated admission is read-only and owned by its port-forward resource. Retire only owned connection marks when
  removing effective mappings; never flush unrelated connections. Do not add automatic broad NAT or
  non-reviewable NAT inferred only from interface role. Route-role networks may forward to other route-role networks by
  default; access networks require explicit routing rules; management is never a route, NAT, or routing-permission
  target.
- Source NAT requires one or more explicit inbound interfaces and one distinct outbound interface. Both sides use enabled,
  available access-mode physical interfaces or enabled VLANs on available trunk parents, with matching-family CIDRs
  and an access or route role. The dedicated management role and wrong-family targets are excluded;
  access-management flags do not
  exclude an otherwise eligible lab target. Any source means any same-family source within the selected ingress; CIDRs and
  shared source groups further restrict that boundary. Render every rule with `iifname` so appliance-local output
  cannot match. Preserve legacy unscoped rows for review and reject enabled apply until explicit ingress is selected.
  NAT remains explicit desired state reviewed through global apply; it is not inferred from an interface role.
- Validate live Routing/WAN state with `ip route`, `ip -6 route`, `ip rule`, `tc qdisc show`, `nft list ruleset`,
  `sysctl net.ipv4.ip_forward`, and `sysctl net.ipv6.conf.all.forwarding` after applying on Photon.

## Database And Verification

- This project is still in MVP scaffold mode. When model/schema changes make the development SQLite database stale,
  prefer deleting/reseeding `data/atlaso.db` over adding migrations, unless the user explicitly asks for migrations.
- Do not delete the DB for data-only seed/default updates if a focused in-place update is safer and the schema did not
  change.
- Backup / Restore owns desired-state settings archives. Do not include audit events, jobs, API tokens, password hashes,
  uploaded secret bodies, or runtime history in those archives. The separate passphrase-encrypted LDAP directory
  recovery export/import is an explicit special case that also lives on Backup / Restore; it preserves slapcat password
  hashes, remains outside the settings archive, and stages import for global LDAP apply. Settings restore leaves service
  status rows stopped, disabled, and `unconfigured`, and its host mutation still belongs to the global
  `/ui/management/appliance-apply` workflow. Complete factory reset is different: it atomically replaces every database
  table with factory/bootstrap records, invalidates all previous sessions, credentials, jobs, schedules, tokens, and
  audit history, then preflights and activates every factory apply unit through the dedicated reset transaction. Core
  routing, firewall, authentication, and management reachability must finish coherent; optional services must finish
  disabled; desired/applied baselines must match for all 17 units with no follow-up Apply. Factory reset must reseed only
  core defaults and must not recreate demo
  VLANs, trunk-only
  parent NIC posture, routes, NAT rules, WAN policies, DHCP scopes/reservations, firewall rules, CA requests, vSphere
  providers/trusted vCenters, depot download profiles, or service listener bindings, including after service restart.
  The only DNS record factory reset should reseed is the app-owned appliance FQDN record pointed at the management IP.
  After factory reset, only `eth0` should be desired admin up; other physical NICs should be desired admin down until
  an operator enables them. Disabled service settings should have blank listen interfaces and addresses until an
  operator selects a valid bind target.
- Authentication lifetime policy is immediate application state, not an Appliance Apply unit. Settings archives retain
  the configured browser inactivity timeout and maximum new-token lifetime but exclude server-owned browser-session
  activity and API-token rows. Browser expiry must be decided from persisted server activity before protected handlers;
  background polling and assets cannot extend it. Token policy is an issuance ceiling only, and never rewrites existing
  absolute expirations. Factory reset restores the packaged lifetime defaults while invalidating all earlier browser
  sessions and bearer tokens.
- Before replacing the database, complete factory reset must persist a bounded, non-secret journal/marker outside the
  database, construct and validate a private candidate database, preflight generated nginx, network, firewall, resolver,
  systemd, and service configuration, and quiesce Atlaso database writers. The same marker drives idempotent boot resume.
  After helper-action quiescence, stop and verify any pre-existing fixed-name management restart timer and service, then
  stop and verify the application services again before factory activation.
  Serialize scheduled, boot-resume, and console runners with a nonblocking appliance transaction lock; a rejected
  overlapping runner or active delay timer must not overwrite or remove the active runner's marker, candidate, or result.
  Preserve depot content, backup artifacts, managed ESX Storage payloads, and other documented payload paths by default;
  clear only logical database references and fixed transient Apply staging. Scrub secret-bearing staging on success and
  failure, including retained bootstrap and root SSH authorization files, VCF Backup authorized keys, Web Terminal CA
  material, pending terminal requests, KMIP operational state, managed Photon repository credentials, and
  Atlaso-synchronized package-source state. Keep
  credential-bearing repository removal durable by fsyncing its parent directory before advancing the reset marker.
  Keep
  explicit keep-or-change choices for both the bootstrap administrator and root passwords. New values must satisfy the
  packaged factory Local Users policy, remain only in request-bound mode-0600 transient and root-owned durable reset
  recovery files, reach OS password tools only through the constrained helper and stdin, and never enter the database,
  marker, jobs, audits, logs, or UI responses. The bootstrap choice covers both web and Photon OS authentication; the
  root choice must not enable root
  SSH. Keep the request marker in `awaiting_readiness` until Atlaso, worker, nginx, and the management OpenAPI front
  door are stable; a restart or readiness failure must retain a resumable failure marker. If management addressing
  returns to the image
  default, provide a login and local-console handoff instead of requiring the operator to discover a pending Apply modal.
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
- Treat comment-based help and rationale-focused comments as the PowerShell authoring standard. Every new or changed
  `.ps1` or `.psm1` file requires file/module help and help for every function, including nested helpers, with a concise
  `.SYNOPSIS` and one `.PARAMETER` entry per declared parameter. Keep exactly one canonical help block per script,
  module, or function; do not place generated and purpose-specific blocks beside the same scope. The incremental checker
  enforces this before explicit `dynamicparam`, `begin`, `process`, `end`, and `clean` blocks as well as ordinary
  statements.
  Explain non-obvious safety ordering, trust boundaries, and platform behavior without narrating self-evident commands.
  Run
  `scripts/check_powershell_help.ps1` against the
  base checkout; CI applies the same incremental whole-file gate to every changed PowerShell source.
- Pin PowerShell static analysis to PSScriptAnalyzer `1.25.0` and run `scripts/check_powershell_analysis.ps1` before
  committing. The repository profile covers every tracked `.ps1`, `.psm1`, and `.psd1` file. Credential parameters use
  `SecureString` or `PSCredential`, never declare defaults, and never rely on broad
  `PSAvoidUsingPlainTextForPassword` suppressions; CI and pre-commit enforce the same contract.
- Before finalizing UI/backend changes, run focused tests for the touched area when available. Do not run the complete
  Python test suite locally; GitHub CI owns it. Also run `python -m compileall atlaso` after broad
  Python/template-adjacent changes.
- Before finalizing appliance deployment changes, also run `python scripts/check_photon_compatibility.py`. If image
  build files changed and Packer is available, run `packer fmt` and `packer validate` from the changed image target
  directory `image/vmware-workstation/`.
- Restart the local uvicorn server after template/static/route changes so the in-app browser sees the new code. Bump the
  static asset query string in `base.html` after CSS or JS changes.
