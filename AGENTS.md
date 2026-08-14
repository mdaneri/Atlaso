# Atlaso Agent Notes

## Mandatory Agent Startup Gate

Before planning implementation or changing repository or external state, read this file completely, then read
[CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md). Treat all
four documents as mandatory instructions. In the first progress update, confirm that the policy files were read,
classify the work as `bug`, `enhancement`, `documentation`, or security-sensitive work, and identify the linked GitHub
issue.

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

### Unsupported title controls

When supported task-title controls are unavailable, or the runtime does not have a mutable Codex task, continue without
blocking on the rename. Do not invent or depend on an undocumented CLI fallback.

### Schema-constrained reporting

Include every linked issue and pull-request identifier in the first progress update and final response only when those
reporting surfaces accept free-form traceability metadata. When a required output schema does not permit extra metadata,
follow the schema and do not block solely to add the identifiers.

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

### Extended merge descriptions

Before performing any explicitly authorized squash merge, finalize the pull-request title and body, then provide an
explicit subject and extended squash-commit body instead of accepting a title-only or autogenerated default message.
The body must explain the outcome and rationale, summarize the principal changes, record validation evidence, and name
the linked issue or issues. Keep it accurate to the exact merged head and exclude secrets. This requirement does not
grant merge authorization.

## Documentation and branding

Markdown is the canonical documentation source. Follow the
[documentation authoring guide](docs/contribute/documentation-authoring.md), keep `npm run lint:markdown` clean, and
update affected pages and media manifests whenever behavior or UI changes. Follow the
[Atlaso Brand Kit](docs/assets/brand/BRAND_GUIDE.md) for documentation, screenshots, video, and promotional claims.

Every new or changed `/api/v1` operation must follow the
[API authoring standard](docs/contribute/api-authoring.md), including operation, authorization, parameter,
schema-property, response, compatibility, enforcement-test, and topic-documentation requirements. Keep supported
non-`/api/v1` browser and protocol routes out of OpenAPI and documented in their canonical guides.

## Canonical implementation policies

Read [Detailed agent policies](docs/contribute/agent-policies.md) before appliance, UI, networking, service, image,
deployment, or live-VM work. Its subsystem contracts remain mandatory. Use the documentation index to locate the closest
current operator or contributor guide before making a change.

The following cross-cutting boundaries always apply:

- Canonical human browser surfaces belong to `/ui/management` or `/ui/public`; `/` is only the requested-interface
  dispatcher. Keep API, OpenAPI, OIDC, CA-download, PXE, `/PROD/`, registry, static, and other machine/protocol routes at
  their stable paths. A URL prefix never replaces listener, authentication, authorization, CSRF, or session enforcement.
  Safe legacy `GET`/`HEAD` bookmarks may redirect only after destination eligibility is proven; bridge legacy mutations
  internally and never replay them through `307`/`308`. Route-inventory coverage must fail for an undeclared human UI
  route. Scope management browser caching to `/ui/management/` and keep public UI caching disabled.
- `/ui/management/appliance-apply` is the only desired-state host-mutation workflow.
- Physical-interface desired-state updates from the API and UI use one atomic domain service. Capture the previous
  IPv4 and IPv6 CIDRs before mutation, refresh dependent service, ESX Storage, Web Terminal, DHCP, and Network Boot
  bindings before one commit, include child VLAN dependencies when their parent becomes unavailable, roll back every
  row when reconciliation fails, rebase reservations and their app-owned DNS records only when one updated DHCP scope
  is unambiguous, ignore inactive legacy DHCP binding fields when real scopes exist, and audit the dependent units that
  changed.
- Keep **Static Routes** separate from **Routing Permissions** in operator language. Static Routes choose destination,
  gateway, target interface/VLAN, and metric in the lab route table; Routing Permissions authorize forwarding between
  interface/VLAN networks, with route-role paths generated automatically and Access networks requiring explicit rules.
  Static Routes, Routing Permissions, NAT Rules, and WAN Policies are wizard-backed Tabulator collections. Add launches
  from the bottom row; edit launches from row double-click or the context menu; generated routing permissions remain
  read-only; and ordinary persisted **Enabled** state remains directly editable without host mutation.
- Physical and VLAN interfaces share exactly `management`, `access`, `route`, and `unused` roles. Reject retired or
  unknown values on new UI, API, desired-state, and helper inputs. Upgrade and settings-archive compatibility may map
  only retired `services` and `storage` values to `access` while preserving every other interface field.
- Keep ordinary `/ui/management/appliance-apply/status` polling on the non-reconciling desired-state projection.
  Prevent overlapping browser polls, suspend them while hidden, back off when idle, and refresh promptly after successful
  mutations and Apply completion. Retain the tracked master task until a valid terminal task response is rendered, retry
  transient status and terminal-reconciliation failures at the active cadence with an observable warning, and never let
  an older active response replace a terminal result. Reconcile a retained task and run its completion refresh before
  accepting a different session's newer active task. Full review, validation, and submission must still reconcile current
  host observations.
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
- VMware Workstation is the default live appliance target; use Hyper-V lifecycle coverage for exact VLAN behavior.
- VMware Workstation recursive cleanup requires an exact non-reparse-point artifact root containing every expected VMX.
  Test-VM redeploy fails closed when its named VMX is missing or has another display name, and data-disk reset accepts
  only strict path-component descendants of that VM output. Before deleting files, cleanup must use the checked
  `vmrun` running inventory and Workstation registration inventory, stop running targets, unregister registered targets,
  and verify both transitions; any unresolved command or state preserves the artifacts and returns failure.
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
- VMware release images use separate compacted Photon OS and required Atlaso system-content payload VMDKs, followed by
  empty 500 GiB depot and backup disks. Preserve `/opt/atlaso` and appliance-wide PowerShell modules on the UUID-mounted
  system-content disk, size-gate individual OVF release assets below 2 GiB, and publish the aggregate OVA only when it
  independently fits that limit. OVF export may recursively replace only a strict, non-reparse-point descendant of the
  repository OVF output root. `-Release` provides implicit replacement only for the canonical derived destination; an
  explicitly supplied existing destination still requires `-Force`, which never widens the approved deletion boundary.
- First-boot depot and backup initialization requires the root-owned image policy, exact platform SCSI identities,
  topology-derived `atlaso-path-*` links, and exact 500 GiB capacities. Complete an all-disk preflight before `mkfs` and
  fail closed for missing, extra, reordered, ambiguous, read-only, in-use, or identity/capacity-mismatched disks.
  Existing correctly labeled ext4 disks remain UUID-mounted and must never be reformatted. After both fixed disks are
  initialized, admit additional disks only when they satisfy the root-owned managed ESX Storage identity, UUID, mount,
  and fstab contract. Atlaso-formatted disks retain their `lf-<hash>` label; claimed existing ext4 disks additionally
  require an exact root-owned allowlist record. Make data-disk success a hard systemd requirement for nginx, the HTTPS
  bootstrap, control plane, and worker so a failed preflight cannot fall through to root-filesystem-backed mount paths.
- Inventory Linux is an independently versioned Atlaso release package; full images leave it uninstalled so an
  administrator downloads a signed release on demand. Supported VMware wheel deployment synchronizes it unless
  explicitly skipped. Publish it only through the protected manual Inventory
  Linux release workflow for an exact successful `main` CI SHA. Every workflow build is a final immutable
  `inventory-linux-v<version>` release and signed Pages pointer; never attach it to an appliance release or introduce
  development, preview, or staging channels.
- VMware wheel deployment validates `RemoteDirectory` before build or upload as an absolute POSIX path containing only
  ASCII letters, digits, `/`, `.`, `_`, and `-`, with no `.` or `..` components. Keep key/agent and password-backed
  authentication on this shared path contract, and serialize every key-backed remote shell argument explicitly.
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
  Reference variables and ESX installer ISO intake.
- Windows Inventory Linux and Photon builds select the dedicated `Atlaso-Build` WSL distribution by default. WSL is a
  pre-existing host prerequisite: ordinary builds must never install or configure WSL, create a missing distribution,
  change the default distribution, elevate, reboot, or remove a distribution. Keep the pinned setup contract, explicit
  distribution selection, native-Linux cache, Linux-only child `PATH`, per-repository `flock`, and checkout-wide output
  serialization described in the canonical contributor guide.
- Treat Packer HCL, systemd units/manager drop-ins, and sudoers fragments as protected deployment assets. Keep them in
  the checked-in inventory, run `scripts/check_deployment_assets.py` through pre-commit where native tools are
  available, and require full Packer validation plus native Linux systemd/sudoers validation in canonical CI. Pass the
  read-only GitHub Actions token to Packer only through `PACKER_GITHUB_API_TOKEN` on the canonical validation step for
  protected events and same-repository pull requests. Keep fork validation tokenless, checkout credentials
  unpersisted, and token material out of output, files, caches, and artifacts.
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
- VCF Offline Depot login return targets must be reconstructed beneath the server-owned `/PROD` prefix after strict
  relative-path validation. Unsupported or malformed destinations fall back to `/PROD/`; never redirect a successful
  depot login to an authority, scheme, traversal path, or browser-equivalent backslash form supplied by the request.
- When local DNS points the management resolver to loopback, recover empty DNS service upstreams from the exact
  management interface's systemd-networkd DHCP lease. Reject loopback, unscoped IPv6 link-local, duplicate, malformed,
  and other-interface lease values, preserve explicit upstream precedence, and fail both desired-state and helper
  validation when DHCP fallback is required but unavailable.
