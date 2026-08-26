# Atlaso

Authenticated primary navigation is organized into accessible, independently collapsible sections. First use keeps
every authorized section open; later visits restore browser-local choices while always reopening the section that
contains the current page. A compact two-state control expands or collapses every rendered section through the same
per-section preference model. Permission-filtered empty sections are never rendered, and the persistent **Review
appliance changes** card remains outside the disclosures.

Authenticated pages share a lightweight, visibility-aware Appliance Apply status projection. Apply review and
validation continue to reconcile live host state, while idle sidebar polling never starts privileged helper work. The
shared task monitor retries transient status failures, follows a completed master to its terminal task record, and keeps
the modal, sidebar, pending count, and global lock synchronized without requiring a page reload. It completes a retained
task's terminal refresh before following a newer Apply started by another session. Ordinary Appliance Settings apply
proves the running Atlaso loopback upstream before publishing nginx, verifies the guest-local management front door
after reload, and never restarts the active Atlaso worker. A readiness failure restores the prior nginx and systemd
configuration and leaves truthful failed-task evidence. The monitor retains bounded reconnect handling for task records
created by older releases, but current tasks do not manufacture a reconnect window for this apply step.

Management-path changes use one recoverable Appliance Apply handoff across Network, Firewall, Certificate Authority,
Appliance Settings, and Public Services. Atlaso keeps the previous path active until the candidate listener passes
bounded application-upstream, nginx, and host-facing readiness checks. Its rollback marker remains durable until the
task and baselines commit; a failure or pre-commit restart restores the previous runtime state and records the
non-secret failing layer in the task. Physical Interface autosave does not alter active requested-interface routing:
the last-applied management bindings remain authoritative until that handoff commits, and a desired-state mutation that
would leave no complete replacement management listener is rejected before it can strand the current session. Static
dedicated-management policy routing persists both the on-link subnet and its default route in table 100 so same-subnet
host replies and routed traffic recover together after reboot.
Every effective management listener, including a flagged access physical interface or VLAN, retains Source
Group-filtered TCP/22 for ordinary bootstrap-administrator recovery together with TCP/80 and TCP/443; unflagged access
networks do not gain SSH admission, and root SSH remains a separate explicit appliance setting.

![Atlaso — Everything your virtualization lab needs](docs/assets/brand/atlaso-docs-header-dark-1600x400.png)

**Everything your virtualization lab needs.**

Atlaso is an all-in-one infrastructure appliance for virtualization proof-of-concept, lab, and test environments. It
brings infrastructure, storage, identity, networking, and lifecycle workflows into one operator-focused control plane.

## Start here

- [Documentation](https://mdaneri.github.io/Atlaso/docs/) — install, configure, operate, and troubleshoot Atlaso.
- [What is Atlaso?](docs/project/what-is-atlaso.md) — discover the Esperanto word, the map, and the myth behind the
  Atlaso name.
- [Getting started](docs/getting-started/index.md) — choose an appliance path and complete initial setup.
- [Operations](docs/operate/index.md) — run the appliance and review desired-state changes.
- [Primary navigation](docs/operate/navigation.md) — collapse authorized sidebar sections, understand active-page
  reopening, and use the same disclosure behavior at desktop and narrow viewports.
- [Backup and restore](docs/operate/backup-restore.md) — export and atomically restore desired state, or run the
  dedicated crash-safe factory reset that replaces the control-plane database, restores all 16 appliance defaults,
  invalidates existing sessions and service credentials, asks whether to keep or change the admin and root passwords,
  quiesces in-flight privileged helper actions, and preserves appliance payload storage.
- [Local appliance console](docs/operate/appliance-console.md) — correct management networking from `tty1` and have
  Atlaso reconcile Firewall, retry unfinished first-boot HTTPS, and verify the complete management front door.
- [Network configuration](docs/operate/networking.md) — inspect physical interfaces, preserve and explicitly review a
  DHCP-learned management gateway during DHCP-to-static conversion, atomically migrate static management gateways to
  Routes & WAN defaults during management-to-access conversion, and manage each tagged VLAN as one reviewed wizard
  record using the shared management, access, route, or unused role contract before global apply.
- [Network Objects](docs/operate/network-objects.md) — create reusable Source Groups in a full-height compact grid,
  choose exclusive Any-source behavior, validate explicit address/CIDR/nested-group tags individually, review their
  Firewall, managed-rule, and NAT consumers, and return to an in-progress rule wizard without losing its tab-local draft.
- [Use the Atlaso API](docs/operate/api.md) — create least-privilege tokens, call the versioned REST contract safely,
  and interpret responses, request IDs, locks, and apply boundaries. Typed physical-interface PATCH requests reconcile
  dependent service, ESX Storage, Web Terminal, DHCP, Network Boot, and management-gateway route intent in the same
  desired-state transaction; terminal management-plane eligibility stays on the last-applied Network binding.
- [Appliance Update](docs/operate/appliance-update.md) — inspect configured Photon, PowerShell, and signed Atlaso
  sources in read-only repository tabs, then create or edit desired source state through the shared reviewed wizard
  before explicitly synchronizing package clients. The built-in Atlaso source follows the signed `stable` channel;
  Pages publication guards verify that its pointer, immutable release manifest, trust key, and CPython 3.14
  compatibility remain usable. Checks persist bounded per-stream availability, drive a global authenticated update
  indicator, disable repository-backed streams until their required sources are synchronized, and provide a direct
  accessible path from **Repository setup required** to the audited synchronization action. Ready streams remain
  independent, while both browser and server admission reject blocked checks or installations. Atlaso Release
  installation reports success only after the durable
  active link, signed receipt, running version, internal API, nginx management front door, and post-maintenance service
  state all agree on the candidate. Maintenance remains closed through every rollback-capable stage; after a durable
  activation commit, final front-door failures preserve the candidate and retry forward through a gated post-start
  worker handoff instead
  of discarding later operator writes, including after reboot when the volatile gate must be recreated.
  Startup rejects inconsistent success evidence and resumes only untouched update children.
- [Services](docs/services/index.md) — configure DNS, identity, storage, network boot, and VCF integrations.
- [Network configuration](docs/operate/networking.md) — distinguish static paths from forwarding permissions, create
  explicit IPv4 or IPv6 default routes through native IP-family choices without entering `/0` manually, and manage
  Static Routes, Routing Permissions, IPv4 masquerade NAT rules, and interface-level WAN Simulation through reviewed
  add/edit wizards before global appliance apply.
- [Public Services](docs/services/public-services.md) — use the canonical `/ui/management` and `/ui/public` browser
  planes, understand interface-aware `/` dispatch, and keep machine/protocol routes at their stable paths.
- [DNS](docs/services/dns.md) — preserve explicit forwarders or usable resolvers from the management interface's exact
  DHCP lease
  across global appliance applies, including applies triggered by unrelated settings such as Web Terminal.
- [Network Boot](docs/services/ipxe.md) — discover unassigned hardware with
  independently released read-only Inventory Linux, download its latest package
  through the fixed signed manifest at `/updates/inventory-linux/latest/manifest.json`,
  activate interactive maintenance media including verified
  single-kernel ShredOS PXE,
  and retain the ESX scripted-install workflow. Inventory schema v2 retains
  bounded CPU/DIMM, NIC, disk/controller, PCI/USB, and system identity details;
  its appliance-colored local console provides height-aware paged review, an
  Atlaso boot splash, and a suspendable five-minute post-submission reboot
  countdown. Retained reports render as printable semantic hardware summaries
  with JSON export; newly reported hosts refresh automatically, assigned ESXi
  hostname and address remain visible, and standard grid-backed wizards manage
  Host References and installer ISOs. Assigned discoveries are removed only
  through their Host Reference, with an explicit choice to retain or remove the
  matching discovery history; shared discoveries remain protected while any
  other Host Reference is assigned. Audited Wake-on-LAN is available for
  discovered hosts and saved ESXi Host References; scripted ESXi boots require
  an administrator to enter the one-time code shown by the exact host-console
  attempt before a short-lived, single-use authorization is bound to applied state.
- [Vaults](docs/services/vaults.md) — scope encrypted VCF and ESX passwords to managed scripts and exact Kickstart
  source markers.
- [OpenID Connect provider](docs/services/oidc-provider.md) — use the dedicated tabbed administration page for
  confidential clients, exact redirects, key rotation, explicit identity sources, and privacy-safe scoped claims.
- [vSphere Key Providers](docs/services/vsphere-key-providers.md) — manage isolated provider UUIDs, trusted vCenters,
  public-certificate trust, and redacted lifecycle counts; the bounded VCF 9.1 contract remains unverified.
- [vSphere Key Provider protocol](docs/reference/vsphere-key-provider-protocol.md) — review the appliance-native
  daemon's narrow KMIP contract and live-evidence promotion gate.
- [Technical reference](docs/reference/index.md) — API, image building, lifecycle testing, and detailed behavior.
- [Contributing](CONTRIBUTING.md) — issue, version, focused local validation, full-suite GitHub CI, exact-head review
  follow-through, protected trusted-CI status handoff, multi-entry GitHub Pages publication serialization,
  incremental comment-based-help enforcement for changed PowerShell files, pinned repository-wide PSScriptAnalyzer
  enforcement, and default-free `SecureString` credential parameters,
  pull-request, capability-aware completed-task lease-guarded remote/local-branch, worktree, and title cleanup with
  guarded resumable restoration,
  and seven-day Python dependency-age requirements.
- [Dependency management](docs/contribute/dependency-management.md) — regenerate hash locks without selecting newly
  published packages that approved mirrors may not have synchronized.
- [Python static analysis](docs/contribute/python-static-analysis.md) — run the enforced Ruff baseline and expand the
  strict mypy service-module ratchet.
- [Router architecture](docs/contribute/router-architecture.md) — preserve deterministic UI/API registration,
  dependency direction, route inventory, and OpenAPI contracts during the staged domain split under issue #317,
  including the extracted physical-interface and VLAN transport boundary and the typed atomic physical-interface
  desired-state service shared by both transports.
- [UI Design Guide](docs/contribute/ui-design-guide.md) — approved Atlaso patterns and the shared
  `AtlasoUiPatterns.createGrid(...)` / `createWizard(...)` foundation used by every grid and wizard.
- [API authoring standard](docs/contribute/api-authoring.md) — required operation, parameter, schema, authorization,
  response, compatibility, and topic documentation for every `/api/v1` change.
- [Windows image-build WSL environment](docs/contribute/windows-image-build-wsl.md) — provision and select the pinned,
  isolated `Atlaso-Build` host used by Inventory Linux and Photon image wrappers.
- [Deployment asset validation](docs/reference/full-technical-reference.md#deployment-asset-validation) — validate the
  complete Packer, systemd, and sudoers inventory locally and in protected CI; both image targets pin and verify exact
  Packer plugin binaries, while authenticated discovery uses the step-scoped read-only Actions token without persisting
  checkout credentials or exposing the token to fork code.

## Supported appliance targets

Photon OS 5.0 is the appliance operating system. VMware Workstation is the default live-test target; its cleanup tools
are authoritative only for exact non-reparse-point Atlaso artifact roots. They match running target aliases by
filesystem identity, stop exact targets, atomically detach external VMDKs, and use checked `vmrun deleteVM` only for an
exact in-scope registration. Immutable root and descendant identities plus an immediate target, running, registration,
and VMX-set recheck protect each provider deletion and the final recursive removal. Unrelated stale, malformed, missing,
or inconsistent Workstation library entries cannot block normal Atlaso cleanup.
With the Workstation UI closed, a narrow stale-registration fallback validates only the selected library ID, holds a
write-excluding inventory handle through byte comparison and atomic replacement, and rolls back a concurrently replaced
provider inventory without requiring unrelated registrations to resolve. Atomic VMX replacement retains its displaced
backup until identity and byte validation completes, restoring it on validation failure or preserving an actionable
recovery copy if rollback cannot complete.
If checked `deleteVM` removes the complete validated root, cleanup retains scoped registration and running-state
verification, requires that exact root to stay absent, and lets the active redeploy continue without a second filesystem
deletion.
The supported VMware image wrapper starts a responsive Workstation UI in a separate process before GUI-mode Packer
builds and reports bounded, sanitized, exact-VM startup diagnostics until SSH provisioning begins.
Hyper-V remains
the authoritative lifecycle interoperability environment for exact access and trunk VLAN behavior.
Image-build download caches verify pinned checksums before reuse or durable promotion; ordinary retries replace only
the exact corrupt expected cache entries and do not require manual cleanup.
The VMware wheel-deployment helper accepts only absolute POSIX remote staging directories composed of ASCII letters,
digits, `/`, `.`, `_`, and `-`, with no `.` or `..` components. It rejects whitespace, shell metacharacters, and control
characters before building or uploading through either SSH authentication mode.
The normal VMware test-VM wrapper provisions the current Windows user's existing `.ssh/id_ed25519.pub` for `admin`
and grants that development VM passwordless sudo, so subsequent local key/agent-backed deployments need no password
handoff. It never generates or copies a private key, and lifecycle and exported appliances retain their ordinary
password-backed sudo policy. First boot publishes only the test VM's public Ed25519 SSH host key through VMware
guest-info; the wrapper prints the exact key and SHA-256 fingerprint for explicit `known_hosts` verification without
trusting `ssh-keyscan`.
Before it prints ready state or connection endpoints, the wrapper also proves one identity tuple across the exact
running VMX, management NIC MAC, injected hostname, guest-published actual hostname, VMware Tools address, and Windows
neighbor cache. Every running guest must answer the address inventory query. A static address also claimed by another
running Workstation VM fails closed with the conflicting VMX and MAC. The wrapper re-lists the running inventory and
rechecks the target address immediately before returning, retrying when either changes. Recovery remains an explicit
stop-or-readdress operation and never rewrites SSH `known_hosts`.
Password-backed Windows deployment binds the concealed `DEFAULT_ADMIN_PASSWORD` variable from the verified `Atlaso`
1Password Environment through the Windows-supported 1Password SDK desktop integration; the SDK and Paramiko run in one
bounded child that rejects unknown SSH host keys and never accepts a password
argument, local `.env`, or the retired `ATLASO_DEPLOY_SSH_PASSWORD` fallback. See the
[VMware Workstation deployment reference](docs/reference/full-technical-reference.md#vmware-workstation-workflow).

The VMware release appliance uses separate compacted Photon OS and Atlaso/tools payload VMDKs, followed by empty
500 GiB VCF Offline Depot and VCF Backups disks. The OVF package is the canonical GitHub-distributable form; its assets
are size-gated individually, while the combined OVA is published only when it remains below GitHub's asset limit. OVF
export limits recursive replacement to repository-owned OVF output descendants; release mode implicitly replaces only
its canonical destination, and an explicit existing destination also requires `-Force`.
First boot formats those data disks only after both match the image's fixed SCSI-slot, stable `atlaso-path-*`, and exact
capacity policy. The preflight resolves `/` through its block-device dependency chain and requires exactly one physical
operating-system disk before excluding it from data-disk candidates. Missing, extra, reordered, ambiguous, or mismatched
disks stop initialization before either disk is formatted; correctly labeled disks remain idempotent and mount by UUID.
After both fixed disks are initialized, only positively identified Atlaso-managed ESX Storage volumes are accepted as
additional disks. Existing ext4 whole disks
also require UUID-backed fstab persistence and a root-owned Atlaso claim. A failed disk preflight blocks nginx, the
HTTPS bootstrap, control plane, and worker rather than starting them against empty root-filesystem directories.
VMware first boot validates management addresses and gateways as one contract before host mutation. Invalid OVF
networking pauses initialization at the Atlaso `tty1` review screen so an administrator can correct it in place.
Privileged tty1 actions remain locked until deployment credentials apply, and interrupted review cleanup recovers from
the applied marker on the next boot. When VMware Tools authoritatively reports no OVF envelope for 30 consecutive
reads, Atlaso records a durable non-OVF completion marker, logs that image defaults are in use, clears the initialization
handshake, and opens the ordinary console without presenting OVF network review.

Development appliances keep host-mutating adapters in dry-run mode by default. Atlaso applies selected desired state
only through the global appliance-change workflow and its constrained privileged helper. Secret-bearing Local Users,
Certificate Authority, and Managed LDAP inputs are staged with mode `0600` only for the helper execution window and
removed after every terminal outcome and during application startup recovery. The KMS compatibility listener and
pre-authentication VCF Automation and vSphere certificate probes require TLS 1.2 or newer; the probes retain explicit
certificate-fingerprint confirmation as their trust decision.

VCF Offline Depot settings and download-profile applies preserve the registered VCF Download Tool software depot ID.
Atlaso generates a replacement only during first setup or when an administrator explicitly confirms
**Refresh software depot ID** through global appliance apply. A shared VCFDT configuration wizard saves Broadcom
credential replacements and application properties together, then queues an explicitly reviewed ID refresh through the
scoped Appliance Apply unit. A successful identity replacement removes both the staged download token and activation
code because they no longer match the new Software Depot ID. Package add/update uses a separate reviewed package wizard;
reset clears the package and its complete saved configuration together.
Enabled depot profiles can use the shared Automation scheduler. Manual and scheduled downloads atomically deduplicate
the same profile while distinct profiles queue in FIFO order; exactly one VCFDT process executes at a time and mutable
prerequisites are revalidated when a queued task is claimed. Software Depot ID replacement and depot Appliance Apply
remain exclusive until the download queue drains. Schedule definitions contain no Broadcom secrets, and the selected
profile opens a server-bound contextual schedule wizard without leaving the depot page.
VCF Offline Depot browser login returns only to validated canonical `/PROD` paths; unsupported destinations fall back
to the depot root.

The integrated CA can maintain trust and deploy managed service certificates without publishing its public portal on
an access interface. Selecting a CA listen interface is the explicit portal-publication boundary. When NTS server
changes are selected, global appliance apply automatically runs Certificate Authority before NTP/NTS so missing or
stale runtime certificate files are repaired even when the CA desired-state baseline appears current. Disabling NTS
server mode removes only its managed server certificate, key, cookie material, and TCP/4460 listener; authenticated NTS
upstream clients remain available independently.

## Project

- [Brand guide](docs/assets/brand/BRAND_GUIDE.md)
- [Security reporting, private remediation, and data classification policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [License](LICENSE)

The repository documentation describes the latest supported Atlaso release. Roadmaps and historical design records are
clearly labeled and are not statements of current behavior.

Atlaso code and configuration editing uses the locally bundled Monaco Editor. ESXi Kickstarts use a dedicated language
with completion for built-in, discovered custom, and authorized vault markers; credential values remain server-side.
