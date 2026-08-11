# Atlaso

Authenticated pages share a lightweight, visibility-aware Appliance Apply status projection. Apply review and
validation continue to reconcile live host state, while idle sidebar polling never starts privileged helper work.

![Atlaso — Everything your virtualization lab needs](docs/assets/brand/atlaso-docs-header-dark-1600x400.png)

**Everything your virtualization lab needs.**

Atlaso is an all-in-one infrastructure appliance for virtualization proof-of-concept, lab, and test environments. It
brings infrastructure, storage, identity, networking, and lifecycle workflows into one operator-focused control plane.

## Start here

- [Documentation](https://mdaneri.github.io/Atlaso/docs/) — install, configure, operate, and troubleshoot Atlaso.
- [Getting started](docs/getting-started/index.md) — choose an appliance path and complete initial setup.
- [Operations](docs/operate/index.md) — run the appliance and review desired-state changes.
- [Local appliance console](docs/operate/appliance-console.md) — correct management networking from `tty1` and have
  Atlaso reconcile Firewall, retry unfinished first-boot HTTPS, and verify the complete management front door.
- [Use the Atlaso API](docs/operate/api.md) — create least-privilege tokens, call the versioned REST contract safely,
  and interpret responses, request IDs, locks, and apply boundaries.
- [Appliance Update](docs/operate/appliance-update.md) — inspect configured Photon, PowerShell, and signed Atlaso
  sources in read-only repository tabs, then create or edit desired source state through the shared reviewed wizard
  before explicitly synchronizing package clients.
- [Services](docs/services/index.md) — configure DNS, identity, storage, network boot, and VCF integrations.
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
  Host References and installer ISOs. Audited Wake-on-LAN is available for
  discovered hosts and saved ESXi Host References.
- [Vaults](docs/services/vaults.md) — scope encrypted VCF and ESX passwords to managed scripts and exact Kickstart
  source markers.
- [OpenID Connect provider](docs/services/oidc-provider.md) — use the dedicated tabbed administration page for
  confidential clients, exact redirects, key rotation, explicit identity sources, and privacy-safe scoped claims.
- [vSphere Key Providers](docs/services/vsphere-key-providers.md) — manage isolated provider UUIDs, trusted vCenters,
  public-certificate trust, and redacted lifecycle counts; the bounded VCF 9.1 contract remains unverified.
- [vSphere Key Provider protocol](docs/reference/vsphere-key-provider-protocol.md) — review the appliance-native
  daemon's narrow KMIP contract and live-evidence promotion gate.
- [Technical reference](docs/reference/index.md) — API, image building, lifecycle testing, and detailed behavior.
- [Contributing](CONTRIBUTING.md) — issue, version, validation, pull-request, and seven-day Python dependency-age
  requirements.
- [Dependency management](docs/contribute/dependency-management.md) — regenerate hash locks without selecting newly
  published packages that approved mirrors may not have synchronized.
- [UI Design Guide](docs/contribute/ui-design-guide.md) — approved Atlaso patterns and the shared
  `AtlasoUiPatterns.createGrid(...)` / `createWizard(...)` foundation used by every grid and wizard.
- [API authoring standard](docs/contribute/api-authoring.md) — required operation, parameter, schema, authorization,
  response, compatibility, and topic documentation for every `/api/v1` change.
- [Windows image-build WSL environment](docs/contribute/windows-image-build-wsl.md) — provision and select the pinned,
  isolated `Atlaso-Build` host used by Inventory Linux and Photon image wrappers.

## Supported appliance targets

Photon OS 5.0 is the appliance operating system. VMware Workstation is the default live-test target; Hyper-V remains the
authoritative lifecycle interoperability environment for exact access and trunk VLAN behavior.

The VMware release appliance uses separate compacted Photon OS and Atlaso/tools payload VMDKs, followed by empty
500 GiB VCF Offline Depot and VCF Backups disks. The OVF package is the canonical GitHub-distributable form; its assets
are size-gated individually, while the combined OVA is published only when it remains below GitHub's asset limit.

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
Enabled depot profiles can use the shared Automation scheduler. Manual and scheduled downloads share one global
single-active task guard and execution-time prerequisite validation; schedule definitions contain no Broadcom secrets.

The integrated CA can maintain trust and deploy managed service certificates without publishing its public portal on
an access interface. Selecting a CA listen interface is the explicit portal-publication boundary. When NTS server
changes are selected, global appliance apply automatically runs Certificate Authority before NTP/NTS so missing or
stale runtime certificate files are repaired even when the CA desired-state baseline appears current. Disabling NTS
server mode removes only its managed server certificate, key, cookie material, and TCP/4460 listener; authenticated NTS
upstream clients remain available independently.

## Project

- [Brand guide](docs/assets/brand/BRAND_GUIDE.md)
- [Security and data classification policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [License](LICENSE)

The repository documentation describes the latest supported Atlaso release. Roadmaps and historical design records are
clearly labeled and are not statements of current behavior.

Atlaso code and configuration editing uses the locally bundled Monaco Editor. ESXi Kickstarts use a dedicated language
with completion for built-in, discovered custom, and authorized vault markers; credential values remain server-side.
