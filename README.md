# Atlaso

![Atlaso — Everything your virtualization lab needs](docs/assets/brand/atlaso-docs-header-dark-1600x400.png)

**Everything your virtualization lab needs.**

Atlaso is an all-in-one infrastructure appliance for virtualization proof-of-concept, lab, and test environments. It
brings infrastructure, storage, identity, networking, and lifecycle workflows into one operator-focused control plane.

The shared [Appliance Apply review](docs/operate/appliance-apply.md) shows the complete execution plan, including
unchanged required dependencies and their reasons, before submitting one task.

DNS listeners serve managed zones and configured upstream forwarding together, excluding appliance-local `/etc/hosts`
entries from published answers. Appliance Apply coordinates host
resolution with DNS activation and updates Atlaso-owned service records after listener-address readiness; DHCP scopes
may advertise routed DNS/NTP service endpoints. See the
[DNS](docs/services/dns.md) and [DHCP](docs/services/dhcp.md) guides.
DHCP exposes an enabled-by-default IP availability check, staged until Apply, with dnsmasq native limits documented.
Pool Health supports bounded report-only IPv4 verification and administrator-managed hourly-or-slower schedules;
DHCP writers can verify and cancel, and unresolved findings retain identity evidence through silent scans.

[Appliance time synchronization](docs/services/ntp.md#appliance-clock-source) uses one clock authority: VMware Tools,
NTP client, or the managed NTP/NTS server. Server mode takes precedence over the remembered client choice. Appliance
Apply and startup enforce mutual exclusion; health requires actual synchronization, not merely listening sockets.

## What Atlaso brings together

[Managed reverse proxies](docs/services/reverse-proxies.md) are planned under issue #723 for **Traffic Publishing**.
Operators review hostname, exact listener addresses, ordered path routes, and upstream TLS trust in one wizard;
global Appliance Apply coordinates publication, certificates, firewall admissions, and owned DNS records.
Native appliance acceptance remains incomplete, so this workflow retains roadmap status.

- **Infrastructure** — deploy and operate a Photon OS appliance across supported virtualization platforms.
- **Storage** — provide lab storage and manage VCF depot and backup workflows.
- **Identity** — manage local users, LDAP, OpenID Connect, certificates, and scoped credentials. Managed LDAP exposes
  separate [VCF and vCenter group search bases](docs/services/managed-ldap.md#vcenter-openldap-groups).
- **Networking** — configure interfaces, default-off routing with explicit IPv4/IPv6 forwarding permissions, source
  NAT and dual-stack port forwarding with explicit ingress, WAN simulation, DNS, DHCP,
  firewall policy, public services, and network boot through reviewed desired state.
  Applied management and lab source addresses keep separate reply tables even while Routing is off. A persistent
  local-source guard blocks newly acquired global DHCP/SLAAC addresses until their exact rules exist, while unbound
  and link-local traffic retains ordinary main-table source selection.
- **Lifecycle** — review desired-state changes, automate tasks, monitor health, and install signed updates.

[Appliance Update](docs/operate/appliance-update.md) follows one durable task through service restarts and recovery,
with automatic browser status navigation and a final result backed by active-release and service checks.

For troubleshooting, correlate significant operation events across [Tasks](docs/operate/tasks.md),
[Operational Logs](docs/operate/logs.md), and the [Audit log](docs/operate/audit-log.md). The
[important-event coverage guide](docs/operate/logs.md#important-event-coverage) explains which milestones are retained,
how verbosity affects App logs, and where native evidence can remain incomplete.

[vSphere Key Providers](docs/services/vsphere-key-providers.md) uses one **+ Add trusted vCenter here** wizard with
**Enroll from vCenter** and **Configure manually** methods. Enrollment starts in vCenter, then requires an Atlaso
administrator to confirm the displayed HTTPS certificate with a checkbox before using request-only manual credentials
or a saved Vault credential. The administrator then inspects and approves the exact public client certificate for one
provider before Appliance Apply permits KMIP key operations. Atlaso CA manages the server identity; certificate cutover
retains the prior files and service state for recovery. The feature remains experimental; support is limited to the
VCF 9.1 matrix actually observed. The maintainer owns separate encrypted-workload verification.
The [KMIP disaster-recovery runbook](docs/operate/kmip-recovery.md) covers authenticated passphrase-encrypted bundles,
empty-target restore, and legacy-store protection.

[VCF Helper lab overrides](docs/services/vcf-helper.md#lab--non-production-overrides) let administrators review either
or both fixed domainmanager properties in a tile-launched wizard on VCF Installer and SDDC Manager 9.0.x / 9.1.x.
SSH connects as `vcf` and uses separate root credentials through `su`, with verified writes,
service restart and explicit recovery. These lab-only settings do not certify hardware or establish production support.

VCF Helper groups its workflows into Deployment, Credentials, Certificates, LDAP, and Lab tabs.
The Appliance Certificate Replacement wizard supports standalone SRM and vCenter plus the SDDC Manager appliance
resource in initialized VCF 9.x management domains. Native SDDC Manager lab validation remains pending; see the
[certificate operator guide](docs/services/appliance-certificates.md#sddc-manager-9x) for API scope and limits.
The experimental **Certificate Renewal** workflow adds opt-in, Atlaso-managed renewal for vCenter Machine SSL on the
VCF Operations 9.1.1 contract. Schedules discover due work; an administrator explicitly prepares and approves each
replacement. Live acceptance is pending, and the workflow does not claim to enable VCF Operations' native auto-renewal.
See the [VCF Helper guide](docs/services/vcf-helper.md#certificate-renewal) for operating steps and limits.
VCF Helper also lets administrators review supported, accessible VCF/ESX credential candidates and import selected
passwords into encrypted vaults for URI-backed autofill and scripts or Kickstarts. See the
[Vaults guide](docs/services/vaults.md#vcf-helper-import) for discovery coverage, endpoint mapping, and reimport
behavior, and the [VCF Helper guide](docs/services/vcf-helper.md) for the wizard workflow.

[Maintenance](docs/operate/backup-restore.md) groups LDAP, Backup, Reset, and Diagnostics into separate tabs.
Administrators can create [diagnostic support bundles](docs/operate/diagnostics.md) through a reviewed wizard or use
the recovery CLI when the web service, worker, or database is unavailable. Optional hostname and username aliases are
consistent within each bundle; IP and MAC addresses stay unchanged, and secrets are always excluded. Managed bundles
expire after 24 hours and support manual deletion. Collection is observational and never uploads evidence automatically.

Successful `main` CI automatically publishes the immutable wheel handoff, creates the signed software Release, and
advances `development`. Promotion to `preview` or `stable` and all OVA/virtualization production remain explicit manual
operations.

## Start here

For native same-address static-to-DHCP management acceptance, use the
[same-address lifecycle mode](docs/reference/vmware-workstation-lifecycle-testing.md#same-address-acceptance).
For ISO appliance address changes, use the explicit
[trusted-host certificate lab procedure](docs/reference/certificate-address-control.md).

- [Documentation](https://mdaneri.github.io/Atlaso/docs/) — browse the published Atlaso documentation.
- [Getting started](docs/getting-started/index.md) — choose an appliance path and complete initial configuration.
- [Physical installation](docs/getting-started/physical-installation.md) — review the planned signed offline ISO installation
  flow; physical hardware validation is pending.
- [Operate](docs/operate/index.md) — manage daily appliance tasks, changes, updates, and troubleshooting.
- [Services](docs/services/index.md) — configure infrastructure, identity, storage, and VCF integrations.
- [Reference](docs/reference/index.md) — review APIs, image building, interoperability, and technical behavior.
- [Contribute](docs/contribute/index.md) — follow repository, documentation, design, and implementation policies.
- [Project](docs/project/index.md) — learn about Atlaso branding, roadmaps, and design history.

## Supported appliance targets

Atlaso runs on Photon OS 5.0. VMware Workstation is the canonical image-build, live-test, and documentation target. The
validated OVF/OVA supports VMware deployment and is the source artifact for KVM and Proxmox VE imports; Hyper-V uses a
portable ZIP converted from that same appliance image. Canonical Workstation builds reserve their temporary static
builder address outside VMware DHCP before Packer starts, so concurrent clean worktrees do not reuse one endpoint.
Completed builders can release their reservation despite stale-only neighbor cache entries; new builds still exclude
those addresses. See [retained builder address recovery](docs/reference/vmware-workstation-lifecycle-testing.md#recover-a-retained-builder-address)
for verification and cleanup prerequisites.
Build preflight checks VMware-generated paths against a 240-character budget; choose a shorter `-StagingRoot` for
virtualization prereleases or a shorter canonical `-OutputDirectory` parent for direct image builds when rejected.
Protected release finalization and stable promotion admit exactly one version-derived Hyper-V ZIP; suffix-compatible
aliases or additional archives fail before signing or publication.
Visible builds repair exact missing Atlaso library registrations before starting Workstation, while full artifact
cleanup retains its checked post-network-preflight boundary.
Successful builders atomically remove empty Packer lock directories; export retains strict read-only lock checks.
Failure cleanup verifies Workstation's shutdown-only VMX rewrite before adopting its stopped file identity; unrelated
configuration changes and replacements still preserve the artifacts and reservation for recovery.

Contributor-created VMware lifecycle and acceptance VMs use pull-request-owned identities so validation artifacts
remain traceable and cleanup cannot adopt a shared or provisional VM name. Task-owned Photon builders follow the same
rule: their exact PR identity owns the Packer VM, output, reservation, provenance, and cleanup scope, while portable
product and release names remain PR-independent. Before a pull request exists, the explicit local/test builder and
normal test-VM modes derive guarded identities from the clean source commit; protected release paths reject local/test
provenance, and acceptance evidence remains PR-numbered. See the
[VMware Workstation lifecycle testing guide](docs/reference/vmware-workstation-lifecycle-testing.md).
Normal test-VM creation records the task's original clone identities outside its worktree before configuration or
startup. Preserve both the creation intent and original receipt for retry, redeployment, and ownership-checked cleanup;
existing VMs without creation evidence are preserved rather than adopted.
Interrupted Photon sensitive staging has a supported `-CleanupOnly` recovery path bound to the original task worktree
and root identity. Inspection preserves state; execution revalidates registration after confirmation and proves process
quiescence before retirement. VM artifacts and reservations use separate owning cleanup procedures; recovery obtains
no new credentials and never starts an image build.
Certificate-only handoff testing on a retained clone requires an independently owned private management segment,
receipt-bound address control, pinned peer and appliance identities, and CA-verified HTTPS before any native address
change. A discovered DHCP address or successful clone deployment alone is not acceptance evidence; the
[lifecycle certificate handoff procedure](docs/reference/vmware-workstation-lifecycle-testing.md) records the required
readbacks and restoration.
The DHCP peer seed contains an SSH public key and disables password login; the selected key must already be loaded
in the local SSH agent before the peer VM is created.

Password-backed Windows build and test helpers require standard GIL-enabled x64 CPython 3.14. Until 1Password ships
an eligible official wheel, Atlaso verifies one immutable, attested compatibility release from the public
`mdaneri/onepassword-sdk-python` fork by exact URL, filename, size, and SHA-256 before 1Password authorization or VMware
activity. The wheel is never checked into Atlaso or published to PyPI.
When a restricted build network supplies the credential-free `PipGlobalIndex` and `PipGlobalIndexUrl` pair, Atlaso
uses that same resolved pair for both the host-side hash-locked 1Password dependency closure and the guest Photon build;
partial overrides and silent public-PyPI fallback are rejected.

See [Getting started](docs/getting-started/index.md) for the first-use path and
[Portable virtualization artifacts](docs/reference/virtualization-artifacts.md) for platform-specific import details.

## Safety model

Development appliances keep host-mutating adapters in dry-run mode by default. Operators edit desired state, review
the resulting appliance changes, and explicitly submit valid units through the global Appliance Apply workflow.

[ESXi Network Boot](docs/services/ipxe.md) authorizes against the exact successfully applied configuration, retained
in a dedicated encrypted runtime record. Display previews and Apply baselines remain redacted; standalone IP addresses,
MAC addresses, and host UUIDs remain visible operational identifiers. Recovery from an incomplete applied snapshot
requires a real ESXi PXE Apply followed by a fresh host boot attempt; a dry run does not repair it.

The Boot Service **Require console authorization** switch is off by default. Apply this policy to let assigned ESXi
hosts continue without a console code, or enable it for per-attempt administrator approval. Generated attempt
directories remain readable by the boot servers even under the appliance service's restrictive umask.

## Project and community

Automated pull-request monitoring uses one four-minute current-task heartbeat as the exclusive routine reconciliation
mechanism; contributor tasks may make immediate bounded reads while awake, but must not self-schedule delayed shell
status checks alongside that heartbeat. See [Contributing](CONTRIBUTING.md) for the complete workflow.

- [What is Atlaso?](docs/project/what-is-atlaso.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Brand kit](docs/assets/brand/BRAND_GUIDE.md)
- [License](LICENSE)

The documentation describes the latest supported Atlaso release. Pages marked **Roadmap** or **Historical** provide
context and do not describe current appliance behavior.

For local appliance recovery, see the [appliance console guide](docs/operate/appliance-console.md).
