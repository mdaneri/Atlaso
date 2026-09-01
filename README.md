# Atlaso

![Atlaso — Everything your virtualization lab needs](docs/assets/brand/atlaso-docs-header-dark-1600x400.png)

**Everything your virtualization lab needs.**

Atlaso is an all-in-one infrastructure appliance for virtualization proof-of-concept, lab, and test environments. It
brings infrastructure, storage, identity, networking, and lifecycle workflows into one operator-focused control plane.

## What Atlaso brings together

- **Infrastructure** — deploy and operate a Photon OS appliance across supported virtualization platforms.
- **Storage** — provide lab storage and manage VCF depot and backup workflows.
- **Identity** — manage local users, LDAP, OpenID Connect, certificates, and scoped credentials.
- **Networking** — configure interfaces, routing, DNS, DHCP, firewall policy, public services, and network boot.
- **Lifecycle** — review desired-state changes, automate tasks, monitor health, and install signed updates.

Successful `main` CI automatically publishes the immutable wheel handoff, creates the signed software Release, and
advances `development`. Promotion to `preview` or `stable` and all OVA/virtualization production remain explicit manual
operations.

## Start here

- [Documentation](https://mdaneri.github.io/Atlaso/docs/) — browse the published Atlaso documentation.
- [Getting started](docs/getting-started/index.md) — choose an appliance path and complete initial configuration.
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
Protected release finalization and stable promotion admit exactly one version-derived Hyper-V ZIP; suffix-compatible
aliases or additional archives fail before signing or publication.
Visible builds repair exact missing Atlaso library registrations before starting Workstation, while full artifact
cleanup retains its checked post-network-preflight boundary.

Contributor-created VMware test and lifecycle VMs use pull-request-owned identities so validation artifacts remain
traceable and cleanup cannot adopt a shared or provisional VM name. Task-owned Photon builders follow the same rule:
their exact PR identity owns the Packer VM, output, reservation, provenance, and cleanup scope, while portable product
and release names remain PR-independent. See the
[VMware Workstation lifecycle testing guide](docs/reference/vmware-workstation-lifecycle-testing.md).

See [Getting started](docs/getting-started/index.md) for the first-use path and
[Portable virtualization artifacts](docs/reference/virtualization-artifacts.md) for platform-specific import details.

## Safety model

Development appliances keep host-mutating adapters in dry-run mode by default. Operators edit desired state, review
the resulting appliance changes, and explicitly submit valid units through the global Appliance Apply workflow.

## Project and community

- [What is Atlaso?](docs/project/what-is-atlaso.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Brand kit](docs/assets/brand/BRAND_GUIDE.md)
- [License](LICENSE)

The documentation describes the latest supported Atlaso release. Pages marked **Roadmap** or **Historical** provide
context and do not describe current appliance behavior.
