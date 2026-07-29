# Atlaso

![Atlaso — Everything your virtualization lab needs](docs/assets/brand/atlaso-docs-header-dark-1600x400.png)

**Everything your virtualization lab needs.**

Atlaso is an all-in-one infrastructure appliance for virtualization proof-of-concept, lab, and test environments. It
brings infrastructure, storage, identity, networking, and lifecycle workflows into one operator-focused control plane.

## Start here

- [Documentation](https://mdaneri.github.io/Atlaso/docs/) — install, configure, operate, and troubleshoot Atlaso.
- [Getting started](docs/getting-started/index.md) — choose an appliance path and complete initial setup.
- [Operations](docs/operate/index.md) — run the appliance and review desired-state changes.
- [Services](docs/services/index.md) — configure DNS, identity, storage, network boot, and VCF integrations.
- [Network Boot](docs/services/ipxe.md) — discover unassigned hardware with
  read-only Inventory Linux, activate verified interactive maintenance media,
  and retain the ESX scripted-install workflow.
- [Vaults](docs/services/vaults.md) — scope encrypted VCF and ESX passwords to managed scripts and exact Kickstart
  source markers.
- [OpenID Connect provider](docs/services/oidc-provider.md) — use the dedicated tabbed administration page for
  confidential clients, exact redirects, key rotation, explicit identity sources, and privacy-safe scoped claims.
- [vSphere Key Provider protocol](docs/reference/vsphere-key-provider-protocol.md) — review the appliance-native
  daemon's bounded, currently unverified VCF 9.1 KMIP contract and live-evidence promotion gate.
- [Technical reference](docs/reference/index.md) — API, image building, lifecycle testing, and detailed behavior.
- [Contributing](CONTRIBUTING.md) — issue, version, validation, and pull-request requirements.
- [UI Design Guide](docs/contribute/ui-design-guide.md) — approved Atlaso patterns and the shared
  `AtlasoUiPatterns.createGrid(...)` / `createWizard(...)` foundation used by every grid and wizard.

## Supported appliance targets

Photon OS 5.0 is the appliance operating system. VMware Workstation is the default live-test target; Hyper-V remains the
authoritative lifecycle interoperability environment for exact access and trunk VLAN behavior.

Development appliances keep host-mutating adapters in dry-run mode by default. Atlaso applies selected desired state
only through the global appliance-change workflow and its constrained privileged helper. Secret-bearing Local Users,
Certificate Authority, and Managed LDAP inputs are staged with mode `0600` only for the helper execution window and
removed after every terminal outcome and during application startup recovery. The KMS compatibility listener and
pre-authentication VCF Automation and vSphere certificate probes require TLS 1.2 or newer; the probes retain explicit
certificate-fingerprint confirmation as their trust decision.

## Project

- [Brand guide](docs/assets/brand/BRAND_GUIDE.md)
- [Security and data classification policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [License](LICENSE)

The repository documentation describes the latest supported Atlaso release. Roadmaps and historical design records are
clearly labeled and are not statements of current behavior.

Atlaso code and configuration editing uses the locally bundled Monaco Editor. ESXi Kickstarts use a dedicated language
with completion for built-in, discovered custom, and authorized vault markers; credential values remain server-side.
