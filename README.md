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
- [Technical reference](docs/reference/index.md) — API, image building, lifecycle testing, and detailed behavior.
- [Contributing](CONTRIBUTING.md) — issue, version, validation, and pull-request requirements.

## Supported appliance targets

Photon OS 5.0 is the appliance operating system. VMware Workstation is the default live-test target; Hyper-V remains the
authoritative lifecycle interoperability environment for exact access and trunk VLAN behavior.

Development appliances keep host-mutating adapters in dry-run mode by default. Atlaso applies selected desired state
only through the global appliance-change workflow and its constrained privileged helper.

## Project

- [Brand guide](docs/assets/brand/BRAND_GUIDE.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [License](LICENSE)

The repository documentation describes the latest supported Atlaso release. Roadmaps and historical design records are
clearly labeled and are not statements of current behavior.
