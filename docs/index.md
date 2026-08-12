---
title: Atlaso documentation
description: Install, configure, operate, and extend the Atlaso virtualization lab appliance.
audience:
  - operator
  - contributor
  - maintainer
status: current
---

# Atlaso documentation

Atlaso brings infrastructure, storage, identity, networking, and lifecycle workflows together for virtualization
proof-of-concept, lab, and test environments.

## Choose your path

- [Getting started](getting-started/index.md) for installation and first configuration.
- [Operate](operate/index.md) for daily appliance tasks, changes, updates, automation, and troubleshooting.
- [Services](services/index.md) for DNS, identity, storage, network boot, VCF/ESX password vaults, and VCF integrations.
- [Reference](reference/index.md) for APIs, image building, interoperability, and detailed technical behavior.
- [Contribute](contribute/index.md) for repository workflow, documentation, design, and implementation policies.
- [Project](project/index.md) for the Atlaso name, branding, roadmaps, and historical design records.

> **Latest documentation:** This site describes the latest supported Atlaso release. Pages marked **Roadmap** or
> **Historical** are context, not statements of current appliance behavior.

## Popular guides

Start with these common operator tasks. The section indexes above contain the complete guide set.

- [Recover management access](operate/appliance-console.md) — correct management networking from the local console.
- [Use the Atlaso API](operate/api.md) — create scoped tokens and call the versioned REST contract safely.
- [Update the appliance](operate/appliance-update.md) — review update sources and install signed updates.
- [Configure DNS](services/dns.md) — manage appliance name resolution and authoritative zones.
- [Prepare Network Boot](services/ipxe.md) — discover hosts and stage interactive or scripted boot workflows.
- [Manage credentials with Vaults](services/vaults.md) — scope encrypted VCF and ESX credentials to approved workflows.
- [Configure OpenID Connect](services/oidc-provider.md) — manage clients, identity sources, claims, and key rotation.
- [Manage vSphere Key Providers](services/vsphere-key-providers.md) — configure provider-scoped VCF 9.1 key services.

## Safety boundary

Development appliances keep system adapters in dry-run mode by default. Desired-state editing does not mutate the host.
Operators explicitly review and submit selected valid units through the global appliance-change workflow.
