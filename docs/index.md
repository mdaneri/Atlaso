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

## Safety boundary

Development appliances keep system adapters in dry-run mode by default. Desired-state editing does not mutate the host.
Operators explicitly review and submit selected valid units through the global appliance-change workflow.
