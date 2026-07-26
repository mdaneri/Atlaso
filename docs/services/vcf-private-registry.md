---
title: VCF Private Registry
description: Configure and verify Atlaso private-registry desired state for supported VCF workflows.
audience:
  - operator
status: current
---

# VCF Private Registry

Open **VCF Private Registry** to configure the appliance-hosted registry endpoint, storage, listener, and access
boundaries.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso VCF Private Registry page in the clean-appliance desktop viewport.](../assets/screenshots/vcf-private-registry-clean-desktop.webp)

*Figure: VCF Private Registry in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure the registry

1. Confirm the registry storage mount and intended listener interface.
2. Configure only the access needed by approved lab clients.
3. Resolve validation errors and inspect the rendered service preview.
4. Submit the VCF Private Registry unit through [Appliance Apply](../operate/appliance-apply.md).

Keep credentials, authenticated image references, and private certificate material out of documentation and task
output.

## Verify and roll back

After a successful task, confirm the endpoint presents the expected certificate and an approved client can perform the
required registry operation. Restore the previous desired state and reapply if the listener or trust configuration is
incorrect; do not edit appliance-owned service files directly.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### VCF Private Registry

![Atlaso VCF Private Registry page in the clean-appliance responsive viewport.](../assets/screenshots/vcf-private-registry-clean-responsive.webp)

*Figure: VCF Private Registry in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
