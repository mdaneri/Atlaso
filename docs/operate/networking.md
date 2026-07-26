---
title: Network configuration
description: Inspect physical interfaces and configure VLAN, routing, and WAN desired state.
audience:
  - operator
status: current
---

# Network configuration

Use **Physical Interfaces**, **VLAN Interfaces**, and **Routes and WAN** to build Atlaso network desired state while
preserving management access.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Physical Interfaces page in the clean-appliance desktop viewport.](../assets/screenshots/physical-interfaces-clean-desktop.webp)

*Figure: Physical Interfaces in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Before you begin

Record the current management interface, address, gateway, and VM network attachment. Keep the
[local appliance console](appliance-console.md) available. A wrong interface, route, or VLAN can make the web UI
unreachable after apply.

## Configure the network

1. Inspect physical inventory and link state; do not treat an unused interface as failed.
2. Create VLAN interfaces only on the intended parent and use the required VLAN identifier.
3. Define routes and WAN behavior with explicit interface and network boundaries.
4. Review validation and rendered network previews.
5. Submit the selected network units through [Appliance Apply](appliance-apply.md).

Management-to-lab and lab-to-management forwarding remain prohibited. Service listeners and firewall rules must bind to
the same intended interfaces.

## Verify and roll back

Confirm the management URL, expected routes, and interface state after apply. If access is lost, use the local console
network recovery action to restore a known-good management configuration, then review desired state before retrying.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Physical interfaces

![Atlaso Physical Interfaces page in the clean-appliance responsive viewport.](../assets/screenshots/physical-interfaces-clean-responsive.webp)

*Figure: Physical Interfaces in the verified clean-appliance responsive state.*

### Routes and WAN simulation

![Atlaso Routes and WAN Simulation page in the clean-appliance desktop viewport.](../assets/screenshots/routes-wan-clean-desktop.webp)

*Figure: Routes and WAN Simulation in the verified clean-appliance desktop state.*

![Atlaso Routes and WAN Simulation page in the clean-appliance responsive viewport.](../assets/screenshots/routes-wan-clean-responsive.webp)

*Figure: Routes and WAN Simulation in the verified clean-appliance responsive state.*

### VLAN interfaces

![Atlaso VLAN Interfaces page in the clean-appliance desktop viewport.](../assets/screenshots/vlan-interfaces-clean-desktop.webp)

*Figure: VLAN Interfaces in the verified clean-appliance desktop state.*

![Atlaso VLAN Interfaces page in the clean-appliance responsive viewport.](../assets/screenshots/vlan-interfaces-clean-responsive.webp)

*Figure: VLAN Interfaces in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
