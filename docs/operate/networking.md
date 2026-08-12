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

![Atlaso Physical Interfaces page showing inherent management UI on eth0 and the true glyph on access interface eth1.](../assets/screenshots/physical-interfaces-clean-desktop.webp)

*Figure: Physical Interfaces showing inherent management exposure and the standard Atlaso true glyph for access exposure.*

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

### Choose where the management UI is available

A physical interface with the **management** role always exposes `/ui/management`; it has no separate management UI
switch. An addressed physical interface with the **access** role and **Access (untagged)** link type, or an enabled
access VLAN, can additionally enable **Management UI**. The interface remains an ordinary access network: it stays
eligible for public services and access service bindings, and it keeps access routing rather than gaining a
management-specific gateway or policy route.

The default configuration remains `eth0` as the dedicated management interface with the switch disabled on all access
interfaces. To use one network for both planes, change `eth0` from management to access; Atlaso enables its management UI
switch as part of that conversion. You may then disable the unused second interface. Converting an access interface to
management clears its switch because management exposure is inherent in the role.

Atlaso permits at most one dedicated management-role physical interface. It also prevents desired state with no
effective management browser path: when no dedicated role exists, at least one active access interface or enabled
access VLAN must have **Management UI** enabled. Multiple flagged access interfaces are allowed. On a flagged access
address, `/` prefers the management sign-in, `/ui/management` requires normal authentication, and `/ui/public` remains
available for the same access network.

Only a dedicated management role owns management DHCP, default gateways, DHCP resolver recovery, and isolated
management policy routing. If that role is absent, flagged access interfaces retain their normal access routes. The
appliance FQDN and managed HTTPS certificate cover every effective management UI address.

Management-to-lab and lab-to-management forwarding remain prohibited. Service listeners and firewall rules must bind to
the same intended interfaces.

## Verify and roll back

Confirm the management URL, expected routes, and interface state after apply. If access is lost, use the local console
network recovery action to restore a known-good management configuration, then review desired state before retrying.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Physical interfaces

![Responsive Atlaso Physical Interfaces page showing inherent management UI and the true glyph for access management UI.](../assets/screenshots/physical-interfaces-clean-responsive.webp)

*Figure: Physical Interfaces showing inherent management exposure and the standard Atlaso true glyph at the responsive viewport.*

### Routes and WAN simulation

![Atlaso Routes and WAN Simulation page in the clean-appliance desktop viewport.](../assets/screenshots/routes-wan-clean-desktop.webp)

*Figure: Routes and WAN Simulation in the verified clean-appliance desktop state.*

![Atlaso Routes and WAN Simulation page in the clean-appliance responsive viewport.](../assets/screenshots/routes-wan-clean-responsive.webp)

*Figure: Routes and WAN Simulation in the verified clean-appliance responsive state.*

### VLAN interfaces

![Atlaso VLAN Interfaces page showing the access VLAN management UI option.](../assets/screenshots/vlan-interfaces-clean-desktop.webp)

*Figure: VLAN Interfaces showing optional access management UI exposure in the verified appliance desktop state.*

![Responsive Atlaso VLAN Interfaces page showing the access VLAN management UI option.](../assets/screenshots/vlan-interfaces-clean-responsive.webp)

*Figure: VLAN Interfaces management UI option in the verified appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
