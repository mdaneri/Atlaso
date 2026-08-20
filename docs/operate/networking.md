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

![Atlaso Physical Interfaces page showing false glyphs in the IPv6 column and canonical interface roles.](../assets/screenshots/physical-interfaces-clean-desktop.webp)

*Figure: Physical Interfaces showing the standard Atlaso false glyph for disabled IPv6 and canonical network roles.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Before you begin

Record the current management interface, address, gateway, and VM network attachment. Keep the
[local appliance console](appliance-console.md) available. A wrong interface, route, or VLAN can make the web UI
unreachable after apply.

## Configure the network

1. Inspect physical inventory and link state; do not treat an unused interface as failed.
2. Create VLAN interfaces only on the intended trunk parent and use the required VLAN identifier.
3. Define routes and WAN behavior with explicit interface and network boundaries.
4. Review validation and rendered network previews.
5. Submit the selected network units through [Appliance Apply](appliance-apply.md).

### Assign an interface role

Physical and VLAN interfaces share one role contract:

- **management** identifies the dedicated management network. Only a physical interface can own management DHCP,
  default gateways, and management policy routing.
- **access** identifies an ordinary lab or service network. Access networks require explicit Routing Permissions before
  Atlaso forwards traffic between them.
- **route** identifies a lab routing network. Atlaso generates forwarding paths between route-role networks.
- **unused** keeps an interface outside lab routing and service-listener eligibility.

The retired **services** and **storage** choices no longer appear and cannot be submitted through the UI or API.
During an upgrade, Atlaso maps either retired value to **access** once and preserves the interface's addresses, Admin
Up state, enabled state, and management UI switch. Settings backup export and restore apply the same compatibility map.
Edits from Physical Interfaces and `PATCH /api/v1/interfaces/physical/{name}` share the same transaction. When an
IPv4 or IPv6 CIDR changes, Atlaso derives the replacement addresses for selected DNS, NTP/NTS, CA, KMS, LDAP, VCF,
ESX Storage, Web Terminal, DHCP, and Network Boot/PXE bindings before committing. A reconciliation failure, including
an existing DHCP range that cannot fit after a prefix shrink, rolls back the interface and every dependent desired-state
row together. Atlaso also rejects address removal, trunk conversion, or administrative disablement while an enabled
service, ESX Storage datastore, DHCP scope, or Network Boot/PXE binding would lose its final eligible address. A
physical parent becoming unavailable also evaluates bindings to its child VLANs. When other selected interfaces remain
eligible, reconciliation removes only the ineligible service, Web Terminal, or PXE selection. Disable or move a final
binding before retrying. Saving still does not change Photon until global Appliance Apply is submitted.

The internal Certificate Authority does not require a public listener. If its last selected portal interface becomes
ineligible, reconciliation clears the CA portal interface/address and alias without disabling internal CA custody.
Valid operator-selected DHCP gateway, DNS, and NTP values remain unchanged unless they match a replaced interface
address or otherwise become stale. Enabled DHCP reservations retain their host offsets when exactly one rebased scope
can receive them, including app-owned reservation DNS records; an ambiguous reservation move rolls back the interface
edit. Legacy global DHCP binding fields are inactive when real scope rows exist and do not block unrelated changes.
The saved interface, all reconciled dependent rows, and the value-free audit event commit together. The audit detail
names only dependent units whose desired state changed; a reconciliation or audit-staging failure leaves no partial
interface, dependency, reservation, DNS, or audit update.

### Choose where the management UI is available

A physical interface with the **management** role always exposes `/ui/management`; it has no separate management UI
switch. An addressed physical interface with the **access** role and **Access (untagged)** link type, or an enabled
access VLAN, can additionally enable **Management UI**. The interface remains an ordinary access network: it stays
eligible for public services and access service bindings, and it keeps access routing rather than gaining a
management-specific gateway or policy route.

Atlaso accepts that flag only when the access interface has a configured or observed usable non-link-local address.
An unaddressed or link-local-only interface cannot satisfy management lockout protection because no management HTTPS
listener can bind to it.

The default configuration remains `eth0` as the dedicated management interface with the switch disabled on all access
interfaces. To use one network for both planes, change `eth0` from management to access; Atlaso enables its management UI
switch as part of that conversion. You may then disable the unused second interface. Converting an access interface to
management clears its switch because management exposure is inherent in the role.

Atlaso permits at most one dedicated management-role physical interface. It also prevents desired state with no
effective management browser path: when no dedicated role exists, at least one active access interface or enabled
access VLAN must have **Management UI** enabled. Multiple flagged access interfaces are allowed. On a flagged access
address, `/` prefers the management sign-in, `/ui/management` requires normal authentication, and `/ui/public` remains
available for the same access network. The listener also preserves the complete authenticated management front door,
including stable API, API documentation, manifest, and service-worker routes required by the management UI and PWA.

When an Apply changes an effective management interface, address, gateway, or listener role, Atlaso automatically
bundles Network with Firewall, Certificate Authority, Appliance Settings, and Public Services. The old management path
stays active while the candidate network, policy routes, firewall, certificate/nginx configuration, Atlaso loopback
upstream, and host-facing `/openapi.json` complete bounded readiness checks. Only then does Atlaso retire the old path.

Only a dedicated management role owns management DHCP, default gateways, DHCP resolver recovery, and isolated
management policy routing. If that role is absent, flagged access interfaces retain their normal access routes. The
appliance FQDN and managed HTTPS certificate cover every effective management UI address.

Management-to-lab and lab-to-management forwarding remain prohibited. Service listeners and firewall rules must bind to
the same intended interfaces.

## Configure routes and WAN behavior

**Static Routes** and **Routing Permissions** solve different jobs:

- A **Static Route** selects a path to an IPv4 or IPv6 destination through a non-management interface or VLAN. It owns
  the destination CIDR, optional gateway, output target, metric, enabled state, and optional interface-level WAN policy.
- A **Routing Permission** authorizes forwarded traffic from one non-management interface/VLAN network to another.
  Route-role networks generate these paths automatically. Access networks remain blocked until an explicit permission
  is enabled. Management is never an eligible source or destination.

Use the bottom add row in each tab to open the shared reviewed wizard. Double-click a saved row or use **Edit** in its
row menu to update it. The standard step rail remains beside the form on wide screens and adapts to the narrow layout.
Each wizard retains entered values while moving backward, validates before Review, and saves only after the final
add/update action. A saved row's **Enabled** value remains directly editable; this changes desired state only.

The **NAT** wizard creates explicit IPv4 masquerade rules. Choose Any, an existing Firewall source group, or IPv4 source
CIDRs, then select an eligible IPv4-bearing access interface or enabled VLAN. Atlaso does not infer an outbound target
from an interface role and does not provide destination NAT, port forwarding, or IPv6 NAT in v1.

The **WAN Policies** wizard groups delay/capacity settings separately from packet loss and error effects. Assigning a
policy to a Static Route identifies its target interface or VLAN; WAN Simulation v1 impairs all traffic on that target,
not only traffic matching the route destination.

Saving any of these resources does not change Photon. Review the rendered configuration and submit the global
**Routes & WAN Simulation** unit through Appliance Apply when the complete desired state is ready.

### Add or edit a VLAN interface

The VLAN table is a read-only browse surface. Select **+ Add VLAN interface here** to create a row, or double-click an
existing row and use **Edit VLAN** from its context menu to revise it. The shared wizard reviews the complete VLAN
record in five steps:

1. Select an available trunk parent and VLAN ID; Atlaso derives the read-only `<parent>.<VLAN ID>` interface name.
2. Enter a valid IPv4 CIDR, IPv6 CIDR, or both, then confirm the MTU from `576` through `9000`. A new record starts with
   the selected parent MTU.
3. Select the VLAN role.
4. Confirm **Admin Up**. It is enabled by default for a new VLAN and preserves the saved value when editing.
5. Review the full desired-state change and save it.

The parent and VLAN ID must be unique. A VLAN whose previously saved parent is now missing may remain saved only while
disabled; select an available trunk before enabling it. Recoverable validation or server errors leave the wizard open
with its entered values. Saving refreshes validation and the configuration preview but does not change the host. Use
global **Appliance Apply** with the `network` unit when the reviewed desired state is ready for enforcement. Delete
remains a confirmed row-context action.

## Verify and roll back

Confirm the management URL, expected routes, and interface state after apply. A failed management handoff reports its
non-secret failing layer and rolls back the captured network, firewall, nginx, certificate, and service state before
the task becomes failed. If automatic rollback cannot restore access, use the local console network recovery action to
restore a known-good management configuration, then review desired state before retrying.

## Transport ownership

The management Routes/WAN transports and their API v1 counterparts are owned by the dedicated `routes_wan` domain
routers. The stable UI and API facade modules continue to aggregate and export those handlers. This internal ownership
split does not change any path, method, permission, response, desired-state behavior, or the global Appliance Apply
boundary described above.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Physical interfaces

![Responsive Atlaso Physical Interfaces page showing false glyphs for disabled IPv6.](../assets/screenshots/physical-interfaces-clean-responsive.webp)

*Figure: Physical Interfaces showing the standard Atlaso IPv6 glyphs at the responsive viewport.*

### Routes Wan: Policies

![Atlaso WAN policy wizard using the standard responsive rail and five reviewed configuration steps.](../assets/screenshots/routes-wan-policy-wizard-responsive.webp)

*Figure: Shared WAN policy wizard in the verified responsive viewport.*

### Routes Wan: Routes

![Atlaso static route wizard using the standard rail while reviewing the destination, interface path, WAN Simulation selection, and enabled state.](../assets/screenshots/routes-wan-static-route-wizard-desktop.webp)

*Figure: Shared static route wizard review with the complete path and appliance-apply boundary.*

### Routes and WAN simulation

![Atlaso Routes and WAN Simulation page in the clean-appliance desktop viewport.](../assets/screenshots/routes-wan-clean-desktop.webp)

*Figure: Routes and WAN Simulation in the verified clean-appliance desktop state.*

![Atlaso Routes and WAN Simulation page in the clean-appliance responsive viewport.](../assets/screenshots/routes-wan-clean-responsive.webp)

*Figure: Routes and WAN Simulation in the verified clean-appliance responsive state.*

### VLAN interfaces

![Atlaso VLAN Interfaces add wizard Role step showing access as the default role with the Management UI switch.](../assets/screenshots/vlan-interfaces-clean-desktop.webp)

*Figure: VLAN Interfaces shared Role step defaulting a new VLAN to the canonical access role.*

![Responsive Atlaso VLAN Interfaces page backed by the canonical management, access, route, and unused roles.](../assets/screenshots/vlan-interfaces-clean-responsive.webp)

*Figure: VLAN Interfaces with canonical role data in the verified responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
