---
title: Traffic Publishing
description: Configure explicit IPv4 and IPv6 source translation and apply it safely.
audience:
  - operator
  - maintainer
status: current
---

# Traffic Publishing

Use **Network → Traffic Publishing** at `/ui/management/traffic-publishing` to configure source NAT. **Routing & WAN**
at `/ui/management/routes-wan` owns static routes, routing permissions, forwarding, and WAN simulation. Traffic
Publishing requires Firewall read permission; changing its browser settings or rules requires Firewall write permission.

## Configure source translation

1. Configure two distinct addressed lab targets in Physical Interfaces or VLAN Interfaces. Use enabled `access` or
   `route` targets. A VLAN also needs an available, enabled trunk parent. Dedicated management, unused, missing,
   disabled, and unaddressed targets are excluded. Access-management flags do not exclude an eligible access target.
2. Add a rule from the Source NAT grid's bottom row, or open an existing rule to edit it.
3. Select **IP family**: IPv4 or IPv6. Select every intended **Inbound interface or VLAN** and one distinct
   **Outbound interface or VLAN** with addresses in that family.
4. Select any same-family source, a shared Source Group, or explicit same-family source CIDRs. A Source Group must
   resolve entirely within the selected family. These selectors restrict addresses inside the selected ingress;
   they never grant access from another interface. **Manage source groups** preserves the tab-local wizard draft.
5. Select **Interface-address masquerade**, or **Fixed SNAT** and the exact same-family address assigned to the egress
   target. Fixed SNAT does not assign an address or create a pool. IPv6 translation is stateful NAT66.
6. Review the family, ingress, source, egress, translation, priority, and enabled state, then save.
7. Enable **NAT enabled** and enable Routing in **Routing & WAN** when forwarding is intended. Both switches default
   off. Routing is the sole owner of IPv4 and IPv6 forwarding. NAT intent remains saved and visibly suspended while
   Routing is off; WAN simulation remains independent.
8. Review global Appliance Apply and submit **Traffic Publishing** (`nat`). Changed Network and Routing dependencies
   join the submission so the translation snapshot matches target and forwarding state. Management changes retain
   the protected management handoff.

Saving only changes desired state. There is no rule-specific Apply action. Disabled features preserve their rows.
Every rendered rule includes explicit ingress selectors, so appliance-originated traffic cannot match it. This page
does not configure destination NAT, port forwarding, proxies, address pools, or NPTv6.

## Verify and recover

At boot, the NAT replay service runs after Routing & WAN and before Atlaso startup. Atlaso's subsequent startup
reconciliation therefore verifies the saved NAT state without racing the replay service.

Inspect the global task result and `nft list table ip atlaso_nat` and `nft list table ip6 atlaso_nat` on the appliance.
Use traffic from a selected ingress to verify the translated source and return path. Also verify that another ingress,
the dedicated management interface, the wrong family, and appliance-local traffic do not match. Existing connection
tracking can retain an established flow's prior translation; use new connections when testing changed rules.

The NAT helper validates the captured configuration, verifies each physical MAC and live interface index, and verifies
that a fixed address is actually assigned to the live egress. It atomically replaces the two Atlaso-owned NAT tables
without replacing unrelated nftables tables. A durable recovery record restores the previous configuration, runtime
program, and service enablement if persistence or activation fails. Failed recovery remains actionable.

Successful Apply persists `/etc/atlaso/traffic-publishing/atlaso-nat.conf` and enables `atlaso-nat.service` only while
NAT intent is enabled. Disabling NAT or factory reset disables that replay service and clears translation. Boot and
control-plane startup rebuild selectors using current interface indexes. A replaced or missing NIC, or an unavailable
fixed address, quarantines translation and requires review. The saved desired rule is preserved. Do not hand-edit
`/etc/atlaso/nftables.d/atlaso-nat.nft`; the managed include path remains stable.

## Upgrade, archives, and API compatibility

Existing IPv4 rules gain `ip_family=4`, `translation_mode=masquerade`, and an empty `translated_address`. Existing
explicit NAT enablement migrates to the single `traffic_publishing.nat_enabled` setting. A rule without explicit
ingress stays saved for review and cannot become active until its ingress is selected. Archives preserve rules and
missing identities backed by archived host inventory; restoring them does not make those identities runtime-eligible.
Factory reset disables NAT and clears its desired rules through the normal reset and Apply lifecycle.

`GET` and `PUT /api/v1/traffic-publishing/settings` use `read:firewall` and `write:firewall`. The response exposes
`nat_enabled`, `routing_enabled`, `effective_nat_enabled`, and `suspended`; only `nat_enabled` is writable. These are
desired-state values, not a live-health assertion. Validation failures use ProblemDetails.

Existing `/api/v1/nat/rules` paths, operation IDs, and `read:wan` / `write:wan` authorization remain compatible. The
family, mode, and translated-address fields are additive. Older IPv4 request bodies retain their defaults. Rule PATCH
preserves omitted ingress, family, mode, and translated-address fields. `masquerade` remains a compatibility mirror.
`RoutesWanSettings.nat_enabled` is deprecated and projects the same canonical setting; legacy writes update that
setting in the same desired-state transaction. It does not create a second NAT owner.

Existing Routes/WAN NAT form submissions are internally handled and return a same-host `303` to Traffic Publishing;
mutations are never replayed through `307` or `308`. Use the canonical Traffic Publishing bookmark for the rule grid.
