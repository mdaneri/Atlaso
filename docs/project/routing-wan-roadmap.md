---
title: Routing And WAN Roadmap
description: Historical design roadmap for Atlaso routing and WAN behavior.
audience:
  - contributor
  - maintainer
status: roadmap
---

# Routing And WAN Roadmap

Current source translation is documented in [Traffic Publishing](../operate/traffic-publishing.md), including IPv6
masquerade and fixed SNAT. The original v1 scope below records the pre-split design; destination NAT and NPTv6 remain
separate future work.

Atlaso Routing/WAN v1 was intentionally appliance-owned and conservative. Desired state is edited on
`/ui/management/routes-wan`; host mutation happens only through the global `/ui/management/appliance-apply` `wan` unit.

The original v1 UI presented four wizard-backed collections: **Static Routes**, **Routing Permissions**, **NAT**, and
**WAN Policies**. Static Routes define paths in the lab route table. Routing Permissions separately define forwarding
between interface/VLAN networks. Add/edit changes are reviewed before one desired-state save, while ordinary Enabled
state remains directly editable and generated route-role permissions remain read-only. A non-grid
**Routing & WAN Settings** card provides independent global Routing, NAT, and WAN Simulation desired-state switches;
all three are off on fresh install and factory reset.

Atlaso has no `wan` interface role. The `wan` apply-unit name and WAN Simulation UI describe explicit routing, NAT, and
impairment behavior only; they must not be used as an interface classification.

## Original V1 Scope

- Static route desired state rendered to `/var/lib/atlaso/apply/wan/atlaso-wan.conf`.
- Explicit IPv4 and IPv6 default-route wizard paths that persist canonical `0.0.0.0/0` and `::/0`, require a
  same-family next-hop gateway that is on-link for the selected target (or IPv6 link-local), and allow one default per
  family while preserving canonical `/0` API compatibility.
- Separate route tables for management and lab networks: management keeps its own default gateway, while non-management
  routes install into the lab route table.
- Routing permissions for lab forwarding. Route-role networks forward to other route-role networks by default; access
  networks need explicit routing rules.
- IPv4 outbound masquerade NAT rules rendered as the Atlaso-owned `table ip atlaso_nat`, with explicit inbound
  interface/VLAN membership and one distinct outbound target. Legacy unscoped rules remain saved but require review
  before enablement or active NAT apply.
  Boot replay and management-handoff recovery retire legacy NAT rules without ingress or physical-identity
  provenance while restoring prior routing, forwarding, and WAN simulation settings. Handoff preflight validates
  the same normalized rollback configuration before candidate mutation. Original snapshots remain intact; handoff
  rollback persists the normalized runtime, and modern scoped rules retain their NAT identity checks.
  If a saved NIC identity is absent or replaced during recovery, Atlaso reports NAT quarantine and restores the
  remaining WAN state only after clearing the NAT table successfully. Ordinary Apply still fails on identity mismatch.
  Settings archives preserve enabled NAT rules awaiting missing-NIC review when their selectors are backed by
  archived inert physical-interface or disabled VLAN records. Restore preserves that intent; Appliance Apply still
  rejects those targets until an administrator selects available interfaces.
- NAT outbound interfaces can be access physical interfaces with IPv4 CIDRs or enabled VLAN interfaces with IPv4 CIDRs;
  NAT eligibility is not inferred from an interface role.
- IPv4 and IPv6 packet forwarding follow the global Routing switch. NAT is effective only when both Routing and NAT
  are enabled, while WAN Simulation remains independent.
- Feature switches preserve all saved resource rows and assignments while clearing inactive runtime state. Legacy
  installations and settings archives infer absent switches once from previously effective enabled rows.
- Management is never a route, NAT, or routing-permission target, and firewall apply generates explicit
  management-to-lab and lab-to-management forward drops.
- Interface/VLAN-level WAN simulation through one `tc qdisc replace dev <target> root netem ...` per target with an
  enabled assigned policy.
- Disabled or unassigned WAN policy targets clear only Atlaso-owned root qdisc intent.
- Route commands use `ip route replace <destination> [via <gateway>] dev <interface> metric <metric> table 200`.
- A static management-to-access conversion moves each valid management gateway into an enabled canonical family default
  on the converted access target. Equivalent defaults are reused; conflicting family defaults reject the atomic edit.
  When that route is not in the last-applied WAN baseline, WAN joins the existing protected management handoff and its
  rollback config restores the prior table `200` intent.

`wan_mode=interface` is the only supported WAN impairment mode in v1. Route-specific impairment is not exposed in the UI
or public API until it has a real helper implementation.

## Planned Route-Specific Impairment

Route-specific WAN impairment should let an operator attach a WAN policy to traffic matching a route or route-like
destination without impairing all traffic on that interface. This is planned work, not current behavior.

Before exposing a `route` mode, the design needs to settle:

- Packet classification approach: `tc` filters, nftables packet marks, policy routing, or another Photon-safe mechanism.
- Conflict behavior when multiple routes, NAT rules, firewall rules, or service listeners match the same packets.
- Rollback semantics for marks, filters, chains, and qdisc state based on the last-applied Atlaso baseline.
- Observability in previews and jobs so operators can see every mark/filter/qdisc command that will run.
- Photon verification commands that prove only the intended destination traffic is impaired.

The likely implementation shape is:

1. Render explicit route impairment entries in the staged WAN config.
2. Validate destination CIDRs, target interfaces, mark IDs, and policy references in `atlaso-helper wan validate`.
3. Install a Atlaso-owned classification layer, avoiding broad rewrites of unrelated nftables or `tc` state.
4. Apply `tc` filters and netem classes only for tracked Atlaso-owned route impairment entries.
5. Remove disabled or removed route impairment only when it appears in the last-applied baseline.

## NAT Roadmap

Original NAT v1 supported IPv4 masquerade only. Current source NAT also supports IPv6 and fixed SNAT. Future work can consider:

- Destination NAT and port forwarding with clear listener ownership.
- Per-rule counters or status readback.
- NPTv6 remains future work only if a concrete lab use case
  justifies it.

Do not infer broad NAT automatically from interface roles. NAT must remain an explicit desired-state rule reviewed
through global appliance apply.

## Verification

Live Photon validation for Routing/WAN changes should inspect both the Atlaso preview/job and the host state:

```bash
ip route
tc qdisc show
nft list ruleset
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
systemctl status atlaso-nat.service --no-pager
```

For route-specific impairment work, add packet-level validation that shows matching destination traffic is impaired
while unrelated traffic on the same interface is not.
