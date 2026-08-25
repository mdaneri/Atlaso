---
title: Firewall
description: Review and configure Atlaso nftables desired state with reusable Source Groups.
audience:
  - operator
  - maintainer
status: current
---

# Firewall

Open **Firewall** to manage Atlaso-owned nftables desired state. The page combines generated service-listener rules,
routing permissions, and operator-defined rules. Reusable Source Groups are owned by the separate
[Network Objects](../operate/network-objects.md) page.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Firewall page in the clean-appliance desktop viewport.](../assets/screenshots/firewall-clean-desktop.webp)

*Figure: Firewall in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

Select **Add rule here** or open an existing operator rule to use the five-step guided workflow. Rule identity, traffic
matching, priority and notes, enablement, and final review are separate decisions. The dedicated **Enablement** step
makes clear that enabling a rule changes rendered desired state only; enforcement still waits for the global Firewall
appliance-apply unit.

## Review safely

1. Confirm management access remains allowed from the intended source.
2. Review enabled service listeners and their bound interfaces.
3. Use **Manage source groups** in the rule wizard when a reusable Source Group should narrow a source or destination.
4. Inspect the rendered ruleset and resolve validation errors.
5. Submit the Firewall unit through [Appliance Apply](../operate/appliance-apply.md).

Atlaso always blocks management-to-lab and lab-to-management forwarding. DHCP bootstrap rules remain interface-bound
and are not group-filtered.

Generated management-listener rules admit TCP/22, TCP/80, and TCP/443 on both a dedicated management interface and an
access physical interface or VLAN whose **Management UI** flag is applied. The listener's configured Source Group
predicate governs all three ports. Atlaso does not add TCP/22 to unflagged access networks, and firewall admission does
not enable root login: the separate Appliance Settings root-SSH preference remains authoritative while ordinary
bootstrap-administrator or key-based SSH stays available on every effective management listener.

During a protected management handoff, the previous listener retains its SSH rule until the candidate management path
and front door pass readiness. A successful handoff leaves the generated TCP/22 rule on the new listener; rollback
restores the previous rule with its original Source Group constraint.

## Verify and recover

After a successful task, test the required TCP or UDP service from the intended network. On the appliance, maintainers
can verify the effective state with `nft list ruleset`. If a rule removes management access, recover through the
[local appliance console](../operate/appliance-console.md) and restore the previous desired state.

## Transport ownership

Firewall management and API v1 transports are owned by dedicated `firewall` domain routers and aggregated through the
stable UI and API facades. Network Objects owns Source Group projection and mutation while retaining the established
`firewall.managed_source_groups` state and Firewall apply semantics. Both surfaces continue to use
`read:firewall` and `write:firewall`, so moving the editor does not broaden access.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Firewall

![Atlaso Firewall page in the clean-appliance responsive viewport.](../assets/screenshots/firewall-clean-responsive.webp)

*Figure: Firewall in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
