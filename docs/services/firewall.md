---
title: Firewall
description: Review and configure Atlaso nftables desired state and access groups.
audience:
  - operator
  - maintainer
status: current
---

# Firewall

Open **Firewall** to manage Atlaso-owned nftables desired state. The page combines generated service-listener rules,
routing permissions, and operator-defined access groups.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Firewall page in the clean-appliance desktop viewport.](../assets/screenshots/firewall-clean-desktop.webp)

*Figure: Firewall in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Review safely

1. Confirm management access remains allowed from the intended source.
2. Review enabled service listeners and their bound interfaces.
3. Use access groups to narrow sources or destinations when `Any` is too broad.
4. Inspect the rendered ruleset and resolve validation errors.
5. Submit the Firewall unit through [Appliance Apply](../operate/appliance-apply.md).

Atlaso always blocks management-to-lab and lab-to-management forwarding. DHCP bootstrap rules remain interface-bound
and are not group-filtered.

## Verify and recover

After a successful task, test the required TCP or UDP service from the intended network. On the appliance, maintainers
can verify the effective state with `nft list ruleset`. If a rule removes management access, recover through the
[local appliance console](../operate/appliance-console.md) and restore the previous desired state.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Firewall

![Atlaso Firewall page in the clean-appliance responsive viewport.](../assets/screenshots/firewall-clean-responsive.webp)

*Figure: Firewall in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
