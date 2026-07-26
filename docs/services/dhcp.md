---
title: DHCP
description: Configure Atlaso DHCP scopes, reservations, interfaces, and validation.
audience:
  - operator
status: current
---

# DHCP

Open **DHCP** to manage scope and reservation desired state rendered into the shared dnsmasq apply unit.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso DHCP page in the clean-appliance desktop viewport.](../assets/screenshots/dhcp-clean-desktop.webp)

*Figure: DHCP in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure a scope

1. Select the interface that owns the client network.
2. Define a non-overlapping address range, lease policy, gateway, and DNS options.
3. Add reservations with unique client identity and address values.
4. Resolve Validation-card errors and inspect the rendered dnsmasq preview.
5. Submit `DNS/DHCP (dnsmasq)` through [Appliance Apply](../operate/appliance-apply.md).

Changing a scope does not serve leases until the global apply task succeeds. Interface changes also affect generated
firewall bootstrap rules, so confirm the intended bind target in the review.

## Verify

Confirm the task succeeded, `dnsmasq` is healthy, and a test client on the selected network receives the expected lease
and options. Roll back by restoring the previous desired state and submitting a new global apply.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### DHCP

![Atlaso DHCP page in the clean-appliance responsive viewport.](../assets/screenshots/dhcp-clean-responsive.webp)

*Figure: DHCP in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
