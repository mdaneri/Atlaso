---
title: NTP and NTS
description: Configure and verify Atlaso NTPsec time-service desired state.
audience:
  - operator
status: current
---

# NTP and NTS

Open **NTP and NTS** to configure appliance time sources, service behavior, and network time security settings owned by
NTPsec.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso NTP and NTS page in the clean-appliance desktop viewport.](../assets/screenshots/ntp-clean-desktop.webp)

*Figure: NTP and NTS in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure time service

1. Add reachable, trusted time sources.
2. Configure NTS only when the source and certificate trust are available.
3. Review warnings about source reachability or incomplete security settings.
4. Inspect the rendered NTPsec preview.
5. Submit the NTPsec unit through [Appliance Apply](../operate/appliance-apply.md).

Appliance Settings does not own time enforcement. DNS/DHCP also does not apply NTP configuration.

## Verify

After the task succeeds, confirm the service is active and the appliance has selected a valid peer. Allow normal
settling time before treating an initial unsynchronized state as failure. Restore the previous sources and reapply if
the selected configuration cannot synchronize.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### NTP and NTS

![Atlaso NTP and NTS page in the clean-appliance responsive viewport.](../assets/screenshots/ntp-clean-responsive.webp)

*Figure: NTP and NTS in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
