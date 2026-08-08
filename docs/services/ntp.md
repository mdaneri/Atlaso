---
title: NTP
description: Configure and verify Atlaso NTPsec time-service desired state.
audience:
  - operator
status: current
---

# NTP

Open **NTP** to configure appliance time sources and service behavior owned by NTPsec. Atlaso supports ordinary NTP;
NTS is disabled.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure time service

1. Select **Add source here** and use the reviewed source wizard to enter the endpoint and a full-width multiline
   description.
2. Configure desired enablement in the wizard. Existing source enablement remains directly editable in the grid.
   Editing a source updates that row; source names are unique after hostname, address, and optional-port normalization.
   Rename or remove an existing row before reusing its source name.
3. Review warnings about source reachability or incomplete settings.
4. Inspect the rendered NTPsec preview.
5. Submit the NTPsec unit through [Appliance Apply](../operate/appliance-apply.md).

Appliance Settings does not own time enforcement. DNS/DHCP also does not apply NTP configuration.

Atlaso normalizes legacy NTS flags off, rejects NTS directives, and removes legacy NTP certificate and cookie material
during NTP apply. Firewall apply opens UDP/123 only; it does not open the NTS-KE TCP/4460 listener.

## Verify

After the task succeeds, confirm the service is active and the appliance has selected a valid peer. Allow normal
settling time before treating an initial unsynchronized state as failure. Restore the previous sources and reapply if
the selected configuration cannot synchronize.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
