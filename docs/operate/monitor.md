---
title: Monitor appliance health
description: Read Atlaso CPU, memory, network, disk-activity, interface, and virtual-machine health.
audience:
  - operator
status: current
---

# Monitor appliance health

Open **Monitor** for a read-only view of current appliance runtime health. The page reports CPU, memory pressure,
network throughput, unique-device disk activity, interface state, and virtual-machine context.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Monitor page in the clean-appliance desktop viewport.](../assets/screenshots/monitor-clean-desktop.webp)

*Figure: Monitor in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Read the charts

- Start with the appliance totals before expanding per-CPU, per-interface, or per-device series.
- Use the common time-range selector to compare the same interval across charts.
- Expand a chart when series overlap; full-screen zoom does not change the selected history range.
- Treat unexpectedly down configured physical interfaces as actionable. Disabled optional services and unused
  interfaces are not exceptions.

Filesystem-capacity charts are intentionally not part of this page. Disk activity is counted once per underlying
device, even when a filesystem is visible through multiple mount paths.

## Verify an exception

Compare interface exceptions with [Network configuration](networking.md), service health with the owning service guide,
and recent failures with [Tasks](tasks.md). Monitor is read-only; make changes through the owning desired-state workflow
and use [Appliance Apply](appliance-apply.md) for enforcement.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Monitor

![Atlaso Monitor page showing live appliance runtime metrics after apply.](../assets/screenshots/monitor-applied-desktop.webp)

*Figure: Runtime monitoring after a successful appliance apply.*

![Atlaso Monitor page in the clean-appliance responsive viewport.](../assets/screenshots/monitor-clean-responsive.webp)

*Figure: Monitor in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
