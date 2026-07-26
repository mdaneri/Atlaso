---
title: VCF backups
description: Configure and run Atlaso-managed backup workflows for supported VCF targets.
audience:
  - operator
status: current
---

# VCF backups

Open **VCF Backups** to configure supported VCF backup targets and follow their task-based execution.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso VCF Backups page in the clean-appliance desktop viewport.](../assets/screenshots/vcf-backups-clean-desktop.webp)

*Figure: VCF Backups in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure a target

1. Select the supported VCF appliance and provide its network endpoint.
2. Use the minimum required credential and confirm TLS identity when prompted.
3. Review storage location, retention, and validation warnings.
4. Save the desired configuration and submit any required VCF Backups apply unit.
5. Start the backup operation and follow it on [Tasks](../operate/tasks.md).

Credentials must remain encrypted or transient and must not appear in jobs, audits, logs, or screenshots.

## Verify and recover

Treat a successful task plus a readable backup artifact as completion. Record the target, timestamp, task identifier,
and artifact identity. Periodically test the documented restore path in an isolated environment; an unverified archive
is not sufficient recovery evidence.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### VCF backups

![Atlaso VCF Backups page in the clean-appliance responsive viewport.](../assets/screenshots/vcf-backups-clean-responsive.webp)

*Figure: VCF Backups in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
