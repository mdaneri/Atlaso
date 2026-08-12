---
title: Backup and restore
description: Create, download, validate, and restore Atlaso settings backups safely.
audience:
  - operator
  - maintainer
status: current
---

# Backup and restore

Open **Backup and Restore** to protect Atlaso settings before maintenance and recover the control-plane configuration
when needed.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Backup and Restore page in the clean-appliance desktop viewport.](../assets/screenshots/backup-restore-clean-desktop.webp)

*Figure: Backup and Restore in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Create a backup

1. Create a named backup before a high-risk configuration or update operation.
2. Download the archive and store it according to the environment's access policy.
3. Retain the appliance secrets key with the appliance recovery material; encrypted private keys are not portable
   without it.

Backups can contain operational configuration and encrypted sensitive material. Do not attach them to public issues.
VCF/ESX password vault entries are not included in settings archives. Restore clears vaults and the unused legacy
Kickstart-binding compatibility table; recreate or reimport vault entries before re-enabling dependent scripts or PXE
workflows. Non-secret ESXi PXE custom-variable catalog definitions and defaults are included so restored Kickstarts
retain their `{{custom.*}}` prerequisites.

## Restore safely

1. Take a VM snapshot or equivalent rollback point.
2. Select the intended archive and review the restore warning.
3. Confirm the destructive restore through the shared confirmation dialog.
4. Wait for the restore task to finish, then sign in again if the session was invalidated.
5. Review pending desired state before submitting any appliance apply.

Atlaso validates every supplied archive collection, required row field, relationship, and enabled VLAN or static-route
target before it removes current desired state. If validation or a later restore phase fails, Atlaso rolls back the
database transaction and leaves any separately staged LDAP recovery import metadata and in-memory payload available for
the next global LDAP apply. A successful settings restore or factory reset intentionally clears that staged LDAP
recovery material.

Verify identity, DNS, service configuration, and recent tasks after recovery. Restore changes Atlaso state; host
services are enforced only through their documented workflows.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Backup and restore

![Atlaso Backup and Restore page in the clean-appliance responsive viewport.](../assets/screenshots/backup-restore-clean-responsive.webp)

*Figure: Backup and Restore in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
