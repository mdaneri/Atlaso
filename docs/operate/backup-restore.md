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
retain their `{{custom.*}}` prerequisites. Uploaded VCF Private Registry CA bundle bytes are also excluded. When an
enabled registry depends on an uploaded bundle instead of the internal CA, the export records the registry as disabled;
upload the CA bundle again and review the registry settings before re-enabling it.

## Restore safely

1. Take a VM snapshot or equivalent rollback point.
2. Select the intended archive and review the restore warning.
3. Confirm the destructive restore through the shared confirmation dialog.
4. Wait for the restore task to finish, then sign in again if the session was invalidated.
5. Review pending desired state before submitting any appliance apply.

Atlaso validates every supplied archive collection, required row field, relationship, and enabled VLAN or static-route
target before it removes current desired state. Enabled service listener addresses must exactly match the addresses
derived from their selected interfaces. Firewall source groups must use nonblank current-format identifiers and names,
nonempty string entry lists, unique identifiers, and assignments that resolve to `any` or a supplied group. Every
non-comment DNS conditional-forwarder line must include a domain and one or more servers. Because password hashes remain
outside settings archives, exported Managed LDAP users are disabled and restored archives that try to enable a user
without a staged password are rejected. Recover the directory passwords and review user enablement before the next
global LDAP apply. If validation or a later restore phase fails, Atlaso rolls back the database transaction and leaves
any separately staged LDAP recovery import metadata and in-memory payload available. A successful settings restore or
factory reset intentionally clears that staged LDAP recovery material.

OIDC group mappings are preflighted in their effective global, client, and managed-LDAP organization contexts. A
client-specific mapping may replace the global mapping for the same source, but effective external group names must
remain unique case-insensitively within every context before current desired state is removed. Mapping source fields and
external group names must be supplied as JSON strings rather than values that require scalar coercion. Atlaso trims
those names before checking effective case-insensitive uniqueness, matching the persisted mapping form.

Restored vSphere Key Provider, trusted-vCenter, and public-certificate identities must use canonical UUIDs so every
retained record remains addressable through the management UI and API after restore.

Certificate and signing-key lifecycle state is restored with the desired state. Atlaso reconstructs CA certificate
validity, serial numbers, and SHA-256 fingerprints from the archived public PEM, preserves CA issue, expiry, and
revocation timestamps, and preserves OIDC key activation, retirement, and publication-overlap timestamps so still-live
tokens retain their verification key. Disabled CA certificate rows receive the same bounded status, managed-path, and
supplied-material checks as enabled rows before any current state is removed. Every restored leaf PEM must contain
exactly one canonical public certificate, and every restored chain must contain only its canonical parsed certificates;
every restored CSR must likewise contain only its single canonical public request. None may include trailing or
private-key material. Disabled issued or revoked certificate rows are still verified against the restored CA root before
mutation, so an unrelated certificate serial cannot enter Atlaso's restored revocation state.
Every revoked row must retain both its certificate serial number and revocation timestamp even while the CA or row is
disabled, ensuring later CA enablement can publish a complete CRL.

ESXi Network Boot host MAC addresses are normalized and checked for duplicate identities before restore. Installer ISO
references are normalized beneath the managed ISO root before they are restored, so a valid relative archive reference
cannot become dependent on the appliance helper's working directory. VCF Offline Depot archives must retain Atlaso's
fixed `/mnt/atlaso-vcf-offline-depot` store path; another absolute path is rejected before current desired state is
removed. Archived ESXi custom-variable definitions retain the same 64-entry limit enforced by the management workflow.
ESX Storage resources receive canonical validation even when the optional settings row is absent; Atlaso uses the same
default disabled settings applied during later state reads.

Preflight also requires every canonical service-status row, limits DHCP scopes to access physical interfaces or enabled
VLANs with a matching address family, and reserves firewall source-group ID `any` for Atlaso's built-in unrestricted
group. These checks prevent a successful restore from creating missing service controls, publishing DHCP on management
networks, or widening a restricted firewall assignment.
All nonempty DHCP reservation addresses are parsed during preflight, including disabled rows; enabled reservations alone
receive the additional enabled-scope membership check.
An enabled Management HTTPS, NTS, KMS, or OIDC service must reference an enabled, issued managed certificate containing
both its public certificate and encrypted private key. Disabled certificate rows never satisfy service readiness.

Settings restore accepts only the current settings-archive schema v2 and requires its complete section inventory.
Older archive schemas are rejected before current desired state is removed; export a fresh archive from a current
Atlaso appliance before relying on it for recovery.

Verify identity, DNS, service configuration, and recent tasks after recovery. Restore changes Atlaso state; host
services are enforced only through their documented workflows.

Every archived physical-interface and VLAN row must include a non-empty role. Atlaso rejects a missing or null role
before clearing current desired state; only the retired `services` and `storage` values receive the bounded compatibility
mapping to `access`.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Backup and restore

![Atlaso Backup and Restore page in the clean-appliance responsive viewport.](../assets/screenshots/backup-restore-clean-responsive.webp)

*Figure: Backup and Restore in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
