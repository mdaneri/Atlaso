---
title: Certificate Authority
description: Operate the Atlaso certificate authority, certificate requests, and public certificate portal.
audience:
  - operator
status: current
---

# Certificate Authority

Use **Certificate Authority** to manage appliance CA desired state, **Certificate Requests** to review enrollment work,
and the public certificate portal to provide approved unauthenticated CA and request workflows.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Certificate Authority page in the clean-appliance desktop viewport.](../assets/screenshots/certificate-authority-clean-desktop.webp)

*Figure: Certificate Authority in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Manage the authority

1. Confirm the appliance FQDN and management HTTPS settings are correct.
2. Review root and leaf validity, subject, and key settings.
3. Leave **Listen interfaces** empty when the CA is needed only for appliance trust and managed service certificates.
   Select one or more interfaces only when the public CA portal should be published on those networks.
4. Resolve validation errors and inspect the rendered certificate preview.
5. Submit the Certificate Authority unit through [Appliance Apply](../operate/appliance-apply.md).

Atlaso encrypts CA root and leaf private keys with the appliance secrets key. Preserve that key with recovery material,
and never expose private keys in documentation, screenshots, tasks, or logs.

An enabled CA with no listen interface still writes its root bundle and managed service certificates through global
appliance apply. It does not add the CA portal to access-interface DNS, firewall, or public-service configuration.

## Review requests

Use **Certificate Requests** to identify the requester, requested names, intended use, and current status before
approving or rejecting enrollment. Confirm that every requested name belongs to the intended lab boundary.
The management and public request lists use the same read-only collection pattern. Sort or inspect the rows normally;
when an issued certificate can be revoked, open its row menu and select **Revoke certificate**. The shared confirmation
states that revocation changes desired state and reaches appliance files only through the next global CA apply. The
server-rendered list and revoke forms remain available when browser scripting is unavailable.
The request wizard presents the common name, profile, multiline description, DNS SANs, and IP SANs on separate rows so
long names, operator notes, and multi-value SAN lists remain readable before review. Descriptions stay with request
identity, while enablement has a
dedicated step for both certificate profiles and requests. **CSR Intake** uses the same guided pattern to separate
metadata, SANs, PEM content, and final review.

The public portal exposes only the approved public certificate surface. It must not disclose operator-only state or
offer administrative actions.

## Verify and recover

After apply, verify the presented management certificate and download the expected public root certificate. Keep a VM
snapshot or equivalent rollback point before replacing active trust. Use [VCF Certificate Trust](vcf-trust.md) for the
separate task that installs the active Atlaso root into a supported VCF appliance.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Certificate Authority

![Atlaso Certificate Authority page in the clean-appliance responsive viewport.](../assets/screenshots/certificate-authority-clean-responsive.webp)

*Figure: Certificate Authority in the verified clean-appliance responsive state.*

### Certificate requests

![Atlaso public Certificate Request Portal showing issued certificates in a read-only grid.](../assets/screenshots/ca-requests-clean-desktop.webp)

*Figure: Public certificate requests rendered through the shared read-only grid in the desktop viewport.*

![Atlaso public Certificate Request Portal showing its read-only grid in the narrow viewport.](../assets/screenshots/ca-requests-clean-responsive.webp)

*Figure: Public certificate requests remain contained in the narrow viewport.*

### Certificate requests (management)

![Atlaso management Certificate Requests page showing issued certificates in a read-only grid.](../assets/screenshots/ca-management-requests-clean-desktop.webp)

*Figure: Management certificate requests rendered through the shared read-only grid in the desktop viewport.*

![Atlaso management Certificate Requests page showing its read-only grid in the narrow viewport.](../assets/screenshots/ca-management-requests-clean-responsive.webp)

*Figure: Management certificate requests remain contained in the narrow viewport.*

### Public certificate portal

![Atlaso Public certificate portal page in the clean-appliance desktop viewport.](../assets/screenshots/ca-public-clean-desktop.webp)

*Figure: Public certificate portal in the verified clean-appliance desktop state.*

![Atlaso Public certificate portal page in the clean-appliance responsive viewport.](../assets/screenshots/ca-public-clean-responsive.webp)

*Figure: Public certificate portal in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
