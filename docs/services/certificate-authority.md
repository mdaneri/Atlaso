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
3. Resolve validation errors and inspect the rendered certificate preview.
4. Submit the Certificate Authority unit through [Appliance Apply](../operate/appliance-apply.md).

Atlaso encrypts CA root and leaf private keys with the appliance secrets key. Preserve that key with recovery material,
and never expose private keys in documentation, screenshots, tasks, or logs.

## Review requests

Use **Certificate Requests** to identify the requester, requested names, intended use, and current status before
approving or rejecting enrollment. Confirm that every requested name belongs to the intended lab boundary.

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

![Atlaso Certificate requests page in the clean-appliance desktop viewport.](../assets/screenshots/ca-requests-clean-desktop.webp)

*Figure: Certificate requests in the verified clean-appliance desktop state.*

![Atlaso Certificate requests page in the clean-appliance responsive viewport.](../assets/screenshots/ca-requests-clean-responsive.webp)

*Figure: Certificate requests in the verified clean-appliance responsive state.*

### Public certificate portal

![Atlaso Public certificate portal page in the clean-appliance desktop viewport.](../assets/screenshots/ca-public-clean-desktop.webp)

*Figure: Public certificate portal in the verified clean-appliance desktop state.*

![Atlaso Public certificate portal page in the clean-appliance responsive viewport.](../assets/screenshots/ca-public-clean-responsive.webp)

*Figure: Public certificate portal in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
