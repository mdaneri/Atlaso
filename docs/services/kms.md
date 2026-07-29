---
title: KMS and KMIP
description: Configure Atlaso KMS and KMIP listener desired state and client trust.
audience:
  - operator
status: current
---

# KMS and KMIP

Open **KMS and KMIP** to configure the appliance-managed key service, listener binding, and client trust material.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso KMS and KMIP page in the clean-appliance desktop viewport.](../assets/screenshots/kms-clean-desktop.webp)

*Figure: KMS and KMIP in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure the service

1. Select only the interfaces that should accept KMIP traffic.
2. Review certificate and client identity requirements.
3. Resolve Validation-card errors and inspect the rendered service configuration.
4. Submit the KMS/KMIP unit through [Appliance Apply](../operate/appliance-apply.md).

Keep the listener restricted to intended lab networks. Never publish private keys or client credentials in
documentation, screenshots, task notes, or issues. The compatibility listener requires TLS 1.2 or newer.

## Verify

Confirm the apply task succeeded, the service is healthy, and an approved client can establish the expected trusted
connection. If validation or client negotiation fails, restore the prior desired state and submit a new apply rather
than editing appliance files directly.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### KMS and KMIP

![Atlaso KMS and KMIP page in the clean-appliance responsive viewport.](../assets/screenshots/kms-clean-responsive.webp)

*Figure: KMS and KMIP in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
