---
title: KMS and KMIP
description: Configure Atlaso KMS and KMIP listener desired state and client trust.
audience:
  - operator
status: current
---

# KMS and KMIP

Open **KMS and KMIP** to configure the appliance-managed key service, listener binding, and client trust material.
Atlaso's appliance-native `atlaso-kmip` daemon implements only the bounded VCF 9.1 candidate contract. Treat the
service as experimental until the live interoperability and recovery gate in issue #172 passes.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso KMS and KMIP page in the clean-appliance desktop viewport.](../assets/screenshots/kms-clean-desktop.webp)

*Figure: KMS and KMIP in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure the service

1. Select only the interfaces that should accept KMIP traffic.
2. Enable the CA-managed server certificate and at least one client whose exact SHA-256 certificate fingerprint maps
   to the provider.
3. Resolve Validation-card errors and inspect the rendered service configuration.
4. Submit the KMS/KMIP unit through [Appliance Apply](../operate/appliance-apply.md).

The managed-key wizard keeps the key name, algorithm, length, and full-width multiline purpose description together in
its first identity step. Policy and lifecycle choices remain in their dedicated steps before review.

The apply unit installs `/etc/atlaso/kmip/server.json` and manages `atlaso-kmip.service` as an unprivileged account.
It gives systemd a root-managed mode-`0600`, machine-encrypted credential containing only `ATLASO_SECRETS_KEY`;
systemd decrypts it into the service's private runtime credential directory, and the daemon does not receive the web
session key or bootstrap administrator password from the shared appliance environment. On an upgraded appliance, the
first KMS apply reconciles the `atlaso-kmip` system account and its state directories before
starting the service. Wrapped operational keys and the protected KEK envelope remain under `/var/lib/atlaso/kmip`
when the service is disabled. Keep the listener restricted to intended lab networks. Never publish private keys,
plaintext key material, or client credentials in documentation, screenshots, task notes, or issues.

When the CA issues a replacement client certificate, Atlaso keeps both the prior and current exact fingerprints in
desired state. Install and verify the replacement in vCenter, then use **Retire previous certificate** from that client
row's context menu. The audited action removes earlier fingerprints from desired state; submit another global KMS
apply to enforce the retirement on the appliance.

A nonempty legacy PyKMIP database blocks in-place replacement. Keep the old appliance available while VMware rekeys
workloads into a newly configured provider; Atlaso does not migrate legacy key rows.
The appliance-native listener requires TLS 1.2 or newer.

## Verify

Confirm the apply task succeeded, `atlaso-kmip.service` is healthy, and an approved client can complete a bounded KMIP
operation over mutual TLS. A successful TLS handshake is insufficient unless the exact client fingerprint maps to the
provider. If validation or negotiation fails, restore the prior desired state and submit a new apply rather than
editing appliance files directly.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### KMS and KMIP

![Atlaso KMS and KMIP page in the clean-appliance responsive viewport.](../assets/screenshots/kms-clean-responsive.webp)

*Figure: KMS and KMIP in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
