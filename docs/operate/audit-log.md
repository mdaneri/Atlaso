---
title: Audit log
description: Review security-relevant and operator activity recorded by Atlaso.
audience:
  - operator
  - maintainer
status: current
---

# Audit log

Open **Audit Log** to review who changed desired state or started an operational task. The page is read-only and is
intended for investigation and change review.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Audit Events page in the clean-appliance desktop viewport.](../assets/screenshots/audit-log-clean-desktop.webp)

*Figure: Audit Events in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Review an event

1. Filter the grid by actor, action, resource, or time.
2. Open the relevant event and compare its timestamp with related entries on **Tasks**.
3. Confirm that the actor and affected resource match the intended change.

Audit entries describe the action and sanitized result. They must not expose passwords, private keys, authenticated
URLs, or other secret-bearing values.

IP addresses, MAC addresses, hostnames, and account names are not sensitive by themselves in Atlaso and may remain in
an audit event when they identify the affected resource. Passwords, tokens, authenticated URLs, session material,
private keys, password hashes, credential verifiers, and other secret-bearing data remain sensitive. Content-integrity
hashes of non-secret material and one-way change-detection hashes of encrypted-at-rest ciphertext do not. An identifier
must also be treated as sensitive when it is embedded in or paired with authentication or cryptographic material.

## Verify and escalate

For an appliance apply or maintenance action, correlate the event with the task identifier and terminal task state.
Use [Operational logs](logs.md) for runtime diagnostics. Preserve the relevant timestamps and identifiers when
escalating; do not copy credentials or raw secrets into an issue. The data classification does not make authenticated
audit history public or override site handling policy.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Audit events

![Atlaso Audit Events page in the clean-appliance responsive viewport.](../assets/screenshots/audit-log-clean-responsive.webp)

*Figure: Audit Events in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
