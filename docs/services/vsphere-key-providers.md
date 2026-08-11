---
title: vSphere Key Providers
description: Manage isolated vSphere Key Provider namespaces and exact public-certificate trust for vCenter.
audience:
  - operator
status: current
---

# vSphere Key Providers

Open **vSphere Key Providers** at `/ui/management/vsphere-key-providers` to manage Atlaso's appliance-native KMIP
endpoint. The
listener and server identity are shared appliance-wide, while every provider UUID is an isolated operational key
namespace.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso vSphere Key Providers page in the clean-appliance desktop viewport.](../assets/screenshots/vsphere-key-providers-clean-desktop.webp)

*Figure: vSphere Key Providers in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

Atlaso implements a bounded candidate profile for VCF 9.1. Keep it experimental until the observed interoperability
and recovery work in issue #172 is complete. Do not describe the current candidate as observed or supported VCF 9.1
behavior.

![vSphere Key Providers in the clean-appliance desktop viewport.](../assets/screenshots/vsphere-key-providers-clean-desktop.webp)

*Figure: the provider, trusted-vCenter, certificate, and lifecycle tools with listener settings in the right rail.*

## Add a provider and trusted vCenter

1. On **Providers**, add a unique name, description, and saved enabled state. Atlaso assigns an immutable provider UUID.
2. On **Trusted vCenters**, select the provider and enter the vCenter name and optional operational hostname.
3. Paste exactly one current public X.509 client certificate. Atlaso rejects private-key blocks, malformed or expired
   certificates, CA certificates, and certificates that cannot perform client authentication.
4. Review the exact provider assignment and save the record.
5. Review **Pending Appliance Changes**, then run global **Appliance Apply** for the internal `kms` unit.
6. Download the public Atlaso server chain from the listener rail and configure the shared endpoint in vCenter.

Certificate fingerprints are normalized SHA-256 values and are unique appliance-wide. The same fingerprint cannot be
assigned to another trusted vCenter or provider. Atlaso stores canonical public PEM and parsed public metadata only; it
does not generate, accept, export, or reveal a vCenter client private key.

Listener settings accept only currently available addressed access or VLAN interfaces. Atlaso derives the saved IPv4
and IPv6 listener addresses from those selected interfaces; API callers cannot bind the service to an unrelated address
by supplying a different `listen_addresses` value.

## Rotate or retire public trust

Use **Add public certificate** on a trusted-vCenter row or **Add replacement certificate** on a certificate row. Apply
the overlapping trust bundle globally, move vCenter to the new certificate, and then use **Retire certificate**. An
enabled trusted vCenter cannot lose its last usable fingerprint. Vault-assisted rotation belongs to issue #171.

Settings backups preserve public certificate history, including certificates that expire after they were accepted.
Restore revalidates each PEM body and exact fingerprint while retaining its expired status; an expired record never
becomes usable trust merely because it was restored.

## Health and lifecycle counts

**Health & lifecycle** reports saved provider state, apply readiness, shared-daemon state, and authenticated redacted
counts for **Pre-Active**, **Active**, and total operational keys. Counts come from the protected wrapped-key store
through the fixed `atlaso-helper kms status` operation. If authentication, integrity verification, or store access is
unavailable, Atlaso reports **Not reported** and null counts; it never substitutes zero.

Operational keys are daemon-owned. No browser or REST operation creates, edits, exports, deletes, or lists operational
key identifiers, and KMIP Destroy remains outside the bounded protocol contract.

## Removal safeguards

A provider can be deleted only when all of these conditions hold:

- it is disabled;
- every trusted vCenter has been detached;
- the disabled and detached desired state has completed global Appliance Apply; and
- authenticated runtime evidence reports exactly zero operational keys for its UUID.

Atlaso fails closed when empty-store evidence is unavailable. A trusted vCenter can be deleted only after it is disabled
and every certificate record is retired.

## Apply and trust-bundle boundary

Saving page or API changes updates database desired state only. Global Appliance Apply renders the enabled providers
with exact enabled fingerprints, configures the daemon on every derived selected listener address, stages
`/var/lib/atlaso/apply/kms/server.json` and
`/var/lib/atlaso/apply/kms/client-trust.pem`, and invokes the constrained helper. The helper accepts only those fixed
paths, rejects symbolic links and private-key material, and installs the bundle as
`/etc/atlaso/kmip/client-trust.pem` with root and `atlaso-kmip` ownership.

The TLS trust bundle contains the internal CA public root plus imported public leaf certificates. The daemon requires
TLS 1.2 or newer, permits X.509 partial-chain verification for explicitly imported leaf trust, and still authorizes the
connection only when the peer's exact fingerprint maps to one provider UUID.

## API access

Reads require `read:kms`; mutations require `write:kms`. The versioned resources are rooted at
`/api/v1/vsphere-key-providers` and include listener settings, providers, trusted vCenters, certificates, readiness,
health, lifecycle counts, and the public server chain. See the generated OpenAPI document at `/openapi.json` for request,
response, authorization, validation, and compatibility details.

![vSphere Key Providers in the clean-appliance narrow viewport.](../assets/screenshots/vsphere-key-providers-clean-responsive.webp)

*Figure: the wide service frame and DNS-style settings rail in the verified narrow layout.*

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### vSphere Key Providers

![Atlaso vSphere Key Providers page in the clean-appliance responsive viewport.](../assets/screenshots/vsphere-key-providers-clean-responsive.webp)

*Figure: vSphere Key Providers in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
