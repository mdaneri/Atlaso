---
title: vSphere Key Provider security architecture
description: Security boundaries, key custody, recovery, and failure behavior for the Atlaso vSphere Key Provider.
audience:
  - contributor
  - maintainer
status: roadmap
---

# vSphere Key Provider security architecture

This design record defines the security contract for the appliance-native vSphere Key Provider. It applies to the
implementation tracked by issues [#169](https://github.com/mdaneri/Atlaso/issues/169) through
[#172](https://github.com/mdaneri/Atlaso/issues/172). Until the VCF 9.1 promotion gate is complete, current PyKMIP
behavior remains lab-only and the new provider must be described as experimental.

## Architecture decision

Atlaso will implement a small Python service with an internal, bounded KMIP 1.4 TTLV codec and operation dispatcher.
It will not embed the PyKMIP server, request engine, policy engine, storage model, or compatibility wrapper.

Python keeps the service inside Atlaso's existing build, packaging, logging, testing, and Photon lifecycle. The
security boundary comes from the narrow checked-in protocol allowlist rather than the language. The adapter must:

- decode only the required TTLV types and structures;
- reject unknown, duplicate, oversized, deeply nested, or malformed input before dispatch;
- enforce a maximum request size, batch size, nesting depth, connection count, and idle timeout;
- bind a verified client certificate fingerprint to one or more explicitly selected providers;
- authorize every batch item independently inside the provider namespace;
- never include raw TTLV, key bytes, wrapped blobs, credentials, or private material in logs and errors; and
- use deterministic protocol errors without falling back to a broader KMIP implementation.

The service runs as the unprivileged `atlaso-kmip` identity. Only `/appliance-apply` may ask the constrained
`atlaso-helper` to install configuration, certificates, systemd units, ownership, and firewall state.

## Assets and trust boundaries

| Asset | Boundary and protection |
| --- | --- |
| Plaintext data-encryption key | Exists only in service memory while creating or returning one key; zeroed on a best-effort basis after use |
| Wrapped key blob | Stored under `/var/lib/atlaso/kmip` with provider ID and authenticated metadata |
| Runtime key-encryption key | Wrapped under `ATLASO_SECRETS_KEY`; never stored or logged in plaintext |
| Provider server identity | CA-managed certificate and private key readable only by the KMIP service |
| vCenter client identity | Exact certificate fingerprint mapped to explicit provider IDs |
| Recovery bundle | Encrypted with a user-supplied passphrase and produced only through an authenticated, audited workflow |
| Vault-assisted credential | Read only for the selected vCenter operation; never copied into provider records, tasks, or traces |
| Interop evidence | Metadata-only JSONL validated against the bounded protocol contract |

The FastAPI control plane owns desired state and authenticated administration. The KMIP daemon owns protocol handling
and wrapped operational keys. The root helper owns host installation. None may silently inherit another component's
authority.

## Provider and identity isolation

Every provider receives an immutable UUID and an independent key namespace. Every key receives a stable random UUID
whose lookup is always qualified by provider ID. Database constraints and service-layer queries both enforce the
qualification.

A trusted client record contains a normalized SHA-256 certificate fingerprint and explicit provider membership.
Multiple vCenters may be trusted by one provider, but a successful TLS handshake alone grants no key access. Missing,
disabled, expired, ambiguous, or unmapped identities fail closed. LDAP organization membership is irrelevant.

Certificate replacement uses an overlap window: the administrator adds and verifies the new fingerprint before
retiring the old one. The service must not automatically trust a renewed certificate merely because its subject or CA
matches.

## Key creation and storage

The service generates AES-256 key material with the operating system CSPRNG. It wraps each key with AES-256-GCM under
the runtime key-encryption key (KEK). The authenticated additional data binds at least:

- storage schema version;
- provider UUID;
- key UUID;
- algorithm and length;
- creation time; and
- lifecycle state.

Replacing a provider ID, moving a wrapped blob into another namespace, editing metadata, or rolling a row backward must
make decryption fail. Files and database pages use service-only permissions. Successful startup requires both the
operational store and the KEK protected by the current `ATLASO_SECRETS_KEY`.

Atlaso never exports plaintext keys through its UI or management API. KMIP `Get` is the sole planned plaintext release
path and is restricted to an authenticated client mapped to the same provider.

## Recovery and disaster recovery

The normal Atlaso settings archive excludes operational keys, the runtime KEK, private certificates, and Vault
passwords. A separate recovery workflow produces a passphrase-encrypted bundle containing the minimum material needed
to restore provider identity, wrapped keys, the runtime KEK, and integrity metadata.

Recovery requirements:

1. The passphrase is accepted through a no-log input and is never stored in Atlaso.
2. Key derivation uses a memory-hard, salted construction with parameters recorded in the bundle header.
3. Bundle encryption is authenticated, versioned, and binds a manifest digest.
4. Export and restore create audit events without filenames, passphrases, key IDs, or secret contents.
5. Restore is allowed only into an empty new store or an explicitly verified matching store.
6. A dry-run verifies format, authentication, version compatibility, provider IDs, row counts, and store emptiness.
7. Restore is atomic; any validation or write failure leaves the previous store and service state intact.
8. Success is not claimed until an existing encrypted workload retrieves its original key after restart.

Losing both the running store and a valid recovery bundle is unrecoverable. Losing only
`ATLASO_SECRETS_KEY` is also unrecoverable unless the recovery bundle contains a separately passphrase-protected KEK.

## Legacy upgrade boundary

There is no PyKMIP key migration. During upgrade:

- an empty or absent legacy `/var/lib/atlaso/kms/pykmip.db` may be replaced;
- a nonempty legacy store blocks in-place replacement with a clear, secret-free diagnostic;
- the old appliance must remain available while VMware rekeys workloads into a newly configured provider; and
- no code may read and rewrite legacy plaintext key rows into the new store.

This boundary avoids silently changing key identifiers, ownership, lifecycle semantics, or protection guarantees.

## Abuse cases and mitigations

| Abuse case | Required mitigation |
| --- | --- |
| Untrusted client requests another provider's key | Exact fingerprint mapping plus provider-qualified lookup |
| Captured trace or task leaks a key | Metadata-only structured events; forbidden-field tests and redaction |
| Malformed TTLV consumes memory or CPU | Pre-dispatch size, depth, batch, connection, and timeout limits |
| Root helper is used as a general service control | Fixed paths, exact verbs, ownership checks, and staged desired state |
| Wrapped blob is copied or rolled back | AES-GCM authenticated metadata and store integrity checks |
| Vault credential escapes vCenter automation | One-operation decrypt, no subprocess arguments, no logging, audited presence only |
| Certificate rotation creates an outage | Add-verify-retire overlap with health proof before removal |
| Recovery overwrites a healthy store | Empty/matching-store precondition, dry-run, atomic install, explicit confirmation |
| Legacy upgrade loses keys | Nonempty PyKMIP store hard block and documented VMware rekey procedure |
| Broad KMIP behavior is accidentally exposed | Checked-in allowlist, fail-closed dispatch, and live evidence promotion gate |

## Security review gates

The implementation cannot be called supported until tests and live evidence cover:

- cross-provider key and identity isolation;
- malformed TTLV, oversized frames, deep nesting, batch limits, and connection exhaustion;
- storage tamper, wrong `ATLASO_SECRETS_KEY`, wrong recovery passphrase, and rollback;
- service and appliance restart without identifier drift;
- client certificate add, replacement overlap, disable, expiration, and ambiguity;
- helper path, owner, mode, symlink, service, and firewall constraints;
- redaction across service logs, task results, audits, API responses, UI, recovery, and trace output; and
- VCF 9.1 create, retrieve, encrypted workload, restart, and restore acceptance.

Security-sensitive code requires the normal Atlaso review and CI gates. Any discovery of exposed key material or a
cross-provider authorization failure is critical and blocks release.
