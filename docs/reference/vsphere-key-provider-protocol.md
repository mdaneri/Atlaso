---
title: vSphere Key Provider protocol contract
description: Bounded VCF 9.1 KMIP contract, evidence format, and support-promotion gate.
audience:
  - contributor
  - maintainer
status: roadmap
---

# vSphere Key Provider protocol contract

Atlaso provides an appliance-native service for one narrow use case: a
**vSphere Key Provider** consumed by VMware Cloud Foundation (VCF) 9.1. This page defines the candidate protocol boundary
for implementation. The bounded daemon exists, but this contract does not claim that it is interoperable or supported
yet.

The machine-readable source is
[`atlaso/app/kmip/contracts/vcf_9_1.json`](../../atlaso/app/kmip/contracts/vcf_9_1.json). Issue
[#172](https://github.com/mdaneri/Atlaso/issues/172) owns the live acceptance run that may promote its status from
`candidate-unverified` to `observed`.

## Compatibility statement

- The only initial product target is VCF 9.1.
- The service accepts the bounded KMIP 1.1 and 1.4 TTLV profiles over mutually authenticated TLS on TCP 5696.
  vCenter 9.1.1 starts discovery with a KMIP 1.1 request; negotiation must answer that request before key operations.
- It manages AES-256 symmetric keys in Raw format.
- It is not a general-purpose KMIP implementation, production HSM, or compatibility claim for other vSphere or VCF
  releases.
- A logical vSphere Key Provider is an isolated key namespace. It may trust multiple vCenter client certificates.
- Atlaso organizations and LDAP identities do not select or cross provider namespaces.

The candidate operation list is intentionally allowlisted. The daemon must return a protocol error for every operation,
object, algorithm, length, format, or attribute outside the checked-in contract. Expanding the list requires recorded
VCF 9.1 evidence, tests, documentation, and security review.

## Candidate allowlist

The candidate contract allows the operations below for implementation and capture. This list is based on the OASIS
KMIP baseline and symmetric-key lifecycle profiles plus the vSphere `CryptoManagerKmip` integration surface.
Issue [#957](https://github.com/mdaneri/Atlaso/issues/957) records KMIP 1.1 discovery and Create requests with a
Unique Batch Item ID observed from vCenter 9.1.1. The daemon validates this Byte String correlation field and echoes
it on success and failure responses. Multi-item requests require distinct identifiers. This bounded observation does
not complete the VCF 9.1 acceptance or recovery matrix.

The observed Create profile also includes five VMware informational attributes: `x-Component`, `x-Identifier`,
`x-Product`, `x-Product_Version`, and `x-Vendor`. Only those custom names are accepted, each once as a Text String of
at most 512 UTF-8 bytes. They are authenticated with the wrapped key, survive activation and restart, and are available
through provider-scoped Get Attributes and Get Attribute List. Custom values are never included in logs or traces.
Existing keys without these attributes retain their original authenticated format and are not rewritten on startup.

vCenter 9.1.1 retrieves a newly created key before sending Activate. An authenticated client may therefore Get its
provider's Pre-Active or Active keys. Get does not activate a key or authorize server-side cryptographic use; explicit
Activate retains its separate lifecycle transition. Other lifecycle states remain outside this bounded contract.

| Area | Candidate boundary |
| --- | --- |
| Discovery | Discover Versions, Query |
| Key creation | Create, Activate |
| Key lookup | Get, Get Attribute List, Get Attributes, Locate |
| Object | Symmetric Key only |
| Algorithm | AES-256 only |
| Format | Raw only |
| Transport | KMIP 1.1 and 1.4 TTLV, TLS 1.2 or newer, mutual TLS, TCP 5696 |

The contract explicitly excludes cryptographic execution such as Encrypt, Decrypt, Sign, and MAC; asymmetric or secret
data objects; key-pair creation; Register; Re-Key; Revoke; Archive; Recover; and every destructive operation. A future
change may add an operation only after it is shown to be required by the target acceptance scenario.

## Evidence capture

Interop evidence is newline-delimited JSON containing metadata only. Each event has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Trace schema version, currently `1` |
| `timestamp` | UTC event time |
| `connection_id` | Ephemeral correlation identifier |
| `client_cert_sha256` | SHA-256 fingerprint, never certificate private material |
| `provider_id` | Logical provider identifier |
| `protocol_version` | Negotiated KMIP version |
| `operation` | Decoded operation name |
| `object_type` | Decoded object type or `null` |
| `algorithm` | Contract algorithm such as `AES`, or `null` when not applicable |
| `key_length` | Contract key length such as `256`, or `null` when not applicable |
| `key_format_type` | Contract key format such as `Raw`, or `null` when not applicable |
| `attribute_names` | Attribute names only, never values |
| `result_status` | KMIP result status |
| `result_reason` | Allowlisted KMIP reason name or `null`, never free-form diagnostics |
| `request_digest` | SHA-256 digest of the canonical request, never the request bytes |

Raw TTLV, request or response bodies, key bytes, credentials, secrets, private keys, and passwords are forbidden. The
validator rejects secret-bearing field names, unexpected fields, non-contract operations, algorithms, lengths, formats,
attributes and reasons, and invalid digests. Every Create event must record all three non-secret key-shape values:

```powershell
python scripts/kmip/validate_interop_trace.py <redacted-trace.jsonl> --output <summary.json>
```

The summary is safe to attach to an issue only after a human confirms that the source trace followed the same
metadata-only contract. Neither file should include authenticated URLs or client certificate contents.

## Promotion to observed

The status may become `observed` only when all of the following are recorded for the exact VCF 9.1 target:

1. vCenter registers the provider and completes mutual trust.
2. Provider health is green from vCenter and every participating ESXi host.
3. VCF creates an AES-256 key and subsequently retrieves it by stable unique identifier.
4. A real encrypted workload survives service restart, appliance restart, and a tested restore from the recovery
   bundle.
5. The redacted trace passes the validator without adding permissive fallback behavior.
6. All observed operations and attributes are represented by focused protocol tests.
7. Security review confirms namespace isolation, fail-closed identity mapping, and absence of secret material from
   logs, tasks, audits, screenshots, and evidence.

If a VCF 9.1 client uses an operation outside the candidate list, acceptance fails. Contributors must first determine
whether the operation is required, document its lifecycle and authorization semantics, and review the threat model
before changing the allowlist.

## Authoritative sources

- [OASIS KMIP Specification Version 1.1](https://docs.oasis-open.org/kmip/spec/v1.1/os/kmip-spec-v1.1-os.html)
- [OASIS KMIP Specification Version 1.4](https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html)
- [OASIS KMIP Profiles Version 1.4](https://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html)
- [Broadcom vSphere `CryptoManagerKmip` API](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.encryption.CryptoManagerKmip.html)

The Broadcom API documents vCenter trust and KMS registration controls. It does not, by itself, prove the on-wire
operation set used by the VCF 9.1 acceptance scenario; the observed trace remains mandatory.
