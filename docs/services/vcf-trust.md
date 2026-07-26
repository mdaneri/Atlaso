---
title: VCF Certificate Trust
description: Establish and verify Atlaso certificate trust for VCF integrations.
audience:
  - operator
status: current
---

# VCF Certificate Trust

VCF Certificate Trust deploys the active Atlaso root CA to one VCF 9 Installer or SDDC Manager appliance. Open it from
the `VCF Certificate Trust` button on `/vcf-helper`. It is a remote maintenance task, not DNS desired state and not an
Appliance Apply unit.

For an existing appliance, create a current VM snapshot or equivalent rollback point before changing trust. The wizard
collects only:

- target VCF API endpoint, as `host`, `host:port`, or `https://host:port`;
- one-time VCF API administrator credentials;
- target HTTPS TLS fingerprint confirmation;
- snapshot acknowledgment.

Atlaso never persists the API password. It stores only sanitized target, port, role/version, confirmed TLS fingerprint,
deployed CA fingerprint, and task result metadata.

The task authenticates through `POST /v1/tokens`, detects the appliance using `GET /v1/system/appliance-info`, checks
`GET /v1/sddc-manager/trusted-certificates`, and imports missing outbound trust through
`POST /v1/sddc-manager/trusted-certificates`. An identical certificate is a successful no-op.

VCF Installer and SDDC Manager both use the same API-only flow. Atlaso does not SSH to the appliance and does not
restart SDDC Manager services. API verification means the certificate is present in the VCF trusted-certificate API
after import. VCF releases before 9.x and certificate deletion are outside this release.

Routes:

- `GET /vcf-trust` redirects compatibility links to `/vcf-helper?vcf_trust=1`, which opens the modal.
- `POST /vcf-helper/trust-root-ca/inspect-target` confirms target HTTPS TLS, validates API credentials, and returns
  role/version.
- `POST /vcf-trust/root-ca` queues the task and redirects to `/tasks?job_id=<id>`.
- `POST /vcf-helper/trust-root-ca` remains a compatibility alias for cached clients.
