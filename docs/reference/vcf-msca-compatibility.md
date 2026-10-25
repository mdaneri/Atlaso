---
title: VCF Microsoft CA compatibility investigation
description: Phase 0 evidence, unresolved protocol requirements, and an isolated-lab procedure for VCF-native renewal.
audience:
  - contributor
  - maintainer
status: roadmap
---

# VCF Microsoft CA compatibility investigation

This is the research-only work package for [#1042](https://github.com/mdaneri/Atlaso/issues/1042), tracked in
[#1050](https://github.com/mdaneri/Atlaso/issues/1050). Research date: **2026-10-25**. No appliances were contacted,
credentials obtained, certificates issued, or enrollment/renewal tests performed for this report.

**Recommendation: adapter implementation gate not satisfied; lab validation required.**
The official evidence makes a narrow AD CS Web Enrollment investigation worthwhile, but does not establish an
implementable VCF wire contract or Atlaso interoperability. Missing evidence is neither a technical NO-GO nor a
reason to start the fallback renewal controller. Keep #1042 open.

Atlaso currently provides [on-demand appliance certificate replacement](../services/appliance-certificates.md).
[VCF Certificate Trust](../services/vcf-trust.md) distributes public trust. Neither establishes VCF-native enrollment
or automatic renewal. An experimental Microsoft CA compatibility adapter would remain unsupported unless Broadcom
independently confirms support for that configuration; technical success alone cannot establish vendor support.
The VCF-integrated OpenSSL CA is not a generic external OpenSSL enrollment protocol and is not an emulation target.

## Evidence rules and sources

Use these evidence classes in every matrix and future lab result:

- **Documented:** an official source states the requirement for its named product/version.
- **Repository:** current Atlaso code implements the behavior; this is not external interoperability evidence.
- **Hypothesis:** a candidate exchange or relationship to investigate, not an implementation requirement.
- **Untested:** no observation from an identified lab build. An inaccessible document remains unavailable evidence.

All sources below were retrieved on **2026-10-25**. The Broadcom KB pages are mutable and several expose no update
date; record their article IDs and environment statements rather than inventing revision dates. Recheck sources when
the lab build is selected. Microsoft browser enrollment guidance does not describe VCF's machine client.

| ID | Official source and source version | Evidence used here |
| --- | --- | --- |
| B1 | [Broadcom KB 452531: MSCA configuration](https://knowledge.broadcom.com/external/article/452531/error-failed-to-update-certificate-autho.html), VCF Operations 9.1.0.x | Basic authentication, template access, IIS client-certificate setting, patch recommendation. |
| B2 | [Broadcom KB 441892: intermediate MSCA failures](https://knowledge.broadcom.com/external/article/441892/vcf-91-components-do-not-work-properly-a.html), VCF 9.1 GA and Operations 9.1.0.0200 fix | Early-build chain/replacement defects. |
| B3 | [Broadcom KB 453252: certificate generation failure](https://knowledge.broadcom.com/external/article/453252/automated-certificate-generation-fails-f.html), VCF 9.x; introduction names 9.1 | Web Enrollment ASP execution, PKCS#7 conversion failure and a chain-retrieval diagnostic. |
| B4 | [Broadcom KB 455643: CA classification](https://knowledge.broadcom.com/external/article/455643/vmca-signed-certificates-incorrectly-lab.html), Operations 9.1; 9.1.1 correction | CA collection/display classification changes. |
| B5 | [Broadcom KB 454242: MSCA endpoint SAN validation](https://knowledge.broadcom.com/external/article/454242/sddc-manager-microsoft-ca-connection-fai.html), SDDC Manager 9.1.1 | HTTPS endpoint certificate must contain the endpoint FQDN in SAN. |
| M1 | [Microsoft CA Web Enrollment](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-authority-web-enrollment), Windows Server 2016/2019/2022/2025 | HTTPS, PKCS#10 browser intake, target-CA selection; distinction from Certificate Enrollment Web Service. |
| M2 | [Microsoft Web Enrollment guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831649%28v%3Dws.11%29), Windows Server 2012/2012 R2 | Historical browser template selection, PKCS#10/PKCS#7 submission, pending retrieval and chain download. |
| M3 | [Microsoft IIS logging](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis), Windows Server 2012 tutorial | Configurable W3C logging fields; verify availability on the chosen Windows build. |
| A1 | [Fleet Certificate Management API](https://developer.broadcom.com/xapis/vcf-operations-api/latest/fleet-certificate-management/), unpinned `latest` | Candidate CA configuration, certificate inventory, CSR and replacement operations. |
| A2 | [Get VCF Certificate](https://developer.broadcom.com/xapis/vcf-operations-api/latest/suite-api/api/fleet-management/certificate-management/certificates/certificateId/get/), unpinned `latest` | Candidate certificate classification and renewal observation fields. |
| A3 | [Configure CA](https://developer.broadcom.com/xapis/vcf-operations-api/latest/suite-api/api/fleet-management/certificate-management/certificate-authorities/put/), unpinned `latest` | Candidate Microsoft CA configuration shape. |
| A4 | [Get CA](https://developer.broadcom.com/xapis/vcf-operations-api/latest/suite-api/api/fleet-management/certificate-management/certificate-authorities/get/), unpinned `latest` | Response is potentially secret-bearing; never dump it to evidence. |

The release-note and CA-configuration TechDocs links reached from B1/B2 could not be retrieved during this research.
Version-specific API entry pages for `9.1` and `9.1.1` also could not be retrieved. These access failures establish
neither that documentation is absent nor that an API is unsupported. Obtain accessible version-matched documentation
or the appliance's supported API specification before making requests. No API availability is assigned from `latest`.

## Version and protocol matrix

No row below has lab-confirmed Atlaso compatibility. Keep the VCF Operations, SDDC Manager, fleet-management component,
and Microsoft CA plugin versions separate; a product-family label is insufficient.

| Product/build named by source | Documented evidence | Remaining gate |
| --- | --- | --- |
| Operations 9.1.0.0000 / 9.1.0.0100 | B2 identifies failures with an intermediate Microsoft CA and describes manual external signing/import as a workaround. | Do not use manual replacement as native enrollment/renewal evidence. |
| Operations 9.1.0.0200 | B2 identifies the intermediate-chain issue as fixed here. | A fix for that defect does not prove the complete MSCA protocol or renewal behavior. |
| Operations 9.1.0.0400 or higher within B1's 9.1.0.x context | B1 recommends this patch level for MSCA integration/truststore improvements. | Confirm installed plugin behavior; do not extrapolate the recommendation into a universal compatibility guarantee. |
| Operations 9.1 versus 9.1.1 | B4 describes incorrectly collected/displayed CA types in 9.1 and a 9.1.1 classification correction. | Classification can change independently of leaf issuance; inspect actual fields and renewal jobs on each build. |
| SDDC Manager 9.1.1 | B5 requires a matching SAN on the AD CS HTTPS endpoint certificate. | This is SDDC Manager evidence, not proof of identical Operations plugin behavior. |
| Operations 9.1.1, exact build/plugin unknown | No complete version-pinned enrollment/renewal wire contract established by this research. | Obtain exact build, API contract, real-MSCA baseline and second-renewal evidence. |

| Area | Documented evidence | Hypothesis or unresolved requirement |
| --- | --- | --- |
| Authentication | B1 requires Basic authentication at `/certsrv`; its IIS guidance sets client certificates to Ignore. | Challenge/retry sequence, realm handling, redirects, cookies, username syntax and whether other builds differ are unobserved. Basic credentials require verified HTTPS. |
| Template | B1 requires Read and Enroll permissions and refers to the friendly name VMware. M2 describes browser template selection. | Exact template identifier sent by VCF, attribute encoding, allowed profile mapping and behavior for missing/wrong templates. |
| CA selection | M1 describes configuring Web Enrollment's target CA. A3 shows a Microsoft CA specification. | Whether VCF discovers CA names, uses server URL alone, or depends on AD CS-specific CA identity. |
| CSR | M1 describes PKCS#10 intake; M2 also describes PKCS#7 renewal submission in the older browser workflow. | VCF request method, form keys, PEM/base64/DER handling, escaping, CSR versus renewal format and key reuse. |
| Retrieval | B3 gives `/certsrv/certnew.p7b?ReqID=CACert&Enc=b64` as a diagnostic and describes PKCS#7-to-PEM failure. | This does not prove VCF's actual method/sequence, issued-leaf URL, request-ID extraction, MIME type, chain order or encoding. |
| Pending/errors | M2 documents browser pending/issued pages; B3 documents an ASP/chain-processing failure. | VCF polling, pending support, denial parsing, timeouts and retry/idempotency behavior; HTTP 200 may still contain an enrollment error. |

`/certsrv/`, `/certsrv/certfnsh.asp`, `/certsrv/certnew.cer`, and `/certsrv/certnew.p7b` are candidate observation paths.
Only the limited source statements above are documented here. Do not implement the four paths as an assumed complete
contract. M1 explicitly distinguishes CA Web Enrollment from Certificate Enrollment Web Service; do not substitute
the latter, general Active Directory emulation, ACME, SCEP or EST for an observed VCF dependency.

## Certificate origin and renewal ownership

A3's unpinned configuration model includes `microsoftCertificateAuthoritySpec` with `serverUrl`, `username`, `secret`
and `templateName`. These suggest configuration inputs, not how VCF binds an issued certificate to its CA. A4's example
also includes a secret field: even a read-only CA-config response must be filtered inside the trusted consumer before
anything is persisted or displayed. Do not download complete configuration responses into reports or shell output.

A2 exposes `type`, `autoRenewInfo`, `autoRenewState` and `displayAutoRenewState`; its example contains `type: MSCA`,
`autoRenewInfo.autoRenewStatus: DISABLED` and `autoRenewState: ENABLED` together. Treat these as separate observations,
not equivalent booleans. Examples are not normative state-machine definitions or proof of a functioning scheduler.

For each lab stage, record certificate resource identity, issuer/root fingerprints, leaf fingerprint, VCF-reported CA
type, every available renewal field and a sanitized reason code. Record absent fields as **absent**, not false. Then
correlate those observations with VCF's own task history and the certificate actually served over TLS. A subject/issuer
name match, successful replacement, or changed UI label is insufficient to establish native auto-renewal.

The unresolved question is whether a correctly authenticated Web Enrollment exchange is sufficient for VCF to retain
CA origin and schedule renewal, or whether additional AD CS/plugin state is required. Do not edit VCF databases or
plugin binaries to force classification. Preserve VCF's native status for externally imported Atlaso certificates.
If a future Atlaso-managed controller is selected, its ownership/status must remain distinct from VCF-native renewal.

## Existing Atlaso building blocks

Repository inspection used base commit `cfcb5c95afeb16c88ecec7a66ac04334c79e532b`. The following are reuse candidates,
not an inbound enrollment authorization model. Source links are pinned to that commit.

| Capability | Existing implementation | Limit for an MSCA adapter |
| --- | --- | --- |
| CA issuance and accounting | [`ca.py`](https://github.com/mdaneri/Atlaso/blob/cfcb5c95afeb16c88ecec7a66ac04334c79e532b/atlaso/app/services/ca.py): `issue_certificate`, `validate_ca_csr_text`; persisted `CaCertificate` records | Signed bounded PKCS#10 intake and profile-based signing exist. CSR issuance uses the supplied public key; no target private key is needed. Incoming machine authorization and template mapping remain undefined. |
| Product policy and public material | [`vcf_certificate_material.py`](https://github.com/mdaneri/Atlaso/blob/cfcb5c95afeb16c88ecec7a66ac04334c79e532b/atlaso/app/services/vcf_certificate_material.py): `validate_profile`, `validate_product_csr`, `validate_issued_certificate`, `public_chain_pem` | Exact product/SAN/profile and chain checks are useful primitives; they do not establish AD CS response semantics or all VCF target profiles. |
| Durable operation and audit | [`vcf_certificates.py`](https://github.com/mdaneri/Atlaso/blob/cfcb5c95afeb16c88ecec7a66ac04334c79e532b/atlaso/app/services/vcf_certificates.py): `_ready_ca`, `_issue`, `run_job`, `_verify`, `_reconcile`, `recover_interrupted_jobs`, calls to `record_audit` | Existing actor-bound reviews, checkpoints and reservations protect outbound replacement for SRM, standalone vCenter and SDDC Manager. They are not a VCF Operations scheduler or an authenticated service enrollment endpoint. |
| Connection identity | [`vcf_certificate_remote.py`](https://github.com/mdaneri/Atlaso/blob/cfcb5c95afeb16c88ecec7a66ac04334c79e532b/atlaso/app/services/vcf_certificate_remote.py): `PinnedHTTPS`, `Target` | Existing endpoint confirmation and strict-TLS post-install verification can inform the design; server-side enrollment authentication is separate. |
| SDDC integration | [`vcf_certificate_sddc.py`](https://github.com/mdaneri/Atlaso/blob/cfcb5c95afeb16c88ecec7a66ac04334c79e532b/atlaso/app/services/vcf_certificate_sddc.py): `SddcAdapter` | Native SDDC Manager appliance-resource replacement is not an Operations MSCA plugin implementation. |

Existing focused evidence includes the signed/bounded PKCS#10 case in `tests/test_ca.py`, SAN/root cases in
`tests/services/test_vcf_certificate_material.py`, and uncertain-install/reservation cases in
`tests/services/test_vcf_certificates.py`. These tests were inspected, not executed for this documentation work; none
proves Web Enrollment interoperability. No incoming MSCA routes, request-ID registry, template-to-profile mapping,
VCF-origin binding or VCF-managed renewal integration is supplied by this change.

## Security requirements for a later proof of concept

Before a Phase 0 GO, review a model that binds a dedicated authenticated enrollment identity to exact allowed target
identities, SANs, templates and existing enabled CA profiles. A submitted template or SAN is a request, not authority.
Preserve CSR signature/key checks, issuance accounting and audit; never call a lower-level signer to bypass policy.
Keep target keys on VCF/its native appliance and Atlaso's signing key inside Atlaso's existing custody boundary.

Require verified HTTPS, bounded request/response sizes and timeouts, rate/concurrency limits, durable request identity,
replay/idempotency handling, and recovery after uncertain issuance. Define whether pending requests are supported from
observed behavior. Deny unsupported routes/templates/targets by default. Authentication errors and failed CSR validation
must not issue a certificate. Do not weaken shared CA profiles, enable anonymous enrollment, or disable TLS validation.
This report supplies requirements, not a completed security design or approval to expose an enrollment listener.

## Isolated-lab investigation procedure

This procedure is for a later, separately authorized lab session. It was not executed for #1050. Start with a real
Microsoft CA baseline; the adapter comparison and negative adapter tests require a subsequent Phase 0 GO and Phase 1
implementation. Do not create an adapter merely to complete this runbook.

### 1. Establish ownership, versions and recovery

1. Select one disposable VCF-supported TLS component, initially a lab vCenter Machine SSL target if the exact installed
   VCF build supports its coordinated CA workflow. Record its resource/VM identity and dependencies. If unsupported,
   stop and record that prerequisite; do not substitute an unrelated certificate role.
2. Record Operations, SDDC Manager, fleet-management component and plugin versions/builds independently, plus Windows,
   IIS, AD CS roles, CA hierarchy, template identifier/schema and Atlaso commit/profile. Mark unavailable plugin
   version data explicitly and obtain the supported identification method before claiming a reproducible baseline.
3. Load the current [VMware lifecycle procedure](vmware-workstation-lifecycle-testing.md),
   [certificate address-control procedure](certificate-address-control.md), and
   [credential policy](../contribute/credential-policy.md). Establish original ownership receipts, isolated network
   scope, permitted evidence locations and supported teardown before resource creation. Use the exact Atlaso
   1Password Environment through the supported bounded helpers; never put credentials into commands or evidence.
4. Obtain version-matched CA configuration, certificate replacement, health and recovery instructions. Confirm supported
   backups and recovery access before modifying the target. Record current public leaf/chain, service health and VCF
   certificate status. Keep the existing [clock authority](../services/ntp.md); do not advance or roll back clocks.

### 2. Prepare the reference CA and safe observation

1. On the isolated real AD CS endpoint, verify trusted HTTPS with the correct hostname SAN. Apply the documented
   build-specific Basic-authentication and template permissions through the lab owner. Record the template's internal
   and friendly names separately. Do not apply B1's IIS settings to other services or production infrastructure.
2. Before enrollment, use **IIS Manager → test website → Logging → W3C → Select Fields** (M3). Retain only UTC date/time,
   method, URI stem, HTTP/substatus/Win32 result, and duration. Omit query strings, cookies, referrers, user agents,
   usernames and custom headers. Verify inherited logging, proxy logs and diagnostic tracing cannot persist secrets.
   Use only the isolated fixed-path enrollment endpoint; retain unexpected path content only as an unknown-path count.
3. Verify observation with synthetic non-secret traffic. Do not use HAR exports, TLS key logging, decrypted packet
   capture, verbose authenticated HTTP clients, full request/response dumps or unrestricted VCF support bundles.
   Filtering must happen before persistence, not as later redaction of a secret-bearing capture.
4. W3C logs establish method/path/status order only. To resolve form/query names, encodings, response MIME/body category,
   auth scheme and request-ID transitions, require an approved lab observer that emits only those allowlisted metadata
   fields and public certificate/CSR fingerprints. Exclude header values, cookies, credentials and raw bodies at source.
   If no safe observer exists, mark those protocol cells unresolved and stop short of a protocol-complete GO.

### 3. Observe real-MSCA enrollment and origin

1. In the version-matched **Fleet Management → Certificates → Configure CA** workflow, configure the real test Microsoft
   CA using documented inputs and verified trust. Record input field names and non-secret template/CA identity only.
   Never export the full configuration API response; A4 may contain secrets.
2. Select the one disposable component and invoke the documented native CA-backed generation/replacement workflow.
   Manual CSR download, external signing and import are not a substitute. Record UTC stage times, sanitized VCF task
   IDs, ordered CA exchanges and request-ID correlation. Do not overwrite an existing pending CSR.
3. Complete the protocol matrix from observations, including validation/configuration requests, leaf and chain retrieval,
   authentication challenges, encoding, template/CA selection, pending/denied behavior and bounded retries. Keep every
   unsupported or unobserved case explicit; a successful happy path does not define error semantics.
4. Independently obtain the served leaf and validate hostname, full chain, expiry, SANs, KU/EKU and CSR public-key match.
   Compare its fingerprint with the issued leaf and VCF task result, then verify component/integration health. From an
   authorized host with OpenSSL, this read-only example verifies the named TLS service using a reviewed public root:

   ```sh
   openssl s_client -connect vcenter.lab.example:443 -servername vcenter.lab.example \
     -CAfile reviewed-lab-root.pem -verify_hostname vcenter.lab.example -verify_return_error </dev/null
   ```

   Use actual independently verified lab names and public trust files. A successful handshake does not by itself prove
   exact leaf identity, complete application health, or issuance provenance; compare the public certificate separately.
5. Using the installed build's supported certificate-details interface/API, record the actual CA type and separate
   renewal fields before and after issuance. Filter inside the authenticated consumer; persist only the allowed public
   metadata and normalized status/reason codes. Do not assume A2's fields or states exist on the installed build.

### 4. Establish scheduler behavior and the adapter gate

1. On the real-MSCA baseline, enable native renewal through the documented supported control. Select an allowed short
   validity/template or supported lab scheduling control and a bounded observation window before issuance. If no safe
   acceleration exists, wait for the native threshold or record the test as pending; never alter clocks or hidden state.
2. Observe a second issuance and installation attributable to VCF's scheduler/orchestrator. Correlate trigger/task time,
   new CA request/serial and changed served fingerprint. Verify the renewed leaf, full chain and health again. Clicking
   manual replacement or a manual renew action alone does not prove scheduler ownership.
3. Record the exact protocol and a proposed narrow security model. A **Phase 0 GO** permits only a separately reviewed,
   opt-in lab adapter proof of concept when its required exchange and authorization design are sufficiently evidenced.
   A failing or incomplete real-MSCA reference must be diagnosed before attributing failure to an Atlaso adapter.
4. After that GO and a separate Phase 1 implementation, repeat steps 2–4 with the candidate Atlaso adapter and fresh
   disposable target state. Compare the entire exchange, origin classification, renewal eligibility and full scheduled
   second renewal. Do not claim Atlaso compatibility from the real-MSCA baseline alone.

### 5. Negative cases, recovery and evidence

Run each case separately on disposable state. Record result, sanitized reason, issuance count, pending request state,
installed fingerprint and health. Inject malformed responses only through an approved lab test mechanism after the
adapter exists; never patch the real CA or VCF binaries to fabricate behavior.

| Case | Required observation |
| --- | --- |
| Bad credentials; unknown or unauthorized template | Enrollment denied, no certificate issued, bounded retries; existing service remains usable. |
| Disallowed SAN/target; malformed or incorrectly signed CSR | Policy/signature rejection before issuance; no fallback to a broader profile. |
| Invalid PKCS#7, incomplete or wrong chain | Honest failure, no false replacement success; reconcile any uncertain native write. |
| Pending/denied request | Observed request-ID/status transition and polling bound, or an explicit unsupported result; no invented pending support. |
| Duplicate submission, retry or interrupted response | Determine real-MSCA behavior; require adapter idempotency/accounting without duplicate untracked issuance or blind install retry. |
| CA outage, timeout or target restart | Existing leaf remains identifiable; failures surface; any resumed work reconciles outstanding issuance/install before another write. |
| Recovery after replacement failure | Execute the exact version-matched vendor recovery plan; prove restored certificate and service health before continuing. |

Preserve a sanitized result bundle outside disposal roots: ownership/source references, exact builds and API-spec
version, source retrieval dates, completed matrices, allowed protocol events, public CSR/leaf/chain fingerprints,
VCF task correlation, health evidence, negative-case results and recovery outcome. No arbitrary error strings or
configuration exports belong in the bundle. Release only proven task-owned resources through their supported tools
after downstream work no longer needs them; preserve ambiguous or recovery-pending state.

## Decision record and next work

| Decision | Current result | Evidence needed to change it |
| --- | --- | --- |
| Research-only work package | Official-source and repository investigation completed; lab runbook provided. | This does not complete #1042's protocol discovery or renewal acceptance. |
| Phase 0 adapter implementation gate | **Not satisfied; lab validation required.** | Exact build/plugin contract, safe real-MSCA protocol observations, unresolved-case disposition, and reviewed authorization/security model. |
| Atlaso adapter native-renewal acceptance | **Untested.** | Atlaso-backed native enrollment, independently verified origin/eligibility, full VCF-scheduled second renewal and recovery tests. |
| Production/vendor support | **Unconfirmed; no supported emulation claim.** | Independent Broadcom confirmation for the actual non-Microsoft configuration, separate from technical acceptance. |
| Fallback Atlaso-managed controller | **Not selected by this research.** | Evidence-backed incompatibility or an explicit support/security-risk decision under #1042, followed by its own implementation scope. |

The next bounded task is the isolated real-MSCA investigation. Do not mark unperformed cases passed, classify missing
lab access as technical failure, close #1042 on documentation delivery, or expose an experimental enrollment endpoint
as a consequence of publishing this report.
