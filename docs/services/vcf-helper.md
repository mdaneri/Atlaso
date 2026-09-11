---
title: VCF Helper
description: Operate the Atlaso VCF helper workflow and its constrained PowerCLI boundary.
audience:
  - operator
status: current
---

# VCF Helper

VCF Helper prepares deployment DNS desired state. It is available under `VCF Workflows` at
`/ui/management/vcf-helper`.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso VCF Helper page in the clean-appliance desktop viewport.](../assets/screenshots/vcf-helper-clean-desktop.webp)

*Figure: VCF Helper in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

Administrators can also use **Import passwords into a vault** for VCF 9 SDDC Manager and VCF Installer appliances.
The wizard chooses vault or manual credentials first, confirms the server second, and then opens a dedicated TLS page.
Atlaso probes the server without resolving or sending credentials and requires the operator to confirm the observed
fingerprint before vault or manual authentication can continue. The probe requires TLS 1.2 or newer, and explicit
fingerprint confirmation remains the trust decision rather than being replaced with ordinary CA verification. It
displays only discovered metadata for selection, then re-fetches and encrypts the reviewed VCF/ESX passwords in the
selected vault. Source credentials are request-local and password values are never included in the discovery response.
See [Vaults](vaults.md) for supported entries, managed-script and Kickstart access, URI targets, and restore behavior.

The helper creates DNS records in Atlaso, deploys SDDC Manager OVAs, and configures VCF 9 appliances to use the applied
local offline depot. DNS does not reload `dnsmasq` or change the appliance directly. Review and submit the changed
`DNS/DHCP (dnsmasq)` unit through the global `/ui/management/appliance-apply` workflow after generation or deletion.

The `VCF Certificate Trust` button opens the separate remote certificate task in a modal without mixing CA details into
the main DNS helper workspace. See [VCF Certificate Trust](vcf-trust.md).

## Use a saved vault credential

An administrator can select **Vault** and then **Key** anywhere VCF Helper requests a remote vCenter, ESXi, SDDC
Manager, VCF Installer, or VCF Automation login. Atlaso fills the server from the HTTP or HTTPS URI selected for the
entry and fills its username. The server control is read-only, the manual-login controls are disabled, and the login
page is skipped. The picker omits keys without an HTTP or HTTPS URI and shows one choice per valid URI when a key has
several.
If the selected vault has no usable keys, it shows **No HTTP/HTTPS credentials available** and keeps manual mode active.

Address fields display only the selected hostname, IP, and non-default port; they do not display `http://` or
`https://`. Fields explicitly labeled as a URL, such as **VCF Automation URL**, retain the complete URL.

The selected password is not loaded into the page, copied into the password input, or returned by an API. The disabled
password input indicates that the stored value will be used. Atlaso validates that the key belongs to the selected
vault, decrypts the password on the server for that request only, and records the use without recording the value.
Choose **Enter credentials manually** to return to request-local username and password entry. Service administrators
can continue to use manual credentials but cannot select administrator-owned vault entries.

Remote VCF wizards consistently use **Credential**, **Server**, **TLS fingerprint**, and **Login** as their first four
steps. The TLS step is always pre-authentication. Workflow-specific selection and review pages follow it.

The picker is available for SDDC Manager deployment inventory, VCF Offline Depot configuration, VCF Certificate Trust,
VCF password import source authentication, and Managed LDAP for VCF Automation. The local offline-depot HTTP password
and OVA appliance passwords remain separate fields and are never filled from this picker.

## Deploy SDDC Manager

### Upload an OVA without VCFDT

Administrators and service administrators can select **Add SDDC Manager OVA** under **SDDC Manager / VCF Installer**.
Choose the original `.ova` file from your computer, review its filename, size, and destination, then select
**Upload SDDC Manager OVA**. The two-step wizard follows **Add ESX ISO**, but accepts deployment OVAs rather than
ISO boot images. JavaScript is required for the chunked upload. The limit is 16 GiB.

The final destination is `/mnt/atlaso-vcf-offline-depot/PROD/COMP/SDDC_MANAGER_VCF/<original-filename>.ova`, directly
inside the component folder without an extra version or upload directory. This matches the packaged VCFDT
`application-prodv2.properties` defaults and the
[VMware Holodeck offline depot layout](https://github.com/vmware/Holodeck/blob/main/docs/offline_depot.md).
Keep the vendor filename; only letters, numbers, dots, underscores, and hyphens are accepted.

The wizard reports transfer progress, then shows validation while Atlaso checks the OVF, referenced files, and manifest
checksums. Admission limits archive metadata to 8 MiB, 4,096 members, a 4 MiB OVF, and a 1 MiB manifest before
using the deployment parser. OVA staging writes and disk flushing run outside the event loop so slow depot storage
does not block management requests. After success, the page refreshes and **Deploy SDDC Manager** discovers the
package in the same folder used
by VCFDT. Uploading does not deploy a VM, enable the depot, or require global Appliance Apply. It does not require
VCFDT, Broadcom credentials, or a software depot ID, and does not populate the metadata needed to serve a complete
offline depot to VCF.

For an existing OVA, ESX ISO, or VCF Download Tool filename, Atlaso shows **Overwrite existing file?** before sending
file bytes. **Cancel** keeps the original file; **Overwrite** replaces it only after validation succeeds. Confirmation
is bound to the current file revision: if another upload changes it during transfer, select the file again and confirm
the new warning. ESX ISO names use the same whitespace trimming for overwrite checks and final storage.
A failed OVA audit commit restores the previous package. Optional audit refresh or operational logging failures after
a successful commit preserve the published OVA and its durable success record. For invalid or truncated files, obtain
the complete
original OVA and retry. For storage failures, check depot free space and write access.
Failed or disconnected uploads are removed from staging; a process interruption can leave a private staging directory
outside deployment discovery, but never a partially uploaded selectable OVA.

### Chunked browser uploads

Multipart and no-JavaScript media uploads may create a new filename but cannot replace an existing file without
revision-bound overwrite consent. Use the browser confirmation flow to replace existing media. After publication,
backup-link and caller-owned staging-file cleanup errors are logged without changing the upload result; cleanup
still attempts each private link. ISO permissions are set before publication.

VCF Download Tool filenames are validated before chunk storage is reserved. Final chunk cleanup attempts every staged
file; a handle-close error is logged without replacing the consuming endpoint result. Expiry sweeps and shutdown
also attempt every eligible handle after a close failure, and expiry continues for remaining sessions.
Replaced OVA backup links
are removed with private staging in the shielded worker cleanup, so old-file deallocation does not block management requests.

Browser file uploads use a shared sequential transport, including SDDC Manager OVA, ESX ISO, VCFDT packages,
Network Boot media, credential files, registry CA bundles, and backup imports. Each request carries at most 8 MiB;
small files use one chunk. Hashing supports both HTTP and HTTPS management pages. This works with the existing
management proxy limit without applying Appliance Settings.
Successful finalization retains the shared pending-changes sidebar refresh; staging reservations, chunks, and
cancellation do not trigger extra status requests. Progress counts acknowledged bytes.
A failed chunk retries up to three times with the same offset and SHA-256
checksum; already acknowledged chunks are not resent. Atlaso rejects changed retries, gaps, and size overruns.
OVA filenames are validated before reserving a session, so unsupported names transfer no file bytes.
Archive members and their total logical size are each limited to 16 GiB before manifest hashing, including
sparse disk members whose logical size exceeds their physical archive size. Manifest entries must reference
unique regular files, and total hashing work is bounded by the same limit.
Final validation and publication use the existing endpoint, permissions, duplicate policy, and desired-state boundary.
A lost final response is not retried automatically: inspect the destination before submitting again.

The OVA wizard locks Back, Cancel, step navigation, and Escape during transfer and validation.
A staging cleanup error after successful publication and audit does not turn the completed upload into a failure.
Keep the page open during transfer and validation. Sessions expire after 30 minutes without an accepted chunk;
page reload, logout, application restart, or exhausting retries requires selecting and uploading the file again.
Browser completion or failure releases staging in a worker thread, including when finalization is canceled,
so closing large temporary files does not block management requests. Rejected OVA staging directories also
use shielded worker-thread cleanup. Abandoned sessions expire automatically.
Files up to 16 MiB stay
in memory, so credential-file contents never enter chunk staging on disk. Larger files use private anonymous
files beneath `/mnt/atlaso-vcf-offline-depot/.atlaso-uploads`, outside artifact discovery. The depot volume must be
available and staging must not be writable by other users. The service reserves capacity for upload and validation,
with at most four sessions per browser, sixteen per process, and 32 GiB of total declared file sizes. Existing
file-specific limits still apply (including the configured ESX ISO limit); VCFDT packages are limited to 2 GiB,
LDAP recovery archives to 1 GiB, and credential/CA files to 1 MiB in this browser transport.

The browser protocol is excluded from OpenAPI: `POST /ui/management/uploads/chunks` creates a session,
`PUT /ui/management/uploads/chunks/data` appends a checked chunk, and `DELETE` on that same data route cancels it.
All operations require a current browser session and `X-CSRF-Token`. Session identifiers travel in headers,
not URLs. Finalization sends a bounded form envelope with `X-Atlaso-Chunked: 1` to the original upload endpoint.
Existing multipart API clients and server-rendered fallback forms remain compatible; they do not gain automatic
chunk retries. Local file imports into text editors remain editor operations rather than binary file uploads.

### Deploy a validated package

`Deploy SDDC Manager` becomes available when a valid OVA is present beneath
`/mnt/atlaso-vcf-offline-depot/PROD/COMP/SDDC_MANAGER_VCF`. Atlaso validates the OVA manifest, reads its
user-configurable OVF properties, confirms the vCenter or ESXi TLS fingerprint, and asks the selected target to parse
the OVF descriptor. VMware's parsed properties, defaults, deployment options, errors, and sanitized warnings are the
authoritative import contract. Atlaso reviews and passes a value for every target-deployable property. A direct
standalone ESXi connection is bound to its single host; vCenter retains automatic placement unless an operator selected
a host. Atlaso then streams the disks through a vSphere NFC lease.

Before power-on or any DNS, trust, or depot follow-up, Atlaso verifies every reviewed OVF value. With vCenter, the
imported VM must retain its vApp properties and a supported declared transport (`com.vmware.guestInfo` or `iso`).
Standalone ESXi discards vApp configuration during import, even when its generated import specification contains the
properties. For that target, Atlaso installs an escaped OVF environment in the exact powered-off VM's
`guestinfo.ovfEnv` setting and reads it back before allowing power-on. The OVA must declare `com.vmware.guestInfo`.
The environment includes a `PlatformSection` before its properties, identifying VMware ESXi, the connected target's
version and vendor, and the `en` locale. Readback verifies this platform metadata and section ordering as well.
Guest keys retain VMware's class and instance qualification, such as `vami.ip0.SDDC-Manager`, while reviewed empty
values and non-editable appliance defaults are preserved. A missing, malformed, duplicated, or changed environment
fails verification; the absence of ESXi `vAppConfig` alone is expected.
Standalone import warnings are redacted against both reviewed values and the additional non-editable defaults.
Failed standalone import specifications may omit property metadata, so their vendor diagnostic text is withheld.
Cancellation during metadata work is checked before either powered-off completion or power-on.
VMX response reads enforce a 30-second overall body deadline and check cancellation between bounded reads.

ESXi can expose an empty `guestinfo.ovfEnv` API value even though the VMX contains the complete XML. In that case,
Atlaso reads only the exact imported VM's configuration from the selected datastore over HTTPS, checks the certificate
against the confirmed fingerprint before sending its session cookie, and verifies the decoded XML in memory. The
deployment account therefore needs permission to read that VMX through the datastore browser. A refused read, changed
certificate, redirect, or invalid configuration fails verification and triggers the same rollback. Results identify
this readback as `datastore-vmx`; no configuration file or property values are saved in task logs.
If cancellation arrives during metadata installation or readback, Atlaso finishes that verification but checks
cancellation again before starting power-on. The verified VM remains powered off and is reported as a partial deployment.

If installation or verification fails, Atlaso removes only the exact VM created by that task. A failed removal is reported
as a partial deployment requiring manual cleanup. The pre-authentication fingerprint probe requires TLS 1.2 or newer
while preserving explicit fingerprint confirmation as the trust decision. Atlaso refuses duplicate VM names and waits
up to 90 minutes for the VCF API after
a verified VM is powered on.

The form can optionally add managed DNS desired state, deploy Atlaso CA trust, and configure the local offline depot.
Trust uses the VCF API only and does not require a snapshot acknowledgement.
Manually entered vSphere, OVF, VCF API, and depot passwords remain transient; a selected vault password remains
encrypted at rest and is resolved only on the server for the request.

### Standalone ESXi acceptance check

Run this check in a lab that has the exact supported VCF Installer OVA and a directly connected standalone ESXi host.
Use a disposable VM name and do not record credentials or OVF property values.

1. Record the sanitized Atlaso version and Git SHA, OVA product/version identity, ESXi version and API type, selected
   deployment option, and OVF property key names.
2. In **Deploy SDDC Manager**, confirm the ESXi TLS fingerprint, select the deployment option and destination, review
   every rendered property key, and deploy with power-on disabled first.
3. Confirm the task reports `HostAgent`, the selected deployment option, sanitized parser/import warnings, qualified
   property keys, and the `guestinfo.ovfEnv` verification source with `com.vmware.guestInfo` transport. Compare the
   persisted environment privately with the reviewed mapping; never copy XML or values into the evidence record.
4. Power on the verified VM and confirm the VCF Installer consumes its OVF environment and becomes usable. Repeat the
   supported vCenter path as a regression check when a safe vCenter target is available.
5. For a negative check, use a disposable controlled descriptor or test target that cannot retain the required
   transport. Confirm Atlaso powers on nothing, runs no DNS/trust/depot follow-up, and removes only the task-created VM.

Record only sanitized diagnostics and key names. Never capture passwords, vSphere credentials, private material,
property values, or the complete VM configuration. If the lab result differs, attach the sanitized task diagnostics to
issue #801 before approving the pull request. Powered-off import verification does not prove that the appliance consumed
the environment; complete the real guest boot and readiness check as well.

## Configure VCF Offline Depot

The standalone helper is available only when the local depot is enabled, applied, CA-backed, has a generated software
depot ID, and has a selected HTTP user. Its wizard follows **Credential**, **Server**, **TLS fingerprint**, and
**Login** before collecting the one-time depot HTTP password and reading the current sanitized depot configuration.
The TLS probe runs before Atlaso resolves a selected vault password or reads manual login fields. After confirmation,
Atlaso detects VCF Installer or SDDC Manager 9.x. Replacing a different depot requires explicit confirmation.

Atlaso calls `PUT /v1/system/settings/depot`, triggers metadata refresh with
`PATCH /v1/system/settings/depot/depot-sync-info`, and polls the matching GET endpoint for up to 60 minutes. It asks for
the local depot user's password for each run and never stores it. Certificate trust is not implicit; configure it
separately when the target does not yet trust the Atlaso CA.

## Generate FQDNs

Open `Generated VCF FQDNs` and select:

- the deployment catalog;
- an optional hostname prefix and suffix;
- a domain from the DNS zones managed by Atlaso;
- a starting IPv4 or IPv6 address with its CIDR prefix, such as `192.168.50.100/24` or `2001:db8:50::100/64`.

The preview updates as the deployment, prefix, suffix, or domain changes. A generated hostname is formed as:

```text
<prefix><catalog hostname><suffix>.<managed domain>
```

For example, prefix `lab-`, hostname `vc01`, suffix `-mgmt`, and domain `example.internal` produce
`lab-vc01-mgmt.example.internal`.

Each selected catalog component also has an editable **Hostname** in the review table. Prefix and suffix changes update
rows that still use their generated defaults while preserving deliberate per-component edits. Changing the deployment
catalog preserves edited hostnames for components that remain selected and initializes newly selected components from
the current pattern. **Clear pattern** removes the prefix and suffix and restores every selected component to its
catalog hostname.

Atlaso normalizes reviewed hostnames to lowercase and accepts exactly one DNS label per component. Labels must contain
1 to 63 letters, numbers, or hyphens and cannot begin or end with a hyphen. Every component in the selected catalog must
appear exactly once, and two components cannot use the same reviewed hostname. The server derives each FQDN from the
reviewed label and selected managed domain; it never trusts a browser-generated FQDN.

Select **Populate** to allocate and display the proposed A or AAAA addresses without changing DNS desired state. The
hostname inputs use their component descriptions as accessible names without repeating visible labels in every compact
row. **Create DNS records** remains disabled until Populate succeeds. Changing the deployment, domain, address range,
prefix, suffix, or any reviewed hostname invalidates that populated revision and requires Populate again. Atlaso binds
creation to the exact signed, time-limited populated inputs so a stale or changed browser submission cannot bypass the
review. Create also recomputes current DNS and DHCP availability and rejects the request when its allocations or skips
no longer match the signed plan, requiring Populate again instead of silently changing reviewed addresses.
If inputs change while a Populate request is still running, Atlaso discards that superseded response and requires a
fresh Populate instead of displaying or enabling an obsolete plan.
Without JavaScript, Populate submits the same inputs to a server-rendered review stage. That response displays the
planned allocation, carries the signed revision, and enables Create DNS records for the reviewed values.
Planned rows remain incomplete even if the page was rendered with an address that was removed before Populate.

Creating records then requires confirmation. The modal remains open after creation so assigned addresses can be
reviewed. When every displayed FQDN has an A or AAAA address, the primary action changes to `Done`; `Done` closes the
modal.

## Deployment Catalogs

The catalog is versioned so later VCF and VVF releases can define different component sets without changing existing
selections.

| Hostname        | Component description       | VCF 9.1 | VVF 9.1 |
| --------------- | --------------------------- | ------- | ------- |
| `vc01`          | vCenter                     | Yes     | Yes     |
| `nsx01`         | NSX Manager cluster         | Yes     | No      |
| `nsx02`         | NSX Manager appliance 1     | Yes     | No      |
| `nsx03`         | NSX Manager appliance 2     | Yes     | No      |
| `nsx04`         | NSX Manager appliance 3     | Yes     | No      |
| `ops01`         | VCF Operations primary node | Yes     | Yes     |
| `ops02`         | VCF Operations replica node | Yes     | No      |
| `ops03`         | VCF Operations data node    | Yes     | No      |
| `collector`     | Cloud Proxy                 | Yes     | No      |
| `auto-vip`      | VCF Automation              | Yes     | No      |
| `auto-platform` | VCF Automation Runtime      | Yes     | No      |
| `sddcm`         | SDDC Manager                | Yes     | No      |
| `vsp01`         | VCF services runtime        | Yes     | Yes     |
| `fleetlcm`      | Fleet components            | Yes     | Yes     |
| `shared01`      | Instance components         | Yes     | Yes     |
| `vidb`          | Identity Broker             | Yes     | No      |
| `license`       | License Server              | Yes     | Yes     |

## Address Allocation

An IPv4 starting CIDR creates A records. An IPv6 starting CIDR creates AAAA records. Allocation starts at the entered
address and advances sequentially within that network.

Atlaso skips:

- addresses already used by DNS records of the selected address family;
- IPv4 addresses used by DHCP reservations;
- generated FQDNs that already exist as any DNS record type.

Existing FQDNs are never overwritten. Existing A and AAAA addresses are shown in the preview when available. If the
remaining network cannot provide an address for every missing FQDN, allocation fails transactionally and creates no
records.

IPv4 network and broadcast addresses are not allocatable. The IPv6 network address is treated as the subnet-router
anycast address and is not allocatable.

## Record Ownership And Deletion

New records use the catalog component description, such as `vCenter` or `VCF Automation`, as the DNS record description.
Helper ownership is stored separately in structured record metadata with source `vcf_helper`, the immutable catalog
component key, and the reviewed generated hostname label.

`Delete generated records` is enabled only when at least one displayed FQDN has a currently persisted A or AAAA
address; proposed Populate addresses and stale page snapshots alone never enable deletion. Deletion requires
confirmation and submits the same exact
component-to-hostname mapping used by creation. Atlaso removes a record only
when its FQDN and helper metadata prove ownership for that submitted component and reviewed hostname. Unrelated,
manually created, mismatched, and legacy description-only records are preserved even when their names or descriptions
match the current catalog.

## Routes And Responses

- `GET /ui/management/vcf-helper` renders the helper page.
- `POST /ui/management/vcf-helper/generated-fqdns/populate` validates and previews allocation without mutation.
- `POST /ui/management/vcf-helper/generated-fqdns` validates and creates missing records.
- `POST /ui/management/vcf-helper/generated-fqdns/delete` deletes matching helper-owned records.
- `POST /ui/management/vcf-helper/sddc-manager/inventory` confirms TLS and discovers vSphere inventory.
- `POST /ui/management/vcf-helper/sddc-manager/ovas/upload` streams an OVA after session, role, and CSRF checks.
- `POST /ui/management/vcf-helper/sddc-manager/deploy` queues an OVA deployment.
- `GET /ui/management/vcf-helper/sddc-manager/tasks/{job_id}` reports deployment progress.
- `POST /ui/management/vcf-helper/offline-depot/inspect-target` previews remote depot state.
- `POST /ui/management/vcf-helper/offline-depot/configure` queues remote depot configuration.
- `GET /ui/management/vcf-helper/offline-depot/tasks/{job_id}` reports configuration and sync progress.

Fetch and no-JavaScript form responses report the current edited FQDN set as created, skipped, deleted, or preserved
rows with assigned addresses, plus validation or allocation errors. All mutations use the existing authenticated
session, CSRF validation, audit logging, and DNS desired state model.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### VCF Helper

![Atlaso VCF Helper page in the clean-appliance responsive viewport.](../assets/screenshots/vcf-helper-clean-responsive.webp)

*Figure: VCF Helper in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
