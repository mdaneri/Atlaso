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
page is skipped. The picker omits keys without an HTTP or HTTPS URI and shows one choice per valid URI when a key has several.
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

`Deploy SDDC Manager` becomes available when a valid OVA is present beneath
`/mnt/atlaso-vcf-offline-depot/PROD/COMP/SDDC_MANAGER_VCF`. Atlaso validates the OVA manifest, reads its
user-configurable OVF properties, confirms the vCenter or ESXi TLS fingerprint, and asks the selected target to parse
the OVF descriptor. VMware's parsed properties, defaults, deployment options, errors, and sanitized warnings are the
authoritative import contract. Atlaso reviews and passes a value for every target-deployable property. A direct
standalone ESXi connection is bound to its single host; vCenter retains automatic placement unless an operator selected
a host. Atlaso then streams the disks through a vSphere NFC lease.

Before power-on or any DNS, trust, or depot follow-up, Atlaso verifies that the imported VM retained every mapped vApp
property and a supported OVF environment transport (`com.vmware.guestInfo` or `iso`). If verification fails, Atlaso
removes only the exact VM created by that task. A failed removal is reported as a partial deployment requiring manual
cleanup. The pre-authentication fingerprint probe requires TLS 1.2 or newer while preserving explicit fingerprint
confirmation as the trust decision. Atlaso refuses duplicate VM names and waits up to 90 minutes for the VCF API after
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
3. Confirm the task reports `HostAgent`, the selected deployment option, sanitized parser/import warnings, every mapped
   property key, and an accepted OVF environment transport. In ESXi, confirm the VM's vApp/OVF properties exist without
   copying their values into the evidence record.
4. Power on the verified VM and confirm the VCF Installer consumes its OVF environment and becomes usable. Repeat the
   supported vCenter path as a regression check when a safe vCenter target is available.
5. For a negative check, use a disposable controlled descriptor or test target that cannot retain the required
   transport. Confirm Atlaso powers on nothing, runs no DNS/trust/depot follow-up, and removes only the task-created VM.

Record only sanitized diagnostics and key names. Never capture passwords, vSphere credentials, private material,
property values, or the complete VM configuration. If the lab result differs, attach the sanitized task diagnostics to
issue #595 before approving the pull request.

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

`Delete generated records` is enabled only when at least one displayed FQDN has an A or AAAA address. Deletion requires
confirmation and submits the same exact component-to-hostname mapping used by creation. Atlaso removes a record only
when its FQDN and helper metadata prove ownership for that submitted component and reviewed hostname. Unrelated,
manually created, mismatched, and legacy description-only records are preserved even when their names or descriptions
match the current catalog.

## Routes And Responses

- `GET /ui/management/vcf-helper` renders the helper page.
- `POST /ui/management/vcf-helper/generated-fqdns/populate` validates and previews allocation without mutation.
- `POST /ui/management/vcf-helper/generated-fqdns` validates and creates missing records.
- `POST /ui/management/vcf-helper/generated-fqdns/delete` deletes matching helper-owned records.
- `POST /ui/management/vcf-helper/sddc-manager/inventory` confirms TLS and discovers vSphere inventory.
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
