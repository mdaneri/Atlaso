---
title: VCF Helper
description: Operate the Atlaso VCF helper workflow and its constrained PowerCLI boundary.
audience:
  - operator
status: current
---

# VCF Helper

VCF Helper prepares deployment DNS desired state. It is available under `VCF Workflows` at `/vcf-helper`.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso VCF Helper page in the clean-appliance desktop viewport.](../assets/screenshots/vcf-helper-clean-desktop.webp)

*Figure: VCF Helper in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

Administrators can also use **Import passwords into a vault** for VCF 9 SDDC Manager and VCF Installer appliances.
The wizard chooses vault or manual credentials first, confirms the server second, and then opens a dedicated TLS page.
Atlaso probes the server without resolving or sending credentials and requires the operator to confirm the observed
fingerprint before vault or manual authentication can continue. It displays only discovered metadata for selection,
then re-fetches and encrypts the reviewed VCF/ESX passwords in the selected vault. Source credentials are request-local
and password values are never included in the discovery response. See [Vaults](vaults.md) for supported entries,
managed-script and Kickstart access, URI targets, and restore behavior.

The helper creates DNS records in Atlaso, deploys SDDC Manager OVAs, and configures VCF 9 appliances to use the applied
local offline depot. DNS does not reload `dnsmasq` or change the appliance directly. Review and submit the changed
`DNS/DHCP (dnsmasq)` unit through the global `/appliance-apply` workflow after generation or deletion.

The `VCF Certificate Trust` button opens the separate remote certificate task in a modal without mixing CA details into
the main DNS helper workspace. See [VCF Certificate Trust](vcf-trust.md).

## Use a saved vault credential

An administrator can select **Vault** and then **Key** anywhere VCF Helper requests a remote vCenter, ESXi, SDDC
Manager, VCF Installer, or VCF Automation login. Atlaso fills the server from the first HTTP or HTTPS URI on the entry
and fills its username. The server control is read-only, the manual-login controls are disabled, and the login page is
skipped. If the entry has no HTTP or HTTPS URI, enter the server manually.

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
user-configurable OVF properties, confirms the vCenter or ESXi TLS fingerprint, discovers destination inventory, and
streams the disks through a vSphere NFC lease. It refuses duplicate VM names, powers on the VM, and waits up to 90
minutes for the VCF API.

The form can optionally add managed DNS desired state, deploy Atlaso CA trust, and configure the local offline depot.
Trust uses the VCF API only and does not require a snapshot acknowledgement.
Manually entered vSphere, OVF, VCF API, and depot passwords remain transient; a selected vault password remains
encrypted at rest and is resolved only on the server for the request.

## Configure VCF Offline Depot

The standalone helper is available only when the local depot is enabled, applied, CA-backed, has a generated software
depot ID, and has a selected HTTP user. Its wizard confirms the target HTTPS fingerprint, detects VCF Installer or SDDC
Manager 9.x, collects the one-time depot HTTP password, and reads the current sanitized depot configuration. Replacing a
different depot requires explicit confirmation.

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

Creating records requires confirmation. The modal remains open after creation so assigned addresses can be reviewed.
When every displayed FQDN has an A or AAAA address, the primary action changes to `Done`; `Done` closes the modal.

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
Helper ownership is stored separately in structured record metadata with source `vcf_helper` and the catalog component
hostname.

`Delete generated records` is enabled only when at least one displayed FQDN has an A or AAAA address. Deletion requires
confirmation and removes only records owned by VCF Helper for the selected deployment, prefix, suffix, and domain.
Unrelated or manually created records are preserved. Legacy helper records without ownership metadata are removed only
when their description exactly matches the expected component description.

## Routes And Responses

- `GET /vcf-helper` renders the helper page.
- `POST /vcf-helper/generated-fqdns` validates and creates missing records.
- `POST /vcf-helper/generated-fqdns/delete` deletes matching helper-owned records.
- `POST /vcf-helper/sddc-manager/inventory` confirms TLS and discovers vSphere inventory.
- `POST /vcf-helper/sddc-manager/deploy` queues an OVA deployment.
- `GET /vcf-helper/sddc-manager/tasks/{job_id}` reports deployment progress.
- `POST /vcf-helper/offline-depot/inspect-target` previews remote depot state.
- `POST /vcf-helper/offline-depot/configure` queues remote depot configuration.
- `GET /vcf-helper/offline-depot/tasks/{job_id}` reports configuration and sync progress.

Fetch responses report created, skipped, deleted, and preserved rows with their assigned addresses, plus validation or
allocation errors. All mutations use the existing authenticated session, CSRF validation, audit logging, and DNS desired
state model.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### VCF Helper

![Atlaso VCF Helper page in the clean-appliance responsive viewport.](../assets/screenshots/vcf-helper-clean-responsive.webp)

*Figure: VCF Helper in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
