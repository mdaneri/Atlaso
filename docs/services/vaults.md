---
title: Vaults
description: Store and scope VCF and ESX passwords for Atlaso-managed scripts and ESXi Kickstarts.
audience:
  - operator
status: current
---

# Vaults

Open **VCF Workflows > Vaults** to manage encrypted VCF and ESX passwords. Each named vault appears as a tab containing
a table with **Key**, **Description**, **Username**, **URI(s)**, and **Password** columns. Multiple URIs are displayed
on separate lines. Passwords are masked by default. Administrators can use the compact eye control to reveal one value
for 15 seconds; Atlaso audits the reveal without recording the value and returns it with browser caching disabled.

Vault keys use lowercase dotted segments, for example `vcf.sddc_manager.admin` or `esx.esx01.root`. Values are encrypted
with the appliance secrets key before database storage. Keep `ATLASO_SECRETS_KEY` with the appliance recovery material.
Each entry may also store up to nine credential-free HTTP, HTTPS, SSH, or SFTP URIs. Add them on the third page of the
entry wizard. Right-click an existing row, or focus it and press **Shift+F10**, to open its context menu. **Edit**
reopens the entry wizard, **Copy** creates a new entry without loading the encrypted value into the page, **Open**
contains a submenu with every configured URI, and **Remove** uses the shared destructive confirmation. HTTP and HTTPS
open in a separate browser tab; SSH and SFTP open the Atlaso Web Terminal and authenticate with the entry username and
password. Atlaso opens the remote terminal window only after the administrator accepts the displayed host-key
fingerprint. If the target cannot be reached, the Vaults page displays a visible error naming the URI and safe
troubleshooting guidance. The confirmation displays the SHA-256 fingerprint in a dedicated wrapping field so it
remains readable without horizontal scrolling. That window is a standalone terminal surface identified only by the
remote hostname; it does not include the Atlaso administration shell.

## Managed scripts

Choose one **Scoped vault** when scheduling or manually starting a managed script. The worker supplies that vault through
a transient systemd credential available only to the script process.

```powershell
$password = Get-AtlasoVault -Key "vcf.sddc_manager.admin"
```

```bash
password="$(atlaso-vault get --key esx.esx01.root)"
```

The commands fail outside a scoped managed-script run. Atlaso redacts exact injected values from captured stdout and
stderr, but scripts must still treat passwords as secrets and must not transform, print, or transmit them. Both commands
are installed in interactive appliance shells for discoverability; invoking them there fails closed because no scoped
runtime credential is present.

Each queued execution records a non-reusable fingerprint for the selected vault. Before decrypting anything, the worker
verifies that fingerprint as well as the database ID, so deleting and recreating a vault cannot redirect an older queued
job to different credentials.

## ESXi Kickstarts

Kickstarts do not select or bind a vault. Declare each required value directly in Kickstart source. The vault-name
segment is the vault name normalized to lowercase, with spaces and punctuation replaced by underscores. Reference the
entry username and password explicitly:

```text
network --hostname={{vault.management.esx.esx01.root.username}}
rootpw {{vault.management.esx.esx01.root.password}}
```

URIs use their one-based position in the entry:

```text
%include {{vault.management.esx.esx01.root.uri1}}
```

Markers are available from `uri1` through `uri9` when that position is configured. Removing or reordering an entry URI
changes its marker position.

The Kickstart Monaco Editor suggests authorized vault, key, and supported subkey names after `{{`; completion metadata
contains names and descriptions only, never credential values. Saving or validating source parses every vault marker
and rejects malformed markers, missing or renamed vaults and keys, unsupported subkeys, and inaccessible references.
Atlaso resolves only the exact referenced values for an enabled host assigned to that Kickstart and revalidates them at
request time. Source, preview, and download views retain the marker; the dynamic response is not persisted and is
returned with `Cache-Control: no-store`. Atlaso blocks deletion of a vault while an enabled Kickstart references one of
its markers; remove or replace those marker dependencies first.

## Remote URI security

Do not place credentials in a URI. For SSH and SFTP targets, Atlaso probes the remote host key before decrypting the
entry password and requires the administrator to confirm its SHA-256 fingerprint. Verify that fingerprint out of band.
After confirmation, Atlaso creates a short-lived one-use launch token, rechecks the host key, and performs password
authentication server-side. The password is not sent to the browser, included in the launch URL, or written to the
audit event. An SFTP URI opens an interactive SSH terminal on the same endpoint; file-transfer browsing is not provided.

## VCF Helper import

**VCF Helper > Import passwords into a vault** discovers supported password metadata from a VCF 9 SDDC Manager or VCF
Installer. After the server page, Atlaso probes without resolving or sending credentials and opens a dedicated TLS
page. Confirm the observed SHA-256 fingerprint out of band before authentication, select the passwords, and choose a
destination vault. Discovery covers credentials the authenticated account can access; it is not a complete inventory of
every appliance account. For SDDC Manager, Atlaso requests the credential collection with the documented
`pageSize=0` all-records behavior and follows additional pages only when response metadata explicitly reports them.
Duplicate or incomplete page results stop discovery. If a listed SDDC Manager password is absent or masked, Atlaso
retrieves that supported credential by ID with `GET /v1/credentials/{id}`. For VCF Installer, discovery reads password
fields from its latest available SDDC specification only. Unsupported, unavailable, masked, or permission-limited
candidates are summarized by skipped count and reason; vendor error messages and password values are not shown.

Atlaso builds credential-free URIs only from authoritative resource metadata. SDDC Manager SSH credentials use a
validated FQDN `resourceName` or `resourceIp`; API, SSO, AUDIT, and missing credential types use HTTPS only for known
web resource types. Installer mappings use the latest available SDDC specification only, not a live appliance
inventory: vCenter root uses SSH to `vcenterHostname`; vCenter SSO uses `adminUserSsoUsername` and HTTPS to
`vcenterHostname`; each `nsxtManagers[].hostname` gets an NSX root SSH URI (never the cluster VIP); NSX admin and audit
use HTTPS to `vipFqdn`. Root and ESX accounts use SSH, while other known web-component accounts use HTTPS.
Unknown credential purposes need an operator URI association. FTP credentials are not treated as SFTP endpoints. If
the metadata has no valid host, including a short resource label or opaque ID, the URI list stays empty. After import,
use the entry's **Edit** action to add a verified endpoint. Reimport preserves an existing nonempty operator-managed
URI list and adds discovered URIs only when that list is empty. Atlaso re-reads the selected values during the reviewed
import and encrypts them immediately; existing keys are rotated. See Broadcom's [SDDC specification](https://developer.broadcom.com/xapis/vcf-installer-api/latest/data-structures/SddcSpec/)
for the source field definitions.

For the SDDC Manager response and endpoint contract, see Broadcom's [Get Credentials API](https://developer.broadcom.com/xapis/vmware-cloud-foundation-api/latest/v1/credentials/get/)
and [Get Credential API](https://developer.broadcom.com/xapis/vmware-cloud-foundation-api/latest/v1/credentials/id/get/).

## VCF Helper autofill

VCF Helper remote-connection wizards start with an administrator-only **Vault** and **Key** choice. Selecting a key
fills and locks the server address from the chosen HTTP or HTTPS URI, fills its username, and skips the manual API-login
page. The picker hides keys without an HTTP or HTTPS URI and creates one choice per valid URI when a key has several.
A vault with no usable keys shows **No HTTP/HTTPS credentials available** and leaves manual entry active. The password
remains encrypted at rest and is resolved only after the dedicated TLS page confirms the observed server fingerprint.
It is never copied into the password input or included in the page metadata.

The server rejects a key that does not belong to the selected vault and audits each use without the value. A vault
entry intended for VCF Helper must therefore include a username and an HTTP or HTTPS URI. Operators can instead choose
manual credentials and enter the server themselves.

Vault entries are intentionally excluded from settings archives. Reimport or recreate them after restore.
