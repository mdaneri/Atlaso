---
title: Vaults
description: Store and scope VCF and ESX passwords for Atlaso-managed scripts and ESXi Kickstarts.
audience:
  - operator
status: current
---

# Vaults

Open **VCF Workflows > Vaults** to manage encrypted VCF and ESX passwords. Each named vault appears as a tab containing
a table with **Key**, **Description**, and **Password** columns. Passwords are masked by default. Administrators can use
the eye control to reveal one value for 15 seconds; Atlaso audits the reveal without recording the value and returns it
with browser caching disabled.

Vault keys use lowercase dotted segments, for example `vcf.sddc_manager.admin` or `esx.esx01.root`. Values are encrypted
with the appliance secrets key before database storage. Keep `ATLASO_SECRETS_KEY` with the appliance recovery material.
Each entry may also store up to nine credential-free HTTP, HTTPS, SSH, or SFTP URIs. Add them on the third page of the
entry wizard. Right-click an existing row, or focus it and press **Shift+F10**, to open its context menu. **Edit
password** reopens the entry wizard, **Delete password** uses the shared destructive confirmation, and each configured
URI has its own action. HTTP and HTTPS open in a separate browser tab; SSH and SFTP open the Atlaso Web Terminal and
authenticate with the entry username and password.

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

Choose one vault in the Kickstart editor. The vault-name segment is the selected vault name normalized to lowercase,
with spaces and punctuation replaced by underscores. Reference the entry username and password explicitly:

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

Atlaso resolves vault markers only for an enabled host assigned to that Kickstart. Source, preview, and download views
retain the marker; the dynamic response is not persisted and is returned with `Cache-Control: no-store`. A marker naming
a vault other than the vault selected for the Kickstart fails validation.

## Remote URI security

Do not place credentials in a URI. For SSH and SFTP targets, Atlaso probes the remote host key before decrypting the
entry password and requires the administrator to confirm its SHA-256 fingerprint. Verify that fingerprint out of band.
After confirmation, Atlaso creates a short-lived one-use launch token, rechecks the host key, and performs password
authentication server-side. The password is not sent to the browser, included in the launch URL, or written to the
audit event. An SFTP URI opens an interactive SSH terminal on the same endpoint; file-transfer browsing is not provided.

## VCF Helper import

**VCF Helper > Import passwords into a vault** discovers supported password metadata from a VCF 9 SDDC Manager or VCF
Installer. Confirm the TLS SHA-256 fingerprint out of band, authenticate, select the passwords, and choose a destination
vault. Atlaso re-reads the selected values during the reviewed import and encrypts them immediately. Existing keys are
rotated.

## VCF Helper autofill

VCF Helper remote-connection forms provide an administrator-only **Vault** and **Key** picker. Selecting a key fills
the server from its first HTTP or HTTPS URI and fills its username. The password remains encrypted at rest and is
resolved only by the server when the operator inspects or submits the remote operation. It is never copied into the
password input or included in the page metadata.

The server rejects a key that does not belong to the selected vault and audits each use without the value. A vault
entry intended for VCF Helper should therefore include a username and, when possible, an HTTP or HTTPS URI. Operators
can still enter the server manually when a key has no suitable URI.

Vault entries are intentionally excluded from settings archives. Reimport or recreate them after restore.
