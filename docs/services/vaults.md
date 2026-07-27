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
stderr, but scripts must still treat passwords as secrets and must not transform, print, or transmit them.

## ESXi Kickstarts

Choose one vault in the Kickstart editor, then reference a value with a marker such as:

```text
rootpw {{vault.esx.esx01.root}}
```

Atlaso resolves vault markers only for an enabled host assigned to that Kickstart. Source, preview, and download views
retain the marker; the dynamic response is not persisted and is returned with `Cache-Control: no-store`.

## VCF Helper import

**VCF Helper > Import passwords into a vault** discovers supported password metadata from a VCF 9 SDDC Manager or VCF
Installer. Confirm the TLS SHA-256 fingerprint out of band, authenticate, select the passwords, and choose a destination
vault. Atlaso re-reads the selected values during the reviewed import and encrypts them immediately. Existing keys are
rotated.

Vault entries are intentionally excluded from settings archives. Reimport or recreate them after restore.
