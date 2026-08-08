---
title: Services
description: Configure Atlaso-managed infrastructure, identity, storage, and VCF integration services.
audience:
  - operator
status: current
---

# Services

For VCF and ESX credential workflows, start with [Vaults](vaults.md). The guide covers encrypted storage, managed-script
access, Kickstart markers, connection URIs, VCF Helper imports, reveal auditing, and backup/restore behavior.

- [DNS](dns.md)
- [DHCP](dhcp.md)
- [Firewall](firewall.md)
- [NTP](ntp.md)
- [Certificate Authority](certificate-authority.md)
- [ESX storage over NFS](esx-storage.md)
- [ESX network boot and scripted installation](ipxe.md)
- [KMS and KMIP](kms.md)
- [Local users](local-users.md)
- [Managed LDAP](managed-ldap.md)
- [OpenID Connect provider](oidc-provider.md)
- [VCF backups](vcf-backups.md)
- [Vaults](vaults.md)
- [VCF Helper](vcf-helper.md)
- [VCF Offline Depot](vcf-offline-depot.md)
- [VCF Private Registry](vcf-private-registry.md)
- [VCF certificate trust](vcf-trust.md)

Service forms describe desired state. Use each page's Validation card to resolve errors and warnings, then submit valid
units through [Appliance Apply](../operate/appliance-apply.md).
