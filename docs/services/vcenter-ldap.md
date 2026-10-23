---
title: vCenter OpenLDAP login with Atlaso
description: Configure and verify a vCenter Server OpenLDAP identity source backed by Atlaso Managed LDAP.
audience:
  - operator
status: current
---

# vCenter OpenLDAP login with Atlaso

Use Atlaso Managed LDAP as a native OpenLDAP identity source for vCenter Server Single Sign-On. This guide covers
LDAP password authentication for directory users. It does not configure the Atlaso OpenID Connect provider or
federation through VCF Operations Identity Broker; that separate interoperability path remains unvalidated and is not
required for direct LDAP login.

## Before you begin

- Use a supported vCenter Server release with an administrator who can add identity sources and assign permissions.
- Keep a working `administrator@vsphere.local` vCenter Single Sign-On administrator session available for recovery. Do not
  remove or change the `vsphere.local` identity source while setting up LDAP.
- In Atlaso, enable Managed LDAP and create an enabled organization with an enabled user and password. Set or reset the
  user's password if it has not been applied. The vCenter bind identity is read-only and scoped to that organization.
- Confirm the Atlaso appliance hostname, LDAPS listener address, firewall path, and DNS record from the systems where
  vCenter resolves and connects. Use the hostname covered by the LDAP server certificate. The example below uses
  `ldap.lab.example.test` at private address `192.168.50.53`; replace both with your own values.
- Keep the CA certificate chain available if the vCenter wizard asks you to provide trust material. Verify the chain
  and hostname through your normal certificate process; do not bypass a certificate warning.
- If you use Atlaso's KMIP service, retain its provider and trust configuration. LDAP identity-source setup and
  cleanup do not configure or rotate KMIP keys or certificates.

Atlaso stores each organization under an isolated suffix. For an organization named **Engineering** with slug
`engineering`, the service presents these values:

| Purpose | Example |
| --- | --- |
| Organization suffix | `dc=engineering,dc=ldap,dc=atlaso,dc=internal` |
| Users base | `ou=users,dc=engineering,dc=ldap,dc=atlaso,dc=internal` |
| vCenter groups base | `ou=vcenter-groups,dc=engineering,dc=ldap,dc=atlaso,dc=internal` |
| Read-only bind DN | `uid=vcf-bind,ou=service-accounts,dc=engineering,dc=ldap,dc=atlaso,dc=internal` |

Use the values displayed for the selected organization on Atlaso's **Managed LDAP** page. Do not guess a suffix or use
the VCF groups base in the vCenter configuration.

## Apply LDAP and its dependencies

1. In Atlaso, open **Managed LDAP** and select the organization. Confirm the user is enabled and has a password staged
   for apply. The page shows **Users base**, **vCenter groups base**, and **VCF bind DN**.
2. Make sure LDAPS is enabled and the service hostname resolves to the intended listener address from vCenter. Atlaso
   publishes its managed LDAP certificate and firewall rules through Appliance Apply. The certificate must be valid
   for the hostname used in the vCenter server URL.
3. Open **Review appliance changes**. Review **Managed LDAP** and any required **Certificate Authority**, **DNS/DHCP**,
   or **Firewall** dependencies. Clear unrelated, valid changes so they remain pending; required dependencies remain
   selected and locked by Atlaso.
4. Choose **Submit appliance changes** and wait for the LDAP and required dependency components to complete. Resolve
   failures from the component result before configuring vCenter.

The Apply task is global even when this run contains only Managed LDAP and its required dependencies. Applying the
LDAP unit publishes the saved user, bind identity, and vCenter group projections. A successful Atlaso save by itself
does not update the OpenLDAP service.

## Add the OpenLDAP identity source

In the vSphere Client, open **Administration > Single Sign-On > Configuration > Identity Sources**, then select
**Add Identity Source**. Some vCenter releases place the same page under **Administration > Configuration > Identity
Sources**. Choose **OpenLDAP** as the identity source type; do not choose **Active Directory over LDAP** for Atlaso's
OpenLDAP directory. Broadcom documents the OpenLDAP fields and the LDAPS identity-source flow in its [vCenter LDAPS
configuration guide](https://knowledge.broadcom.com/external/article/411071/error-null-or-empty-values-when-vcenter.html).

Use these values, substituting the effective hostname and organization values shown by Atlaso:

| vCenter field | Example value |
| --- | --- |
| Identity Source Type | `OpenLDAP` |
| Name | `Atlaso Engineering` |
| Domain name | `engineering.ldap.example.test` (the identity-source login suffix, distinct from the server hostname) |
| Domain alias, when shown | `engineering` (a unique short login alias) |
| Primary server URL | `ldaps://ldap.lab.example.test:636` |
| Base DN for users | `ou=users,dc=engineering,dc=ldap,dc=atlaso,dc=internal` |
| Base DN for groups | `ou=vcenter-groups,dc=engineering,dc=ldap,dc=atlaso,dc=internal` |
| Username / Bind DN | `uid=vcf-bind,ou=service-accounts,dc=engineering,dc=ldap,dc=atlaso,dc=internal` |
| Password | The current organization bind password from your secret manager |
| User name attribute, when shown | `uid` |

The wizard's exact labels and certificate controls vary by vCenter version. For any additional OpenLDAP search fields,
use the RFC4519 schema and Atlaso's displayed bases; do not copy Active Directory attribute names such as
`sAMAccountName`. Atlaso's vCenter group entries use `groupOfUniqueNames` and `uniqueMember`; use your vCenter
release's OpenLDAP guidance for any group-search setting, then test group discovery independently. If the wizard
requests an LDAPS certificate, provide the appropriate trusted CA/certificate chain using the process for that vCenter
release. Check that its server URL hostname appears in the certificate SAN and that the certificate is current; see
Broadcom's [vSphere LDAPS guidance](https://knowledge.broadcom.com/external/article/316596/single-signon-identity-source-configura.html).

Submit the identity source and confirm vCenter accepts the configuration. Avoid changing an existing identity source
that other permissions depend on. If replacing one, first record its name, domain, and permissions; Broadcom notes that
the exact identity-source name can matter when preserving assignments.

## Assign and verify least-privilege access

Test with one enabled Atlaso LDAP user. Start with a narrow inventory object and the built-in **Read-only** role.
Select **Propagate to children** only for the subtree that user needs to inspect. Do not grant Administrator while
validating sign-in.

1. In vCenter's **Permissions** view for the chosen inventory object, add the test user from the `Atlaso Engineering`
   identity source, assign **Read-only**, and set **Propagate to children** for that selected scope.
2. Keep the administrator session open. In a separate private browser session, sign in using the LDAP
   username and configured identity-source domain (for example, `alice@engineering.ldap.example.test`), along with the
   user's LDAP password. Use the domain alias only where the vCenter version supports it.
3. Confirm the user can view only the expected inventory scope. Then sign out and confirm the `administrator@vsphere.local`
   administrator can still sign in.

The recorded lab verification for this direct-user path used a vCenter API login on Server `9.1.1`, build `25712839`,
with an LDAP user assigned **Read-only** and **Propagate to children**. This verifies direct-user authentication for
that API path; verify vSphere Client sign-in for your deployment as well. A successful user login does not verify
vCenter group discovery, nested membership, or group-based authorization.

Atlaso publishes two group layouts to preserve consumer compatibility. The existing `ou=groups` subtree uses
`groupOfNames` with `member` and remains the VCF Automation representation. The separate `ou=vcenter-groups` subtree
uses `groupOfUniqueNames` with `uniqueMember`, and stable server-managed `entryUUID` values, for vCenter's OpenLDAP
schema expectations. Apply synchronizes those projections without replacing the VCF entries. Broadcom's [OpenLDAP
schema article](https://knowledge.broadcom.com/external/article?legacyId=2064977) lists its documented vCenter versions
through 8.x; it does not establish group interoperability for 9.x. Keep user login and group-based authorization as
separate acceptance checks. Do not grant production permissions through LDAP groups until your target vCenter version
has passed explicit group-picker and authorization tests. See [group compatibility issue #1009](https://github.com/mdaneri/Atlaso/issues/1009)
for the schema-change background.

## Rotate the bind password

Treat bind rotation as a coordinated change because vCenter stores its own copy of the bind credential.

1. In **Managed LDAP**, choose **Rotate bind credential** for the organization. Store the one-time generated value in
   your approved secret manager before closing the result.
2. Open **Review appliance changes**, select **Managed LDAP** and any locked dependencies, and submit the global Apply.
   Wait for the LDAP component to succeed.
3. Edit the vCenter identity source and replace its bind password with the newly applied value. Save, then verify the
   identity source can search the user base and authenticate the test user.
4. Keep the `vsphere.local` administrator session open until LDAP login and permission checks pass.

If vCenter can no longer query LDAP, sign in with `administrator@vsphere.local` and update the identity source bind password
to the current Atlaso organization credential. If the saved credential is unavailable, rotate it again in Atlaso,
apply **Managed LDAP**, then update vCenter with the new value. Do not delete the identity source as a first recovery
step.

## Remove the identity source or organization

To stop using LDAP in vCenter, first sign in with `administrator@vsphere.local`, remove or replace the LDAP identity source
and its LDAP-based permissions in vCenter, and verify local administrator access again. Removing a vCenter source
does not remove Atlaso's LDAP organization. Existing LDAP identities can no longer authenticate through that source;
review any permissions that referenced those identities before removal.

Before deleting an Atlaso organization, export its separate passphrase-encrypted LDAP recovery archive from
**Backup / Restore** if its directory data may be needed. Delete or migrate vCenter permissions that use its users or
groups, then remove the organization in Atlaso and submit global **Review appliance changes** / **Submit appliance
changes** for Managed LDAP and required dependencies. Deleting an LDAP organization does not delete or rotate the
`vsphere.local` administrator or KMIP provider data. Retain the administrator and KMIP recovery material under their
own recovery procedures.

## Troubleshoot

| Symptom | Checks |
| --- | --- |
| vCenter cannot add or connect to the source | Confirm vCenter resolves the configured hostname to the intended address, TCP/636 is reachable, LDAPS is enabled, the certificate is trusted and current, and the certificate SAN matches the hostname. Confirm the global LDAP Apply completed. |
| Bind or search fails | Use the exact **VCF bind DN** shown by Atlaso and the current applied bind password. Check the users and vCenter groups bases against the selected organization. Re-enter the credential after rotation. |
| User is not found | Confirm the Atlaso user is enabled, has an applied password, and lies under the configured users base. Use OpenLDAP and `uid`; do not select Active Directory over LDAP or expect `sAMAccountName`. |
| User can sign in but cannot use expected permissions | Check the permission principal's identity-source suffix and assigned inventory scope. Verify direct user permission first. Group discovery and authorization require separate version-specific tests. |
| Apply fails | Open the failed Apply component result and resolve the Managed LDAP or required dependency validation before retrying. See [Apply appliance changes](../operate/appliance-apply.md#recover-from-a-failed-apply). |
| LDAP is unavailable during recovery | Use the retained `administrator@vsphere.local` administrator, restore vCenter's bind credential to Atlaso's current applied value, and inspect the LDAP Apply result and operational logs. Preserve the KMIP service while diagnosing LDAP. |

For Atlaso's organization lifecycle, directory schema, recovery export, and service security boundaries, see [Managed LDAP](managed-ldap.md).
