---
title: Constrained OpenID Connect provider
description: Configure Atlaso as a constrained OpenID Connect provider for approved VCF clients.
audience:
  - operator
  - maintainer
status: current
---

# Constrained OpenID Connect provider

Atlaso is delivering an in-process OpenID Connect provider for appliance integrations and VCF lab environments in five
reviewable phases. Phase 3 adds explicit organization selection, current-state claims, and privacy-safe
local-role/LDAP-group mappings to the constrained Authorization Code protocol surface. Provider enablement requires the
applied management HTTPS setting, canonical issuer, active RS256 key, and protocol readiness.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Authentication page in the clean-appliance desktop viewport.](../assets/screenshots/authentication-clean-desktop.webp)

*Figure: Authentication in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Architecture and trust boundaries

The canonical issuer is exactly `https://<applied-appliance-fqdn>/identity`. It is configured from Appliance Settings,
never inferred from `Host`, `Forwarded`, or `X-Forwarded-*` request headers. IP issuers, explicit ports, query strings,
fragments, user information, and path or trailing-slash variants are rejected.

One credential-verification service resolves only two persisted identity types:

- enabled local `User` records, verified through the existing stdin-only Photon password helper with bootstrap
  compatibility; and
- enabled users in enabled Atlaso-managed OpenLDAP organizations.

Managed LDAP means the integrated organizations under `/ldap`; external LDAP sources are outside the design. Before a
bind, the control plane resolves the organization and user from the database and rejects disabled or missing records. It
then calls only `atlaso-helper ldap authenticate <generated-user-dn>`. The helper reads the password from stdin, writes
it to a mode-`0600` temporary file, invokes `ldapwhoami -x -H ldapi:/// -D <dn> -y <file>`, suppresses command output,
and removes the file. Passwords never enter argv, application storage, task or audit payloads, or logs.

Managed LDAP credentials are exposed to OIDC only. They do not create an operator UI session. Existing Atlaso operator
authentication remains local-only.

Each successfully resolved source record receives one opaque UUID in `oidc_subjects`. The UUID links to the database
identity record rather than mutable username, email, display name, DN, hostname, or organization label. Those metadata
changes therefore preserve `sub`. Deleting the source cascades to the subject; recreating the identity creates a new
UUID.

SQLite foreign-key enforcement is enabled on every connection. OIDC child records use explicit cascade or restrict
behavior: redirect records follow their client, subjects follow deletion of their source identity, and an organization
referenced by a client cannot be silently removed.

## Clients, redirects, and secrets

All clients are confidential and use `client_secret_basic`. Client IDs and secrets are generated from cryptographic
randomness. Secrets are stored only as Argon2 hashes and plaintext is returned once on client creation or rotation.
Rotation replaces the hash in the same transaction, so the previous secret is immediately invalid.

Administrators can delete a client from the Authentication page through the shared confirmation modal. Deletion removes
its secret hash and exact redirect records immediately from application state, requires no global appliance apply, and
releases any restrictive organization reference so that a previously bound managed LDAP organization can be deleted
afterward.

Redirect and post-logout records are stored individually. Matching in the protocol phase will be byte-for-byte against
those stored values. Wildcards, fragments, credentials in the authority, control characters, and non-HTTPS redirects are
rejected. An operator can explicitly create a development client using HTTP only on a literal loopback address with an
exact port; the VCF preset never enables that exception. The VCF 9.1 form requires the operator to paste the exact
redirect URI reported by its Identity Broker.

## Signing keys and public metadata

Signing keys are 3072-bit RSA keys fixed to RS256. Atlaso encrypts private PKCS#8 PEM with `ATLASO_SECRETS_KEY` and
stores only a public JWK alongside it. A uniqueness constraint permits one active key. Rotation retires the prior key
and keeps its public JWK publishable for the greater of the configured overlap or the longest ID/access-token lifetime
plus clock skew. The default overlap is one hour.

Discovery and JWKS are published only after the provider passes its enablement validation. The issuer is never derived
from request headers.

Initial protocol defaults are a 60-second authorization code, five-minute ID and access tokens, two-minute clock skew,
RS256, mandatory PKCE S256, and scopes `openid profile email groups`.

## Dependency decision

The runtime lock includes Authlib 1.7.2. RSA/JWK handling remains fixed to `joserfc`, RS256, and an explicit `kid`; no
algorithm negotiation is accepted.

## Authorization Code browser flow

Only `response_type=code`, query response mode, confidential `client_secret_basic`, and PKCE `S256` are accepted. Every
request has an exact stored redirect URI, `state`, `nonce`, and a server-side short-lived authorization transaction
bound to the signed browser session. Codes are random opaque values whose SHA-256 digest is stored; redemption uses one
conditional `UPDATE ... RETURNING` operation, so a code can succeed once even when two token requests race.

`/identity/authorize`, `/identity/token`, `/identity/userinfo`, and `/identity/logout` require HTTPS. A forwarded HTTPS
indication is trusted only from the loopback management proxy. Browser authentication rotates the OIDC session
identifier and CSRF value and never sets an operator UI user session.

An organization-bound client permits only its configured enabled managed-LDAP organization. Its sign-in page names that
organization and contains no source selector; a submitted source value is rejected. An unbound client requires an
explicit **Local** or enabled managed-LDAP organization selection on every interactive sign-in. The server resolves the
exact selection against current persisted state. It never infers a source from a username, so identical usernames in
Local and multiple organizations remain unambiguous, and it never treats a form-provided organization ID as trusted.

ID and access tokens have five-minute lifetimes, client ID audience, and fixed `JWT` / `at+jwt` types. UserInfo validates
the signing key, fixed algorithm, issuer, audience, expiry, client, identity source, organization, and subject against
current database state before returning claims. Disabling a client, managed LDAP source, organization, or user blocks
new authorization and token issuance immediately and makes UserInfo reject an existing access token. Already-issued
JWTs remain bounded by the existing short lifetime. Logout requires a valid ID-token hint for a post-logout redirect and
matches that URI byte-for-byte before returning optional state.

## Claims and external group mappings

Claims are filtered strictly by the scopes granted to the authorization code:

- `openid` supplies required protocol claims such as opaque `sub`, issuer, audience, timestamps, authentication time,
  and nonce.
- `profile` adds `preferred_username`, display `name`, and the selected `organization`.
- `email` adds `email` and always sets `email_verified` to `false`; Atlaso does not verify mailbox ownership.
- `groups` adds a sorted list of explicit external mapping values.

The Authentication page provides a direct-edit mapping grid for local Atlaso roles and managed LDAP groups. A mapping
with no client is the Local or organization default. A client-specific mapping for the same source replaces that
default; it does not append a second name. Local mappings may target only unbound clients. LDAP mappings may target
unbound clients or clients bound to the group's organization. Atlaso rejects duplicate source/scope rows and
case-insensitive collisions among effective external names for every affected client and identity organization.

Local group claims are derived from the user's current normalized Atlaso roles. Managed LDAP group claims use current
enabled direct and nested memberships from the existing cycle-safe group graph. Disabled groups and memberships that no
longer exist stop contributing immediately. Only the configured external strings are emitted. LDAP group names, DNs,
suffixes, bind identities, endpoints, server details, and unmapped names never enter ID tokens, access tokens, UserInfo,
jobs, audits, or logs.

![OIDC external group mapping grid at the desktop viewport](../assets/screenshots/authentication-group-mappings-desktop.webp)

The direct-edit collection keeps source, organization, optional client override, and external name in one compact
workspace. The responsive capture shows the same server-backed mapping contract at the narrow documentation viewport.

![OIDC external group mapping grid at the responsive viewport](../assets/screenshots/authentication-group-mappings-responsive.webp)

## Backup, restore, reset, and key custody

Settings backup includes provider settings, stable subject mappings, confidential-client metadata and Argon2 hashes,
exact redirects, local-role/LDAP-group mappings, and encrypted signing private keys. Mappings use stable archive
references such as organization slug, group name, and public client ID rather than copying database IDs. It never
includes plaintext client secrets or identity passwords. A restored signing key is usable only with the same
`ATLASO_SECRETS_KEY`; preserve that key through the appliance recovery process.

Factory reset deletes provider settings, clients, redirects, subjects, group mappings, and signing keys before reseeding
disabled defaults. Normal database upgrades create the mapping table additively through the existing metadata startup
path; older databases retain their records. Older binaries ignore the new table. Do not destructively drop OIDC tables
during ordinary downgrade. If complete rollback requires their removal, restore the pre-upgrade SQLite snapshot.

## Staged rollout and unsupported features

1. Authentication foundation and disabled provider skeleton.
2. Authorization Code flow, browser-session hardening, token issuance, UserInfo, and RP-initiated logout.
3. Organization selection, scope-filtered current-state claims, and explicit local-role/LDAP-group mappings. **Delivered
   in this phase.**
4. Administration and lifecycle completion, issuer/applied-certificate validation, centralized redaction, and
   integration export.
5. VCF 9.1 interoperability and all acceptance scenarios.

Until the final phase succeeds, Atlaso does not claim VCF OIDC compatibility. The constrained design excludes implicit,
password, device, client-credentials, token-exchange, and dynamic-registration flows; refresh tokens; consent; external
LDAP sources; social/federated identity; SAML; SCIM; wildcard redirects; front-channel logout; and back-channel logout.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Authentication

![Atlaso Authentication page in the clean-appliance responsive viewport.](../assets/screenshots/authentication-clean-responsive.webp)

*Figure: Authentication in the verified clean-appliance responsive state.*

### Authentication: Oidc Group Mappings

![Atlaso Authentication page showing the OIDC external group mapping grid at the desktop viewport.](../assets/screenshots/authentication-group-mappings-desktop.webp)

*Figure: OIDC external group mappings in the desktop direct-edit collection.*

![Atlaso Authentication page showing the OIDC external group mapping grid at the responsive viewport.](../assets/screenshots/authentication-group-mappings-responsive.webp)

*Figure: OIDC external group mappings in the responsive direct-edit collection.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
