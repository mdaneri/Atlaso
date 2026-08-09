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
reviewable phases. Phase 4 completes its administration and lifecycle surfaces. Provider enablement requires the exact
service-owned issuer, an addressed access or routed listener, its applied CA-managed certificate, an active RS256 key,
and protocol readiness.

OIDC discovery, authorization, token, user-info, and key endpoints under `/identity` are protocol routes documented in
this guide. They remain operational and are intentionally absent from Swagger; only OIDC administration operations
under `/api/v1` belong to the generated REST contract.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso OpenID Connect provider status with right-column service settings.](../assets/screenshots/authentication-clean-desktop.webp)

*Figure: OIDC provider status and issuer information with service settings in the right column.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Architecture and trust boundaries

The canonical issuer is derived as `https://<oidc-hostname>[:port]/identity`; the default hostname is
`oidc.atlaso.internal` and port 443 is omitted. It is never inferred from `Host`, `Forwarded`, or `X-Forwarded-*`
request headers. IP issuers, query strings, fragments, user information, and path or trailing-slash variants are
rejected. Readiness parses the issued CA-managed `oidc:https` certificate and requires its DNS SAN to cover the exact
hostname and its IP SANs to cover every selected listener address. Global Appliance Apply installs that certificate,
the restricted nginx listener, DNS records, and firewall rules.

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
redirect URI reported by its Identity Broker. The client wizard requires at least one redirect URI and validates every
redirect and optional post-logout URI before advancing; the service repeats the same authoritative validation when the
client is submitted.

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
Editing a client invalidates its pending authorization transactions, and code issuance independently rechecks the
client's current enabled state, organization, exact redirect, and granted scopes.

`/identity/authorize`, `/identity/token`, `/identity/userinfo`, and `/identity/logout` require HTTPS. A forwarded HTTPS
indication is trusted only from a loopback proxy whose listener-address header matches the configured OIDC service
addresses. Requests received through the management listener are rejected. Browser authentication rotates the OIDC session
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

## Administration and lifecycle

The dedicated **OpenID Connect** navigation page keeps Provider, Clients, Signing Keys, Group Mappings, and Stable
Subjects as tool tabs inside one framed OIDC Administration workspace. The selected tab occupies the main column while
the editable Provider Settings and Validation cards remain available in the right-hand service settings column.
Validation lists readiness errors only when attention is required. Provider state autosaves but rejects enablement until
every readiness check passes. The Validation card also opens the redacted public-services nginx configuration at its
truthful staged path so operators can review the OIDC listener before global Appliance Apply.

Provider Settings owns the service hostname, one or more listener interfaces, and HTTPS port. Listener choices use the
same service selector as LDAP: addressed access or routed physical interfaces and enabled VLANs are accepted, while
management, unused, down, missing, trunk-only, and addressless targets are rejected. Addresses are derived rather than
typed. When local DNS is enabled, Atlaso maintains app-owned A or AAAA records for the selected addresses; otherwise
register the same hostname externally. The restricted public-services nginx front door proxies only `/identity/` and
returns 404 for unrelated paths. Listener, DNS, certificate, and firewall desired state becomes active through global
Appliance Apply. Client, key, mapping, and subject lifecycle remains immediate application state.

Confidential clients are browsed in a Tabulator collection. The bottom **+ Add client here** row and existing client
rows open the shared reviewed wizard for creation and editing.
Editing can change the operator label, full-width multiline purpose description, identity-source binding, granted
scopes, exact redirect and post-logout URIs, loopback-development posture, and enabled state. Description stays in the
first identity step. Enablement has its own wizard step before review. It never changes the generated client ID or
exposes the Argon2 secret hash. Creation and secret rotation show plaintext exactly once.

Client row actions provide a redacted relying-party integration download. It contains only issuer and discovery
metadata, public endpoints, client ID, authentication method, granted scopes, exact registered URIs, identity-source
posture, and enabled state. It never includes a client secret, token, authorization code, private key, password,
authenticated URL, or guessed VCF value.

Signing keys use a wizard-backed collection. Rotation atomically activates a new 3072-bit RS256 key and retires the
previous key. A retired key cannot be removed until its enforced publication overlap has elapsed. Stable subjects remain
a read-only collection; mapping edits remain compact row-level autosave using the Physical Interfaces reference.

Operational redaction covers secret-bearing fields, private-key blocks, JWT path values, authenticated URL user
information, and OIDC query parameters such as authorization codes, client secrets, access tokens, and ID token hints.

The rendered administration page is verified at desktop and narrow viewports with no page-level horizontal overflow.
Keyboard activation opens the shared client wizard, focus moves to its first required field and returns to the launch
control, step validation preserves entered values, and status/error regions announce updates. Shared modal focus
containment, labels, fallback tables, and the explicit no-JavaScript read-only state preserve an accessible recovery
path. If an interactive grid cannot initialize, its mutation launcher remains disabled so a one-time client secret or
key result cannot be lost after a server-side change. Collection overflow remains inside its labeled grid region at
narrow widths.

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
disabled defaults. OIDC records created by pre-release development builds have no data-migration contract; take a
SQLite snapshot and reset the OIDC tables when moving those appliances to this lifecycle model. Normal startup still
creates any missing schema before reseeding the disabled provider default.

## Staged rollout and unsupported features

1. Authentication foundation and disabled provider skeleton.
2. Authorization Code flow, browser-session hardening, token issuance, UserInfo, and RP-initiated logout.
3. Organization selection, scope-filtered current-state claims, and explicit local-role/LDAP-group mappings.
4. Administration and lifecycle completion, issuer/applied-certificate validation, centralized redaction, and
   integration export. **Delivered in this phase.**
5. VCF 9.1 interoperability and all acceptance scenarios.

Until the final phase succeeds, Atlaso does not claim VCF OIDC compatibility. The constrained design excludes implicit,
password, device, client-credentials, token-exchange, and dynamic-registration flows; refresh tokens; consent; external
LDAP sources; social/federated identity; SAML; SCIM; wildcard redirects; front-channel logout; and back-channel logout.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Openid Connect: Oidc Group Mappings

![Atlaso OpenID Connect page showing the external group mapping grid at the desktop viewport.](../assets/screenshots/authentication-group-mappings-desktop.webp)

*Figure: OIDC external group mappings in the desktop direct-edit collection.*

![Atlaso OpenID Connect page showing the external group mapping grid at the responsive viewport.](../assets/screenshots/authentication-group-mappings-responsive.webp)

*Figure: OIDC external group mappings in the responsive direct-edit collection.*

### Openid Connect: Oidc Provider

![Atlaso OpenID Connect provider settings stacked with status and issuer information at a narrow viewport.](../assets/screenshots/authentication-clean-responsive.webp)

*Figure: OIDC provider settings with status and issuer information stacked at the responsive viewport.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
