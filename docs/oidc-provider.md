# Constrained OpenID Connect provider

LabFoundry is delivering an in-process OpenID Connect provider for appliance integrations and VCF lab environments in five reviewable phases. Phase 2 provides the constrained Authorization Code protocol surface. Provider enablement requires the applied management HTTPS setting, canonical issuer, active RS256 key, and protocol readiness.

## Architecture and trust boundaries

The canonical issuer is exactly `https://<applied-appliance-fqdn>/identity`. It is configured from Appliance Settings, never inferred from `Host`, `Forwarded`, or `X-Forwarded-*` request headers. IP issuers, explicit ports, query strings, fragments, user information, and path or trailing-slash variants are rejected.

One credential-verification service resolves only two persisted identity types:

- enabled local `User` records, verified through the existing stdin-only Photon password helper with bootstrap compatibility; and
- enabled users in enabled LabFoundry-managed OpenLDAP organizations.

Managed LDAP means the integrated organizations under `/ldap`; external LDAP sources are outside the design. Before a bind, the control plane resolves the organization and user from the database and rejects disabled or missing records. It then calls only `labfoundry-helper ldap authenticate <generated-user-dn>`. The helper reads the password from stdin, writes it to a mode-`0600` temporary file, invokes `ldapwhoami -x -H ldapi:/// -D <dn> -y <file>`, suppresses command output, and removes the file. Passwords never enter argv, application storage, task or audit payloads, or logs.

Managed LDAP credentials are exposed to OIDC only. They do not create an operator UI session. Existing LabFoundry operator authentication remains local-only.

Each successfully resolved source record receives one opaque UUID in `oidc_subjects`. The UUID links to the database identity record rather than mutable username, email, display name, DN, hostname, or organization label. Those metadata changes therefore preserve `sub`. Deleting the source cascades to the subject; recreating the identity creates a new UUID.

SQLite foreign-key enforcement is enabled on every connection. OIDC child records use explicit cascade or restrict behavior: redirect records follow their client, subjects follow deletion of their source identity, and an organization referenced by a client cannot be silently removed.

## Clients, redirects, and secrets

All clients are confidential and use `client_secret_basic`. Client IDs and secrets are generated from cryptographic randomness. Secrets are stored only as Argon2 hashes and plaintext is returned once on client creation or rotation. Rotation replaces the hash in the same transaction, so the previous secret is immediately invalid.

Administrators can delete a client from the Authentication page through the shared confirmation modal. Deletion removes its secret hash and exact redirect records immediately from application state, requires no global appliance apply, and releases any restrictive organization reference so that a previously bound managed LDAP organization can be deleted afterward.

Redirect and post-logout records are stored individually. Matching in the protocol phase will be byte-for-byte against those stored values. Wildcards, fragments, credentials in the authority, control characters, and non-HTTPS redirects are rejected. An operator can explicitly create a development client using HTTP only on a literal loopback address with an exact port; the VCF preset never enables that exception. The VCF 9.1 form requires the operator to paste the exact redirect URI reported by its Identity Broker.

## Signing keys and public metadata

Signing keys are 3072-bit RSA keys fixed to RS256. LabFoundry encrypts private PKCS#8 PEM with `LABFOUNDRY_SECRETS_KEY` and stores only a public JWK alongside it. A uniqueness constraint permits one active key. Rotation retires the prior key and keeps its public JWK publishable for the greater of the configured overlap or the longest ID/access-token lifetime plus clock skew. The default overlap is one hour.

Discovery and JWKS are published only after the provider passes its enablement validation. The issuer is never derived from request headers.

Initial protocol defaults are a 60-second authorization code, five-minute ID and access tokens, two-minute clock skew, RS256, mandatory PKCE S256, and scopes `openid profile email groups`.

## Dependency decision

The runtime lock includes Authlib 1.7.2. RSA/JWK handling remains fixed to `joserfc`, RS256, and an explicit `kid`; no algorithm negotiation is accepted.

## Authorization Code browser flow

Only `response_type=code`, query response mode, confidential `client_secret_basic`, and PKCE `S256` are accepted. Every request has an exact stored redirect URI, `state`, `nonce`, and a server-side short-lived authorization transaction bound to the signed browser session. Codes are random opaque values whose SHA-256 digest is stored; redemption uses one conditional `UPDATE ... RETURNING` operation, so a code can succeed once even when two token requests race.

`/identity/authorize`, `/identity/token`, `/identity/userinfo`, and `/identity/logout` require HTTPS. A forwarded HTTPS indication is trusted only from the loopback management proxy. Browser authentication rotates the OIDC session identifier and CSRF value and never sets an operator UI user session. Unbound clients permit local identities only; an organization-bound client permits only its fixed enabled managed-LDAP organization.

ID and access tokens have five-minute lifetimes, client ID audience, and fixed `JWT` / `at+jwt` types. UserInfo validates the signing key, fixed algorithm, issuer, audience, expiry, source, organization and subject before returning claims. Logout requires a valid ID-token hint for a post-logout redirect and matches that URI byte-for-byte before returning optional state.

## Backup, restore, reset, and key custody

Settings backup includes provider settings, stable subject mappings, confidential-client metadata and Argon2 hashes, exact redirects, and encrypted signing private keys. It never includes plaintext client secrets or identity passwords. A restored signing key is usable only with the same `LABFOUNDRY_SECRETS_KEY`; preserve that key through the appliance recovery process.

Factory reset deletes provider settings, clients, redirects, subjects, and signing keys before reseeding disabled defaults. Normal database upgrades are additive: older binaries ignore the new tables. Do not destructively drop OIDC tables during ordinary downgrade. If complete rollback requires their removal, restore the pre-upgrade SQLite snapshot.

## Staged rollout and unsupported features

1. Authentication foundation and disabled provider skeleton.
2. Authorization Code flow, browser-session hardening, token issuance, UserInfo, and RP-initiated logout.
3. Organization selection, scope-filtered claims, and explicit local-role/LDAP-group mappings.
4. Administration and lifecycle completion, issuer/applied-certificate validation, centralized redaction, and integration export.
5. VCF 9.1 interoperability and all acceptance scenarios.

Until the final phase succeeds, LabFoundry does not claim VCF OIDC compatibility. The constrained design excludes implicit, password, device, client-credentials, token-exchange, and dynamic-registration flows; refresh tokens; consent; external LDAP sources; social/federated identity; SAML; SCIM; wildcard redirects; front-channel logout; and back-channel logout.
