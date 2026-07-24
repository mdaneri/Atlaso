from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
from hashlib import sha256
from ipaddress import ip_address
import json
import re
from secrets import token_urlsafe
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from authlib import __version__ as AUTHLIB_VERSION
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from labfoundry.app.models import (
    ApplianceSettings,
    LdapOrganization,
    LdapUser,
    OidcClient,
    OidcClientRedirectUri,
    OidcAuthorizationCode,
    OidcAuthorizationTransaction,
    OidcProviderSettings,
    OidcSigningKey,
    OidcSubject,
    Setting,
    User,
    utcnow,
)
from labfoundry.app.secrets import encrypt_secret
from labfoundry.app.secrets import decrypt_secret
from labfoundry.app.services.identity_credentials import VerifiedIdentity, ensure_oidc_subject
from labfoundry.app.services.appliance_settings import normalize_fqdn


OIDC_ISSUER_PATH = "/identity"
OIDC_SCOPES = ("openid", "profile", "email", "groups")
OIDC_SIGNING_ALGORITHM = "RS256"
OIDC_TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_basic"
OIDC_AUTHORIZATION_FLOW_AVAILABLE = True
OIDC_TOKEN_LIFETIME_SECONDS = 300
OIDC_PKCE_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
OIDC_CODE_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
OIDC_CLIENT_SECRET_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


class OidcConfigurationError(ValueError):
    pass


class OidcConflictError(RuntimeError):
    pass


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _appliance_settings(db: Session) -> ApplianceSettings:
    row = db.execute(select(ApplianceSettings)).scalar_one_or_none()
    if row is None:
        row = ApplianceSettings()
        db.add(row)
        db.flush()
    return row


def expected_issuer_url(appliance: ApplianceSettings) -> str:
    fqdn = normalize_fqdn(appliance.fqdn)
    if not fqdn:
        return ""
    return f"https://{fqdn}{OIDC_ISSUER_PATH}"


def normalize_issuer_url(value: str) -> str:
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise OidcConfigurationError("Issuer URL is not valid.") from exc
    if parsed.scheme.lower() != "https":
        raise OidcConfigurationError("Issuer URL must use HTTPS.")
    if parsed.username or parsed.password:
        raise OidcConfigurationError("Issuer URL must not contain user information.")
    if not parsed.hostname:
        raise OidcConfigurationError("Issuer URL must contain a DNS hostname.")
    try:
        ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise OidcConfigurationError("Issuer URL must use a configured FQDN, not an IP address.")
    hostname = normalize_fqdn(parsed.hostname)
    if not hostname or "." not in hostname:
        raise OidcConfigurationError("Issuer URL must contain a fully qualified DNS name.")
    if port is not None:
        raise OidcConfigurationError("Issuer URL must not contain an explicit port.")
    if parsed.path != OIDC_ISSUER_PATH:
        raise OidcConfigurationError(f"Issuer URL path must be exactly {OIDC_ISSUER_PATH}.")
    if parsed.query or parsed.fragment:
        raise OidcConfigurationError("Issuer URL must not contain a query string or fragment.")
    return f"https://{hostname}{OIDC_ISSUER_PATH}"


def ensure_provider_settings(db: Session) -> OidcProviderSettings:
    row = db.execute(select(OidcProviderSettings)).scalar_one_or_none()
    if row is None:
        row = OidcProviderSettings(issuer_url=expected_issuer_url(_appliance_settings(db)))
        db.add(row)
        db.flush()
    return row


def active_signing_key(db: Session) -> OidcSigningKey | None:
    return db.execute(
        select(OidcSigningKey).where(
            OidcSigningKey.status == "active",
            OidcSigningKey.active_slot == 1,
        )
    ).scalar_one_or_none()


def provider_validation_errors(
    db: Session,
    provider: OidcProviderSettings | None = None,
    *,
    require_active_key: bool = True,
) -> list[str]:
    provider = provider or ensure_provider_settings(db)
    appliance = _appliance_settings(db)
    errors: list[str] = []
    try:
        normalized = normalize_issuer_url(provider.issuer_url)
    except OidcConfigurationError as exc:
        errors.append(str(exc))
        normalized = ""
    expected = expected_issuer_url(appliance)
    if normalized and normalized != expected:
        errors.append(
            "Issuer URL must exactly match the configured Appliance Settings FQDN and /identity path."
        )
    if not appliance.management_https_enabled:
        errors.append("Management HTTPS must be enabled before the OIDC provider can be enabled.")
    elif not _management_https_is_applied(db, appliance):
        errors.append("Management HTTPS and the issuer FQDN must be applied before the OIDC provider can be enabled.")
    if require_active_key and active_signing_key(db) is None:
        errors.append("Generate an active OIDC signing key before enabling the provider.")
    elif require_active_key:
        signing_key = active_signing_key(db)
        try:
            public_jwk = json.loads(signing_key.public_jwk_json) if signing_key else {}
            if (
                signing_key is None
                or signing_key.algorithm != OIDC_SIGNING_ALGORITHM
                or public_jwk.get("kid") != signing_key.kid
                or public_jwk.get("alg") != OIDC_SIGNING_ALGORITHM
            ):
                raise ValueError
            RSAKey.import_key(decrypt_secret(signing_key.private_key_encrypted))
        except Exception:
            errors.append("The active OIDC signing key is not protocol-ready.")
    if provider.access_token_lifetime_seconds != OIDC_TOKEN_LIFETIME_SECONDS:
        errors.append("OIDC access tokens must use the fixed five-minute lifetime.")
    if provider.id_token_lifetime_seconds != OIDC_TOKEN_LIFETIME_SECONDS:
        errors.append("OIDC ID tokens must use the fixed five-minute lifetime.")
    if AUTHLIB_VERSION != "1.7.2":
        errors.append("OIDC protocol readiness requires Authlib 1.7.2.")
    return errors


def _management_https_is_applied(db: Session, appliance: ApplianceSettings) -> bool:
    row = db.execute(
        select(Setting).where(Setting.key == "appliance_apply.baselines.v1")
    ).scalar_one_or_none()
    if row is None:
        return False
    try:
        baselines = json.loads(row.value)
        preview = json.loads(baselines["appliance_settings"]["config_preview"])
    except (KeyError, TypeError, json.JSONDecodeError):
        return False
    return bool(
        preview.get("management_https_enabled") is True
        and normalize_fqdn(str(preview.get("fqdn") or "")) == normalize_fqdn(appliance.fqdn)
        and bool(preview.get("management_https_cert_path"))
        and bool(preview.get("management_https_key_path"))
    )


def validate_enabled_provider_at_startup(db: Session) -> None:
    provider = db.execute(select(OidcProviderSettings)).scalar_one_or_none()
    if provider is None or not provider.enabled:
        return
    errors = provider_validation_errors(db, provider)
    if not OIDC_AUTHORIZATION_FLOW_AVAILABLE:
        errors.append(
            "This build contains only the OIDC protocol skeleton; the authorization flow is not available."
        )
    if errors:
        raise RuntimeError("OIDC provider startup validation failed: " + " ".join(errors))


def issuer_endpoint_urls(issuer_url: str) -> dict[str, str]:
    issuer = normalize_issuer_url(issuer_url)
    return {
        "issuer": issuer,
        "discovery_url": f"{issuer}/.well-known/openid-configuration",
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks",
        "end_session_endpoint": f"{issuer}/logout",
    }


def discovery_document(db: Session) -> dict[str, object]:
    if not OIDC_AUTHORIZATION_FLOW_AVAILABLE:
        raise OidcConfigurationError("OIDC provider is disabled.")
    provider = ensure_provider_settings(db)
    if not provider.enabled:
        raise OidcConfigurationError("OIDC provider is disabled.")
    errors = provider_validation_errors(db, provider)
    if errors:
        raise OidcConfigurationError(" ".join(errors))
    urls = issuer_endpoint_urls(provider.issuer_url)
    return {
        "issuer": urls["issuer"],
        "authorization_endpoint": urls["authorization_endpoint"],
        "token_endpoint": urls["token_endpoint"],
        "userinfo_endpoint": urls["userinfo_endpoint"],
        "jwks_uri": urls["jwks_uri"],
        "end_session_endpoint": urls["end_session_endpoint"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [OIDC_SIGNING_ALGORITHM],
        "token_endpoint_auth_methods_supported": [OIDC_TOKEN_ENDPOINT_AUTH_METHOD],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": list(OIDC_SCOPES),
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce"],
        "claims_parameter_supported": False,
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
    }


def jwks_document(db: Session, *, now: datetime | None = None) -> dict[str, list[dict[str, object]]]:
    if not OIDC_AUTHORIZATION_FLOW_AVAILABLE:
        raise OidcConfigurationError("OIDC provider is disabled.")
    provider = ensure_provider_settings(db)
    if not provider.enabled:
        raise OidcConfigurationError("OIDC provider is disabled.")
    errors = provider_validation_errors(db, provider)
    if errors:
        raise OidcConfigurationError(" ".join(errors))
    current = now or utcnow()
    rows = db.execute(select(OidcSigningKey).order_by(OidcSigningKey.created_at)).scalars().all()
    keys: list[dict[str, object]] = []
    for row in rows:
        publish = row.status == "active"
        if row.status == "retired" and row.publish_until is not None:
            publish = _aware(row.publish_until) > current
        if not publish:
            continue
        public_jwk = json.loads(row.public_jwk_json)
        keys.append(public_jwk)
    return {"keys": keys}


def generate_signing_key(
    db: Session,
    *,
    rotate: bool,
    now: datetime | None = None,
) -> tuple[OidcSigningKey, OidcSigningKey | None]:
    current_time = now or utcnow()
    provider = ensure_provider_settings(db)
    previous = active_signing_key(db)
    if previous is not None and not rotate:
        raise OidcConflictError("An active OIDC signing key already exists; use the rotation action.")
    if previous is not None:
        longest_client_lifetime = max(
            (
                max(client.access_token_lifetime_seconds, client.id_token_lifetime_seconds)
                for client in db.execute(select(OidcClient)).scalars().all()
            ),
            default=0,
        )
        minimum_overlap = max(
            provider.access_token_lifetime_seconds,
            provider.id_token_lifetime_seconds,
            longest_client_lifetime,
        ) + provider.clock_skew_seconds
        previous.status = "retired"
        previous.active_slot = None
        previous.retired_at = current_time
        previous.publish_until = current_time + timedelta(
            seconds=max(provider.signing_key_overlap_seconds, minimum_overlap)
        )
        db.add(previous)
        db.flush()

    generated = RSAKey.generate_key(
        key_size=3072,
        parameters={"alg": OIDC_SIGNING_ALGORITHM, "use": "sig"},
        private=True,
        auto_kid=True,
    )
    if not generated.kid:
        raise RuntimeError("OIDC signing key generation did not produce a key identifier.")
    private_pem = generated.as_pem(private=True).decode("ascii")
    public_jwk = generated.as_dict(private=False)
    row = OidcSigningKey(
        kid=generated.kid,
        algorithm=OIDC_SIGNING_ALGORITHM,
        private_key_encrypted=encrypt_secret(private_pem),
        public_jwk_json=json.dumps(public_jwk, sort_keys=True, separators=(",", ":")),
        status="active",
        active_slot=1,
        created_at=current_time,
        activated_at=current_time,
    )
    db.add(row)
    db.flush()
    return row, previous


def signing_key_to_dict(row: OidcSigningKey) -> dict[str, object]:
    public_jwk = json.loads(row.public_jwk_json)
    return {
        "id": row.id,
        "kid": row.kid,
        "algorithm": row.algorithm,
        "status": row.status,
        "key_type": public_jwk.get("kty"),
        "created_at": row.created_at,
        "activated_at": row.activated_at,
        "retired_at": row.retired_at,
        "publish_until": row.publish_until,
    }


def generate_client_id() -> str:
    return f"lf_oidc_{token_urlsafe(24)}"


def generate_client_secret() -> str:
    return token_urlsafe(48)


def hash_client_secret(raw_secret: str) -> str:
    return OIDC_CLIENT_SECRET_HASHER.hash(raw_secret)


def verify_client_secret(secret_hash: str, raw_secret: str) -> bool:
    try:
        return OIDC_CLIENT_SECRET_HASHER.verify(secret_hash, raw_secret)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def normalize_allowed_scopes(scopes: list[str]) -> list[str]:
    normalized: list[str] = []
    for scope in scopes:
        value = scope.strip()
        if value and value not in normalized:
            normalized.append(value)
    unknown = set(normalized) - set(OIDC_SCOPES)
    if unknown:
        raise OidcConfigurationError(f"Unsupported OIDC scopes: {', '.join(sorted(unknown))}.")
    if "openid" not in normalized:
        raise OidcConfigurationError("OIDC clients must allow the openid scope.")
    return [scope for scope in OIDC_SCOPES if scope in normalized]


def validate_redirect_uri(uri: str, *, allow_loopback: bool) -> str:
    if not uri or uri != uri.strip():
        raise OidcConfigurationError("Redirect URIs must not be blank or contain surrounding whitespace.")
    if "*" in uri:
        raise OidcConfigurationError("Wildcard redirect URIs are not supported.")
    if "\\" in uri or any(ord(character) < 0x20 for character in uri):
        raise OidcConfigurationError("Redirect URI contains an invalid character.")
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError as exc:
        raise OidcConfigurationError("Redirect URI is not valid.") from exc
    if parsed.username or parsed.password:
        raise OidcConfigurationError("Redirect URIs must not contain user information.")
    if not parsed.hostname or not parsed.netloc:
        raise OidcConfigurationError("Redirect URIs must be absolute.")
    if parsed.fragment:
        raise OidcConfigurationError("Redirect URIs must not contain fragments.")
    if parsed.scheme.lower() == "https":
        return uri
    if parsed.scheme.lower() != "http" or not allow_loopback:
        raise OidcConfigurationError("Redirect URIs must use HTTPS.")
    try:
        loopback = ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = False
    if not loopback or port is None:
        raise OidcConfigurationError(
            "HTTP redirect URIs are allowed only for explicit loopback development clients with a port."
        )
    return uri


def validate_redirect_uri_list(
    values: list[str],
    *,
    allow_loopback: bool,
    required: bool,
) -> list[str]:
    if required and not values:
        raise OidcConfigurationError("At least one exact redirect URI is required.")
    normalized = [validate_redirect_uri(value, allow_loopback=allow_loopback) for value in values]
    if len(set(normalized)) != len(normalized):
        raise OidcConfigurationError("Duplicate redirect URIs are not allowed.")
    return normalized


def get_client(db: Session, client_id: int) -> OidcClient:
    row = db.execute(
        select(OidcClient)
        .where(OidcClient.id == client_id)
        .options(selectinload(OidcClient.redirect_uris), selectinload(OidcClient.organization))
    ).scalar_one_or_none()
    if row is None:
        raise OidcConfigurationError("OIDC client not found.")
    return row


def create_client(
    db: Session,
    *,
    name: str,
    organization_id: int | None,
    redirect_uris: list[str],
    post_logout_redirect_uris: list[str],
    allowed_scopes: list[str],
    allow_loopback_redirects: bool,
    access_token_lifetime_seconds: int,
    id_token_lifetime_seconds: int,
    authorization_code_lifetime_seconds: int,
    enabled: bool,
) -> tuple[OidcClient, str]:
    normalized_name = name.strip()
    if not normalized_name:
        raise OidcConfigurationError("OIDC client name is required.")
    organization = None
    if organization_id is not None:
        organization = db.get(LdapOrganization, organization_id)
        if organization is None or not organization.enabled:
            raise OidcConfigurationError("Bound OIDC client organization must exist and be enabled.")
    normalized_redirects = validate_redirect_uri_list(
        redirect_uris,
        allow_loopback=allow_loopback_redirects,
        required=True,
    )
    normalized_logout_redirects = validate_redirect_uri_list(
        post_logout_redirect_uris,
        allow_loopback=allow_loopback_redirects,
        required=False,
    )
    scopes = normalize_allowed_scopes(allowed_scopes)
    raw_secret = generate_client_secret()
    row = OidcClient(
        name=normalized_name,
        client_id=generate_client_id(),
        client_secret_hash=hash_client_secret(raw_secret),
        organization_id=organization.id if organization else None,
        allowed_scopes=" ".join(scopes),
        token_endpoint_auth_method=OIDC_TOKEN_ENDPOINT_AUTH_METHOD,
        access_token_lifetime_seconds=access_token_lifetime_seconds,
        id_token_lifetime_seconds=id_token_lifetime_seconds,
        authorization_code_lifetime_seconds=authorization_code_lifetime_seconds,
        allow_loopback_redirects=allow_loopback_redirects,
        enabled=enabled,
        updated_at=utcnow(),
    )
    db.add(row)
    db.flush()
    for uri in normalized_redirects:
        db.add(OidcClientRedirectUri(oidc_client_id=row.id, kind="redirect", uri=uri))
    for uri in normalized_logout_redirects:
        db.add(OidcClientRedirectUri(oidc_client_id=row.id, kind="post_logout", uri=uri))
    db.flush()
    return get_client(db, row.id), raw_secret


def rotate_client_secret(db: Session, row: OidcClient) -> str:
    raw_secret = generate_client_secret()
    row.client_secret_hash = hash_client_secret(raw_secret)
    row.updated_at = utcnow()
    db.add(row)
    db.flush()
    return raw_secret


def oidc_client_to_dict(row: OidcClient) -> dict[str, object]:
    redirects = [item.uri for item in row.redirect_uris if item.kind == "redirect"]
    logout_redirects = [item.uri for item in row.redirect_uris if item.kind == "post_logout"]
    return {
        "id": row.id,
        "name": row.name,
        "client_id": row.client_id,
        "organization_id": row.organization_id,
        "organization_slug": row.organization.slug if row.organization else None,
        "redirect_uris": redirects,
        "post_logout_redirect_uris": logout_redirects,
        "allowed_scopes": row.allowed_scopes.split(),
        "token_endpoint_auth_method": row.token_endpoint_auth_method,
        "access_token_lifetime_seconds": row.access_token_lifetime_seconds,
        "id_token_lifetime_seconds": row.id_token_lifetime_seconds,
        "authorization_code_lifetime_seconds": row.authorization_code_lifetime_seconds,
        "allow_loopback_redirects": row.allow_loopback_redirects,
        "enabled": row.enabled,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def list_clients(db: Session) -> list[OidcClient]:
    return list(
        db.execute(
            select(OidcClient)
            .options(selectinload(OidcClient.redirect_uris), selectinload(OidcClient.organization))
            .order_by(OidcClient.name, OidcClient.id)
        ).scalars()
    )


def list_subjects(db: Session) -> list[dict[str, object]]:
    local_users = {row.id: row for row in db.execute(select(User)).scalars().all()}
    ldap_users = {
        row.id: row
        for row in db.execute(
            select(LdapUser).options(selectinload(LdapUser.organization))
        ).scalars().all()
    }
    output: list[dict[str, object]] = []
    for row in db.execute(select(OidcSubject).order_by(OidcSubject.created_at, OidcSubject.id)).scalars():
        if row.local_user_id is not None and row.local_user_id in local_users:
            user = local_users[row.local_user_id]
            output.append(
                {
                    "subject": row.subject_uuid,
                    "source": "local",
                    "username": user.username,
                    "organization_id": None,
                    "organization_name": "Local",
                    "created_at": row.created_at,
                }
            )
        elif row.ldap_user_id is not None and row.ldap_user_id in ldap_users:
            user = ldap_users[row.ldap_user_id]
            output.append(
                {
                    "subject": row.subject_uuid,
                    "source": "managed_ldap",
                    "username": user.uid,
                    "organization_id": user.organization_id,
                    "organization_name": user.organization.name,
                    "created_at": row.created_at,
                }
            )
    return output


def protocol_provider(db: Session) -> OidcProviderSettings:
    provider = ensure_provider_settings(db)
    if not provider.enabled:
        raise OidcConfigurationError("OIDC provider is disabled.")
    errors = provider_validation_errors(db, provider)
    if errors:
        raise OidcConfigurationError(" ".join(errors))
    return provider


def _token_hash(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _new_opaque_value() -> str:
    return token_urlsafe(48)


def client_by_public_id(db: Session, client_id: str) -> OidcClient | None:
    return db.execute(
        select(OidcClient).where(OidcClient.client_id == client_id).options(
            selectinload(OidcClient.redirect_uris), selectinload(OidcClient.organization)
        )
    ).scalar_one_or_none()


def begin_authorization(
    db: Session, *, client_id: str, redirect_uri: str, scope: str, state: str,
    nonce: str, code_challenge: str, browser_session_id: str, prompt: str,
    max_age: int | None, login_hint: str,
) -> OidcAuthorizationTransaction:
    protocol_provider(db)
    client = client_by_public_id(db, client_id)
    if client is None or not client.enabled or (client.organization and not client.organization.enabled):
        raise OidcConfigurationError("Unknown or disabled client.")
    if redirect_uri not in {row.uri for row in client.redirect_uris if row.kind == "redirect"}:
        raise OidcConfigurationError("Invalid redirect URI.")
    requested = tuple(part for part in scope.split() if part)
    if not requested or "openid" not in requested or not set(requested).issubset(set(client.allowed_scopes.split())):
        raise OidcConfigurationError("Invalid scope.")
    if (
        not state
        or len(state) > 1024
        or not nonce
        or len(nonce) > 1024
        or not OIDC_CODE_CHALLENGE_RE.fullmatch(code_challenge)
        or prompt not in {"none", "login"}
        or (max_age is not None and not 0 <= max_age <= 2_147_483_647)
    ):
        raise OidcConfigurationError("Invalid authorization request.")
    provider = ensure_provider_settings(db)
    row = OidcAuthorizationTransaction(
        transaction_id=_new_opaque_value(), oidc_client_id=client.id, redirect_uri=redirect_uri,
        scopes=" ".join(dict.fromkeys(requested)), state=state, nonce=nonce,
        code_challenge=code_challenge, browser_session_id=browser_session_id, prompt=prompt,
        max_age=max_age, login_hint=login_hint[:240],
        expires_at=utcnow() + timedelta(seconds=provider.authorization_code_lifetime_seconds),
    )
    db.add(row); db.flush()
    return row


def issue_authorization_code(
    db: Session, *, transaction: OidcAuthorizationTransaction, identity: VerifiedIdentity,
    request_browser_session_id: str, authenticated_browser_session_id: str, auth_time: datetime,
) -> str:
    if (
        _aware(transaction.expires_at) <= utcnow()
        or transaction.browser_session_id != request_browser_session_id
    ):
        raise OidcConfigurationError("Authorization request expired.")
    client = db.get(OidcClient, transaction.oidc_client_id)
    if client is None or not client.enabled or (client.organization and not client.organization.enabled):
        raise OidcConfigurationError("Unknown or disabled client.")
    if client.organization_id is None and identity.source != "local":
        raise OidcConfigurationError("Identity is not permitted for this client.")
    if client.organization_id is not None and (identity.source != "managed_ldap" or identity.organization_id != client.organization_id):
        raise OidcConfigurationError("Identity is not permitted for this client.")
    raw = _new_opaque_value()
    subject = ensure_oidc_subject(db, identity)
    transaction.subject_id = subject.id
    transaction.organization_id = identity.organization_id
    transaction.source = identity.source
    transaction.auth_time = auth_time
    db.add(OidcAuthorizationCode(
        code_hash=_token_hash(raw), oidc_client_id=client.id, subject_id=subject.id,
        organization_id=identity.organization_id, redirect_uri=transaction.redirect_uri,
        scopes=transaction.scopes, state=transaction.state, nonce=transaction.nonce,
        code_challenge=transaction.code_challenge,
        browser_session_id=authenticated_browser_session_id,
        source=identity.source,
        auth_time=auth_time,
        expires_at=utcnow() + timedelta(seconds=client.authorization_code_lifetime_seconds),
    ))
    db.delete(transaction); db.flush()
    return raw


def redeem_authorization_code(db: Session, *, raw_code: str, client: OidcClient, redirect_uri: str, verifier: str) -> OidcAuthorizationCode:
    # UPDATE ... RETURNING is the atomic one-use boundary even under concurrent requests.
    if not OIDC_PKCE_RE.fullmatch(verifier):
        raise OidcConfigurationError("Invalid authorization code.")
    challenge = _base64url_sha256(verifier)
    row = db.execute(
        update(OidcAuthorizationCode)
        .where(OidcAuthorizationCode.code_hash == _token_hash(raw_code), OidcAuthorizationCode.oidc_client_id == client.id,
               OidcAuthorizationCode.redirect_uri == redirect_uri, OidcAuthorizationCode.code_challenge == challenge,
               OidcAuthorizationCode.redeemed_at.is_(None), OidcAuthorizationCode.expires_at > utcnow())
        .values(redeemed_at=utcnow()).returning(OidcAuthorizationCode)
    ).scalar_one_or_none()
    if row is None:
        raise OidcConfigurationError("Invalid authorization code.")
    return row


def _base64url_sha256(value: str) -> str:
    return base64.urlsafe_b64encode(sha256(value.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def _sign_token(db: Session, claims: dict[str, object], typ: str) -> str:
    key = active_signing_key(db)
    if key is None or key.algorithm != OIDC_SIGNING_ALGORITHM:
        raise OidcConfigurationError("OIDC signing key unavailable.")
    rsa_key = RSAKey.import_key(decrypt_secret(key.private_key_encrypted))
    return jwt.encode({"alg": OIDC_SIGNING_ALGORITHM, "kid": key.kid, "typ": typ}, claims, rsa_key, algorithms=[OIDC_SIGNING_ALGORITHM])


def issue_tokens(db: Session, *, code: OidcAuthorizationCode, client: OidcClient) -> dict[str, object]:
    provider = protocol_provider(db)
    subject = db.get(OidcSubject, code.subject_id)
    if subject is None:
        raise OidcConfigurationError("Invalid authorization code.")
    now = utcnow(); issued = int(now.timestamp())
    common = {"iss": normalize_issuer_url(provider.issuer_url), "sub": subject.subject_uuid, "aud": client.client_id, "iat": issued, "auth_time": int(_aware(code.auth_time).timestamp())}
    id_claims = common | {
        "exp": issued + OIDC_TOKEN_LIFETIME_SECONDS,
        "nonce": code.nonce,
        "client_id": client.client_id,
    }
    access_claims = common | {
        "exp": issued + OIDC_TOKEN_LIFETIME_SECONDS,
        "scope": code.scopes,
        "client_id": client.client_id,
        "source": code.source,
        "organization_id": code.organization_id,
    }
    return {
        "token_type": "Bearer",
        "expires_in": OIDC_TOKEN_LIFETIME_SECONDS,
        "scope": code.scopes,
        "id_token": _sign_token(db, id_claims, "JWT"),
        "access_token": _sign_token(db, access_claims, "at+jwt"),
    }


def identity_from_source(
    db: Session, *, source: str, source_record_id: int, organization_id: int | None
) -> VerifiedIdentity | None:
    if source == "local":
        user = db.get(User, source_record_id)
        if user is None or not user.enabled or user.auth_provider != "local" or organization_id is not None:
            return None
        return VerifiedIdentity(
            source="local",
            source_record_id=user.id,
            username=user.username,
            display_name=user.external_display_name or user.username,
            email=user.external_email,
            organization_id=None,
            organization_name="Local",
        )
    if source == "managed_ldap":
        user = db.execute(
            select(LdapUser)
            .where(LdapUser.id == source_record_id)
            .options(selectinload(LdapUser.organization))
        ).scalar_one_or_none()
        if (
            user is None
            or not user.enabled
            or user.organization is None
            or not user.organization.enabled
            or user.organization_id != organization_id
        ):
            return None
        return VerifiedIdentity(
            source="managed_ldap",
            source_record_id=user.id,
            username=user.uid,
            display_name=user.display_name or f"{user.given_name} {user.surname}".strip() or user.uid,
            email=user.email,
            organization_id=user.organization_id,
            organization_name=user.organization.name,
        )
    return None


def validate_bearer_token(
    db: Session, raw_token: str, *, expected_typ: str
) -> dict[str, object]:
    if not raw_token or raw_token.count(".") != 2:
        raise OidcConfigurationError("Invalid token.")
    try:
        protected = json.loads(base64.urlsafe_b64decode(raw_token.split(".", 1)[0] + "=="))
    except (ValueError, json.JSONDecodeError):
        raise OidcConfigurationError("Invalid token.") from None
    if protected.get("alg") != OIDC_SIGNING_ALGORITHM or protected.get("typ") != expected_typ:
        raise OidcConfigurationError("Invalid token.")
    kid = protected.get("kid")
    if not isinstance(kid, str) or not kid:
        raise OidcConfigurationError("Invalid token.")
    key = db.execute(select(OidcSigningKey).where(OidcSigningKey.kid == kid)).scalar_one_or_none()
    now = utcnow()
    if key is None or key.algorithm != OIDC_SIGNING_ALGORITHM:
        raise OidcConfigurationError("Invalid token.")
    if key.status != "active" and not (
        key.status == "retired"
        and key.publish_until is not None
        and _aware(key.publish_until) > now
    ):
        raise OidcConfigurationError("Invalid token.")
    try:
        token = jwt.decode(
            raw_token,
            RSAKey.import_key(json.loads(key.public_jwk_json)),
            algorithms=[OIDC_SIGNING_ALGORITHM],
        )
        claims = dict(token.claims)
        provider = protocol_provider(db)
        exp = int(claims.get("exp", 0))
        iat = int(claims.get("iat", 0))
    except Exception:
        raise OidcConfigurationError("Invalid token.") from None
    now_epoch = int(now.timestamp())
    if (
        token.header.get("alg") != OIDC_SIGNING_ALGORITHM
        or token.header.get("kid") != kid
        or token.header.get("typ") != expected_typ
        or claims.get("iss") != normalize_issuer_url(provider.issuer_url)
        or exp <= now_epoch
        or iat > now_epoch + provider.clock_skew_seconds
        or not isinstance(claims.get("aud"), str)
        or claims.get("aud") != claims.get("client_id")
        or not isinstance(claims.get("sub"), str)
    ):
        raise OidcConfigurationError("Invalid token.")
    return claims


def validate_userinfo_claims(db: Session, claims: dict[str, object]) -> OidcSubject:
    client = client_by_public_id(db, str(claims.get("client_id") or ""))
    if client is None or not client.enabled:
        raise OidcConfigurationError("Invalid token.")
    subject = db.execute(
        select(OidcSubject).where(OidcSubject.subject_uuid == claims.get("sub"))
    ).scalar_one_or_none()
    if subject is None:
        raise OidcConfigurationError("Invalid token.")
    source = str(claims.get("source") or "")
    organization_id = claims.get("organization_id")
    if organization_id is not None and not isinstance(organization_id, int):
        raise OidcConfigurationError("Invalid token.")
    source_record_id = subject.local_user_id if source == "local" else subject.ldap_user_id
    if source_record_id is None:
        raise OidcConfigurationError("Invalid token.")
    identity = identity_from_source(
        db,
        source=source,
        source_record_id=source_record_id,
        organization_id=organization_id,
    )
    if identity is None:
        raise OidcConfigurationError("Invalid token.")
    if client.organization_id != identity.organization_id:
        raise OidcConfigurationError("Invalid token.")
    return subject
