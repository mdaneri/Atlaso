from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
from hashlib import sha256
from ipaddress import ip_address, ip_interface
import json
import re
from secrets import token_urlsafe
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from authlib import __version__ as AUTHLIB_VERSION
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session, selectinload

from atlaso.app.models import (
    ApplianceSettings,
    CaCertificate,
    DnsRecord,
    DnsSettings,
    LdapGroup,
    LdapGroupMembership,
    LdapOrganization,
    LdapSettings,
    LdapUser,
    OidcClient,
    OidcClientRedirectUri,
    OidcAuthorizationCode,
    OidcAuthorizationTransaction,
    OidcGroupMapping,
    OidcProviderSettings,
    OidcSigningKey,
    OidcSubject,
    PhysicalInterface,
    Role,
    Setting,
    User,
    VlanInterface,
    utcnow,
)
from atlaso.app.security import user_roles
from atlaso.app.secrets import encrypt_secret
from atlaso.app.secrets import decrypt_secret
from atlaso.app.services.identity_credentials import VerifiedIdentity, ensure_oidc_subject
from atlaso.app.services.appliance_settings import normalize_fqdn
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces
from atlaso.app.services.networking import normalize_interface_mode, normalize_interface_role


OIDC_ISSUER_PATH = "/identity"
OIDC_SCOPES = ("openid", "profile", "email", "groups")
OIDC_SIGNING_ALGORITHM = "RS256"
OIDC_TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_basic"
OIDC_AUTHORIZATION_FLOW_AVAILABLE = True
OIDC_TOKEN_LIFETIME_SECONDS = 300
OIDC_DEFAULT_HOSTNAME = "oidc.atlaso.internal"
OIDC_DEFAULT_PORT = 443
OIDC_DNS_RECORD_DESCRIPTION = "Created from OpenID Connect provider endpoint."
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


def expected_issuer_url(
    provider: OidcProviderSettings | None = None,
    *,
    hostname: str = OIDC_DEFAULT_HOSTNAME,
    port: int = OIDC_DEFAULT_PORT,
) -> str:
    fqdn = normalize_fqdn(provider.hostname if provider is not None else hostname)
    if not fqdn:
        return ""
    listener_port = int(provider.port if provider is not None else port)
    authority = fqdn if listener_port == 443 else f"{fqdn}:{listener_port}"
    return f"https://{authority}{OIDC_ISSUER_PATH}"


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
    if port is not None and not 1 <= port <= 65535:
        raise OidcConfigurationError("Issuer URL port must be between 1 and 65535.")
    if parsed.path != OIDC_ISSUER_PATH:
        raise OidcConfigurationError(f"Issuer URL path must be exactly {OIDC_ISSUER_PATH}.")
    if parsed.query or parsed.fragment:
        raise OidcConfigurationError("Issuer URL must not contain a query string or fragment.")
    authority = hostname if port in {None, 443} else f"{hostname}:{port}"
    return f"https://{authority}{OIDC_ISSUER_PATH}"


def ensure_provider_settings(db: Session) -> OidcProviderSettings:
    row = db.execute(select(OidcProviderSettings)).scalar_one_or_none()
    if row is None:
        row = OidcProviderSettings()
        db.add(row)
        db.flush()
    normalized_hostname = normalize_fqdn(row.hostname or OIDC_DEFAULT_HOSTNAME)
    if row.hostname != normalized_hostname:
        row.hostname = normalized_hostname
    expected = expected_issuer_url(row)
    if row.issuer_url != expected:
        row.issuer_url = expected
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
    errors: list[str] = []
    try:
        normalized = normalize_issuer_url(provider.issuer_url)
    except OidcConfigurationError as exc:
        errors.append(str(exc))
        normalized = ""
    expected = expected_issuer_url(provider)
    if normalized and normalized != expected:
        errors.append("Issuer URL must exactly match the OIDC hostname, HTTPS port, and /identity path.")
    if not provider.hostname or "." not in normalize_fqdn(provider.hostname):
        errors.append("OIDC hostname must be a fully qualified DNS name.")
    dns_settings = db.execute(select(DnsSettings)).scalar_one_or_none()
    if dns_settings and dns_settings.enabled:
        managed_dns_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == normalize_fqdn(provider.hostname),
                DnsRecord.description == OIDC_DNS_RECORD_DESCRIPTION,
                DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]),
                DnsRecord.enabled.is_(True),
            )
        ).first()
        if managed_dns_record is None:
            errors.append(
                "OIDC local DNS requires an app-owned record for the service hostname."
            )
    if not split_interfaces(provider.listen_interface):
        errors.append("OIDC requires at least one access or routed listen interface.")
    if not split_addresses(provider.listen_address):
        errors.append("OIDC listen interfaces must have at least one configured IP address.")
    selected_interfaces = split_interfaces(provider.listen_interface)
    selected_addresses = split_addresses(provider.listen_address)
    valid_targets = _valid_oidc_listener_targets(db)
    if selected_interfaces and any(name not in valid_targets for name in selected_interfaces):
        errors.append(
            "OIDC listener interfaces must be addressed access or routed physical interfaces or enabled VLANs."
        )
    derived_addresses: list[str] = []
    for name in selected_interfaces:
        for address in valid_targets.get(name, []):
            if address not in derived_addresses:
                derived_addresses.append(address)
    if selected_addresses and selected_addresses != derived_addresses:
        errors.append(
            "OIDC listener addresses must be derived from the selected interfaces."
        )
    if not 1 <= int(provider.port or 0) <= 65535:
        errors.append("OIDC HTTPS port must be between 1 and 65535.")
    certificate = db.execute(
        select(CaCertificate).where(CaCertificate.managed_owner == "oidc:https")
    ).scalar_one_or_none()
    if not (
        certificate
        and certificate.status == "issued"
        and certificate.certificate_pem
        and certificate.private_key_encrypted
    ):
        errors.append("OIDC requires an applied managed certificate for its service hostname and listener addresses.")
    else:
        try:
            parsed_certificate = x509.load_pem_x509_certificate(
                certificate.certificate_pem.encode("utf-8")
            )
            subject_alt_names = parsed_certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            dns_names = {
                normalize_fqdn(value)
                for value in subject_alt_names.get_values_for_type(x509.DNSName)
            }
            ip_addresses = {
                str(value)
                for value in subject_alt_names.get_values_for_type(x509.IPAddress)
            }
            if normalize_fqdn(provider.hostname) not in dns_names:
                errors.append(
                    "The applied OIDC service certificate does not cover the exact issuer hostname."
                )
            if set(split_addresses(provider.listen_address)) - ip_addresses:
                errors.append(
                    "The applied OIDC service certificate does not cover every selected listener address."
                )
        except (ValueError, x509.ExtensionNotFound):
            errors.append("The applied OIDC service certificate is not valid.")
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


def _valid_oidc_listener_targets(db: Session) -> dict[str, list[str]]:
    physical = db.execute(
        select(PhysicalInterface).order_by(PhysicalInterface.name)
    ).scalars().all()
    vlans = db.execute(
        select(VlanInterface).where(VlanInterface.enabled.is_(True))
    ).scalars().all()
    physical_by_name = {row.name: row for row in physical}
    targets: dict[str, list[str]] = {}

    def addresses(*cidrs: str | None) -> list[str]:
        values: list[str] = []
        for cidr in cidrs:
            if not cidr:
                continue
            try:
                value = str(ip_interface(cidr).ip)
            except ValueError:
                continue
            if value not in values:
                values.append(value)
        return values

    for row in physical:
        role = normalize_interface_role(row.role)
        mode = normalize_interface_mode(row.mode)
        row_addresses = addresses(
            row.host_ip_cidr if row.ipv4_method == "dhcp" else row.ip_cidr,
            row.ipv6_cidr or row.host_ipv6_cidr,
        )
        if (
            row.oper_state == "missing"
            or row.admin_state == "down"
            or role in {"management", "unused"}
            or mode == "trunk"
            or not row_addresses
        ):
            continue
        targets[row.name] = row_addresses
    for row in vlans:
        parent = physical_by_name.get(row.parent_interface)
        role = normalize_interface_role(row.role)
        row_addresses = addresses(row.ip_cidr, row.ipv6_cidr)
        if (
            (parent and (parent.oper_state == "missing" or parent.admin_state == "down"))
            or role in {"management", "unused"}
            or not row_addresses
        ):
            continue
        targets[row.name] = row_addresses
    return targets


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


def _management_certificate_error(db: Session, appliance: ApplianceSettings) -> str:
    """Return a public-safe readiness error for the applied management certificate."""

    fqdn = normalize_fqdn(appliance.fqdn)
    certificate = db.execute(
        select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")
    ).scalar_one_or_none()
    if (
        certificate is None
        or certificate.status != "issued"
        or not certificate.enabled
        or not certificate.certificate_pem
    ):
        return "The applied Management HTTPS certificate is not available for OIDC issuer validation."
    try:
        parsed = x509.load_pem_x509_certificate(certificate.certificate_pem.encode("utf-8"))
        current_fingerprint = parsed.fingerprint(hashes.SHA256()).hex()
        now = datetime.now(timezone.utc)
        if parsed.not_valid_before_utc > now or parsed.not_valid_after_utc <= now:
            return "The applied Management HTTPS certificate is not currently valid."
        try:
            names = {
                normalize_fqdn(value)
                for value in parsed.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            }
        except x509.ExtensionNotFound:
            names = {
                normalize_fqdn(attribute.value)
                for attribute in parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            }
    except (TypeError, ValueError, x509.InvalidVersion):
        return "The applied Management HTTPS certificate cannot be validated."
    if current_fingerprint != _applied_management_certificate_fingerprint(db):
        return "The current Management HTTPS certificate has not been applied."
    if fqdn not in names:
        return "The applied Management HTTPS certificate does not cover the exact OIDC issuer FQDN."
    return ""


def _applied_management_certificate_fingerprint(db: Session) -> str:
    row = db.execute(
        select(Setting).where(Setting.key == "appliance_apply.baselines.v1")
    ).scalar_one_or_none()
    if row is None:
        return ""
    try:
        baselines = json.loads(row.value)
        preview = json.loads(baselines["ca"]["config_preview"])
        certificates = preview["certificates"]
    except (KeyError, TypeError, json.JSONDecodeError):
        return ""
    for certificate in certificates:
        if (
            isinstance(certificate, dict)
            and certificate.get("managed_owner") == "appliance:https"
        ):
            return str(certificate.get("fingerprint") or "").strip().lower()
    return ""


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
        "claims_supported": [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "preferred_username",
            "name",
            "organization",
            "email",
            "email_verified",
            "groups",
        ],
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


def delete_retired_signing_key(
    db: Session,
    row: OidcSigningKey,
    *,
    now: datetime | None = None,
) -> None:
    if row.status == "active" or row.active_slot is not None:
        raise OidcConflictError("The active OIDC signing key cannot be deleted; rotate it first.")
    if row.status != "retired" or row.publish_until is None:
        raise OidcConflictError("Only a retired OIDC signing key can be deleted.")
    if _aware(row.publish_until) > (now or utcnow()):
        raise OidcConflictError(
            "The retired OIDC signing key must remain published until its overlap window ends."
        )
    db.delete(row)
    db.flush()


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
    validate_all_mapping_contexts(db)
    return get_client(db, row.id), raw_secret


def update_client(
    db: Session,
    *,
    row: OidcClient,
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
) -> OidcClient:
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

    # An administrator can remove a redirect, scope, source, or the client itself
    # while a browser is waiting at the sign-in page.  Never let that request
    # survive a client-policy edit with its older permissions.
    db.execute(
        delete(OidcAuthorizationTransaction).where(
            OidcAuthorizationTransaction.oidc_client_id == row.id
        )
    )
    row.name = normalized_name
    row.organization_id = organization.id if organization else None
    row.allowed_scopes = " ".join(scopes)
    row.access_token_lifetime_seconds = access_token_lifetime_seconds
    row.id_token_lifetime_seconds = id_token_lifetime_seconds
    row.authorization_code_lifetime_seconds = authorization_code_lifetime_seconds
    row.allow_loopback_redirects = allow_loopback_redirects
    row.enabled = enabled
    row.updated_at = utcnow()
    for redirect in list(row.redirect_uris):
        db.delete(redirect)
    db.flush()
    for uri in normalized_redirects:
        db.add(OidcClientRedirectUri(oidc_client_id=row.id, kind="redirect", uri=uri))
    for uri in normalized_logout_redirects:
        db.add(OidcClientRedirectUri(oidc_client_id=row.id, kind="post_logout", uri=uri))
    db.flush()
    validate_all_mapping_contexts(db)
    db.expire(row, ["redirect_uris", "organization"])
    return get_client(db, row.id)


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


def integration_export(db: Session, row: OidcClient) -> dict[str, object]:
    """Build a public-metadata-only relying-party configuration document."""

    provider = ensure_provider_settings(db)
    urls = issuer_endpoint_urls(provider.issuer_url)
    client = oidc_client_to_dict(row)
    return {
        "issuer": urls["issuer"],
        "discovery_url": urls["discovery_url"],
        "authorization_endpoint": urls["authorization_endpoint"],
        "token_endpoint": urls["token_endpoint"],
        "userinfo_endpoint": urls["userinfo_endpoint"],
        "jwks_uri": urls["jwks_uri"],
        "end_session_endpoint": urls["end_session_endpoint"],
        "client_id": row.client_id,
        "token_endpoint_auth_method": row.token_endpoint_auth_method,
        "allowed_scopes": client["allowed_scopes"],
        "redirect_uris": client["redirect_uris"],
        "post_logout_redirect_uris": client["post_logout_redirect_uris"],
        "organization": row.organization.slug if row.organization else "explicit-source-selection",
        "enabled": row.enabled,
    }


def managed_ldap_source_enabled(db: Session) -> bool:
    settings = db.execute(select(LdapSettings)).scalar_one_or_none()
    return bool(settings and settings.enabled)


def enabled_login_organizations(db: Session) -> list[LdapOrganization]:
    if not managed_ldap_source_enabled(db):
        return []
    return list(
        db.execute(
            select(LdapOrganization)
            .where(LdapOrganization.enabled.is_(True))
            .order_by(LdapOrganization.name, LdapOrganization.id)
        ).scalars()
    )


def resolve_login_source(
    db: Session,
    *,
    client: OidcClient,
    selection: str,
) -> tuple[str, int | None]:
    """Resolve only a server-recognized source choice for this client."""
    if client.organization_id is not None:
        if selection:
            raise OidcConfigurationError("Bound clients do not accept an organization selection.")
        organization = db.get(LdapOrganization, client.organization_id)
        if (
            organization is None
            or not organization.enabled
            or not managed_ldap_source_enabled(db)
        ):
            raise OidcConfigurationError("The client authentication source is disabled.")
        return "managed_ldap", organization.id
    if selection == "local":
        return "local", None
    prefix = "managed_ldap:"
    organization_value = selection.removeprefix(prefix)
    if not selection.startswith(prefix) or not organization_value.isdigit():
        raise OidcConfigurationError("Select Local or an enabled managed LDAP organization.")
    organization_id = int(organization_value)
    if organization_id not in {row.id for row in enabled_login_organizations(db)}:
        raise OidcConfigurationError("Select Local or an enabled managed LDAP organization.")
    return "managed_ldap", organization_id


def identity_permitted_for_client(
    db: Session,
    *,
    client: OidcClient,
    identity: VerifiedIdentity,
) -> bool:
    if not client.enabled:
        return False
    if client.organization_id is not None:
        return bool(
            identity.source == "managed_ldap"
            and identity.organization_id == client.organization_id
            and managed_ldap_source_enabled(db)
            and (
                (organization := db.get(LdapOrganization, client.organization_id))
                is not None
                and organization.enabled
            )
        )
    if identity.source == "local":
        return identity.organization_id is None
    if identity.source != "managed_ldap" or identity.organization_id is None:
        return False
    organization = db.get(LdapOrganization, identity.organization_id)
    return bool(
        managed_ldap_source_enabled(db)
        and organization is not None
        and organization.enabled
    )


def _mapping_key(
    *,
    source_type: str,
    local_role: str,
    ldap_group_id: int | None,
    organization_id: int | None,
    oidc_client_id: int | None,
) -> str:
    scope = f"client:{oidc_client_id}" if oidc_client_id is not None else "default"
    if source_type == "local_role":
        return f"{scope}:local_role:{local_role.casefold()}"
    return f"{scope}:organization:{organization_id}:ldap_group:{ldap_group_id}"


def _normalize_external_group_name(value: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 160
        or any(ord(character) < 0x20 for character in normalized)
    ):
        raise OidcConfigurationError(
            "External group names must contain 1-160 printable characters."
        )
    return normalized


def list_group_mappings(db: Session) -> list[OidcGroupMapping]:
    return list(
        db.execute(
            select(OidcGroupMapping)
            .options(
                selectinload(OidcGroupMapping.ldap_group),
                selectinload(OidcGroupMapping.organization),
                selectinload(OidcGroupMapping.client),
            )
            .order_by(
                OidcGroupMapping.organization_id,
                OidcGroupMapping.oidc_client_id,
                OidcGroupMapping.source_type,
                OidcGroupMapping.local_role,
                OidcGroupMapping.id,
            )
        ).scalars()
    )


def group_mapping_to_dict(row: OidcGroupMapping) -> dict[str, object]:
    source_name = (
        row.local_role
        if row.source_type == "local_role"
        else (row.ldap_group.name if row.ldap_group is not None else "")
    )
    return {
        "id": row.id,
        "source_type": row.source_type,
        "source_name": source_name,
        "local_role": row.local_role,
        "ldap_group_id": row.ldap_group_id,
        "organization_id": row.organization_id,
        "organization_name": row.organization.name if row.organization is not None else "Local",
        "oidc_client_id": row.oidc_client_id,
        "oidc_client_name": row.client.name if row.client is not None else "",
        "external_group_name": row.external_group_name,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _mapping_source_key(row: OidcGroupMapping) -> str:
    if row.source_type == "local_role":
        return f"local_role:{row.local_role.casefold()}"
    return f"ldap_group:{row.ldap_group_id}"


def _effective_mapping_rows(
    db: Session,
    *,
    client: OidcClient | None,
    source: str,
    organization_id: int | None,
) -> dict[str, OidcGroupMapping]:
    rows = list_group_mappings(db)
    relevant: list[OidcGroupMapping]
    if source == "local":
        relevant = [
            row
            for row in rows
            if row.source_type == "local_role" and row.organization_id is None
        ]
    else:
        relevant = [
            row
            for row in rows
            if row.source_type == "ldap_group"
            and row.organization_id == organization_id
        ]
    effective = {
        _mapping_source_key(row): row
        for row in relevant
        if row.oidc_client_id is None
    }
    if client is not None:
        effective.update(
            {
                _mapping_source_key(row): row
                for row in relevant
                if row.oidc_client_id == client.id
            }
        )
    return effective


def _validate_effective_mapping_rows(rows: dict[str, OidcGroupMapping]) -> None:
    names: dict[str, str] = {}
    for source_key, row in rows.items():
        normalized_name = row.external_group_name.casefold()
        existing_source = names.get(normalized_name)
        if existing_source is not None and existing_source != source_key:
            raise OidcConfigurationError(
                "Effective external group names must be unique case-insensitively "
                "for each client and organization."
            )
        names[normalized_name] = source_key


def validate_all_mapping_contexts(db: Session) -> None:
    clients = list_clients(db)
    _validate_effective_mapping_rows(
        _effective_mapping_rows(
            db,
            client=None,
            source="local",
            organization_id=None,
        )
    )
    for client in clients:
        if client.organization_id is None:
            _validate_effective_mapping_rows(
                _effective_mapping_rows(
                    db,
                    client=client,
                    source="local",
                    organization_id=None,
                )
            )
    organizations = list(
        db.execute(select(LdapOrganization).order_by(LdapOrganization.id)).scalars()
    )
    for organization in organizations:
        _validate_effective_mapping_rows(
            _effective_mapping_rows(
                db,
                client=None,
                source="managed_ldap",
                organization_id=organization.id,
            )
        )
        for client in clients:
            if client.organization_id in {None, organization.id}:
                _validate_effective_mapping_rows(
                    _effective_mapping_rows(
                        db,
                        client=client,
                        source="managed_ldap",
                        organization_id=organization.id,
                    )
                )


def create_group_mapping(
    db: Session,
    *,
    source_type: str,
    local_role: str,
    ldap_group_id: int | None,
    oidc_client_id: int | None,
    external_group_name: str,
    validate_effective_contexts: bool = True,
) -> OidcGroupMapping:
    client = get_client(db, oidc_client_id) if oidc_client_id is not None else None
    normalized_role = local_role.strip().casefold()
    organization_id: int | None = None
    group: LdapGroup | None = None
    if source_type == "local_role":
        if normalized_role not in {role.value for role in Role} or ldap_group_id is not None:
            raise OidcConfigurationError("Select one supported local Atlaso role.")
        if client is not None and client.organization_id is not None:
            raise OidcConfigurationError(
                "Local role overrides are valid only for unbound OIDC clients."
            )
    elif source_type == "ldap_group":
        if normalized_role or ldap_group_id is None:
            raise OidcConfigurationError("Select one managed LDAP group.")
        group = db.get(LdapGroup, ldap_group_id)
        if group is None:
            raise OidcConfigurationError("Managed LDAP group not found.")
        organization_id = group.organization_id
        if (
            client is not None
            and client.organization_id is not None
            and client.organization_id != organization_id
        ):
            raise OidcConfigurationError(
                "A client override must use a group from its bound organization."
            )
    else:
        raise OidcConfigurationError("Unsupported OIDC group mapping source.")
    mapping_key = _mapping_key(
        source_type=source_type,
        local_role=normalized_role,
        ldap_group_id=group.id if group is not None else None,
        organization_id=organization_id,
        oidc_client_id=client.id if client is not None else None,
    )
    if db.execute(
        select(OidcGroupMapping).where(OidcGroupMapping.mapping_key == mapping_key)
    ).scalar_one_or_none():
        raise OidcConflictError(
            "A mapping already exists for this source and mapping scope."
        )
    row = OidcGroupMapping(
        mapping_key=mapping_key,
        source_type=source_type,
        local_role=normalized_role,
        ldap_group_id=group.id if group is not None else None,
        organization_id=organization_id,
        oidc_client_id=client.id if client is not None else None,
        external_group_name=_normalize_external_group_name(external_group_name),
        updated_at=utcnow(),
    )
    db.add(row)
    db.flush()
    if validate_effective_contexts:
        validate_all_mapping_contexts(db)
    return db.execute(
        select(OidcGroupMapping)
        .where(OidcGroupMapping.id == row.id)
        .options(
            selectinload(OidcGroupMapping.ldap_group),
            selectinload(OidcGroupMapping.organization),
            selectinload(OidcGroupMapping.client),
        )
    ).scalar_one()


def update_group_mapping(
    db: Session,
    *,
    row: OidcGroupMapping,
    oidc_client_id: int | None,
    external_group_name: str,
) -> OidcGroupMapping:
    client = get_client(db, oidc_client_id) if oidc_client_id is not None else None
    if row.source_type == "local_role":
        if client is not None and client.organization_id is not None:
            raise OidcConfigurationError(
                "Local role overrides are valid only for unbound OIDC clients."
            )
    elif row.source_type == "ldap_group":
        if (
            client is not None
            and client.organization_id is not None
            and client.organization_id != row.organization_id
        ):
            raise OidcConfigurationError(
                "A client override must use a group from its bound organization."
            )
    else:
        raise OidcConfigurationError("Unsupported OIDC group mapping source.")
    mapping_key = _mapping_key(
        source_type=row.source_type,
        local_role=row.local_role,
        ldap_group_id=row.ldap_group_id,
        organization_id=row.organization_id,
        oidc_client_id=client.id if client is not None else None,
    )
    conflict = db.execute(
        select(OidcGroupMapping).where(
            OidcGroupMapping.mapping_key == mapping_key,
            OidcGroupMapping.id != row.id,
        )
    ).scalar_one_or_none()
    if conflict is not None:
        raise OidcConflictError(
            "A mapping already exists for this source and mapping scope."
        )
    row.mapping_key = mapping_key
    row.oidc_client_id = client.id if client is not None else None
    row.external_group_name = _normalize_external_group_name(external_group_name)
    row.updated_at = utcnow()
    db.add(row)
    db.flush()
    validate_all_mapping_contexts(db)
    return db.execute(
        select(OidcGroupMapping)
        .where(OidcGroupMapping.id == row.id)
        .options(
            selectinload(OidcGroupMapping.ldap_group),
            selectinload(OidcGroupMapping.organization),
            selectinload(OidcGroupMapping.client),
        )
    ).scalar_one()


def _resolved_enabled_ldap_group_ids(db: Session, user: LdapUser) -> set[int]:
    groups = {
        row.id: row
        for row in db.execute(
            select(LdapGroup).where(
                LdapGroup.organization_id == user.organization_id,
                LdapGroup.enabled.is_(True),
            )
        ).scalars()
    }
    memberships = list(
        db.execute(
            select(LdapGroupMembership).where(
                LdapGroupMembership.group_id.in_(groups)
            )
        ).scalars()
    )
    resolved = {
        membership.group_id
        for membership in memberships
        if membership.member_user_id == user.id and membership.group_id in groups
    }
    parents: dict[int, set[int]] = {}
    for membership in memberships:
        if (
            membership.member_group_id in groups
            and membership.group_id in groups
        ):
            parents.setdefault(int(membership.member_group_id), set()).add(
                membership.group_id
            )
    pending = list(resolved)
    while pending:
        current = pending.pop()
        for parent_id in parents.get(current, set()):
            if parent_id not in resolved:
                resolved.add(parent_id)
                pending.append(parent_id)
    return resolved


def mapped_external_groups(
    db: Session,
    *,
    client: OidcClient,
    identity: VerifiedIdentity,
) -> list[str]:
    effective = _effective_mapping_rows(
        db,
        client=client,
        source=identity.source,
        organization_id=identity.organization_id,
    )
    _validate_effective_mapping_rows(effective)
    selected_source_keys: set[str] = set()
    if identity.source == "local":
        user = db.get(User, identity.source_record_id)
        if user is None or not user.enabled or user.auth_provider != "local":
            raise OidcConfigurationError("Identity is disabled.")
        selected_source_keys = {
            f"local_role:{role.casefold()}" for role in user_roles(user)
        }
    elif identity.source == "managed_ldap":
        user = db.get(LdapUser, identity.source_record_id)
        if user is None or not user.enabled:
            raise OidcConfigurationError("Identity is disabled.")
        selected_source_keys = {
            f"ldap_group:{group_id}"
            for group_id in _resolved_enabled_ldap_group_ids(db, user)
        }
    names = [
        row.external_group_name
        for source_key, row in effective.items()
        if source_key in selected_source_keys
    ]
    return sorted(names, key=str.casefold)


def scoped_identity_claims(
    db: Session,
    *,
    client: OidcClient,
    identity: VerifiedIdentity,
    scopes: str,
) -> dict[str, object]:
    granted = set(scopes.split())
    claims: dict[str, object] = {}
    if "profile" in granted:
        claims.update(
            {
                "preferred_username": identity.username,
                "name": identity.display_name,
                "organization": identity.organization_name,
            }
        )
    if "email" in granted:
        claims.update({"email": identity.email, "email_verified": False})
    if "groups" in granted:
        claims["groups"] = mapped_external_groups(
            db,
            client=client,
            identity=identity,
        )
    return claims


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
    now = utcnow()
    db.execute(
        delete(OidcAuthorizationTransaction).where(
            OidcAuthorizationTransaction.expires_at <= now
        )
    )
    db.execute(
        delete(OidcAuthorizationCode).where(OidcAuthorizationCode.expires_at <= now)
    )
    row = OidcAuthorizationTransaction(
        transaction_id=_new_opaque_value(), oidc_client_id=client.id, redirect_uri=redirect_uri,
        scopes=" ".join(dict.fromkeys(requested)), state=state, nonce=nonce,
        code_challenge=code_challenge, browser_session_id=browser_session_id, prompt=prompt,
        max_age=max_age, login_hint=login_hint[:240],
        expires_at=now + timedelta(seconds=provider.authorization_code_lifetime_seconds),
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
    if (
        client is None
        or not client.enabled
        or (client.organization and not client.organization.enabled)
    ):
        raise OidcConfigurationError("Unknown or disabled client.")
    current_redirects = {
        redirect.uri for redirect in client.redirect_uris if redirect.kind == "redirect"
    }
    transaction_scopes = set(transaction.scopes.split())
    if (
        transaction.redirect_uri not in current_redirects
        or "openid" not in transaction_scopes
        or not transaction_scopes.issubset(set(client.allowed_scopes.split()))
    ):
        raise OidcConfigurationError("Authorization request expired.")
    current_identity = identity_from_source(
        db,
        source=identity.source,
        source_record_id=identity.source_record_id,
        organization_id=identity.organization_id,
    )
    if (
        current_identity is None
        or not identity_permitted_for_client(
            db,
            client=client,
            identity=current_identity,
        )
    ):
        raise OidcConfigurationError("Identity is not permitted for this client.")
    scoped_identity_claims(
        db,
        client=client,
        identity=current_identity,
        scopes=transaction.scopes,
    )
    raw = _new_opaque_value()
    subject = ensure_oidc_subject(db, current_identity)
    transaction.subject_id = subject.id
    transaction.organization_id = current_identity.organization_id
    transaction.source = current_identity.source
    transaction.auth_time = auth_time
    db.add(OidcAuthorizationCode(
        code_hash=_token_hash(raw), oidc_client_id=client.id, subject_id=subject.id,
        organization_id=current_identity.organization_id, redirect_uri=transaction.redirect_uri,
        scopes=transaction.scopes, state=transaction.state, nonce=transaction.nonce,
        code_challenge=transaction.code_challenge,
        browser_session_id=authenticated_browser_session_id,
        source=current_identity.source,
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
    source_record_id = (
        subject.local_user_id if code.source == "local" else subject.ldap_user_id
    )
    if source_record_id is None:
        raise OidcConfigurationError("Invalid authorization code.")
    identity = identity_from_source(
        db,
        source=code.source,
        source_record_id=source_record_id,
        organization_id=code.organization_id,
    )
    if (
        identity is None
        or not identity_permitted_for_client(db, client=client, identity=identity)
    ):
        raise OidcConfigurationError("Invalid authorization code.")
    identity_claims = scoped_identity_claims(
        db,
        client=client,
        identity=identity,
        scopes=code.scopes,
    )
    now = utcnow(); issued = int(now.timestamp())
    common = {"iss": normalize_issuer_url(provider.issuer_url), "sub": subject.subject_uuid, "aud": client.client_id, "iat": issued, "auth_time": int(_aware(code.auth_time).timestamp())}
    id_claims = common | {
        "exp": issued + OIDC_TOKEN_LIFETIME_SECONDS,
        "nonce": code.nonce,
        "client_id": client.client_id,
    } | identity_claims
    access_claims = common | {
        "exp": issued + OIDC_TOKEN_LIFETIME_SECONDS,
        "scope": code.scopes,
        "client_id": client.client_id,
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
        if not managed_ldap_source_enabled(db):
            return None
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


def validate_userinfo_claims(
    db: Session,
    claims: dict[str, object],
) -> tuple[OidcSubject, VerifiedIdentity, OidcClient]:
    client = client_by_public_id(db, str(claims.get("client_id") or ""))
    if client is None or not client.enabled:
        raise OidcConfigurationError("Invalid token.")
    subject = db.execute(
        select(OidcSubject).where(OidcSubject.subject_uuid == claims.get("sub"))
    ).scalar_one_or_none()
    if subject is None:
        raise OidcConfigurationError("Invalid token.")
    if subject.local_user_id is not None:
        source = "local"
        source_record_id = subject.local_user_id
        organization_id = None
    elif subject.ldap_user_id is not None:
        source = "managed_ldap"
        source_record_id = subject.ldap_user_id
        ldap_user = db.get(LdapUser, subject.ldap_user_id)
        organization_id = ldap_user.organization_id if ldap_user is not None else None
    else:
        raise OidcConfigurationError("Invalid token.")
    identity = identity_from_source(
        db,
        source=source,
        source_record_id=source_record_id,
        organization_id=organization_id,
    )
    if identity is None:
        raise OidcConfigurationError("Invalid token.")
    if not identity_permitted_for_client(db, client=client, identity=identity):
        raise OidcConfigurationError("Invalid token.")
    return subject, identity, client
