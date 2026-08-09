import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from secrets import compare_digest, token_urlsafe
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.config import Settings, get_settings
from atlaso.app.database import get_db
from atlaso.app.models import ApiToken, Role, Setting, User, utcnow


ALL_SCOPES = {
    "read:dashboard",
    "read:monitoring",
    "read:interfaces",
    "write:interfaces",
    "read:vlans",
    "write:vlans",
    "read:routes",
    "write:routes",
    "read:wan",
    "write:wan",
    "read:firewall",
    "write:firewall",
    "read:dns",
    "write:dns",
    "read:dhcp",
    "write:dhcp",
    "read:ca",
    "write:ca",
    "write:ca-requests",
    "write:ca-revocations",
    "read:kms",
    "write:kms",
    "read:ldap",
    "write:ldap",
    "read:repository",
    "write:repository",
    "read:esxi-pxe",
    "write:esxi-pxe",
    "read:pxe",
    "write:pxe",
    "read:esx-storage",
    "write:esx-storage",
    "read:vcf-registry",
    "write:vcf-registry",
    "read:vcf-backups",
    "write:vcf-backups",
    "read:services",
    "write:services",
    "read:logs",
    "read:audit",
    "write:backup",
    "admin:all",
}

ROLE_SCOPES = {
    Role.ADMIN.value: ALL_SCOPES,
    Role.NETWORK_ADMIN.value: {
        "read:dashboard",
        "read:monitoring",
        "read:interfaces",
        "write:interfaces",
        "read:vlans",
        "write:vlans",
        "read:routes",
        "write:routes",
        "read:wan",
        "write:wan",
        "read:firewall",
        "write:firewall",
        "read:logs",
        "read:audit",
    },
    Role.SERVICE_ADMIN.value: {
        "read:dashboard",
        "read:monitoring",
        "read:dns",
        "write:dns",
        "read:dhcp",
        "write:dhcp",
        "read:ca",
        "write:ca",
        "write:ca-requests",
        "write:ca-revocations",
        "read:kms",
        "write:kms",
        "read:repository",
        "write:repository",
        "read:esxi-pxe",
        "write:esxi-pxe",
        "read:pxe",
        "write:pxe",
        "read:esx-storage",
        "write:esx-storage",
        "read:vcf-registry",
        "write:vcf-registry",
        "read:vcf-backups",
        "write:vcf-backups",
        "read:services",
        "write:services",
        "read:logs",
        "read:audit",
    },
    Role.VIEWER.value: {
        "read:dashboard",
        "read:monitoring",
        "read:interfaces",
        "read:vlans",
        "read:routes",
        "read:wan",
        "read:firewall",
        "read:dns",
        "read:dhcp",
        "read:ca",
        "read:kms",
        "read:repository",
        "read:esxi-pxe",
        "read:pxe",
        "read:esx-storage",
        "read:vcf-registry",
        "read:vcf-backups",
        "read:services",
        "read:logs",
        "read:audit",
    },
    Role.CERTIFICATE_OPERATOR.value: {
        "read:dashboard",
        "read:monitoring",
        "read:ca",
        "write:ca-requests",
        "write:ca-revocations",
        "read:logs",
        "read:audit",
    },
}

VALID_ROLE_VALUES = {role.value for role in Role}
ROLE_PRIORITY = [
    Role.ADMIN.value,
    Role.SERVICE_ADMIN.value,
    Role.NETWORK_ADMIN.value,
    Role.CERTIFICATE_OPERATOR.value,
    Role.VIEWER.value,
]

UI_PATH_SCOPES = [
    ("/vaults", "admin:all", "admin:all"),
    ("/appliance-apply", "admin:all", "admin:all"),
    ("/appliance-update", "admin:all", "admin:all"),
    ("/backup-restore", "admin:all", "admin:all"),
    ("/settings", "admin:all", "admin:all"),
    ("/users", "admin:all", "admin:all"),
    ("/certificate-authority", "admin:all", "admin:all"),
    ("/ca/requests", "write:ca-requests", "write:ca-requests"),
    ("/ca/certificates", "read:ca", "write:ca-revocations"),
    ("/authentication", "read:dashboard", "read:dashboard"),
    ("/physical-interfaces", "read:interfaces", "write:interfaces"),
    ("/vlan-interfaces", "read:vlans", "write:vlans"),
    ("/routes-wan", "read:routes", "write:routes"),
    ("/firewall", "read:firewall", "write:firewall"),
    ("/dns", "read:dns", "write:dns"),
    ("/dhcp", "read:dhcp", "write:dhcp"),
    ("/kms", "read:kms", "write:kms"),
    ("/ldap", "read:ldap", "write:ldap"),
    ("/ntp", "read:services", "write:services"),
    ("/esxi-pxe", "read:esxi-pxe", "write:esxi-pxe"),
    ("/network-boot", "read:pxe", "write:pxe"),
    ("/esx-storage", "read:esx-storage", "write:esx-storage"),
    ("/vcf-trust/root-ca", "read:ca", "write:ca"),
    ("/vcf-trust", "read:dashboard", "write:ca"),
    ("/vcf-helper/trust-root-ca", "read:ca", "write:ca"),
    ("/vcf-helper", "read:dns", "write:dns"),
    ("/vcf-offline-depot", "read:repository", "write:repository"),
    ("/vcf-private-registry", "read:vcf-registry", "write:vcf-registry"),
    ("/vcf-backups", "read:vcf-backups", "write:vcf-backups"),
    ("/services", "read:services", "write:services"),
    ("/logs", "read:logs", "read:logs"),
    ("/dashboard", "read:dashboard", "read:dashboard"),
    ("/monitor", "read:monitoring", "read:monitoring"),
]

bearer_scheme = HTTPBearer(
    auto_error=False,
    bearerFormat="JWT",
    description=(
        "Atlaso API token issued from Authentication. Send the one-time plaintext value in the "
        "`Authorization: Bearer <token>` header and grant only the scopes required by the operation."
    ),
)
SESSION_APPLIANCE_INSTANCE_SETTING_KEY = "appliance.instance_id.v1"
SESSION_APPLIANCE_INSTANCE_SESSION_KEY = "appliance_instance_id"


class Identity:
    def __init__(
        self,
        username: str,
        role: str,
        scopes: set[str],
        roles: list[str] | None = None,
        user_id: int | None = None,
        token_id: int | None = None,
        token_jti: str | None = None,
        auth_type: str = "session",
    ) -> None:
        self.username = username
        self.roles = normalize_roles(roles or [role])
        self.role = primary_role(self.roles)
        self.scopes = scopes
        self.user_id = user_id
        self.token_id = token_id
        self.token_jti = token_jti
        self.auth_type = auth_type

    def can(self, scope: str) -> bool:
        return "admin:all" in self.scopes or scope in self.scopes

    def has_role(self, role: str) -> bool:
        return role in self.roles


def normalize_roles(roles: object, fallback: str = Role.VIEWER.value) -> list[str]:
    if isinstance(roles, str):
        raw_values = [roles]
    elif isinstance(roles, (list, tuple, set)):
        raw_values = [str(role) for role in roles]
    else:
        raw_values = []
    normalized: list[str] = []
    for raw in raw_values:
        value = str(raw or "").strip().lower()
        if value in VALID_ROLE_VALUES and value not in normalized:
            normalized.append(value)
    if not normalized:
        normalized = [fallback if fallback in VALID_ROLE_VALUES else Role.VIEWER.value]
    return sorted(normalized, key=lambda value: ROLE_PRIORITY.index(value) if value in ROLE_PRIORITY else len(ROLE_PRIORITY))


def roles_from_json(value: str | None, fallback: str) -> list[str]:
    if not value:
        return normalize_roles([fallback])
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return normalize_roles([fallback])
    return normalize_roles(parsed, fallback=fallback)


def roles_to_json(roles: list[str]) -> str:
    return json.dumps(normalize_roles(roles))


def user_roles(user: User) -> list[str]:
    roles = roles_from_json(user.roles_json, user.role)
    if user.roles_json != roles_to_json(roles):
        user.roles_json = roles_to_json(roles)
    return roles


def primary_role(roles: list[str]) -> str:
    return normalize_roles(roles)[0]


def scopes_for_roles(roles: list[str]) -> set[str]:
    scopes: set[str] = set()
    for role in normalize_roles(roles):
        scopes.update(ROLE_SCOPES.get(role, set()))
    return ALL_SCOPES if "admin:all" in scopes else scopes


def role_label(roles: list[str]) -> str:
    return ", ".join(normalize_roles(roles))


def hash_token(raw_token: str) -> str:
    return sha256(raw_token.encode("utf-8")).hexdigest()


def create_jwt(
    *,
    subject: str,
    role: str,
    roles: list[str] | None = None,
    scopes: list[str],
    jti: str,
    expires_at: datetime,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    now = utcnow()
    normalized_roles = normalize_roles(roles or [role])
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": subject,
        "role": primary_role(normalized_roles),
        "roles": normalized_roles,
        "scope": " ".join(scopes),
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def create_raw_api_token() -> str:
    return f"lf_{token_urlsafe(36)}"


def ensure_appliance_instance_id(db: Session) -> str:
    setting = db.execute(select(Setting).where(Setting.key == SESSION_APPLIANCE_INSTANCE_SETTING_KEY)).scalar_one_or_none()
    if setting is not None and setting.value.strip():
        return setting.value.strip()

    instance_id = token_urlsafe(24)
    if setting is None:
        setting = Setting(key=SESSION_APPLIANCE_INSTANCE_SETTING_KEY, value=instance_id)
    else:
        setting.value = instance_id
        setting.updated_at = utcnow()
    db.add(setting)
    db.flush()
    return instance_id


def role_allows_scopes(role: str, requested_scopes: set[str]) -> bool:
    allowed = scopes_for_roles(normalize_roles([role]))
    return "admin:all" in allowed or requested_scopes.issubset(allowed)


def roles_allow_scopes(roles: list[str], requested_scopes: set[str]) -> bool:
    allowed = scopes_for_roles(roles)
    return "admin:all" in allowed or requested_scopes.issubset(allowed)


def scopes_from_string(scopes: str) -> set[str]:
    return {scope for scope in scopes.split() if scope}


def require_scope(scope: str):
    def dependency(identity: Annotated[Identity, Depends(get_current_api_identity)]) -> Identity:
        if not identity.can(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {scope}",
            )
        return identity

    return dependency


def require_api_or_session_scope(scope: str):
    def dependency(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
        db: Annotated[Session, Depends(get_db)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> Identity:
        if credentials is not None:
            identity = get_current_api_identity(credentials, db, settings)
        else:
            identity = get_session_identity(request, db)
            if identity is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                supplied = request.headers.get("X-CSRF-Token", "")
                expected = str(request.session.get("csrf_token") or "")
                if not supplied or not expected or not compare_digest(supplied, expected):
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
        if not identity.can(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {scope}",
            )
        return identity

    return dependency


def get_session_identity(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> Identity | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    if request.session.get(SESSION_APPLIANCE_INSTANCE_SESSION_KEY) != ensure_appliance_instance_id(db):
        request.session.clear()
        db.commit()
        return None
    user = db.get(User, user_id)
    if not user or not user.enabled:
        request.session.clear()
        return None
    roles = user_roles(user)
    identity = Identity(
        username=user.username,
        role=primary_role(roles),
        roles=roles,
        scopes=scopes_for_roles(roles),
        user_id=user.id,
        auth_type="session",
    )
    enforce_ui_path_permission(request, identity)
    return identity


def require_session_identity(identity: Annotated[Identity | None, Depends(get_session_identity)]) -> Identity:
    if identity is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return identity


def get_current_api_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Identity:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.secret_key,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token") from exc

    jti = payload.get("jti")
    username = payload.get("sub")
    role = payload.get("role")
    roles = normalize_roles(payload.get("roles") or [role])
    token = db.execute(select(ApiToken).where(ApiToken.jti == jti)).scalar_one_or_none()
    if not token or not token.enabled or token.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is revoked or unknown")
    if ensure_aware(token.expires_at) <= utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is expired")
    if token.owner_username != username or token.role != primary_role(roles):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token identity mismatch")

    token.last_used_at = utcnow()
    db.add(token)
    db.commit()
    return Identity(
        username=username,
        role=primary_role(roles),
        roles=roles,
        scopes=scopes_from_string(token.scopes),
        user_id=token.owner_user_id,
        token_id=token.id,
        token_jti=token.jti,
        auth_type="bearer",
    )


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    settings = get_settings()
    if user and user.enabled and user.username == settings.bootstrap_admin_username and password == settings.bootstrap_admin_password:
        return user
    return None


def enforce_ui_path_permission(request: Request, identity: Identity) -> None:
    path = request.url.path
    if path in {"/", "/logout"}:
        return
    for prefix, read_scope, write_scope in UI_PATH_SCOPES:
        if path == prefix or path.startswith(f"{prefix}/"):
            required = read_scope if request.method in {"GET", "HEAD", "OPTIONS"} else write_scope
            if not identity.can(required):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing required scope: {required}")
            return


def default_expiration(settings: Settings | None = None) -> datetime:
    settings = settings or get_settings()
    return utcnow() + timedelta(days=settings.api_token_ttl_days)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
