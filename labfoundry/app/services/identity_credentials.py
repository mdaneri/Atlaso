from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from labfoundry.app.adapters.system import SystemAdapter
from labfoundry.app.config import get_settings
from labfoundry.app.models import LdapOrganization, LdapUser, OidcSubject, User
from labfoundry.app.services.ldap import ldap_user_dn


@dataclass(frozen=True)
class VerifiedIdentity:
    source: str
    source_record_id: int
    username: str
    display_name: str
    email: str
    organization_id: int | None
    organization_name: str


def verify_local_credentials(db: Session, username: str, password: str) -> VerifiedIdentity | None:
    normalized_username = username.strip()
    user = db.execute(
        select(User).where(
            User.username == normalized_username,
            User.auth_provider == "local",
        )
    ).scalar_one_or_none()
    if user is None or not user.enabled:
        return None

    settings = get_settings()
    bootstrap_match = (
        user.username == settings.bootstrap_admin_username
        and password == settings.bootstrap_admin_password
    )
    if not bootstrap_match:
        result = SystemAdapter().authenticate_local_user(user.username, password)
        if result.dry_run or result.returncode != 0:
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


def verify_managed_ldap_credentials(
    db: Session,
    *,
    organization_id: int,
    username: str,
    password: str,
) -> VerifiedIdentity | None:
    normalized_username = username.strip()
    user = db.execute(
        select(LdapUser)
        .where(
            LdapUser.organization_id == organization_id,
            LdapUser.uid == normalized_username,
        )
        .options(selectinload(LdapUser.organization))
    ).scalar_one_or_none()
    if (
        user is None
        or not user.enabled
        or user.organization is None
        or not user.organization.enabled
    ):
        return None

    result = SystemAdapter().authenticate_ldap_user(ldap_user_dn(user), password)
    if result.dry_run or result.returncode != 0:
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


def verify_credentials(
    db: Session,
    *,
    source: str,
    username: str,
    password: str,
    organization_id: int | None = None,
) -> VerifiedIdentity | None:
    if source == "local":
        if organization_id is not None:
            return None
        return verify_local_credentials(db, username, password)
    if source == "managed_ldap":
        if organization_id is None:
            return None
        organization = db.get(LdapOrganization, organization_id)
        if organization is None or not organization.enabled:
            return None
        return verify_managed_ldap_credentials(
            db,
            organization_id=organization_id,
            username=username,
            password=password,
        )
    return None


def ensure_oidc_subject(db: Session, identity: VerifiedIdentity) -> OidcSubject:
    if identity.source == "local":
        query = select(OidcSubject).where(OidcSubject.local_user_id == identity.source_record_id)
    elif identity.source == "managed_ldap":
        query = select(OidcSubject).where(OidcSubject.ldap_user_id == identity.source_record_id)
    else:
        raise ValueError("Unsupported OIDC identity source.")
    existing = db.execute(query).scalar_one_or_none()
    if existing is not None:
        return existing
    subject = OidcSubject(
        subject_uuid=str(uuid4()),
        local_user_id=identity.source_record_id if identity.source == "local" else None,
        ldap_user_id=identity.source_record_id if identity.source == "managed_ldap" else None,
    )
    db.add(subject)
    db.flush()
    return subject
