from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
import re
from secrets import token_urlsafe
import socket
import ssl
import tarfile
from typing import Any
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import httpx

from atlaso.app.models import (
    LdapGroup,
    LdapGroupMembership,
    LdapOrganization,
    LdapRecoveryArchive,
    LdapSettings,
    LdapUser,
)
from atlaso.app.secrets import decrypt_secret, encrypt_secret


LDAP_DEFAULT_HOSTNAME = "ldap.atlaso.internal"
LDAP_DEFAULT_PORT = 636
LDAP_DEFAULT_PLAINTEXT_PORT = 389
LDAP_DNS_RECORD_DESCRIPTION = "Managed by Atlaso LDAP service"
LDAP_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/ldap/atlaso-ldap.json"
LDAP_RECOVERY_DIR = "/var/lib/atlaso/ldap/recovery"
LDAP_CERT_PATH = "/etc/atlaso/ldap/tls/server.crt"
LDAP_KEY_PATH = "/etc/atlaso/ldap/tls/server.key"
LDAP_CHAIN_PATH = "/etc/atlaso/ldap/tls/server-chain.crt"
LDAP_ROOT_CA_PATH = "/etc/atlaso/ca/root.crt"
LDAP_UID_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{0,99}$")
LDAP_GROUP_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,119}$")
LDAP_SLUG_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,79}$")
LDAP_DN_COMPONENT_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*=([^,=+<>#;\"\\]|\\.)+$")
LDAP_PENDING_PASSWORDS: dict[int, str] = {}
LDAP_PENDING_RECOVERY_PAYLOADS: dict[int, bytes] = {}


@dataclass(frozen=True)
class VcfLdapInspection:
    target_url: str
    organization_id: str
    organization_name: str
    tls_fingerprint: str
    current_settings: dict[str, Any]
    proposed_settings: dict[str, Any]
    changed: bool


class VcfLdapError(RuntimeError):
    pass


def split_ldap_values(value: str | None) -> list[str]:
    if not value:
        return []
    return list(dict.fromkeys(item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_ldap_slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not normalized or not LDAP_SLUG_PATTERN.fullmatch(normalized):
        raise ValueError("Organization slug must start with a letter and contain only lowercase letters, numbers, and hyphens.")
    return normalized


def default_organization_suffix(slug: str) -> str:
    normalized = normalize_ldap_slug(slug)
    return f"dc={normalized},dc=ldap,dc=atlaso,dc=internal"


def normalize_dn(value: str) -> str:
    parts = [part.strip() for part in value.strip().split(",")]
    if len(parts) < 2 or any(not part for part in parts):
        raise ValueError("Enter a complete LDAP distinguished name with at least two components.")
    if any(not LDAP_DN_COMPONENT_PATTERN.fullmatch(part) for part in parts):
        raise ValueError("LDAP distinguished names must use comma-separated attribute=value components.")
    return ",".join(parts)


def users_base_dn(organization: LdapOrganization) -> str:
    return f"ou=users,{organization.suffix_dn}"


def groups_base_dn(organization: LdapOrganization) -> str:
    return f"ou=groups,{organization.suffix_dn}"


def service_accounts_base_dn(organization: LdapOrganization) -> str:
    return f"ou=service-accounts,{organization.suffix_dn}"


def system_base_dn(organization: LdapOrganization) -> str:
    return f"ou=system,{organization.suffix_dn}"


def ldap_user_dn(user: LdapUser) -> str:
    return f"uid={user.uid},{users_base_dn(user.organization)}"


def ldap_group_dn(group: LdapGroup) -> str:
    return f"cn={escape_dn_value(group.name)},{groups_base_dn(group.organization)}"


def escape_dn_value(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace(",", "\\,").replace("+", "\\+").replace('"', '\\"')
    escaped = escaped.replace("<", "\\<").replace(">", "\\>").replace(";", "\\;").replace("=", "\\=")
    if escaped.startswith(" ") or escaped.startswith("#"):
        escaped = f"\\{escaped}"
    if escaped.endswith(" "):
        escaped = f"{escaped[:-1]}\\ "
    return escaped


def ensure_organization_bind_secret(organization: LdapOrganization) -> str:
    if not organization.bind_dn:
        organization.bind_dn = f"uid=vcf-bind,{service_accounts_base_dn(organization)}"
    if not organization.bind_password_encrypted:
        secret = token_urlsafe(32)
        organization.bind_password_encrypted = encrypt_secret(secret)
        return secret
    return ""


def rotate_organization_bind_secret(organization: LdapOrganization) -> str:
    secret = token_urlsafe(32)
    organization.bind_password_encrypted = encrypt_secret(secret)
    organization.updated_at = utcnow()
    return secret


def organization_bind_secret(organization: LdapOrganization) -> str:
    if not organization.bind_password_encrypted:
        return ""
    return decrypt_secret(organization.bind_password_encrypted)


def stage_ldap_user_password(user: LdapUser, password: str, settings: LdapSettings) -> None:
    errors = validate_ldap_password(password, user.uid, settings)
    if errors:
        raise ValueError(" ".join(errors))
    if user.id is None:
        raise ValueError("LDAP user must be persisted before staging a password.")
    LDAP_PENDING_PASSWORDS[user.id] = password
    user.password_status = "pending_apply"
    user.updated_at = utcnow()


def has_pending_ldap_password(user: LdapUser) -> bool:
    return user.id is not None and user.id in LDAP_PENDING_PASSWORDS


def clear_pending_ldap_password(user: LdapUser) -> None:
    if user.id is not None:
        LDAP_PENDING_PASSWORDS.pop(user.id, None)


def invalidate_ldap_user_password_for_uid_change(user: LdapUser, new_uid: str) -> None:
    if user.uid == new_uid or has_pending_ldap_password(user):
        return
    if user.password_status == "applied" or user.password_applied_at is not None:
        user.password_status = "not_staged"
        user.password_applied_at = None
        user.updated_at = utcnow()


def mark_ldap_apply_complete(users: list[LdapUser]) -> None:
    applied_at = utcnow()
    for user in users:
        if has_pending_ldap_password(user):
            user.password_applied_at = applied_at
            user.password_status = "applied"
            clear_pending_ldap_password(user)
        elif user.password_applied_at:
            user.password_status = "applied"
        user.unlock_requested_at = None
        user.updated_at = applied_at


def stage_ldap_recovery_payload(archive: LdapRecoveryArchive, payload: bytes) -> dict[str, Any]:
    manifest = validate_ldap_recovery_payload(payload)
    if archive.id is None:
        raise ValueError("LDAP recovery archive must be persisted before staging.")
    LDAP_PENDING_RECOVERY_PAYLOADS[archive.id] = payload
    return manifest


def clear_ldap_recovery_payload(archive: LdapRecoveryArchive) -> None:
    if archive.id is not None:
        LDAP_PENDING_RECOVERY_PAYLOADS.pop(archive.id, None)


def validate_ldap_recovery_payload(payload: bytes) -> dict[str, Any]:
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if any(member.name.startswith(("/", "\\")) or ".." in member.name.replace("\\", "/").split("/") for member in members):
                raise ValueError("LDAP recovery archive contains an unsafe path.")
            manifest_member = archive.getmember("manifest.json")
            manifest_file = archive.extractfile(manifest_member)
            if manifest_file is None:
                raise ValueError("LDAP recovery manifest is unreadable.")
            manifest = json.loads(manifest_file.read().decode("utf-8"))
    except (tarfile.TarError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("LDAP recovery payload is not a valid Atlaso tar archive.") from exc
    if manifest.get("format") != "atlaso-ldap-slapcat-v1":
        raise ValueError("Unsupported LDAP recovery manifest format.")
    databases = manifest.get("databases")
    if not isinstance(databases, list) or not databases:
        raise ValueError("LDAP recovery manifest does not contain any slapcat databases.")
    return manifest


def validate_ldap_password(password: str, username: str, settings: LdapSettings) -> list[str]:
    errors: list[str] = []
    min_length = max(8, settings.min_password_length or 14)
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters.")
    if settings.require_uppercase is not False and not any(character.isupper() for character in password):
        errors.append("Password must include an uppercase letter.")
    if settings.require_lowercase is not False and not any(character.islower() for character in password):
        errors.append("Password must include a lowercase letter.")
    if settings.require_number is not False and not any(character.isdigit() for character in password):
        errors.append("Password must include a number.")
    if settings.require_special is not False and not any(not character.isalnum() for character in password):
        errors.append("Password must include a special character.")
    if settings.disallow_username is not False and username.lower() in password.lower():
        errors.append("Password must not contain the username.")
    return errors


def ldap_settings_to_dict(settings: LdapSettings) -> dict[str, Any]:
    return {
        "id": settings.id,
        "enabled": settings.enabled,
        "hostname": settings.hostname,
        "listen_interface": settings.listen_interface,
        "listen_address": settings.listen_address,
        "ldaps_enabled": settings.ldaps_enabled,
        "port": settings.port,
        "ldap_enabled": settings.ldap_enabled,
        "ldap_port": settings.ldap_port,
        "password_policy": {
            "min_length": settings.min_password_length,
            "require_uppercase": settings.require_uppercase,
            "require_lowercase": settings.require_lowercase,
            "require_number": settings.require_number,
            "require_special": settings.require_special,
            "disallow_username": settings.disallow_username,
            "max_failures": settings.max_failures,
            "lockout_minutes": settings.lockout_minutes,
            "failure_window_minutes": settings.failure_window_minutes,
            "history": settings.password_history,
            "max_age_days": settings.password_max_age_days,
        },
        "certificate_path": LDAP_CERT_PATH,
        "key_path": LDAP_KEY_PATH,
        "chain_path": LDAP_CHAIN_PATH,
        "root_ca_path": LDAP_ROOT_CA_PATH,
        "config_path": settings.config_path,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else "",
    }


def ldap_organization_to_dict(organization: LdapOrganization, *, reveal_bind_secret: str = "") -> dict[str, Any]:
    data = {
        "id": organization.id,
        "name": organization.name,
        "description": organization.description,
        "slug": organization.slug,
        "suffix_dn": organization.suffix_dn,
        "users_base_dn": users_base_dn(organization),
        "groups_base_dn": groups_base_dn(organization),
        "service_accounts_base_dn": service_accounts_base_dn(organization),
        "bind_dn": organization.bind_dn,
        "bind_secret_present": bool(organization.bind_password_encrypted),
        "enabled": organization.enabled,
        "user_count": len(organization.users),
        "group_count": len(organization.groups),
        "vcf_target_url": organization.vcf_target_url,
        "vcf_org_id": organization.vcf_org_id,
        "vcf_org_name": organization.vcf_org_name,
        "vcf_tls_fingerprint": organization.vcf_tls_fingerprint,
        "vcf_last_status": organization.vcf_last_status,
        "vcf_last_message": organization.vcf_last_message,
        "vcf_last_verified_at": organization.vcf_last_verified_at.isoformat() if organization.vcf_last_verified_at else "",
        "created_at": organization.created_at.isoformat() if organization.created_at else "",
        "updated_at": organization.updated_at.isoformat() if organization.updated_at else "",
    }
    if reveal_bind_secret:
        data["raw_bind_password"] = reveal_bind_secret
    return data


def ldap_user_to_dict(user: LdapUser) -> dict[str, Any]:
    return {
        "id": user.id,
        "organization_id": user.organization_id,
        "uid": user.uid,
        "dn": ldap_user_dn(user),
        "given_name": user.given_name,
        "surname": user.surname,
        "display_name": user.display_name,
        "email": user.email,
        "telephone": user.telephone,
        "enabled": user.enabled,
        "password_status": "pending_apply" if has_pending_ldap_password(user) else user.password_status,
        "password_applied_at": user.password_applied_at.isoformat() if user.password_applied_at else "",
        "unlock_requested": bool(user.unlock_requested_at),
        "created_at": user.created_at.isoformat() if user.created_at else "",
        "updated_at": user.updated_at.isoformat() if user.updated_at else "",
    }


def ldap_group_to_dict(group: LdapGroup) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    for membership in group.members:
        if membership.member_user is not None:
            members.append(
                {
                    "type": "user",
                    "id": membership.member_user.id,
                    "name": membership.member_user.uid,
                    "dn": ldap_user_dn(membership.member_user),
                }
            )
        elif membership.member_group is not None:
            members.append(
                {
                    "type": "group",
                    "id": membership.member_group.id,
                    "name": membership.member_group.name,
                    "dn": ldap_group_dn(membership.member_group),
                }
            )
    return {
        "id": group.id,
        "organization_id": group.organization_id,
        "name": group.name,
        "dn": ldap_group_dn(group),
        "description": group.description,
        "enabled": group.enabled,
        "members": members,
        "created_at": group.created_at.isoformat() if group.created_at else "",
        "updated_at": group.updated_at.isoformat() if group.updated_at else "",
    }


def _group_edges(groups: list[LdapGroup]) -> dict[int, set[int]]:
    return {
        group.id: {
            membership.member_group_id
            for membership in group.members
            if membership.member_group_id is not None
        }
        for group in groups
        if group.id is not None
    }


def validate_group_cycles(groups: list[LdapGroup]) -> list[str]:
    names = {group.id: group.name for group in groups}
    edges = _group_edges(groups)
    errors: list[str] = []
    visiting: set[int] = set()
    visited: set[int] = set()

    def visit(group_id: int, path: list[int]) -> None:
        if group_id in visiting:
            cycle = path[path.index(group_id) :] + [group_id] if group_id in path else [group_id, group_id]
            label = " -> ".join(names.get(item, str(item)) for item in cycle)
            errors.append(f"Nested LDAP groups contain a cycle: {label}.")
            return
        if group_id in visited:
            return
        visiting.add(group_id)
        for child_id in edges.get(group_id, set()):
            visit(child_id, [*path, group_id])
        visiting.remove(group_id)
        visited.add(group_id)

    for group_id in edges:
        visit(group_id, [])
    return list(dict.fromkeys(errors))


def validate_ldap_state(
    settings: LdapSettings,
    organizations: list[LdapOrganization],
    *,
    available_interfaces: set[str] | None = None,
    ca_ready: bool = False,
    recovery_staged: bool = False,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if settings.hostname.strip().lower().endswith(".local"):
        warnings.append("Avoid .local for LDAP; use an internal DNS domain such as atlaso.internal.")
    if settings.port < 1 or settings.port > 65535:
        errors.append("LDAPS port must be between 1 and 65535.")
    if settings.ldap_port < 1 or settings.ldap_port > 65535:
        errors.append("LDAP port must be between 1 and 65535.")
    if settings.ldaps_enabled and settings.ldap_enabled and settings.port == settings.ldap_port:
        errors.append("LDAP and LDAPS listeners must use different TCP ports.")
    if settings.min_password_length < 8 or settings.min_password_length > 128:
        errors.append("LDAP minimum password length must be between 8 and 128.")
    if settings.max_failures < 1 or settings.max_failures > 100:
        errors.append("LDAP maximum failures must be between 1 and 100.")
    if settings.lockout_minutes < 1 or settings.lockout_minutes > 1440:
        errors.append("LDAP lockout duration must be between 1 minute and 24 hours.")
    if settings.password_history < 0 or settings.password_history > 24:
        errors.append("LDAP password history must be between 0 and 24.")
    if settings.enabled:
        if not settings.ldaps_enabled and not settings.ldap_enabled:
            errors.append("Enable at least one LDAP or LDAPS listener before enabling the service.")
        if not settings.listen_interface.strip() or not settings.listen_address.strip():
            errors.append("Select at least one addressed interface before enabling LDAP.")
        if settings.ldaps_enabled and not ca_ready:
            errors.append("Enable and initialize the Atlaso CA before enabling LDAPS.")
        if available_interfaces is not None:
            for interface_name in split_ldap_values(settings.listen_interface):
                if interface_name not in available_interfaces:
                    errors.append(f"LDAP listen interface {interface_name} is not an available addressed interface.")
    slugs: set[str] = set()
    suffixes: set[str] = set()
    for organization in organizations:
        try:
            normalized_slug = normalize_ldap_slug(organization.slug)
        except ValueError as exc:
            errors.append(f"{organization.name or 'LDAP organization'}: {exc}")
            continue
        if normalized_slug in slugs:
            errors.append(f"LDAP organization slug {normalized_slug} is duplicated.")
        slugs.add(normalized_slug)
        try:
            suffix = normalize_dn(organization.suffix_dn)
        except ValueError as exc:
            errors.append(f"{organization.name or normalized_slug}: {exc}")
            continue
        if not suffix.lower().startswith("dc="):
            errors.append(f"{organization.name or normalized_slug}: organization suffix must start with a dc component.")
        if suffix.lower() in suffixes:
            errors.append(f"LDAP organization suffix {suffix} is duplicated.")
        suffixes.add(suffix.lower())
        if not organization.bind_password_encrypted:
            errors.append(f"{organization.name}: generate a VCF bind credential before applying LDAP.")
        missing_password_uids: list[str] = []
        for user in organization.users:
            if not LDAP_UID_PATTERN.fullmatch(user.uid):
                errors.append(f"{organization.name}: user {user.uid or user.id} has an invalid uid.")
            if user.enabled and not recovery_staged and not user.password_applied_at and not has_pending_ldap_password(user):
                missing_password_uids.append(user.uid)
        if missing_password_uids:
            examples = ", ".join(missing_password_uids[:3])
            if len(missing_password_uids) > 3:
                examples = f"{examples}, and {len(missing_password_uids) - 3} more"
            errors.append(
                f"{organization.name}: {len(missing_password_uids)} enabled "
                f"{'user needs' if len(missing_password_uids) == 1 else 'users need'} staged passwords "
                f"({examples}). Use VCF Helper > Generate LDAP Test Directory > Recover missing passwords."
            )
        for group in organization.groups:
            if not LDAP_GROUP_PATTERN.fullmatch(group.name):
                errors.append(f"{organization.name}: group {group.name or group.id} has an invalid name.")
            if group.enabled and not group.members:
                errors.append(f"{organization.name}: enabled group {group.name} must contain at least one user or nested group.")
            for membership in group.members:
                has_user = membership.member_user_id is not None
                has_group = membership.member_group_id is not None
                if has_user == has_group:
                    errors.append(f"{organization.name}: group {group.name} has an invalid membership row.")
                if membership.member_user and membership.member_user.organization_id != organization.id:
                    errors.append(f"{organization.name}: group {group.name} references a user in another organization.")
                if membership.member_group and membership.member_group.organization_id != organization.id:
                    errors.append(f"{organization.name}: group {group.name} references a group in another organization.")
        errors.extend(validate_group_cycles(organization.groups))
    if settings.enabled and not organizations:
        errors.append("Create at least one LDAP organization before enabling the service.")
    if settings.password_max_age_days:
        warnings.append("Expired LDAP passwords cause VCF login failure; v1 does not include end-user password self-service.")
    warnings.append("Keep VCF local break-glass administrator accounts because LDAP v1 is single-node.")
    return list(dict.fromkeys(errors)), list(dict.fromkeys(warnings))


def vcf_ldap_settings(settings: LdapSettings, organization: LdapOrganization, *, include_password: bool) -> dict[str, Any]:
    use_ldaps = bool(settings.ldaps_enabled)
    hostname = settings.hostname or LDAP_DEFAULT_HOSTNAME
    defined_settings: dict[str, Any] = {
        "hostName": hostname,
        "port": settings.port if use_ldaps else settings.ldap_port,
        "ssl": use_ldaps,
        "pagedSearchDisabled": False,
        "pageSize": 200,
        "maxResults": 1000,
        "maxUserGroups": 1000,
        "searchBase": users_base_dn(organization),
        "userName": organization.bind_dn,
        "groupSearchBase": groups_base_dn(organization),
        "customUiButtonLabel": f"{organization.name} directory",
        "userAttributes": {
            "objectClass": "inetOrgPerson",
            "objectIdentifier": "entryUUID",
            "userName": "uid",
            "email": "mail",
            "displayName": "displayName",
            "givenName": "givenName",
            "surname": "sn",
            "telephone": "telephoneNumber",
            "groupMembershipIdentifier": "dn",
            "groupBackLinkIdentifier": "memberOf",
            "domain": "associatedDomain",
            "managerIdentifier": "manager",
            "serviceAccount": "employeeType",
        },
        "groupAttributes": {
            "objectClass": "groupOfNames",
            "objectIdentifier": "entryUUID",
            "groupName": "cn",
            "membership": "member",
            "membershipIdentifier": "dn",
            "backLinkIdentifier": "memberOf",
        },
    }
    if include_password:
        defined_settings["password"] = organization_bind_secret(organization)
    return {
        "enabled": bool(settings.enabled and organization.enabled),
        "settingsSource": "DEFINED",
        "definedSettings": defined_settings,
        "vcf91IdentityBrokerCompatibility": {
            "requiredInternalAttribute": "serviceAccount",
            "ldapAttribute": "employeeType",
            "humanValue": "person",
            "serviceValue": "serviceAccount",
        },
    }


def ldap_apply_payload(
    settings: LdapSettings,
    organizations: list[LdapOrganization],
    *,
    include_secrets: bool,
    recovery_archive: LdapRecoveryArchive | None = None,
) -> dict[str, Any]:
    organization_rows: list[dict[str, Any]] = []
    for organization in organizations:
        users = []
        for user in organization.users:
            row = ldap_user_to_dict(user)
            row["password"] = LDAP_PENDING_PASSWORDS.get(user.id, "") if include_secrets else ("[pending]" if has_pending_ldap_password(user) else "")
            row["unlock_requested"] = bool(user.unlock_requested_at)
            row["employee_type"] = "person"
            users.append(row)
        groups = [ldap_group_to_dict(group) for group in organization.groups]
        organization_rows.append(
            {
                **ldap_organization_to_dict(organization),
                "bind_password": organization_bind_secret(organization) if include_secrets else "[encrypted]",
                "users": users,
                "groups": groups,
                "vcf_settings": vcf_ldap_settings(settings, organization, include_password=False),
            }
        )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "service": ldap_settings_to_dict(settings),
        "organizations": organization_rows,
    }
    if recovery_archive and recovery_archive.state == "staged":
        payload["recovery_import"] = {
            "path": recovery_archive.path,
            "sha256": recovery_archive.sha256,
            "filename": recovery_archive.filename,
            "payload_b64": (
                base64.b64encode(LDAP_PENDING_RECOVERY_PAYLOADS.get(recovery_archive.id, b"")).decode("ascii")
                if include_secrets
                else ("[pending]" if recovery_archive.id in LDAP_PENDING_RECOVERY_PAYLOADS else "")
            ),
        }
    return payload


def render_ldap_preview(
    settings: LdapSettings,
    organizations: list[LdapOrganization],
    *,
    recovery_archive: LdapRecoveryArchive | None = None,
) -> str:
    return json.dumps(
        ldap_apply_payload(settings, organizations, include_secrets=False, recovery_archive=recovery_archive),
        indent=2,
        sort_keys=True,
    )


def render_ldap_apply_config(
    settings: LdapSettings,
    organizations: list[LdapOrganization],
    *,
    recovery_archive: LdapRecoveryArchive | None = None,
) -> str:
    return json.dumps(
        ldap_apply_payload(settings, organizations, include_secrets=True, recovery_archive=recovery_archive),
        indent=2,
        sort_keys=True,
    )


def manual_vcf_bundle(
    settings: LdapSettings,
    organization: LdapOrganization,
    *,
    root_ca_pem: str,
) -> dict[str, Any]:
    use_ldaps = bool(settings.ldaps_enabled)
    endpoint_port = settings.port if use_ldaps else settings.ldap_port
    hostname = settings.hostname or LDAP_DEFAULT_HOSTNAME
    return {
        "manifestVersion": 1,
        "generatedAt": utcnow().isoformat(),
        "organization": ldap_organization_to_dict(organization),
        "endpoint": {
            "url": f"{'ldaps' if use_ldaps else 'ldap'}://{hostname}:{endpoint_port}",
            "hostname": hostname,
            "port": endpoint_port,
            "ssl": use_ldaps,
            "rootCaFilename": "atlaso-root-ca.pem" if use_ldaps else "",
        },
        "vcfAutomation91": vcf_ldap_settings(settings, organization, include_password=False),
        "rootCaPem": root_ca_pem if use_ldaps else "",
        "instructions": [
            "Configure custom organization LDAP settings using settingsSource DEFINED.",
            "Supply the one-time VCF bind password separately; it is intentionally absent from this bundle.",
            "Test LDAP, search for users and groups, then import selected groups and assign roles in VCF.",
            "Retain a VCF local break-glass administrator account.",
        ],
    }


def _recovery_fernet(passphrase: str, salt: bytes) -> Fernet:
    if len(passphrase) < 12:
        raise ValueError("Recovery passphrase must be at least 12 characters.")
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    ).derive(passphrase.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_recovery_payload(payload: bytes, passphrase: str, *, salt: bytes | None = None) -> bytes:
    salt = salt or token_urlsafe(18).encode("ascii")
    envelope = {
        "format": "atlaso-ldap-recovery-v1",
        "salt": base64.b64encode(salt).decode("ascii"),
        "payload": _recovery_fernet(passphrase, salt).encrypt(payload).decode("ascii"),
    }
    return json.dumps(envelope, sort_keys=True).encode("utf-8")


def decrypt_recovery_payload(encrypted: bytes, passphrase: str) -> bytes:
    try:
        envelope = json.loads(encrypted.decode("utf-8"))
        if envelope.get("format") != "atlaso-ldap-recovery-v1":
            raise ValueError("Unsupported LDAP recovery archive format.")
        salt = base64.b64decode(envelope["salt"])
        return _recovery_fernet(passphrase, salt).decrypt(envelope["payload"].encode("ascii"))
    except (InvalidToken, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("Unsupported"):
            raise
        raise ValueError("LDAP recovery archive could not be decrypted with the supplied passphrase.") from exc


def recovery_sha256(content: bytes) -> str:
    return sha256(content).hexdigest()


def normalize_vcf_target_url(value: str) -> str:
    raw = value.strip()
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlsplit(raw)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("VCF Automation target must be an HTTPS hostname or URL.")
    port = parsed.port or 443
    return f"https://{parsed.hostname}:{port}"


def _fingerprint_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def tls_sha256_fingerprint(target_url: str, *, timeout_seconds: float = 10) -> str:
    parsed = urlsplit(normalize_vcf_target_url(target_url))
    context = _fingerprint_tls_context()
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=timeout_seconds) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=parsed.hostname) as tls_socket:
                certificate = tls_socket.getpeercert(binary_form=True)
    except OSError as exc:
        raise VcfLdapError(f"Unable to inspect VCF Automation TLS certificate: {exc}") from exc
    digest = sha256(certificate).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


class VcfAutomationLdapClient:
    API_VERSION = "9.1.0"

    def __init__(
        self,
        target_url: str,
        *,
        username: str,
        password: str,
        organization_id: str,
        confirmed_tls_fingerprint: str,
        timeout_seconds: float = 30,
    ) -> None:
        self.target_url = normalize_vcf_target_url(target_url)
        self.username = username
        self.password = password
        self.organization_id = organization_id.strip()
        self.confirmed_tls_fingerprint = confirmed_tls_fingerprint.strip().upper()
        self.timeout_seconds = timeout_seconds
        self.token = ""

    @property
    def headers(self) -> dict[str, str]:
        headers = {
            "Accept": f"application/json;version={self.API_VERSION}",
            "Content-Type": "application/json",
            "X-VMWARE-VCLOUD-TENANT-CONTEXT": self.organization_id,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _client(self) -> httpx.Client:
        fingerprint = tls_sha256_fingerprint(self.target_url)
        if not self.confirmed_tls_fingerprint or fingerprint != self.confirmed_tls_fingerprint:
            raise VcfLdapError("The VCF Automation TLS certificate does not match the confirmed fingerprint.")
        return httpx.Client(base_url=self.target_url, verify=False, timeout=self.timeout_seconds)  # noqa: S501 - fingerprint is pinned above.

    @staticmethod
    def _raise(response: httpx.Response, message: str) -> None:
        if response.is_success:
            return
        detail = ""
        try:
            payload = response.json()
            detail = str(payload.get("message") or payload.get("detail") or "")
        except (ValueError, AttributeError):
            detail = response.text.strip()
        raise VcfLdapError(f"{message}: HTTP {response.status_code}{f' - {detail}' if detail else ''}")

    def authenticate(self) -> dict[str, Any]:
        basic = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        with self._client() as client:
            response = client.post(
                "/cloudapi/1.0.0/sessions",
                headers={
                    "Authorization": f"Basic {basic}",
                    "Accept": f"application/json;version={self.API_VERSION}",
                },
            )
        self._raise(response, "VCF Automation authentication failed")
        self.token = (
            response.headers.get("X-VMWARE-VCLOUD-ACCESS-TOKEN")
            or response.headers.get("x-vcloud-authorization")
            or ""
        )
        if not self.token:
            authorization = response.headers.get("Authorization", "")
            self.token = authorization.removeprefix("Bearer ").strip()
        if not self.token:
            raise VcfLdapError("VCF Automation authentication returned no bearer token.")
        try:
            return response.json()
        except ValueError:
            return {}

    def get_settings(self) -> dict[str, Any]:
        if not self.token:
            self.authenticate()
        with self._client() as client:
            response = client.get("/cloudapi/v1/orgSettings/ldap", headers=self.headers)
        self._raise(response, "Could not read VCF organization LDAP settings")
        return response.json()

    def configure(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.token:
            self.authenticate()
        wire_payload = dict(payload)
        wire_payload.pop("vcf91IdentityBrokerCompatibility", None)
        with self._client() as client:
            response = client.put("/cloudapi/v1/orgSettings/ldap", headers=self.headers, json=wire_payload)
        self._raise(response, "VCF rejected the LDAP organization settings")
        return response.json() if response.content else {}

    def test(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.token:
            self.authenticate()
        wire_payload = dict(payload)
        wire_payload.pop("vcf91IdentityBrokerCompatibility", None)
        with self._client() as client:
            response = client.post("/cloudapi/1.0.0/ldap/test", headers=self.headers, json=wire_payload)
        self._raise(response, "VCF LDAP connection test failed")
        return response.json() if response.content else {}

    def search_users(self, query: str = "") -> list[dict[str, Any]]:
        if not self.token:
            self.authenticate()
        with self._client() as client:
            response = client.get("/cloudapi/1.0.0/ldap/search/user", headers=self.headers, params={"q": query})
        self._raise(response, "VCF LDAP user search failed")
        payload = response.json()
        return payload if isinstance(payload, list) else []

    def search_groups(self, query: str = "") -> list[dict[str, Any]]:
        if not self.token:
            self.authenticate()
        with self._client() as client:
            response = client.get("/cloudapi/1.0.0/ldap/search/group", headers=self.headers, params={"q": query})
        self._raise(response, "VCF LDAP group search failed")
        payload = response.json()
        return payload if isinstance(payload, list) else []
