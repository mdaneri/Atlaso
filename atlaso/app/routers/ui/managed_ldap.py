"""Own Managed LDAP management UI transport handlers."""

from __future__ import annotations

import csv
import io
import json
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    LdapGroup,
    LdapGroupMembership,
    LdapOrganization,
    LdapRecoveryArchive,
    LdapSettings,
    LdapUser,
    utcnow,
)
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.ldap import (
    LDAP_DEFAULT_HOSTNAME,
    LDAP_DEFAULT_PLAINTEXT_PORT,
    LDAP_DEFAULT_PORT,
    LDAP_GROUP_PATTERN,
    LDAP_RECOVERY_DIR,
    LDAP_STAGED_CONFIG_PATH,
    LDAP_UID_PATTERN,
    VcfAutomationLdapClient,
    VcfLdapError,
    clear_ldap_recovery_payload,
    clear_pending_ldap_password,
    decrypt_recovery_payload,
    default_organization_suffix,
    encrypt_recovery_payload,
    ensure_organization_bind_secret,
    has_pending_ldap_password,
    invalidate_ldap_user_password_for_uid_change,
    ldap_group_to_dict,
    ldap_user_to_dict,
    manual_vcf_bundle,
    normalize_dn,
    normalize_ldap_slug,
    normalize_vcf_target_url,
    recovery_sha256,
    rotate_organization_bind_secret,
    stage_ldap_recovery_payload,
    stage_ldap_user_password,
    validate_group_cycles,
    vcf_ldap_settings,
)
from atlaso.app.services.ldap import (
    tls_sha256_fingerprint as ldap_vcf_tls_fingerprint,
)
from atlaso.app.services.vaults import redact_secret_values
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class ManagedLdapUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    render: Endpoint
    verify_csrf: Endpoint
    appliance_apply_status: Endpoint
    appliance_apply_client_status: Endpoint
    get_ldap_settings_row: Endpoint
    resolve_ldap_bind_targets: Endpoint
    ensure_dns_for_ldap: Endpoint
    ldap_context: Endpoint
    require_admin_identity: Endpoint
    resolve_vcf_helper_credentials: Endpoint
    vcf_helper_page_context: Endpoint
    get_ca_settings_row: Endpoint
    normalize_dns_hostname: Endpoint


@dataclass(frozen=True)
class ManagedLdapUiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def _ldap_organization_location(organization: LdapOrganization) -> str:
    """Return the directory location for a loaded organization row."""
    return f"/ldap?organization_id={organization.id}"


def build_router(dependencies: ManagedLdapUiDependencies) -> ManagedLdapUiRouter:
    """Build the Managed LDAP management UI router.

    Args:
        dependencies: Stable facade dependencies used by Managed LDAP transports.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )

    @router.get("/ldap", response_class=HTMLResponse, response_model=None)
    def ldap_page(
        request: Request,
        organization_id: int | None = Query(None),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the ldap page endpoint.

        Args:
            request: Incoming HTTP request.
            organization_id: Identifier of the organization.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return dependencies.render(
            request,
            "ldap.html",
            {
                "identity": identity,
                **dependencies.ldap_context(
                    db, selected_organization_id=organization_id
                ),
                "appliance_apply_status": dependencies.appliance_apply_status(
                    db, "ldap"
                ),
            },
        )

    @router.post("/ldap/settings", response_model=None)
    def update_ldap_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        hostname: str = Form(LDAP_DEFAULT_HOSTNAME),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        ldaps_enabled: str | None = Form(None),
        port: int = Form(LDAP_DEFAULT_PORT),
        ldap_enabled: str | None = Form(None),
        ldap_port: int = Form(LDAP_DEFAULT_PLAINTEXT_PORT),
        min_password_length: int = Form(14),
        require_uppercase: str | None = Form(None),
        require_lowercase: str | None = Form(None),
        require_number: str | None = Form(None),
        require_special: str | None = Form(None),
        disallow_username: str | None = Form(None),
        max_failures: int = Form(5),
        lockout_minutes: int = Form(15),
        failure_window_minutes: int = Form(15),
        password_history: int = Form(5),
        password_max_age_days: int = Form(0),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update ldap settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            hostname: DNS hostname of the target resource.
            listen_interfaces: Interfaces on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            ldaps_enabled: Ldaps enabled supplied by the caller.
            port: TCP or UDP port of the target service.
            ldap_enabled: Ldap enabled supplied by the caller.
            ldap_port: Ldap port supplied by the caller.
            min_password_length: Min password length supplied by the caller.
            require_uppercase: Require uppercase supplied by the caller.
            require_lowercase: Require lowercase supplied by the caller.
            require_number: Require number supplied by the caller.
            require_special: Require special supplied by the caller.
            disallow_username: Disallow username supplied by the caller.
            max_failures: Max failures supplied by the caller.
            lockout_minutes: Lockout minutes supplied by the caller.
            failure_window_minutes: Failure window minutes supplied by the caller.
            password_history: Password history supplied by the caller.
            password_max_age_days: Password max age days supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        dependencies.verify_csrf(request, csrf)
        settings = dependencies.get_ldap_settings_row(db)
        previous_hostname = settings.hostname
        selected_interfaces, selected_addresses = (
            dependencies.resolve_ldap_bind_targets(
                db,
                listen_interfaces,
                current_interface=settings.listen_interface,
                listen_interfaces_present=listen_interfaces_present,
            )
        )
        settings.enabled = enabled is not None
        settings.hostname = dependencies.normalize_dns_hostname(
            hostname or LDAP_DEFAULT_HOSTNAME
        )
        settings.listen_interface = selected_interfaces
        settings.listen_address = selected_addresses
        settings.ldaps_enabled = ldaps_enabled is not None
        settings.port = port
        settings.ldap_enabled = ldap_enabled is not None
        settings.ldap_port = ldap_port
        settings.min_password_length = min_password_length
        settings.require_uppercase = require_uppercase is not None
        settings.require_lowercase = require_lowercase is not None
        settings.require_number = require_number is not None
        settings.require_special = require_special is not None
        settings.disallow_username = disallow_username is not None
        settings.max_failures = max_failures
        settings.lockout_minutes = lockout_minutes
        settings.failure_window_minutes = failure_window_minutes
        settings.password_history = password_history
        settings.password_max_age_days = password_max_age_days
        settings.config_path = LDAP_STAGED_CONFIG_PATH
        settings.updated_at = utcnow()
        dependencies.ensure_dns_for_ldap(
            db, settings, actor=identity.username, previous_hostname=previous_hostname
        )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_ldap_settings",
            resource_type="ldap",
            resource_id=str(settings.id),
        )
        context = dependencies.ldap_context(db)
        if request.headers.get(
            "X-Atlaso-Autosave"
        ) == "1" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse(
                {
                    "saved": True,
                    "settings": context["ldap_settings_json"],
                    "service_status": context["ldap_service_status"],
                    "validation_errors": context["ldap_validation_errors"],
                    "validation_warnings": context["ldap_validation_warnings"],
                    "config_preview": context["ldap_config_preview"],
                    "appliance_apply_status": dependencies.appliance_apply_client_status(
                        dependencies.appliance_apply_status(db, "ldap")
                    ),
                }
            )
        return RedirectResponse("/ldap", status_code=303)

    @router.post("/ldap/organizations", response_model=None)
    def create_ldap_organization_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        slug: str = Form(""),
        suffix_dn: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create ldap organization from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            slug: Slug supplied by the caller.
            suffix_dn: Suffix dn supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            ValueError: If an input value is invalid.
        """
        dependencies.verify_csrf(request, csrf)
        try:
            normalized_slug = normalize_ldap_slug(slug or name)
            normalized_suffix = normalize_dn(
                suffix_dn or default_organization_suffix(normalized_slug)
            )
            if not normalized_suffix.lower().startswith("dc="):
                raise ValueError(
                    "LDAP organization suffix must start with a dc component."
                )
        except ValueError as exc:
            return dependencies.render(
                request,
                "ldap.html",
                {
                    "identity": identity,
                    **dependencies.ldap_context(db),
                    "form_error": str(exc),
                    "appliance_apply_status": dependencies.appliance_apply_status(
                        db, "ldap"
                    ),
                },
                status_code=400,
            )
        organization = LdapOrganization(
            name=name.strip(),
            description=description.strip(),
            slug=normalized_slug,
            suffix_dn=normalized_suffix,
            enabled=enabled is not None,
        )
        raw_secret = ensure_organization_bind_secret(organization)
        db.add(organization)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return dependencies.render(
                request,
                "ldap.html",
                {
                    "identity": identity,
                    **dependencies.ldap_context(db),
                    "form_error": "An LDAP organization already uses that slug or suffix.",
                    "appliance_apply_status": dependencies.appliance_apply_status(
                        db, "ldap"
                    ),
                },
                status_code=409,
            )
        db.refresh(organization)
        record_audit(
            db,
            actor=identity.username,
            action="create_ldap_organization",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
        )
        return dependencies.render(
            request,
            "ldap.html",
            {
                "identity": identity,
                **dependencies.ldap_context(
                    db, selected_organization_id=organization.id
                ),
                "ldap_one_time_bind_secret": raw_secret,
                "ldap_one_time_bind_dn": organization.bind_dn,
                "appliance_apply_status": dependencies.appliance_apply_status(
                    db, "ldap"
                ),
            },
            status_code=201,
        )

    @router.post("/ldap/organizations/{organization_id}/delete", response_model=None)
    def delete_ldap_organization_from_ui(
        request: Request,
        organization_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete ldap organization from ui endpoint.

        Args:
            request: Incoming HTTP request.
            organization_id: Identifier of the organization.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        db.delete(organization)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_ldap_organization",
            resource_type="ldap_organization",
            resource_id=str(organization_id),
        )
        return RedirectResponse("/ldap", status_code=303)

    @router.post(
        "/ldap/organizations/{organization_id}/bind-credential/rotate",
        response_model=None,
    )
    def rotate_ldap_bind_credential_from_ui(
        request: Request,
        organization_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the rotate ldap bind credential from ui endpoint.

        Args:
            request: Incoming HTTP request.
            organization_id: Identifier of the organization.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        raw_secret = rotate_organization_bind_secret(organization)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="rotate_ldap_bind_credential",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
        )
        return dependencies.render(
            request,
            "ldap.html",
            {
                "identity": identity,
                **dependencies.ldap_context(
                    db, selected_organization_id=organization.id
                ),
                "ldap_one_time_bind_secret": raw_secret,
                "ldap_one_time_bind_dn": organization.bind_dn,
                "appliance_apply_status": dependencies.appliance_apply_status(
                    db, "ldap"
                ),
            },
        )

    LDAP_SYNTHETIC_FIRST_NAMES = (
        "Avery",
        "Cameron",
        "Diego",
        "Elena",
        "Fatima",
        "Harper",
        "Isaac",
        "Jia",
        "Kai",
        "Leila",
        "Mateo",
        "Nora",
        "Owen",
        "Priya",
        "Quinn",
        "Rafael",
        "Sofia",
        "Theo",
        "Uma",
        "Zoe",
    )
    LDAP_SYNTHETIC_SURNAMES = (
        "Anders",
        "Bennett",
        "Chen",
        "Diaz",
        "Edwards",
        "Farah",
        "Gupta",
        "Hughes",
        "Ibrahim",
        "Jensen",
        "Keller",
        "Lopez",
        "Morgan",
        "Novak",
        "Okafor",
        "Patel",
        "Reyes",
        "Singh",
        "Turner",
        "Wilson",
    )
    LDAP_SYNTHETIC_GROUPS = (
        "Cloud Operations",
        "Platform Engineering",
        "Automation Authors",
        "Security Reviewers",
        "Application Owners",
        "Network Engineering",
        "Identity Administrators",
        "Backup Operators",
        "Lab Developers",
        "VCF Auditors",
    )

    def _unique_ldap_synthetic_name(base: str, existing: set[str]) -> str:
        """Return unique ldap synthetic name.

        Args:
            base: Base consumed by unique LDAP synthetic name.
            existing: Existing consumed by unique LDAP synthetic name.
        """
        candidate = base
        suffix = 2
        while candidate.lower() in existing:
            candidate = f"{base}-{suffix}"
            suffix += 1
        existing.add(candidate.lower())
        return candidate

    def _synthetic_ldap_password(settings: LdapSettings) -> str:
        """Return synthetic ldap password.

        Args:
            settings: Current Atlaso settings used to configure the operation.
        """
        length = max(14, settings.min_password_length)
        return ("Aa1!" + (uuid4().hex * 8))[:length]

    def _ldap_credentials_csv(credentials: list[dict[str, str]]) -> str:
        """Return ldap credentials csv.

        Args:
            credentials: Credential bundle used for the immediate external request.
        """
        credential_buffer = io.StringIO(newline="")
        credential_writer = csv.DictWriter(
            credential_buffer,
            fieldnames=["uid", "password", "display_name", "email", "telephone"],
            lineterminator="\n",
        )
        credential_writer.writeheader()
        credential_writer.writerows(credentials)
        return credential_buffer.getvalue()

    @router.post(
        "/ldap/organizations/{organization_id}/generate-directory", response_model=None
    )
    def generate_ldap_directory_from_ui(
        request: Request,
        organization_id: int,
        user_count: int = Form(...),
        group_count: int = Form(...),
        action: str = Form("generate"),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the generate ldap directory from ui endpoint.

        Args:
            request: Incoming HTTP request.
            organization_id: Identifier of the organization.
            user_count: User count supplied by the caller.
            group_count: Group count supplied by the caller.
            action: Operation to perform on the target resource.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            ValueError: If an input value is invalid.
        """
        dependencies.verify_csrf(request, csrf)
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        settings = dependencies.get_ldap_settings_row(db)
        if not settings.enabled or not organization.enabled:
            raise HTTPException(
                status_code=400,
                detail="Enable Managed LDAP and this organization before generating test entries.",
            )
        if action == "stage_missing":
            missing_users = [
                user
                for user in organization.users
                if user.enabled
                and not user.password_applied_at
                and not has_pending_ldap_password(user)
            ]
            if not missing_users:
                raise HTTPException(
                    status_code=400,
                    detail="This organization has no enabled users that need staged passwords.",
                )
            credentials: list[dict[str, str]] = []
            try:
                for user in missing_users:
                    password = _synthetic_ldap_password(settings)
                    stage_ldap_user_password(user, password, settings)
                    credentials.append(
                        {
                            "uid": user.uid,
                            "password": password,
                            "display_name": user.display_name,
                            "email": user.email,
                            "telephone": user.telephone,
                        }
                    )
                db.commit()
            except ValueError as exc:
                for user in missing_users:
                    clear_pending_ldap_password(user)
                db.rollback()
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            record_audit(
                db,
                actor=identity.username,
                action="stage_missing_ldap_passwords",
                resource_type="ldap_organization",
                resource_id=str(organization.id),
                detail=f"users={len(missing_users)}",
            )
            return dependencies.render(
                request,
                "vcf_helper.html",
                dependencies.vcf_helper_page_context(
                    db,
                    identity,
                    selected_ldap_organization_id=organization.id,
                    ldap_generate_auto_open=True,
                    extra={
                        "ldap_generated_credentials_text": _ldap_credentials_csv(
                            credentials
                        ),
                        "ldap_staged_missing_password_count": len(missing_users),
                    },
                ),
            )
        if action != "generate":
            raise HTTPException(
                status_code=400, detail="Unsupported LDAP test-directory action."
            )
        if (
            not 0 <= user_count <= 500
            or not 0 <= group_count <= 100
            or user_count + group_count == 0
        ):
            raise HTTPException(
                status_code=400,
                detail="Generate between 0 and 500 users and 0 and 100 groups, with at least one entry.",
            )
        existing_uids = {row.uid.lower() for row in organization.users}
        existing_group_names = {row.name.lower() for row in organization.groups}
        generated_users: list[LdapUser] = []
        generated_groups: list[LdapGroup] = []
        credentials: list[dict[str, str]] = []
        offset = int(uuid4().hex[:8], 16)
        try:
            for index in range(user_count):
                given_name = LDAP_SYNTHETIC_FIRST_NAMES[
                    (offset + index) % len(LDAP_SYNTHETIC_FIRST_NAMES)
                ]
                surname = LDAP_SYNTHETIC_SURNAMES[
                    (offset // 7 + index * 3) % len(LDAP_SYNTHETIC_SURNAMES)
                ]
                uid = _unique_ldap_synthetic_name(
                    f"{given_name}.{surname}".lower(), existing_uids
                )
                phone_seed = int(uuid4().hex[:8], 16)
                telephone = f"+1-555-{(phone_seed // 10_000) % 1_000:03d}-{phone_seed % 10_000:04d}"
                user = LdapUser(
                    organization=organization,
                    uid=uid,
                    given_name=given_name,
                    surname=surname,
                    display_name=f"{given_name} {surname}",
                    email=f"{uid}@{organization.slug}.test",
                    telephone=telephone,
                    enabled=True,
                )
                db.add(user)
                db.flush()
                password = _synthetic_ldap_password(settings)
                stage_ldap_user_password(user, password, settings)
                generated_users.append(user)
                credentials.append(
                    {
                        "uid": uid,
                        "password": password,
                        "display_name": user.display_name,
                        "email": user.email,
                        "telephone": telephone,
                    }
                )

            available_users = [*organization.users]
            if group_count and not available_users:
                raise ValueError("Create at least one user before generating groups.")
            for index in range(group_count):
                base_name = LDAP_SYNTHETIC_GROUPS[index % len(LDAP_SYNTHETIC_GROUPS)]
                name = _unique_ldap_synthetic_name(base_name, existing_group_names)
                group = LdapGroup(
                    organization=organization,
                    name=name,
                    description=f"Synthetic {name.lower()} group for {organization.name} lab validation.",
                    enabled=True,
                )
                db.add(group)
                db.flush()
                member_total = min(4, len(available_users))
                start = (offset + index * max(1, member_total)) % len(available_users)
                for member_offset in range(member_total):
                    group.members.append(
                        LdapGroupMembership(
                            member_user=available_users[
                                (start + member_offset) % len(available_users)
                            ]
                        )
                    )
                if generated_groups and index % 2 == 1:
                    group.members.append(
                        LdapGroupMembership(member_group=generated_groups[-1])
                    )
                generated_groups.append(group)
            db.commit()
        except (IntegrityError, ValueError) as exc:
            for user in generated_users:
                clear_pending_ldap_password(user)
            db.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        record_audit(
            db,
            actor=identity.username,
            action="generate_ldap_directory",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
            detail=f"users={user_count}; groups={group_count}",
        )
        return dependencies.render(
            request,
            "vcf_helper.html",
            dependencies.vcf_helper_page_context(
                db,
                identity,
                selected_ldap_organization_id=organization.id,
                ldap_generate_auto_open=True,
                extra={
                    "ldap_generated_credentials_text": _ldap_credentials_csv(
                        credentials
                    ),
                    "ldap_generated_user_count": user_count,
                    "ldap_generated_group_count": group_count,
                },
            ),
            status_code=201,
        )

    @router.post("/ldap/organizations/{organization_id}/users", response_model=None)
    def create_ldap_user_from_ui(
        request: Request,
        organization_id: int,
        uid: str = Form(...),
        given_name: str = Form(""),
        surname: str = Form(""),
        display_name: str = Form(""),
        email: str = Form(""),
        telephone: str = Form(""),
        password: str = Form(""),
        confirm_password: str = Form(""),
        password_confirmation_present: str | None = Form(None),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create ldap user from ui endpoint.

        Args:
            request: Incoming HTTP request.
            organization_id: Identifier of the organization.
            uid: Uid supplied by the caller.
            given_name: Given name supplied by the caller.
            surname: Surname supplied by the caller.
            display_name: Display name supplied by the caller.
            email: Email supplied by the caller.
            telephone: Telephone supplied by the caller.
            password: Password supplied for the immediate authenticated operation.
            confirm_password: Confirm password supplied by the caller.
            password_confirmation_present: Password confirmation present supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        normalized_uid = uid.strip().lower()
        if not LDAP_UID_PATTERN.fullmatch(normalized_uid):
            raise HTTPException(
                status_code=400, detail="LDAP uid contains unsupported characters."
            )
        if password_confirmation_present is not None and password != confirm_password:
            raise HTTPException(
                status_code=400, detail="LDAP password confirmation does not match."
            )
        user = LdapUser(
            organization_id=organization_id,
            uid=normalized_uid,
            given_name=given_name.strip(),
            surname=surname.strip() or normalized_uid,
            display_name=display_name.strip()
            or " ".join(
                part for part in [given_name.strip(), surname.strip()] if part
            ).strip()
            or normalized_uid,
            email=email.strip().lower(),
            telephone=telephone.strip(),
            enabled=enabled is not None
            and enabled.lower() not in {"false", "0", "off"},
        )
        db.add(user)
        try:
            db.flush()
            if password:
                stage_ldap_user_password(
                    user, password, dependencies.get_ldap_settings_row(db)
                )
            db.commit()
        except (IntegrityError, ValueError) as exc:
            db.rollback()
            raise HTTPException(
                status_code=409 if isinstance(exc, IntegrityError) else 400,
                detail="LDAP uid already exists in this organization."
                if isinstance(exc, IntegrityError)
                else str(exc),
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_ldap_user",
            resource_type="ldap_user",
            resource_id=str(user.id),
            detail=f"organization_id={organization_id}",
        )
        if request.headers.get(
            "x-atlaso-grid"
        ) == "1" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse(ldap_user_to_dict(user), status_code=201)
        return RedirectResponse(
            _ldap_organization_location(organization), status_code=303
        )

    @router.post("/ldap/users/{user_id}/edit", response_model=None)
    def edit_ldap_user_from_ui(
        request: Request,
        user_id: int,
        uid: str = Form(...),
        given_name: str = Form(""),
        surname: str = Form(""),
        display_name: str = Form(""),
        email: str = Form(""),
        telephone: str = Form(""),
        password: str = Form(""),
        confirm_password: str = Form(""),
        password_confirmation_present: str | None = Form(None),
        enabled: str = Form("false"),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the edit ldap user from ui endpoint.

        Args:
            request: Incoming HTTP request.
            user_id: Identifier of the user.
            uid: Uid supplied by the caller.
            given_name: Given name supplied by the caller.
            surname: Surname supplied by the caller.
            display_name: Display name supplied by the caller.
            email: Email supplied by the caller.
            telephone: Telephone supplied by the caller.
            password: Password supplied for the immediate authenticated operation.
            confirm_password: Confirm password supplied by the caller.
            password_confirmation_present: Password confirmation present supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        user = db.get(LdapUser, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="LDAP user not found")
        normalized_uid = uid.strip().lower()
        if not LDAP_UID_PATTERN.fullmatch(normalized_uid):
            raise HTTPException(
                status_code=400, detail="LDAP uid contains unsupported characters."
            )
        if password_confirmation_present is not None and password != confirm_password:
            raise HTTPException(
                status_code=400, detail="LDAP password confirmation does not match."
            )
        invalidate_ldap_user_password_for_uid_change(user, normalized_uid)
        user.uid = normalized_uid
        user.given_name = given_name.strip()
        user.surname = surname.strip() or normalized_uid
        user.display_name = (
            display_name.strip()
            or " ".join(
                part for part in [given_name.strip(), surname.strip()] if part
            ).strip()
            or normalized_uid
        )
        user.email = email.strip().lower()
        user.telephone = telephone.strip()
        user.enabled = enabled.lower() not in {"false", "0", "off"}
        user.updated_at = utcnow()
        try:
            if password:
                stage_ldap_user_password(
                    user, password, dependencies.get_ldap_settings_row(db)
                )
            db.commit()
        except (IntegrityError, ValueError) as exc:
            db.rollback()
            raise HTTPException(
                status_code=409 if isinstance(exc, IntegrityError) else 400,
                detail="LDAP uid already exists in this organization."
                if isinstance(exc, IntegrityError)
                else str(exc),
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_ldap_user",
            resource_type="ldap_user",
            resource_id=str(user.id),
        )
        return JSONResponse(ldap_user_to_dict(user))

    @router.post("/ldap/users/{user_id}/password", response_model=None)
    def reset_ldap_user_password_from_ui(
        request: Request,
        user_id: int,
        password: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the reset ldap user password from ui endpoint.

        Args:
            request: Incoming HTTP request.
            user_id: Identifier of the user.
            password: Password supplied for the immediate authenticated operation.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        user = db.get(LdapUser, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="LDAP user not found")
        try:
            stage_ldap_user_password(
                user, password, dependencies.get_ldap_settings_row(db)
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="reset_ldap_user_password",
            resource_type="ldap_user",
            resource_id=str(user.id),
        )
        return RedirectResponse(
            f"/ldap?organization_id={user.organization_id}", status_code=303
        )

    @router.post("/ldap/users/{user_id}/unlock", response_model=None)
    def unlock_ldap_user_from_ui(
        request: Request,
        user_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the unlock ldap user from ui endpoint.

        Args:
            request: Incoming HTTP request.
            user_id: Identifier of the user.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        user = db.get(LdapUser, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="LDAP user not found")
        user.unlock_requested_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="unlock_ldap_user",
            resource_type="ldap_user",
            resource_id=str(user.id),
        )
        return RedirectResponse(
            f"/ldap?organization_id={user.organization_id}", status_code=303
        )

    @router.post("/ldap/users/{user_id}/enabled", response_model=None)
    def set_ldap_user_enabled_from_ui(
        request: Request,
        user_id: int,
        enabled: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the set ldap user enabled from ui endpoint.

        Args:
            request: Incoming HTTP request.
            user_id: Identifier of the user.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        user = db.get(LdapUser, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="LDAP user not found")
        user.enabled = enabled.lower() == "true"
        user.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="enable_ldap_user" if user.enabled else "disable_ldap_user",
            resource_type="ldap_user",
            resource_id=str(user.id),
        )
        return RedirectResponse(
            f"/ldap?organization_id={user.organization_id}", status_code=303
        )

    @router.post("/ldap/users/{user_id}/delete", response_model=None)
    def delete_ldap_user_from_ui(
        request: Request,
        user_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete ldap user from ui endpoint.

        Args:
            request: Incoming HTTP request.
            user_id: Identifier of the user.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        user = db.get(LdapUser, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="LDAP user not found")
        organization_id = user.organization_id
        clear_pending_ldap_password(user)
        db.delete(user)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_ldap_user",
            resource_type="ldap_user",
            resource_id=str(user_id),
        )
        return RedirectResponse(
            f"/ldap?organization_id={organization_id}", status_code=303
        )

    def ldap_group_members_from_form(
        db: Session, organization_id: int, member_values: list[str]
    ) -> list[LdapGroupMembership]:
        """Return ldap group members from form.

        Args:
            db: Active database session.
            organization_id: Identifier of the organization.
            member_values: Member values supplied by the caller.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        memberships: list[LdapGroupMembership] = []
        for raw_value in dict.fromkeys(member_values):
            member_type, separator, raw_id = raw_value.partition(":")
            if separator != ":" or not raw_id.isdigit():
                raise HTTPException(
                    status_code=400, detail="LDAP group member selection is invalid."
                )
            member_id = int(raw_id)
            if member_type == "user":
                user = db.get(LdapUser, member_id)
                if user is None or user.organization_id != organization_id:
                    raise HTTPException(
                        status_code=400,
                        detail="LDAP group user must belong to the selected organization.",
                    )
                memberships.append(LdapGroupMembership(member_user=user))
            elif member_type == "group":
                group = db.get(LdapGroup, member_id)
                if group is None or group.organization_id != organization_id:
                    raise HTTPException(
                        status_code=400,
                        detail="Nested LDAP group must belong to the selected organization.",
                    )
                memberships.append(LdapGroupMembership(member_group=group))
            else:
                raise HTTPException(
                    status_code=400, detail="LDAP group member selection is invalid."
                )
        return memberships

    @router.post("/ldap/organizations/{organization_id}/groups", response_model=None)
    def create_ldap_group_from_ui(
        request: Request,
        organization_id: int,
        name: str = Form(...),
        description: str = Form(""),
        members: list[str] = Form(default_factory=list),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create ldap group from ui endpoint.

        Args:
            request: Incoming HTTP request.
            organization_id: Identifier of the organization.
            name: Name of the target object.
            description: Human-readable description of the resource.
            members: Members supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            ValueError: If an input value is invalid.
        """
        dependencies.verify_csrf(request, csrf)
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        normalized_name = name.strip()
        if not LDAP_GROUP_PATTERN.fullmatch(normalized_name):
            raise HTTPException(
                status_code=400,
                detail="LDAP group name contains unsupported characters.",
            )
        group = LdapGroup(
            organization_id=organization_id,
            name=normalized_name,
            description=description.strip(),
            enabled=enabled is not None
            and enabled.lower() not in {"false", "0", "off"},
        )
        db.add(group)
        try:
            db.flush()
            group.members = ldap_group_members_from_form(db, organization_id, members)
            db.flush()
            cycle_errors = validate_group_cycles(
                db.execute(
                    select(LdapGroup).where(
                        LdapGroup.organization_id == organization_id
                    )
                )
                .scalars()
                .all()
            )
            if cycle_errors:
                raise ValueError(cycle_errors[0])
            db.commit()
        except (IntegrityError, ValueError) as exc:
            db.rollback()
            raise HTTPException(
                status_code=409 if isinstance(exc, IntegrityError) else 400,
                detail="LDAP group already exists in this organization."
                if isinstance(exc, IntegrityError)
                else str(exc),
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_ldap_group",
            resource_type="ldap_group",
            resource_id=str(group.id),
        )
        if request.headers.get(
            "x-atlaso-grid"
        ) == "1" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse(ldap_group_to_dict(group), status_code=201)
        return RedirectResponse(
            _ldap_organization_location(organization), status_code=303
        )

    @router.post("/ldap/groups/{group_id}/edit", response_model=None)
    def edit_ldap_group_from_ui(
        request: Request,
        group_id: int,
        name: str = Form(...),
        description: str = Form(""),
        members: list[str] = Form(default_factory=list),
        members_present: str | None = Form(None),
        enabled: str = Form("false"),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the edit ldap group from ui endpoint.

        Args:
            request: Incoming HTTP request.
            group_id: Identifier of the group.
            name: Name of the target object.
            description: Human-readable description of the resource.
            members: Members supplied by the caller.
            members_present: Members present supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            ValueError: If an input value is invalid.
        """
        dependencies.verify_csrf(request, csrf)
        group = db.get(LdapGroup, group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="LDAP group not found")
        normalized_name = name.strip()
        if not LDAP_GROUP_PATTERN.fullmatch(normalized_name):
            raise HTTPException(
                status_code=400,
                detail="LDAP group name contains unsupported characters.",
            )
        group.name = normalized_name
        group.description = description.strip()
        group.enabled = enabled.lower() not in {"false", "0", "off"}
        group.updated_at = utcnow()
        try:
            if members_present is not None:
                group.members = ldap_group_members_from_form(
                    db, group.organization_id, members
                )
                db.flush()
                cycle_errors = validate_group_cycles(
                    db.execute(
                        select(LdapGroup).where(
                            LdapGroup.organization_id == group.organization_id
                        )
                    )
                    .scalars()
                    .all()
                )
                if cycle_errors:
                    raise ValueError(cycle_errors[0])
            db.commit()
        except (IntegrityError, ValueError) as exc:
            db.rollback()
            raise HTTPException(
                status_code=409 if isinstance(exc, IntegrityError) else 400,
                detail="LDAP group already exists in this organization."
                if isinstance(exc, IntegrityError)
                else str(exc),
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_ldap_group",
            resource_type="ldap_group",
            resource_id=str(group.id),
        )
        return JSONResponse(ldap_group_to_dict(group))

    @router.post("/ldap/groups/{group_id}/members", response_model=None)
    def update_ldap_group_members_from_ui(
        request: Request,
        group_id: int,
        members: list[str] = Form(default_factory=list),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update ldap group members from ui endpoint.

        Args:
            request: Incoming HTTP request.
            group_id: Identifier of the group.
            members: Members supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            ValueError: If an input value is invalid.
        """
        dependencies.verify_csrf(request, csrf)
        group = db.get(LdapGroup, group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="LDAP group not found")
        group.members.clear()
        db.flush()
        group.members = ldap_group_members_from_form(db, group.organization_id, members)
        try:
            db.flush()
            cycle_errors = validate_group_cycles(
                db.execute(
                    select(LdapGroup).where(
                        LdapGroup.organization_id == group.organization_id
                    )
                )
                .scalars()
                .all()
            )
            if cycle_errors:
                raise ValueError(cycle_errors[0])
            group.updated_at = utcnow()
            db.commit()
        except (IntegrityError, ValueError) as exc:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_ldap_group_members",
            resource_type="ldap_group",
            resource_id=str(group.id),
            detail=f"members={len(members)}",
        )
        return RedirectResponse(
            f"/ldap?organization_id={group.organization_id}#ldap-groups-panel",
            status_code=303,
        )

    @router.post("/ldap/groups/{group_id}/delete", response_model=None)
    def delete_ldap_group_from_ui(
        request: Request,
        group_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete ldap group from ui endpoint.

        Args:
            request: Incoming HTTP request.
            group_id: Identifier of the group.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        group = db.get(LdapGroup, group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="LDAP group not found")
        organization_id = group.organization_id
        db.delete(group)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_ldap_group",
            resource_type="ldap_group",
            resource_id=str(group_id),
        )
        return RedirectResponse(
            f"/ldap?organization_id={organization_id}", status_code=303
        )

    @router.post("/ldap/groups/{group_id}/enabled", response_model=None)
    def set_ldap_group_enabled_from_ui(
        request: Request,
        group_id: int,
        enabled: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the set ldap group enabled from ui endpoint.

        Args:
            request: Incoming HTTP request.
            group_id: Identifier of the group.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        group = db.get(LdapGroup, group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="LDAP group not found")
        group.enabled = enabled.lower() == "true"
        group.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="enable_ldap_group" if group.enabled else "disable_ldap_group",
            resource_type="ldap_group",
            resource_id=str(group.id),
        )
        return RedirectResponse(
            f"/ldap?organization_id={group.organization_id}", status_code=303
        )

    @router.get(
        "/ldap/organizations/{organization_id}/vcf-bundle.zip", response_model=None
    )
    def download_ldap_vcf_bundle(
        organization_id: int,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download ldap vcf bundle endpoint.

        Args:
            organization_id: Identifier of the organization.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        ca_settings = dependencies.get_ca_settings_row(db)
        bundle = manual_vcf_bundle(
            dependencies.get_ldap_settings_row(db),
            organization,
            root_ca_pem=ca_settings.root_certificate_pem or "",
        )
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(
            archive_buffer, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr(
                "vcf-automation-9.1-ldap.json",
                json.dumps(bundle["vcfAutomation91"], indent=2, sort_keys=True),
            )
            archive.writestr("atlaso-root-ca.pem", bundle["rootCaPem"])
            archive.writestr(
                "manifest.json",
                json.dumps(
                    {
                        key: value
                        for key, value in bundle.items()
                        if key not in {"rootCaPem", "vcfAutomation91"}
                    },
                    indent=2,
                    sort_keys=True,
                ),
            )
            archive.writestr("README.txt", "\n".join(bundle["instructions"]) + "\n")
        record_audit(
            db,
            actor=identity.username,
            action="download_ldap_vcf_bundle",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
        )
        return Response(
            archive_buffer.getvalue(),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="atlaso-ldap-{organization.slug}-vcf91.zip"'
            },
        )

    @router.post(
        "/ldap/organizations/{organization_id}/vcf/inspect", response_model=None
    )
    def inspect_ldap_vcf_from_ui(
        request: Request,
        organization_id: int,
        target_url: str = Form(...),
        vcf_organization_id: str = Form(...),
        vcf_organization_name: str = Form(""),
        username: str = Form(""),
        password: str = Form(""),
        credential_vault_id: str = Form(""),
        credential_entry_id: str = Form(""),
        confirmed_tls_fingerprint: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the inspect ldap vcf from ui endpoint.

        Args:
            request: Incoming HTTP request.
            organization_id: Identifier of the organization.
            target_url: URL for the target.
            vcf_organization_id: Identifier of the vcf organization.
            vcf_organization_name: Vcf organization name supplied by the caller.
            username: Account name used for authentication or lookup.
            password: Password supplied for the immediate authenticated operation.
            credential_vault_id: Identifier of the credential vault.
            credential_entry_id: Identifier of the credential entry.
            confirmed_tls_fingerprint: Confirmed tls fingerprint supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.verify_csrf(request, csrf)
        username, password = dependencies.resolve_vcf_helper_credentials(
            db,
            identity,
            {
                "username": username,
                "password": password,
                "credential_vault_id": credential_vault_id,
                "credential_entry_id": credential_entry_id,
            },
            username_field="username",
            password_field="password",
            purpose="ldap_inspect",
        )
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        normalized_target = normalize_vcf_target_url(target_url)
        fingerprint = ldap_vcf_tls_fingerprint(normalized_target)
        result: dict[str, Any] = {
            "target_url": normalized_target,
            "organization_id": vcf_organization_id,
            "organization_name": vcf_organization_name,
            "tls_fingerprint": fingerprint,
            "proposed_settings": vcf_ldap_settings(
                dependencies.get_ldap_settings_row(db),
                organization,
                include_password=False,
            ),
            "current_settings": {},
        }
        if confirmed_tls_fingerprint:
            try:
                client = VcfAutomationLdapClient(
                    normalized_target,
                    username=username,
                    password=password,
                    organization_id=vcf_organization_id,
                    confirmed_tls_fingerprint=confirmed_tls_fingerprint,
                )
                current = client.get_settings()
                defined = current.get("definedSettings")
                if isinstance(defined, dict) and "password" in defined:
                    defined["password"] = "[redacted]"
                result["current_settings"] = current
            except (ValueError, VcfLdapError) as exc:
                raise HTTPException(
                    status_code=400,
                    detail=redact_secret_values(str(exc), [password]),
                ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="inspect_vcf_organization_ldap",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
            detail=f"target={normalized_target}; org_id={vcf_organization_id}",
        )
        return dependencies.render(
            request,
            "vcf_helper.html",
            dependencies.vcf_helper_page_context(
                db,
                identity,
                selected_ldap_organization_id=organization_id,
                ldap_vcf_auto_open=True,
                extra={"ldap_vcf_inspection": result},
            ),
        )

    @router.post(
        "/ldap/organizations/{organization_id}/vcf/configure", response_model=None
    )
    def configure_ldap_vcf_from_ui(
        request: Request,
        organization_id: int,
        target_url: str = Form(...),
        vcf_organization_id: str = Form(...),
        vcf_organization_name: str = Form(""),
        username: str = Form(""),
        password: str = Form(""),
        credential_vault_id: str = Form(""),
        credential_entry_id: str = Form(""),
        confirmed_tls_fingerprint: str = Form(...),
        replace_existing: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the configure ldap vcf from ui endpoint.

        Args:
            request: Incoming HTTP request.
            organization_id: Identifier of the organization.
            target_url: URL for the target.
            vcf_organization_id: Identifier of the vcf organization.
            vcf_organization_name: Vcf organization name supplied by the caller.
            username: Account name used for authentication or lookup.
            password: Password supplied for the immediate authenticated operation.
            credential_vault_id: Identifier of the credential vault.
            credential_entry_id: Identifier of the credential entry.
            confirmed_tls_fingerprint: Confirmed tls fingerprint supplied by the caller.
            replace_existing: Replace existing supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            VcfLdapError: If the operation encounters an invalid state.
        """
        dependencies.verify_csrf(request, csrf)
        username, password = dependencies.resolve_vcf_helper_credentials(
            db,
            identity,
            {
                "username": username,
                "password": password,
                "credential_vault_id": credential_vault_id,
                "credential_entry_id": credential_entry_id,
            },
            username_field="username",
            password_field="password",
            purpose="ldap_configure",
        )
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        proposed = vcf_ldap_settings(
            dependencies.get_ldap_settings_row(db), organization, include_password=True
        )
        try:
            client = VcfAutomationLdapClient(
                target_url,
                username=username,
                password=password,
                organization_id=vcf_organization_id,
                confirmed_tls_fingerprint=confirmed_tls_fingerprint,
            )
            current = client.get_settings()
            if current.get("enabled") and replace_existing is None:
                raise VcfLdapError(
                    "VCF organization already has LDAP enabled; explicitly confirm replacement."
                )
            client.configure(proposed)
            test_result = client.test(proposed)
            users = client.search_users()
            groups = client.search_groups()
            if not users or not groups:
                raise VcfLdapError(
                    "VCF LDAP verification must find at least one user and one group."
                )
            verified = client.get_settings()
        except (ValueError, VcfLdapError) as exc:
            safe_error = redact_secret_values(str(exc), [password])
            organization.vcf_last_status = "failed"
            organization.vcf_last_message = safe_error
            organization.updated_at = utcnow()
            db.commit()
            raise HTTPException(status_code=400, detail=safe_error) from exc
        organization.vcf_target_url = normalize_vcf_target_url(target_url)
        organization.vcf_org_id = vcf_organization_id
        organization.vcf_org_name = vcf_organization_name
        organization.vcf_tls_fingerprint = confirmed_tls_fingerprint.upper()
        organization.vcf_last_status = "verified"
        organization.vcf_last_message = (
            f"VCF found {len(users)} users and {len(groups)} groups."
        )
        organization.vcf_last_verified_at = utcnow()
        organization.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="configure_vcf_organization_ldap",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
            detail=f"target={organization.vcf_target_url}; org_id={vcf_organization_id}; users={len(users)}; groups={len(groups)}",
        )
        if isinstance(verified.get("definedSettings"), dict):
            verified["definedSettings"]["password"] = "[redacted]"
        return dependencies.render(
            request,
            "vcf_helper.html",
            dependencies.vcf_helper_page_context(
                db,
                identity,
                selected_ldap_organization_id=organization_id,
                ldap_vcf_auto_open=True,
                extra={
                    "ldap_vcf_configuration_result": {
                        "verified_settings": verified,
                        "test_result": test_result,
                        "user_count": len(users),
                        "group_count": len(groups),
                    }
                },
            ),
        )

    @router.post("/ldap/recovery/export", response_model=None, include_in_schema=False)
    @router.post("/backup-restore/ldap/export", response_model=None)
    def export_ldap_recovery_from_ui(
        request: Request,
        passphrase: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the export ldap recovery from ui endpoint.

        Args:
            request: Incoming HTTP request.
            passphrase: Passphrase supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.require_admin_identity(identity)
        dependencies.verify_csrf(request, csrf)
        timestamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        plain_path = Path(LDAP_RECOVERY_DIR) / f"ldap-recovery-{timestamp}.tar.gz"
        result = SystemAdapter().export_ldap_recovery(str(plain_path))
        if result.dry_run:
            raise HTTPException(
                status_code=409,
                detail="LDAP recovery export requires a live appliance with OpenLDAP applied.",
            )
        if result.returncode != 0 or not plain_path.is_file():
            raise HTTPException(
                status_code=500,
                detail=(result.stderr or "LDAP recovery export failed.").strip(),
            )
        try:
            encrypted = encrypt_recovery_payload(plain_path.read_bytes(), passphrase)
        finally:
            plain_path.unlink(missing_ok=True)
        record_audit(
            db,
            actor=identity.username,
            action="export_ldap_recovery",
            resource_type="ldap_recovery",
            detail=f"created_at={timestamp}",
        )
        return Response(
            encrypted,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="atlaso-ldap-recovery-{timestamp}.lfldap"'
            },
        )

    @router.post("/ldap/recovery/import", response_model=None, include_in_schema=False)
    @router.post("/backup-restore/ldap/import", response_model=None)
    async def import_ldap_recovery_from_ui(
        request: Request,
        archive: UploadFile = File(...),
        passphrase: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the import ldap recovery from ui endpoint.

        Args:
            request: Incoming HTTP request.
            archive: Archive payload or path to process.
            passphrase: Passphrase supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        dependencies.require_admin_identity(identity)
        dependencies.verify_csrf(request, csrf)
        encrypted = await archive.read()
        try:
            decrypted = decrypt_recovery_payload(encrypted, passphrase)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        for stale in (
            db.execute(
                select(LdapRecoveryArchive).where(LdapRecoveryArchive.state == "staged")
            )
            .scalars()
            .all()
        ):
            clear_ldap_recovery_payload(stale)
            stale.state = "replaced"
        row = LdapRecoveryArchive(
            filename=archive.filename or "ldap-recovery.lfldap",
            path="memory://pending-ldap-recovery",
            sha256=recovery_sha256(decrypted),
            state="staged",
            organization_count=0,
            created_by=identity.username,
        )
        db.add(row)
        db.flush()
        try:
            manifest = stage_ldap_recovery_payload(row, decrypted)
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        row.organization_count = len(manifest.get("databases") or [])
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="stage_ldap_recovery_import",
            resource_type="ldap_recovery",
            resource_id=str(row.id),
            detail=f"sha256={row.sha256}; databases={row.organization_count}",
        )
        return RedirectResponse(
            "/backup-restore#ldap-directory-recovery", status_code=303
        )

    return ManagedLdapUiRouter(
        router=router,
        endpoints={
            "ldap_page": ldap_page,
            "update_ldap_settings_from_ui": update_ldap_settings_from_ui,
            "create_ldap_organization_from_ui": create_ldap_organization_from_ui,
            "delete_ldap_organization_from_ui": delete_ldap_organization_from_ui,
            "rotate_ldap_bind_credential_from_ui": rotate_ldap_bind_credential_from_ui,
            "_unique_ldap_synthetic_name": _unique_ldap_synthetic_name,
            "_synthetic_ldap_password": _synthetic_ldap_password,
            "_ldap_credentials_csv": _ldap_credentials_csv,
            "generate_ldap_directory_from_ui": generate_ldap_directory_from_ui,
            "create_ldap_user_from_ui": create_ldap_user_from_ui,
            "edit_ldap_user_from_ui": edit_ldap_user_from_ui,
            "reset_ldap_user_password_from_ui": reset_ldap_user_password_from_ui,
            "unlock_ldap_user_from_ui": unlock_ldap_user_from_ui,
            "set_ldap_user_enabled_from_ui": set_ldap_user_enabled_from_ui,
            "delete_ldap_user_from_ui": delete_ldap_user_from_ui,
            "ldap_group_members_from_form": ldap_group_members_from_form,
            "create_ldap_group_from_ui": create_ldap_group_from_ui,
            "edit_ldap_group_from_ui": edit_ldap_group_from_ui,
            "update_ldap_group_members_from_ui": update_ldap_group_members_from_ui,
            "delete_ldap_group_from_ui": delete_ldap_group_from_ui,
            "set_ldap_group_enabled_from_ui": set_ldap_group_enabled_from_ui,
            "download_ldap_vcf_bundle": download_ldap_vcf_bundle,
            "inspect_ldap_vcf_from_ui": inspect_ldap_vcf_from_ui,
            "configure_ldap_vcf_from_ui": configure_ldap_vcf_from_ui,
            "export_ldap_recovery_from_ui": export_ldap_recovery_from_ui,
            "import_ldap_recovery_from_ui": import_ldap_recovery_from_ui,
        },
    )
