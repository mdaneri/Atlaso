"""Own Managed LDAP API v1 transport handlers."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import ip_interface
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile
from fastapi import Path as ApiPath
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    ApplianceSettings,
    CaSettings,
    LdapGroup,
    LdapGroupMembership,
    LdapOrganization,
    LdapRecoveryArchive,
    LdapSettings,
    LdapUser,
    PhysicalInterface,
    ServiceState,
    VlanInterface,
    utcnow,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    LdapBindCredentialResponse,
    LdapGroupCreate,
    LdapGroupResponse,
    LdapHealthResponse,
    LdapOrganizationCreate,
    LdapOrganizationResponse,
    LdapPasswordResetRequest,
    LdapRecoveryExportRequest,
    LdapRecoveryImportResponse,
    LdapSettingsResponse,
    LdapSettingsUpdate,
    LdapUserCreate,
    LdapUserResponse,
    LdapVcfConfigureRequest,
    LdapVcfInspectionResponse,
    LdapVcfInspectRequest,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces
from atlaso.app.services.ldap import (
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
    invalidate_ldap_user_password_for_uid_change,
    ldap_group_to_dict,
    ldap_organization_to_dict,
    ldap_settings_to_dict,
    ldap_user_to_dict,
    manual_vcf_bundle,
    normalize_dn,
    normalize_ldap_slug,
    normalize_vcf_target_url,
    recovery_sha256,
    rotate_organization_bind_secret,
    stage_ldap_recovery_payload,
    stage_ldap_user_password,
    tls_sha256_fingerprint,
    validate_group_cycles,
    validate_ldap_state,
    vcf_ldap_settings,
)
from atlaso.app.services.networking import (
    normalize_interface_mode,
    normalize_interface_role,
)
from atlaso.app.services.service_dns_defaults import factory_service_hostname

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class ManagedLdapApiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    backing_systemd_unit_active: Endpoint


@dataclass(frozen=True)
class ManagedLdapApiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: ManagedLdapApiDependencies) -> ManagedLdapApiRouter:
    """Build the Managed LDAP API v1 router.

    Args:
        dependencies: Stable facade dependencies used by Managed LDAP transports.
    """
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)

    def _ldap_settings_row(db: Session) -> LdapSettings:
        """Return ldap settings row.

        Args:
            db: Active database session.
        """
        settings = db.execute(select(LdapSettings)).scalar_one_or_none()
        if settings is None:
            appliance = db.execute(
                select(ApplianceSettings).order_by(ApplianceSettings.id)
            ).scalars().first()
            settings = LdapSettings(
                hostname=factory_service_hostname(
                    "ldap",
                    appliance.fqdn if appliance else get_settings().appliance_fqdn,
                ),
                config_path=LDAP_STAGED_CONFIG_PATH,
            )
            db.add(settings)
            db.commit()
            db.refresh(settings)
        return settings

    def _ldap_organizations(db: Session) -> list[LdapOrganization]:
        """Return ldap organizations.

        Args:
            db: Active database session.
        """
        return (
            db.execute(
                select(LdapOrganization)
                .options(
                    selectinload(LdapOrganization.users),
                    selectinload(LdapOrganization.groups)
                    .selectinload(LdapGroup.members)
                    .selectinload(LdapGroupMembership.member_user),
                    selectinload(LdapOrganization.groups)
                    .selectinload(LdapGroup.members)
                    .selectinload(LdapGroupMembership.member_group),
                )
                .order_by(LdapOrganization.name)
            )
            .scalars()
            .all()
        )

    def _ldap_api_interface_addresses(db: Session) -> dict[str, list[str]]:
        """Return ldap api interface addresses.

        Args:
            db: Active database session.
        """
        result: dict[str, list[str]] = {}
        physical_rows = db.execute(select(PhysicalInterface)).scalars().all()
        physical_by_name = {row.name: row for row in physical_rows}
        for row in physical_rows:
            if (
                row.oper_state == "missing"
                or row.admin_state == "down"
                or normalize_interface_role(row.role) in {"management", "unused"}
                or normalize_interface_mode(row.mode) == "trunk"
            ):
                continue
            addresses: list[str] = []
            ipv4_cidr = row.host_ip_cidr if row.ipv4_method == "dhcp" else row.ip_cidr
            ipv6_cidr = row.ipv6_cidr or row.host_ipv6_cidr
            for cidr in (ipv4_cidr, ipv6_cidr):
                if not cidr:
                    continue
                try:
                    addresses.append(str(ip_interface(cidr).ip))
                except ValueError:
                    continue
            if addresses:
                result[row.name] = addresses
        for row in db.execute(select(VlanInterface)).scalars().all():
            parent = physical_by_name.get(row.parent_interface)
            if (
                not row.enabled
                or normalize_interface_role(row.role) in {"management", "unused"}
                or (
                    parent
                    and (parent.oper_state == "missing" or parent.admin_state == "down")
                )
            ):
                continue
            addresses = []
            for cidr in (row.ip_cidr, row.ipv6_cidr):
                if not cidr:
                    continue
                try:
                    addresses.append(str(ip_interface(cidr).ip))
                except ValueError:
                    continue
            if addresses:
                result[row.name] = addresses
        return result

    def _ldap_settings_response(db: Session) -> LdapSettingsResponse:
        """Return ldap settings response.

        Args:
            db: Active database session.
        """
        settings = _ldap_settings_row(db)
        organizations = _ldap_organizations(db)
        ca = db.execute(select(CaSettings)).scalar_one_or_none()
        available_interfaces = set(_ldap_api_interface_addresses(db))
        errors, warnings = validate_ldap_state(
            settings,
            organizations,
            available_interfaces=available_interfaces,
            ca_ready=bool(ca and ca.enabled and ca.root_certificate_pem),
        )
        data = ldap_settings_to_dict(settings)
        policy = data["password_policy"]
        return LdapSettingsResponse(
            id=settings.id,
            enabled=settings.enabled,
            hostname=settings.hostname,
            listen_interfaces=split_interfaces(settings.listen_interface),
            listen_addresses=split_addresses(settings.listen_address),
            ldaps_enabled=settings.ldaps_enabled,
            port=settings.port,
            ldap_enabled=settings.ldap_enabled,
            ldap_port=settings.ldap_port,
            password_policy=policy,
            config_path=settings.config_path,
            certificate_path=data["certificate_path"],
            key_path=data["key_path"],
            chain_path=data["chain_path"],
            root_ca_path=data["root_ca_path"],
            valid=not errors,
            validation_errors=errors,
            validation_warnings=warnings,
            updated_at=settings.updated_at,
        )

    @router.get(
        "/ldap/settings",
        response_model=LdapSettingsResponse,
        tags=["LDAP"],
        operation_id="getLdapSettings",
    )
    def get_ldap_settings(
        identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapSettingsResponse:
        """Get Ldap Settings.

        Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return _ldap_settings_response(db)

    @router.get(
        "/ldap/health",
        response_model=LdapHealthResponse,
        tags=["LDAP"],
        operation_id="getLdapHealth",
    )
    def get_ldap_health(
        identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapHealthResponse:
        """Get Ldap Health.

        Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        response = _ldap_settings_response(db)
        organizations = _ldap_organizations(db)
        service = db.execute(
            select(ServiceState).where(ServiceState.service == "ldap")
        ).scalar_one_or_none()
        running = bool(service and service.running)
        if not get_settings().dry_run_system_adapters:
            running = dependencies.backing_systemd_unit_active("slapd.service") is True
        health = (
            "healthy"
            if response.enabled and running and response.valid
            else "degraded"
            if response.enabled
            else "disabled"
        )
        return LdapHealthResponse(
            enabled=response.enabled,
            running=running,
            health=health,
            ldaps_only=bool(response.ldaps_enabled and not response.ldap_enabled),
            ldaps_enabled=response.ldaps_enabled,
            ldaps_port=response.port,
            ldap_enabled=response.ldap_enabled,
            ldap_port=response.ldap_port,
            hostname=response.hostname,
            port=response.port,
            organization_count=len(organizations),
            user_count=sum(len(row.users) for row in organizations),
            group_count=sum(len(row.groups) for row in organizations),
            validation_errors=response.validation_errors,
            validation_warnings=response.validation_warnings,
        )

    @router.patch(
        "/ldap/settings",
        response_model=LdapSettingsResponse,
        tags=["LDAP"],
        operation_id="updateLdapSettings",
    )
    def update_ldap_settings(
        payload: LdapSettingsUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapSettingsResponse:
        """Update Ldap Settings.

        Requires the `write:ldap` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = _ldap_settings_row(db)
        settings.enabled = payload.enabled
        settings.hostname = (payload.hostname or settings.hostname).strip().lower()
        available = _ldap_api_interface_addresses(db)
        selected_interfaces = [
            item.strip()
            for item in payload.listen_interfaces
            if item.strip() in available
        ]
        settings.listen_interface = ",".join(dict.fromkeys(selected_interfaces))
        settings.listen_address = ",".join(
            dict.fromkeys(
                address
                for interface_name in selected_interfaces
                for address in available[interface_name]
            )
        )
        settings.ldaps_enabled = payload.ldaps_enabled
        settings.port = payload.port
        settings.ldap_enabled = payload.ldap_enabled
        settings.ldap_port = payload.ldap_port
        settings.min_password_length = payload.password_policy.min_length
        settings.require_uppercase = payload.password_policy.require_uppercase
        settings.require_lowercase = payload.password_policy.require_lowercase
        settings.require_number = payload.password_policy.require_number
        settings.require_special = payload.password_policy.require_special
        settings.disallow_username = payload.password_policy.disallow_username
        settings.max_failures = payload.password_policy.max_failures
        settings.lockout_minutes = payload.password_policy.lockout_minutes
        settings.failure_window_minutes = payload.password_policy.failure_window_minutes
        settings.password_history = payload.password_policy.history
        settings.password_max_age_days = payload.password_policy.max_age_days
        settings.config_path = LDAP_STAGED_CONFIG_PATH
        settings.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_ldap_settings",
            resource_type="ldap",
            resource_id=str(settings.id),
        )
        return _ldap_settings_response(db)

    @router.get(
        "/ldap/organizations",
        response_model=list[LdapOrganizationResponse],
        tags=["LDAP"],
        operation_id="listLdapOrganizations",
    )
    def list_ldap_organizations(
        identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
        db: Session = Depends(get_db),
    ) -> list[LdapOrganizationResponse]:
        """List Ldap Organizations.

        Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            LdapOrganizationResponse(**ldap_organization_to_dict(row))
            for row in _ldap_organizations(db)
        ]

    @router.post(
        "/ldap/organizations",
        response_model=LdapOrganizationResponse,
        status_code=201,
        tags=["LDAP"],
        operation_id="createLdapOrganization",
    )
    def create_ldap_organization(
        payload: LdapOrganizationCreate,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapOrganizationResponse:
        """Create Ldap Organization.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        try:
            slug = normalize_ldap_slug(payload.slug or payload.name)
            suffix = normalize_dn(
                payload.suffix_dn or default_organization_suffix(slug)
            )
            if not suffix.lower().startswith("dc="):
                raise ValueError(
                    "LDAP organization suffix must start with a dc component."
                )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        organization = LdapOrganization(
            name=payload.name.strip(),
            slug=slug,
            suffix_dn=suffix,
            enabled=payload.enabled,
        )
        raw_secret = ensure_organization_bind_secret(organization)
        db.add(organization)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="LDAP organization slug or suffix already exists.",
            ) from exc
        db.refresh(organization)
        record_audit(
            db,
            actor=identity.username,
            action="create_ldap_organization",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
        )
        return LdapOrganizationResponse(
            **ldap_organization_to_dict(organization, reveal_bind_secret=raw_secret)
        )

    @router.put(
        "/ldap/organizations/{organization_id}",
        response_model=LdapOrganizationResponse,
        tags=["LDAP"],
        operation_id="updateLdapOrganization",
    )
    def update_ldap_organization(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        payload: LdapOrganizationCreate,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapOrganizationResponse:
        """Update Ldap Organization.

        Requires the `write:ldap` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        try:
            organization.name = payload.name.strip()
            new_slug = normalize_ldap_slug(payload.slug or payload.name)
            new_suffix = normalize_dn(
                payload.suffix_dn or default_organization_suffix(new_slug)
            )
            if not new_suffix.lower().startswith("dc="):
                raise ValueError(
                    "LDAP organization suffix must start with a dc component."
                )
            if (
                new_slug != organization.slug or new_suffix != organization.suffix_dn
            ) and (organization.users or organization.groups):
                raise ValueError(
                    "LDAP organization slug and suffix cannot change after directory entries exist."
                )
            organization.slug = new_slug
            organization.suffix_dn = new_suffix
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        organization.bind_dn = (
            f"uid=vcf-bind,ou=service-accounts,{organization.suffix_dn}"
        )
        organization.enabled = payload.enabled
        organization.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="LDAP organization slug or suffix already exists.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_ldap_organization",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
        )
        return LdapOrganizationResponse(**ldap_organization_to_dict(organization))

    @router.delete(
        "/ldap/organizations/{organization_id}",
        status_code=204,
        tags=["LDAP"],
        operation_id="deleteLdapOrganization",
    )
    def delete_ldap_organization(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Ldap Organization.

        Requires the `write:ldap` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
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
        return Response(status_code=204)

    @router.post(
        "/ldap/organizations/{organization_id}/bind-credential/rotate",
        response_model=LdapBindCredentialResponse,
        tags=["LDAP"],
        operation_id="rotateLdapBindCredential",
    )
    def rotate_ldap_bind_credential(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapBindCredentialResponse:
        """Rotate Ldap Bind Credential.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
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
        response = LdapOrganizationResponse(**ldap_organization_to_dict(organization))
        return LdapBindCredentialResponse(
            organization=response, raw_bind_password=raw_secret
        )

    @router.get(
        "/ldap/organizations/{organization_id}/users",
        response_model=list[LdapUserResponse],
        tags=["LDAP"],
        operation_id="listLdapUsers",
    )
    def list_ldap_users(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
        db: Session = Depends(get_db),
    ) -> list[LdapUserResponse]:
        """List Ldap Users.

        Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rows = (
            db.execute(
                select(LdapUser)
                .where(LdapUser.organization_id == organization_id)
                .order_by(LdapUser.uid)
            )
            .scalars()
            .all()
        )
        return [LdapUserResponse(**ldap_user_to_dict(row)) for row in rows]

    def _apply_ldap_user_payload(user: LdapUser, payload: LdapUserCreate) -> None:
        """Update ldap user payload.

        Args:
            user: User record or identity affected by the operation.
            payload: Validated request or task payload consumed by the operation.


        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        uid = payload.uid.strip().lower()
        if not LDAP_UID_PATTERN.fullmatch(uid):
            raise HTTPException(
                status_code=400,
                detail="LDAP uid must start with a letter and use only lowercase letters, numbers, dot, underscore, or hyphen.",
            )
        user.uid = uid
        user.given_name = payload.given_name.strip()
        user.surname = payload.surname.strip() or payload.display_name.strip() or uid
        user.display_name = (
            payload.display_name.strip()
            or " ".join(
                part for part in [user.given_name, user.surname] if part
            ).strip()
            or uid
        )
        user.email = payload.email.strip().lower()
        user.telephone = payload.telephone.strip()
        user.enabled = payload.enabled
        user.updated_at = utcnow()

    @router.post(
        "/ldap/organizations/{organization_id}/users",
        response_model=LdapUserResponse,
        status_code=201,
        tags=["LDAP"],
        operation_id="createLdapUser",
    )
    def create_ldap_user(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        payload: LdapUserCreate,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapUserResponse:
        """Create Ldap User.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        user = LdapUser(organization_id=organization_id)
        _apply_ldap_user_payload(user, payload)
        db.add(user)
        try:
            db.flush()
            if payload.password:
                stage_ldap_user_password(user, payload.password, _ldap_settings_row(db))
            db.commit()
        except (IntegrityError, ValueError) as exc:
            db.rollback()
            status_code = 409 if isinstance(exc, IntegrityError) else 400
            raise HTTPException(
                status_code=status_code,
                detail="LDAP uid already exists in this organization."
                if status_code == 409
                else str(exc),
            ) from exc
        db.refresh(user)
        record_audit(
            db,
            actor=identity.username,
            action="create_ldap_user",
            resource_type="ldap_user",
            resource_id=str(user.id),
            detail=f"organization_id={organization_id}",
        )
        return LdapUserResponse(**ldap_user_to_dict(user))

    @router.put(
        "/ldap/users/{user_id}",
        response_model=LdapUserResponse,
        tags=["LDAP"],
        operation_id="updateLdapUser",
    )
    def update_ldap_user(
        user_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the user record addressed by this operation."
            ),
        ],
        payload: LdapUserCreate,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapUserResponse:
        """Update Ldap User.

        Requires the `write:ldap` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            user_id: Stable identifier of the associated user resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        user = db.get(LdapUser, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="LDAP user not found")
        invalidate_ldap_user_password_for_uid_change(user, payload.uid.strip().lower())
        _apply_ldap_user_payload(user, payload)
        try:
            if payload.password:
                stage_ldap_user_password(user, payload.password, _ldap_settings_row(db))
            db.commit()
        except (IntegrityError, ValueError) as exc:
            db.rollback()
            status_code = 409 if isinstance(exc, IntegrityError) else 400
            raise HTTPException(
                status_code=status_code,
                detail="LDAP uid already exists in this organization."
                if status_code == 409
                else str(exc),
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_ldap_user",
            resource_type="ldap_user",
            resource_id=str(user.id),
        )
        return LdapUserResponse(**ldap_user_to_dict(user))

    @router.post(
        "/ldap/users/{user_id}/password",
        response_model=LdapUserResponse,
        tags=["LDAP"],
        operation_id="resetLdapUserPassword",
    )
    def reset_ldap_user_password(
        user_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the user record addressed by this operation."
            ),
        ],
        payload: LdapPasswordResetRequest,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapUserResponse:
        """Reset Ldap User Password.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            user_id: Stable identifier of the associated user resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        user = db.get(LdapUser, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="LDAP user not found")
        try:
            stage_ldap_user_password(user, payload.password, _ldap_settings_row(db))
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
        return LdapUserResponse(**ldap_user_to_dict(user))

    @router.post(
        "/ldap/users/{user_id}/unlock",
        response_model=LdapUserResponse,
        tags=["LDAP"],
        operation_id="unlockLdapUser",
    )
    def unlock_ldap_user(
        user_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the user record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapUserResponse:
        """Unlock Ldap User.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            user_id: Stable identifier of the associated user resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
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
        return LdapUserResponse(**ldap_user_to_dict(user))

    @router.delete(
        "/ldap/users/{user_id}",
        status_code=204,
        tags=["LDAP"],
        operation_id="deleteLdapUser",
    )
    def delete_ldap_user(
        user_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the user record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Ldap User.

        Requires the `write:ldap` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            user_id: Stable identifier of the associated user resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        user = db.get(LdapUser, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="LDAP user not found")
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
        return Response(status_code=204)

    def _set_ldap_group_members(
        db: Session, group: LdapGroup, payload: LdapGroupCreate
    ) -> None:
        """Update ldap group members.

        Args:
            db: Active database session.
            group: Role, firewall, or directory group to process.
            payload: Validated request or operation payload.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        group.members.clear()
        db.flush()
        for member in payload.members:
            if member.type == "user":
                user = db.get(LdapUser, member.id)
                if user is None or user.organization_id != group.organization_id:
                    raise HTTPException(
                        status_code=400,
                        detail="LDAP group member user must belong to the same organization.",
                    )
                group.members.append(LdapGroupMembership(member_user=user))
            else:
                member_group = db.get(LdapGroup, member.id)
                if (
                    member_group is None
                    or member_group.organization_id != group.organization_id
                ):
                    raise HTTPException(
                        status_code=400,
                        detail="Nested LDAP group must belong to the same organization.",
                    )
                if member_group.id == group.id:
                    raise HTTPException(
                        status_code=400, detail="LDAP group cannot contain itself."
                    )
                group.members.append(LdapGroupMembership(member_group=member_group))
        db.flush()
        organization_groups = (
            db.execute(
                select(LdapGroup).where(
                    LdapGroup.organization_id == group.organization_id
                )
            )
            .scalars()
            .all()
        )
        cycle_errors = validate_group_cycles(organization_groups)
        if cycle_errors:
            raise HTTPException(status_code=400, detail=cycle_errors[0])

    @router.get(
        "/ldap/organizations/{organization_id}/groups",
        response_model=list[LdapGroupResponse],
        tags=["LDAP"],
        operation_id="listLdapGroups",
    )
    def list_ldap_groups(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
        db: Session = Depends(get_db),
    ) -> list[LdapGroupResponse]:
        """List Ldap Groups.

        Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rows = (
            db.execute(
                select(LdapGroup)
                .where(LdapGroup.organization_id == organization_id)
                .options(
                    selectinload(LdapGroup.organization),
                    selectinload(LdapGroup.members)
                    .selectinload(LdapGroupMembership.member_user)
                    .selectinload(LdapUser.organization),
                    selectinload(LdapGroup.members)
                    .selectinload(LdapGroupMembership.member_group)
                    .selectinload(LdapGroup.organization),
                )
                .order_by(LdapGroup.name)
            )
            .scalars()
            .all()
        )
        return [LdapGroupResponse(**ldap_group_to_dict(row)) for row in rows]

    def _ldap_group_response(db: Session, group_id: int) -> LdapGroupResponse:
        """Return ldap group response.

        Args:
            db: Active database session.
            group_id: Identifier of the group.
        """
        group = (
            db.execute(
                select(LdapGroup)
                .where(LdapGroup.id == group_id)
                .options(
                    selectinload(LdapGroup.organization),
                    selectinload(LdapGroup.members)
                    .selectinload(LdapGroupMembership.member_user)
                    .selectinload(LdapUser.organization),
                    selectinload(LdapGroup.members)
                    .selectinload(LdapGroupMembership.member_group)
                    .selectinload(LdapGroup.organization),
                )
            )
            .scalars()
            .one()
        )
        return LdapGroupResponse(**ldap_group_to_dict(group))

    @router.post(
        "/ldap/organizations/{organization_id}/groups",
        response_model=LdapGroupResponse,
        status_code=201,
        tags=["LDAP"],
        operation_id="createLdapGroup",
    )
    def create_ldap_group(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        payload: LdapGroupCreate,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapGroupResponse:
        """Create Ldap Group.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        if not LDAP_GROUP_PATTERN.fullmatch(payload.name.strip()):
            raise HTTPException(
                status_code=400,
                detail="LDAP group name contains unsupported characters.",
            )
        group = LdapGroup(
            organization=organization,
            name=payload.name.strip(),
            description=payload.description.strip(),
            enabled=payload.enabled,
        )
        db.add(group)
        try:
            db.flush()
            _set_ldap_group_members(db, group, payload)
            db.commit()
        except HTTPException:
            db.rollback()
            raise
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="LDAP group name already exists in this organization.",
            ) from exc
        db.refresh(group)
        record_audit(
            db,
            actor=identity.username,
            action="create_ldap_group",
            resource_type="ldap_group",
            resource_id=str(group.id),
        )
        return _ldap_group_response(db, group.id)

    @router.put(
        "/ldap/groups/{group_id}",
        response_model=LdapGroupResponse,
        tags=["LDAP"],
        operation_id="updateLdapGroup",
    )
    def update_ldap_group(
        group_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the group record addressed by this operation."
            ),
        ],
        payload: LdapGroupCreate,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapGroupResponse:
        """Update Ldap Group.

        Requires the `write:ldap` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            group_id: Stable identifier of the associated group resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        group = db.get(LdapGroup, group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="LDAP group not found")
        if not LDAP_GROUP_PATTERN.fullmatch(payload.name.strip()):
            raise HTTPException(
                status_code=400,
                detail="LDAP group name contains unsupported characters.",
            )
        group.name = payload.name.strip()
        group.description = payload.description.strip()
        group.enabled = payload.enabled
        group.updated_at = utcnow()
        try:
            _set_ldap_group_members(db, group, payload)
            db.commit()
        except HTTPException:
            db.rollback()
            raise
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="LDAP group name already exists in this organization.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_ldap_group",
            resource_type="ldap_group",
            resource_id=str(group.id),
        )
        return _ldap_group_response(db, group.id)

    @router.delete(
        "/ldap/groups/{group_id}",
        status_code=204,
        tags=["LDAP"],
        operation_id="deleteLdapGroup",
    )
    def delete_ldap_group(
        group_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the group record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Ldap Group.

        Requires the `write:ldap` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            group_id: Stable identifier of the associated group resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        group = db.get(LdapGroup, group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="LDAP group not found")
        db.delete(group)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_ldap_group",
            resource_type="ldap_group",
            resource_id=str(group_id),
        )
        return Response(status_code=204)

    @router.get(
        "/ldap/organizations/{organization_id}/vcf-bundle",
        response_model=dict[str, Any],
        tags=["LDAP"],
        operation_id="getLdapVcfBundle",
    )
    def get_ldap_vcf_bundle(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:ldap"))],
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        """Get Ldap Vcf Bundle.

        Requires the `read:ldap` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        ca = db.execute(select(CaSettings)).scalar_one_or_none()
        bundle = manual_vcf_bundle(
            _ldap_settings_row(db),
            organization,
            root_ca_pem=ca.root_certificate_pem if ca else "",
        )
        record_audit(
            db,
            actor=identity.username,
            action="generate_ldap_vcf_bundle",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
        )
        return bundle

    def _sanitize_vcf_ldap_settings(payload: dict[str, Any]) -> dict[str, Any]:
        """Return sanitize vcf ldap settings.

        Args:
            payload: Validated request or task payload consumed by the operation.
        """
        sanitized = json.loads(json.dumps(payload))
        defined = sanitized.get("definedSettings")
        if isinstance(defined, dict) and "password" in defined:
            defined["password"] = "[redacted]"
        return sanitized

    @router.post(
        "/ldap/organizations/{organization_id}/vcf/inspect",
        response_model=LdapVcfInspectionResponse,
        tags=["LDAP"],
        operation_id="inspectLdapVcfConnection",
    )
    def inspect_ldap_vcf_connection(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        payload: LdapVcfInspectRequest,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapVcfInspectionResponse:
        """Inspect Ldap Vcf Connection.

        Requires the `write:ldap` API scope. The request is evaluated without persisting desired state
        or mutating appliance runtime state.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        target_url = normalize_vcf_target_url(payload.target_url)
        try:
            fingerprint = tls_sha256_fingerprint(target_url)
        except (ValueError, VcfLdapError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        proposed = vcf_ldap_settings(
            _ldap_settings_row(db), organization, include_password=False
        )
        if not payload.confirmed_tls_fingerprint:
            record_audit(
                db,
                actor=identity.username,
                action="inspect_vcf_organization_tls",
                resource_type="ldap_organization",
                resource_id=str(organization.id),
                detail=f"target={target_url}; org_id={payload.organization_id}",
            )
            return LdapVcfInspectionResponse(
                target_url=target_url,
                organization_id=payload.organization_id,
                organization_name=payload.organization_name,
                tls_fingerprint=fingerprint,
                current_settings={},
                proposed_settings=proposed,
                changed=True,
            )
        try:
            client = VcfAutomationLdapClient(
                target_url,
                username=payload.username,
                password=payload.password,
                organization_id=payload.organization_id,
                confirmed_tls_fingerprint=payload.confirmed_tls_fingerprint,
            )
            current = client.get_settings()
        except (ValueError, VcfLdapError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        record_audit(
            db,
            actor=identity.username,
            action="inspect_vcf_organization_ldap",
            resource_type="ldap_organization",
            resource_id=str(organization.id),
            detail=f"target={target_url}; org_id={payload.organization_id}",
        )
        return LdapVcfInspectionResponse(
            target_url=target_url,
            organization_id=payload.organization_id,
            organization_name=payload.organization_name,
            tls_fingerprint=fingerprint,
            current_settings=_sanitize_vcf_ldap_settings(current),
            proposed_settings=proposed,
            changed=_sanitize_vcf_ldap_settings(current)
            != _sanitize_vcf_ldap_settings(proposed),
        )

    @router.post(
        "/ldap/organizations/{organization_id}/vcf/configure",
        response_model=LdapVcfInspectionResponse,
        tags=["LDAP"],
        operation_id="configureLdapVcfConnection",
    )
    def configure_ldap_vcf_connection(
        organization_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the organization record addressed by this operation."
            ),
        ],
        payload: LdapVcfConfigureRequest,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> LdapVcfInspectionResponse:
        """Configure Ldap Vcf Connection.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            organization_id: Stable identifier of the associated organization resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        organization = db.get(LdapOrganization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="LDAP organization not found")
        settings = _ldap_settings_row(db)
        proposed = vcf_ldap_settings(settings, organization, include_password=True)
        try:
            client = VcfAutomationLdapClient(
                payload.target_url,
                username=payload.username,
                password=payload.password,
                organization_id=payload.organization_id,
                confirmed_tls_fingerprint=payload.confirmed_tls_fingerprint,
            )
            current = client.get_settings()
            current_enabled = bool(current.get("enabled"))
            if current_enabled and not payload.replace_existing:
                raise VcfLdapError(
                    "VCF organization already has LDAP enabled; confirm replacement before configuring it."
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
            organization.vcf_last_status = "failed"
            organization.vcf_last_message = str(exc)
            organization.updated_at = utcnow()
            db.commit()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        organization.vcf_target_url = normalize_vcf_target_url(payload.target_url)
        organization.vcf_org_id = payload.organization_id
        organization.vcf_org_name = payload.organization_name
        organization.vcf_tls_fingerprint = payload.confirmed_tls_fingerprint.upper()
        organization.vcf_last_status = "verified"
        organization.vcf_last_message = (
            f"LDAP configured; VCF found {len(users)} users and {len(groups)} groups."
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
            detail=f"target={organization.vcf_target_url}; org_id={organization.vcf_org_id}; users={len(users)}; groups={len(groups)}",
        )
        return LdapVcfInspectionResponse(
            target_url=organization.vcf_target_url,
            organization_id=organization.vcf_org_id,
            organization_name=organization.vcf_org_name,
            tls_fingerprint=organization.vcf_tls_fingerprint,
            current_settings=_sanitize_vcf_ldap_settings(verified),
            proposed_settings=_sanitize_vcf_ldap_settings(proposed),
            changed=False,
            test_result=test_result,
            user_count=len(users),
            group_count=len(groups),
        )

    @router.post(
        "/ldap/recovery/export",
        response_model=None,
        tags=["LDAP"],
        operation_id="exportLdapRecovery",
    )
    def export_ldap_recovery(
        payload: LdapRecoveryExportRequest,
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Export Ldap Recovery.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
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
            encrypted = encrypt_recovery_payload(
                plain_path.read_bytes(), payload.passphrase
            )
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

    @router.post(
        "/ldap/recovery/import",
        response_model=LdapRecoveryImportResponse,
        status_code=201,
        tags=["LDAP"],
        operation_id="stageLdapRecoveryImport",
    )
    async def stage_ldap_recovery_import(
        identity: Annotated[Identity, Depends(require_scope("write:ldap"))],
        archive: UploadFile = File(
            ..., description="Request value supplying archive for this operation."
        ),
        passphrase: str = Form(
            ..., description="Request value supplying passphrase for this operation."
        ),
        db: Session = Depends(get_db),
    ) -> LdapRecoveryImportResponse:
        """Stage Ldap Recovery Import.

        Requires the `write:ldap` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            identity: Authenticated identity authorizing the operation.
            archive: Archive consumed by stage LDAP recovery import.
            passphrase: Passphrase consumed by stage LDAP recovery import.
            db: Active database session used by the operation.
        """
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
        db.refresh(row)
        record_audit(
            db,
            actor=identity.username,
            action="stage_ldap_recovery_import",
            resource_type="ldap_recovery",
            resource_id=str(row.id),
            detail=f"sha256={row.sha256}; databases={row.organization_count}",
        )
        return LdapRecoveryImportResponse(
            id=row.id,
            filename=row.filename,
            sha256=row.sha256,
            state=row.state,
            organization_count=row.organization_count,
            created_at=row.created_at,
        )

    return ManagedLdapApiRouter(
        router=router,
        endpoints={
            "_ldap_settings_row": _ldap_settings_row,
            "_ldap_organizations": _ldap_organizations,
            "_ldap_api_interface_addresses": _ldap_api_interface_addresses,
            "_ldap_settings_response": _ldap_settings_response,
            "get_ldap_settings": get_ldap_settings,
            "get_ldap_health": get_ldap_health,
            "update_ldap_settings": update_ldap_settings,
            "list_ldap_organizations": list_ldap_organizations,
            "create_ldap_organization": create_ldap_organization,
            "update_ldap_organization": update_ldap_organization,
            "delete_ldap_organization": delete_ldap_organization,
            "rotate_ldap_bind_credential": rotate_ldap_bind_credential,
            "list_ldap_users": list_ldap_users,
            "_apply_ldap_user_payload": _apply_ldap_user_payload,
            "create_ldap_user": create_ldap_user,
            "update_ldap_user": update_ldap_user,
            "reset_ldap_user_password": reset_ldap_user_password,
            "unlock_ldap_user": unlock_ldap_user,
            "delete_ldap_user": delete_ldap_user,
            "_set_ldap_group_members": _set_ldap_group_members,
            "list_ldap_groups": list_ldap_groups,
            "_ldap_group_response": _ldap_group_response,
            "create_ldap_group": create_ldap_group,
            "update_ldap_group": update_ldap_group,
            "delete_ldap_group": delete_ldap_group,
            "get_ldap_vcf_bundle": get_ldap_vcf_bundle,
            "_sanitize_vcf_ldap_settings": _sanitize_vcf_ldap_settings,
            "inspect_ldap_vcf_connection": inspect_ldap_vcf_connection,
            "configure_ldap_vcf_connection": configure_ldap_vcf_connection,
            "export_ldap_recovery": export_ldap_recovery,
            "stage_ldap_recovery_import": stage_ldap_recovery_import,
        },
    )
