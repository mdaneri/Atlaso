from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    ApiToken,
    DnsRecord,
    LdapGroup,
    LdapOrganization,
    OidcGroupMapping,
    OidcSigningKey,
    Role,
    User,
    utcnow,
)
from atlaso.app.schemas import ApiTokenCreate
from atlaso.app.security import (
    Identity,
    primary_role,
    require_session_identity,
    roles_to_json,
    scopes_for_roles,
)
from atlaso.app.services.appliance_settings import normalize_fqdn
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces
from atlaso.app.services.local_users import (
    DEFAULT_LOCAL_USER_SHELL,
    DEFAULT_PASSWORD_POLICY,
    LOCAL_USER_SHELLS,
    LOCAL_USERS_PASSWORD_POLICY_KEY,
    clear_pending_os_password,
    has_pending_os_password,
    is_valid_user_shell,
    normalize_user_shell,
    password_policy_from_json,
    password_policy_summary,
    password_policy_to_json,
    rename_pending_os_password,
    stage_user_os_password,
    validate_password,
)
from atlaso.app.services.oidc import (
    OIDC_AUTHORIZATION_FLOW_AVAILABLE,
    OIDC_DEFAULT_HOSTNAME,
    OIDC_DNS_RECORD_DESCRIPTION,
    OidcConfigurationError,
    OidcConflictError,
    oidc_client_to_dict,
)
from atlaso.app.services.oidc import create_client as create_oidc_client_record
from atlaso.app.services.oidc import (
    create_group_mapping as create_oidc_group_mapping_record,
)
from atlaso.app.services.oidc import (
    delete_retired_signing_key as delete_retired_oidc_signing_key_record,
)
from atlaso.app.services.oidc import (
    ensure_provider_settings as ensure_oidc_provider_settings,
)
from atlaso.app.services.oidc import expected_issuer_url as expected_oidc_issuer_url
from atlaso.app.services.oidc import generate_signing_key as generate_oidc_signing_key
from atlaso.app.services.oidc import get_client as get_oidc_client
from atlaso.app.services.oidc import group_mapping_to_dict as oidc_group_mapping_to_dict
from atlaso.app.services.oidc import integration_export as oidc_integration_export
from atlaso.app.services.oidc import issuer_endpoint_urls as oidc_issuer_endpoint_urls
from atlaso.app.services.oidc import list_clients as list_oidc_clients
from atlaso.app.services.oidc import list_group_mappings as list_oidc_group_mappings
from atlaso.app.services.oidc import list_subjects as list_oidc_subjects
from atlaso.app.services.oidc import normalize_issuer_url as normalize_oidc_issuer_url
from atlaso.app.services.oidc import (
    provider_validation_errors as oidc_provider_validation_errors,
)
from atlaso.app.services.oidc import (
    rotate_client_secret as rotate_oidc_client_secret_value,
)
from atlaso.app.services.oidc import signing_key_to_dict as oidc_signing_key_to_dict
from atlaso.app.services.oidc import update_client as update_oidc_client_record
from atlaso.app.services.oidc import (
    update_group_mapping as update_oidc_group_mapping_record,
)
from atlaso.app.services.oidc import (
    validate_all_mapping_contexts as validate_oidc_mapping_contexts,
)
from atlaso.app.token_service import create_token_for_user
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class IdentityUiDependencies:
    require_management_ui_request: Endpoint
    appliance_apply_status: Endpoint
    ensure_ca_state: Endpoint
    ensure_dns_for_oidc: Endpoint
    get_dns_settings_row: Endpoint
    grid_request: Endpoint
    grid_saved_response: Endpoint
    ldap_service_bind_options: Endpoint
    local_users_password_policy: Endpoint
    normalize_dns_hostname: Endpoint
    protect_last_admin: Endpoint
    public_services_context: Endpoint
    render: Endpoint
    require_admin_identity: Endpoint
    resolve_ldap_bind_targets: Endpoint
    revoke_user_tokens: Endpoint
    roles_from_form: Endpoint
    set_setting_value: Endpoint
    user_to_dict: Endpoint
    users_context: Endpoint
    verify_csrf: Endpoint


@dataclass(frozen=True)
class IdentityUiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: IdentityUiDependencies) -> IdentityUiRouter:
    """Build identity-management transports without importing the UI facade."""
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    appliance_apply_status = dependencies.appliance_apply_status
    ensure_ca_state = dependencies.ensure_ca_state
    ensure_dns_for_oidc = dependencies.ensure_dns_for_oidc
    get_dns_settings_row = dependencies.get_dns_settings_row
    grid_request = dependencies.grid_request
    grid_saved_response = dependencies.grid_saved_response
    ldap_service_bind_options = dependencies.ldap_service_bind_options
    local_users_password_policy = dependencies.local_users_password_policy
    normalize_dns_hostname = dependencies.normalize_dns_hostname
    protect_last_admin = dependencies.protect_last_admin
    public_services_context = dependencies.public_services_context
    render = dependencies.render
    require_admin_identity = dependencies.require_admin_identity
    resolve_ldap_bind_targets = dependencies.resolve_ldap_bind_targets
    revoke_user_tokens = dependencies.revoke_user_tokens
    roles_from_form = dependencies.roles_from_form
    set_setting_value = dependencies.set_setting_value
    user_to_dict = dependencies.user_to_dict
    users_context = dependencies.users_context
    verify_csrf = dependencies.verify_csrf

    @router.get("/authentication", response_class=HTMLResponse, response_model=None)
    def authentication(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the authentication endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "authentication.html",
            authentication_context(db, identity, raw_token=None),
        )

    @router.get("/openid-connect", response_class=HTMLResponse, response_model=None)
    def openid_connect(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the openid connect endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_admin_identity(identity)
        return render(
            request,
            "authentication.html",
            authentication_context(db, identity, raw_token=None, oidc_page=True),
        )

    def api_token_grid_row(token: ApiToken) -> dict[str, Any]:
        """Return api token grid row.

        Args:
            token: Credential or token value consumed by the operation.
        """
        active = bool(token.enabled and not token.revoked_at)
        return {
            "id": token.id,
            "name": token.name,
            "description": token.description or "",
            "owner_username": token.owner_username,
            "role": token.role,
            "scopes": token.scopes,
            "expires_at": token.expires_at.isoformat(),
            "expires_label": token.expires_at.strftime("%Y-%m-%d"),
            "enabled": active,
            "status": "active" if active else "revoked",
        }

    def authentication_context(
        db: Session,
        identity: Identity,
        *,
        raw_token: str | None,
        oidc_client_secret: str | None = None,
        oidc_client_id: str | None = None,
        oidc_error: str | None = None,
        oidc_page: bool = False,
    ) -> dict[str, Any]:
        """Return authentication context.

        Args:
            db: Active database session.
            identity: Authenticated identity authorizing the request.
            raw_token: Raw token supplied by the caller.
            oidc_client_secret: Oidc client secret supplied by the caller.
            oidc_client_id: Identifier of the oidc client.
            oidc_error: Oidc error supplied by the caller.
            oidc_page: Oidc page supplied by the caller.
        """
        query = select(ApiToken).order_by(desc(ApiToken.created_at))
        if not identity.has_role(Role.ADMIN.value):
            query = query.where(ApiToken.owner_user_id == identity.user_id)
        tokens = db.execute(query).scalars().all()
        context: dict[str, Any] = {
            "identity": identity,
            "tokens": tokens,
            "api_token_rows": [api_token_grid_row(token) for token in tokens],
            "api_token_scope_options": sorted(scopes_for_roles(identity.roles)),
            "raw_token": raw_token,
            "oidc_page": oidc_page,
            "oidc_admin": identity.has_role(Role.ADMIN.value),
            "oidc_client_secret": oidc_client_secret,
            "oidc_client_id": oidc_client_id,
            "oidc_error": oidc_error,
        }
        if not oidc_page or not context["oidc_admin"]:
            return context
        provider = ensure_oidc_provider_settings(db)
        try:
            endpoint_urls = oidc_issuer_endpoint_urls(provider.issuer_url)
        except OidcConfigurationError:
            endpoint_urls = {
                "issuer": provider.issuer_url,
                "discovery_url": "",
                "authorization_endpoint": "",
                "token_endpoint": "",
                "userinfo_endpoint": "",
                "jwks_uri": "",
                "end_session_endpoint": "",
            }
        oidc_client_rows = list_oidc_clients(db)
        dns_settings = get_dns_settings_row(db)
        oidc_available_interfaces = ldap_service_bind_options(db)
        public_services = public_services_context(db, reconcile=False)
        issuer_fqdn = normalize_fqdn(provider.hostname or OIDC_DEFAULT_HOSTNAME)
        managed_issuer_dns_records = (
            db.execute(
                select(DnsRecord)
                .where(
                    DnsRecord.description == OIDC_DNS_RECORD_DESCRIPTION,
                    DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]),
                    DnsRecord.enabled.is_(True),
                )
                .order_by(DnsRecord.hostname, DnsRecord.record_type)
            )
            .scalars()
            .all()
        )
        oidc_ldap_group_rows = (
            db.execute(
                select(LdapGroup)
                .options(selectinload(LdapGroup.organization))
                .order_by(LdapGroup.organization_id, LdapGroup.name)
            )
            .scalars()
            .all()
        )
        context.update(
            {
                "oidc_provider": provider,
                "oidc_issuer_fqdn": issuer_fqdn,
                "oidc_available_interfaces": oidc_available_interfaces,
                "oidc_selected_interfaces": split_interfaces(provider.listen_interface),
                "oidc_selected_addresses": split_addresses(provider.listen_address),
                "oidc_dns_enabled": dns_settings.enabled,
                "oidc_dns_records": [
                    {
                        "hostname": row.hostname,
                        "record_type": row.record_type,
                        "address": row.address,
                    }
                    for row in managed_issuer_dns_records
                ],
                "oidc_flow_available": OIDC_AUTHORIZATION_FLOW_AVAILABLE,
                "oidc_validation_errors": oidc_provider_validation_errors(db, provider),
                "oidc_urls": endpoint_urls,
                "oidc_config_preview": public_services["public_service_config_preview"],
                "oidc_config_path": public_services["public_service_config_path"],
                "oidc_clients": jsonable_encoder(
                    [oidc_client_to_dict(row) for row in oidc_client_rows]
                ),
                "oidc_keys": jsonable_encoder(
                    [
                        oidc_signing_key_to_dict(row)
                        for row in db.execute(
                            select(OidcSigningKey).order_by(
                                OidcSigningKey.created_at.desc()
                            )
                        )
                        .scalars()
                        .all()
                    ]
                ),
                "oidc_subjects": jsonable_encoder(list_oidc_subjects(db)),
                "oidc_group_mappings": jsonable_encoder(
                    [
                        oidc_group_mapping_to_dict(row)
                        for row in list_oidc_group_mappings(db)
                    ]
                ),
                "oidc_local_roles": [role.value for role in Role],
                "oidc_ldap_group_options": [
                    {
                        "id": row.id,
                        "label": (
                            f"{row.organization.name} / {row.name}"
                            f"{'' if row.enabled else ' (disabled)'}"
                        ),
                        "organization_id": row.organization_id,
                        "organization_name": row.organization.name,
                        "enabled": row.enabled,
                    }
                    for row in oidc_ldap_group_rows
                ],
                "oidc_client_options": [
                    {
                        "id": row.id,
                        "name": row.name,
                        "organization_id": row.organization_id,
                        "organization_name": (
                            row.organization.name
                            if row.organization is not None
                            else "Unbound"
                        ),
                        "enabled": row.enabled,
                    }
                    for row in oidc_client_rows
                ],
                "oidc_organizations": db.execute(
                    select(LdapOrganization)
                    .where(LdapOrganization.enabled.is_(True))
                    .order_by(LdapOrganization.name)
                )
                .scalars()
                .all(),
            }
        )
        return context

    @router.post("/authentication/oidc/provider", response_model=None)
    def update_oidc_provider_from_ui(
        request: Request,
        enabled: bool = Form(False),
        hostname: str = Form(OIDC_DEFAULT_HOSTNAME),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        port: int = Form(443),
        access_token_lifetime_seconds: int = Form(300),
        id_token_lifetime_seconds: int = Form(300),
        authorization_code_lifetime_seconds: int = Form(60),
        clock_skew_seconds: int = Form(120),
        signing_key_overlap_seconds: int = Form(3600),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update oidc provider from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            hostname: DNS hostname of the target resource.
            listen_interfaces: Interfaces on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            port: TCP or UDP port of the target service.
            access_token_lifetime_seconds: Access token lifetime seconds supplied by the caller.
            id_token_lifetime_seconds: Id token lifetime seconds supplied by the caller.
            authorization_code_lifetime_seconds: Authorization code lifetime seconds supplied by the caller.
            clock_skew_seconds: Clock skew seconds supplied by the caller.
            signing_key_overlap_seconds: Signing key overlap seconds supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            OidcConfigurationError: If the operation encounters an invalid state.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        provider = ensure_oidc_provider_settings(db)
        previous_hostname = provider.hostname
        try:
            normalized_hostname = normalize_dns_hostname(hostname)
            if not normalized_hostname or "." not in normalized_hostname:
                raise OidcConfigurationError(
                    "OIDC hostname must be a fully qualified DNS name."
                )
            selected_interfaces, selected_addresses = resolve_ldap_bind_targets(
                db,
                listen_interfaces,
                current_interface=provider.listen_interface,
                listen_interfaces_present=listen_interfaces_present,
            )
            provider.hostname = normalized_hostname
            provider.listen_interface = selected_interfaces
            provider.listen_address = selected_addresses
            provider.port = max(1, min(port, 65535))
            provider.issuer_url = normalize_oidc_issuer_url(
                expected_oidc_issuer_url(provider)
            )
        except OidcConfigurationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        provider.access_token_lifetime_seconds = max(
            60, min(access_token_lifetime_seconds, 3600)
        )
        provider.id_token_lifetime_seconds = max(
            60, min(id_token_lifetime_seconds, 3600)
        )
        provider.authorization_code_lifetime_seconds = max(
            30, min(authorization_code_lifetime_seconds, 300)
        )
        provider.clock_skew_seconds = max(0, min(clock_skew_seconds, 300))
        provider.signing_key_overlap_seconds = max(
            300, min(signing_key_overlap_seconds, 604800)
        )
        provider.enabled = enabled
        provider.updated_at = utcnow()
        db.add(provider)
        db.flush()
        ensure_dns_for_oidc(
            db,
            provider,
            identity.username,
            previous_hostname=previous_hostname,
        )
        ensure_ca_state(db)
        db.flush()
        validation_errors = oidc_provider_validation_errors(db, provider)
        if enabled and validation_errors:
            provider.enabled = False
            ensure_dns_for_oidc(
                db,
                provider,
                identity.username,
                previous_hostname=provider.hostname,
            )
            validation_errors = [
                "Provider enablement was rejected until every readiness check passes.",
                *validation_errors,
            ]
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_oidc_provider",
            resource_type="oidc_provider",
            resource_id=str(provider.id),
        )
        payload = {
            "saved": True,
            "valid": not validation_errors,
            "enabled": provider.enabled,
            "issuer_url": provider.issuer_url,
            "hostname": provider.hostname,
            "listen_interfaces": split_interfaces(provider.listen_interface),
            "listen_addresses": split_addresses(provider.listen_address),
            "port": provider.port,
            "validation_errors": validation_errors,
            "urls": oidc_issuer_endpoint_urls(provider.issuer_url),
        }
        if request.headers.get("X-Atlaso-Autosave") == "1":
            return JSONResponse(payload)
        return RedirectResponse("/openid-connect#oidc-provider", status_code=303)

    @router.post(
        "/authentication/oidc/clients", response_class=HTMLResponse, response_model=None
    )
    def create_oidc_client_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        organization_id: str = Form(""),
        redirect_uris: str = Form(...),
        post_logout_redirect_uris: str = Form(""),
        preset: str = Form("custom"),
        allowed_scopes: list[str] = Form(default_factory=list),
        allow_loopback_redirects: str | None = Form(None),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the create oidc client from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            organization_id: Identifier of the organization.
            redirect_uris: Redirect uris supplied by the caller.
            post_logout_redirect_uris: Post logout redirect uris supplied by the caller.
            preset: Preset supplied by the caller.
            allowed_scopes: Allowed scopes supplied by the caller.
            allow_loopback_redirects: Allow loopback redirects supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            OidcConfigurationError: If the operation encounters an invalid state.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        try:
            if preset == "vcf-9.1" and not redirect_uris.strip():
                raise OidcConfigurationError(
                    "Paste the exact redirect URI supplied by the VCF 9.1 Identity Broker."
                )
            row, raw_secret = create_oidc_client_record(
                db,
                name=name,
                description=description,
                organization_id=int(organization_id)
                if organization_id.strip()
                else None,
                redirect_uris=[
                    value.strip()
                    for value in redirect_uris.splitlines()
                    if value.strip()
                ],
                post_logout_redirect_uris=[
                    value.strip()
                    for value in post_logout_redirect_uris.splitlines()
                    if value.strip()
                ],
                allowed_scopes=allowed_scopes or ["openid"],
                allow_loopback_redirects=allow_loopback_redirects == "on",
                access_token_lifetime_seconds=300,
                id_token_lifetime_seconds=300,
                authorization_code_lifetime_seconds=60,
                enabled=enabled == "on",
            )
        except (OidcConfigurationError, ValueError) as exc:
            return render(
                request,
                "authentication.html",
                authentication_context(
                    db,
                    identity,
                    raw_token=None,
                    oidc_error=str(exc),
                    oidc_page=True,
                ),
                status_code=422,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_oidc_client",
            resource_type="oidc_client",
            resource_id=str(row.id),
            detail=f"client_id={row.client_id}; preset={preset}",
        )
        if request.headers.get("X-Atlaso-Grid") == "1":
            return JSONResponse(
                {
                    "client": jsonable_encoder(oidc_client_to_dict(row)),
                    "client_secret": raw_secret,
                },
                status_code=201,
            )
        return render(
            request,
            "authentication.html",
            authentication_context(
                db,
                identity,
                raw_token=None,
                oidc_client_secret=raw_secret,
                oidc_client_id=row.client_id,
                oidc_page=True,
            ),
        )

    @router.post(
        "/authentication/oidc/clients/{client_record_id}/edit",
        response_model=None,
    )
    def update_oidc_client_from_ui(
        request: Request,
        client_record_id: int,
        name: str = Form(...),
        description: str = Form(""),
        organization_id: str = Form(""),
        redirect_uris: str = Form(...),
        post_logout_redirect_uris: str = Form(""),
        allowed_scopes: list[str] = Form(default_factory=list),
        allow_loopback_redirects: str | None = Form(None),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update oidc client from ui endpoint.

        Args:
            request: Incoming HTTP request.
            client_record_id: Identifier of the client record.
            name: Name of the target object.
            description: Human-readable description of the resource.
            organization_id: Identifier of the organization.
            redirect_uris: Redirect uris supplied by the caller.
            post_logout_redirect_uris: Post logout redirect uris supplied by the caller.
            allowed_scopes: Allowed scopes supplied by the caller.
            allow_loopback_redirects: Allow loopback redirects supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        try:
            row = get_oidc_client(db, client_record_id)
            row = update_oidc_client_record(
                db,
                row=row,
                name=name,
                description=description,
                organization_id=int(organization_id)
                if organization_id.strip()
                else None,
                redirect_uris=[
                    value.strip()
                    for value in redirect_uris.splitlines()
                    if value.strip()
                ],
                post_logout_redirect_uris=[
                    value.strip()
                    for value in post_logout_redirect_uris.splitlines()
                    if value.strip()
                ],
                allowed_scopes=allowed_scopes or ["openid"],
                allow_loopback_redirects=allow_loopback_redirects == "on",
                access_token_lifetime_seconds=300,
                id_token_lifetime_seconds=300,
                authorization_code_lifetime_seconds=60,
                enabled=enabled == "on",
            )
        except OidcConfigurationError as exc:
            db.rollback()
            detail = (
                exc.args[0]
                if len(exc.args) == 1 and isinstance(exc.args[0], str)
                else ("The OIDC client update was rejected.")
            )
            if request.headers.get("X-Atlaso-Grid") == "1":
                return JSONResponse({"detail": detail}, status_code=422)
            raise HTTPException(status_code=422, detail=detail) from None
        record_audit(
            db,
            actor=identity.username,
            action="update_oidc_client",
            resource_type="oidc_client",
            resource_id=str(row.id),
            detail=f"client_id={row.client_id}; organization_id={row.organization_id or 'unbound'}",
        )
        if request.headers.get("X-Atlaso-Grid") == "1":
            return JSONResponse(jsonable_encoder(oidc_client_to_dict(row)))
        return RedirectResponse("/openid-connect#oidc-clients", status_code=303)

    @router.get(
        "/authentication/oidc/clients/{client_record_id}/integration-export",
        response_model=None,
    )
    def export_oidc_client_integration_from_ui(
        request: Request,
        client_record_id: int,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the export oidc client integration from ui endpoint.

        Args:
            request: Incoming HTTP request.
            client_record_id: Identifier of the client record.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        try:
            row = get_oidc_client(db, client_record_id)
        except OidcConfigurationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        record_audit(
            db,
            actor=identity.username,
            action="export_oidc_client_integration",
            resource_type="oidc_client",
            resource_id=str(row.id),
            detail=f"client_id={row.client_id}",
        )
        response = JSONResponse(jsonable_encoder(oidc_integration_export(db, row)))
        response.headers["Content-Disposition"] = (
            f'attachment; filename="atlaso-oidc-{row.id}-integration.json"'
        )
        return response

    @router.post(
        "/authentication/oidc/group-mappings",
        response_class=HTMLResponse,
        response_model=None,
    )
    def create_oidc_group_mapping_from_ui(
        request: Request,
        source_type: str = Form(...),
        local_role: str = Form(""),
        ldap_group_id: str = Form(""),
        oidc_client_id: str = Form(""),
        external_group_name: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create oidc group mapping from ui endpoint.

        Args:
            request: Incoming HTTP request.
            source_type: Source type supplied by the caller.
            local_role: Local role supplied by the caller.
            ldap_group_id: Identifier of the ldap group.
            oidc_client_id: Identifier of the oidc client.
            external_group_name: External group name supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        try:
            row = create_oidc_group_mapping_record(
                db,
                source_type=source_type,
                local_role=local_role,
                ldap_group_id=int(ldap_group_id) if ldap_group_id.strip() else None,
                oidc_client_id=int(oidc_client_id) if oidc_client_id.strip() else None,
                external_group_name=external_group_name,
            )
        except OidcConflictError:
            db.rollback()
            detail = "A mapping already exists for this source and mapping scope."
            if request.headers.get("X-Atlaso-Grid") == "1":
                return JSONResponse({"detail": detail}, status_code=409)
            return render(
                request,
                "authentication.html",
                authentication_context(
                    db,
                    identity,
                    raw_token=None,
                    oidc_error=detail,
                    oidc_page=True,
                ),
                status_code=409,
            )
        except OidcConfigurationError, ValueError:
            db.rollback()
            detail = (
                "Review the group source, client scope, and external name; "
                "the mapping is not valid in its effective context."
            )
            if request.headers.get("X-Atlaso-Grid") == "1":
                return JSONResponse({"detail": detail}, status_code=422)
            return render(
                request,
                "authentication.html",
                authentication_context(
                    db,
                    identity,
                    raw_token=None,
                    oidc_error=detail,
                    oidc_page=True,
                ),
                status_code=422,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_oidc_group_mapping",
            resource_type="oidc_group_mapping",
            resource_id=str(row.id),
            detail=(
                f"source_type={row.source_type}; organization_id={row.organization_id or 'local'}; "
                f"client_id={row.oidc_client_id or 'default'}"
            ),
        )
        if request.headers.get("X-Atlaso-Grid") == "1":
            return JSONResponse(
                jsonable_encoder(oidc_group_mapping_to_dict(row)),
                status_code=201,
            )
        return RedirectResponse("/openid-connect#oidc-group-mappings", status_code=303)

    @router.post(
        "/authentication/oidc/group-mappings/{mapping_id}/edit",
        response_model=None,
    )
    def update_oidc_group_mapping_from_ui(
        request: Request,
        mapping_id: int,
        oidc_client_id: str = Form(""),
        external_group_name: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update oidc group mapping from ui endpoint.

        Args:
            request: Incoming HTTP request.
            mapping_id: Identifier of the mapping.
            oidc_client_id: Identifier of the oidc client.
            external_group_name: External group name supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        row = db.get(OidcGroupMapping, mapping_id)
        if row is None:
            return JSONResponse(
                {"detail": "OIDC group mapping not found."}, status_code=404
            )
        try:
            row = update_oidc_group_mapping_record(
                db,
                row=row,
                oidc_client_id=int(oidc_client_id) if oidc_client_id.strip() else None,
                external_group_name=external_group_name,
            )
        except OidcConflictError:
            db.rollback()
            return JSONResponse(
                {
                    "detail": "A mapping already exists for this source and mapping scope."
                },
                status_code=409,
            )
        except OidcConfigurationError, ValueError:
            db.rollback()
            return JSONResponse(
                {
                    "detail": (
                        "Review the group source, client scope, and external name; "
                        "the mapping is not valid in its effective context."
                    )
                },
                status_code=422,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_oidc_group_mapping",
            resource_type="oidc_group_mapping",
            resource_id=str(row.id),
            detail=(
                f"source_type={row.source_type}; organization_id={row.organization_id or 'local'}; "
                f"client_id={row.oidc_client_id or 'default'}"
            ),
        )
        return JSONResponse(jsonable_encoder(oidc_group_mapping_to_dict(row)))

    @router.post(
        "/authentication/oidc/group-mappings/{mapping_id}/delete",
        response_model=None,
    )
    def delete_oidc_group_mapping_from_ui(
        request: Request,
        mapping_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete oidc group mapping from ui endpoint.

        Args:
            request: Incoming HTTP request.
            mapping_id: Identifier of the mapping.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        row = db.get(OidcGroupMapping, mapping_id)
        if row is None:
            raise HTTPException(status_code=404, detail="OIDC group mapping not found.")
        source_type = row.source_type
        organization_id = row.organization_id
        client_id = row.oidc_client_id
        try:
            db.delete(row)
            db.flush()
            validate_oidc_mapping_contexts(db)
        except OidcConfigurationError:
            db.rollback()
            detail = (
                "Deleting this override would create duplicate effective external "
                "group names. Update the remaining mappings first."
            )
            if request.headers.get("X-Atlaso-Grid") == "1":
                return JSONResponse({"detail": detail}, status_code=422)
            return render(
                request,
                "authentication.html",
                authentication_context(
                    db,
                    identity,
                    raw_token=None,
                    oidc_error=detail,
                    oidc_page=True,
                ),
                status_code=422,
            )
        record_audit(
            db,
            actor=identity.username,
            action="delete_oidc_group_mapping",
            resource_type="oidc_group_mapping",
            resource_id=str(mapping_id),
            detail=(
                f"source_type={source_type}; organization_id={organization_id or 'local'}; "
                f"client_id={client_id or 'default'}"
            ),
        )
        if request.headers.get("X-Atlaso-Grid") == "1":
            return Response(status_code=204)
        return RedirectResponse("/openid-connect#oidc-group-mappings", status_code=303)

    @router.post(
        "/authentication/oidc/clients/{client_record_id}/rotate-secret",
        response_class=HTMLResponse,
        response_model=None,
    )
    def rotate_oidc_client_secret_from_ui(
        request: Request,
        client_record_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the rotate oidc client secret from ui endpoint.

        Args:
            request: Incoming HTTP request.
            client_record_id: Identifier of the client record.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        try:
            row = get_oidc_client(db, client_record_id)
        except OidcConfigurationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        raw_secret = rotate_oidc_client_secret_value(db, row)
        record_audit(
            db,
            actor=identity.username,
            action="rotate_oidc_client_secret",
            resource_type="oidc_client",
            resource_id=str(row.id),
            detail=f"client_id={row.client_id}",
        )
        if request.headers.get("X-Atlaso-Grid") == "1":
            return JSONResponse(
                {"client_id": row.client_id, "client_secret": raw_secret}
            )
        return render(
            request,
            "authentication.html",
            authentication_context(
                db,
                identity,
                raw_token=None,
                oidc_client_secret=raw_secret,
                oidc_client_id=row.client_id,
                oidc_page=True,
            ),
        )

    @router.post(
        "/authentication/oidc/clients/{client_record_id}/delete", response_model=None
    )
    def delete_oidc_client_from_ui(
        request: Request,
        client_record_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete oidc client from ui endpoint.

        Args:
            request: Incoming HTTP request.
            client_record_id: Identifier of the client record.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        try:
            row = get_oidc_client(db, client_record_id)
        except OidcConfigurationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        public_client_id = row.client_id
        db.delete(row)
        db.flush()
        record_audit(
            db,
            actor=identity.username,
            action="delete_oidc_client",
            resource_type="oidc_client",
            resource_id=str(client_record_id),
            detail=f"client_id={public_client_id}",
        )
        if request.headers.get("X-Atlaso-Grid") == "1":
            return Response(status_code=204)
        return RedirectResponse("/openid-connect#oidc-clients", status_code=303)

    @router.post("/authentication/oidc/signing-keys", response_model=None)
    def create_oidc_signing_key_from_ui(
        request: Request,
        rotate: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create oidc signing key from ui endpoint.

        Args:
            request: Incoming HTTP request.
            rotate: Rotate supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        try:
            row, previous = generate_oidc_signing_key(db, rotate=rotate == "true")
        except OidcConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            db,
            actor=identity.username,
            action="rotate_oidc_signing_key"
            if previous
            else "generate_oidc_signing_key",
            resource_type="oidc_signing_key",
            resource_id=str(row.id),
            detail=f"kid={row.kid}; algorithm={row.algorithm}",
        )
        if request.headers.get("X-Atlaso-Grid") == "1":
            return JSONResponse(
                jsonable_encoder(
                    {
                        "key": oidc_signing_key_to_dict(row),
                        "previous": (
                            oidc_signing_key_to_dict(previous)
                            if previous is not None
                            else None
                        ),
                    }
                ),
                status_code=201,
            )
        return RedirectResponse("/openid-connect#oidc-keys", status_code=303)

    @router.post(
        "/authentication/oidc/signing-keys/{key_id}/delete",
        response_model=None,
    )
    def delete_retired_oidc_signing_key_from_ui(
        request: Request,
        key_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete retired oidc signing key from ui endpoint.

        Args:
            request: Incoming HTTP request.
            key_id: Identifier of the key.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        row = db.get(OidcSigningKey, key_id)
        if row is None:
            raise HTTPException(status_code=404, detail="OIDC signing key not found.")
        kid = row.kid
        try:
            delete_retired_oidc_signing_key_record(db, row)
        except OidcConflictError as exc:
            detail = (
                exc.args[0]
                if len(exc.args) == 1 and isinstance(exc.args[0], str)
                else ("The OIDC signing key cannot be deleted.")
            )
            if request.headers.get("X-Atlaso-Grid") == "1":
                return JSONResponse({"detail": detail}, status_code=409)
            raise HTTPException(status_code=409, detail=detail) from None
        record_audit(
            db,
            actor=identity.username,
            action="delete_retired_oidc_signing_key",
            resource_type="oidc_signing_key",
            resource_id=str(key_id),
            detail=f"kid={kid}",
        )
        if request.headers.get("X-Atlaso-Grid") == "1":
            return Response(status_code=204)
        return RedirectResponse("/openid-connect#oidc-keys", status_code=303)

    @router.post("/authentication/api-tokens", response_model=None)
    def create_token_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        scopes: str = Form("read:dashboard read:routes read:wan"),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse | JSONResponse:
        """Handle the create token from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            scopes: Permission scopes to evaluate or grant.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        user = db.get(User, identity.user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Current user not found")
        token_result = create_token_for_user(
            db,
            user=user,
            create=ApiTokenCreate(
                name=name, description=description or None, scopes=scopes.split()
            ),
            settings=get_settings(),
            actor=identity.username,
        )
        if grid_request(request):
            token = db.get(ApiToken, token_result.token.id)
            if token is None:
                raise HTTPException(
                    status_code=500, detail="The created API token could not be loaded."
                )
            return grid_saved_response(
                request,
                redirect_url="/authentication",
                resource_name="token",
                resource=api_token_grid_row(token),
                extra={"raw_token": token_result.raw_token},
            )
        return render(
            request,
            "authentication.html",
            authentication_context(db, identity, raw_token=token_result.raw_token),
        )

    @router.post("/authentication/api-tokens/{token_id}/revoke", response_model=None)
    def revoke_token_from_ui(
        request: Request,
        token_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the revoke token from ui endpoint.

        Args:
            request: Incoming HTTP request.
            token_id: Identifier of the token.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        token = db.get(ApiToken, token_id)
        if not token or (
            not identity.has_role(Role.ADMIN.value)
            and token.owner_user_id != identity.user_id
        ):
            raise HTTPException(status_code=404, detail="API token not found")
        token.enabled = False
        token.revoked_at = utcnow()
        token.revoked_by = identity.username
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="revoke_api_token",
            resource_type="api_token",
            resource_id=str(token.id),
        )
        return grid_saved_response(
            request,
            redirect_url="/authentication",
            resource_name="token",
            resource=api_token_grid_row(token),
        )

    @router.get("/users", response_class=HTMLResponse, response_model=None)
    def users_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the users page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_admin_identity(identity)
        return render(
            request,
            "users.html",
            {
                "identity": identity,
                **users_context(db, identity),
                "appliance_apply_status": appliance_apply_status(db, "local_users"),
            },
        )

    @router.get("/users/status", response_model=None, include_in_schema=False)
    def users_status(
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Return current local-user grid rows for an in-place status refresh.

        Args:
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The current Local Users grid payload.
        """
        require_admin_identity(identity)
        rows = users_context(db, identity)["users_json"]
        return JSONResponse({"users": rows}, headers={"Cache-Control": "no-store"})

    @router.post("/users/password-policy", response_model=None)
    def update_users_password_policy(
        request: Request,
        min_length: str = Form(str(DEFAULT_PASSWORD_POLICY["min_length"])),
        require_uppercase: str | None = Form(None),
        require_lowercase: str | None = Form(None),
        require_number: str | None = Form(None),
        require_special: str | None = Form(None),
        disallow_username: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the update users password policy endpoint.

        Args:
            request: Incoming HTTP request.
            min_length: Min length supplied by the caller.
            require_uppercase: Require uppercase supplied by the caller.
            require_lowercase: Require lowercase supplied by the caller.
            require_number: Require number supplied by the caller.
            require_special: Require special supplied by the caller.
            disallow_username: Disallow username supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        try:
            parsed_min_length = int(min_length)
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail="Minimum length must be a number."
            ) from exc
        if parsed_min_length < 8 or parsed_min_length > 128:
            raise HTTPException(
                status_code=422, detail="Minimum length must be between 8 and 128."
            )
        policy = password_policy_from_json(
            json.dumps(
                {
                    "min_length": parsed_min_length,
                    "require_uppercase": require_uppercase == "on",
                    "require_lowercase": require_lowercase == "on",
                    "require_number": require_number == "on",
                    "require_special": require_special == "on",
                    "disallow_username": disallow_username == "on",
                }
            )
        )
        setting = set_setting_value(
            db, LOCAL_USERS_PASSWORD_POLICY_KEY, password_policy_to_json(policy)
        )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_local_user_password_policy",
            resource_type="user_policy",
        )
        return JSONResponse(
            {
                "updated_at": setting.updated_at.isoformat(),
                "policy": policy,
                "summary": password_policy_summary(policy),
            }
        )

    @router.post("/users", response_model=None)
    def create_user_from_ui(
        request: Request,
        username: str = Form(...),
        description: str = Form(""),
        role: str = Form(Role.VIEWER.value),
        roles: list[str] = Form(default=[]),
        roles_text: str = Form(""),
        shell: str = Form(DEFAULT_LOCAL_USER_SHELL),
        web_terminal_access: bool = Form(False),
        password: str = Form(""),
        confirm_password: str = Form(""),
        enabled: str | None = Form(None),
        enabled_present: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the create user from ui endpoint.

        Args:
            request: Incoming HTTP request.
            username: Account name used for authentication or lookup.
            description: Human-readable description of the resource.
            role: Atlaso role used for authorization.
            roles: Atlaso roles used for authorization.
            roles_text: Roles text supplied by the caller.
            shell: Shell supplied by the caller.
            web_terminal_access: Web terminal access supplied by the caller.
            password: Password supplied for the immediate authenticated operation.
            confirm_password: Confirm password supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            enabled_present: Enabled present supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        username = username.strip().lower()
        if not username:
            raise HTTPException(status_code=400, detail="Username is required.")
        next_roles = roles_from_form(role, roles, roles_text)
        if not is_valid_user_shell(shell):
            raise HTTPException(
                status_code=400,
                detail=f"Shell must be one of {', '.join(LOCAL_USER_SHELLS)}.",
            )
        shell = normalize_user_shell(shell)
        if db.execute(
            select(User).where(User.username == username)
        ).scalar_one_or_none():
            raise HTTPException(
                status_code=409, detail=f"User {username} already exists."
            )
        if web_terminal_access and shell == DEFAULT_LOCAL_USER_SHELL:
            raise HTTPException(
                status_code=400, detail="Web SSH access requires an interactive shell."
            )
        if password or confirm_password:
            if password != confirm_password:
                raise HTTPException(
                    status_code=400, detail="Password confirmation does not match."
                )
            policy_errors = validate_password(
                password, username, local_users_password_policy(db)
            )
            if policy_errors:
                raise HTTPException(status_code=400, detail=" ".join(policy_errors))
        next_enabled = enabled == "on" if enabled_present is not None else False
        if next_enabled and not password:
            raise HTTPException(
                status_code=400,
                detail="Set a Photon password before enabling a new local user.",
            )
        user = User(
            username=username,
            description=description.strip(),
            role=primary_role(next_roles),
            roles_json=roles_to_json(next_roles),
            shell=shell,
            web_terminal_access=bool(web_terminal_access),
            enabled=next_enabled,
        )
        if password:
            stage_user_os_password(user, password)
        db.add(user)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="create_local_user",
            resource_type="user",
            resource_id=str(user.id),
        )
        db.refresh(user)
        return grid_saved_response(
            request,
            redirect_url="/users",
            resource_name="user",
            resource=user_to_dict(user, identity.user_id),
        )

    @router.post("/users/{user_id}/edit", response_model=None)
    def update_user_from_ui(
        user_id: int,
        request: Request,
        username: str = Form(...),
        description: str = Form(""),
        role: str = Form(Role.VIEWER.value),
        roles: list[str] = Form(default=[]),
        roles_text: str = Form(""),
        shell: str = Form(DEFAULT_LOCAL_USER_SHELL),
        web_terminal_access: bool = Form(False),
        password: str = Form(""),
        confirm_password: str = Form(""),
        enabled: str | None = Form(None),
        enabled_present: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the update user from ui endpoint.

        Args:
            user_id: Identifier of the user.
            request: Incoming HTTP request.
            username: Account name used for authentication or lookup.
            description: Human-readable description of the resource.
            role: Atlaso role used for authorization.
            roles: Atlaso roles used for authorization.
            roles_text: Roles text supplied by the caller.
            shell: Shell supplied by the caller.
            web_terminal_access: Web terminal access supplied by the caller.
            password: Password supplied for the immediate authenticated operation.
            confirm_password: Confirm password supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            enabled_present: Enabled present supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        username = username.strip().lower()
        if not username:
            raise HTTPException(status_code=400, detail="Username is required.")
        next_roles = roles_from_form(role, roles, roles_text)
        if not is_valid_user_shell(shell):
            raise HTTPException(
                status_code=400,
                detail=f"Shell must be one of {', '.join(LOCAL_USER_SHELLS)}.",
            )
        shell = normalize_user_shell(shell)
        if web_terminal_access and shell == DEFAULT_LOCAL_USER_SHELL:
            raise HTTPException(
                status_code=400, detail="Web SSH access requires an interactive shell."
            )
        if password or confirm_password:
            if password != confirm_password:
                raise HTTPException(
                    status_code=400, detail="Password confirmation does not match."
                )
            policy_errors = validate_password(
                password, username, local_users_password_policy(db)
            )
            if policy_errors:
                raise HTTPException(status_code=400, detail=" ".join(policy_errors))
        next_enabled = enabled == "on" if enabled_present is not None else user.enabled
        if user.id == identity.user_id and not next_enabled:
            raise HTTPException(
                status_code=400,
                detail="You cannot disable your own active session account.",
            )
        if next_enabled and not (
            password or has_pending_os_password(user) or user.os_password_applied_at
        ):
            raise HTTPException(
                status_code=400,
                detail="Set a Photon password before enabling this local user.",
            )
        protect_last_admin(db, user, next_roles=next_roles, next_enabled=next_enabled)
        existing = db.execute(
            select(User).where(User.username == username, User.id != user.id)
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=409, detail=f"User {username} already exists."
            )
        old_username = user.username
        had_web_terminal_access = bool(user.web_terminal_access)
        user.username = username
        user.description = description.strip()
        user.role = primary_role(next_roles)
        user.roles_json = roles_to_json(next_roles)
        user.web_terminal_access = bool(web_terminal_access)
        shell_changed = user.shell != shell
        user.shell = shell
        was_enabled = bool(user.enabled)
        if old_username != username:
            rename_pending_os_password(old_username, username)
            user.os_password_applied_at = None
        if password:
            stage_user_os_password(user, password)
            revoke_user_tokens(db, user, identity.username)
        if was_enabled and not next_enabled:
            user.os_sync_status = "pending"
            user.os_unlock_requested_at = None
            clear_pending_os_password(user)
            revoke_user_tokens(db, user, identity.username)
        elif not was_enabled and next_enabled:
            user.os_sync_status = "pending"
        user.enabled = next_enabled
        if old_username != username:
            user.os_sync_status = (
                "pending" if has_pending_os_password(user) else "password_not_staged"
            )
        elif shell_changed and next_enabled:
            user.os_sync_status = "pending"
        if old_username != username:
            tokens = (
                db.execute(select(ApiToken).where(ApiToken.owner_user_id == user.id))
                .scalars()
                .all()
            )
            for token in tokens:
                token.owner_username = username
                db.add(token)
        db.add(user)
        db.commit()
        if (
            old_username != username
            or (had_web_terminal_access and not user.web_terminal_access)
            or (was_enabled and not next_enabled)
        ):
            from atlaso.app.web_terminal import revoke_user_terminal_sessions

            revoke_user_terminal_sessions(
                user.id,
                "Local user disabled"
                if was_enabled and not next_enabled
                else "Local user access changed",
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_local_user",
            resource_type="user",
            resource_id=str(user.id),
        )
        db.refresh(user)
        return JSONResponse({"user": user_to_dict(user, identity.user_id)})

    @router.post("/users/{user_id}/disable", response_model=None)
    def disable_user_from_ui(
        user_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the disable user from ui endpoint.

        Args:
            user_id: Identifier of the user.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.id == identity.user_id:
            raise HTTPException(
                status_code=400,
                detail="You cannot disable your own active session account.",
            )
        if not user.enabled:
            return JSONResponse({"user": user_to_dict(user, identity.user_id)})
        protect_last_admin(db, user, next_enabled=False)
        user.enabled = False
        user.os_sync_status = "pending"
        user.os_unlock_requested_at = None
        clear_pending_os_password(user)
        revoke_user_tokens(db, user, identity.username)
        from atlaso.app.web_terminal import revoke_user_terminal_sessions

        revoke_user_terminal_sessions(user.id, "Local user disabled")
        db.add(user)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="disable_local_user",
            resource_type="user",
            resource_id=str(user.id),
        )
        db.refresh(user)
        return JSONResponse({"user": user_to_dict(user, identity.user_id)})

    @router.post("/users/{user_id}/unlock", response_model=None)
    def request_user_os_unlock_from_ui(
        user_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the request user os unlock from ui endpoint.

        Args:
            user_id: Identifier of the user.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not user.enabled:
            raise HTTPException(
                status_code=400,
                detail="Disabled local users are removed from Photon OS during appliance apply.",
            )
        user.os_unlock_requested_at = utcnow()
        user.os_sync_status = "pending"
        db.add(user)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="request_local_user_os_unlock",
            resource_type="user",
            resource_id=str(user.id),
        )
        db.refresh(user)
        return JSONResponse({"user": user_to_dict(user, identity.user_id)})

    @router.post("/users/{user_id}/delete", response_model=None)
    def delete_user_from_ui(
        user_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete user from ui endpoint.

        Args:
            user_id: Identifier of the user.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.id == identity.user_id:
            raise HTTPException(
                status_code=400,
                detail="You cannot remove your own active session account.",
            )
        protect_last_admin(db, user, next_enabled=False)
        revoke_user_tokens(db, user, identity.username)
        from atlaso.app.web_terminal import revoke_user_terminal_sessions

        revoke_user_terminal_sessions(user.id, "Local user removed")
        for token in (
            db.execute(select(ApiToken).where(ApiToken.owner_user_id == user.id))
            .scalars()
            .all()
        ):
            db.delete(token)
        db.delete(user)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_local_user",
            resource_type="user",
            resource_id=str(user_id),
        )
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse("/users", status_code=303)

    @router.post("/users/{user_id}/password", response_model=None)
    def reset_user_password_from_ui(
        user_id: int,
        request: Request,
        password: str = Form(...),
        confirm_password: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the reset user password from ui endpoint.

        Args:
            user_id: Identifier of the user.
            request: Incoming HTTP request.
            password: Password supplied for the immediate authenticated operation.
            confirm_password: Confirm password supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if password != confirm_password:
            raise HTTPException(
                status_code=400, detail="Password confirmation does not match."
            )
        policy_errors = validate_password(
            password, user.username, local_users_password_policy(db)
        )
        if policy_errors:
            raise HTTPException(status_code=400, detail=" ".join(policy_errors))
        stage_user_os_password(user, password)
        user.enabled = True
        db.add(user)
        revoke_user_tokens(db, user, identity.username)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="reset_local_user_password",
            resource_type="user",
            resource_id=str(user.id),
        )
        return RedirectResponse("/users", status_code=303)

    @router.get("/ldap-users", response_model=None)
    def legacy_ldap_users_redirect() -> RedirectResponse:
        """Handle the legacy ldap users redirect endpoint.

        Returns:
            The endpoint response.
        """
        return RedirectResponse("/ldap", status_code=303)

    endpoints: dict[str, Endpoint] = {
        "authentication": authentication,
        "openid_connect": openid_connect,
        "api_token_grid_row": api_token_grid_row,
        "authentication_context": authentication_context,
        "update_oidc_provider_from_ui": update_oidc_provider_from_ui,
        "create_oidc_client_from_ui": create_oidc_client_from_ui,
        "update_oidc_client_from_ui": update_oidc_client_from_ui,
        "export_oidc_client_integration_from_ui": export_oidc_client_integration_from_ui,
        "create_oidc_group_mapping_from_ui": create_oidc_group_mapping_from_ui,
        "update_oidc_group_mapping_from_ui": update_oidc_group_mapping_from_ui,
        "delete_oidc_group_mapping_from_ui": delete_oidc_group_mapping_from_ui,
        "rotate_oidc_client_secret_from_ui": rotate_oidc_client_secret_from_ui,
        "delete_oidc_client_from_ui": delete_oidc_client_from_ui,
        "create_oidc_signing_key_from_ui": create_oidc_signing_key_from_ui,
        "delete_retired_oidc_signing_key_from_ui": delete_retired_oidc_signing_key_from_ui,
        "create_token_from_ui": create_token_from_ui,
        "revoke_token_from_ui": revoke_token_from_ui,
        "users_page": users_page,
        "users_status": users_status,
        "update_users_password_policy": update_users_password_policy,
        "create_user_from_ui": create_user_from_ui,
        "update_user_from_ui": update_user_from_ui,
        "disable_user_from_ui": disable_user_from_ui,
        "request_user_os_unlock_from_ui": request_user_os_unlock_from_ui,
        "delete_user_from_ui": delete_user_from_ui,
        "reset_user_password_from_ui": reset_user_password_from_ui,
        "legacy_ldap_users_redirect": legacy_ldap_users_redirect,
    }
    return IdentityUiRouter(router=router, endpoints=endpoints)
