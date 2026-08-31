"""Own Appliance Settings API v1 transport handlers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import Settings, get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    CaSettings,
    PhysicalInterface,
    VlanInterface,
    utcnow,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import SettingsResponse, SettingsUpdate
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.appliance_settings import (
    APPLIANCE_SETTINGS_STAGED_CONFIG_PATH,
    management_ui_context,
    normalize_fqdn,
    normalize_multiline_values,
    web_terminal_interfaces_to_json,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class SettingsApiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    appliance_settings_response: Endpoint
    get_appliance_settings: Endpoint
    ensure_ca_state: Endpoint
    ensure_dns_for_appliance_settings: Endpoint
    reconcile_factory_service_identities: Endpoint
    reconcile_service_dns_aliases: Endpoint


@dataclass(frozen=True)
class SettingsApiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: SettingsApiDependencies) -> SettingsApiRouter:
    """Build the Appliance Settings API v1 router.

    Args:
        dependencies: Stable facade dependencies used by Settings transports.

    Returns:
        Configured Settings API router and stable endpoint callables.
    """
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
    appliance_settings_response = dependencies.appliance_settings_response
    get_appliance_settings = dependencies.get_appliance_settings
    ensure_ca_state = dependencies.ensure_ca_state
    ensure_dns_for_appliance_settings = (
        dependencies.ensure_dns_for_appliance_settings
    )
    reconcile_factory_service_identities = (
        dependencies.reconcile_factory_service_identities
    )
    reconcile_service_dns_aliases = dependencies.reconcile_service_dns_aliases

    @router.get(
        "/settings",
        response_model=SettingsResponse,
        tags=["Settings"],
        operation_id="getSettings",
    )
    def get_app_settings(
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> SettingsResponse:
        """Get Settings.

        Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        return appliance_settings_response(db, settings)

    @router.patch(
        "/settings",
        response_model=SettingsResponse,
        tags=["Settings"],
        operation_id="updateSettings",
    )
    def update_app_settings(
        payload: SettingsUpdate,
        identity: Annotated[Identity, Depends(require_scope("admin:all"))],
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> SettingsResponse:
        """Update Settings.

        Requires the `admin:all` API scope. The operation updates only properties present in the request,
        preserves every omitted property, and does not bypass the documented global Appliance Apply or
        service lifecycle boundary.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        desired = get_appliance_settings(db)
        supplied_fields = payload.model_fields_set
        previous_fqdn = desired.fqdn
        fqdn_changed = False
        if "appliance_fqdn" in supplied_fields:
            assert payload.appliance_fqdn is not None
            requested_fqdn = normalize_fqdn(payload.appliance_fqdn)
            if requested_fqdn != previous_fqdn:
                desired.fqdn = requested_fqdn
                fqdn_changed = True
        if "management_https_enabled" in supplied_fields:
            assert payload.management_https_enabled is not None
            desired.management_https_enabled = payload.management_https_enabled
        if "web_terminal_enabled" in supplied_fields:
            assert payload.web_terminal_enabled is not None
            desired.web_terminal_enabled = payload.web_terminal_enabled
        if "web_terminal_interfaces" in supplied_fields:
            interfaces = (
                db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name))
                .scalars()
                .all()
            )
            vlans = (
                db.execute(
                    select(VlanInterface).order_by(
                        VlanInterface.parent_interface, VlanInterface.vlan_id
                    )
                )
                .scalars()
                .all()
            )
            management = management_ui_context(interfaces, vlans)
            assert payload.web_terminal_interfaces is not None
            requested_terminal_interfaces = list(payload.web_terminal_interfaces)
            if desired.web_terminal_enabled and management.get("name"):
                requested_terminal_interfaces = [
                    management["name"],
                    *[
                        name
                        for name in requested_terminal_interfaces
                        if name != management["name"]
                    ],
                ]
            desired.web_terminal_interfaces_json = web_terminal_interfaces_to_json(
                requested_terminal_interfaces
            )
        if "root_ssh_enabled" in supplied_fields:
            assert payload.root_ssh_enabled is not None
            desired.root_ssh_enabled = payload.root_ssh_enabled
        if "browser_session_idle_timeout_minutes" in payload.model_fields_set:
            assert payload.browser_session_idle_timeout_minutes is not None
            desired.browser_session_idle_timeout_minutes = (
                payload.browser_session_idle_timeout_minutes
            )
        if "api_token_max_lifetime_days" in payload.model_fields_set:
            assert payload.api_token_max_lifetime_days is not None
            desired.api_token_max_lifetime_days = payload.api_token_max_lifetime_days
        if "external_dns_servers" in supplied_fields:
            assert payload.external_dns_servers is not None
            desired.external_dns_servers = normalize_multiline_values(
                "\n".join(payload.external_dns_servers)
            )
        if supplied_fields:
            desired.config_path = APPLIANCE_SETTINGS_STAGED_CONFIG_PATH
            desired.updated_at = utcnow()
        reconciled_service_identities: list[str] = []
        appliance_dns_action: str | None = None
        reconciled_service_aliases: list[str] = []
        if fqdn_changed:
            reconciled_service_identities = reconcile_factory_service_identities(
                db,
                previous_appliance_fqdn=previous_fqdn,
            )
            appliance_dns_action = ensure_dns_for_appliance_settings(
                db,
                desired,
                previous_fqdn=previous_fqdn,
                actor=None,
            )
            if reconciled_service_identities:
                reconciled_service_aliases = reconcile_service_dns_aliases(
                    db, actor=None
                )
        ca_settings = db.execute(select(CaSettings)).scalar_one_or_none()
        ca_reconciliation_required = fqdn_changed or (
            "management_https_enabled" in supplied_fields
        )
        if (
            ca_reconciliation_required
            and desired.management_https_enabled
            and ca_settings
            and ca_settings.enabled
        ):
            ca_state_errors = ensure_ca_state(db, commit=False)
            if ca_state_errors:
                db.rollback()
                raise HTTPException(
                    status_code=422,
                    detail=" ".join(ca_state_errors),
                )
        db.add(desired)
        db.commit()
        db.refresh(desired)
        audit_details: list[str] = []
        if reconciled_service_identities:
            audit_details.append(
                "factory_service_identities="
                f"{','.join(sorted(reconciled_service_identities))}"
            )
        if appliance_dns_action:
            audit_details.append(f"appliance_dns={appliance_dns_action}")
        if reconciled_service_aliases:
            audit_details.append(
                "service_dns_aliases="
                f"{','.join(sorted(reconciled_service_aliases))}"
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_appliance_settings",
            resource_type="settings",
            resource_id=str(desired.id),
            detail="; ".join(audit_details) or None,
        )
        return appliance_settings_response(db, settings)

    endpoints = {
        endpoint.__name__: endpoint
        for endpoint in (get_app_settings, update_app_settings)
    }
    return SettingsApiRouter(router=router, endpoints=endpoints)
