from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import FirewallRule, utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.firewall import (
    FIREWALL_POLICIES,
    firewall_rule_to_dict,
    firewall_settings_to_dict,
    validate_firewall_rule,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class FirewallUiDependencies:
    require_management_ui_request: Endpoint
    render: Endpoint
    firewall_context: Endpoint
    appliance_apply_status: Endpoint
    verify_csrf: Endpoint
    get_firewall_settings_row: Endpoint
    source_group_state_for_db: Endpoint
    persist_source_group_state: Endpoint
    grid_request: Endpoint
    grid_saved_response: Endpoint


@dataclass(frozen=True)
class FirewallUiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: FirewallUiDependencies) -> FirewallUiRouter:
    """Build the extracted domain router without importing its compatibility facade.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured domain router and its stable endpoint callables.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    render = dependencies.render
    firewall_context = dependencies.firewall_context
    appliance_apply_status = dependencies.appliance_apply_status
    verify_csrf = dependencies.verify_csrf
    get_firewall_settings_row = dependencies.get_firewall_settings_row
    source_group_state_for_db = dependencies.source_group_state_for_db
    persist_source_group_state = dependencies.persist_source_group_state
    grid_request = dependencies.grid_request
    grid_saved_response = dependencies.grid_saved_response

    @router.get("/firewall", response_class=HTMLResponse, response_model=None)
    def firewall(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the firewall endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return cast(
            HTMLResponse,
            render(
                request,
                "firewall.html",
                {
                    "identity": identity,
                    **firewall_context(db),
                    "appliance_apply_status": appliance_apply_status(db, "firewall"),
                },
            ),
        )


    @router.post("/firewall/settings", response_model=None)
    def update_firewall_settings(
        request: Request,
        enabled: str | None = Form(None),
        default_input_policy: str = Form("drop"),
        default_forward_policy: str = Form("drop"),
        default_output_policy: str = Form("accept"),
        allow_established: str | None = Form(None),
        allow_loopback: str | None = Form(None),
        allow_icmp: str | None = Form(None),
        log_dropped: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update firewall settings endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            default_input_policy: Default input policy supplied by the caller.
            default_forward_policy: Default forward policy supplied by the caller.
            default_output_policy: Default output policy supplied by the caller.
            allow_established: Allow established supplied by the caller.
            allow_loopback: Allow loopback supplied by the caller.
            allow_icmp: Allow icmp supplied by the caller.
            log_dropped: Log dropped supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_firewall_settings_row(db)
        settings.enabled = enabled == "on"
        settings.default_input_policy = default_input_policy if default_input_policy in FIREWALL_POLICIES else "drop"
        settings.default_forward_policy = default_forward_policy if default_forward_policy in FIREWALL_POLICIES else "drop"
        settings.default_output_policy = default_output_policy if default_output_policy in FIREWALL_POLICIES else "accept"
        settings.allow_established = allow_established == "on"
        settings.allow_loopback = allow_loopback == "on"
        settings.allow_icmp = allow_icmp == "on"
        settings.log_dropped = log_dropped == "on"
        settings.updated_at = utcnow()
        db.add(settings)
        db.commit()
        db.refresh(settings)
        record_audit(db, actor=identity.username, action="update_firewall_settings", resource_type="firewall", resource_id=str(settings.id))
        if request.headers.get("X-Atlaso-Autosave"):
            context = firewall_context(db)
            return JSONResponse(
                {
                    "updated_at": settings.updated_at.isoformat(),
                    "settings": firewall_settings_to_dict(settings),
                    "enabled": settings.enabled,
                    "valid": not context["firewall_validation_errors"],
                    "validation_errors": context["firewall_validation_errors"],
                    "config_path": settings.config_path,
                    "config_preview": context["firewall_config_preview"],
                }
            )
        return RedirectResponse("/firewall", status_code=303)


    @router.post("/firewall/managed-rules/source-group", response_model=None)
    def update_managed_firewall_rule_source_group(
        request: Request,
        rule_name: str = Form(...),
        source_group_id: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the update managed firewall rule source group endpoint.

        Args:
            request: Incoming HTTP request.
            rule_name: Rule name supplied by the caller.
            source_group_id: Identifier of the source group.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        context = firewall_context(db)
        valid_rule_names = {
            row["name"]
            for row in context["firewall_managed_rule_rows"]
            if row["managed_state"] == "generated" and row["source_group_id"]
        }
        valid_group_ids = {group["id"] for group in context["firewall_source_groups"]}
        if rule_name not in valid_rule_names:
            raise HTTPException(status_code=404, detail="Managed firewall rule not found.")
        if source_group_id not in valid_group_ids:
            raise HTTPException(status_code=422, detail="Source Group does not exist.")
        state = source_group_state_for_db(db)
        state["assignments"][rule_name] = source_group_id
        persist_source_group_state(db, state)
        db.commit()
        record_audit(db, actor=identity.username, action="update_managed_firewall_source_group", resource_type="firewall_rule", resource_id=rule_name)
        return JSONResponse({"status": "saved", "updated_at": utcnow().isoformat()})


    def _assign_firewall_rule(
        rule: FirewallRule,
        *,
        name: str,
        direction: str,
        action: str,
        protocol: str,
        source: str,
        destination: str,
        destination_port: str,
        interface_name: str,
        priority: int,
        enabled: bool,
        description: str,
    ) -> FirewallRule:
        """Return assign firewall rule.

        Args:
            rule: Firewall, routing, or validation rule to process.
            name: Name of the target object.
            direction: Direction supplied by the caller.
            action: Operation to perform on the target resource.
            protocol: Protocol supplied by the caller.
            source: Source path, address, or record to process.
            destination: Destination path, address, or resource.
            destination_port: Destination port supplied by the caller.
            interface_name: Linux interface name of the network target.
            priority: Ordering priority assigned to the item.
            enabled: Whether the requested behavior is enabled.
            description: Human-readable description of the resource.
        """
        rule.name = name.strip()
        rule.direction = direction
        rule.action = action
        rule.protocol = protocol
        rule.source = source.strip() or "any"
        rule.destination = destination.strip() or "any"
        rule.destination_port = destination_port.strip()
        rule.interface_name = interface_name.strip()
        rule.priority = priority
        rule.enabled = enabled
        rule.description = description.strip() or None
        rule.updated_at = utcnow()
        return rule


    @router.post("/firewall/rules", response_model=None)
    def create_firewall_rule(
        request: Request,
        name: str = Form(...),
        direction: str = Form("input"),
        action: str = Form("accept"),
        protocol: str = Form("tcp"),
        source: str = Form("any"),
        destination: str = Form("any"),
        destination_port: str = Form(""),
        interface_name: str = Form(""),
        priority: int = Form(100),
        enabled: str | None = Form(None),
        description: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the create firewall rule endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            direction: Direction supplied by the caller.
            action: Operation to perform on the target resource.
            protocol: Protocol supplied by the caller.
            source: Source path, address, or record to process.
            destination: Destination path, address, or resource.
            destination_port: Destination port supplied by the caller.
            interface_name: Linux interface name of the network target.
            priority: Ordering priority assigned to the item.
            enabled: Whether the requested behavior is enabled.
            description: Human-readable description of the resource.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        rule = _assign_firewall_rule(
            FirewallRule(),
            name=name,
            direction=direction,
            action=action,
            protocol=protocol,
            source=source,
            destination=destination,
            destination_port=destination_port,
            interface_name=interface_name,
            priority=priority,
            enabled=enabled == "on",
            description=description,
        )
        state = source_group_state_for_db(db)
        errors = validate_firewall_rule(rule, state["groups"], require_group_addresses=True)
        if errors:
            raise HTTPException(status_code=422, detail=" ".join(errors))
        db.add(rule)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=f"Firewall rule {rule.name} already exists.") from exc
        record_audit(db, actor=identity.username, action="create_firewall_rule", resource_type="firewall_rule", resource_id=str(rule.id))
        return cast(
            RedirectResponse | JSONResponse,
            grid_saved_response(
                request,
                redirect_url="/firewall",
                resource_name="rule",
                resource=firewall_rule_to_dict(rule),
            ),
        )


    @router.post("/firewall/rules/{rule_id}/edit", response_model=None)
    def update_firewall_rule(
        rule_id: int,
        request: Request,
        name: str = Form(...),
        direction: str = Form("input"),
        action: str = Form("accept"),
        protocol: str = Form("tcp"),
        source: str = Form("any"),
        destination: str = Form("any"),
        destination_port: str = Form(""),
        interface_name: str = Form(""),
        priority: int = Form(100),
        enabled: str | None = Form(None),
        description: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update firewall rule endpoint.

        Args:
            rule_id: Identifier of the rule.
            request: Incoming HTTP request.
            name: Name of the target object.
            direction: Direction supplied by the caller.
            action: Operation to perform on the target resource.
            protocol: Protocol supplied by the caller.
            source: Source path, address, or record to process.
            destination: Destination path, address, or resource.
            destination_port: Destination port supplied by the caller.
            interface_name: Linux interface name of the network target.
            priority: Ordering priority assigned to the item.
            enabled: Whether the requested behavior is enabled.
            description: Human-readable description of the resource.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        rule = db.get(FirewallRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Firewall rule not found")
        _assign_firewall_rule(
            rule,
            name=name,
            direction=direction,
            action=action,
            protocol=protocol,
            source=source,
            destination=destination,
            destination_port=destination_port,
            interface_name=interface_name,
            priority=priority,
            enabled=enabled == "on",
            description=description,
        )
        state = source_group_state_for_db(db)
        errors = validate_firewall_rule(rule, state["groups"], require_group_addresses=True)
        if errors:
            raise HTTPException(status_code=422, detail=" ".join(errors))
        db.add(rule)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=f"Firewall rule {rule.name} already exists.") from exc
        record_audit(db, actor=identity.username, action="update_firewall_rule", resource_type="firewall_rule", resource_id=str(rule.id))
        return cast(
            RedirectResponse | JSONResponse,
            grid_saved_response(
                request,
                redirect_url="/firewall",
                resource_name="rule",
                resource=firewall_rule_to_dict(rule),
            ),
        )


    @router.post("/firewall/rules/{rule_id}/delete", response_model=None)
    def delete_firewall_rule(
        rule_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete firewall rule endpoint.

        Args:
            rule_id: Identifier of the rule.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        rule = db.get(FirewallRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Firewall rule not found")
        db.delete(rule)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_firewall_rule", resource_type="firewall_rule", resource_id=str(rule_id))
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse("/firewall", status_code=303)

    endpoints: dict[str, Endpoint] = {
        "firewall": firewall,
        "update_firewall_settings": update_firewall_settings,
        "update_managed_firewall_rule_source_group": update_managed_firewall_rule_source_group,
        "_assign_firewall_rule": _assign_firewall_rule,
        "create_firewall_rule": create_firewall_rule,
        "update_firewall_rule": update_firewall_rule,
        "delete_firewall_rule": delete_firewall_rule,
    }
    return FirewallUiRouter(router=router, endpoints=endpoints)
