from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.datastructures import FormData

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import FirewallRule, PhysicalInterface, VlanInterface, utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.firewall import (
    FIREWALL_ANY_SOURCE_GROUP_ID,
    FIREWALL_POLICIES,
    FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX,
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    firewall_interface_networks,
    firewall_rule_to_dict,
    firewall_settings_to_dict,
    firewall_source_group_state,
    validate_firewall_rule,
    validate_firewall_source_groups,
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
    setting_value: Endpoint
    set_setting_value: Endpoint
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
    setting_value = dependencies.setting_value
    set_setting_value = dependencies.set_setting_value
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


    def firewall_source_group_state_for_db(db: Session) -> dict[str, Any]:
        """Return firewall source group state for db.

        Args:
            db: Active database session.
        """
        physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
        vlan_interfaces = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
        interface_networks = firewall_interface_networks(
            list(physical_interfaces),
            list(vlan_interfaces),
        )
        return firewall_source_group_state(setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY), interface_networks)


    def persist_firewall_source_group_state(db: Session, state: dict[str, Any]) -> None:
        """Persist firewall source group state.

        Args:
            db: Active database session.
            state: Lifecycle or job state to persist.
        """
        set_setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY, json.dumps(state, indent=2, sort_keys=True))


    def _source_group_entries_from_form(form: FormData) -> list[str]:
        """Return source group entries from form.

        Args:
            form: Form consumed by source group entries from form.
        """
        values = [str(item).strip() for item in form.getlist("group_entries") if str(item).strip()]
        return values or ["any"]


    def _firewall_source_group_id(name: str, groups: list[dict[str, Any]]) -> str:
        """Return firewall source group id.

        Args:
            name: Stable name identifying the resource or operation.
            groups: Groups consumed by firewall source group identifier.
        """
        base = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-") or "group"
        existing = {str(group.get("id", "")) for group in groups}
        candidate = f"custom:{base}"
        index = 2
        while candidate in existing:
            candidate = f"custom:{base}-{index}"
            index += 1
        return candidate


    def _normalized_firewall_source_group(
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Return normalized firewall source group.

        Args:
            group: Group consumed by normalized firewall source group.
        """
        entries = [str(item).strip() for item in (group.get("entries") or group.get("sources") or []) if str(item).strip()] or ["any"]
        normalized_entries = []
        for entry in entries:
            if entry.lower() == "any":
                normalized_entries.append("any")
            elif entry.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
                normalized_entries.append(f"{FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX}{entry[len(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):]}")
            else:
                normalized_entries.append(entry)
        return {
            "id": str(group.get("id", "")),
            "name": str(group.get("name", "")).strip() or str(group.get("id", "")),
            "entries": normalized_entries,
            "sources": normalized_entries,
            "description": str(group.get("description") or "Custom firewall group."),
            "builtin": bool(group.get("builtin")),
        }


    def _strip_deleted_source_group_references(
        groups: list[dict[str, Any]],
        deleted_group_id: str,
        deleted_group_name: str,
    ) -> list[dict[str, Any]]:
        """Return strip deleted source group references.

        Args:
            groups: Groups consumed by strip deleted source group references.
            deleted_group_id: Stable identifier of the associated deleted group resource.
            deleted_group_name: Deleted group name consumed by strip deleted source group references.
        """
        stripped: list[dict[str, Any]] = []
        deleted_ref = f"{FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX}{deleted_group_id}"
        deleted_name_ref = f"@{deleted_group_name}".strip().lower()
        for group in groups:
            entries = []
            for entry in group.get("entries") or group.get("sources") or []:
                normalized_entry = str(entry).strip()
                if normalized_entry == deleted_ref or normalized_entry.lower() == deleted_name_ref:
                    continue
                entries.append(normalized_entry)
            stripped.append(_normalized_firewall_source_group({**group, "entries": entries or ["any"]}))
        return stripped


    def _firewall_source_group_response(db: Session, updated_at: str) -> JSONResponse:
        """Return firewall source group response.

        Args:
            db: Active database session.
            updated_at: Updated at supplied by the caller.
        """
        context = firewall_context(db)
        return JSONResponse(
            {
                "status": "saved",
                "updated_at": updated_at,
                "valid": not context["firewall_validation_errors"],
                "validation_errors": context["firewall_validation_errors"],
                "config_path": context["firewall_settings"].config_path,
                "config_preview": context["firewall_config_preview"],
            }
        )


    @router.post("/firewall/source-groups", response_model=None)
    async def update_firewall_source_groups(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the update firewall source groups endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        form = await request.form()
        verify_csrf(request, str(form.get("csrf", "")))
        state = firewall_source_group_state_for_db(db)
        groups = [_normalized_firewall_source_group(group) for group in state["groups"]]
        assignments = dict(state["assignments"])
        action = str(form.get("action") or "update")
        group_id = str(form.get("group_id") or "")

        if action == "create":
            name = str(form.get("group_name") or "").strip()
            if not name:
                raise HTTPException(status_code=422, detail="Firewall group name is required.")
            groups.append(
                _normalized_firewall_source_group(
                    {
                        "id": _firewall_source_group_id(name, groups),
                        "name": name,
                        "entries": _source_group_entries_from_form(form),
                        "description": "Custom firewall group.",
                    }
                )
            )
        elif action == "rename":
            name = str(form.get("group_name") or "").strip()
            if not name:
                raise HTTPException(status_code=422, detail="Firewall group name is required.")
            updated = False
            for index, group in enumerate(groups):
                if group["id"] != group_id:
                    continue
                if group["id"] == FIREWALL_ANY_SOURCE_GROUP_ID:
                    raise HTTPException(status_code=422, detail="Any cannot be renamed.")
                groups[index] = _normalized_firewall_source_group({**group, "name": name})
                updated = True
                break
            if not updated:
                raise HTTPException(status_code=404, detail="Firewall group not found.")
        elif action == "delete":
            if group_id == FIREWALL_ANY_SOURCE_GROUP_ID:
                raise HTTPException(status_code=422, detail="Any cannot be removed.")
            deleted_group = next((group for group in groups if group["id"] == group_id), None)
            if not deleted_group:
                raise HTTPException(status_code=404, detail="Firewall group not found.")
            groups = [group for group in groups if group["id"] != group_id]
            assignments = {
                rule_name: (FIREWALL_ANY_SOURCE_GROUP_ID if assigned_group == group_id else assigned_group)
                for rule_name, assigned_group in assignments.items()
            }
            groups = _strip_deleted_source_group_references(groups, group_id, str(deleted_group.get("name") or group_id))
        else:
            updated = False
            for index, group in enumerate(groups):
                if group["id"] != group_id:
                    continue
                if group["id"] == FIREWALL_ANY_SOURCE_GROUP_ID:
                    groups[index] = _normalized_firewall_source_group({**group, "name": "Any", "entries": ["any"], "builtin": True})
                else:
                    groups[index] = _normalized_firewall_source_group(
                        {
                            **group,
                            "name": str(form.get("group_name") or group["name"]).strip(),
                            "entries": _source_group_entries_from_form(form),
                        }
                    )
                updated = True
                break
            if not updated:
                raise HTTPException(status_code=404, detail="Firewall group not found.")
        errors = validate_firewall_source_groups(groups)
        if errors:
            return JSONResponse({"status": "error", "errors": errors}, status_code=422)
        updated_state = {"groups": groups, "assignments": assignments}
        persist_firewall_source_group_state(db, updated_state)
        db.commit()
        updated_at = utcnow().isoformat()
        record_audit(
            db,
            actor=identity.username,
            action=f"{action}_firewall_source_group",
            resource_type="firewall",
            resource_id=group_id or "managed-source-groups",
        )
        if request.headers.get("X-Atlaso-Autosave"):
            return _firewall_source_group_response(db, updated_at)
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
            raise HTTPException(status_code=422, detail="Firewall group does not exist.")
        state = firewall_source_group_state_for_db(db)
        state["assignments"][rule_name] = source_group_id
        persist_firewall_source_group_state(db, state)
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
        state = firewall_source_group_state_for_db(db)
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
        state = firewall_source_group_state_for_db(db)
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
        "firewall_source_group_state_for_db": firewall_source_group_state_for_db,
        "persist_firewall_source_group_state": persist_firewall_source_group_state,
        "_source_group_entries_from_form": _source_group_entries_from_form,
        "_firewall_source_group_id": _firewall_source_group_id,
        "_normalized_firewall_source_group": _normalized_firewall_source_group,
        "_strip_deleted_source_group_references": _strip_deleted_source_group_references,
        "_firewall_source_group_response": _firewall_source_group_response,
        "update_firewall_source_groups": update_firewall_source_groups,
        "update_managed_firewall_rule_source_group": update_managed_firewall_rule_source_group,
        "_assign_firewall_rule": _assign_firewall_rule,
        "create_firewall_rule": create_firewall_rule,
        "update_firewall_rule": update_firewall_rule,
        "delete_firewall_rule": delete_firewall_rule,
    }
    return FirewallUiRouter(router=router, endpoints=endpoints)
