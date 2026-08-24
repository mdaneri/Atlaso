from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.datastructures import FormData

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    FirewallRule,
    NatRule,
    PhysicalInterface,
    VlanInterface,
    utcnow,
)
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.firewall import (
    FIREWALL_ANY_SOURCE_GROUP_ID,
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    firewall_interface_networks,
    firewall_source_group_state,
    validate_firewall_source_groups,
)
from atlaso.app.services.network_objects import (
    acquire_network_objects_write_lock,
    normalize_source_group,
    source_group_consumers,
    source_group_id,
    source_group_rows,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]
RETURN_TARGETS = {
    "firewall-rule": f"{MANAGEMENT_UI_ROOT}/firewall",
    "nat-rule": f"{MANAGEMENT_UI_ROOT}/routes-wan",
}


@dataclass(frozen=True)
class NetworkObjectsUiDependencies:
    require_management_ui_request: Endpoint
    render: Endpoint
    verify_csrf: Endpoint
    setting_value: Endpoint
    set_setting_value: Endpoint
    grid_request: Endpoint


@dataclass(frozen=True)
class NetworkObjectsUiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: NetworkObjectsUiDependencies) -> NetworkObjectsUiRouter:
    """Build the Network Objects domain router.

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
    verify_csrf = dependencies.verify_csrf
    setting_value = dependencies.setting_value
    set_setting_value = dependencies.set_setting_value
    grid_request = dependencies.grid_request

    def source_group_state_for_db(db: Session) -> dict[str, Any]:
        """Return Source Group state while retaining the historical settings key.

        Args:
            db: Active database session.

        Returns:
            Normalized Source Group state.
        """
        physical = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
        vlans = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
        networks = firewall_interface_networks(list(physical), list(vlans))
        return cast(
            dict[str, Any],
            firewall_source_group_state(setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY), networks),
        )

    def persist_source_group_state(db: Session, state: dict[str, Any]) -> None:
        """Persist Source Group state under the compatibility settings key.

        Args:
            db: Active database session.
            state: Normalized Source Group state.
        """
        set_setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY, json.dumps(state, indent=2, sort_keys=True))

    def network_objects_context(db: Session) -> dict[str, Any]:
        """Build Network Objects page state including every deletion consumer.

        Args:
            db: Active database session.

        Returns:
            Server-rendered page context.
        """
        state = source_group_state_for_db(db)
        firewall_rules = db.execute(select(FirewallRule).order_by(FirewallRule.priority, FirewallRule.name)).scalars().all()
        nat_rules = db.execute(select(NatRule).order_by(NatRule.priority, NatRule.name)).scalars().all()
        rows = source_group_rows(state["groups"], state["assignments"], firewall_rules, nat_rules)
        return {
            "network_object_source_groups": rows,
            "network_object_source_groups_json": rows,
            "network_object_validation_errors": validate_firewall_source_groups(state["groups"]),
        }

    @router.get("/network-objects", response_class=HTMLResponse, response_model=None)
    def network_objects(
        request: Request,
        return_to: str = "",
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Render the canonical Network Objects page.

        Args:
            request: Incoming HTTP request.
            return_to: Allowlisted wizard return token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        safe_return = return_to if return_to in RETURN_TARGETS else ""
        return cast(
            HTMLResponse,
            render(
                request,
                "network_objects.html",
                {
                    "identity": identity,
                    **network_objects_context(db),
                    "network_objects_can_write": identity.can("write:firewall"),
                    "network_objects_return_token": safe_return,
                    "network_objects_return_url": RETURN_TARGETS.get(safe_return, ""),
                },
            ),
        )

    @router.api_route(
        "/firewall/source-groups",
        methods=["GET", "HEAD"],
        include_in_schema=False,
        response_model=None,
    )
    def legacy_source_groups_page(
        request: Request,
        _identity: Identity = Depends(require_session_identity),
    ) -> RedirectResponse:
        """Redirect safe legacy bookmarks after management-request authorization.

        Args:
            request: Incoming HTTP request.
            _identity: Authenticated identity authorizing the redirect.

        Returns:
            A safe canonical redirect.
        """
        query = f"?{request.url.query}" if request.url.query else ""
        return RedirectResponse(f"{MANAGEMENT_UI_ROOT}/network-objects{query}", status_code=308)

    def _entries_from_form(form: FormData) -> list[str]:
        """Normalize Source Group entry fields from a submitted form.

        Args:
            form: Submitted Source Group form data.

        Returns:
            Normalized entries, defaulting to the built-in ``any`` entry.
        """
        values: list[str] = []
        for raw_value in form.getlist("group_entries"):
            values.extend(item.strip() for item in re.split(r"[\n,]+", str(raw_value)) if item.strip())
        return values or ["any"]

    def _mutation_response(db: Session, group_id_value: str, *, status_code: int = 200) -> JSONResponse:
        """Build the refreshed collection response after one mutation.

        Args:
            db: Active database session.
            group_id_value: Stable identifier of the mutated Source Group.
            status_code: HTTP status assigned to the JSON response.

        Returns:
            JSON response containing the mutated row and refreshed collection.
        """
        context = network_objects_context(db)
        group = next(
            (row for row in context["network_object_source_groups"] if row["id"] == group_id_value),
            None,
        )
        return JSONResponse(
            {
                "status": "saved",
                "updated_at": utcnow().isoformat(),
                "source_group": group,
                "source_groups": context["network_object_source_groups"],
                "validation_errors": context["network_object_validation_errors"],
            },
            status_code=status_code,
        )

    async def _mutate_source_groups(
        request: Request,
        identity: Identity,
        db: Session,
    ) -> Response:
        """Apply a canonical or bridged legacy Source Group mutation.

        Args:
            request: Incoming Source Group mutation request.
            identity: Authenticated identity authorizing the mutation.
            db: Active database session.

        Returns:
            Refreshed JSON for grid requests or a non-replaying redirect.
        """
        form = await request.form()
        verify_csrf(request, str(form.get("csrf", "")))
        acquire_network_objects_write_lock(db)
        state = source_group_state_for_db(db)
        groups = [normalize_source_group(group) for group in state["groups"]]
        assignments = dict(state["assignments"])
        action = str(form.get("action") or "update")
        requested_group_id = str(form.get("group_id") or "")
        affected_group_id = requested_group_id

        if action == "create":
            name = str(form.get("group_name") or "").strip()
            if not name:
                raise HTTPException(status_code=422, detail="Source Group name is required.")
            affected_group_id = source_group_id(name, groups)
            groups.append(
                normalize_source_group(
                    {
                        "id": affected_group_id,
                        "name": name,
                        "entries": _entries_from_form(form),
                        "description": str(form.get("description") or "Custom source group."),
                    }
                )
            )
        elif action == "delete":
            if requested_group_id == FIREWALL_ANY_SOURCE_GROUP_ID:
                raise HTTPException(status_code=422, detail="Any is built in and cannot be removed.")
            existing = next((group for group in groups if group["id"] == requested_group_id), None)
            if not existing:
                raise HTTPException(status_code=404, detail="Source Group not found.")
            firewall_rules = db.execute(select(FirewallRule).order_by(FirewallRule.priority, FirewallRule.name)).scalars().all()
            nat_rules = db.execute(select(NatRule).order_by(NatRule.priority, NatRule.name)).scalars().all()
            consumers = source_group_consumers(requested_group_id, groups, assignments, firewall_rules, nat_rules)
            if consumers:
                return JSONResponse(
                    {
                        "status": "conflict",
                        "detail": "Source Group is in use and cannot be removed.",
                        "consumers": consumers,
                    },
                    status_code=409,
                )
            groups = [group for group in groups if group["id"] != requested_group_id]
        else:
            existing_index = next(
                (index for index, group in enumerate(groups) if group["id"] == requested_group_id),
                None,
            )
            if existing_index is None:
                raise HTTPException(status_code=404, detail="Source Group not found.")
            if requested_group_id == FIREWALL_ANY_SOURCE_GROUP_ID:
                raise HTTPException(status_code=422, detail="Any is built in and cannot be edited.")
            current = groups[existing_index]
            name = str(form.get("group_name") or "").strip()
            if not name:
                raise HTTPException(status_code=422, detail="Source Group name is required.")
            if action == "rename":
                groups[existing_index] = normalize_source_group({**current, "name": name})
            else:
                description = (
                    str(form.get("description") or "Custom source group.")
                    if "description" in form
                    else str(current["description"])
                )
                groups[existing_index] = normalize_source_group(
                    {
                        **current,
                        "name": name,
                        "entries": _entries_from_form(form),
                        "description": description,
                    }
                )

        errors = validate_firewall_source_groups(groups)
        if errors:
            return JSONResponse(
                {"status": "error", "detail": " ".join(errors), "errors": errors},
                status_code=422,
            )
        persist_source_group_state(db, {"groups": groups, "assignments": assignments})
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action=f"{action}_source_group",
            resource_type="source_group",
            resource_id=affected_group_id or "source-groups",
        )
        if grid_request(request) or request.headers.get("X-Atlaso-Autosave") == "1":
            return _mutation_response(db, affected_group_id, status_code=201 if action == "create" else 200)
        return RedirectResponse(f"{MANAGEMENT_UI_ROOT}/network-objects", status_code=303)

    @router.post("/network-objects/source-groups", response_model=None)
    async def update_source_groups(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Create, update, or delete a Source Group on the canonical route.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            Mutation response or canonical redirect.
        """
        return await _mutate_source_groups(request, identity, db)

    @router.post("/firewall/source-groups", include_in_schema=False, response_model=None)
    async def update_source_groups_legacy(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Bridge legacy form mutation without replaying the POST on redirect.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            Canonical non-replaying redirect or validation response.
        """
        response = await _mutate_source_groups(request, identity, db)
        if response.status_code < 300 and request.headers.get("X-Atlaso-Autosave") != "1":
            return RedirectResponse(f"{MANAGEMENT_UI_ROOT}/network-objects", status_code=303)
        return response

    endpoints: dict[str, Endpoint] = {
        "network_objects": network_objects,
        "network_objects_context": network_objects_context,
        "source_group_state_for_db": source_group_state_for_db,
        "persist_source_group_state": persist_source_group_state,
        "legacy_source_groups_page": legacy_source_groups_page,
        "update_source_groups": update_source_groups,
        "update_source_groups_legacy": update_source_groups_legacy,
    }
    return NetworkObjectsUiRouter(router=router, endpoints=endpoints)
