from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any, cast

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import NatRule, Route, RoutingRule, WanPolicy
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.routes_wan import (
    DEFAULT_ROUTE_DESTINATIONS,
    WAN_MODES,
    canonical_route_destination,
    has_default_route_conflict,
    validate_nat_source,
)
from atlaso.app.services.routes_wan import (
    default_route_family as route_default_family,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class RoutesWanUiDependencies:
    require_management_ui_request: Endpoint
    render: Endpoint
    appliance_apply_status: Endpoint
    routes_wan_context: Endpoint
    verify_csrf: Endpoint
    wan_route_targets: Endpoint
    wan_nat_targets_from_route_targets: Endpoint
    firewall_source_group_state_for_db: Endpoint


@dataclass(frozen=True)
class RoutesWanUiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: RoutesWanUiDependencies) -> RoutesWanUiRouter:
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
    appliance_apply_status = dependencies.appliance_apply_status
    routes_wan_context = dependencies.routes_wan_context
    verify_csrf = dependencies.verify_csrf
    wan_route_targets = dependencies.wan_route_targets
    wan_nat_targets_from_route_targets = dependencies.wan_nat_targets_from_route_targets
    firewall_source_group_state_for_db = dependencies.firewall_source_group_state_for_db

    @router.get("/routes-wan", response_class=HTMLResponse, response_model=None)
    def routes_wan(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the routes wan endpoint.

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
                "routes_wan.html",
                {
                    "identity": identity,
                    **routes_wan_context(db),
                    "routes_wan_can_write": identity.can("write:routes"),
                    "appliance_apply_status": appliance_apply_status(db, "wan"),
                },
            ),
        )


    def parse_int_form_value(value: str, field_label: str, *, default: int = 0, minimum: int | None = None) -> int | Response:
        """Parse int form value.

        Args:
            value: Candidate value consumed by parse int form value.
            field_label: Candidate field label to parse.
            default: Candidate default to parse.
            minimum: Candidate minimum to parse.


        Returns:
            The parsed int form value.
        """
        if value == "":
            parsed = default
        else:
            try:
                parsed = int(value)
            except ValueError:
                return Response(f"{field_label} must be a number.", status_code=422, media_type="text/plain")
        if minimum is not None and parsed < minimum:
            return Response(f"{field_label} must be at least {minimum}.", status_code=422, media_type="text/plain")
        return parsed


    def parse_optional_int_form_value(value: str, field_label: str, *, minimum: int | None = None) -> int | None | Response:
        """Parse optional int form value.

        Args:
            value: Candidate value consumed by parse optional int form value.
            field_label: Candidate field label to parse.
            minimum: Candidate minimum to parse.


        Returns:
            The parsed optional int form value.
        """
        if value == "":
            return None
        return parse_int_form_value(value, field_label, minimum=minimum or None)


    def parse_float_form_value(value: str, field_label: str, *, default: float = 0.0, minimum: float | None = None, maximum: float | None = None) -> float | Response:
        """Parse float form value.

        Args:
            value: Value to process.
            field_label: Field label supplied by the caller.
            default: Default supplied by the caller.
            minimum: Minimum supplied by the caller.
            maximum: Maximum supplied by the caller.

        Returns:
            The parsed float form value.
        """
        if value == "":
            parsed = default
        else:
            try:
                parsed = float(value)
            except ValueError:
                return Response(f"{field_label} must be a number.", status_code=422, media_type="text/plain")
        if minimum is not None and parsed < minimum:
            return Response(f"{field_label} must be at least {minimum}.", status_code=422, media_type="text/plain")
        if maximum is not None and parsed > maximum:
            return Response(f"{field_label} must be at most {maximum}.", status_code=422, media_type="text/plain")
        return parsed


    def validate_route_form_values(
        destination_cidr: str,
        gateway: str,
        interface_name: str,
        metric: str,
        wan_policy_id: str,
        wan_mode: str,
        db: Session,
        *,
        default_route: bool = False,
        default_route_family: str = "4",
        exclude_route_id: int | None = None,
    ) -> tuple[str, str | None, str, int, int | None, str] | Response:
        """Validate route form values.

        Args:
            destination_cidr: Destination cidr supplied by the caller.
            gateway: Gateway supplied by the caller.
            interface_name: Linux interface name of the network target.
            metric: Metric supplied by the caller.
            wan_policy_id: Identifier of the wan policy.
            wan_mode: Wan mode supplied by the caller.
            db: Active database session.

        Returns:
            The validate route form values result.
        """
        destination = destination_cidr.strip()
        if default_route:
            if destination:
                return Response("Default route and Destination CIDR are mutually exclusive.", status_code=422, media_type="text/plain")
            try:
                selected_family = int(default_route_family)
            except ValueError:
                selected_family = 0
            if selected_family not in DEFAULT_ROUTE_DESTINATIONS:
                return Response("Default route family must be IPv4 or IPv6.", status_code=422, media_type="text/plain")
            destination = DEFAULT_ROUTE_DESTINATIONS[selected_family]
        elif not destination:
            return Response("Destination CIDR is required unless Default route is selected.", status_code=422, media_type="text/plain")
        try:
            destination_network = ip_network(destination, strict=False)
        except ValueError:
            return Response(f"{destination} is not a valid destination CIDR.", status_code=422, media_type="text/plain")
        if destination_network.prefixlen == 0 and not default_route:
            return Response(
                "Select Default route instead of entering a /0 Destination CIDR.",
                status_code=422,
                media_type="text/plain",
            )
        destination = canonical_route_destination(destination)
        gateway_value = gateway.strip() or None
        if destination_network.prefixlen == 0 and not gateway_value:
            return Response(f"Default IPv{destination_network.version} route requires a gateway.", status_code=422, media_type="text/plain")
        if gateway_value:
            try:
                gateway_address = ip_address(gateway_value)
            except ValueError:
                return Response(f"{gateway_value} is not a valid gateway IP address.", status_code=422, media_type="text/plain")
            if gateway_address.version != destination_network.version:
                return Response("Route gateway family must match the destination CIDR family.", status_code=422, media_type="text/plain")
            gateway_value = str(gateway_address)
        family = route_default_family(destination)
        if family is not None:
            routes = list(db.execute(select(Route).order_by(Route.id)).scalars().all())
            if has_default_route_conflict(routes, family, exclude_route_id):
                return Response(f"Only one IPv{family} default route can be configured.", status_code=422, media_type="text/plain")
        target_names = {target["name"] for target in wan_route_targets(db)}
        interface_value = interface_name.strip()
        if interface_value not in target_names:
            return Response("Choose an access physical interface or enabled VLAN interface with an IP CIDR.", status_code=422, media_type="text/plain")
        metric_value = parse_int_form_value(metric.strip(), "Metric", default=100, minimum=0)
        if isinstance(metric_value, Response):
            return metric_value
        policy_id_value: int | None = None
        if wan_policy_id.strip():
            parsed_policy_id = parse_int_form_value(wan_policy_id.strip(), "WAN policy", minimum=1)
            if isinstance(parsed_policy_id, Response):
                return parsed_policy_id
            if db.get(WanPolicy, parsed_policy_id) is None:
                return Response("WAN policy does not exist.", status_code=422, media_type="text/plain")
            policy_id_value = parsed_policy_id
        raw_mode = wan_mode.strip() or "interface"
        if raw_mode not in WAN_MODES:
            return Response("WAN route mode is planned but not supported in v1. Use interface mode.", status_code=422, media_type="text/plain")
        mode_value = "interface"
        return destination, gateway_value, interface_value, metric_value, policy_id_value, mode_value


    def validate_wan_policy_form_values(
        name: str,
        latency_ms: str,
        jitter_ms: str,
        packet_loss_percent: str,
        bandwidth_mbit: str,
        corrupt_percent: str,
        duplicate_percent: str,
        reorder_percent: str,
    ) -> tuple[str, int, int, float, int | None, float, float, float] | Response:
        """Validate wan policy form values.

        Args:
            name: Name of the target object.
            latency_ms: Latency ms supplied by the caller.
            jitter_ms: Jitter ms supplied by the caller.
            packet_loss_percent: Packet loss percent supplied by the caller.
            bandwidth_mbit: Bandwidth mbit supplied by the caller.
            corrupt_percent: Corrupt percent supplied by the caller.
            duplicate_percent: Duplicate percent supplied by the caller.
            reorder_percent: Reorder percent supplied by the caller.

        Returns:
            The validate wan policy form values result.
        """
        name_value = name.strip()
        if not name_value:
            return Response("WAN policy name is required.", status_code=422, media_type="text/plain")
        latency_value = parse_int_form_value(latency_ms.strip(), "Latency", default=0, minimum=0)
        jitter_value = parse_int_form_value(jitter_ms.strip(), "Jitter", default=0, minimum=0)
        loss_value = parse_float_form_value(packet_loss_percent.strip(), "Packet loss", default=0.0, minimum=0.0, maximum=100.0)
        bandwidth_value = parse_optional_int_form_value(bandwidth_mbit.strip(), "Bandwidth", minimum=1)
        corrupt_value = parse_float_form_value(corrupt_percent.strip(), "Corruption", default=0.0, minimum=0.0, maximum=100.0)
        duplicate_value = parse_float_form_value(duplicate_percent.strip(), "Duplication", default=0.0, minimum=0.0, maximum=100.0)
        reorder_value = parse_float_form_value(reorder_percent.strip(), "Reordering", default=0.0, minimum=0.0, maximum=100.0)
        for value in [latency_value, jitter_value, loss_value, bandwidth_value, corrupt_value, duplicate_value, reorder_value]:
            if isinstance(value, Response):
                return value
        return cast(
            tuple[str, int, int, float, int | None, float, float, float],
            (
                name_value,
                latency_value,
                jitter_value,
                loss_value,
                bandwidth_value,
                corrupt_value,
                duplicate_value,
                reorder_value,
            ),
        )


    def validate_nat_rule_form_values(
        name: str,
        source: str,
        outbound_interface: str,
        priority: str,
        masquerade: str | None,
        db: Session,
    ) -> tuple[str, str, str, bool, int] | Response:
        """Validate nat rule form values.

        Args:
            name: Name of the target object.
            source: Source path, address, or record to process.
            outbound_interface: Outbound interface supplied by the caller.
            priority: Ordering priority assigned to the item.
            masquerade: Masquerade supplied by the caller.
            db: Active database session.

        Returns:
            The validate nat rule form values result.
        """
        name_value = name.strip()
        if not name_value:
            return Response("NAT rule name is required.", status_code=422, media_type="text/plain")
        source_value = source.strip() or "any"
        source_groups = firewall_source_group_state_for_db(db)["groups"]
        source_errors = validate_nat_source(source_value, {str(group.get("id", "")) for group in source_groups}, source_groups)
        if source_errors:
            return Response(source_errors[0], status_code=422, media_type="text/plain")
        target_names = {target["name"] for target in wan_nat_targets_from_route_targets(wan_route_targets(db))}
        outbound_value = outbound_interface.strip()
        if outbound_value not in target_names:
            return Response("Choose an access physical interface or enabled VLAN interface with an IP CIDR.", status_code=422, media_type="text/plain")
        masquerade_value = masquerade == "on"
        if not masquerade_value:
            return Response("NAT v1 supports masquerade only.", status_code=422, media_type="text/plain")
        priority_value = parse_int_form_value(priority.strip(), "Priority", default=100, minimum=0)
        if isinstance(priority_value, Response):
            return priority_value
        return name_value, source_value, outbound_value, masquerade_value, priority_value


    def validate_routing_rule_form_values(
        name: str,
        source_interface: str,
        destination_interface: str,
        priority: str,
        db: Session,
    ) -> tuple[str, str, str, int] | Response:
        """Validate routing rule form values.

        Args:
            name: Name of the target object.
            source_interface: Source interface supplied by the caller.
            destination_interface: Destination interface supplied by the caller.
            priority: Ordering priority assigned to the item.
            db: Active database session.

        Returns:
            The validate routing rule form values result.
        """
        name_value = name.strip()
        if not name_value:
            return Response("Routing rule name is required.", status_code=422, media_type="text/plain")
        target_names = {target["name"] for target in wan_route_targets(db)}
        source_value = source_interface.strip()
        destination_value = destination_interface.strip()
        if source_value not in target_names:
            return Response("Choose a non-management source interface or VLAN with an IP CIDR.", status_code=422, media_type="text/plain")
        if destination_value not in target_names:
            return Response("Choose a non-management destination interface or VLAN with an IP CIDR.", status_code=422, media_type="text/plain")
        if source_value == destination_value:
            return Response("Routing source and destination must be different.", status_code=422, media_type="text/plain")
        priority_value = parse_int_form_value(priority.strip(), "Priority", default=100, minimum=0)
        if isinstance(priority_value, Response):
            return priority_value
        return name_value, source_value, destination_value, priority_value


    @router.post("/routes-wan/routes", response_model=None)
    def create_route_from_ui(
        request: Request,
        destination_cidr: str = Form(""),
        gateway: str = Form(""),
        interface_name: str = Form(""),
        metric: str = Form("100"),
        wan_policy_id: str = Form(""),
        wan_mode: str = Form("interface"),
        default_route: str | None = Form(None),
        default_route_family: str = Form("4"),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the create route from ui endpoint.

        Args:
            request: Incoming HTTP request.
            destination_cidr: Destination cidr supplied by the caller.
            gateway: Gateway supplied by the caller.
            interface_name: Linux interface name of the network target.
            metric: Metric supplied by the caller.
            wan_policy_id: Identifier of the wan policy.
            wan_mode: Wan mode supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        # Serialize the default-family check and write with API and archive mutations.
        acquire_network_objects_write_lock(db)
        parsed = validate_route_form_values(
            destination_cidr,
            gateway,
            interface_name,
            metric,
            wan_policy_id,
            wan_mode,
            db,
            default_route=default_route == "on",
            default_route_family=default_route_family,
        )
        if isinstance(parsed, Response):
            return parsed
        destination, gateway_value, interface_value, metric_value, policy_id_value, mode_value = parsed
        route = Route(
            destination_cidr=destination,
            gateway=gateway_value,
            interface_name=interface_value,
            metric=metric_value,
            wan_policy_id=policy_id_value,
            wan_mode=mode_value,
            enabled=enabled == "on",
        )
        db.add(route)
        db.commit()
        record_audit(db, actor=identity.username, action="create_route", resource_type="route", resource_id=str(route.id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/routes/{route_id}/edit", response_model=None)
    def edit_route_from_ui(
        request: Request,
        route_id: int,
        destination_cidr: str = Form(""),
        gateway: str = Form(""),
        interface_name: str = Form(""),
        metric: str = Form("100"),
        wan_policy_id: str = Form(""),
        wan_mode: str = Form("interface"),
        default_route: str | None = Form(None),
        default_route_family: str = Form("4"),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the edit route from ui endpoint.

        Args:
            request: Incoming HTTP request.
            route_id: Identifier of the route.
            destination_cidr: Destination cidr supplied by the caller.
            gateway: Gateway supplied by the caller.
            interface_name: Linux interface name of the network target.
            metric: Metric supplied by the caller.
            wan_policy_id: Identifier of the wan policy.
            wan_mode: Wan mode supplied by the caller.
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
        acquire_network_objects_write_lock(db)
        route = db.get(Route, route_id)
        if not route:
            raise HTTPException(status_code=404, detail="Route not found")
        parsed = validate_route_form_values(
            destination_cidr,
            gateway,
            interface_name,
            metric,
            wan_policy_id,
            wan_mode,
            db,
            default_route=default_route == "on",
            default_route_family=default_route_family,
            exclude_route_id=route_id,
        )
        if isinstance(parsed, Response):
            return parsed
        destination, gateway_value, interface_value, metric_value, policy_id_value, mode_value = parsed
        route.destination_cidr = destination
        route.gateway = gateway_value
        route.interface_name = interface_value
        route.metric = metric_value
        route.wan_policy_id = policy_id_value
        route.wan_mode = mode_value
        route.enabled = enabled == "on"
        db.add(route)
        db.commit()
        record_audit(db, actor=identity.username, action="update_route", resource_type="route", resource_id=str(route.id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/routes/{route_id}/delete", response_model=None)
    def delete_route_from_ui(
        request: Request,
        route_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete route from ui endpoint.

        Args:
            request: Incoming HTTP request.
            route_id: Identifier of the route.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        route = db.get(Route, route_id)
        if not route:
            raise HTTPException(status_code=404, detail="Route not found")
        db.delete(route)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_route", resource_type="route", resource_id=str(route_id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/routing-rules", response_model=None)
    def create_routing_rule_from_ui(
        request: Request,
        name: str = Form(""),
        source_interface: str = Form(""),
        destination_interface: str = Form(""),
        priority: str = Form("100"),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the create routing rule from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            source_interface: Source interface supplied by the caller.
            destination_interface: Destination interface supplied by the caller.
            priority: Ordering priority assigned to the item.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        parsed = validate_routing_rule_form_values(name, source_interface, destination_interface, priority, db)
        if isinstance(parsed, Response):
            return parsed
        name_value, source_value, destination_value, priority_value = parsed
        rule = RoutingRule(
            name=name_value,
            source_interface=source_value,
            destination_interface=destination_value,
            priority=priority_value,
            description=description.strip() or None,
            enabled=enabled == "on",
        )
        db.add(rule)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return Response(f"Routing rule {rule.name} already exists.", status_code=409, media_type="text/plain")
        record_audit(db, actor=identity.username, action="create_routing_rule", resource_type="routing_rule", resource_id=str(rule.id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/routing-rules/{rule_id}/edit", response_model=None)
    def edit_routing_rule_from_ui(
        request: Request,
        rule_id: int,
        name: str = Form(""),
        source_interface: str = Form(""),
        destination_interface: str = Form(""),
        priority: str = Form("100"),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the edit routing rule from ui endpoint.

        Args:
            request: Incoming HTTP request.
            rule_id: Identifier of the rule.
            name: Name of the target object.
            source_interface: Source interface supplied by the caller.
            destination_interface: Destination interface supplied by the caller.
            priority: Ordering priority assigned to the item.
            description: Human-readable description of the resource.
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
        rule = db.get(RoutingRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Routing rule not found")
        parsed = validate_routing_rule_form_values(name, source_interface, destination_interface, priority, db)
        if isinstance(parsed, Response):
            return parsed
        name_value, source_value, destination_value, priority_value = parsed
        rule.name = name_value
        rule.source_interface = source_value
        rule.destination_interface = destination_value
        rule.priority = priority_value
        rule.description = description.strip() or None
        rule.enabled = enabled == "on"
        db.add(rule)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return Response(f"Routing rule {rule.name} already exists.", status_code=409, media_type="text/plain")
        record_audit(db, actor=identity.username, action="update_routing_rule", resource_type="routing_rule", resource_id=str(rule.id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/routing-rules/{rule_id}/delete", response_model=None)
    def delete_routing_rule_from_ui(
        request: Request,
        rule_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete routing rule from ui endpoint.

        Args:
            request: Incoming HTTP request.
            rule_id: Identifier of the rule.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        rule = db.get(RoutingRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Routing rule not found")
        db.delete(rule)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_routing_rule", resource_type="routing_rule", resource_id=str(rule_id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/nat-rules", response_model=None)
    def create_nat_rule_from_ui(
        request: Request,
        name: str = Form(""),
        source: str = Form("any"),
        outbound_interface: str = Form(""),
        masquerade: str | None = Form(None),
        priority: str = Form("100"),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the create nat rule from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            source: Source path, address, or record to process.
            outbound_interface: Outbound interface supplied by the caller.
            masquerade: Masquerade supplied by the caller.
            priority: Ordering priority assigned to the item.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        acquire_network_objects_write_lock(db)
        parsed = validate_nat_rule_form_values(name, source, outbound_interface, priority, masquerade, db)
        if isinstance(parsed, Response):
            return parsed
        name_value, source_value, outbound_value, masquerade_value, priority_value = parsed
        rule = NatRule(
            name=name_value,
            source=source_value,
            outbound_interface=outbound_value,
            masquerade=masquerade_value,
            priority=priority_value,
            description=description.strip() or None,
            enabled=enabled == "on",
        )
        db.add(rule)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return Response(f"NAT rule {rule.name} already exists.", status_code=409, media_type="text/plain")
        record_audit(db, actor=identity.username, action="create_nat_rule", resource_type="nat_rule", resource_id=str(rule.id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/nat-rules/{rule_id}/edit", response_model=None)
    def edit_nat_rule_from_ui(
        request: Request,
        rule_id: int,
        name: str = Form(""),
        source: str = Form("any"),
        outbound_interface: str = Form(""),
        masquerade: str | None = Form(None),
        priority: str = Form("100"),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the edit nat rule from ui endpoint.

        Args:
            request: Incoming HTTP request.
            rule_id: Identifier of the rule.
            name: Name of the target object.
            source: Source path, address, or record to process.
            outbound_interface: Outbound interface supplied by the caller.
            masquerade: Masquerade supplied by the caller.
            priority: Ordering priority assigned to the item.
            description: Human-readable description of the resource.
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
        acquire_network_objects_write_lock(db)
        rule = db.get(NatRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="NAT rule not found")
        parsed = validate_nat_rule_form_values(name, source, outbound_interface, priority, masquerade, db)
        if isinstance(parsed, Response):
            return parsed
        name_value, source_value, outbound_value, masquerade_value, priority_value = parsed
        rule.name = name_value
        rule.source = source_value
        rule.outbound_interface = outbound_value
        rule.masquerade = masquerade_value
        rule.priority = priority_value
        rule.description = description.strip() or None
        rule.enabled = enabled == "on"
        db.add(rule)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return Response(f"NAT rule {rule.name} already exists.", status_code=409, media_type="text/plain")
        record_audit(db, actor=identity.username, action="update_nat_rule", resource_type="nat_rule", resource_id=str(rule.id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/nat-rules/{rule_id}/delete", response_model=None)
    def delete_nat_rule_from_ui(
        request: Request,
        rule_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete nat rule from ui endpoint.

        Args:
            request: Incoming HTTP request.
            rule_id: Identifier of the rule.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        acquire_network_objects_write_lock(db)
        rule = db.get(NatRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="NAT rule not found")
        db.delete(rule)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_nat_rule", resource_type="nat_rule", resource_id=str(rule_id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/policies", response_model=None)
    def create_policy_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        latency_ms: str = Form("0"),
        jitter_ms: str = Form("0"),
        packet_loss_percent: str = Form("0"),
        bandwidth_mbit: str = Form(""),
        corrupt_percent: str = Form("0"),
        duplicate_percent: str = Form("0"),
        reorder_percent: str = Form("0"),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the create policy from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            latency_ms: Latency ms supplied by the caller.
            jitter_ms: Jitter ms supplied by the caller.
            packet_loss_percent: Packet loss percent supplied by the caller.
            bandwidth_mbit: Bandwidth mbit supplied by the caller.
            corrupt_percent: Corrupt percent supplied by the caller.
            duplicate_percent: Duplicate percent supplied by the caller.
            reorder_percent: Reorder percent supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        parsed = validate_wan_policy_form_values(
            name,
            latency_ms,
            jitter_ms,
            packet_loss_percent,
            bandwidth_mbit,
            corrupt_percent,
            duplicate_percent,
            reorder_percent,
        )
        if isinstance(parsed, Response):
            return parsed
        name_value, latency_value, jitter_value, loss_value, bandwidth_value, corrupt_value, duplicate_value, reorder_value = parsed
        policy = WanPolicy(
            name=name_value,
            description=description.strip() or None,
            latency_ms=latency_value,
            jitter_ms=jitter_value,
            packet_loss_percent=loss_value,
            bandwidth_mbit=bandwidth_value,
            corrupt_percent=corrupt_value,
            duplicate_percent=duplicate_value,
            reorder_percent=reorder_value,
            enabled=enabled == "on",
        )
        db.add(policy)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return Response(f"WAN policy {policy.name} already exists.", status_code=409, media_type="text/plain")
        record_audit(db, actor=identity.username, action="create_wan_policy", resource_type="wan_policy", resource_id=str(policy.id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/policies/{policy_id}/edit", response_model=None)
    def edit_policy_from_ui(
        request: Request,
        policy_id: int,
        name: str = Form(""),
        description: str = Form(""),
        latency_ms: str = Form("0"),
        jitter_ms: str = Form("0"),
        packet_loss_percent: str = Form("0"),
        bandwidth_mbit: str = Form(""),
        corrupt_percent: str = Form("0"),
        duplicate_percent: str = Form("0"),
        reorder_percent: str = Form("0"),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the edit policy from ui endpoint.

        Args:
            request: Incoming HTTP request.
            policy_id: Identifier of the policy.
            name: Name of the target object.
            description: Human-readable description of the resource.
            latency_ms: Latency ms supplied by the caller.
            jitter_ms: Jitter ms supplied by the caller.
            packet_loss_percent: Packet loss percent supplied by the caller.
            bandwidth_mbit: Bandwidth mbit supplied by the caller.
            corrupt_percent: Corrupt percent supplied by the caller.
            duplicate_percent: Duplicate percent supplied by the caller.
            reorder_percent: Reorder percent supplied by the caller.
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
        policy = db.get(WanPolicy, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="WAN policy not found")
        parsed = validate_wan_policy_form_values(
            name,
            latency_ms,
            jitter_ms,
            packet_loss_percent,
            bandwidth_mbit,
            corrupt_percent,
            duplicate_percent,
            reorder_percent,
        )
        if isinstance(parsed, Response):
            return parsed
        name_value, latency_value, jitter_value, loss_value, bandwidth_value, corrupt_value, duplicate_value, reorder_value = parsed
        policy.name = name_value
        policy.description = description.strip() or None
        policy.latency_ms = latency_value
        policy.jitter_ms = jitter_value
        policy.packet_loss_percent = loss_value
        policy.bandwidth_mbit = bandwidth_value
        policy.corrupt_percent = corrupt_value
        policy.duplicate_percent = duplicate_value
        policy.reorder_percent = reorder_value
        policy.enabled = enabled == "on"
        db.add(policy)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return Response(f"WAN policy {policy.name} already exists.", status_code=409, media_type="text/plain")
        record_audit(db, actor=identity.username, action="update_wan_policy", resource_type="wan_policy", resource_id=str(policy.id))
        return RedirectResponse("/routes-wan", status_code=303)


    @router.post("/routes-wan/policies/{policy_id}/delete", response_model=None)
    def delete_policy_from_ui(
        request: Request,
        policy_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete policy from ui endpoint.

        Args:
            request: Incoming HTTP request.
            policy_id: Identifier of the policy.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        policy = db.get(WanPolicy, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="WAN policy not found")
        for route in db.execute(select(Route).where(Route.wan_policy_id == policy.id)).scalars().all():
            route.wan_policy_id = None
            db.add(route)
        db.delete(policy)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_wan_policy", resource_type="wan_policy", resource_id=str(policy_id))
        return RedirectResponse("/routes-wan", status_code=303)

    endpoints: dict[str, Endpoint] = {
        "routes_wan": routes_wan,
        "parse_int_form_value": parse_int_form_value,
        "parse_optional_int_form_value": parse_optional_int_form_value,
        "parse_float_form_value": parse_float_form_value,
        "validate_route_form_values": validate_route_form_values,
        "validate_wan_policy_form_values": validate_wan_policy_form_values,
        "validate_nat_rule_form_values": validate_nat_rule_form_values,
        "validate_routing_rule_form_values": validate_routing_rule_form_values,
        "create_route_from_ui": create_route_from_ui,
        "edit_route_from_ui": edit_route_from_ui,
        "delete_route_from_ui": delete_route_from_ui,
        "create_routing_rule_from_ui": create_routing_rule_from_ui,
        "edit_routing_rule_from_ui": edit_routing_rule_from_ui,
        "delete_routing_rule_from_ui": delete_routing_rule_from_ui,
        "create_nat_rule_from_ui": create_nat_rule_from_ui,
        "edit_nat_rule_from_ui": edit_nat_rule_from_ui,
        "delete_nat_rule_from_ui": delete_nat_rule_from_ui,
        "create_policy_from_ui": create_policy_from_ui,
        "edit_policy_from_ui": edit_policy_from_ui,
        "delete_policy_from_ui": delete_policy_from_ui,
    }
    return RoutesWanUiRouter(router=router, endpoints=endpoints)
