from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi import Path as ApiPath
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    NatRule,
    PhysicalInterface,
    Route,
    ServiceState,
    VlanInterface,
    WanPolicy,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    NatRuleCreate,
    NatRuleResponse,
    RouteCreate,
    RouteResponse,
    RoutesWanSettingsResponse,
    RoutesWanSettingsUpdate,
    WanPolicyCreate,
    WanPolicyResponse,
    WanStatusResponse,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.firewall import (
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    firewall_interface_networks,
    firewall_source_group_state,
)
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.networking import normalize_interface_mode
from atlaso.app.services.routes_wan import (
    canonical_route_destination,
    default_route_family,
    ensure_routes_wan_settings,
    has_default_route_conflict,
    route_gateway_target_error,
    save_routes_wan_settings,
    validate_nat_source,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class RoutesWanApiDependencies:
    setting_value: Endpoint


@dataclass(frozen=True)
class RoutesWanApiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: RoutesWanApiDependencies) -> RoutesWanApiRouter:
    """Build the extracted domain router without importing its compatibility facade.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured domain router and its stable endpoint callables.
    """
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
    setting_value = dependencies.setting_value

    @router.get(
        "/routes-wan/settings",
        response_model=RoutesWanSettingsResponse,
        tags=["Routes", "WAN"],
        operation_id="getRoutesWanSettings",
    )
    def get_routes_wan_settings(
        identity: Annotated[Identity, Depends(require_scope("read:routes"))],
        _wan_identity: Annotated[Identity, Depends(require_scope("read:wan"))],
        db: Session = Depends(get_db),
    ) -> RoutesWanSettingsResponse:
        """Get global Routes and WAN feature settings.

        Requires both `read:routes` and `read:wan`. This operation returns saved desired state and
        does not inspect or mutate Photon runtime networking.

        Args:
            identity: Authenticated identity with the required routes scope.
            _wan_identity: Authenticated identity with the required WAN scope.
            db: Active database session used by the operation.
        """
        settings = ensure_routes_wan_settings(db)
        return RoutesWanSettingsResponse(**settings.as_dict())

    @router.put(
        "/routes-wan/settings",
        response_model=RoutesWanSettingsResponse,
        tags=["Routes", "WAN"],
        operation_id="updateRoutesWanSettings",
    )
    def update_routes_wan_settings(
        payload: RoutesWanSettingsUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:routes"))],
        _wan_identity: Annotated[Identity, Depends(require_scope("write:wan"))],
        db: Session = Depends(get_db),
    ) -> RoutesWanSettingsResponse:
        """Replace global Routes and WAN desired-state activation settings.

        Requires both `write:routes` and `write:wan`. The saved resource rows are preserved and no
        Photon host state changes until the `wan` Appliance Apply unit succeeds.

        Args:
            payload: Complete replacement for the three global feature switches.
            identity: Authenticated identity with the required routes scope.
            _wan_identity: Authenticated identity with the required WAN scope.
            db: Active database session used by the operation.
        """
        acquire_network_objects_write_lock(db)
        settings = save_routes_wan_settings(db, **payload.model_dump())
        service_state = db.execute(
            select(ServiceState).where(ServiceState.service == "routing")
        ).scalar_one_or_none()
        if service_state is not None and service_state.health != "unconfigured":
            service_state.enabled = settings.routing_enabled
            db.add(service_state)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_routes_wan_settings",
            resource_type="routes_wan_settings",
            resource_id="global",
            detail=(
                f"routing_enabled={settings.routing_enabled}; nat_enabled={settings.nat_enabled}; "
                f"wan_simulation_enabled={settings.wan_simulation_enabled}"
            ),
        )
        return RoutesWanSettingsResponse(**settings.as_dict())

    @router.get("/routes", response_model=list[RouteResponse], tags=["Routes"], operation_id="listRoutes")
    def list_routes(identity: Annotated[Identity, Depends(require_scope("read:routes"))], db: Session = Depends(get_db)) -> list[RouteResponse]:
        """List Routes.

        Requires the `read:routes` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rows = db.execute(select(Route).options(selectinload(Route.wan_policy)).order_by(Route.destination_cidr)).scalars().all()
        return [route_response(row) for row in rows]


    def route_response(route: Route) -> RouteResponse:
        """Return route response.

        Args:
            route: Route consumed by route response.
        """
        return RouteResponse(
            id=route.id,
            destination_cidr=canonical_route_destination(route.destination_cidr),
            gateway=route.gateway,
            interface_name=route.interface_name,
            metric=route.metric,
            enabled=route.enabled,
            wan_policy_id=route.wan_policy_id,
            wan_mode="interface",
            wan_policy=WanPolicyResponse.model_validate(route.wan_policy) if route.wan_policy else None,
        )


    def route_target_cidrs(db: Session) -> dict[str, tuple[str | None, str | None]]:
        """Return eligible route targets and their configured CIDRs.

        Args:
            db: Active database session.
        """
        interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
        vlans = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
        targets = {
            interface.name: (interface.ip_cidr, interface.ipv6_cidr)
            for interface in interfaces
            if interface.oper_state != "missing"
            and normalize_interface_mode(interface.mode) != "trunk"
            and (interface.role or "").strip().lower() != "management"
            and (interface.ip_cidr or interface.ipv6_cidr)
        }
        targets.update(
            {
                vlan.name: (vlan.ip_cidr, vlan.ipv6_cidr)
                for vlan in vlans
                if vlan.enabled
                and (vlan.role or "").strip().lower() != "management"
                and (vlan.ip_cidr or vlan.ipv6_cidr)
            }
        )
        return targets


    def route_target_names(db: Session) -> set[str]:
        """Return route target names.

        Args:
            db: Active database session.
        """
        return set(route_target_cidrs(db))


    def validate_route_payload(
        payload: RouteCreate,
        db: Session,
        *,
        exclude_route_id: int | None = None,
    ) -> tuple[str, str | None]:
        """Validate route payload.

        Args:
            payload: Validated request or operation payload.
            db: Active database session.
            exclude_route_id: Existing route identifier to ignore during edits.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        try:
            destination = ip_network(payload.destination_cidr, strict=False)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"{payload.destination_cidr} is not a valid destination CIDR.") from exc
        gateway_value = payload.gateway.strip() if payload.gateway else None
        if destination.prefixlen == 0 and not gateway_value:
            raise HTTPException(status_code=422, detail=f"Default IPv{destination.version} route requires a gateway.")
        if gateway_value:
            try:
                gateway = ip_address(gateway_value)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=f"{gateway_value} is not a valid gateway IP address.") from exc
            if gateway.version != destination.version:
                raise HTTPException(status_code=422, detail="Route gateway family must match the destination CIDR family.")
            gateway_value = str(gateway)
        family = default_route_family(payload.destination_cidr)
        if family is not None:
            routes = list(db.execute(select(Route).order_by(Route.id)).scalars().all())
            if has_default_route_conflict(routes, family, exclude_route_id):
                raise HTTPException(status_code=422, detail=f"Only one IPv{family} default route can be configured.")
        targets = route_target_cidrs(db)
        if payload.interface_name not in targets:
            raise HTTPException(status_code=422, detail="Choose an access physical interface or enabled VLAN interface with an IP CIDR.")
        if target_error := route_gateway_target_error(gateway_value, targets[payload.interface_name]):
            raise HTTPException(status_code=422, detail=target_error)
        if payload.metric < 0:
            raise HTTPException(status_code=422, detail="Route metric cannot be negative.")
        return canonical_route_destination(payload.destination_cidr), gateway_value


    @router.post("/routes", response_model=RouteResponse, status_code=201, tags=["Routes"], operation_id="createRoute")
    def create_route(payload: RouteCreate, identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
        """Create Route.

        Requires the `write:routes` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        # The shared mutation lock also covers settings-archive restores, so the
        # default-family check and insert remain one serialized transaction.
        acquire_network_objects_write_lock(db)
        destination, gateway = validate_route_payload(payload, db)
        values = payload.model_dump()
        values.update(destination_cidr=destination, gateway=gateway)
        route = Route(**values)
        db.add(route)
        db.commit()
        db.refresh(route)
        record_audit(db, actor=identity.username, action="create_route", resource_type="route", resource_id=str(route.id))
        return route_response(cast(Route, db.get(Route, route.id)))


    @router.get("/routes/{route_id}", response_model=RouteResponse, tags=["Routes"], operation_id="getRoute")
    def get_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("read:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
        """Get Route.

        Requires the `read:routes` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            route_id: Stable identifier of the associated route resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        route = db.execute(select(Route).options(selectinload(Route.wan_policy)).where(Route.id == route_id)).scalar_one_or_none()
        if not route:
            raise HTTPException(status_code=404, detail="Route not found")
        return route_response(route)


    @router.patch("/routes/{route_id}", response_model=RouteResponse, tags=["Routes"], operation_id="updateRoute")
    def update_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], payload: RouteCreate, identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
        """Update Route.

        Requires the `write:routes` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            route_id: Stable identifier of the associated route resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        acquire_network_objects_write_lock(db)
        route = db.get(Route, route_id)
        if not route:
            raise HTTPException(status_code=404, detail="Route not found")
        destination, gateway = validate_route_payload(payload, db, exclude_route_id=route_id)
        values = payload.model_dump()
        values.update(destination_cidr=destination, gateway=gateway)
        for key, value in values.items():
            setattr(route, key, value)
        db.commit()
        record_audit(db, actor=identity.username, action="update_route", resource_type="route", resource_id=str(route_id))
        return get_route(route_id, identity, db)


    @router.delete("/routes/{route_id}", status_code=204, tags=["Routes"], operation_id="deleteRoute")
    def delete_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> Response:
        """Delete Route.

        Requires the `write:routes` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            route_id: Stable identifier of the associated route resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        route = db.get(Route, route_id)
        if not route:
            raise HTTPException(status_code=404, detail="Route not found")
        db.delete(route)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_route", resource_type="route", resource_id=str(route_id))
        return Response(status_code=204)


    @router.post("/routes/{route_id}/enable", response_model=RouteResponse, tags=["Routes"], operation_id="enableRoute")
    def enable_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
        """Enable Route.

        Requires the `write:routes` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            route_id: Stable identifier of the associated route resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        route = db.get(Route, route_id)
        if not route:
            raise HTTPException(status_code=404, detail="Route not found")
        route.enabled = True
        db.commit()
        record_audit(db, actor=identity.username, action="enable_route", resource_type="route", resource_id=str(route_id))
        return get_route(route_id, identity, db)


    @router.post("/routes/{route_id}/disable", response_model=RouteResponse, tags=["Routes"], operation_id="disableRoute")
    def disable_route(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
        """Disable Route.

        Requires the `write:routes` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            route_id: Stable identifier of the associated route resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        route = db.get(Route, route_id)
        if not route:
            raise HTTPException(status_code=404, detail="Route not found")
        route.enabled = False
        db.commit()
        record_audit(db, actor=identity.username, action="disable_route", resource_type="route", resource_id=str(route_id))
        return get_route(route_id, identity, db)


    @router.post("/routes/{route_id}/wan-policy", response_model=RouteResponse, tags=["Routes"], operation_id="assignRouteWanPolicy")
    def assign_route_wan_policy(
        route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')],
        wan_policy_id: Annotated[int, Query(description='Unique identifier of the wan policy record addressed by this operation.')],
        identity: Annotated[Identity, Depends(require_scope("write:routes"))],
        db: Session = Depends(get_db),
    ) -> RouteResponse:
        """Assign Route Wan Policy.

        Requires the `write:routes` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            route_id: Stable identifier of the associated route resource.
            wan_policy_id: Stable identifier of the associated WAN policy resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        route = db.get(Route, route_id)
        policy = db.get(WanPolicy, wan_policy_id)
        if not route or not policy:
            raise HTTPException(status_code=404, detail="Route or WAN policy not found")
        route.wan_policy_id = policy.id
        db.commit()
        record_audit(db, actor=identity.username, action="assign_wan_policy", resource_type="route", resource_id=str(route_id))
        return get_route(route_id, identity, db)


    @router.delete("/routes/{route_id}/wan-policy", response_model=RouteResponse, tags=["Routes"], operation_id="clearRouteWanPolicy")
    def clear_route_wan_policy(route_id: Annotated[int, ApiPath(description='Unique identifier of the route record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:routes"))], db: Session = Depends(get_db)) -> RouteResponse:
        """Clear Route Wan Policy.

        Requires the `write:routes` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            route_id: Stable identifier of the associated route resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        route = db.get(Route, route_id)
        if not route:
            raise HTTPException(status_code=404, detail="Route not found")
        route.wan_policy_id = None
        db.commit()
        record_audit(db, actor=identity.username, action="clear_route_wan_policy", resource_type="route", resource_id=str(route_id))
        return get_route(route_id, identity, db)


    @router.get("/wan/policies", response_model=list[WanPolicyResponse], tags=["WAN"], operation_id="listWanPolicies")
    def list_wan_policies(identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> list[WanPolicyResponse]:
        """List Wan Policies.

        Requires the `read:wan` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [WanPolicyResponse.model_validate(row) for row in db.execute(select(WanPolicy).order_by(WanPolicy.name)).scalars().all()]


    @router.post("/wan/policies", response_model=WanPolicyResponse, status_code=201, tags=["WAN"], operation_id="createWanPolicy")
    def create_wan_policy(payload: WanPolicyCreate, identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> WanPolicyResponse:
        """Create Wan Policy.

        Requires the `write:wan` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        policy = WanPolicy(**payload.model_dump())
        db.add(policy)
        db.commit()
        db.refresh(policy)
        record_audit(db, actor=identity.username, action="create_wan_policy", resource_type="wan_policy", resource_id=str(policy.id))
        return WanPolicyResponse.model_validate(policy)


    @router.get("/wan/policies/{policy_id}", response_model=WanPolicyResponse, tags=["WAN"], operation_id="getWanPolicy")
    def get_wan_policy(policy_id: Annotated[int, ApiPath(description='Unique identifier of the policy record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> WanPolicyResponse:
        """Get Wan Policy.

        Requires the `read:wan` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            policy_id: Stable identifier of the associated policy resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        policy = db.get(WanPolicy, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="WAN policy not found")
        return WanPolicyResponse.model_validate(policy)


    @router.patch("/wan/policies/{policy_id}", response_model=WanPolicyResponse, tags=["WAN"], operation_id="updateWanPolicy")
    def update_wan_policy(policy_id: Annotated[int, ApiPath(description='Unique identifier of the policy record addressed by this operation.')], payload: WanPolicyCreate, identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> WanPolicyResponse:
        """Update Wan Policy.

        Requires the `write:wan` API scope. The operation updates saved Atlaso state and does not bypass
        the documented global Appliance Apply or service lifecycle boundary.

        Args:
            policy_id: Stable identifier of the associated policy resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        policy = db.get(WanPolicy, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="WAN policy not found")
        for key, value in payload.model_dump().items():
            setattr(policy, key, value)
        db.commit()
        db.refresh(policy)
        record_audit(db, actor=identity.username, action="update_wan_policy", resource_type="wan_policy", resource_id=str(policy.id))
        return WanPolicyResponse.model_validate(policy)


    @router.delete("/wan/policies/{policy_id}", status_code=204, tags=["WAN"], operation_id="deleteWanPolicy")
    def delete_wan_policy(policy_id: Annotated[int, ApiPath(description='Unique identifier of the policy record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> Response:
        """Delete Wan Policy.

        Requires the `write:wan` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            policy_id: Stable identifier of the associated policy resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        policy = db.get(WanPolicy, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="WAN policy not found")
        db.delete(policy)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_wan_policy", resource_type="wan_policy", resource_id=str(policy_id))
        return Response(status_code=204)


    def nat_outbound_target_names(db: Session) -> set[str]:
        """Return nat outbound target names.

        Args:
            db: Active database session.
        """
        interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
        vlans = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
        names = {
            interface.name
            for interface in interfaces
            if interface.ip_cidr and interface.oper_state != "missing" and normalize_interface_mode(interface.mode) != "trunk"
        }
        names.update({vlan.name for vlan in vlans if vlan.enabled and vlan.ip_cidr})
        return names


    def nat_source_group_ids(db: Session) -> set[str]:
        """Return nat source group ids.

        Args:
            db: Active database session.
        """
        interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
        vlans = db.execute(select(VlanInterface).order_by(VlanInterface.name)).scalars().all()
        networks = firewall_interface_networks(list(interfaces), list(vlans))
        state = firewall_source_group_state(setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY), networks)
        return {str(group.get("id", "")) for group in state["groups"]}


    def validate_nat_rule_payload(payload: NatRuleCreate, db: Session) -> None:
        """Validate nat rule payload.

        Args:
            payload: Validated request or operation payload.
            db: Active database session.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        source_groups = firewall_source_group_state(
            setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY),
            firewall_interface_networks(
                list(db.execute(select(PhysicalInterface)).scalars().all()),
                list(db.execute(select(VlanInterface)).scalars().all()),
            ),
        )["groups"]
        source_errors = validate_nat_source(payload.source, nat_source_group_ids(db), source_groups)
        if source_errors:
            raise HTTPException(status_code=422, detail=source_errors[0])
        if payload.outbound_interface not in nat_outbound_target_names(db):
            raise HTTPException(status_code=422, detail="Choose an access physical interface or enabled VLAN interface with an IP CIDR.")
        if not payload.masquerade:
            raise HTTPException(status_code=422, detail="NAT v1 supports masquerade only.")


    @router.get("/nat/rules", response_model=list[NatRuleResponse], tags=["NAT"], operation_id="listNatRules")
    def list_nat_rules(identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> list[NatRuleResponse]:
        """List Nat Rules.

        Requires the `read:wan` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rows = db.execute(select(NatRule).order_by(NatRule.priority, NatRule.name)).scalars().all()
        return [NatRuleResponse.model_validate(row) for row in rows]


    @router.post("/nat/rules", response_model=NatRuleResponse, status_code=201, tags=["NAT"], operation_id="createNatRule")
    def create_nat_rule(payload: NatRuleCreate, identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> NatRuleResponse:
        """Create Nat Rule.

        Requires the `write:wan` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        acquire_network_objects_write_lock(db)
        validate_nat_rule_payload(payload, db)
        rule = NatRule(**payload.model_dump())
        db.add(rule)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail=f"NAT rule {rule.name} already exists") from None
        db.refresh(rule)
        record_audit(db, actor=identity.username, action="create_nat_rule", resource_type="nat_rule", resource_id=str(rule.id))
        return NatRuleResponse.model_validate(rule)


    @router.get("/nat/rules/{rule_id}", response_model=NatRuleResponse, tags=["NAT"], operation_id="getNatRule")
    def get_nat_rule(rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> NatRuleResponse:
        """Get Nat Rule.

        Requires the `read:wan` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            rule_id: Stable identifier of the associated rule resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rule = db.get(NatRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="NAT rule not found")
        return NatRuleResponse.model_validate(rule)


    @router.patch("/nat/rules/{rule_id}", response_model=NatRuleResponse, tags=["NAT"], operation_id="updateNatRule")
    def update_nat_rule(rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')], payload: NatRuleCreate, identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> NatRuleResponse:
        """Update Nat Rule.

        Requires the `write:wan` API scope. The operation updates saved Atlaso state and does not bypass
        the documented global Appliance Apply or service lifecycle boundary.

        Args:
            rule_id: Stable identifier of the associated rule resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        acquire_network_objects_write_lock(db)
        rule = db.get(NatRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="NAT rule not found")
        validate_nat_rule_payload(payload, db)
        for key, value in payload.model_dump().items():
            setattr(rule, key, value)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail=f"NAT rule {rule.name} already exists") from None
        db.refresh(rule)
        record_audit(db, actor=identity.username, action="update_nat_rule", resource_type="nat_rule", resource_id=str(rule.id))
        return NatRuleResponse.model_validate(rule)


    @router.delete("/nat/rules/{rule_id}", status_code=204, tags=["NAT"], operation_id="deleteNatRule")
    def delete_nat_rule(rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')], identity: Annotated[Identity, Depends(require_scope("write:wan"))], db: Session = Depends(get_db)) -> Response:
        """Delete Nat Rule.

        Requires the `write:wan` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            rule_id: Stable identifier of the associated rule resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        acquire_network_objects_write_lock(db)
        rule = db.get(NatRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="NAT rule not found")
        db.delete(rule)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_nat_rule", resource_type="nat_rule", resource_id=str(rule_id))
        return Response(status_code=204)


    @router.get("/wan/status", response_model=WanStatusResponse, tags=["WAN"], operation_id="getWanStatus")
    def get_wan_status(identity: Annotated[Identity, Depends(require_scope("read:wan"))], db: Session = Depends(get_db)) -> WanStatusResponse:
        """Get Wan Status.

        Requires the `read:wan` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = ensure_routes_wan_settings(db)
        routes: Sequence[Route] = ()
        if settings.wan_simulation_enabled:
            routes = (
                db.execute(
                    select(Route)
                    .join(WanPolicy)
                    .where(
                        Route.enabled.is_(True),
                        WanPolicy.enabled.is_(True),
                    )
                )
                .scalars()
                .all()
            )
        nat_rules: Sequence[NatRule] = ()
        if settings.effective_nat_enabled:
            nat_rules = (
                db.execute(select(NatRule).where(NatRule.enabled.is_(True)))
                .scalars()
                .all()
            )
        return WanStatusResponse(
            active_policy_count=len(routes),
            managed_interfaces=sorted({route.interface_name for route in routes} | {rule.outbound_interface for rule in nat_rules}),
            dry_run=SystemAdapter().dry_run,
        )

    endpoints: dict[str, Endpoint] = {
        "get_routes_wan_settings": get_routes_wan_settings,
        "update_routes_wan_settings": update_routes_wan_settings,
        "list_routes": list_routes,
        "route_response": route_response,
        "route_target_cidrs": route_target_cidrs,
        "route_target_names": route_target_names,
        "validate_route_payload": validate_route_payload,
        "create_route": create_route,
        "get_route": get_route,
        "update_route": update_route,
        "delete_route": delete_route,
        "enable_route": enable_route,
        "disable_route": disable_route,
        "assign_route_wan_policy": assign_route_wan_policy,
        "clear_route_wan_policy": clear_route_wan_policy,
        "list_wan_policies": list_wan_policies,
        "create_wan_policy": create_wan_policy,
        "get_wan_policy": get_wan_policy,
        "update_wan_policy": update_wan_policy,
        "delete_wan_policy": delete_wan_policy,
        "nat_outbound_target_names": nat_outbound_target_names,
        "nat_source_group_ids": nat_source_group_ids,
        "validate_nat_rule_payload": validate_nat_rule_payload,
        "list_nat_rules": list_nat_rules,
        "create_nat_rule": create_nat_rule,
        "get_nat_rule": get_nat_rule,
        "update_nat_rule": update_nat_rule,
        "delete_nat_rule": delete_nat_rule,
        "get_wan_status": get_wan_status,
    }
    return RoutesWanApiRouter(router=router, endpoints=endpoints)
