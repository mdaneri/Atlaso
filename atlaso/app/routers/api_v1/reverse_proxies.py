"""Expose Firewall-scoped managed reverse-proxy desired state."""

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from atlaso.app.database import get_db
from atlaso.app.models import ReverseProxy
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.reverse_proxy_schemas import (
    ReverseProxyCreate,
    ReverseProxyResponse,
    ReverseProxyRouteInput,
    ReverseProxyRouteResponse,
    response_for_proxy,
)
from atlaso.app.schemas import ProblemDetails
from atlaso.app.security import Identity, require_scope
from atlaso.app.services import reverse_proxies as reverse_proxy_service
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.reverse_proxy_observation import observe_reverse_proxy_health

router = APIRouter(prefix="/api/v1/traffic-publishing/reverse-proxies", route_class=DocumentedAPIRoute, tags=["Firewall"])
ProxyId = Annotated[int, Path(ge=1, description="Positive identifier of the saved reverse-proxy resource.")]
Reader = Annotated[Identity, Depends(require_scope("read:firewall"))]
Writer = Annotated[Identity, Depends(require_scope("write:firewall"))]


class ReverseProxyRoutesReplace(BaseModel):
    """Describe an atomic replacement of every ordered path route."""

    model_config = ConfigDict(extra="forbid", strict=True)

    routes: list[ReverseProxyRouteInput] = Field(
        min_length=1,
        max_length=64,
        description="Complete ordered route collection; omitted saved routes are deleted atomically.",
    )


class ReverseProxyHealthItem(BaseModel):
    """Report bounded applied-state and route-health evidence without probing upstreams."""

    proxy_id: int = Field(description="Saved reverse-proxy identity associated with this route.")
    route_id: int = Field(description="Saved path-route identity associated with this observation.")
    proxy_name: str = Field(description="Operator-facing reverse-proxy name.")
    path_prefix: str = Field(description="Configured path prefix; no request or response body is included.")
    status: Literal["healthy", "degraded", "unavailable", "pending", "disabled"] = Field(description="Cached route state, desired-state pending state, or disabled state.")
    last_success: datetime | None = Field(default=None, description="Last successful cached upstream probe time; null when no success is recorded.")
    failure_class: str = Field(description="Bounded failure category without upstream request or response contents.")
    http_status: int | None = Field(default=None, description="Cached upstream HTTP status; null when no status is recorded.")
    tls_status: str = Field(description="Cached TLS verification state, or not_probed when no status is available.")
    pending: bool = Field(description="True while desired intent differs from the complete applied proxy snapshot or observations are unavailable.")
    applied: bool = Field(description="True only when the complete helper snapshot matches current desired proxy intent.")
    warning: str = Field(description="Operator-facing explanation; never contains upstream response data.")


class ReverseProxyHealthResponse(BaseModel):
    """Return a bounded list of read-only route-health observations."""

    items: list[ReverseProxyHealthItem] = Field(description="At most 256 route observations in stable proxy and route order.")


VALIDATION_RESPONSE: dict[int | str, dict[str, Any]] = {
    422: {"model": ProblemDetails, "description": "The request is invalid or conflicts with saved desired state."}
}
NOT_FOUND_RESPONSE: dict[int | str, dict[str, Any]] = {404: {"model": ProblemDetails, "description": "The reverse-proxy resource does not exist."}}


@router.get("", response_model=list[ReverseProxyResponse], operation_id="listReverseProxies", responses=VALIDATION_RESPONSE)
def list_reverse_proxies(identity: Reader, db: Session = Depends(get_db)) -> list[ReverseProxyResponse]:
    """List saved reverse-proxy desired state.

    Requires `read:firewall`. Returns no more than 256 saved proxies, including
    disabled intent. The result does not claim that a proxy is applied or healthy;
    global Appliance Apply owns host publication.

    Args:
        identity: Authorized Firewall reader.
        db: Saved desired-state session.
    """
    return [response_for_proxy(proxy) for proxy in reverse_proxy_service.desired_rows(db)[:256]]


@router.get("/health", response_model=ReverseProxyHealthResponse, operation_id="getReverseProxyHealth")
def get_reverse_proxy_health(identity: Reader, db: Session = Depends(get_db)) -> ReverseProxyHealthResponse:
    """Return bounded cached applied-state and route-health observations.

    Requires `read:firewall`. The endpoint makes one bounded read-only helper
    call and never performs request-time network probes or returns bodies.

    Args:
        identity: Authorized Firewall reader.
        db: Saved desired state compared with the complete applied snapshot.
    """
    return ReverseProxyHealthResponse(items=[ReverseProxyHealthItem.model_validate(item) for item in observe_reverse_proxy_health(db)])


@router.post("", response_model=ReverseProxyResponse, status_code=201, operation_id="createReverseProxy", responses=VALIDATION_RESPONSE)
def create_reverse_proxy(payload: ReverseProxyCreate, identity: Writer, db: Session = Depends(get_db)) -> ReverseProxyResponse:
    """Create a complete proxy and its ordered routes as desired state.

    Requires `write:firewall`. Validates and saves the proxy, nested routes, and
    audit record atomically. Success does not publish listeners; global Appliance
    Apply is the only host-mutation boundary. Enabled HTTPS requires an enabled CA.
    Atlaso service names, including the authoritative DNS primary, are reserved as
    proxy hostnames and upstream targets. Invalid intent returns 422 ProblemDetails.

    Args:
        payload: Complete proxy configuration with every ordered path route.
        identity: Authorized Firewall writer and audit actor.
        db: Atomic desired-state and audit transaction.
    """
    try:
        proxy = reverse_proxy_service.save_proxy(db, payload, actor=identity.username)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return response_for_proxy(proxy)


@router.get("/{proxy_id}", response_model=ReverseProxyResponse, operation_id="getReverseProxy", responses=NOT_FOUND_RESPONSE)
def get_reverse_proxy(proxy_id: ProxyId, identity: Reader, db: Session = Depends(get_db)) -> ReverseProxyResponse:
    """Read one complete saved proxy and its ordered route collection.

    Requires `read:firewall`. Returns desired state only and never probes or
    applies the host. Missing proxies return 404 ProblemDetails.

    Args:
        proxy_id: Stable saved proxy identifier.
        identity: Authorized Firewall reader.
        db: Saved desired-state session.
    """
    proxy = _get_proxy(db, proxy_id)
    if proxy is None:
        raise HTTPException(404, "Reverse proxy does not exist.")
    return response_for_proxy(proxy)


@router.put("/{proxy_id}", response_model=ReverseProxyResponse, operation_id="replaceReverseProxy", responses={**VALIDATION_RESPONSE, **NOT_FOUND_RESPONSE})
def replace_reverse_proxy(
    proxy_id: ProxyId,
    payload: ReverseProxyCreate,
    identity: Writer,
    db: Session = Depends(get_db),
) -> ReverseProxyResponse:
    """Atomically replace one proxy and its complete ordered route collection.

    Requires `write:firewall`. The complete object is required so listener,
    identity, publication, timeout, and nested-route intent are validated and
    audited in one desired-state transaction. Enabled HTTPS requires an enabled CA;
    Atlaso service names are reserved as hostnames and upstream targets. Invalid
    intent returns 422 ProblemDetails. Publication requires global Apply.

    Args:
        proxy_id: Existing proxy identity to replace.
        payload: Complete replacement including every nested path route.
        identity: Authorized Firewall writer and audit actor.
        db: Atomic desired-state and audit transaction.
    """
    try:
        proxy = reverse_proxy_service.save_proxy(db, payload, actor=identity.username, proxy_id=proxy_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return response_for_proxy(proxy)


@router.get("/{proxy_id}/routes", response_model=list[ReverseProxyRouteResponse], operation_id="listReverseProxyRoutes", responses=NOT_FOUND_RESPONSE)
def list_reverse_proxy_routes(proxy_id: ProxyId, identity: Reader, db: Session = Depends(get_db)) -> list[ReverseProxyRouteResponse]:
    """Read the ordered route resources nested under one proxy.

    Requires `read:firewall`. Route order is the matching precedence order used
    by the saved collection. Missing proxies return 404 ProblemDetails.

    Args:
        proxy_id: Parent proxy whose ordered routes are requested.
        identity: Authorized Firewall reader.
        db: Saved desired-state session.
    """
    proxy = _get_proxy(db, proxy_id)
    if proxy is None:
        raise HTTPException(404, "Reverse proxy does not exist.")
    return response_for_proxy(proxy).routes


@router.put("/{proxy_id}/routes", response_model=list[ReverseProxyRouteResponse], operation_id="replaceReverseProxyRoutes", responses={**VALIDATION_RESPONSE, **NOT_FOUND_RESPONSE})
def replace_reverse_proxy_routes(
    proxy_id: ProxyId,
    payload: ReverseProxyRoutesReplace,
    identity: Writer,
    db: Session = Depends(get_db),
) -> list[ReverseProxyRouteResponse]:
    """Atomically replace all route resources under one saved proxy.

    Requires `write:firewall`. The submitted collection is complete: omitted
    routes are deleted, and any invalid route leaves the saved proxy unchanged.
    The shared service validates and commits the entire parent and route set.

    Args:
        proxy_id: Existing parent proxy identity.
        payload: Complete ordered collection replacing every nested route.
        identity: Authorized Firewall writer and audit actor.
        db: Atomic desired-state and audit transaction.
    """
    acquire_network_objects_write_lock(db)
    current = _get_proxy(db, proxy_id)
    if current is None:
        raise HTTPException(404, "Reverse proxy does not exist.")
    replacement = {
        field: getattr(current, field)
        for field in ReverseProxyCreate.model_fields
        if field != "routes"
    }
    replacement["routes"] = [route.model_dump() for route in payload.routes]
    try:
        proxy = reverse_proxy_service.save_proxy(
            db, ReverseProxyCreate.model_validate(replacement), actor=identity.username, proxy_id=proxy_id
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return response_for_proxy(proxy).routes


def _get_proxy(db: Session, proxy_id: int) -> ReverseProxy | None:
    """Load one proxy and its bounded ordered route collection eagerly.

    Args:
        db: Caller-owned database session for proxy desired state.
        proxy_id: Exact saved proxy identifier.
    """
    return db.scalar(
        select(ReverseProxy)
        .options(selectinload(ReverseProxy.routes))
        .where(ReverseProxy.id == proxy_id)
    )


@router.delete("/{proxy_id}", status_code=204, operation_id="deleteReverseProxy", responses={**VALIDATION_RESPONSE, **NOT_FOUND_RESPONSE})
def delete_reverse_proxy(proxy_id: ProxyId, identity: Writer, db: Session = Depends(get_db)) -> Response:
    """Delete a proxy and its nested routes from desired state.

    Requires `write:firewall`. Success removes the saved intent and audit-logs
    the change; nginx, firewall, certificates, and DNS change only through the
    global Appliance Apply transaction. Missing proxies return 404 ProblemDetails;
    DNS ownership conflicts return 422 without deleting the saved proxy.

    Args:
        proxy_id: Exact saved proxy identity to remove.
        identity: Authorized Firewall writer and audit actor.
        db: Atomic desired-state and audit transaction.
    """
    try:
        reverse_proxy_service.delete_proxy(db, proxy_id, actor=identity.username)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return Response(status_code=204)
