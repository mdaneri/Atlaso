"""Read and validate bounded observations from the applied proxy runtime."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.services.reverse_proxies import MAX_TOTAL_PROXY_ROUTES, runtime_snapshot

MAX_HELPER_OUTPUT = 1_048_576
MAX_OBSERVATION_AGE = timedelta(seconds=90)
MAX_FUTURE_SKEW = timedelta(seconds=5)
_GENERATION = re.compile(r"[0-9a-f]{64}\Z")
_SOCKET_ID = re.compile(r"[1-9][0-9]{0,9}-[1-9][0-9]{0,9}\Z")
_STATUSES = {"healthy", "degraded", "unavailable"}
_FAILURES = {"insecure_verification", "invalid_http", "tls_verification", "unavailable", "upstream_http"}
_TLS_STATUSES = {"failed", "fingerprint", "insecure", "not_applicable", "not_probed", "trusted_ca"}


def observe_reverse_proxy_health(db: Session, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Compare saved intent with one bounded helper snapshot and project route health.

    No network probe is performed here. The helper only returns its cached
    observation, and malformed, unavailable, or stale results are fail-closed.

    Args:
        db: Read-only session containing current desired proxy state.
        now: Optional aware UTC time used by deterministic freshness checks.
    """
    desired = runtime_snapshot(db)
    desired_routes = sum(len(proxy["routes"]) for proxy in desired)
    if len(desired) > 256 or desired_routes > MAX_TOTAL_PROXY_ROUTES:
        return _unavailable_items(desired, "desired_state_exceeds_limit")

    try:
        result = SystemAdapter().reverse_proxy_status()
        if result.dry_run or result.returncode != 0 or len(result.stdout) > MAX_HELPER_OUTPUT:
            return _unavailable_items(desired, "runtime_observer_unavailable")
        observation = json.loads(result.stdout)
        parsed = _validate_observation(observation, now=now)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return _unavailable_items(desired, "runtime_observer_unavailable")

    if parsed["proxies"] != desired:
        return _pending_items(desired)

    health = parsed["health"]
    items: list[dict[str, Any]] = []
    for proxy in desired:
        for route in proxy["routes"]:
            socket_id = f"{proxy['id']}-{route['id']}"
            observed = health.get(socket_id)
            if not proxy["enabled"]:
                item = _base_item(proxy, route, status="disabled", applied=True, pending=False,
                                  failure_class="", tls_status="not_probed", http_status=None, last_success=None)
                item["warning"] = "This saved proxy is disabled in the applied runtime."
            elif observed is None:
                item = _base_item(proxy, route, status="unavailable", applied=True, pending=False,
                                  failure_class="health_unavailable", tls_status="not_probed", http_status=None, last_success=None)
                item["warning"] = "The applied proxy has no current route-health observation."
            else:
                status = observed["status"]
                failure_class = observed["failure_class"] or ""
                warning = ""
                if route["trust_mode"] == "insecure":
                    status = "degraded"
                    failure_class = "insecure_verification"
                    warning = "Upstream certificate verification is disabled; this route remains degraded."
                elif status == "degraded":
                    warning = "The applied upstream route is degraded; review its bounded health details."
                elif status == "unavailable":
                    warning = "The applied upstream route is unavailable."
                item = _base_item(proxy, route, status=status, applied=True, pending=False,
                                  failure_class=failure_class, tls_status=observed["tls_status"],
                                  http_status=observed["http_status"], last_success=observed["last_success"])
                item["warning"] = warning
            items.append(item)
    return items[:MAX_TOTAL_PROXY_ROUTES]


def _validate_observation(value: Any, *, now: datetime | None) -> dict[str, Any]:
    """Validate the complete bounded helper response and its cache freshness."""
    required = {"schema", "proxies", "generation", "health", "observed_at"}
    if not isinstance(value, dict) or set(value) != required or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("Invalid reverse-proxy observation schema.")
    proxies = value["proxies"]
    health = value["health"]
    generation = value["generation"]
    if not isinstance(proxies, list) or len(proxies) > 256 or not isinstance(health, dict) or len(health) > MAX_TOTAL_PROXY_ROUTES:
        raise ValueError("Reverse-proxy observation exceeds its limit.")
    if sum(len(proxy.get("routes", [])) for proxy in proxies if isinstance(proxy, dict)) > MAX_TOTAL_PROXY_ROUTES:
        raise ValueError("Applied reverse-proxy route limit exceeded.")
    if generation is not None and (not isinstance(generation, str) or not _GENERATION.fullmatch(generation)):
        raise ValueError("Invalid reverse-proxy generation.")
    observed_at = _parse_timestamp(value["observed_at"])
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("Observation comparison time must be timezone-aware.")
    age = current.astimezone(timezone.utc) - observed_at
    if age > MAX_OBSERVATION_AGE or age < -MAX_FUTURE_SKEW:
        raise ValueError("Reverse-proxy observation is stale or from the future.")
    for socket_id, record in health.items():
        if not isinstance(socket_id, str) or not _SOCKET_ID.fullmatch(socket_id):
            raise ValueError("Invalid reverse-proxy health identity.")
        if not isinstance(record, dict) or set(record) != {"status", "last_success", "failure_class", "http_status", "tls_status"}:
            raise ValueError("Invalid reverse-proxy health record.")
        if record["status"] not in _STATUSES:
            raise ValueError("Invalid reverse-proxy health status.")
        failure = record["failure_class"]
        if failure is not None and failure not in _FAILURES:
            raise ValueError("Invalid reverse-proxy failure class.")
        if record["tls_status"] not in _TLS_STATUSES:
            raise ValueError("Invalid reverse-proxy TLS status.")
        status = record["http_status"]
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError("Invalid observed upstream HTTP status.")
        if record["last_success"] is not None:
            _parse_timestamp(record["last_success"])
    return value


def _parse_timestamp(value: Any) -> datetime:
    """Parse one bounded ISO timestamp and require an explicit UTC offset."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid reverse-proxy observation timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid reverse-proxy observation timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Reverse-proxy timestamps must include a UTC offset.")
    return parsed.astimezone(timezone.utc)


def _pending_items(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build desired-state rows while a different applied snapshot is active."""
    return [
        _base_item(proxy, route, status="pending", applied=False, pending=True,
                   failure_class="desired_state_pending", tls_status="not_probed", http_status=None, last_success=None,
                   warning="Saved desired state differs from the applied proxy snapshot; submit global Appliance Apply.")
        for proxy in proxies for route in proxy["routes"]
    ][:MAX_TOTAL_PROXY_ROUTES]


def _unavailable_items(proxies: list[dict[str, Any]], failure: str) -> list[dict[str, Any]]:
    """Build explicit unavailable rows when helper evidence cannot be trusted."""
    return [
        _base_item(proxy, route, status="unavailable", applied=False, pending=True,
                   failure_class=failure, tls_status="not_probed", http_status=None, last_success=None,
                   warning="Runtime observation is unavailable or stale; no request-time probe was performed.")
        for proxy in proxies for route in proxy["routes"]
    ][:MAX_TOTAL_PROXY_ROUTES]


def _base_item(
    proxy: dict[str, Any], route: dict[str, Any], *, status: str, applied: bool, pending: bool,
    failure_class: str, tls_status: str, http_status: int | None, last_success: str | None,
    warning: str = "",
) -> dict[str, Any]:
    """Return the stable, body-free API and browser health projection."""
    return {
        "proxy_id": proxy["id"],
        "route_id": route["id"],
        "proxy_name": proxy["name"],
        "path_prefix": route["path_prefix"],
        "status": status,
        "last_success": last_success,
        "failure_class": failure_class,
        "http_status": http_status,
        "tls_status": tls_status,
        "pending": pending,
        "applied": applied,
        "warning": warning,
    }
