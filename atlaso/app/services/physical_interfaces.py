"""Own atomic physical-interface desired-state mutations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy.orm import Session

from atlaso.app.models import AuditEvent, PhysicalInterface
from atlaso.app.operational_logging import log_audit_event
from atlaso.app.services.interface_updates import (
    DependentDnsRefresher,
    PhysicalInterfaceUpdateError,
    update_physical_interface_desired_state,
)


@dataclass(frozen=True)
class _UnsetValue:
    """Distinguish an omitted partial-update field from an explicit null value."""


UNSET: Final = _UnsetValue()


@dataclass(frozen=True)
class PhysicalInterfaceMutation:
    """Represent typed partial desired-state input for one physical interface."""

    role: str | None | _UnsetValue = UNSET
    mode: str | None | _UnsetValue = UNSET
    ipv4_method: str | None | _UnsetValue = UNSET
    ip_cidr: str | None | _UnsetValue = UNSET
    gateway: str | None | _UnsetValue = UNSET
    ipv6_enabled: bool | None | _UnsetValue = UNSET
    ipv6_cidr: str | None | _UnsetValue = UNSET
    ipv6_gateway: str | None | _UnsetValue = UNSET
    mtu: int | None | _UnsetValue = UNSET
    admin_state: str | None | _UnsetValue = UNSET
    access_management_ui_enabled: bool | None | _UnsetValue = UNSET

    @classmethod
    def from_mapping(cls, changes: Mapping[str, Any]) -> PhysicalInterfaceMutation:
        """Build typed mutation input from a transport-owned mapping.

        Args:
            changes: Partial physical-interface fields supplied by a transport.
        """
        supported_fields = {
            "role",
            "mode",
            "ipv4_method",
            "ip_cidr",
            "gateway",
            "ipv6_enabled",
            "ipv6_cidr",
            "ipv6_gateway",
            "mtu",
            "admin_state",
            "access_management_ui_enabled",
        }
        unknown_fields = sorted(set(changes) - supported_fields)
        if unknown_fields:
            raise PhysicalInterfaceUpdateError(
                f"Unsupported physical interface field{'s' if len(unknown_fields) != 1 else ''}: "
                f"{', '.join(unknown_fields)}."
            )
        return cls(**changes)

    def as_changes(self) -> dict[str, Any]:
        """Return only fields explicitly supplied by the transport."""
        changes: dict[str, Any] = {}
        for field_name in (
            "role",
            "mode",
            "ipv4_method",
            "ip_cidr",
            "gateway",
            "ipv6_enabled",
            "ipv6_cidr",
            "ipv6_gateway",
            "mtu",
            "admin_state",
            "access_management_ui_enabled",
        ):
            value = getattr(self, field_name)
            if value is not UNSET:
                changes[field_name] = value
        return changes


@dataclass(frozen=True)
class PhysicalInterfaceMutationAudit:
    """Describe the stable audit contract for a physical-interface transport."""

    actor: str
    action: str
    resource_id: str | None = None


@dataclass(frozen=True)
class PhysicalInterfaceMutationResult:
    """Describe one committed interface, dependent-state, and audit transaction."""

    interface: PhysicalInterface
    changed_dependent_units: tuple[str, ...]
    preserved_dhcp_dns: tuple[str, ...]
    routing_updates: tuple[str, ...]
    routing_warnings: tuple[str, ...]
    audit_event: AuditEvent
    routing_audit_event: AuditEvent | None
    audit_detail: str


def _audit_detail(
    changed_dependent_units: tuple[str, ...],
    preserved_dhcp_dns: tuple[str, ...],
    routing_updates: tuple[str, ...],
    routing_warnings: tuple[str, ...],
) -> str:
    """Render the established value-free physical-interface audit detail.

    Args:
        changed_dependent_units: Dependent units refreshed by reconciliation.
        preserved_dhcp_dns: DHCP-provided DNS values preserved in desired state.
        routing_updates: Default-route preservation actions completed in desired state.
        routing_warnings: Missing-gateway outcomes recorded without inventing route intent.
    """
    detail_parts: list[str] = []
    if changed_dependent_units:
        detail_parts.append(
            "Refreshed dependent desired-state addresses: "
            f"{', '.join(changed_dependent_units)}."
        )
    if preserved_dhcp_dns:
        detail_parts.append(
            "Preserved DHCP-provided DNS in desired state: "
            f"{', '.join(preserved_dhcp_dns)}."
        )
    detail_parts.extend(routing_updates)
    detail_parts.extend(routing_warnings)
    return " ".join(detail_parts)


def mutate_physical_interface_desired_state(
    db: Session,
    interface: PhysicalInterface,
    mutation: PhysicalInterfaceMutation,
    *,
    audit: PhysicalInterfaceMutationAudit,
    dns_refresher: DependentDnsRefresher | None = None,
) -> PhysicalInterfaceMutationResult:
    """Atomically mutate and reconcile one physical interface and its audit row.

    The service changes database desired state only. Appliance Apply remains the exclusive host
    mutation workflow.

    Args:
        db: Active database session owning the transaction.
        interface: Persisted physical interface to update.
        mutation: Typed partial desired-state input.
        audit: Stable transport-specific audit metadata.
        dns_refresher: Optional app-owned DNS reconciliation callback.
    """
    try:
        update_result = update_physical_interface_desired_state(
            db,
            interface,
            mutation.as_changes(),
            dns_refresher=dns_refresher,
            commit=False,
        )
        audit_detail = _audit_detail(
            update_result.dependent_updates,
            update_result.preserved_dhcp_dns,
            update_result.routing_updates,
            update_result.routing_warnings,
        )
        audit_event = AuditEvent(
            actor=audit.actor,
            action=audit.action,
            resource_type="interface",
            resource_id=audit.resource_id or update_result.interface.name,
            success=True,
            detail=audit_detail,
        )
        db.add(audit_event)
        routing_audit_event = None
        if update_result.routing_updates:
            routing_audit_event = AuditEvent(
                actor=audit.actor,
                action="preserve_management_gateway_routes",
                resource_type="route",
                resource_id=update_result.interface.name,
                success=True,
                detail=" ".join(update_result.routing_updates),
            )
            db.add(routing_audit_event)
        db.commit()
        db.refresh(update_result.interface)
        db.refresh(audit_event)
        if routing_audit_event is not None:
            db.refresh(routing_audit_event)
    except Exception:
        db.rollback()
        raise

    log_audit_event(audit_event)
    if routing_audit_event is not None:
        log_audit_event(routing_audit_event)
    return PhysicalInterfaceMutationResult(
        interface=update_result.interface,
        changed_dependent_units=update_result.dependent_updates,
        preserved_dhcp_dns=update_result.preserved_dhcp_dns,
        routing_updates=update_result.routing_updates,
        routing_warnings=update_result.routing_warnings,
        audit_event=audit_event,
        routing_audit_event=routing_audit_event,
        audit_detail=audit_detail,
    )
