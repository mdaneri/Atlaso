"""Test atomic physical-interface desired-state mutations."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    AuditEvent,
    DhcpReservation,
    DhcpScope,
    DhcpSettings,
    DnsRecord,
    DnsSettings,
    NtpSettings,
    PhysicalInterface,
    Route,
    VlanInterface,
)
from atlaso.app.services.physical_interfaces import (
    PhysicalInterfaceMutation,
    PhysicalInterfaceMutationAudit,
    PhysicalInterfaceUpdateError,
    mutate_physical_interface_desired_state,
)


def _physical_interface(db, name: str = "eth2") -> PhysicalInterface:
    """Return one seeded physical interface by name.

    Args:
        db: Database session containing the seeded interface rows.
        name: Physical-interface name to select.
    """
    return db.execute(
        select(PhysicalInterface).where(PhysicalInterface.name == name)
    ).scalar_one()


def _mutation_audit(action: str = "test_update_interface") -> PhysicalInterfaceMutationAudit:
    """Return stable audit metadata for direct service tests.

    Args:
        action: Audit action to associate with the test mutation.
    """
    return PhysicalInterfaceMutationAudit(actor="service-test", action=action)


def _static_management_interface(db) -> PhysicalInterface:
    """Return one dual-stack static interface configured as a management listener."""
    interface = _physical_interface(db)
    interface.role = "management"
    interface.mode = "access"
    interface.admin_state = "up"
    interface.oper_state = "up"
    interface.ipv4_method = "static"
    interface.ip_cidr = "192.0.2.10/24"
    interface.gateway = "192.0.2.1"
    interface.ipv6_enabled = True
    interface.ipv6_cidr = "2001:db8:50::10/64"
    interface.ipv6_gateway = "2001:db8:50::1"
    interface.access_management_ui_enabled = False
    db.add(interface)
    return interface


def test_management_to_access_migrates_dual_stack_gateways_atomically(client):
    """Stage both default routes, dependent units, and value-free audit in one commit."""
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = _static_management_interface(db)
        db.commit()

        result = mutate_physical_interface_desired_state(
            db,
            interface,
            PhysicalInterfaceMutation(role="access"),
            audit=_mutation_audit("test_management_gateway_migration"),
        )

        routes = db.execute(select(Route).order_by(Route.destination_cidr)).scalars().all()
        assert {
            (route.destination_cidr, route.gateway, route.interface_name, route.enabled)
            for route in routes
        } == {
            ("0.0.0.0/0", "192.0.2.1", "eth2", True),
            ("::/0", "2001:db8:50::1", "eth2", True),
        }
        assert result.interface.gateway is None
        assert result.interface.ipv6_gateway is None
        assert result.interface.access_management_ui_enabled is True
        assert "Routes & WAN Simulation" in result.changed_dependent_units
        assert "Appliance Settings" in result.changed_dependent_units
        assert "Staged an IPv4 default route" in result.audit_detail
        assert "Staged an IPv6 default route" in result.audit_detail
        assert result.routing_audit_event is not None
        assert result.routing_audit_event.resource_type == "route"
        assert result.routing_audit_event.action == "preserve_management_gateway_routes"


def test_management_to_access_reuses_equivalent_default_without_duplicate(client):
    """Enable and reuse an equivalent family default rather than inserting a second row."""
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = _static_management_interface(db)
        interface.ipv6_gateway = None
        db.add(
            Route(
                destination_cidr="0.0.0.0/0",
                gateway="192.0.2.1",
                interface_name=interface.name,
                metric=25,
                enabled=False,
            )
        )
        db.commit()

        result = mutate_physical_interface_desired_state(
            db,
            interface,
            PhysicalInterfaceMutation(role="access"),
            audit=_mutation_audit("test_management_gateway_reuse"),
        )

        routes = db.execute(select(Route)).scalars().all()
        assert len(routes) == 1
        assert routes[0].enabled is True
        assert routes[0].metric == 25
        assert "Enabled the existing IPv4 default route" in result.audit_detail
        assert "no IPv6 default route was staged" in result.audit_detail


def test_management_to_access_conflicting_default_rolls_back_every_row(client):
    """Reject a conflicting family default without clearing management or persisting audit."""
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = _static_management_interface(db)
        db.add(
            Route(
                destination_cidr="0.0.0.0/0",
                gateway="198.51.100.1",
                interface_name="eth1",
                enabled=True,
            )
        )
        db.commit()

        with pytest.raises(
            PhysicalInterfaceUpdateError,
            match="IPv4 default route already targets eth1",
        ):
            mutate_physical_interface_desired_state(
                db,
                interface,
                PhysicalInterfaceMutation(role="access"),
                audit=_mutation_audit("test_management_gateway_conflict"),
            )

    with SessionLocal() as db:
        restored = _physical_interface(db)
        assert restored.role == "management"
        assert restored.gateway == "192.0.2.1"
        assert restored.ipv6_gateway == "2001:db8:50::1"
        assert db.execute(select(Route)).scalars().one().interface_name == "eth1"
        assert (
            db.execute(
                select(AuditEvent).where(
                    AuditEvent.action == "test_management_gateway_conflict"
                )
            ).scalar_one_or_none()
            is None
        )


def test_management_to_access_missing_gateways_does_not_invent_routes(client):
    """Record the no-gateway outcome while preserving management-listener continuity."""
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = _static_management_interface(db)
        interface.gateway = None
        interface.ipv6_gateway = None
        db.commit()

        result = mutate_physical_interface_desired_state(
            db,
            interface,
            PhysicalInterfaceMutation(role="access"),
            audit=_mutation_audit("test_management_gateway_missing"),
        )

        assert db.execute(select(Route)).scalars().all() == []
        assert len(result.routing_warnings) == 2
        assert result.interface.access_management_ui_enabled is True


def test_mutation_commits_interface_dependencies_and_audit_together(client):
    """Verify typed service output and dependent-unit audit detail share one commit.

    Args:
        client: Application fixture that initializes an isolated seeded database.
    """
    with SessionLocal() as db:
        db.query(DhcpScope).delete()
        interface = _physical_interface(db)
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.1/24"
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.enabled = True
        dns.listen_interface = interface.name
        dns.listen_address = "192.168.50.1"
        ntp = db.execute(select(NtpSettings)).scalar_one()
        ntp.enabled = True
        ntp.listen_interface = interface.name
        ntp.listen_address = "192.168.50.1"
        db.commit()

        result = mutate_physical_interface_desired_state(
            db,
            interface,
            PhysicalInterfaceMutation(ip_cidr="192.168.60.1/24"),
            audit=_mutation_audit(),
        )

        assert result.interface.ip_cidr == "192.168.60.1/24"
        assert "DNS" in result.changed_dependent_units
        assert "NTP / NTS" in result.changed_dependent_units
        assert result.audit_event.id is not None
        assert result.audit_event.detail == result.audit_detail
        assert "DNS" in result.audit_detail
        assert "NTP / NTS" in result.audit_detail

    with SessionLocal() as db:
        assert _physical_interface(db).ip_cidr == "192.168.60.1/24"
        assert db.execute(select(DnsSettings)).scalar_one().listen_address == "192.168.60.1"
        assert db.execute(select(NtpSettings)).scalar_one().listen_address == "192.168.60.1"
        audit = db.execute(
            select(AuditEvent).where(AuditEvent.action == "test_update_interface")
        ).scalar_one()
        assert audit.resource_id == "eth2"
        assert audit.detail == result.audit_detail


def test_mutation_rolls_back_interface_dependents_and_audit_on_reconciliation_failure(
    client,
    monkeypatch,
):
    """Verify reconciliation failure rolls back every staged row and emits no audit.

    Args:
        client: Application fixture that initializes an isolated seeded database.
        monkeypatch: Pytest fixture used to inject a dependent reconciliation failure.
    """
    from atlaso.app.services import interface_updates

    with SessionLocal() as db:
        interface = _physical_interface(db)
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.ip_cidr = "192.168.50.1/24"
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.listen_interface = interface.name
        dns.listen_address = "192.168.50.1"
        db.commit()

        def fail_after_dependent_mutation(session, **_kwargs):
            """Mutate a dependent row, then model a reconciliation failure.

            Args:
                session: Database session used by the reconciliation helper.
                **_kwargs: Additional reconciliation inputs ignored by the test double.
            """
            dependent_dns = session.execute(select(DnsSettings)).scalar_one()
            dependent_dns.listen_address = "192.168.60.1"
            session.add(dependent_dns)
            raise RuntimeError("injected dependent failure")

        monkeypatch.setattr(
            interface_updates,
            "refresh_interface_dependent_addresses",
            fail_after_dependent_mutation,
        )
        with pytest.raises(RuntimeError, match="injected dependent failure"):
            mutate_physical_interface_desired_state(
                db,
                interface,
                PhysicalInterfaceMutation(ip_cidr="192.168.60.1/24"),
                audit=_mutation_audit("test_reconciliation_failure"),
            )

    with SessionLocal() as db:
        assert _physical_interface(db).ip_cidr == "192.168.50.1/24"
        assert db.execute(select(DnsSettings)).scalar_one().listen_address == "192.168.50.1"
        assert db.execute(
            select(AuditEvent).where(AuditEvent.action == "test_reconciliation_failure")
        ).scalar_one_or_none() is None


def test_mutation_rolls_back_reconciled_rows_when_audit_staging_fails(client, monkeypatch):
    """Verify audit construction failure cannot commit interface or dependent state.

    Args:
        client: Application fixture that initializes an isolated seeded database.
        monkeypatch: Pytest fixture used to fail audit staging after reconciliation.
    """
    from atlaso.app.services import physical_interfaces

    with SessionLocal() as db:
        interface = _physical_interface(db)
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.ip_cidr = "192.168.50.1/24"
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.enabled = True
        dns.listen_interface = interface.name
        dns.listen_address = "192.168.50.1"
        db.commit()

        def fail_audit_staging(**_kwargs):
            """Model audit construction failure after reconciliation.

            Args:
                **_kwargs: Audit fields ignored by the test double.
            """
            raise RuntimeError("injected audit staging failure")

        monkeypatch.setattr(physical_interfaces, "AuditEvent", fail_audit_staging)
        with pytest.raises(RuntimeError, match="injected audit staging failure"):
            mutate_physical_interface_desired_state(
                db,
                interface,
                PhysicalInterfaceMutation(ip_cidr="192.168.60.1/24"),
                audit=_mutation_audit("test_audit_failure"),
            )

    with SessionLocal() as db:
        assert _physical_interface(db).ip_cidr == "192.168.50.1/24"
        assert db.execute(select(DnsSettings)).scalar_one().listen_address == "192.168.50.1"
        assert db.execute(
            select(AuditEvent).where(AuditEvent.action == "test_audit_failure")
        ).scalar_one_or_none() is None


def test_mutation_rebases_one_unambiguous_reservation_and_owned_dns_record(client):
    """Verify one changed DHCP scope rebases its reservation and app-owned DNS only.

    Args:
        client: Application fixture that initializes an isolated seeded database.
    """
    mac_address = "02:00:00:00:38:50"
    hostname = "service-reservation.atlaso.internal"
    with SessionLocal() as db:
        db.query(DhcpScope).delete()
        interface = _physical_interface(db)
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.ip_cidr = "192.168.50.1/24"
        db.add_all(
            [
                DhcpScope(
                    name="service-rebase-scope",
                    address_family="ipv4",
                    interface_name=interface.name,
                    site_address="192.168.50.1",
                    prefix_length=24,
                    range_expression="192.168.50.100-192.168.50.120",
                    dns_server="192.168.50.1",
                    enabled=True,
                ),
                DhcpReservation(
                    hostname=hostname,
                    mac_address=mac_address,
                    ip_address="192.168.50.10",
                    description="Operator note remains operator-owned.",
                    enabled=True,
                ),
                DnsRecord(
                    hostname=hostname,
                    record_type="A",
                    address="192.168.50.10",
                    description=f"Created from DHCP reservation for {mac_address}.",
                    enabled=True,
                ),
                DnsRecord(
                    hostname="operator-owned.atlaso.internal",
                    record_type="A",
                    address="192.168.50.10",
                    description="Operator-owned record.",
                    enabled=True,
                ),
            ]
        )
        db.commit()

        result = mutate_physical_interface_desired_state(
            db,
            interface,
            PhysicalInterfaceMutation(ip_cidr="192.168.60.1/24"),
            audit=_mutation_audit("test_dhcp_dns_rebase"),
        )

        assert "DHCP" in result.changed_dependent_units
        assert "DNS" in result.changed_dependent_units

    with SessionLocal() as db:
        reservation = db.execute(
            select(DhcpReservation).where(DhcpReservation.mac_address == mac_address)
        ).scalar_one()
        owned_record = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == hostname)
        ).scalar_one()
        operator_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "operator-owned.atlaso.internal"
            )
        ).scalar_one()
        assert reservation.ip_address == "192.168.60.10"
        assert owned_record.address == "192.168.60.10"
        assert operator_record.address == "192.168.50.10"


def test_mutation_includes_child_vlan_dependencies_and_legacy_dhcp_is_inactive(client):
    """Verify parent loss evaluates child VLANs while real scopes supersede legacy binding.

    Args:
        client: Application fixture that initializes an isolated seeded database.
    """
    with SessionLocal() as db:
        db.query(DhcpScope).delete()
        parent = _physical_interface(db)
        parent.role = "unused"
        parent.mode = "trunk"
        parent.admin_state = "up"
        parent.oper_state = "up"
        child = VlanInterface(
            name="eth2.385",
            parent_interface=parent.name,
            vlan_id=385,
            ip_cidr="192.168.85.1/24",
            mtu=1500,
            role="access",
            enabled=True,
        )
        db.add(child)
        dns = db.execute(select(DnsSettings)).scalar_one()
        dns.enabled = True
        dns.listen_interface = child.name
        dns.listen_address = "192.168.85.1"
        db.add(
            DhcpScope(
                name="real-scope-on-other-interface",
                interface_name="eth1",
                site_address="192.168.40.1",
                prefix_length=24,
                range_expression="192.168.40.100-192.168.40.120",
                dns_server="192.168.40.1",
                enabled=True,
            )
        )
        legacy = db.execute(select(DhcpSettings)).scalar_one()
        legacy.enabled = True
        legacy.interface_name = parent.name
        legacy.site_address = "192.168.50.1"
        legacy.prefix_length = 24
        legacy.range_expression = "192.168.50.100-192.168.50.120"
        legacy.dns_server = "192.168.50.1"
        db.commit()

        with pytest.raises(
            PhysicalInterfaceUpdateError,
            match="Enabled DNS still depends on eth2",
        ):
            mutate_physical_interface_desired_state(
                db,
                parent,
                PhysicalInterfaceMutation(admin_state="down"),
                audit=_mutation_audit("test_child_vlan_dependency"),
            )

    with SessionLocal() as db:
        assert _physical_interface(db).admin_state == "up"
        legacy = db.execute(select(DhcpSettings)).scalar_one()
        assert legacy.interface_name == "eth2"
        assert legacy.site_address == "192.168.50.1"
        assert db.execute(
            select(AuditEvent).where(AuditEvent.action == "test_child_vlan_dependency")
        ).scalar_one_or_none() is None
