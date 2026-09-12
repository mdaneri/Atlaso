"""Test management-plane Port Forwarding forms and authorization boundaries."""

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import PhysicalInterface, PortForward, Role, User
from atlaso.app.security import roles_to_json
from tests.routers.ui.helpers import login
from tests.services.test_port_forwarding import payload


@pytest.mark.parametrize(("routing", "enabled", "invalid", "expected"), [
    (True, True, False, "valid"), (True, True, True, "needs attention"),
    (False, True, False, "suspended"), (True, False, False, "disabled"),
])
def test_forward_only_publishing_status(client, routing, enabled, invalid, expected):
    """Report destination publication even when source NAT is disabled.

    Args:
        client: Isolated application database fixture.
        routing: Global forwarding intent.
        enabled: Destination translation intent.
        invalid: Whether its listener conflicts with a reserved service.
        expected: Combined Traffic Publishing summary.
    """
    from atlaso.app import ui

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0],
                                    enabled=enabled, external_port_start=22 if invalid else 12000,
                                    external_port_end=24 if invalid else 12002)))
        ui.set_setting_value(db, "routes_wan.routing_enabled", str(routing).lower())
        ui.set_setting_value(db, "traffic_publishing.nat_enabled", "false")
        db.commit()
        assert ui.traffic_publishing_context(db)["nat_status"] == expected


def test_service_only_apply_cannot_redirect_an_enabled_port_forward(client, monkeypatch):
    """A later service listener change must validate the existing DNAT boundary.

    Args:
        client: Isolated management application.
        monkeypatch: Forbid host publication when desired listeners conflict.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import SystemAdapter
    from atlaso.app.models import KmsSettings

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])))
        kms = db.scalar(select(KmsSettings))
        kms.enabled = True
        kms.listen_interface = "eth2"
        kms.port = 12001
        ui.set_setting_value(db, "routes_wan.routing_enabled", "true")
        db.commit()
        units = ui.appliance_apply_units(db)
        nat = next(unit for unit in units if unit["id"] == "nat")
        assert any("listener" in error.lower() for error in nat["validation_errors"])

    def forbidden(*args, **kwargs):
        """Reject any mutation after invalid desired state.

        Args:
            *args: Unexpected helper arguments.
            **kwargs: Unexpected helper options.
        """
        raise AssertionError("Conflicting listener reached the host")

    monkeypatch.setattr(SystemAdapter, "_helper_result", forbidden)
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "kms"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 422


def test_port_forward_wizard_and_forms_preserve_desired_only_boundary(client, monkeypatch):
    """Browser CRUD requires CSRF and never runs the host helper.

    Args:
        client: Isolated authenticated management client.
        monkeypatch: Forbid privileged enforcement during browser mutations.
    """
    from atlaso.app.adapters.system import SystemAdapter

    login(client)
    page = client.get("/ui/management/traffic-publishing")
    assert page.status_code == 200
    assert 'id="port-forward-table"' in page.text
    assert 'id="port-forward-fallback"' in page.text
    assert 'data-port-forward-wizard' in page.text
    assert 'data-atlaso-wizard-step="listener"' in page.text
    assert 'name="acknowledge_source_loss"' in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        assert interface is not None
        values = payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])
    form = {key: "on" if value is True else "off" if value is False else str(value) for key, value in values.items()}
    form["csrf"] = csrf
    root = "/ui/management/traffic-publishing/port-forwards"

    def forbidden(*args, **kwargs):
        """Reject host-helper calls from desired-state transports.

        Args:
            *args: Unexpected helper arguments.
            **kwargs: Unexpected helper options.
        """
        raise AssertionError("Desired-state form invoked the host")

    monkeypatch.setattr(SystemAdapter, "_helper_result", forbidden)
    assert client.post(root, data={**form, "csrf": "invalid"}).status_code == 403
    response = client.post(root, data=form, headers={"Accept": "application/json"})
    assert response.status_code == 200, response.text
    row = response.json()["rows"][0]
    assert row["enabled"] is True
    assert "[port_forwards]" in response.json()["config_preview"]
    response = client.post(f"{root}/{row['id']}/enabled", data={"csrf": csrf, "enabled": "off"}, headers={"Accept": "application/json"})
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        saved = db.get(PortForward, row["id"])
        assert not saved.enabled and saved.target_port_start == 13000
    response = client.post(f"{root}/{row['id']}/edit", data={**form, "target_port_end": "13003"}, headers={"Accept": "application/json"})
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.get(PortForward, row["id"]).target_port_end == 13002
    response = client.post(f"{root}/{row['id']}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/management/traffic-publishing#port-forward-panel"


def test_read_only_port_forward_page_has_no_mutation_wizard(client):
    """A Firewall reader keeps fallback data and observations without edit controls.

    Args:
        client: Isolated management client.
    """
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        admin.role = Role.VIEWER.value
        admin.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()
    login(client)
    page = client.get("/ui/management/traffic-publishing")
    assert page.status_code == 200
    assert 'id="port-forward-table"' in page.text
    assert 'data-port-forward-wizard' not in page.text
    assert 'data-port-forward-refresh' in page.text
    assert client.post("/ui/management/traffic-publishing/port-forwards", data={"csrf": "invalid"}).status_code == 403
