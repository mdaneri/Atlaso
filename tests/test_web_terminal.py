"""Test web terminal behavior."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from atlaso.app import web_terminal
from atlaso.app.models import ApplianceSettings, PhysicalInterface, VlanInterface
from atlaso.app.services.appliance_settings import (
    normalized_web_terminal_interfaces,
    validate_appliance_settings,
    web_terminal_addresses,
    web_terminal_interface_options,
    web_terminal_listener_interfaces,
)


def test_web_terminal_interface_options_require_addressed_non_trunk_interfaces():
    """Verify that web terminal interface options require addressed non trunk interfaces."""
    interfaces = [
        PhysicalInterface(
            name="eth0",
            role="management",
            mode="access",
            admin_state="up",
            oper_state="up",
            ip_cidr="192.168.49.1/24",
        ),
        PhysicalInterface(
            name="eth1",
            role="route",
            mode="trunk",
            admin_state="up",
            oper_state="up",
            ip_cidr="192.168.50.1/24",
        ),
        PhysicalInterface(
            name="eth2",
            role="access",
            mode="access",
            admin_state="up",
            oper_state="up",
            ip_cidr="192.168.87.32/24",
        ),
        PhysicalInterface(
            name="eth3",
            role="management",
            mode="access",
            admin_state="up",
            oper_state="up",
            ip_cidr="192.168.88.32/24",
        ),
    ]
    vlans = [
        VlanInterface(
            name="eth1.50",
            parent_interface="eth1",
            vlan_id=50,
            role="access",
            enabled=True,
            ip_cidr="192.168.50.1/24",
        ),
        VlanInterface(
            name="eth1.60",
            parent_interface="eth1",
            vlan_id=60,
            role="management",
            enabled=True,
            ip_cidr="192.168.60.1/24",
        ),
    ]

    options = web_terminal_interface_options(interfaces, vlans)

    assert [option["name"] for option in options] == ["eth0", "eth2", "eth3", "eth1.50", "eth1.60"]
    assert web_terminal_listener_interfaces(
        ["eth0", "eth2", "eth3", "eth1.50", "eth1.60"],
        options,
    ) == ["eth0", "eth2", "eth1.50"]
    assert web_terminal_addresses(["eth0", "eth2", "eth1.50"], options) == [
        "192.168.49.1",
        "192.168.87.32",
        "192.168.50.1",
    ]
    settings = ApplianceSettings(
        fqdn="core.atlaso.internal",
        management_https_enabled=True,
        web_terminal_enabled=True,
        web_terminal_interfaces_json='["eth0", "eth1.60"]',
        config_path="/var/lib/atlaso/apply/appliance-settings/atlaso-settings.json",
    )
    errors, _warnings = validate_appliance_settings(
        settings,
        local_dns_enabled=False,
        management_interface={"name": "eth0", "ip": "192.168.49.1", "ip_cidr": "192.168.49.1/24"},
        ca_enabled=True,
        management_https_cert_available=True,
        web_terminal_options=options,
    )
    assert "Additional Web terminal interfaces cannot use the management role: eth1.60." in errors


def test_web_terminal_validation_forces_management_and_rejects_unavailable_selection():
    """Verify that web terminal validation forces management and rejects unavailable selection."""
    settings = ApplianceSettings(
        fqdn="core.atlaso.internal",
        management_https_enabled=True,
        web_terminal_enabled=True,
        web_terminal_interfaces_json='["eth2", "eth9"]',
        config_path="/var/lib/atlaso/apply/appliance-settings/atlaso-settings.json",
    )
    management = {"name": "eth0", "ip": "192.168.49.1", "ip_cidr": "192.168.49.1/24"}
    options = [
        {"name": "eth0", "addresses": ["192.168.49.1"]},
        {"name": "eth2", "addresses": ["192.168.87.32"]},
    ]

    selected = normalized_web_terminal_interfaces(settings, management)
    errors, _warnings = validate_appliance_settings(
        settings,
        local_dns_enabled=False,
        management_interface=management,
        ca_enabled=True,
        management_https_cert_available=True,
        web_terminal_options=options,
    )

    assert selected == ["eth0", "eth2", "eth9"]
    assert "Web terminal interfaces are unavailable or have no address: eth9." in errors


def test_terminal_ticket_is_one_use_and_bound_to_session_identity():
    """Verify that terminal ticket is one use and bound to session identity."""
    raw = "one-use-ticket"
    digest = web_terminal._ticket_digest(raw)
    web_terminal._tickets[digest] = web_terminal.TerminalTicket(
        user_id=7,
        username="admin",
        csrf_token="csrf",
        browser_session_id="browser_session_1234",
        takeover=False,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
    )

    assert web_terminal._consume_ticket(raw, 7, "admin", "csrf") is not None
    assert web_terminal._consume_ticket(raw, 7, "admin", "csrf") is None


def test_terminal_replay_removes_historic_cursor_position_queries():
    """Verify that terminal replay removes historic cursor position queries."""
    output = bytearray(b"prompt\x1b[6n middle\x1b[?6n end")

    assert web_terminal._terminal_replay_output(output) == b"prompt middle end"


def test_selected_listener_header_is_accepted_only_from_loopback_proxy(monkeypatch):
    """Verify that selected listener header is accepted only from loopback proxy.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    monkeypatch.setattr(web_terminal, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    headers = {"x-atlaso-listener-address": "192.168.87.32"}

    assert web_terminal._request_uses_selected_listener(headers, "127.0.0.1", ["192.168.87.32"]) is True
    assert web_terminal._request_uses_selected_listener(headers, "10.0.0.10", ["192.168.87.32"]) is False
    assert web_terminal._request_uses_selected_listener(headers, "127.0.0.1", ["192.168.88.32"]) is False
