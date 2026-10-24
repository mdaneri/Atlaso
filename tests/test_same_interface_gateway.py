"""Exercise reviewed same-interface gateway validation and projection."""

from functools import lru_cache
from pathlib import Path

import pytest

from atlaso.app.models import Route, RoutingRule
from atlaso.app.services.routes_wan import (
    RoutesWanSettings,
    render_wan_config,
    validate_wan_state,
)
from tests.test_appliance_helper import load_helper_module


def _gateway_rule(*, interface: str = "eth2", policy: str = "allow", family: int = 4) -> RoutingRule:
    return RoutingRule(
        name="Reviewed same-interface gateway",
        enabled=True,
        source_interface=interface,
        destination_interface=interface,
        policy=policy,
        ip_family=family,
        priority=100,
    )


def _lab_target(*, family: int = 4) -> dict[str, str]:
    return {
        "name": "eth2",
        "kind": "physical",
        "role": "access",
        "routing_domain": "lab",
        "route_allowed": "true",
        "nat_allowed": "true",
        "ip_cidr": "192.0.2.2/24" if family == 4 else "",
        "ipv6_cidr": "2001:db8:2::2/64" if family == 6 else "",
        "gateway": "192.0.2.1" if family == 4 else "",
        "ipv6_gateway": "2001:db8:2::1" if family == 6 else "",
    }


@pytest.mark.parametrize("family", [4, 6])
def test_wan_state_accepts_explicit_same_interface_permission_for_configured_lab_family(family):
    """Accept an explicit self-pair when its selected lab interface has that family."""
    interface = "eth2"
    target_cidr = "192.0.2.2/24" if family == 4 else "2001:db8:2::2/64"
    errors = validate_wan_state(
        routes=[],
        policies=[],
        target_names={interface},
        routing_rules=[_gateway_rule(family=family)],
        routing_target_names={interface},
        route_target_cidrs={interface: (target_cidr,)},
        management_target_names={"eth0"},
    )

    assert errors == []


@pytest.mark.parametrize(
    ("rule", "routing_targets", "cidrs", "management_targets", "error_fragment"),
    [
        (
            _gateway_rule(interface="eth0"),
            {"eth2"},
            {"eth2": ("192.0.2.2/24",)},
            {"eth0"},
            "source",
        ),
        (
            _gateway_rule(interface="missing0"),
            {"eth2"},
            {"eth2": ("192.0.2.2/24",)},
            {"eth0"},
            "source",
        ),
        (
            _gateway_rule(family=6),
            {"eth2"},
            {"eth2": ("192.0.2.2/24",)},
            {"eth0"},
            "common configured IP family",
        ),
    ],
)
def test_wan_state_rejects_ineligible_same_interface_permission(
    rule, routing_targets, cidrs, management_targets, error_fragment
):
    """Do not admit management, missing, or wrong-family same-interface scopes."""
    errors = validate_wan_state(
        routes=[],
        policies=[],
        target_names=set(routing_targets),
        routing_rules=[rule],
        routing_target_names=routing_targets,
        route_target_cidrs=cidrs,
        management_target_names=management_targets,
    )

    assert any(error_fragment in error for error in errors), errors


def _rendered_gateway_config(*, family: int = 4, routing_enabled: bool = True) -> str:
    target = _lab_target(family=family)
    route = Route(
        destination_cidr="203.0.113.0/24" if family == 4 else "2001:db8:99::/64",
        gateway="192.0.2.1" if family == 4 else "2001:db8:2::1",
        interface_name="eth2",
        enabled=True,
        metric=100,
    )
    return render_wan_config(
        routes=[route],
        targets=[target],
        routing_rules=[_gateway_rule(family=family)],
        settings=RoutesWanSettings(routing_enabled, False, False),
    )


def _helper_errors(config_text: str) -> list[str]:
    helper = _helper_module()
    parsed = helper._parse_wan_config(Path("unused.conf"), content=config_text)
    return helper._wan_config_errors(Path("unused.conf"), parsed=parsed)


@lru_cache(maxsize=1)
def _helper_module():
    return load_helper_module()


@pytest.mark.parametrize("family", [4, 6])
def test_wan_helper_accepts_same_interface_permission_with_routed_destination(family):
    """Validate that a selected lab target can both receive and emit routed traffic."""
    assert _helper_errors(_rendered_gateway_config(family=family)) == []


def test_wan_helper_rejects_management_self_permission():
    """A self-pair cannot turn a dedicated-management target into a gateway."""
    config = _rendered_gateway_config()
    config = config.replace("target=eth2", "target=eth0").replace("role=access", "role=management")
    config = config.replace("routing_domain=lab", "routing_domain=management")
    config = config.replace("route_allowed=true", "route_allowed=false")
    config = config.replace("interface=eth2", "interface=eth0")
    errors = _helper_errors(config)

    assert any("management routing domain" in error for error in errors), errors


def test_wan_helper_rejects_same_interface_permission_without_selected_family():
    """A v6 permission cannot be emitted by an IPv4-only target."""
    config = _rendered_gateway_config()
    config = config.replace("ip_family=4", "ip_family=6")

    errors = _helper_errors(config)

    assert any("no common selected IP family" in error for error in errors), errors


def test_routing_off_retains_gateway_intent_and_disables_forwarding():
    """Turning Routing off keeps permission data while its host forwarding stays off."""
    config = _rendered_gateway_config(routing_enabled=False)

    assert "routing_enabled=false" in config
    assert "source_interface=eth2" in config
    assert "destination_interface=eth2" in config
    assert "policy=allow" in config
    assert "ip_family=4" in config
    assert "sysctl -w net.ipv4.ip_forward=0" in config
    assert "sysctl -w net.ipv6.conf.all.forwarding=0" in config
    assert _helper_errors(config) == []
