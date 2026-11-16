"""Separate assigned static-address readiness from dynamic carrier acquisition."""

from ipaddress import ip_interface
from pathlib import Path

import pytest

from tests.test_appliance_helper import load_helper_module


def readiness_fixture(monkeypatch, kind, *, up=True, carrier=False, state="assigned"):
    """Bind exact parsed intent and complete native observations without host commands.

    Args:
        monkeypatch: Replace only network observation/configuration seams.
        kind: Static IPv4/IPv6 or native DHCPv4/IPv4LL/automatic IPv6 acquisition.
        up: Observed administrative state.
        carrier: Observed physical carrier state.
        state: Assigned, tentative, conflict, incomplete or unconfigured observation.
    """
    helper = load_helper_module()
    ipv6 = kind in {"static6", "auto6"}
    cidr = "2001:db8::50/64" if ipv6 else "169.254.20.10/16" if kind == "ipv4ll" else "192.0.2.50/24"
    static = kind.startswith("static")
    row = {"name": "eth2", "admin_state": "up", "ipv4_method": "static" if static or ipv6 else "dhcp",
           "ipv6_enabled": "true" if ipv6 else "false", "ipv4_link_local_fallback_enabled": "true"}
    if static:
        row["ipv6_cidr" if ipv6 else "ip_cidr"] = cidr
    record = {"address": str(ip_interface(cidr).ip), "cidr": cidr,
              "source": "static" if static else "IPv4LL" if kind == "ipv4ll" else "NDisc" if ipv6 else "DHCPv4",
              "state": state if state in {"tentative", "conflict"} else "assigned"}
    observation = {"complete": state != "incomplete", "conflicts": [], "links": [
        {"name": "eth2", "configured": state != "unconfigured", "up": up, "carrier": carrier, "addresses": [record]},
    ]}
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([row], [], []))
    monkeypatch.setattr(helper, "_network_address_observation", lambda: observation)
    monkeypatch.setattr(helper, "_retain_network_conflicts", lambda *_args: None)
    return helper, observation


@pytest.mark.parametrize("kind", ["static4", "static6", "dhcp4", "ipv4ll", "auto6"])
@pytest.mark.parametrize("up,carrier", [(True, True), (True, False), (False, True), (False, False)])
def test_carrier_is_required_only_for_dynamic_acquisition(monkeypatch, kind, up, carrier):
    """Disconnected static lab addresses retain the pre-feature readiness contract.

    Args:
        monkeypatch: Supply bounded native observations.
        kind: Address intent and native acquisition source.
        up: Native administrative flag.
        carrier: Native carrier flag.
    """
    helper, observation = readiness_fixture(monkeypatch, kind, up=up, carrier=carrier)
    if kind.startswith("static") or up and carrier:
        assert helper._wait_network_addresses(Path("in-memory-intent"), attempts=1) == observation
    else:
        with pytest.raises(ValueError, match="Unable to verify candidate addresses"):
            helper._wait_network_addresses(Path("in-memory-intent"), attempts=1)


@pytest.mark.parametrize("kind", ["static4", "static6"])
@pytest.mark.parametrize("state", ["assigned", "tentative", "conflict", "incomplete", "unconfigured"])
def test_static_carrier_compatibility_preserves_readiness_guards(monkeypatch, kind, state):
    """Static compatibility cannot accept tentative, conflicted or incomplete native state.

    Args:
        monkeypatch: Supply bounded native observations.
        kind: Static IPv4 or static IPv6 intent.
        state: Address or observation prerequisite under test.
    """
    helper, observation = readiness_fixture(monkeypatch, kind, state=state)
    if state == "assigned":
        assert helper._wait_network_addresses(Path("in-memory-intent"), attempts=1) == observation
    else:
        with pytest.raises(ValueError, match="IP conflict" if state == "conflict" else "Unable to verify"):
            helper._wait_network_addresses(Path("in-memory-intent"), attempts=1)
