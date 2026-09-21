"""Regress pre-mutation rule admission and connected-route cleanup ownership."""

import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("protected", [False, True])
def test_source_conflict_precedes_transaction_artifacts(tmp_path, monkeypatch, protected):
    """A conflicting source window never publishes a rollback marker or backup.

    Args:
        tmp_path: Owned validation directory.
        monkeypatch: Reversible native dependency replacement.
        protected: Select protected management or ordinary Network admission.
    """
    helper = load_helper_module()
    config = tmp_path / "network.conf"
    config.write_text("# atlaso-network-task: test\n")
    monkeypatch.setattr(helper, "_network_transaction_state", lambda: {})
    monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_STATE_PATH", tmp_path / "state.json")
    commands = []
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 1, "", "foreign occupant"))
    before = list(tmp_path.iterdir())
    with pytest.raises(ValueError, match="ownership preflight"):
        if protected:
            helper._snapshot_management_handoff({})
        else:
            with helper._network_apply_transaction(config):
                pytest.fail("candidate mutation entered")
    assert list(tmp_path.iterdir()) == before
    assert commands == [["/opt/atlaso/.venv/bin/python", "-I", "-m", "atlaso.route_domains", "--preflight"]]


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("operation", ["disabled", "removed", "routing-off"])
@pytest.mark.parametrize("metric,gateway", [(0, False), (100, False), (1024, False), (1024, True)])
def test_static_cleanup_keeps_connected_identity(monkeypatch, family, operation, metric, gateway):
    """Retiring static rows cannot remove the preceding connected-route identity.

    Args:
        monkeypatch: Reversible native command replacement.
        family: Static and connected route address family.
        operation: Saved-route or feature transition requesting cleanup.
        metric: Saved static route metric, including native connected aliases.
        gateway: Whether this is a distinct next-hop static route.
    """
    helper = load_helper_module()
    prefix, address, next_hop = (("192.0.2.0/24", "192.0.2.10/24", "192.0.2.1") if family == 4
                                 else ("2001:db8::/64", "2001:db8::10/64", "2001:db8::1"))
    target = {"name": "eth1", "routing_domain": "lab", "ip_cidr" if family == 4 else "ipv6_cidr": address}
    row = {"destination_cidr": prefix, "interface": "eth1", "metric": str(metric),
           "gateway": next_hop if gateway else "", "enabled": "false" if operation == "disabled" else "true"}
    parsed = {"targets": [target], "routes": [] if operation == "removed" else [row],
              "removed_routes": [row] if operation == "removed" else [], "removed_main_defaults": [],
              "wan_policies": [], "routing_rules": [], "nat_rules": [],
              "feature_settings": [{"routing_enabled": "false" if operation == "routing-off" else "true",
                                    "nat_enabled": "false", "wan_simulation_enabled": "false"}]}
    commands = []
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "ip")
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    assert helper._apply_wan_target_routes(parsed) == 0
    assert helper._apply_wan_routes_and_qdiscs(parsed) == 0
    deletions = [command for command in commands if "route" in command and "del" in command]
    alias = not gateway and (metric == 0 or (family == 6 and metric == 1024))
    if alias:
        assert deletions == []
    else:
        expected = ["ip", *(["-6"] if family == 6 else []), "route", "del", prefix,
                    "dev", "eth1", "table", "200", "metric", str(metric)]
        if gateway:
            expected += ["via", next_hop]
        assert deletions == [expected]


def test_unrelated_static_cleanup_is_not_suppressed(monkeypatch):
    """Another destination still uses the established static cleanup path.

    Args:
        monkeypatch: Reversible native command replacement.
    """
    helper = load_helper_module()
    commands = []
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    assert helper._retire_wan_static_route(
        {"destination_cidr": "198.51.100.0/24", "interface": "eth1", "metric": "0"},
        {"eth1": {"ip_cidr": "192.0.2.10/24"}},
    ) == 0
    assert commands == [["ip", "route", "del", "198.51.100.0/24", "dev", "eth1", "table", "200"]]


def test_nonowner_duplicate_prefix_is_not_protected(monkeypatch):
    """An omitted duplicate target route cannot be mistaken for the installed owner.

    Args:
        monkeypatch: Reversible native command replacement.
    """
    helper = load_helper_module()
    commands = []
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    targets = {name: {"name": name, "ip_cidr": address} for name, address in
               [("eth1", "192.0.2.10/24"), ("eth2", "192.0.2.20/24")]}
    assert helper._retire_wan_static_route(
        {"destination_cidr": "192.0.2.0/24", "interface": "eth2", "metric": "0"}, targets,
    ) == 0
    assert commands == [["ip", "route", "del", "192.0.2.0/24", "dev", "eth2", "table", "200"]]
