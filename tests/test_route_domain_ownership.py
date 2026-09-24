"""Regress pre-mutation rule admission and connected-route cleanup ownership."""

import ipaddress
import json
import subprocess
from contextlib import nullcontext

import pytest

from atlaso import route_domains as domains
from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("candidate_count,exhausted,incomplete", [
    (249, False, False), (249, False, True), (250, True, True),
])
def test_transition_capacity_reserves_old_and_candidate_sources(monkeypatch, candidate_count, exhausted, incomplete):
    """A large renumber must fit old and candidate IPv4 slots together.

    Args:
        monkeypatch: Isolated native inventory and capacity boundary.
        candidate_count: Candidate address count under test.
        exhausted: Whether the combined source count exceeds capacity.
        incomplete: Whether a live source identity is unavailable.
    """
    old = [str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("10.0.0.1")) + index))
           for index in range(251)]
    candidates = [str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("10.1.0.1")) + index))
                  for index in range(candidate_count)]
    existing = domains.plan_rules({source: 200 for source in old}, set())
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains, "read_native", lambda _command: [])
    monkeypatch.setattr(domains, "owned_rules", lambda _rows, family: existing if family == 4 else set())
    monkeypatch.setattr(domains, "transition_guard_present", lambda *_args: False)
    monkeypatch.setattr(domains, "transition_exemptions_present", lambda *_args: False)
    monkeypatch.setattr(domains, "read_intent", lambda: None)
    monkeypatch.setattr(domains, "source_tables", lambda _intent, _rows: ({source: 200 for source in old}, incomplete))
    if exhausted:
        with pytest.raises(domains.ReconcileError, match="capacity exhausted"):
            domains.preflight_capacity(candidates)
    else:
        domains.preflight_capacity(candidates)


@pytest.mark.parametrize("protected", [False, True])
def test_transition_capacity_failure_precedes_network_mutation(tmp_path, monkeypatch, protected):
    """Both Apply paths reject an overfull transition before writing state.

    Args:
        tmp_path: Disposable candidate Network configuration location.
        monkeypatch: Isolated network mutation boundary.
        protected: Whether the protected handoff path is used.
    """
    helper = load_helper_module()
    config = tmp_path / "candidate.conf"
    config.write_text("# atlaso-network-task: test\n[physical_interfaces]\ninterface=eth0\n"
                      "role=management\nmode=access\nadmin_state=up\nip_cidr=192.0.2.10/24\n")
    monkeypatch.setattr(helper, "_preflight_route_domains", lambda: None)
    monkeypatch.setattr(helper, "_network_config_errors", lambda _path: [])
    monkeypatch.setattr(helper, "_network_transaction_state", lambda: {})
    monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(helper, "_run_with_input", lambda command, payload:
                        subprocess.CompletedProcess(command, 1, "", "capacity exhausted")
                        if json.loads(payload) == ["192.0.2.10"] else pytest.fail("wrong candidate"))
    before = list(tmp_path.iterdir())
    with pytest.raises(ValueError, match="transition source capacity preflight failed"):
        if protected:
            helper._snapshot_management_handoff({"network_config_path": str(config)})
        else:
            with helper._network_apply_transaction(config):
                pytest.fail("candidate mutation entered")
    assert list(tmp_path.iterdir()) == before


@pytest.mark.parametrize("count,over_limit", [(256, False), (257, True)])
def test_source_intent_capacity_is_checked_before_network_mutation(tmp_path, monkeypatch, count, over_limit):
    """Routing-off Network still owns every active local source interface.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture replacing external dependencies.
        count: Number of active interfaces in the candidate configuration.
        over_limit: Whether the candidate exceeds source-rule capacity.
    """
    helper = load_helper_module()
    rows = ["[physical_interfaces]", "interface=eth0", "role=management", "mode=access",
            "admin_state=up", "ipv4_method=static", "ip_cidr=192.0.2.10/24"]
    for index in range(1, count):
        rows.extend(["[physical_interfaces]", f"interface=eth{index}", "role=access",
                     "mode=access", "admin_state=up", f"ip_cidr=198.51.{index // 256}.{index % 256}/24"])
    config = tmp_path / "candidate.conf"
    config.write_text("\n".join(rows) + "\n", encoding="utf-8")
    errors = helper._network_config_errors(config)
    assert any("256 active routing-domain" in error for error in errors) is over_limit
    if over_limit:
        monkeypatch.setattr(helper, "_validate_network_config_path", lambda _path: config)
        monkeypatch.setattr(helper, "_network_apply_transaction", lambda _path: pytest.fail("mutation began"))
        assert helper._handle_network_locked("apply", [str(config)]) == 2
        monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_STATE_PATH", tmp_path / "handoff-state.json")
        monkeypatch.setattr(helper, "_preflight_route_domains", lambda: None)
        with pytest.raises(ValueError, match="256 active routing-domain"):
            helper._snapshot_management_handoff({"network_config_path": str(config)})


@pytest.mark.parametrize("inventory", [
    None,
    {},
    [[]],
    [{"address": "00:11:22:33:44:55"}],
    [{"ifname": "eth0", "addr_info": []}],
    [{"ifname": "eth0", "address": "00:11:22:33:44:55", "addr_info": {}}],
    [{"ifname": "eth0", "address": "00:11:22:33:44:55", "addr_info": [None]}],
    [{"ifname": "eth0", "address": "00:11:22:33:44:55",
      "addr_info": [{"scope": "global"}]}],
])
def test_malformed_address_inventory_raises_recoverable_network_error(tmp_path, monkeypatch, inventory):
    """Malformed successful `ip -j` output uses the Network rollback error type.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture replacing external dependencies.
        inventory: Observed native interface and address inventory.
    """
    helper = load_helper_module()
    config = tmp_path / "network.conf"
    config.write_text("[physical_interfaces]\ninterface=eth0\n", encoding="utf-8")
    intent = tmp_path / "route-domains.json"
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", intent)
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_SERVICE_PATH", tmp_path / "route-domains.service")
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: (
        [{"name": "eth0", "role": "access", "mode": "access", "admin_state": "up"}], [], [],
    ))
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda: {"Name": []})
    monkeypatch.setattr(helper, "_network_observation_command", lambda command:
                        subprocess.CompletedProcess(command, 0, json.dumps(inventory), ""))

    with pytest.raises(ValueError, match="routing-domain .* (inventory|identity) .*malformed"):
        helper._install_route_domain_intent(config)
    assert not intent.exists()


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


@pytest.mark.parametrize("protected", [False, True])
def test_invalid_applied_intent_precedes_network_mutation(tmp_path, monkeypatch, protected):
    """Both Network paths reject corrupt applied intent before creating state.

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

    def run(command):
        """Record the native command for this isolated test.

        Args:
            command: Native command being recorded.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0 if len(commands) == 1 else 1, "", "")

    monkeypatch.setattr(helper, "_run", run)
    before = list(tmp_path.iterdir())
    with pytest.raises(ValueError, match="applied routing-domain intent preflight failed"):
        if protected:
            helper._snapshot_management_handoff({})
        else:
            with helper._network_apply_transaction(config):
                pytest.fail("candidate mutation entered")
    assert list(tmp_path.iterdir()) == before
    assert commands[0] == ["/opt/atlaso/.venv/bin/python", "-I", "-m", "atlaso.route_domains", "--preflight"]
    assert commands[1] == ["/opt/atlaso/.venv/bin/python", "-I", "-c",
                           "from atlaso.route_domains import read_intent\nread_intent()\n"]


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
