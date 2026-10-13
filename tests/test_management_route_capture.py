"""Keep native domain identity when main and domain routes share a key."""

import json
import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


@pytest.fixture(scope="module")
def helper():
    """Load the helper once while each test restores observation boundaries."""
    return load_helper_module()


@pytest.fixture(params=[(4, "192.0.2.0/24", "192.0.2.10", 24, 0),
                       (6, "2001:db8::/64", "2001:db8::10", 64, 1024)])
def inventory(helper, monkeypatch, request):
    """Model main kernel routes and legacy domain boot routes independently.

    Args:
        helper: Loaded helper module.
        monkeypatch: Restore external observation boundaries.
        request: Native family, prefix, assigned source and legacy metric.
    """
    family, destination, source, prefixlen, metric = request.param
    main = {"dst": destination, "table": "main", "protocol": "kernel",
            "scope": "link", "metric": metric, "prefsrc": source}
    domain = {"dst": destination, "protocol": "boot", "scope": "link", "metric": metric}
    native = {"routes": [], "domain": domain, "main": main,
              "mac": "02:00:00:00:00:01", "source": source}

    def observe(command):
        """Return only selector-bound native rows, without mutating the host.

        Args:
            command: Interface, family and table inventory command.
        """
        if "address" in command:
            rows = [{"ifname": "eth0", "address": native["mac"], "addr_info": [
                {"local": native["source"], "prefixlen": prefixlen, "scope": "global"}]}]
        elif f"-{family}" not in command:
            rows = []
        elif command[command.index("table") + 1] == "all":
            rows = native["routes"]
        else:
            rows = [native["domain"]]
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    monkeypatch.setattr(helper, "_network_observation_command", observe)
    monkeypatch.setattr(helper, "_run", lambda *_args: pytest.fail("captured routes must remain untouched"))
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: None)
    return native


@pytest.mark.parametrize("table", [100, 200])
@pytest.mark.parametrize("domain_first", [False, True])
def test_connected_boot_capture_and_repeated_apply(helper, inventory, tmp_path, table, domain_first):
    """Domain identity wins independently of native enumeration order.

    Args:
        helper: Loaded helper.
        inventory: Native main/domain route model.
        tmp_path: Owned marker location.
        table: Previous management listener's routing domain.
        domain_first: Whether the domain row precedes its main-table counterpart.
    """
    domain = {**inventory["domain"], "table": table}
    inventory["routes"] = [domain, inventory["main"]] if domain_first else [inventory["main"], domain]
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": table})
    route = evidence["eth0"]["routes"][0]
    assert route["protocol"] == "boot"
    assert route["preferred_source"] == ""
    assert len(evidence["eth0"]["routes"]) == 1
    for _ in range(2):
        state = {"previous_management_routing": evidence}
        helper._seed_transition_routes(state, [{"name": "eth0", "table": table}], tmp_path / "state.json")
        assert state["transition_seed_routes"] == []
        helper._retire_transition_routes(state, tmp_path / "state.json", require_replacement=True)


@pytest.mark.parametrize("change", [
    {"prefsrc": "192.0.2.99"}, {"gateway": "192.0.2.1"}, {"metric": 20},
    {"protocol": "unknown"}, {"protocol": 99}, {"nhid": 7},
    {"multipath": [{"gateway": "192.0.2.1"}]}, {"from": "192.0.2.0/24"},
    {"dev": "eth1"}, {"table": 100}, {"type": "blackhole"},
])
def test_connected_boot_live_identity_change_is_rejected(helper, inventory, monkeypatch, tmp_path, change):
    """Capture priority never relaxes boot source, path or owner checks.

    Args:
        helper: Loaded helper.
        inventory: Native main/domain route model.
        monkeypatch: Reject journaling before live identity admission.
        tmp_path: Owned marker location.
        change: Live route identity that differs from captured domain evidence.
    """
    inventory["routes"] = [{**inventory["domain"], "table": 200}, inventory["main"]]
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 200})
    inventory["domain"] = {**inventory["domain"], **change}
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: pytest.fail("must not journal"))
    with pytest.raises(ValueError):
        helper._seed_transition_routes({"previous_management_routing": evidence},
                                       [{"name": "eth0", "table": 200}], tmp_path / "state.json")


@pytest.mark.parametrize("field", ["mac", "source"])
def test_connected_capture_rechecks_link_and_assigned_source(helper, inventory, monkeypatch, tmp_path, field):
    """A captured domain route cannot authorize a replaced NIC or old source.

    Args:
        helper: Loaded helper.
        inventory: Native main/domain route model.
        monkeypatch: Reject journaling before identity admission.
        tmp_path: Owned marker location.
        field: Assigned address or physical link identity being changed.
    """
    inventory["routes"] = [{**inventory["domain"], "table": 200}]
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 200})
    inventory[field] = ("02:00:00:00:00:02" if field == "mac"
                        else "2001:db8::11" if ":" in inventory["source"] else "192.0.2.11")
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: pytest.fail("must not journal"))
    with pytest.raises(ValueError, match="changed before transition"):
        helper._seed_transition_routes({"previous_management_routing": evidence},
                                       [{"name": "eth0", "table": 200}], tmp_path / "state.json")


def test_main_only_upgrade_retains_source_and_rolls_back_seed(helper, inventory, monkeypatch, tmp_path):
    """An older main-only baseline still seeds and retires only its journaled route.

    Args:
        helper: Loaded helper.
        inventory: Native main/domain route model.
        monkeypatch: Isolate route commands and live domain observation.
        tmp_path: Owned marker location.
    """
    inventory["routes"] = [inventory["main"]]
    evidence = helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 200})
    route = evidence["eth0"]["routes"][0]
    assert route["preferred_source"] == inventory["main"]["prefsrc"]
    observed = []
    commands = []
    monkeypatch.setattr(helper, "_transition_route_rows", lambda *_args: observed)
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    state = {"previous_management_routing": evidence}
    marker = tmp_path / "state.json"
    helper._seed_transition_routes(state, [{"name": "eth0", "table": 200}], marker)
    seeded = state["transition_seed_routes"][0]
    observed.append({"dst": route["destination"], "dev": "eth0", "table": 200,
                     "protocol": "kernel", "metric": seeded["seed_metric"]})
    helper._retire_transition_routes(state, marker, require_replacement=False)
    assert [command[3] for command in commands] == ["add", "del"]
    assert commands[0][4:] == commands[1][4:]
    assert state["transition_seed_routes"] == []


def test_conflicting_domain_copies_fail_before_seed(helper, inventory):
    """An ambiguous native domain key cannot be resolved by enumeration order.

    Args:
        helper: Loaded helper.
        inventory: Native main/domain route model.
    """
    domain = {**inventory["domain"], "table": 200}
    inventory["routes"] = [domain, {**domain, "prefsrc": inventory["main"]["prefsrc"]}]
    with pytest.raises(ValueError, match="identity is ambiguous"):
        helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 200})
