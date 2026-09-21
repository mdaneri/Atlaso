"""Verify journalable legacy rule migration without applying pending WAN state."""

import copy
import json
import subprocess

import pytest

from tests.test_appliance_helper import (
    load_helper_module,
    network_config_text,
    wan_config_text,
)


@pytest.fixture(scope="module")
def helper():
    """Load one helper module; individual test monkeypatches remain reversible."""
    return load_helper_module()


def native_rules(helper, monkeypatch, rows4, rows6=None):
    """Supply both fixed native rule observations and capture mutations.

    Args:
        helper: Privileged helper module under test.
        monkeypatch: Reversible dependency replacement.
        rows4: IPv4 native rule inventory.
        rows6: Optional IPv6 native rule inventory.
    """
    commands = []

    def observe(command):
        """Return the corresponding numeric native inventory."""
        assert command in [["ip", "-N", "-j", "-details", f"-{family}", "rule", "show"]
                           for family in (4, 6)]
        rows = rows4 if "-4" in command else rows6 or []
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    monkeypatch.setattr(helper, "_network_observation_command", observe)
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    return commands


def test_snapshot_and_restore_preserve_dual_stack_rules(helper, monkeypatch):
    """Capture exact prefixes and ingress rules while ignoring unrelated priorities."""
    original4 = [{"priority": 1000, "src": "192.0.2.0/24", "table": 100, "protocol": 3}]
    original6 = [{"priority": 2001, "src": "2001:db8::/64", "table": 200, "protocol": "boot"}]
    native_rules(helper, monkeypatch, [{"priority": 32766, "src": "all", "table": 254}, *original4], original6)
    snapshot = helper._snapshot_route_domain_rules()
    assert [(row["family"], row["source"], row["table"]) for row in snapshot] == [
        (4, "192.0.2.0/24", 100), (6, "2001:db8::/64", 200),
    ]
    commands = native_rules(helper, monkeypatch, [{"priority": 2000, "src": "all", "table": 200, "iif": "eth1"}])
    helper._restore_route_domain_rules(snapshot)
    assert commands == [
        ["ip", "-4", "rule", "del", "iif", "eth1", "table", "200", "priority", "2000", "protocol", "0"],
        ["ip", "-4", "rule", "add", "from", "192.0.2.0/24", "table", "100", "priority", "1000", "protocol", "3"],
        ["ip", "-6", "rule", "add", "from", "2001:db8::/64", "table", "200", "priority", "2001", "protocol", "3"],
    ]


@pytest.mark.parametrize("override", [
    {"fwmark": "0x1"}, {"table": 254}, {"protocol": 99}, {"protocol": True}, {"protocol": 2},
    {"action": "blackhole"}, {"src": "all"}, {"src": "2001:db8::/64"},
    {"iif": "eth0"}, {"src": "192.0.2.3/24"}, {"srclen": True},
    {"uidrange": {"start": 0, "end": 1000}},
])
def test_foreign_window_occupants_prevent_any_mutation(helper, monkeypatch, override):
    """Unexpected rule shapes must never be deleted or replayed.

    Args:
        helper: Loaded helper module.
        monkeypatch: Reversible dependency replacement.
        override: One independently inadmissible native rule field.
    """
    row = {"priority": 1000, "src": "192.0.2.0/24", "table": 100, **override}
    commands = native_rules(helper, monkeypatch, [row])
    with pytest.raises(ValueError):
        helper._restore_route_domain_rules([])
    assert commands == []


def test_duplicate_priorities_and_corrupt_journal_fail_before_mutation(helper, monkeypatch):
    """Ambiguous ownership and journal paths cannot broaden rule mutation."""
    row = {"priority": 1000, "src": "192.0.2.0/24", "table": 100}
    commands = native_rules(helper, monkeypatch, [row, row])
    with pytest.raises(ValueError, match="ambiguous"):
        helper._snapshot_route_domain_rules()
    assert commands == []
    native_rules(helper, monkeypatch, [row])
    snapshot = helper._snapshot_route_domain_rules()
    snapshot[0]["priority"] = 32766
    with pytest.raises(ValueError, match="outside owned"):
        helper._restore_route_domain_rules(snapshot)


@pytest.mark.parametrize("applied_forwarding", [False, True, None])
def test_migration_reads_only_applied_wan_and_network_domains(helper, monkeypatch, tmp_path, applied_forwarding):
    """Network Apply does not consume pending WAN edits or change WAN artifacts.

    Args:
        helper: Loaded helper module.
        monkeypatch: Reversible dependency replacement.
        tmp_path: Task-owned isolated configuration root.
        applied_forwarding: Applied forwarding choice, or absent WAN baseline.
    """
    network = tmp_path / "network.conf"
    network.write_text(network_config_text(), encoding="utf-8")
    wan = tmp_path / "applied-wan.conf"
    if applied_forwarding is not None:
        wan.write_text(f"[feature_settings]\nrouting_enabled={str(applied_forwarding).lower()}\n" + wan_config_text(), encoding="utf-8")
    pending = tmp_path / "pending-wan.conf"
    pending.write_text("routing_enabled=true\npolicy=unapplied\nlatency_ms=9000\n", encoding="utf-8")
    before = {path: path.read_bytes() for path in (wan, pending) if path.exists()}
    monkeypatch.setattr(helper, "WAN_RUNTIME_CONFIG_PATH", wan)
    commands = native_rules(helper, monkeypatch, [{"priority": 1000, "src": "192.168.49.0/24", "table": 100}])
    helper._apply_route_domain_ingress(network)
    assert commands[0][3] == "del"
    additions = [command for command in commands if command[3] == "add"]
    assert len(additions) == (2 if applied_forwarding else 0)
    if additions:
        assert all(command[4:8] == ["iif", "eth2.20", "table", "200"] for command in additions)
        assert all(command[-2:] == ["protocol", "2"] for command in additions)
    assert all(command[:1] == ["ip"] and "rule" in command for command in commands)
    assert {path: path.read_bytes() for path in before} == before


def test_applied_domain_projection_excludes_held_management(helper, monkeypatch, tmp_path):
    """An old management listener keeps its domain until the retirement phase."""
    path = tmp_path / "route-domains.json"
    intent = {"schema": 1, "interfaces": [
        {"name": "eth0", "table": 200, "mac": "00:11:22:33:44:00"},
        {"name": "eth1", "table": 100, "mac": "00:11:22:33:44:01"},
        {"name": "eth2", "table": 200, "mac": "00:11:22:33:44:02"},
    ]}
    path.write_text(json.dumps(intent), encoding="utf-8")
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", path)
    assert helper._route_domain_ingress_interfaces(held_management_interfaces={"eth0"}) == ["eth2"]
    assert helper._route_domain_ingress_interfaces() == ["eth0", "eth2"]
    intent["held_addresses"] = [{"name": "eth0", "table": 100, "mac": "00:11:22:33:44:00", "address": "192.0.2.1"}]
    path.write_text(json.dumps(intent), encoding="utf-8")
    assert helper._route_domain_ingress_interfaces() == ["eth2"]


def test_invalid_applied_wan_fails_before_rule_mutation(helper, monkeypatch, tmp_path):
    """A corrupt applied forwarding policy cannot silently authorize migration."""
    network = tmp_path / "network.conf"
    network.write_text(network_config_text(), encoding="utf-8")
    wan = tmp_path / "wan.conf"
    wan.write_text("[feature_settings]\nrouting_enabled=maybe\n" + wan_config_text(), encoding="utf-8")
    monkeypatch.setattr(helper, "WAN_RUNTIME_CONFIG_PATH", wan)
    commands = native_rules(helper, monkeypatch, [])
    with pytest.raises(ValueError, match="applied WAN configuration is invalid"):
        helper._apply_route_domain_ingress(network)
    assert commands == []


def test_partial_failure_can_restore_original_journal(helper, monkeypatch):
    """An interrupted mutation propagates failure and admits exact subsequent recovery."""
    original = [{"priority": 1000, "src": "192.0.2.0/24", "table": 100}]
    native_rules(helper, monkeypatch, original)
    snapshot = helper._snapshot_route_domain_rules()
    desired = copy.deepcopy(snapshot)
    desired[0].update(priority=2000, table=200, source="0.0.0.0/0", incoming_interface="eth1")
    commands = []

    def fail_second(command):
        """Fail after deletion so the journal is necessary for recovery."""
        commands.append(command)
        return subprocess.CompletedProcess(command, 1 if len(commands) == 2 else 0, "", "")

    monkeypatch.setattr(helper, "_run", fail_second)
    with pytest.raises(ValueError, match="migration failed"):
        helper._restore_route_domain_rules(desired)
    commands = native_rules(helper, monkeypatch, [])
    helper._restore_route_domain_rules(snapshot)
    assert len(commands) == 1
    assert commands[0][3:6] == ["add", "from", "192.0.2.0/24"]


def test_unchanged_snapshot_does_not_churn_rules(helper, monkeypatch):
    """Repeated reconciliation preserves already matching rule state."""
    commands = native_rules(helper, monkeypatch, [{"priority": 1000, "src": "192.0.2.0/24", "table": 100}])
    snapshot = helper._snapshot_route_domain_rules()
    helper._restore_route_domain_rules(snapshot)
    assert commands == []


def test_photon_numeric_strings_and_unspecified_protocol_round_trip(helper, monkeypatch):
    """Preserve Photon 257's actual numeric-string table and protocol-zero records."""
    native_rules(helper, monkeypatch, [
        {"priority": 0, "src": "all", "table": "255", "protocol": "2"},
        {"priority": 1000, "src": "192.168.167.0", "srclen": 24, "table": "100", "protocol": "0"},
    ], [{"priority": 2000, "src": "2001:db8::", "srclen": 64, "table": "200", "protocol": "0"}])
    snapshot = helper._snapshot_route_domain_rules()
    assert [row["protocol"] for row in snapshot] == [0, 0]
    assert snapshot[0]["source"] == "192.168.167.0/24"
    commands = native_rules(helper, monkeypatch, [])
    helper._restore_route_domain_rules(snapshot)
    assert commands == [
        ["ip", "-4", "rule", "add", "from", "192.168.167.0/24", "table", "100", "priority", "1000", "protocol", "0"],
        ["ip", "-6", "rule", "add", "from", "2001:db8::/64", "table", "200", "priority", "2000", "protocol", "0"],
    ]


@pytest.mark.parametrize("protocol", [4, "4", "static"])
def test_legacy_networkd_static_source_rule_is_preserved(helper, monkeypatch, protocol):
    """Networkd v257 marks Atlaso's prior persisted prefix rules RTPROT_STATIC."""
    native_rules(helper, monkeypatch, [{"priority": 1000, "src": "192.0.2.0", "srclen": 24,
                                        "table": "100", "protocol": protocol}])
    snapshot = helper._snapshot_route_domain_rules()
    commands = native_rules(helper, monkeypatch, [])
    helper._restore_route_domain_rules(snapshot)
    assert commands[0][-2:] == ["protocol", "4"]
    commands = native_rules(helper, monkeypatch, [{"priority": 2000, "src": "all", "iif": "eth1",
                                                   "table": "200", "protocol": protocol}])
    with pytest.raises(ValueError, match="foreign routing-domain ingress"):
        helper._restore_route_domain_rules([])
    assert commands == []


def test_owned_kernel_ingress_protocol_survives_snapshot_and_restore(helper, monkeypatch):
    """Accept only the narrow kernel-protocol ingress shape used to survive networkd."""
    native_rules(helper, monkeypatch, [{"priority": 2000, "src": "all", "iif": "eth1",
                                        "table": "200", "protocol": "2"}])
    snapshot = helper._snapshot_route_domain_rules()
    commands = native_rules(helper, monkeypatch, [])
    helper._restore_route_domain_rules(snapshot)
    assert commands == [["ip", "-4", "rule", "add", "iif", "eth1", "table", "200",
                         "priority", "2000", "protocol", "2"]]
