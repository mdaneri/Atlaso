"""Verify journalable legacy rule migration without applying pending WAN state."""

import copy
import json
import subprocess
from contextlib import nullcontext

import pytest

from atlaso import route_domains as domains
from tests.test_appliance_helper import (
    load_helper_module,
    network_config_text,
    wan_config_text,
)


@pytest.mark.parametrize("scope", ["global", 0])
def test_first_apply_seeds_exact_old_sources_before_deleting_legacy_prefixes(monkeypatch, scope):
    """An overlapping candidate cannot inherit the old table on first Apply.

    Args:
        monkeypatch: Pytest fixture replacing native routing operations.
        scope: Textual or numeric native global address scope.
    """
    legacy = [
        {"family": 4, "priority": 1000, "table": 100, "source": "10.42.0.0/16",
         "incoming_interface": "", "protocol": 4},
        {"family": 6, "priority": 1000, "table": 100, "source": "2001:db8:42::/64",
         "incoming_interface": "", "protocol": 4},
    ]
    inventory = [{"ifname": "eth0", "addr_info": [
        {"scope": scope, "local": "10.42.1.5"},
        {"scope": scope, "local": "2001:db8:42::5"},
    ]}]
    commands: list[list[str]] = []
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains.subprocess, "run", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 3, b"", b""))
    monkeypatch.setattr(domains, "read_native", lambda args:
                        inventory if args == ["address", "show"] else [])
    monkeypatch.setattr(domains, "run_ip", lambda command: commands.append(command) or "")

    domains.migrate_legacy_sources(legacy)

    assert len(commands) == 6
    assert all("unreachable" in command for command in commands[:2])
    assert all("table" in command for command in commands[2:])
    assert all(command[3] == "del" for command in commands[-2:])
    assert {command[command.index("from") + 1] for command in commands[2:4]} == {
        "10.42.1.5/32", "2001:db8:42::5/128",
    }
    assert {command[command.index("from") + 1] for command in commands[-2:]} == {
        "10.42.0.0/16", "2001:db8:42::/64",
    }


def test_active_watcher_refuses_unowned_legacy_source_migration(monkeypatch):
    """An active watcher cannot discard a newly seeded unproven old source.

    Args:
        monkeypatch: Pytest fixture replacing native routing operations.
    """
    legacy = [{"family": 4, "priority": 1000, "table": 100, "source": "10.42.0.0/16",
               "incoming_interface": "", "protocol": 4}]
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains.subprocess, "run", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, b"", b""))
    monkeypatch.setattr(domains, "read_native", lambda args:
                        [{"ifname": "eth0", "addr_info": [{"scope": "global", "local": "10.42.1.5"}]}]
                        if args == ["address", "show"] else [])
    monkeypatch.setattr(domains, "run_ip", lambda _command: pytest.fail("migration changed native rules"))

    with pytest.raises(domains.ReconcileError, match="active watcher"):
        domains.migrate_legacy_sources(legacy)


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
        """Return the corresponding numeric native inventory.

        Args:
            command: Native command being recorded or simulated.
        """
        assert command in [["ip", "-N", "-j", "-details", f"-{family}", "rule", "show"]
                           for family in (4, 6)]
        rows = rows4 if "-4" in command else rows6 or []
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    monkeypatch.setattr(helper, "_network_observation_command", observe)
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    return commands


def test_snapshot_and_restore_preserve_dual_stack_rules(helper, monkeypatch):
    """Capture exact prefixes and ingress rules while ignoring unrelated priorities.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
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
    """Ambiguous ownership and journal paths cannot broaden rule mutation.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
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
    assert commands[0][3] == ("add" if applied_forwarding else "del")
    additions = [command for command in commands if command[3] == "add"]
    assert len(additions) == (4 if applied_forwarding else 0)
    if additions:
        assert all(command[4:6] == ["iif", "eth2.20"] for command in additions)
        assert len([command for command in additions if "unreachable" in command]) == 2
        assert all(command[6:8] == ["table", "200"] for command in additions if "unreachable" not in command)
        assert all(command[-2:] == ["protocol", "2"] for command in additions)
    assert all(command[:1] == ["ip"] and "rule" in command for command in commands)
    assert {path: path.read_bytes() for path in before} == before


def test_applied_domain_projection_excludes_held_management(helper, monkeypatch, tmp_path):
    """An old management listener keeps its domain until the retirement phase.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
    """
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
    """A corrupt applied forwarding policy cannot silently authorize migration.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
    """
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
    """An interrupted mutation propagates failure and admits exact subsequent recovery.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    original = [{"priority": 1000, "src": "192.0.2.0/24", "table": 100}]
    native_rules(helper, monkeypatch, original)
    snapshot = helper._snapshot_route_domain_rules()
    desired = copy.deepcopy(snapshot)
    desired[0].update(priority=2000, table=200, source="0.0.0.0/0", incoming_interface="eth1")
    commands = []

    def fail_second(command):
        """Fail after deletion so the journal is necessary for recovery.

        Args:
            command: Native command being recorded or simulated.
        """
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
    """Repeated reconciliation preserves already matching rule state.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    commands = native_rules(helper, monkeypatch, [{"priority": 1000, "src": "192.0.2.0/24", "table": 100}])
    snapshot = helper._snapshot_route_domain_rules()
    helper._restore_route_domain_rules(snapshot)
    assert commands == []


def test_photon_numeric_strings_and_unspecified_protocol_round_trip(helper, monkeypatch):
    """Preserve Photon 257's actual numeric-string table and protocol-zero records.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
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
    """Networkd v257 marks Atlaso's prior persisted prefix rules RTPROT_STATIC.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        protocol: Native protocol identifier to preserve during migration.
    """
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
    """Accept only the narrow kernel-protocol ingress shape used to survive networkd.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    native_rules(helper, monkeypatch, [{"priority": 2000, "src": "all", "iif": "eth1",
                                        "table": "200", "protocol": "2"}])
    snapshot = helper._snapshot_route_domain_rules()
    commands = native_rules(helper, monkeypatch, [])
    helper._restore_route_domain_rules(snapshot)
    assert commands == [["ip", "-4", "rule", "add", "iif", "eth1", "table", "200",
                         "priority", "2000", "protocol", "2"]]


@pytest.mark.parametrize("action", ["unreachable", "7"])
def test_ingress_guards_round_trip_distinct_interfaces_at_shared_priority(helper, monkeypatch, action):
    """Native numeric actions and distinct same-priority iif guards stay journalable.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        action: Native policy action under test or requested rule operation.
    """
    rows = [{"priority": 2100, "src": "all", "iif": name, "protocol": "2", "action": action}
            for name in ("eth1", "eth2")]
    native_rules(helper, monkeypatch, rows, rows)
    snapshot = helper._snapshot_route_domain_rules()
    assert len(snapshot) == 4
    assert all(row["table"] is None and len(row) == 6 for row in snapshot)
    commands = native_rules(helper, monkeypatch, [])
    helper._restore_route_domain_rules(snapshot)
    assert len(commands) == 4
    assert all(command[6:] == ["unreachable", "priority", "2100", "protocol", "2"] for command in commands)


@pytest.mark.parametrize("override", [
    {"iif": "lo"}, {"iif": ""}, {"src": "192.0.2.0/24"}, {"table": 200},
    {"action": "blackhole"}, {"action": 7}, {"protocol": 0}, {"protocol": True},
    {"fwmark": "0x1"}, {"srclen": True}, {"srclen": 24},
])
def test_foreign_terminal_priority_is_never_adopted_or_deleted(helper, monkeypatch, override):
    """Only exact protocol2 interface terminal guards belong to Atlaso at2100.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        override: Foreign or malformed rule fields injected into the snapshot.
    """
    row = {"priority": 2100, "src": "all", "iif": "eth1", "protocol": "2", "action": "7", **override}
    commands = native_rules(helper, monkeypatch, [row])
    with pytest.raises(ValueError):
        helper._restore_route_domain_rules(helper._route_domain_ingress_rules(["eth1"]))
    assert not commands


def test_duplicate_identical_guard_is_ambiguous(helper, monkeypatch):
    """Same-priority guards need distinct iif selectors for exact deletion.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    row = {"priority": 2100, "src": "all", "iif": "eth1", "protocol": "2", "action": "7"}
    native_rules(helper, monkeypatch, [row, row])
    with pytest.raises(ValueError, match="ambiguous"):
        helper._snapshot_route_domain_rules()


def test_ingress_guard_capacity_remains_one_hundred_interfaces(helper):
    """Terminal protection does not halve the admitted lab-interface capacity.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
    """
    desired = helper._route_domain_ingress_rules([f"eth{index}" for index in range(100)])
    assert len(helper._validated_route_domain_rule_snapshot(desired)) == 400
    assert max(row["priority"] for row in desired if row["table"] == 200) == 2099


def test_ordinary_network_seeds_only_existing_management_interface(helper, monkeypatch, tmp_path):
    """An unchanged old listener is seeded; a newly promoted lab link is not.

    Args:
        helper: Loaded appliance helper module.
        monkeypatch: Isolated applied Network observation.
        tmp_path: Disposable candidate Network configuration location.
    """
    config = tmp_path / "network.conf"
    config.write_text(network_config_text(), encoding="utf-8")
    monkeypatch.setattr(helper, "_read_existing_management_network_values",
                        lambda: {"Name": ["eth0"]})
    assert helper._ordinary_network_old_management_bindings(config) == [{"name": "eth0", "table": 100}]
    monkeypatch.setattr(helper, "_read_existing_management_network_values",
                        lambda: {"Name": ["eth2"]})
    assert helper._ordinary_network_old_management_bindings(config) == []


def test_ordinary_network_seeds_existing_flagged_access_listener(helper, monkeypatch, tmp_path):
    """A marker-free flagged-only listener retains its lab-domain return path.

    Args:
        helper: Loaded appliance helper module.
        monkeypatch: Isolated applied Network observation.
        tmp_path: Disposable candidate Network configuration location.
    """
    config = tmp_path / "network.conf"
    config.write_text(network_config_text(eth2_mode="access", include_vlan=False).replace(
        "  role=access\n  mode=access", "  role=access\n  access_management_ui_enabled=true\n  mode=access"),
        encoding="utf-8")
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda: {"Name": ["eth2"]})

    assert helper._ordinary_network_old_management_bindings(config) == [{"name": "eth2", "table": 200}]


def test_transition_helper_supplies_proven_sources_before_guard(helper, monkeypatch):
    """The appliance boundary sends old link domains to the seeded entry point.

    Args:
        helper: Loaded appliance helper module.
        monkeypatch: Isolated transition command replacement.
    """
    calls = []
    monkeypatch.setattr(helper, "_run_with_input", lambda command, payload:
                        calls.append((command, json.loads(payload)))
                        or subprocess.CompletedProcess(command, 0, "", ""))
    bindings = [{"name": "eth0", "table": 100}]

    helper._transition_source_guard(True, seed_interfaces=bindings)

    assert calls[0][0][-1] == "--transition-start-seeded"
    assert calls[0][1] == bindings

    monkeypatch.setattr(helper, "_run_with_input", lambda command, _payload:
                        subprocess.CompletedProcess(command, 1, "", "invalid transition source addresses\n"))
    with pytest.raises(ValueError, match="invalid transition source addresses"):
        helper._transition_source_guard(True, seed_interfaces=bindings)


@pytest.mark.parametrize("enabled", [False, True])
def test_ingress_capacity_preflight_applies_only_with_routing(helper, monkeypatch, tmp_path, enabled):
    """Reject a large Network intent before mutation only when Routing needs rules.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture used to replace the applied WAN path.
        tmp_path: Temporary directory for the applied WAN snapshot.
        enabled: Whether applied WAN Routing requires ingress rules.
    """
    wan = tmp_path / "applied-wan.conf"
    wan.write_text(f"[feature_settings]\nrouting_enabled={str(enabled).lower()}\n" + wan_config_text(),
                   encoding="utf-8")
    monkeypatch.setattr(helper, "WAN_RUNTIME_CONFIG_PATH", wan)
    monkeypatch.setattr(helper, "_route_domain_ingress_projection", lambda *_args, **_kwargs:
                        ([f"eth{index}" for index in range(101)],
                         [f"eth{index}" for index in range(101)]))
    if enabled:
        with pytest.raises(ValueError, match="exceed rule capacity"):
            helper._route_domain_ingress_desired_rules(tmp_path / "network.conf")
    else:
        assert helper._route_domain_ingress_desired_rules(tmp_path / "network.conf") == []


def test_network_apply_rejects_ingress_capacity_before_transaction(helper, monkeypatch, tmp_path, capsys):
    """A full route rule set must fail before ordinary Network Apply mutates the host.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture used to replace native operations.
        tmp_path: Temporary directory for a staged network configuration.
        capsys: Pytest fixture used to capture the preflight error.
    """
    config = tmp_path / "network.conf"
    config.write_text("[network]\n", encoding="utf-8")
    monkeypatch.setattr(helper, "_validate_network_config_path", lambda _path: config)
    monkeypatch.setattr(helper, "_network_config_errors", lambda _path: [])
    monkeypatch.setattr(helper, "_network_detection_preflight", lambda _path: None)
    monkeypatch.setattr(helper, "_route_domain_ingress_desired_rules", lambda _path: (_ for _ in ()).throw(
        ValueError("route-domain ingress rules exceed rule capacity")))
    monkeypatch.setattr(helper, "_network_apply_transaction", lambda _path: pytest.fail("mutation began"))

    assert helper._handle_network_locked("apply", [str(config)]) == 2
    assert "exceed rule capacity" in capsys.readouterr().err


def test_failed_lookup_install_retains_guards_and_allows_exact_rollback(helper, monkeypatch):
    """Guards precede legacy retirement and survive an interrupted lookup addition.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    original = [{"priority": 1000, "src": "192.0.2.0/24", "table": 100}]
    native_rules(helper, monkeypatch, original)
    snapshot = helper._snapshot_route_domain_rules()
    commands = []

    def fail_lookup(command):
        """Model a native lookup failure after both family guards are installed.

        Args:
            command: Native command being recorded or simulated.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, int("add" in command and "table" in command), "", "")

    monkeypatch.setattr(helper, "_run", fail_lookup)
    with pytest.raises(ValueError, match="migration failed"):
        helper._restore_route_domain_rules(helper._route_domain_ingress_rules(["eth1"]))
    assert [command[3] for command in commands] == ["add", "add", "del", "add"]
    assert all("unreachable" in command for command in commands[:2])
    guard = {"priority": 2100, "src": "all", "iif": "eth1", "protocol": "2", "action": "7"}
    commands = native_rules(helper, monkeypatch, [guard], [guard])
    helper._restore_route_domain_rules(snapshot)
    assert commands[0][3:6] == ["add", "from", "192.0.2.0/24"]
    assert all(command[3] == "del" and "unreachable" in command for command in commands[1:])


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("lab_route_exists", [False, True])
def test_lab_lookup_miss_cannot_fall_through_management_main_default(helper, family, lab_route_exists):
    """Model RPDB fallthrough with overlapping lab traffic and a management default.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        family: IP version, either 4 or 6.
        lab_route_exists: Whether the simulated lab table contains the requested destination.
    """
    rules = helper._route_domain_ingress_rules(["eth1", "eth2"])
    rules += [{"family": family, "priority": 5000, "incoming_interface": "lo", "table": 100},
              {"family": family, "priority": 5001, "incoming_interface": "lo", "table": None},
              {"family": family, "priority": 32766, "incoming_interface": "", "table": 254}]

    def route(incoming):
        """An unsuccessful table lookup continues; unreachable ends evaluation.

        Args:
            incoming: Ingress interface selecting the simulated routing domain.
        """
        for rule in sorted(rules, key=lambda item: item["priority"]):
            if rule["family"] != family or rule["incoming_interface"] not in {"", incoming}:
                continue
            if rule["table"] is None:
                return "unreachable"
            if rule["table"] == 200 and lab_route_exists:
                return "lab"
            if rule["table"] in {100, 254}:
                return "management"
        return "unreachable"

    assert route("eth1") == ("lab" if lab_route_exists else "unreachable")
    assert route("eth2") == ("lab" if lab_route_exists else "unreachable")
    assert route("lo") == "management"


def test_wan_uses_same_guards_and_preserves_local_source_rules(helper, monkeypatch, tmp_path):
    """WAN enabled/disabled reconciliation never claims the5000 local-source window.

    Args:
        helper: Loaded appliance helper with isolated test dependencies.
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        tmp_path: Isolated temporary directory for test-owned state.
    """
    intent = tmp_path / "route-domains.json"
    intent.write_text(json.dumps({"schema": 1, "interfaces": [{"name": "eth1", "table": 200}]}))
    monkeypatch.setattr(helper, "ROUTE_DOMAIN_CONFIG_PATH", intent)
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "ip")
    local = [{"priority": 5000, "src": "192.0.2.10", "iif": "lo", "table": 100, "protocol": "2"},
             {"priority": 5001, "src": "192.0.2.10", "iif": "lo", "action": "7", "protocol": "2"}]
    commands = native_rules(helper, monkeypatch, local)
    monkeypatch.setattr(helper, "_wan_feature_settings", lambda _parsed: {"routing_enabled": True})
    assert helper._apply_wan_policy_rules({}) == 0
    assert len(commands) == 4
    assert all("unreachable" in command for command in commands[:2])
    assert all("lo" not in command for command in commands)
    guard = {"priority": 2100, "src": "all", "iif": "eth1", "protocol": "2", "action": "7"}
    commands = native_rules(helper, monkeypatch, [*local, guard], [guard])
    monkeypatch.setattr(helper, "_wan_feature_settings", lambda _parsed: {"routing_enabled": False})
    assert helper._apply_wan_policy_rules({}) == 0
    assert len(commands) == 2
    assert all(command[3] == "del" and "unreachable" in command and "lo" not in command for command in commands)


@pytest.mark.parametrize("protected", [False, True])
def test_removed_vlan_guard_survives_until_link_deletion(helper, monkeypatch, tmp_path, protected):
    """Normal and protected handoff retire old lookups while the live VLAN stays guarded.

    Args:
        helper: Loaded appliance helper under test.
        monkeypatch: Pytest fixture replacing external dependencies.
        tmp_path: Pytest-owned temporary directory.
        protected: Whether the operation uses the protected management handoff.
    """
    config = tmp_path / "network.conf"
    config.write_text("[removed_vlan_interfaces]\nvlan=eth1.120\n  parent=eth1\n  vlan_id=120\n", encoding="utf-8")
    current = helper._route_domain_ingress_rules(["eth1.120"])
    commands: list[list[str]] = []
    seen_holds: list[set[str] | None] = []

    def desired(_path, *, held_management_interfaces=None):
        """Supply candidate rules while observing protected management exclusions.

        Args:
            _path: Unused configuration path accepted by the test double.
            held_management_interfaces: Old management interfaces retained during handoff.
        """
        seen_holds.append(held_management_interfaces)
        return []

    def run(command):
        """Track exact rule deletion against the live native-rule model.

        Args:
            command: Command or command result under test.
        """
        commands.append(command)
        if command[3] == "del":
            family = 4 if "-4" in command else 6
            guard = "unreachable" in command
            row = next(row for row in current if row["family"] == family and (row["table"] is None) == guard)
            current.remove(row)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_route_domain_ingress_desired_rules", desired)
    monkeypatch.setattr(helper, "_snapshot_route_domain_rules", lambda: list(current))
    monkeypatch.setattr(helper, "_run", run)
    holds = {"eth0"} if protected else None
    helper._apply_route_domain_ingress(config, held_management_interfaces=holds,
                                       retain_removed_vlan_guards=True)
    assert len(current) == 2 and all(row["table"] is None for row in current)
    assert all("unreachable" not in command for command in commands)
    assert seen_holds == [holds]

    # A failed VLAN deletion never reaches the final reconciliation. In the
    # successful path, both family guards are removed only after link deletion.
    commands.append(["ip", "link", "delete", "dev", "eth1.120"])
    helper._apply_route_domain_ingress(config, held_management_interfaces=holds)
    deletion = commands.index(["ip", "link", "delete", "dev", "eth1.120"])
    assert all(index > deletion for index, command in enumerate(commands)
               if "unreachable" in command and command[3] == "del")
    assert current == []


@pytest.mark.parametrize("retirement_fails", [False, True])
def test_network_apply_retires_vlan_but_keeps_terminal_source_guard(helper, monkeypatch, tmp_path, retirement_fails):
    """Old VLAN guards retire after deletion while the terminal source guard persists.

    Args:
        helper: Loaded appliance helper under test.
        monkeypatch: Pytest fixture replacing external dependencies.
        tmp_path: Pytest-owned temporary directory.
        retirement_fails: Whether deferred VLAN deletion fails.
    """
    config = tmp_path / "network.conf"
    config.write_text("[network]\n", encoding="utf-8")
    events: list[str] = []
    monkeypatch.setattr(helper, "_validate_network_config_path", lambda _path: config)
    monkeypatch.setattr(helper, "_network_config_errors", lambda _path: [])
    monkeypatch.setattr(helper, "_network_detection_preflight", lambda _path: None)
    monkeypatch.setattr(helper, "_route_domain_ingress_desired_rules", lambda _path: [])
    monkeypatch.setattr(helper, "_network_apply_transaction", lambda _path: nullcontext())
    monkeypatch.setattr(helper, "_stage_candidate_ingress_guards", lambda _path: None)
    monkeypatch.setattr(helper, "_retire_legacy_source_rules", lambda: None)
    monkeypatch.setattr(helper, "_install_systemd_networkd_files", lambda _path: (0, [], [], []))
    monkeypatch.setattr(helper, "_wait_network_addresses", lambda *_args, **_kwargs: None)
    holds = [{"name": "eth1.120", "mac": "02:00:00:00:01:20", "address": "192.0.2.20", "table": 200}]
    monkeypatch.setattr(helper, "_install_route_domain_intent", lambda _path, **kwargs: events.append(
        "held-intent" if kwargs.get("held_addresses") == holds else "final-intent"))
    monkeypatch.setattr(helper, "_removed_vlan_source_holds", lambda _path: holds)
    monkeypatch.setattr(helper, "_transition_source_guard", lambda enabled: events.append("source-guard-on" if enabled else "source-guard-off"))
    monkeypatch.setattr(helper, "_reconcile_route_domains", lambda: events.append("reconcile"))

    def vlans(_path, *, defer_removed=False, removed_only=False):
        """Model one deferred old link and an optional deletion failure.

        Args:
            _path: Unused configuration path accepted by the test double.
            defer_removed: Whether to defer removal of old VLAN links.
            removed_only: Whether to process only removed VLAN links.
        """
        events.append("delete" if removed_only else "activate")
        return int(retirement_fails and removed_only)

    def ingress(_path, *, retain_removed_vlan_guards=False):
        """Record the protected and final rule reconciliation phases.

        Args:
            _path: Unused configuration path accepted by the test double.
            retain_removed_vlan_guards: Whether to retain ingress guards until link retirement.
        """
        events.append("retain" if retain_removed_vlan_guards else "retire")

    monkeypatch.setattr(helper, "_apply_vlan_interfaces", vlans)
    monkeypatch.setattr(helper, "_apply_route_domain_ingress", ingress)
    assert helper._handle_network_locked("apply", [str(config)]) == (2 if retirement_fails else 0)
    assert events == (["source-guard-on", "activate", "held-intent", "retain", "reconcile", "delete"]
                      if retirement_fails else ["source-guard-on", "activate", "held-intent", "retain",
                                               "reconcile", "delete", "final-intent", "retire", "reconcile"])


@pytest.mark.parametrize("protected_finalization", [False, True])
def test_ordinary_first_upgrade_seeds_and_reconfigures_management_before_exact_guard(
    helper, monkeypatch, tmp_path, protected_finalization,
):
    """Marker-free Management needs table-100 routes before source rules.

    Args:
        helper: Loaded appliance helper module under test.
        monkeypatch: Pytest fixture for replacing helper operations.
        tmp_path: Pytest fixture for the temporary network configuration.
        protected_finalization: Whether an enclosing handoff retires seeds later.
    """
    config = tmp_path / "network.conf"
    config.write_text("[network]\n", encoding="utf-8")
    events = []
    state = {"transition_seed_routes": [{"name": "eth0", "table": 100}]}
    monkeypatch.setattr(helper, "_validate_network_config_path", lambda _path: config)
    monkeypatch.setattr(helper, "_network_config_errors", lambda _path: [])
    monkeypatch.setattr(helper, "_network_detection_preflight", lambda _path: None)
    monkeypatch.setattr(helper, "_route_domain_ingress_desired_rules", lambda _path: [])
    monkeypatch.setattr(helper, "_network_apply_transaction", lambda _path: nullcontext())
    monkeypatch.setattr(helper, "_network_transaction_state", lambda: state)
    monkeypatch.setattr(helper, "_ordinary_network_old_management_bindings",
                        lambda _path: [{"name": "eth0", "table": 100}])
    monkeypatch.setattr(helper, "_removed_vlan_source_holds", lambda _path: [])
    monkeypatch.setattr(helper, "_seed_transition_routes",
                        lambda *_args: events.append("seed"))
    monkeypatch.setattr(helper, "_transition_source_guard",
                        lambda *_args, **_kwargs: events.append("source-guard"))
    monkeypatch.setattr(helper, "_stage_candidate_ingress_guards", lambda _path: None)
    monkeypatch.setattr(helper, "_retire_legacy_source_rules", lambda: None)
    monkeypatch.setattr(helper, "_install_systemd_networkd_files",
                        lambda _path: (events.append("install") or 0, [], [], []))
    monkeypatch.setattr(helper, "_run", lambda command:
                        events.append("reconfigure" if command == ["networkctl", "reconfigure", "eth0"] else "other")
                        or subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(helper, "_apply_vlan_interfaces", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(helper, "_wait_network_addresses", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_install_route_domain_intent", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_apply_route_domain_ingress", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_reconcile_route_domains", lambda: None)
    monkeypatch.setattr(helper, "_retire_transition_routes",
                        lambda *_args, **_kwargs: events.append("retire"))
    assert helper._handle_network_locked(
        "apply", [str(config)], preserve_transition_routes=protected_finalization,
    ) == 0
    assert events == (["source-guard", "install"] if protected_finalization else
                      ["seed", "source-guard", "install", "reconfigure", "retire"])


def test_incomplete_ordinary_network_rollback_keeps_seed_journal(helper, monkeypatch, tmp_path):
    """A failed snapshot restore cannot delete the only old management route.

    Args:
        helper: Loaded appliance helper module under test.
        monkeypatch: Replace native restore operations.
        tmp_path: Isolated transaction directory.
    """
    state = {"snapshots": [{"path": str(tmp_path / "old.network")}],
             "transition_seed_routes": [{"name": "eth0"}]}
    monkeypatch.setattr(helper, "NETWORK_TRANSACTION_DIR", tmp_path)
    monkeypatch.setattr(helper, "_stop_route_domains_for_restore", lambda _state: None)
    monkeypatch.setattr(helper, "_restore_management_handoff_snapshot",
                        lambda _item: (_ for _ in ()).throw(ValueError("snapshot unavailable")))
    monkeypatch.setattr(helper, "_run", lambda command: subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(helper, "_restore_management_handoff_links", lambda *_args: None)
    monkeypatch.setattr(helper, "_restore_route_domains", lambda _state: None)
    monkeypatch.setattr(helper, "_retire_transition_routes",
                        lambda *_args, **_kwargs: pytest.fail("seed retired during incomplete rollback"))
    with pytest.raises(ValueError, match="network rollback incomplete: snapshot unavailable"):
        helper._restore_network_transaction(state)
    assert state["transition_seed_routes"] == [{"name": "eth0"}]


def test_removed_vlan_missing_guard_refuses_before_rule_mutation(helper, monkeypatch, tmp_path):
    """An inconsistent applied lookup cannot expose a deferred VLAN to the main table.

    Args:
        helper: Loaded appliance helper under test.
        monkeypatch: Pytest fixture replacing external dependencies.
        tmp_path: Pytest-owned temporary directory.
    """
    config = tmp_path / "network.conf"
    config.write_text("[removed_vlan_interfaces]\nvlan=eth1.120\n  parent=eth1\n  vlan_id=120\n", encoding="utf-8")
    lookup = [row for row in helper._route_domain_ingress_rules(["eth1.120"]) if row["table"] == 200]
    commands: list[list[str]] = []
    monkeypatch.setattr(helper, "_route_domain_ingress_desired_rules", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(helper, "_snapshot_route_domain_rules", lambda: lookup)
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0, "", ""))
    with pytest.raises(ValueError, match="without its terminal ingress guard"):
        helper._apply_route_domain_ingress(config, retain_removed_vlan_guards=True)
    assert commands == []
