"""Verify paired Firewall/NAT publication and application-commit recovery."""

import json
import subprocess
from contextlib import nullcontext
from pathlib import Path

import pytest

from atlaso.app.models import PortForward
from atlaso.app.services.port_forwarding import render_port_forward_records
from atlaso.app.services.routes_wan import RoutesWanSettings, render_wan_config
from atlaso.app.services.traffic_publishing import (
    TrafficPublishingSettings,
    nat_targets,
    render_nat_config,
)
from tests.services.test_port_forwarding import interfaces, payload
from tests.test_appliance_helper import load_helper_module

JOB = "job_123456789abc"
FIREWALL = "flush ruleset\ntable inet atlaso {\n chain forward { type filter hook forward priority 0; policy drop; }\n}\n"


@pytest.mark.parametrize("state,expected", [("missing", False), ("source-only", False), ("retained", True),
    ("disabled", False), ("suspended", False), ("malformed", None), ("oversized", None), ("encoding", None)])
def test_privileged_status_projects_durable_intent_without_counters(transaction, monkeypatch, capsys, state, expected):
    """Root-only snapshots yield a bounded intent projection even when nft is unavailable.

    Args:
        transaction: Isolated root helper runtime.
        monkeypatch: Simulate unavailable kernel counters.
        capsys: Capture only the public helper projection.
        state: Durable snapshot condition.
        expected: Proven presence or unavailable projection.
    """
    helper, nat, _firewall, _previous, _programs, _commands = transaction
    runtime = helper.NAT_RUNTIME_CONFIG_PATH
    if state == "missing":
        runtime.unlink()
    elif state == "suspended":
        runtime.write_text(nat.read_text().replace("routing_enabled=true", "routing_enabled=false"))
    elif state in {"retained", "disabled"}:
        runtime.write_text(nat.read_text().replace('"enabled":true', '"enabled":false') if state == "disabled" else nat.read_text())
    elif state == "malformed":
        runtime.write_text("[port_forwards]\njson=broken\n")
    elif state == "oversized":
        runtime.write_bytes(b"x" * 2_000_001)
    elif state == "encoding":
        runtime.write_bytes(b"\xff")
    if runtime.exists():
        runtime.chmod(0o600)
    monkeypatch.setattr(helper, "_run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, "", ""))
    assert helper._port_forward_status() == 0
    assert json.loads(capsys.readouterr().out)["runtime_has_port_forwards"] is expected


@pytest.mark.parametrize("previous_active", [False, True])
def test_standalone_nat_accepts_disabled_intent_only_without_active_prior_pair(transaction, monkeypatch, previous_active):
    """Disabled saved rows need no pair, but retiring an applied mapping still does.

    Args:
        transaction: Isolated source and destination translation runtime.
        monkeypatch: Bind boot recovery identity to the test directory.
        previous_active: Existing applied mapping requiring paired retirement.
    """
    helper, nat, _firewall, _previous, _programs, _commands = transaction
    active = nat.read_text()
    disabled = active.replace('"enabled":true', '"enabled":false')
    nat.write_text(disabled)
    helper.NAT_RUNTIME_CONFIG_PATH.write_text(active if previous_active else disabled)
    boot = nat.parent / "boot-id"
    boot.write_text("test-boot")
    monkeypatch.setattr(helper, "NAT_BOOT_ID_PATH", boot)
    assert helper._handle_nat_locked("apply", [str(nat)]) == (1 if previous_active else 0)


@pytest.mark.parametrize("change", ["unchanged", "metadata", "target", "removed"])
def test_pair_preserves_unchanged_connections(transaction, change):
    """Unrelated submissions retain sessions and mapping edits retire only their own marks.

    Args:
        transaction: Isolated publication fixture with captured host commands.
        change: Candidate modification relative to two existing effective mappings.
    """
    helper, nat, firewall, _previous, _programs, commands = transaction
    prefix = render_nat_config([], nat_targets(interfaces(), []), [], TrafficPublishingSettings(False, True))
    first = PortForward(id=1, **payload())
    second = PortForward(id=2, **payload(name="second", external_port_start=14000, external_port_end=14002))
    helper.NAT_RUNTIME_CONFIG_PATH.write_text(prefix + render_port_forward_records([first, second], []))
    if change == "metadata":
        first.description = "Updated operator notes"
    elif change == "target":
        first.target_address = "198.51.100.11"
    candidate = [second] if change == "removed" else [first, second]
    nat.write_text(prefix + render_port_forward_records(candidate, []))
    helper._publishing_apply(JOB, str(nat), str(firewall))
    retirement = [command for command in commands if command[0] == "conntrack"]
    if change in {"unchanged", "metadata"}:
        assert retirement == []
    else:
        assert len(retirement) == 2
        assert all(command[-1] == "0xa7000001/0xffffffff" for command in retirement)


@pytest.fixture()
def transaction(tmp_path, monkeypatch):
    """Bind every durable path and privileged command to an isolated fixture.

    Args:
        tmp_path: Task-owned transaction filesystem.
        monkeypatch: Replace kernel and systemd boundaries.
    """
    helper = load_helper_module()
    paths = {
        "NAT_APPLY_DIR": tmp_path / "staged-nat", "FIREWALL_APPLY_DIR": tmp_path / "staged-firewall",
        "WAN_APPLY_DIR": tmp_path / "staged-wan",
        "NETWORK_APPLY_DIR": tmp_path / "staged-network",
        "NAT_RUNTIME_CONFIG_PATH": tmp_path / "runtime.conf", "WAN_NAT_CONFIG_PATH": tmp_path / "nat.nft",
        "WAN_NAT_SERVICE_PATH": tmp_path / "nat.service", "FIREWALL_CONFIG_PATH": tmp_path / "firewall.nft",
        "FIREWALL_SERVICE_PATH": tmp_path / "firewall.service",
        "WAN_RUNTIME_CONFIG_PATH": tmp_path / "wan-runtime.conf", "WAN_SYSCTL_PATH": tmp_path / "wan-forwarding.conf",
        "WAN_SERVICE_PATH": tmp_path / "wan.service",
    }
    for key, path in paths.items():
        monkeypatch.setattr(helper, key, path)
    paths["NAT_APPLY_DIR"].mkdir()
    paths["FIREWALL_APPLY_DIR"].mkdir()
    paths["WAN_APPLY_DIR"].mkdir()
    paths["NETWORK_APPLY_DIR"].mkdir()
    intent = render_nat_config([], nat_targets(interfaces(), []), [], TrafficPublishingSettings(False, True))
    old = intent + render_port_forward_records([], [])
    candidate = intent + render_port_forward_records([PortForward(id=1, **payload())], [])
    nat_path = paths["NAT_APPLY_DIR"] / "candidate.conf"
    firewall_path = paths["FIREWALL_APPLY_DIR"] / "candidate.nft"
    wan_candidate_path = paths["WAN_APPLY_DIR"] / "candidate.conf"
    wan_enabled_candidate_path = paths["WAN_APPLY_DIR"] / "candidate-enabled.conf"
    wan_rollback_path = paths["WAN_APPLY_DIR"] / "rollback.conf"
    wan_target = [{"name": "eth1", "kind": "physical", "role": "access", "ip_cidr": "192.0.2.10/24",
                   "routing_domain": "lab", "route_allowed": "true"}]
    wan_candidate = render_wan_config([], targets=wan_target, settings=RoutesWanSettings(False, False, False))
    wan_enabled_candidate = render_wan_config([], targets=wan_target, settings=RoutesWanSettings(True, False, True))
    wan_rollback = render_wan_config([], targets=wan_target, settings=RoutesWanSettings(True, False, False))
    nat_path.write_text(candidate)
    firewall_path.write_text(FIREWALL)
    wan_candidate_path.write_text(wan_candidate)
    wan_enabled_candidate_path.write_text(wan_enabled_candidate)
    wan_rollback_path.write_text(wan_rollback)
    previous = {
        paths["NAT_RUNTIME_CONFIG_PATH"]: old, paths["WAN_NAT_CONFIG_PATH"]: helper._render_wan_nat_config([], port_forwards=[]),
        paths["WAN_NAT_SERVICE_PATH"]: "prior nat service", paths["FIREWALL_CONFIG_PATH"]: FIREWALL,
        paths["FIREWALL_SERVICE_PATH"]: "prior firewall service",
        paths["WAN_RUNTIME_CONFIG_PATH"]: wan_rollback,
        paths["WAN_SERVICE_PATH"]: "prior wan service", paths["WAN_SYSCTL_PATH"]: "prior forwarding config",
    }
    for path, content in previous.items():
        path.write_text(content)
    programs = []
    commands = []

    def run(command):
        """Record only the bounded host operations issued by the transaction.

        Args:
            command: Fixed privileged command.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    def run_input(command, content):
        """Record complete atomic nft programs.

        Args:
            command: Native nft invocation.
            content: Complete captured program.
        """
        programs.append(content)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_run_with_input", run_input)
    monkeypatch.setattr(helper, "_validate_wan_nat_config", lambda text: subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(helper, "_wan_nat_interface_indexes", lambda parsed, rules: {"eth1": 11})
    monkeypatch.setattr(helper, "_nat_observed_addresses", lambda rules: None)
    monkeypatch.setattr(helper, "_port_forward_observed_interfaces", lambda parsed, rules: {"eth1": 11})
    return helper, nat_path, firewall_path, previous, programs, commands


def test_pair_waits_for_exact_application_commit(transaction):
    """A successful kernel publication retains rollback until both baselines commit.

    Args:
        transaction: Isolated helper and durable snapshots.
    """
    helper, nat, firewall, _previous, programs, commands = transaction
    result = helper._publishing_apply(JOB, str(nat), str(firewall))
    marker = helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json")
    assert result["publishing"] == "awaiting application commit"
    assert json.loads(marker.read_text())["phase"] == "awaiting-application-commit"
    assert "postrouting" not in programs[0]
    assert "flush chain ip atlaso_nat prerouting" in programs[0]
    assert programs[1].index("table inet atlaso") < programs[1].index("table ip atlaso_nat")
    assert "add rule inet atlaso forward ct mark 0xa7000001" in programs[1]
    assert not any("--now" in command for command in commands)
    with pytest.raises(ValueError, match="does not match"):
        helper._publishing_acknowledge("job_000000000000")
    assert marker.exists()
    helper._publishing_acknowledge(JOB)
    helper._publishing_acknowledge(JOB)
    helper._publishing_recover()
    assert not marker.exists()
    assert len(programs) == 2
    with pytest.raises(ValueError, match="already committed"):
        helper._publishing_apply(JOB, str(nat), str(firewall))


@pytest.mark.parametrize("output", ["FIREWALL_CONFIG_PATH", "NAT_RUNTIME_CONFIG_PATH", "WAN_NAT_SERVICE_PATH"])
def test_pair_persistence_failure_restores_both_runtimes(transaction, monkeypatch, output):
    """A partial disk write must restore both snapshots and the complete nft pair.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Inject one persistence failure after kernel publication.
        output: Exact paired artifact whose candidate write fails.
    """
    helper, nat, firewall, previous, programs, _commands = transaction
    write = helper._nat_write
    failed = False

    def fail_once(path, content):
        """Fail only the candidate write so rollback must perform real restoration.

        Args:
            path: Fixed runtime artifact.
            content: Candidate or recovery content.
        """
        nonlocal failed
        if path == getattr(helper, output) and not failed:
            failed = True
            raise OSError("injected persistence failure")
        write(path, content)

    monkeypatch.setattr(helper, "_nat_write", fail_once)
    with pytest.raises(ValueError, match="previous Firewall and NAT were restored"):
        helper._publishing_apply(JOB, str(nat), str(firewall))
    assert failed
    for path, content in previous.items():
        assert path.read_text() == content
    assert programs[-1].startswith("flush ruleset")
    assert "dnat to" not in programs[-1]
    assert not helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json").exists()


def test_unacknowledged_pair_recovers_previous_files_and_rules(transaction):
    """A worker interruption before baseline commit cannot silently retain the pair.

    Args:
        transaction: Isolated helper and durable snapshots.
    """
    helper, nat, firewall, previous, programs, _commands = transaction
    helper._publishing_apply(JOB, str(nat), str(firewall))
    helper._publishing_recover()
    for path, content in previous.items():
        assert path.read_text() == content
    assert "dnat to" not in programs[-1]
    assert not helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json").exists()


def test_pair_validation_has_no_persistence_or_kernel_mutation(transaction):
    """Complete pair validation must not create a rollback journal or run systemd.

    Args:
        transaction: Isolated helper and durable snapshots.
    """
    helper, nat, firewall, previous, programs, commands = transaction
    assert helper._publishing_apply(JOB, str(nat), str(firewall), validate_only=True)["publishing"] == "validation ok"
    assert programs == [] and commands == []
    assert all(path.read_text() == content for path, content in previous.items())
    assert not helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json").exists()


def _enable_wan_pair_test_seams(helper, monkeypatch, *, events=None):
    """Replace WAN host mutations with bounded state changes for group tests.

    Args:
        helper: Isolated helper module.
        monkeypatch: Test-owned replacements.
        events: Optional ordered event trace.
    """
    events = events if events is not None else []
    old_intent = helper.NAT_RUNTIME_CONFIG_PATH.read_text()
    old_firewall = helper.FIREWALL_CONFIG_PATH.read_text()
    old_firewall, old_nat, _ = helper._publishing_program(old_intent, old_firewall, observed=True)
    old_pair = old_firewall.rstrip() + "\n" + old_nat

    def apply_wan(action, args, *, replay=False, defer_forwarding=False):
        """Record one admitted WAN stage and emulate runtime persistence.

        Args:
            action: WAN operation.
            args: Exact staged path.
            replay: Unused replay flag.
            defer_forwarding: Must remain true for the paired transaction.
        """
        assert action == "apply" and defer_forwarding
        content = helper._validate_wan_config_path(args[0]).read_text()
        enabled = helper._wan_forwarding_required(helper._parse_wan_config(Path(args[0]), content=content))
        events.append(("wan", enabled))
        helper.WAN_RUNTIME_CONFIG_PATH.write_text(content)
        return 0

    monkeypatch.setattr(helper, "_handle_wan", apply_wan)
    monkeypatch.setattr(helper, "_publishing_snapshot_wan_forwarding", lambda: {"ipv4": True, "ipv6": True})
    def set_forwarding(enabled, *, persist=True):
        """Record a forwarding quiesce and optionally persist it.

        Args:
            enabled: Desired forwarding state.
            persist: Whether to write the boot policy.
        """
        events.append(("quiesce", enabled))
        if persist:
            value = "1" if enabled else "0"
            helper.WAN_SYSCTL_PATH.write_text(
                f"net.ipv4.ip_forward = {value}\nnet.ipv6.conf.all.forwarding = {value}\n"
            )
        return 0

    def apply_forwarding(parsed, *, persist=True):
        """Record parsed forwarding intent and optional boot policy.

        Args:
            parsed: Parsed WAN candidate.
            persist: Whether to write the boot policy.
        """
        enabled = helper._wan_forwarding_required(parsed)
        events.append(("forwarding", enabled))
        if persist:
            value = "1" if enabled else "0"
            helper.WAN_SYSCTL_PATH.write_text(
                f"net.ipv4.ip_forward = {value}\nnet.ipv6.conf.all.forwarding = {value}\n"
            )
        return 0

    monkeypatch.setattr(helper, "_set_wan_forwarding", set_forwarding)
    monkeypatch.setattr(helper, "_apply_wan_forwarding", apply_forwarding)
    install = helper._publishing_install

    def trace_install(*args, **kwargs):
        """Record the combined Firewall/NAT publication.

        Args:
            *args: Original positional installation arguments.
            **kwargs: Original keyword installation arguments.
        """
        events.append(("publish", None))
        return install(*args, **kwargs)

    monkeypatch.setattr(helper, "_publishing_install", trace_install)
    run_input = helper._run_with_input

    def trace_restore_policy(command, content):
        """Record restoration of the previous nft policy.

        Args:
            command: Host nft command.
            content: Complete nft program.
        """
        if command == ["nft", "-f", "-"] and content == old_pair:
            events.append(("restore-policy", None))
        return run_input(command, content)

    monkeypatch.setattr(helper, "_run_with_input", trace_restore_policy)
    restore_forwarding = helper._publishing_restore_wan_forwarding

    def trace_restore_forwarding(wan):
        """Record restoration of the previous forwarding state.

        Args:
            wan: Journaled previous WAN state.
        """
        events.append(("restore-forwarding", wan["previous_forwarding"]))
        return restore_forwarding(wan)

    monkeypatch.setattr(helper, "_publishing_restore_wan_forwarding", trace_restore_forwarding)
    return events


def _enable_network_pair_test_seams(helper, monkeypatch, events):
    """Emulate the retained Network journal inside a four-unit publication.

    Args:
        helper: Isolated privileged helper module.
        monkeypatch: Test-owned host boundary replacements.
        events: Ordered publication and rollback trace.
    """
    transaction = {}
    monkeypatch.setattr(helper, "_network_config_errors", lambda _path: [])

    def network_state():
        """Return the current emulated Network transaction journal."""
        return transaction.copy()

    def handle_network(action, args):
        """Record apply, rollback, and commit acknowledgement.

        Args:
            action: Requested Network transaction operation.
            args: Exact staged path or owning job ID.
        """
        events.append(("network-" + action, None))
        if action == "apply":
            assert f"# atlaso-network-task: {JOB}" in Path(args[0]).read_text()
            transaction.update(job_id=JOB, phase="awaiting-commit")
        else:
            assert args == [JOB]
            transaction.clear()
        return 0

    monkeypatch.setattr(helper, "_network_transaction_state", network_state)
    monkeypatch.setattr(helper, "_handle_network", handle_network)
    path = helper.NETWORK_APPLY_DIR / "candidate.conf"
    path.write_text(f"# atlaso-network-task: {JOB}\n# changed Access prefix\n")
    return path


def test_four_unit_group_quiesces_before_network_and_recovers_on_wan_failure(transaction, monkeypatch):
    """A failed paired WAN step restores Network before forwarding returns.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Replace host Network and WAN operations.
    """
    helper, nat, firewall, _previous, _programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    network = _enable_network_pair_test_seams(helper, monkeypatch, events)
    apply_wan = helper._publishing_apply_wan
    failed = False

    def fail_candidate_wan(content):
        """Reject only the candidate WAN route update.

        Args:
            content: Captured WAN candidate or rollback text.
        """
        nonlocal failed
        if not failed and content == (helper.WAN_APPLY_DIR / "candidate.conf").read_text():
            failed = True
            events.append(("wan-failed", None))
            raise ValueError("injected WAN failure")
        return apply_wan(content)

    monkeypatch.setattr(helper, "_publishing_apply_wan", fail_candidate_wan)
    with pytest.raises(ValueError, match="previous Firewall and NAT were restored"):
        helper._publishing_apply(
            JOB, str(nat), str(firewall), str(helper.WAN_APPLY_DIR / "candidate.conf"),
            str(helper.WAN_APPLY_DIR / "rollback.conf"), str(network),
        )
    assert failed
    assert events.index(("quiesce", False)) < events.index(("network-apply", None))
    assert events.index(("network-recover", None)) < events.index(
        ("restore-forwarding", {"ipv4": True, "ipv6": True}),
    )
    assert not helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json").exists()


def test_four_unit_group_acknowledges_network_only_after_application_commit(transaction, monkeypatch):
    """Network rollback remains available until the full group is acknowledged.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Replace host Network and WAN operations.
    """
    helper, nat, firewall, _previous, _programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    network = _enable_network_pair_test_seams(helper, monkeypatch, events)
    helper._publishing_apply(
        JOB, str(nat), str(firewall), str(helper.WAN_APPLY_DIR / "candidate-enabled.conf"),
        str(helper.WAN_APPLY_DIR / "rollback.conf"), str(network),
    )
    assert events.index(("network-apply", None)) < events.index(("publish", None))
    assert ("network-acknowledge", None) not in events
    assert helper._network_transaction_state()["phase"] == "awaiting-commit"
    assert "net.ipv4.ip_forward = 0" in helper.WAN_SYSCTL_PATH.read_text()

    helper._publishing_acknowledge(JOB)

    assert ("network-acknowledge", None) in events
    assert events.index(("publish", None)) < events.index(("forwarding", True))
    assert helper._network_transaction_state() == {}
    assert "net.ipv4.ip_forward = 1" in helper.WAN_SYSCTL_PATH.read_text()


def test_four_unit_group_boot_restores_network_before_forward_replay(transaction, monkeypatch):
    """An undecided boot restores Network, then committed Apply replays the group.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Replace host Network and WAN operations.
    """
    helper, nat, firewall, _previous, _programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    network = _enable_network_pair_test_seams(helper, monkeypatch, events)
    helper._publishing_apply(
        JOB, str(nat), str(firewall), str(helper.WAN_APPLY_DIR / "candidate-enabled.conf"),
        str(helper.WAN_APPLY_DIR / "rollback.conf"), str(network),
    )
    events.clear()

    assert helper._publishing_boot_restore()
    assert events.index(("network-recover", None)) < events.index(
        ("restore-forwarding", {"ipv4": True, "ipv6": True}),
    )
    state = json.loads(helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json").read_text())
    assert state["runtime_restored"] is True
    assert state["network"]["phase"] == "rolled-back"
    assert helper._network_transaction_state() == {}
    events.clear()

    helper._publishing_acknowledge(JOB)

    assert events.index(("network-apply", None)) < events.index(("publish", None))
    assert events.index(("publish", None)) < events.index(("network-acknowledge", None))
    assert helper._network_transaction_state() == {}
    assert "net.ipv4.ip_forward = 1" in helper.WAN_SYSCTL_PATH.read_text()


def test_four_unit_group_committed_receipt_retries_network_ack_after_boot(transaction, monkeypatch):
    """A committed group keeps its journal until Network acknowledgement succeeds.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Interrupt the first Network acknowledgement.
    """
    helper, nat, firewall, _previous, _programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    network = _enable_network_pair_test_seams(helper, monkeypatch, events)
    helper._publishing_apply(
        JOB, str(nat), str(firewall), str(helper.WAN_APPLY_DIR / "candidate-enabled.conf"),
        str(helper.WAN_APPLY_DIR / "rollback.conf"), str(network),
    )
    handle_network = helper._handle_network
    failed = False

    def fail_first_ack(action, args):
        """Leave one exact Network journal pending after application commit.

        Args:
            action: Requested Network operation.
            args: Exact staged path or task owner.
        """
        nonlocal failed
        if action == "acknowledge" and not failed:
            failed = True
            return 1
        return handle_network(action, args)

    monkeypatch.setattr(helper, "_handle_network", fail_first_ack)
    with pytest.raises(ValueError, match="Network commit acknowledgement failed"):
        helper._publishing_acknowledge(JOB)
    receipt = helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-commit.json")
    marker = helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json")
    assert receipt.exists() and marker.exists()
    assert helper._network_transaction_state()["phase"] == "awaiting-commit"

    assert helper._publishing_boot_restore()
    assert not marker.exists()
    assert helper._network_transaction_state() == {}
    assert ("network-acknowledge", None) in events


def test_three_unit_group_publishes_firewall_nat_before_forwarding(transaction, monkeypatch):
    """Candidate WAN intent is installed with forwarding off before Firewall/NAT.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Replace only host WAN operations.
    """
    helper, nat, firewall, _previous, programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    wan_candidate = helper.WAN_APPLY_DIR / "candidate.conf"
    wan_rollback = helper.WAN_APPLY_DIR / "rollback.conf"

    result = helper._publishing_apply(JOB, str(nat), str(firewall), str(wan_candidate), str(wan_rollback))

    state = json.loads(helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json").read_text())
    assert result["publishing"] == "awaiting application commit"
    assert state["wan"]["candidate"] == wan_candidate.read_text()
    assert state["wan"]["rollback"] == wan_rollback.read_text()
    assert events == [
        ("quiesce", False), ("wan", False), ("publish", None),
        ("forwarding", False),
    ]
    assert programs[1].index("table inet atlaso") < programs[1].index("table ip atlaso_nat")


def test_wan_forwarding_failure_after_pair_publication_rolls_back_group(transaction, monkeypatch):
    """A forwarding failure after nft publication restores WAN and Firewall/NAT.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Inject candidate forwarding failure after publication.
    """
    helper, nat, firewall, previous, programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    apply_forwarding = helper._apply_wan_forwarding
    failed = False

    def fail_candidate_forwarding(parsed, *, persist=True):
        """Fail candidate forwarding once after policy publication.

        Args:
            parsed: Parsed WAN candidate.
            persist: Whether to write the boot policy.
        """
        nonlocal failed
        enabled = helper._wan_forwarding_required(parsed)
        if not enabled and not failed:
            failed = True
            events.append(("forwarding-failed", enabled))
            return 1
        return apply_forwarding(parsed, persist=persist)

    monkeypatch.setattr(helper, "_apply_wan_forwarding", fail_candidate_forwarding)
    with pytest.raises(ValueError, match="previous Firewall and NAT were restored"):
        helper._publishing_apply(
            JOB, str(nat), str(firewall),
            str(helper.WAN_APPLY_DIR / "candidate.conf"), str(helper.WAN_APPLY_DIR / "rollback.conf"),
        )

    assert failed
    assert events == [
        ("quiesce", False), ("wan", False), ("publish", None), ("forwarding-failed", False),
        ("quiesce", False), ("wan", True), ("restore-policy", None),
        ("restore-forwarding", {"ipv4": True, "ipv6": True}),
    ]
    assert helper.WAN_RUNTIME_CONFIG_PATH.read_text() == (helper.WAN_APPLY_DIR / "rollback.conf").read_text()
    assert all(path.read_text() == content for path, content in previous.items())
    assert programs[-1].startswith("flush ruleset")
    assert not helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json").exists()


def test_interrupted_three_unit_group_restores_then_replays_candidate_on_ack(transaction, monkeypatch):
    """Boot recovery restores prior WAN and policy; owner ack can then replay forward.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Replace only host WAN operations.
    """
    helper, nat, firewall, _previous, programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    wan_candidate = helper.WAN_APPLY_DIR / "candidate.conf"
    wan_rollback = helper.WAN_APPLY_DIR / "rollback.conf"
    helper._publishing_apply(JOB, str(nat), str(firewall), str(wan_candidate), str(wan_rollback))
    events.clear()
    programs.clear()

    assert helper._publishing_boot_restore()
    marker = helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json")
    assert json.loads(marker.read_text())["runtime_restored"] is True
    assert helper.WAN_RUNTIME_CONFIG_PATH.read_text() == wan_rollback.read_text()
    assert events == [
        ("quiesce", False), ("wan", True), ("restore-policy", None),
        ("restore-forwarding", {"ipv4": True, "ipv6": True}),
    ]
    events.clear()
    programs.clear()

    helper._publishing_acknowledge(JOB)

    assert helper.WAN_RUNTIME_CONFIG_PATH.read_text() == wan_candidate.read_text()
    assert events == [
        ("quiesce", False), ("wan", False), ("publish", None),
        ("forwarding", False), ("forwarding", False),
    ]
    assert not marker.exists()
    assert json.loads(helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-commit.json").read_text()) == {
        "job_id": JOB, "phase": "committed",
    }


def test_enabled_routing_publishes_policy_before_forwarding(transaction, monkeypatch):
    """Routing enable turns forwarding on only after candidate Firewall/NAT publication.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Replace only host WAN operations.
    """
    helper, nat, firewall, _previous, _programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)

    helper._publishing_apply(
        JOB, str(nat), str(firewall),
        str(helper.WAN_APPLY_DIR / "candidate-enabled.conf"), str(helper.WAN_APPLY_DIR / "rollback.conf"),
    )

    assert events == [
        ("quiesce", False), ("wan", True), ("publish", None), ("forwarding", True),
    ]
    assert "net.ipv4.ip_forward = 0" in helper.WAN_SYSCTL_PATH.read_text()
    events.clear()

    helper._publishing_acknowledge(JOB)

    assert "net.ipv4.ip_forward = 1" in helper.WAN_SYSCTL_PATH.read_text()
    assert events == [("forwarding", True)]


def test_wan_boot_replay_defers_forwarding_while_group_journal_is_pending(transaction, monkeypatch):
    """WAN unit cannot enable forwarding before NAT recovery examines its journal.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Capture the boot replay defer flag.
    """
    from contextlib import contextmanager

    helper, nat, firewall, _previous, _programs, _commands = transaction
    real_handle_wan = helper._handle_wan
    _enable_wan_pair_test_seams(helper, monkeypatch)
    helper._publishing_apply(
        JOB, str(nat), str(firewall),
        str(helper.WAN_APPLY_DIR / "candidate-enabled.conf"), str(helper.WAN_APPLY_DIR / "rollback.conf"),
    )
    calls = []

    @contextmanager
    def replay_config(path):
        """Yield the test-owned WAN replay path.

        Args:
            path: Existing WAN runtime configuration path.
        """
        yield Path(path)

    def handle_config(action, path, *, replay=False, defer_forwarding=False):
        """Capture replay forwarding behavior without changing the host.

        Args:
            action: Requested WAN operation.
            path: Replay configuration path.
            replay: Whether this is a boot replay.
            defer_forwarding: Whether publication owns forwarding activation.
        """
        calls.append((action, replay, defer_forwarding))
        return 0

    monkeypatch.setattr(helper, "_wan_replay_config", replay_config)
    monkeypatch.setattr(helper, "_handle_wan", real_handle_wan)
    monkeypatch.setattr(helper, "_handle_wan_config", handle_config)

    assert helper._handle_wan("restore", [str(helper.WAN_RUNTIME_CONFIG_PATH)]) == 0
    assert calls == [("restore", True, True)]
    assert "net.ipv4.ip_forward = 0" in helper.WAN_SYSCTL_PATH.read_text()


def test_wan_mutation_failure_prevents_candidate_pair_publication(transaction, monkeypatch):
    """A candidate WAN failure leaves candidate Firewall/NAT unpublished.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Fail the candidate WAN application and allow rollback.
    """
    helper, nat, firewall, _previous, _programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    apply_wan = helper._publishing_apply_wan
    failed = False

    def fail_candidate_once(content):
        """Fail the candidate route update before nft publication.

        Args:
            content: Staged WAN candidate or rollback text.
        """
        nonlocal failed
        if not failed and content == (helper.WAN_APPLY_DIR / "candidate-enabled.conf").read_text():
            failed = True
            events.append(("wan-failed", True))
            raise ValueError("injected candidate WAN failure")
        return apply_wan(content)

    monkeypatch.setattr(helper, "_publishing_apply_wan", fail_candidate_once)
    with pytest.raises(ValueError, match="previous Firewall and NAT were restored"):
        helper._publishing_apply(
            JOB, str(nat), str(firewall),
            str(helper.WAN_APPLY_DIR / "candidate-enabled.conf"), str(helper.WAN_APPLY_DIR / "rollback.conf"),
        )

    assert failed
    assert not any(event[0] == "publish" for event in events)
    assert events == [
        ("quiesce", False), ("wan-failed", True), ("quiesce", False),
        ("wan", True), ("restore-policy", None),
        ("restore-forwarding", {"ipv4": True, "ipv6": True}),
    ]


def test_first_apply_rollback_preserves_missing_wan_runtime_files(transaction, monkeypatch):
    """An initial grouped Apply restores absent runtime, service, and sysctl files.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Fail candidate WAN mutation after recording an absent baseline.
    """
    helper, nat, firewall, _previous, _programs, _commands = transaction
    events = _enable_wan_pair_test_seams(helper, monkeypatch)
    prior_files = (helper.WAN_RUNTIME_CONFIG_PATH, helper.WAN_SERVICE_PATH, helper.WAN_SYSCTL_PATH)
    for path in prior_files:
        path.unlink()
    monkeypatch.setattr(helper, "_publishing_snapshot_wan_forwarding", lambda: {"ipv4": False, "ipv6": False})
    run = helper._run

    def service_disabled(command):
        """Report the initially absent WAN service as disabled.

        Args:
            command: Host command requested by the helper.
        """
        if command == ["systemctl", "is-enabled", "atlaso-wan.service"]:
            return subprocess.CompletedProcess(command, 1, "", "")
        return run(command)

    monkeypatch.setattr(helper, "_run", service_disabled)
    apply_wan = helper._publishing_apply_wan
    failed = False

    def fail_initial_apply(content):
        """Fail the first candidate WAN apply after snapshot capture.

        Args:
            content: Staged WAN candidate or rollback text.
        """
        nonlocal failed
        if not failed and content == (helper.WAN_APPLY_DIR / "candidate-enabled.conf").read_text():
            failed = True
            events.append(("wan-failed", True))
            raise ValueError("injected candidate WAN failure")
        return apply_wan(content)

    monkeypatch.setattr(helper, "_publishing_apply_wan", fail_initial_apply)
    with pytest.raises(ValueError, match="previous Firewall and NAT were restored"):
        helper._publishing_apply(
            JOB, str(nat), str(firewall),
            str(helper.WAN_APPLY_DIR / "candidate-enabled.conf"), str(helper.WAN_APPLY_DIR / "rollback.conf"),
        )

    assert all(not path.exists() for path in prior_files)
    assert events[-2:] == [
        ("restore-policy", None), ("restore-forwarding", {"ipv4": False, "ipv6": False}),
    ]


def test_legacy_publication_cannot_bypass_the_pair(transaction):
    """An admitted NAT staging path cannot publish destination rules alone.

    Args:
        transaction: Isolated helper and durable snapshots.
    """
    helper, nat, _firewall, previous, programs, commands = transaction
    assert helper._handle_nat_locked("apply", [str(nat)]) == 1
    assert programs == [] and commands == []
    assert all(path.read_text() == content for path, content in previous.items())


def test_factory_reset_retires_only_owned_forwarding_sessions(transaction, monkeypatch):
    """Reset disables new admissions before retiring both marked families.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Substitute root-owned lock admission for this unprivileged fixture.
    """
    helper, nat, firewall, _previous, programs, commands = transaction
    # Exercise retirement and pending-journal behavior without requiring the CI
    # account to own root's runtime directory. Production lock checks stay intact.
    monkeypatch.setattr(helper, "_nat_transaction_lock", nullcontext)
    helper._publishing_apply(JOB, str(nat), str(firewall))
    with pytest.raises(ValueError, match="reconciliation"):
        helper._reset_factory_port_forward_runtime()
    helper._publishing_acknowledge(JOB)
    programs.clear()
    commands.clear()
    helper._reset_factory_port_forward_runtime()
    assert "flush chain ip atlaso_nat prerouting" in programs[0]
    assert "dnat to" not in programs[-1]
    retire = [command for command in commands if command[0] == "conntrack"]
    assert len(retire) == 2
    assert all("0xa7000000/0xff000000" in command for command in retire)
    assert not helper.NAT_RUNTIME_CONFIG_PATH.exists()
    assert not helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-commit.json").exists()


@pytest.mark.parametrize("enabled", [False, True])
def test_inactive_forward_replay_preserves_firewall_and_saved_enablement(transaction, monkeypatch, enabled):
    """Suspended replay keeps its boot unit without flushing the Firewall again.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Bind boot identity to the task fixture.
        enabled: Saved forwarding intent while Routing is disabled.
    """
    helper, nat, _firewall, _previous, programs, commands = transaction
    boot = nat.parent / "boot-id"
    boot.write_text("test-boot", encoding="utf-8")
    monkeypatch.setattr(helper, "NAT_BOOT_ID_PATH", boot)
    intent = render_nat_config([], nat_targets(interfaces(), []), [], TrafficPublishingSettings(False, False))
    intent += render_port_forward_records([PortForward(id=1, **payload(enabled=enabled))], [])
    helper.NAT_RUNTIME_CONFIG_PATH.write_text(intent, encoding="utf-8")
    assert helper._handle_nat_locked("restore", [str(helper.NAT_RUNTIME_CONFIG_PATH)]) == 0
    assert programs and all("flush ruleset" not in program and "dnat to" not in program for program in programs)
    assert "table inet atlaso_port_forwards" in programs[-1]
    assert ["systemctl", "enable" if enabled else "disable", "atlaso-nat.service"] in commands
    assert "atlaso-firewall.service" in helper.WAN_NAT_SERVICE_PATH.read_text()


def test_boot_retains_candidate_until_application_commit_is_known(transaction):
    """Boot restores prior state, then a durable application commit recovers forward.

    Args:
        transaction: Isolated helper and durable snapshots.
    """
    helper, nat, firewall, previous, programs, _commands = transaction
    candidate = nat.read_text()
    helper._publishing_apply(JOB, str(nat), str(firewall))
    assert helper._publishing_boot_restore() is True
    assert all(path.read_text() == content for path, content in previous.items())
    assert "dnat to" not in programs[-1]
    marker = helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json")
    assert json.loads(marker.read_text())["runtime_restored"] is True
    helper._publishing_acknowledge(JOB)
    assert helper.NAT_RUNTIME_CONFIG_PATH.read_text() == candidate
    assert "dnat to" in programs[-1]
    assert not marker.exists()


def test_first_apply_crash_restores_firewall_without_nat_snapshot(transaction, monkeypatch):
    """Startup restores a journaled first publication before control-plane recovery.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Interrupt the first NAT snapshot write and isolate locking.
    """
    helper, nat, firewall, previous, programs, _commands = transaction
    helper.NAT_RUNTIME_CONFIG_PATH.unlink()
    write = helper._nat_write

    def interrupted_write(path, content):
        """Simulate power loss after Firewall persistence but before NAT persistence.

        Args:
            path: Durable output selected by the transaction.
            content: Candidate file content.
        """
        if path == helper.NAT_RUNTIME_CONFIG_PATH:
            raise SystemExit("power loss")
        write(path, content)

    with monkeypatch.context() as crash:
        crash.setattr(helper, "_nat_write", interrupted_write)
        with pytest.raises(SystemExit, match="power loss"):
            helper._publishing_apply(JOB, str(nat), str(firewall))
    assert not helper.NAT_RUNTIME_CONFIG_PATH.exists()
    assert helper.FIREWALL_CONFIG_PATH.read_text() != previous[helper.FIREWALL_CONFIG_PATH]
    monkeypatch.setattr(helper, "_nat_transaction_lock", nullcontext)
    assert helper._reconcile_startup_nat() == 0
    assert helper.FIREWALL_CONFIG_PATH.read_text() == previous[helper.FIREWALL_CONFIG_PATH]
    assert not helper.NAT_RUNTIME_CONFIG_PATH.exists()
    assert "dnat to" not in programs[-1]
    marker = helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json")
    assert json.loads(marker.read_text())["runtime_restored"] is True


def test_boot_without_application_commit_recovers_prior_pair(transaction):
    """An uncommitted database must never cause boot to activate the candidate.

    Args:
        transaction: Isolated helper and durable snapshots.
    """
    helper, nat, firewall, previous, programs, _commands = transaction
    helper._publishing_apply(JOB, str(nat), str(firewall))
    helper._publishing_boot_restore()
    helper._publishing_recover()
    assert all(path.read_text() == content for path, content in previous.items())
    assert "dnat to" not in programs[-1]
    assert not helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json").exists()


def test_failed_forward_recovery_retains_exact_candidate(transaction, monkeypatch):
    """A changed listener after reboot cannot be acknowledged as committed runtime.

    Args:
        transaction: Isolated helper and durable snapshots.
        monkeypatch: Simulate changed live interface identity.
    """
    helper, nat, firewall, _previous, _programs, _commands = transaction
    helper._publishing_apply(JOB, str(nat), str(firewall))
    helper._publishing_boot_restore()

    def missing_listener(*args, **kwargs):
        """Reject a candidate that lost its reviewed ingress.

        Args:
            *args: Captured candidate selectors.
            **kwargs: Observation options.
        """
        raise ValueError("reviewed listener disappeared")

    monkeypatch.setattr(helper, "_port_forward_observed_interfaces", missing_listener)
    with pytest.raises(ValueError, match="listener disappeared"):
        helper._publishing_acknowledge(JOB)
    marker = helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-recovery.json")
    assert json.loads(marker.read_text())["candidate"]["intent"] == nat.read_text()
    assert not helper.NAT_RUNTIME_CONFIG_PATH.with_suffix(".publishing-commit.json").exists()
