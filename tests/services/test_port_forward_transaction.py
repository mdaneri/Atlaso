"""Verify paired Firewall/NAT publication and application-commit recovery."""

import json
import subprocess
from contextlib import nullcontext

import pytest

from atlaso.app.models import PortForward
from atlaso.app.services.port_forwarding import render_port_forward_records
from atlaso.app.services.traffic_publishing import (
    TrafficPublishingSettings,
    nat_targets,
    render_nat_config,
)
from tests.services.test_port_forwarding import interfaces, payload
from tests.test_appliance_helper import load_helper_module

JOB = "job_123456789abc"
FIREWALL = "flush ruleset\ntable inet atlaso {\n chain forward { type filter hook forward priority 0; policy drop; }\n}\n"


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
        "NAT_RUNTIME_CONFIG_PATH": tmp_path / "runtime.conf", "WAN_NAT_CONFIG_PATH": tmp_path / "nat.nft",
        "WAN_NAT_SERVICE_PATH": tmp_path / "nat.service", "FIREWALL_CONFIG_PATH": tmp_path / "firewall.nft",
        "FIREWALL_SERVICE_PATH": tmp_path / "firewall.service",
    }
    for key, path in paths.items():
        monkeypatch.setattr(helper, key, path)
    paths["NAT_APPLY_DIR"].mkdir()
    paths["FIREWALL_APPLY_DIR"].mkdir()
    intent = render_nat_config([], nat_targets(interfaces(), []), [], TrafficPublishingSettings(False, True))
    old = intent + render_port_forward_records([], [])
    candidate = intent + render_port_forward_records([PortForward(id=1, **payload())], [])
    nat_path = paths["NAT_APPLY_DIR"] / "candidate.conf"
    firewall_path = paths["FIREWALL_APPLY_DIR"] / "candidate.nft"
    nat_path.write_text(candidate)
    firewall_path.write_text(FIREWALL)
    previous = {
        paths["NAT_RUNTIME_CONFIG_PATH"]: old, paths["WAN_NAT_CONFIG_PATH"]: helper._render_wan_nat_config([], port_forwards=[]),
        paths["WAN_NAT_SERVICE_PATH"]: "prior nat service", paths["FIREWALL_CONFIG_PATH"]: FIREWALL,
        paths["FIREWALL_SERVICE_PATH"]: "prior firewall service",
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
