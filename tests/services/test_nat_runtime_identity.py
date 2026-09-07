"""Verify applied NAT identity survives neither NIC replacement nor unsafe replay."""

import subprocess
from pathlib import Path

import pytest

from tests.test_appliance_helper import load_helper_module, wan_config_text


@pytest.mark.parametrize("snapshot", ["modern", "legacy", "missing", "invalid", "replaced"])
def test_control_plane_start_reconciles_pre_upgrade_nat(runtime, monkeypatch, snapshot):
    """Upgrade startup retires raw replay and fences active NAT before inventory.

    Args:
        runtime: Isolated helper and fake kernel inventory.
        monkeypatch: Fixture capturing privileged commands.
        snapshot: Last-applied snapshot or current identity to exercise.
    """
    helper, config, sysfs = runtime
    baseline = config.read_text(encoding="utf-8")
    if snapshot == "legacy":
        config.write_text(baseline.replace("inbound_interfaces=eth2", "inbound_interfaces="), encoding="utf-8")
    elif snapshot == "missing":
        config.unlink()
    elif snapshot == "invalid":
        config.write_text(baseline.replace("route=10.20.0.0/24", "route=invalid"), encoding="utf-8")
    elif snapshot == "replaced":
        (sysfs / "eth2" / "address").write_text("00:11:22:33:44:99", encoding="utf-8")
    saved = config.read_bytes() if config.exists() else None
    helper.WAN_NAT_SERVICE_PATH.write_text("legacy raw replay", encoding="utf-8")
    helper.WAN_NAT_CONFIG_PATH.write_text('iifname "eth2" masquerade', encoding="utf-8")
    commands = []

    def run(command):
        """Capture service retirement and the kernel NAT replacement.

        Args:
            command: Privileged command supplied by the production helper.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", run)
    assert helper.main(["atlaso-helper", "wan", "reconcile-nat", "--real"]) == 0
    assert commands[:2] == [["systemctl", "disable", "--now", "atlaso-nat.service"],
                            ["systemctl", "daemon-reload"]]
    assert commands[2:] == [["nft", "-f", str(helper.WAN_NAT_CONFIG_PATH)]]
    assert not helper.WAN_NAT_SERVICE_PATH.exists()
    applied = helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")
    if snapshot == "modern":
        assert "meta iif { 3 } meta oif 4" in applied
    else:
        assert "masquerade" not in applied
    assert (config.read_bytes() if config.exists() else None) == saved
    assert helper.main(["atlaso-helper", "wan", "reconcile-nat", "--real"]) == 0
    assert helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8") == applied


@pytest.mark.parametrize("failure", ["retirement", "nft"])
def test_startup_nat_failure_blocks_control_plane(runtime, monkeypatch, failure):
    """The startup hook cannot report success while old runtime may remain.

    Args:
        runtime: Isolated helper and fake kernel inventory.
        monkeypatch: Fixture injecting a failed privileged operation.
        failure: Legacy service retirement or kernel table replacement failure.
    """
    helper, _config, _sysfs = runtime
    helper.WAN_NAT_SERVICE_PATH.write_text("legacy raw replay", encoding="utf-8")

    def run(command):
        """Fail the selected privileged operation.

        Args:
            command: Command supplied by the production helper.
        """
        failed = command[:2] == (["systemctl", "disable"] if failure == "retirement" else ["nft", "-f"])
        return subprocess.CompletedProcess(command, 1 if failed else 0, "", "")

    monkeypatch.setattr(helper, "_run", run)
    assert helper.main(["atlaso-helper", "wan", "reconcile-nat", "--real"]) != 0


def test_startup_nat_hook_precedes_application_and_follows_boot_restore():
    """Ship a blocking privileged hook in the unit installed by release updates."""
    unit = (Path(__file__).resolve().parents[2] / "image/common/systemd/atlaso.service").read_text(encoding="utf-8")
    hook = "ExecStartPre=+/opt/atlaso/bin/atlaso-helper wan reconcile-nat --real"
    assert hook in unit
    assert unit.index(hook) < unit.index("ExecStart=")
    assert "atlaso-wan.service" in next(line for line in unit.splitlines() if line.startswith("After="))


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    """Provide a fake kernel inventory and isolated privileged runtime files.

    Args:
        tmp_path: Isolated filesystem for all helper artifacts.
        monkeypatch: Fixture replacing runtime paths and command execution.
    """
    helper = load_helper_module()
    sysfs = tmp_path / "net"
    for name, index, mac in [("eth1", 2, "00:11:22:33:44:01"), ("eth1.20", 4, "00:11:22:33:44:01"), ("eth2", 3, "00:11:22:33:44:02")]:
        (sysfs / name).mkdir(parents=True)
        (sysfs / name / "ifindex").write_text(str(index), encoding="utf-8")
        (sysfs / name / "address").write_text(mac, encoding="utf-8")
    (sysfs / "eth1.20" / "iflink").write_text("2", encoding="utf-8")
    config = tmp_path / "atlaso-wan.conf"
    config.write_text(wan_config_text(), encoding="utf-8")
    monkeypatch.setattr(helper, "SYSTEMD_NETWORK_INTERFACE_DIR", sysfs)
    monkeypatch.setattr(helper, "WAN_NAT_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(helper, "WAN_NAT_CONFIG_PATH", tmp_path / "nat.nft")
    monkeypatch.setattr(helper, "WAN_NAT_SERVICE_PATH", tmp_path / "nat.service")
    monkeypatch.setattr(helper, "WAN_RUNTIME_CONFIG_PATH", config)
    monkeypatch.setattr(helper, "_run", lambda command: subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(helper, "_validate_wan_nat_config", lambda config: subprocess.CompletedProcess(["nft"], 0, "", ""))
    return helper, config, sysfs


@pytest.mark.parametrize("replaced", ["eth2", "eth1"])
def test_replaced_physical_nic_cannot_replay_nat(runtime, replaced):
    """Ingress and VLAN-parent egress replacement quarantine saved NAT.

    Args:
        runtime: Isolated helper and fake kernel inventory.
        replaced: Physical ingress or outbound VLAN parent to replace.
    """
    helper, config, sysfs = runtime
    parsed = helper._parse_wan_config(config)
    assert helper._apply_wan_nat(parsed) == 0
    applied = helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")
    assert "meta iif { 3 } meta oif 4" in applied
    # A replacement receives a new kernel index even if its Linux name is reused.
    replacement_target = "eth2" if replaced == "eth2" else "eth1.20"
    (sysfs / replacement_target / "ifindex").write_text("9", encoding="utf-8")
    (sysfs / replaced / "address").write_text("00:11:22:33:44:99", encoding="utf-8")
    assert "meta iif { 9 }" not in applied and "meta oif 9" not in applied
    assert helper._apply_wan_nat(helper._parse_wan_config(config)) == 1
    assert "masquerade" not in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")
    assert helper._parse_wan_config(config)["nat_rules"] == parsed["nat_rules"]


def test_nat_reboot_rebinds_same_mac_to_current_index(runtime):
    """A verified same NIC may acquire a different index across reboot.

    Args:
        runtime: Isolated helper and fake kernel inventory.
    """
    helper, config, sysfs = runtime
    (sysfs / "eth2" / "ifindex").write_text("12", encoding="utf-8")
    assert helper._apply_wan_nat(helper._parse_wan_config(config)) == 0
    assert "meta iif { 12 } meta oif 4" in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")


def test_legacy_saved_identity_fails_closed(runtime):
    """Saved intent without physical provenance cannot infer a new NIC identity.

    Args:
        runtime: Isolated helper and fake kernel inventory.
    """
    helper, config, _sysfs = runtime
    parsed = helper._parse_wan_config(config)
    parsed["targets"][0].pop("nat_physical_mac")
    assert helper._apply_wan_nat(parsed) == 1
    assert "masquerade" not in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")


def test_missing_interface_retires_applied_nat(runtime):
    """A disappeared interface leaves an empty table and preserves saved intent.

    Args:
        runtime: Isolated helper and fake kernel inventory.
    """
    helper, config, sysfs = runtime
    parsed = helper._parse_wan_config(config)
    assert helper._apply_wan_nat(parsed) == 0
    (sysfs / "eth2" / "ifindex").unlink()
    assert helper._apply_wan_nat(parsed) == 1
    assert "masquerade" not in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")


def test_vlan_parent_rebinding_retires_nat(runtime):
    """A VLAN cannot use the name of a saved target on a different physical NIC.

    Args:
        runtime: Isolated helper and fake kernel inventory.
    """
    helper, config, sysfs = runtime
    (sysfs / "eth1.20" / "iflink").write_text("3", encoding="utf-8")
    assert helper._apply_wan_nat(helper._parse_wan_config(config)) == 1
    assert "masquerade" not in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")


def test_obsolete_ingress_config_retires_nat_on_restore(runtime):
    """Early schema validation failure also retires a prior NAT table at boot.

    Args:
        runtime: Isolated helper and fake kernel inventory.
    """
    helper, config, _sysfs = runtime
    assert helper._apply_wan_nat(helper._parse_wan_config(config)) == 0
    config.write_text(
        config.read_text(encoding="utf-8").replace("inbound_interfaces=eth2", "inbound_interfaces=")
        .replace("route=10.20.0.0/24", "route=invalid"), encoding="utf-8",
    )
    assert helper._handle_wan("restore", [str(config)]) == 2
    assert "masquerade" not in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("legacy_field", ["inbound_interfaces", "nat_physical_mac", None])
@pytest.mark.parametrize("entrypoint", ["rollback", "boot"])
@pytest.mark.parametrize("explicit_settings", [False, True])
def test_management_rollback_restores_wan_with_legacy_nat_retired(runtime, monkeypatch, legacy_field, entrypoint, explicit_settings):
    """Replay old routes and forwarding without restoring unscoped NAT.

    Args:
        runtime: Isolated helper and kernel inventory.
        monkeypatch: Fixture intercepting non-NAT runtime operations.
        legacy_field: Provenance removed from the baseline, or a modern snapshot.
        entrypoint: Recovery entry point that must restore the non-NAT runtime.
        explicit_settings: Preserve saved switches rather than legacy inference.
    """
    helper, config, _sysfs = runtime
    if explicit_settings:
        config.write_text(
            config.read_text(encoding="utf-8")
            + "\n[feature_settings]\nrouting_enabled=true\nnat_enabled=true\nwan_simulation_enabled=false\n",
            encoding="utf-8",
        )
    candidate = helper._parse_wan_config(config)
    assert helper._apply_wan_nat(candidate) == 0
    baseline = "\n".join(
        line for line in config.read_text(encoding="utf-8").splitlines()
        if legacy_field is None or not line.strip().startswith(f"{legacy_field}=")
    ) + "\n"
    config.write_text(baseline, encoding="utf-8")
    monkeypatch.setattr(helper, "WAN_APPLY_DIR", config.parent)
    restored = {}
    for operation in (
        "_apply_wan_forwarding", "_apply_wan_target_routes",
        "_apply_wan_policy_rules", "_apply_wan_routes_and_qdiscs",
    ):
        monkeypatch.setattr(
            helper, operation,
            lambda parsed, *_args, operation=operation: restored.update({operation: parsed}) or 0,
        )
    persisted = config.parent / "persisted.conf"
    monkeypatch.setattr(
        helper, "_install_wan_runtime",
        lambda path: persisted.write_text(path.read_text(encoding="utf-8"), encoding="utf-8"),
    )
    evidence = []
    if entrypoint == "rollback":
        helper._restore_management_handoff_wan({"wan_rollback_config_path": str(config)}, evidence)
        assert evidence[0]["returncode"] == 0
        replay = helper._parse_wan_config(persisted)
        assert helper._wan_config_errors(persisted) == []
    else:
        assert helper._handle_wan("restore", [str(config)]) == 0
        replay = restored["_apply_wan_forwarding"]
        assert not persisted.exists()
    assert len(restored) == 4
    assert replay["routes"] == candidate["routes"]
    assert replay["wan_policies"] == candidate["wan_policies"]
    assert helper._wan_feature_settings(replay) == helper._wan_feature_settings(candidate)
    assert helper._wan_forwarding_required(replay)
    assert bool(replay["nat_rules"]) == (legacy_field is None)
    assert ("masquerade" in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")) == (legacy_field is None)
    assert config.read_text(encoding="utf-8") == baseline
    assert not list(config.parent.glob("wan-rollback-*.conf"))


def test_wan_replay_retains_modern_rules_alongside_legacy_nat(runtime):
    """Retire only unprovable rows when a snapshot also contains scoped NAT.

    Args:
        runtime: Isolated helper and kernel inventory.
    """
    helper, config, _sysfs = runtime
    modern_rules = helper._parse_wan_config(config)["nat_rules"]
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "[wan_policies]", "nat=Legacy\nenabled=true\noutbound_interface=eth1.20\n[wan_policies]",
        ), encoding="utf-8",
    )
    with helper._wan_replay_config(str(config)) as replay_path:
        replay = helper._parse_wan_config(replay_path)
        assert replay["nat_rules"] == modern_rules
        assert helper._wan_config_errors(replay_path) == []
        assert helper._apply_wan_nat(replay) == 0
    assert "masquerade" in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("candidate_legacy", [False, True])
def test_handoff_preflight_normalizes_only_legacy_rollback(runtime, monkeypatch, candidate_legacy):
    """Admit safe recovery snapshots while still rejecting unscoped candidates.

    Args:
        runtime: Isolated helper and kernel inventory.
        monkeypatch: Fixture isolating unrelated preflight layers.
        candidate_legacy: Whether the candidate also has an invalid NAT scope.
    """
    helper, config, _sysfs = runtime
    modern = config.read_text(encoding="utf-8")
    legacy = modern.replace("inbound_interfaces=eth2", "inbound_interfaces=")
    config.write_text(legacy, encoding="utf-8")
    candidate = config.parent / "candidate.conf"
    candidate.write_text(legacy if candidate_legacy else modern, encoding="utf-8")
    monkeypatch.setattr(helper, "WAN_APPLY_DIR", config.parent)
    for operation in ("_network_config_errors", "_appliance_settings_config_errors", "_public_services_config_errors"):
        monkeypatch.setattr(helper, operation, lambda *_args, **_kwargs: [])
    monkeypatch.setattr(helper, "_validate_firewall_config", lambda *_args: subprocess.CompletedProcess([], 0, "", ""))
    errors = helper._management_handoff_validation_errors({
        "network_config_path": "network.conf", "firewall_config_path": "firewall.nft",
        "appliance_settings_config_path": "settings.conf", "public_services_config_path": "public.conf",
        "wan_config_path": str(candidate), "wan_rollback_config_path": str(config),
    })
    assert not any(error.startswith("WAN rollback:") for error in errors)
    assert bool(errors) == candidate_legacy
    if candidate_legacy:
        assert any(error.startswith("WAN candidate:") and "requires explicit inbound" in error for error in errors)
    assert config.read_text(encoding="utf-8") == legacy
    assert not list(config.parent.glob("wan-rollback-*.conf"))


def test_legacy_wan_rollback_still_rejects_invalid_routes(runtime, monkeypatch):
    """Retiring legacy NAT must not bypass unrelated WAN validation.

    Args:
        runtime: Isolated helper and kernel inventory.
        monkeypatch: Fixture configuring the admitted staging directory.
    """
    helper, config, _sysfs = runtime
    config.write_text(
        config.read_text(encoding="utf-8").replace("inbound_interfaces=eth2", "inbound_interfaces=")
        .replace("route=10.20.0.0/24", "route=invalid"),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "WAN_APPLY_DIR", config.parent)
    evidence = []
    with pytest.raises(ValueError, match="Routes & WAN rollback failed"):
        helper._restore_management_handoff_wan({"wan_rollback_config_path": str(config)}, evidence)
    assert evidence[0]["returncode"] == 2
    assert not list(config.parent.glob("wan-rollback-*.conf"))


@pytest.mark.parametrize("entrypoint", ["boot", "rollback", "apply"])
@pytest.mark.parametrize("identity_failure", ["missing", "replaced"])
def test_identity_quarantine_continues_only_recovery(runtime, monkeypatch, capsys, entrypoint, identity_failure):
    """Quarantine stale NAT while replaying other WAN layers, keeping Apply strict.

    Args:
        runtime: Isolated helper and kernel inventory.
        monkeypatch: Fixture isolating non-NAT runtime stages.
        capsys: Fixture capturing explicit quarantine diagnostics.
        entrypoint: Boot, handoff rollback, or ordinary desired-state Apply.
        identity_failure: Missing NIC or replacement with a different MAC.
    """
    helper, config, sysfs = runtime
    baseline = config.read_text(encoding="utf-8")
    assert helper._apply_wan_nat(helper._parse_wan_config(config)) == 0
    if identity_failure == "missing":
        (sysfs / "eth2" / "ifindex").unlink()
    else:
        (sysfs / "eth2" / "address").write_text("00:11:22:33:44:99", encoding="utf-8")
    calls = []
    for operation in (
        "_apply_wan_forwarding", "_apply_wan_target_routes",
        "_apply_wan_policy_rules", "_apply_wan_routes_and_qdiscs",
    ):
        monkeypatch.setattr(helper, operation, lambda *_args, operation=operation: calls.append(operation) or 0)
    monkeypatch.setattr(helper, "_install_wan_runtime", lambda *_args: calls.append("persist"))
    if entrypoint == "rollback":
        evidence = []
        helper._restore_management_handoff_wan({"wan_rollback_config_path": str(config)}, evidence)
        assert evidence[0]["returncode"] == 0
        assert calls[-1] == "persist"
    else:
        result = helper._handle_wan("restore" if entrypoint == "boot" else "apply", [str(config)])
        assert result == (1 if entrypoint == "apply" else 0)
    assert len(calls) == {"boot": 4, "rollback": 5, "apply": 0}[entrypoint]
    if entrypoint != "apply":
        assert '"nat": "quarantined"' in capsys.readouterr().out
    assert "masquerade" not in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")
    assert config.read_text(encoding="utf-8") == baseline


def test_recovery_cannot_continue_when_nat_quarantine_fails(runtime, monkeypatch):
    """A failed kernel table replacement still blocks recovery.

    Args:
        runtime: Isolated helper and kernel inventory.
        monkeypatch: Fixture injecting a failed nft command.
    """
    helper, config, sysfs = runtime
    (sysfs / "eth2" / "address").write_text("00:11:22:33:44:99", encoding="utf-8")
    monkeypatch.setattr(helper, "_run", lambda command: subprocess.CompletedProcess(command, 7, "", "failed"))
    calls = []
    monkeypatch.setattr(helper, "_apply_wan_forwarding", lambda *_args: calls.append("forwarding") or 0)
    assert helper._handle_wan("restore", [str(config)]) == 7
    assert not calls


def test_recovery_cannot_ignore_legacy_nat_service_retirement_failure(runtime, monkeypatch):
    """Do not treat an unsafe old boot service as a recoverable NIC mismatch.

    Args:
        runtime: Isolated helper and kernel inventory.
        monkeypatch: Fixture injecting a failed service retirement.
    """
    helper, config, _sysfs = runtime

    def fail_retirement():
        """Simulate inability to disable the legacy raw nft boot unit."""
        raise ValueError("Could not retire the legacy NAT boot replay service")

    monkeypatch.setattr(helper, "_retire_wan_nat_service", fail_retirement)
    calls = []
    monkeypatch.setattr(helper, "_apply_wan_forwarding", lambda *_args: calls.append("forwarding") or 0)
    assert helper._handle_wan("restore", [str(config)]) == 1
    assert not calls
