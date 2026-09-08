"""Exercise source NAT family, isolation, compatibility and transaction boundaries."""

import subprocess
from contextlib import nullcontext

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.models import Base, NatRule, PhysicalInterface, Setting
from atlaso.app.services.routes_wan import (
    ensure_routes_wan_settings,
    save_routes_wan_settings,
)
from atlaso.app.services.traffic_publishing import (
    LEGACY_NAT_ENABLED_SETTING_KEY,
    NAT_ENABLED_SETTING_KEY,
    TrafficPublishingSettings,
    ensure_traffic_publishing_settings,
    nat_targets,
    render_nat_config,
    save_traffic_publishing_settings,
    validate_nat_rule,
)
from tests.test_appliance_helper import load_helper_module


def interfaces():
    """Provide independent dual-stack lab ingress, egress and dedicated management."""
    return [PhysicalInterface(name=f"eth{n}", role="management" if n == 0 else "access",
                              mode="access", admin_state="up", oper_state="up",
                              ip_cidr=f"192.0.{n}.1/24", ipv6_cidr=f"2001:db8:{n}::1/64",
                              mac_address=f"00:11:22:33:44:0{n}") for n in range(3)]


def rule(**changes):
    """Build explicit reviewed source translation.

    Args:
        **changes: Candidate changes for validation and rendering scenarios.
    """
    return NatRule(**dict(dict(name="source translation", enabled=True, source="any",
                              inbound_interfaces=["eth1"], outbound_interface="eth2",
                              ip_family=4, translation_mode="masquerade", translated_address="",
                              priority=100, masquerade=True), **changes))


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("mode", ["masquerade", "snat"])
def test_dual_stack_rules_keep_explicit_ingress_and_fixed_egress(family, mode, tmp_path):
    """Both families retain ingress/name/index boundaries and exact assigned SNAT.

    Args:
        family: Selected translation family.
        mode: Interface-address or fixed translation.
        tmp_path: Isolated helper snapshot directory.
    """
    address = ("192.0.2.1" if family == 4 else "2001:db8:2::1") if mode == "snat" else ""
    candidate = rule(ip_family=family, translation_mode=mode, translated_address=address)
    targets = nat_targets(interfaces(), [])
    assert not validate_nat_rule(candidate, targets, [])
    assert "eth0" not in {target["name"] for target in targets}
    path = tmp_path / "nat.conf"
    path.write_text(render_nat_config([candidate], targets, [], TrafficPublishingSettings(True, True)))
    helper = load_helper_module()
    assert not helper._wan_config_errors(path)
    output = helper._render_wan_nat_config(helper._parse_wan_config(path)["nat_rules"], {"eth1": 11, "eth2": 22})
    assert 'meta iif { 11 } meta oif 22 iifname { "eth1" } oifname "eth2"' in output
    assert ("snat to " + address if mode == "snat" else "masquerade") in output
    assert '"eth0"' not in output and "hook output" not in output
    if mode == "snat":
        candidate.translated_address = "192.0.2.9" if family == 4 else "2001:db8:2::9"
        assert validate_nat_rule(candidate, targets, [])


def test_nat_snapshot_is_stable_across_database_row_order():
    """Unchanged targets must not create false pending or stale queued snapshots."""
    rows = interfaces()
    settings = TrafficPublishingSettings(True, True)
    forward = render_nat_config([rule()], nat_targets(rows, []), [], settings)
    reverse = render_nat_config([rule()], nat_targets(list(reversed(rows)), []), [], settings)
    assert forward == reverse


def test_nat_validation_returns_fixed_parser_error_messages():
    """Parser failures expose actionable field guidance without exception text."""
    targets = nat_targets(interfaces(), [])
    value = "invalid-input-sentinel"
    source_errors = validate_nat_rule(rule(source=value), targets, [])
    address_errors = validate_nat_rule(rule(translation_mode="snat", translated_address=value), targets, [])
    assert source_errors == ["NAT source is invalid; select a valid Source Group or IPv4 addresses or CIDRs."]
    assert address_errors == ["Fixed SNAT requires a valid same-family address assigned to the selected egress interface."]
    assert value not in " ".join([*source_errors, *address_errors])


def test_invalid_ingress_family_and_disabled_target_are_rejected():
    """Unselected, management, wrong-family and dormant targets cannot widen scope."""
    rows = interfaces()
    targets = nat_targets(rows, [])
    for candidate in (rule(inbound_interfaces=[]), rule(inbound_interfaces=["eth0"]),
                      rule(inbound_interfaces=["eth2"]), rule(inbound_interfaces=["missing"]),
                      rule(source="2001:db8::/32"), rule(ip_family=6, source="192.0.2.0/24")):
        assert validate_nat_rule(candidate, targets, [])
    rows[1].admin_state = "down"
    assert validate_nat_rule(rule(), nat_targets(rows, []), [])
    legacy = rule(inbound_interfaces=[], enabled=False)
    assert not validate_nat_rule(legacy, targets, [])
    assert validate_nat_rule(rule(masquerade=False), targets, [])


def test_canonical_setting_migrates_once_and_legacy_writes_share_owner():
    """Migration preserves explicit intent, and rollback cannot leave two owners."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Setting(key=LEGACY_NAT_ENABLED_SETTING_KEY, value="true"))
        db.commit()
        settings = ensure_routes_wan_settings(db)
        assert settings.nat_enabled
        assert db.scalar(select(Setting).where(Setting.key == LEGACY_NAT_ENABLED_SETTING_KEY)) is None
        db.commit()
        save_routes_wan_settings(db, routing_enabled=True, nat_enabled=False, wan_simulation_enabled=False)
        assert not ensure_traffic_publishing_settings(db).nat_enabled
        db.rollback()
        assert ensure_traffic_publishing_settings(db).nat_enabled
        save_traffic_publishing_settings(db, nat_enabled=False)
        assert not ensure_routes_wan_settings(db).nat_enabled
        ensure_routes_wan_settings(db, force_disabled=True)
        assert not ensure_traffic_publishing_settings(db).effective_nat_enabled
        assert len(list(db.scalars(select(Setting).where(Setting.key == NAT_ENABLED_SETTING_KEY)))) == 1


def test_nat_apply_rolls_back_files_and_runtime_on_persistence_failure(tmp_path, monkeypatch):
    """A post-nft persistence failure restores prior runtime and enablement.

    Args:
        tmp_path: Task-owned isolated managed filesystem.
        monkeypatch: Bounded fake privileged operations and injected file failure.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_nat_transaction_lock", nullcontext)
    paths = {"NAT_APPLY_DIR": tmp_path, "NAT_RUNTIME_CONFIG_PATH": tmp_path / "runtime.conf",
             "WAN_NAT_CONFIG_PATH": tmp_path / "nat.nft", "WAN_NAT_SERVICE_PATH": tmp_path / "nat.service",
             "NAT_BOOT_ID_PATH": tmp_path / "boot-id"}
    for name, path in paths.items():
        monkeypatch.setattr(helper, name, path)
    paths["NAT_BOOT_ID_PATH"].write_text("boot-1")
    old = render_nat_config([], nat_targets(interfaces(), []), [], TrafficPublishingSettings(False, True))
    paths["NAT_RUNTIME_CONFIG_PATH"].write_text(old)
    paths["WAN_NAT_CONFIG_PATH"].write_text(helper._render_wan_nat_config([]))
    paths["WAN_NAT_SERVICE_PATH"].write_text("prior unit")
    staged = tmp_path / "candidate.conf"
    staged.write_text(render_nat_config([rule()], nat_targets(interfaces(), []), [], TrafficPublishingSettings(True, True)))
    programs = []
    monkeypatch.setattr(helper, "_run", lambda cmd: subprocess.CompletedProcess(cmd, 0, "", ""))
    monkeypatch.setattr(helper, "_run_with_input", lambda cmd, text: (programs.append(text) or subprocess.CompletedProcess(cmd, 0, "", "")))
    monkeypatch.setattr(helper, "_validate_wan_nat_config", lambda text: subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(helper, "_wan_nat_interface_indexes", lambda parsed, rules: {"eth1": 11, "eth2": 22})
    original = helper._nat_write
    failed = False

    def fail_once(path, text):
        """Fail only candidate service persistence; permit complete rollback.

        Args:
            path: Destination being replaced.
            text: Non-secret content to write.
        """
        nonlocal failed
        if path == paths["WAN_NAT_SERVICE_PATH"] and not failed:
            failed = True
            raise OSError("injected persistence failure")
        original(path, text)

    monkeypatch.setattr(helper, "_nat_write", fail_once)
    assert helper._handle_nat("apply", [str(staged)]) == 1
    assert "masquerade" in programs[0] and "masquerade" not in programs[-1]
    assert paths["NAT_RUNTIME_CONFIG_PATH"].read_text() == old
    assert paths["WAN_NAT_SERVICE_PATH"].read_text() == "prior unit"
    assert not paths["NAT_RUNTIME_CONFIG_PATH"].with_suffix(".recovery.json").exists()


def test_nat_boot_rebuilds_indexes_and_disabling_retires_runtime(tmp_path, monkeypatch, capsys):
    """Rebuild selectors on boot, quarantine replacement NICs, and disable replay.

    Args:
        tmp_path: Isolated runtime and staging tree.
        monkeypatch: Bounded privileged command doubles.
        capsys: Capture the truthful quarantine outcome.
    """
    helper = load_helper_module()
    for name, path in {"NAT_APPLY_DIR": tmp_path, "NAT_RUNTIME_CONFIG_PATH": tmp_path / "runtime.conf",
                       "WAN_NAT_CONFIG_PATH": tmp_path / "nat.nft", "WAN_NAT_SERVICE_PATH": tmp_path / "nat.service",
                       "NAT_BOOT_ID_PATH": tmp_path / "boot-id"}.items():
        monkeypatch.setattr(helper, name, path)
    helper.NAT_BOOT_ID_PATH.write_text("boot-1")
    monkeypatch.setattr(helper, "_nat_transaction_lock", nullcontext)
    programs, commands = [], []
    indexes = {"eth1": 11, "eth2": 22}
    monkeypatch.setattr(helper, "_wan_nat_interface_indexes", lambda parsed, rules: dict(indexes))
    monkeypatch.setattr(helper, "_run", lambda cmd: (commands.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", "")))
    monkeypatch.setattr(helper, "_run_with_input", lambda cmd, text: (programs.append(text) or subprocess.CompletedProcess(cmd, 0, "", "")))
    monkeypatch.setattr(helper, "_validate_wan_nat_config", lambda text: subprocess.CompletedProcess([], 0, "", ""))
    staged = tmp_path / "staged.conf"
    intent = render_nat_config([rule()], nat_targets(interfaces(), []), [], TrafficPublishingSettings(True, True))
    staged.write_text(intent)
    assert helper._handle_nat("apply", [str(staged)]) == 0
    assert "meta iif { 11 }" in programs[-1]
    unit = helper.WAN_NAT_SERVICE_PATH.read_text()
    assert "After=network-online.target atlaso-wan.service" in unit
    assert "Before=atlaso.service" in unit
    indexes["eth1"] = 99
    helper.NAT_BOOT_ID_PATH.write_text("boot-2")
    assert helper._handle_nat("restore", [str(helper.NAT_RUNTIME_CONFIG_PATH)]) == 0
    assert "meta iif { 99 }" in programs[-1] and "meta iif { 11 }" not in programs[-1]

    def replaced(parsed, rules):
        """Simulate a replacement NIC failing the existing MAC identity guard.

        Args:
            parsed: Prior saved targets.
            rules: Effective translation rules.
        """
        raise ValueError("replacement identity")

    monkeypatch.setattr(helper, "_wan_nat_interface_indexes", replaced)
    assert helper._handle_nat("restore", [str(helper.NAT_RUNTIME_CONFIG_PATH)]) == 0
    assert '"nat": "quarantined"' in capsys.readouterr().out
    assert "masquerade" not in programs[-1]
    assert helper.NAT_RUNTIME_CONFIG_PATH.read_text() == intent
    monkeypatch.setattr(helper, "_wan_nat_interface_indexes", lambda parsed, rules: dict(indexes))
    staged.write_text(render_nat_config([rule()], nat_targets(interfaces(), []), [], TrafficPublishingSettings(False, True)))
    assert helper._handle_nat("apply", [str(staged)]) == 0
    assert "masquerade" not in programs[-1] and "snat to" not in programs[-1]
    assert commands[-1] == ["systemctl", "disable", "atlaso-nat.service"]


@pytest.mark.parametrize("family,address", [(4, "192.0.2.1"), (6, "2001:db8:2::1")])
def test_fixed_snat_requires_observed_egress_address(monkeypatch, family, address):
    """Desired addresses alone cannot authorize source translation.

    Args:
        monkeypatch: Replace only the live address observation command.
        family: Reviewed translation family.
        address: Exact egress address in that family.
    """
    import json

    helper = load_helper_module()
    candidate = {"enabled": "true", "translation_mode": "snat", "ip_family": str(family),
                 "outbound_interface": "eth2", "translated_address": address}
    commands = []
    observed = [{"addr_info": [{"local": address, "flags": []}]}]

    def observe(command):
        """Return a bounded simulated address observation.

        Args:
            command: Argument vector to verify against the exact target.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(observed), "")

    monkeypatch.setattr(helper, "_run", observe)
    helper._nat_observed_addresses([candidate])
    assert commands == [["ip", "-j", f"-{family}", "address", "show", "dev", "eth2"]]
    observed[0]["addr_info"][0]["flags"] = ["tentative"]
    with pytest.raises(ValueError, match="not assigned"):
        helper._nat_observed_addresses([candidate])
    observed.clear()
    with pytest.raises(ValueError, match="not assigned"):
        helper._nat_observed_addresses([candidate])


@pytest.mark.parametrize("enabled,explicit,force_disabled,expected", [
    (True, None, False, True), (False, None, False, False),
    (True, "false", False, False), (False, "true", False, True),
    (True, None, True, False),
])
def test_legacy_nat_inference_preserves_intent(enabled, explicit, force_disabled, expected):
    """Migrate old rows once without overriding explicit switches or factory reset.

    Args:
        enabled: Legacy rule activation state.
        explicit: Optional legacy global switch.
        force_disabled: Whether factory reset overrides migration.
        expected: Canonical activation expected after migration.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(rule(enabled=enabled))
        if explicit is not None:
            db.add(Setting(key=LEGACY_NAT_ENABLED_SETTING_KEY, value=explicit))
        db.flush()
        assert ensure_traffic_publishing_settings(db, force_disabled=force_disabled).nat_enabled is expected
        for item in db.scalars(select(NatRule)):
            item.enabled = not enabled
        db.flush()
        assert ensure_traffic_publishing_settings(db).nat_enabled is expected
