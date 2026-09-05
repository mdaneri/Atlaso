"""Verify applied NAT identity survives neither NIC replacement nor unsafe replay."""

import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module, wan_config_text


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
    assert helper._handle_wan("restore", [str(config)]) == 1
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
    config.write_text(config.read_text(encoding="utf-8").replace("inbound_interfaces=eth2", "inbound_interfaces="), encoding="utf-8")
    assert helper._handle_wan("restore", [str(config)]) == 2
    assert "masquerade" not in helper.WAN_NAT_CONFIG_PATH.read_text(encoding="utf-8")
