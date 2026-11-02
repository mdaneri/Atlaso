"""Focused safety checks for the isolated certificate DHCP peer seed."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
from create_certificate_peer_seed_iso import (
    peer_files,  # noqa: E402 - Local interop import after path setup.
)


def _args(**overrides: object) -> argparse.Namespace:
    """Handle args for certificate handoff verification.

    Args:
        **overrides: Overrides used by this operation."""
    values = {
        "server_cidr": "192.168.77.1/24",
        "lease_address": "192.168.77.10",
        "client_mac": "00:50:56:2a:11:22",
        "hostname": "certificate-peer",
        "user": "alpine",
        "public_key": "ssh-ed25519 " + "A" * 44 + " test-key",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_peer_has_exact_mac_static_only_dhcp_on_private_interface() -> None:
    files = peer_files(_args())
    config = files["user-data"]
    assert "interface=eth1\n" in config
    assert "except-interface=eth0\n" in config
    assert "dhcp-range=192.168.77.0,static,255.255.255.0,12h\n" in config
    assert "dhcp-host=00:50:56:2a:11:22,192.168.77.10,12h\n" in config
    parsed = yaml.safe_load(config)
    assert parsed["ssh_pwauth"] is False
    assert "chpasswd" not in parsed
    assert parsed["users"][1]["lock_passwd"] is True
    assert parsed["users"][1]["ssh_authorized_keys"] == ["ssh-ed25519 " + "A" * 44 + " test-key"]
    assert parsed["write_files"][0]["path"] == "/usr/local/etc/atlaso-certificate-peer.conf"
    probe = parsed["write_files"][1]["content"]
    assert "--cacert \"$1\"" in probe
    assert "--noproxy '*'" in probe
    assert "https://$2/openapi.json" in probe
    assert "--insecure" not in probe and " -k" not in probe
    assert "dhcp4: true" in files["network-config"].split("  eth1:")[0]
    assert "dhcp4: false" in files["network-config"].split("  eth1:")[1]
    assert files["meta-data"] == "instance-id: certificate-peer\nlocal-hostname: certificate-peer\n"
    assert "open-vm-tools" not in config
    assert "publish-host-key" not in config
    assert "ATLASO_CERTIFICATE_PEER_ED25519_HOST_KEY_V1" not in config


def test_optional_bootstrap_installs_tools_and_publishes_only_public_host_key() -> None:
    args = _args(publish_host_key_to_serial=True)

    files = peer_files(args)

    parsed = yaml.safe_load(files["user-data"])
    assert "open-vm-tools" in parsed["packages"]
    assert "open-vm-tools-openrc" in parsed["packages"]
    assert "open-vm-tools-guestinfo" in parsed["packages"]
    assert "open-vm-tools-timesync" not in parsed["packages"]
    commands = parsed["runcmd"]
    assert commands.index("rc-service sshd restart") < commands.index("rc-service dnsmasq restart")
    assert commands.index("rc-service dnsmasq restart") < commands.index("rc-service open-vm-tools start")
    assert commands.index("rc-update add open-vm-tools default") < commands.index(
        "/usr/local/sbin/atlaso-certificate-peer-publish-host-key"
    )

    publisher = next(
        item["content"] for item in parsed["write_files"]
        if item["path"] == "/usr/local/sbin/atlaso-certificate-peer-publish-host-key"
    )
    assert publisher.startswith("#!/bin/sh\n")
    assert "key_file=/etc/ssh/ssh_host_ed25519_key.pub" in publisher
    assert "ATLASO_CERTIFICATE_PEER_ED25519_HOST_KEY_V1 " in publisher
    assert "> /dev/ttyS0" in publisher
    assert "-le 512" in publisher and '"$attempt" -lt 30' in publisher
    assert "ssh-keygen -lf \"$key_file\"" in publisher
    assert args.public_key not in publisher
    assert "/etc/ssh/ssh_host_ed25519_key \"" not in publisher


def test_optional_instance_id_is_quoted_and_safe_for_cloud_init() -> None:
    files = peer_files(_args(instance_id="certificate-peer-rerun-001"))

    metadata = yaml.safe_load(files["meta-data"])

    assert metadata == {
        "instance-id": "certificate-peer-rerun-001",
        "local-hostname": "certificate-peer",
    }


def test_authorized_reseed_preserves_original_console_host_key() -> None:
    parsed = yaml.safe_load(peer_files(_args(preserve_host_keys=True, publish_host_key_to_serial=True))["user-data"])
    assert parsed["ssh_deletekeys"] is False
    assert parsed["ssh_pwauth"] is False
    assert "iproute2" in parsed["packages"] and "sudo" in parsed["packages"]
    assert "ssh_deletekeys" not in yaml.safe_load(peer_files(_args())["user-data"])


def test_management_channels_are_limited_to_three_addresses_before_sshd_restart() -> None:
    """Configure the private SSH destinations without enabling remote forwarding."""
    parsed = yaml.safe_load(peer_files(_args(management_addresses=[
        "192.168.77.40", "192.168.77.10", "192.168.77.30",
    ]))["user-data"])
    files = {item["path"]: item["content"] for item in parsed["write_files"]}
    policy = files["/etc/ssh/sshd_config.d/00-atlaso-certificate-peer.conf"]
    assert policy == (
        "DisableForwarding no\nAllowTcpForwarding local\nGatewayPorts no\n"
        "AllowAgentForwarding no\nX11Forwarding no\n"
        "PermitOpen 192.168.77.10:22 192.168.77.10:443 192.168.77.30:22 "
        "192.168.77.30:443 192.168.77.40:22 192.168.77.40:443\n"
    )
    installer = "/usr/local/sbin/atlaso-certificate-peer-sshd"
    assert 'sshd -t\n' in files[installer]
    assert parsed["runcmd"].index(installer) < parsed["runcmd"].index("rc-service sshd restart")
    assert "AllowTcpForwarding" not in peer_files(_args())["user-data"]


def test_optional_ntp_uses_the_same_peer_after_public_ssh_admission():
    """Add real time serving without adding a VM or changing upstream sources."""
    parsed = yaml.safe_load(peer_files(_args(serve_ntp=True, publish_host_key_to_serial=True,
                                           management_addresses=["192.168.77.10", "192.168.77.30", "192.168.77.40"]))["user-data"])
    assert "chrony" in parsed["packages"]
    assert parsed["runcmd"].index("/usr/local/sbin/atlaso-certificate-peer-publish-host-key") < parsed["runcmd"].index(
        "/usr/local/sbin/atlaso-certificate-peer-chrony")
    config = next(row["content"] for row in parsed["write_files"] if row["path"].endswith("peer-chrony.conf"))
    assert "bindaddress 192.168.77.1" in config and "allow 192.168.77.40/32" in config
    assert "local stratum" not in config and "server " not in config
    with pytest.raises(ValueError):
        peer_files(_args(serve_ntp=True))


@pytest.mark.parametrize("addresses", [
    ["192.168.78.10"], ["192.168.77.1"], ["192.168.77.0"], ["192.168.77.255"],
    ["192.168.77.30"], ["192.168.77.10", "192.168.77.10"], ["any"],
    ["192.168.77.10", "192.168.77.30", "192.168.77.40", "192.168.77.50"],
])
def test_management_channels_reject_ambiguous_or_external_destinations(addresses: list[str]) -> None:
    """Reject tunnel destinations outside the exact appliance address set.

    Args:
        addresses: Invalid destination list supplied to the seed generator.
    """
    with pytest.raises(ValueError):
        peer_files(_args(management_addresses=addresses))


@pytest.mark.parametrize(
    "bad",
    [
        {"lease_address": "192.168.78.10"},
        {"lease_address": "192.168.77.1"},
        {"lease_address": "192.168.77.255"},
        {"client_mac": "00:50:56:*"},
        {"client_mac": "01:50:56:2a:11:22"},
        {"server_cidr": "192.168.77.1/16"},
        {"server_cidr": "192.168.77.0/24"},
        {"hostname": "bad\nconfig"},
        {"public_key": "ssh-rsa " + "A" * 44},
        {"instance_id": "bad\nlocal-hostname: attacker"},
        {"instance_id": ""},
        {"publish_host_key_to_serial": "yes"},
    ],
)
def test_peer_rejects_ambiguous_or_external_input(bad: dict[str, str]) -> None:
    """Handle test peer rejects ambiguous or external input for certificate handoff verification.

    Args:
        bad: Bad used by this operation."""
    with pytest.raises(ValueError):
        peer_files(_args(**bad))
