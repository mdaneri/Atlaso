"""Focused safety checks for the isolated certificate DHCP peer seed."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
from create_certificate_peer_seed_iso import (
    peer_files,  # noqa: E402 - Local interop import after path setup.
)


def _args(**overrides: str) -> argparse.Namespace:
    values = {
        "server_cidr": "192.168.77.1/24",
        "lease_address": "192.168.77.10",
        "client_mac": "00:50:56:2a:11:22",
        "hostname": "certificate-peer",
        "user": "alpine",
        "password": 'test: "quoted"',
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
    expected_password = json.dumps('test: "quoted"')
    assert f"password: {expected_password}" in config
    parsed = yaml.safe_load(config)
    assert parsed["chpasswd"]["users"][0]["password"] == 'test: "quoted"'
    assert parsed["write_files"][0]["path"] == "/usr/local/etc/atlaso-certificate-peer.conf"
    probe = parsed["write_files"][1]["content"]
    assert "--cacert \"$1\"" in probe
    assert "--noproxy '*'" in probe
    assert "https://$2/openapi.json" in probe
    assert "--insecure" not in probe and " -k" not in probe
    assert "dhcp4: true" in files["network-config"].split("  eth1:")[0]
    assert "dhcp4: false" in files["network-config"].split("  eth1:")[1]


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
    ],
)
def test_peer_rejects_ambiguous_or_external_input(bad: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        peer_files(_args(**bad))
