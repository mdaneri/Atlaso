"""Focused fail-closed checks for the private certificate address producer."""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
import certificate_peer_proof as proof  # noqa: E402 - Local interop script import.


class FakePeer:
    """Return only bounded network readbacks used by the proof."""

    def __init__(self, *, wrong_lease: bool = False):
        self.wrong_lease = wrong_lease

    def command(self, command: str) -> bytes:
        if command == "cat /etc/dnsmasq.conf":
            return (
                "port=0\ninterface=eth1\nbind-interfaces\nexcept-interface=eth0\n"
                "dhcp-range=192.168.77.0,static,255.255.255.0,12h\n"
                "dhcp-host=00:50:56:aa:bb:cc,192.168.77.10,12h\n"
                "dhcp-leasefile=/var/lib/misc/dnsmasq.leases\ndhcp-authoritative\n"
            ).encode()
        if command == "rc-service dnsmasq status":
            return b"dnsmasq is started"
        if command == "ip -j -4 addr show dev eth1":
            return json.dumps([{"addr_info": [{"local": "192.168.77.1", "prefixlen": 24}]}]).encode()
        if command == "cat /var/lib/misc/dnsmasq.leases":
            address = "192.168.77.11" if self.wrong_lease else "192.168.77.10"
            return f"{int(time.time()) + 3600} 00:50:56:aa:bb:cc {address} atlaso *\n".encode()
        raise AssertionError(command)


class FakeAppliance:
    """Return management address and route readbacks."""

    def command(self, command: str) -> bytes:
        if command == "cat /sys/class/net/eth0/address":
            return b"00:50:56:aa:bb:cc\n"
        if command == "ip -j -4 addr show dev eth0":
            return json.dumps([{"addr_info": [{"local": "192.168.77.30", "prefixlen": 24}]}]).encode()
        if command == "ip -j -4 route show dev eth0":
            return json.dumps([{"dev": "eth0", "prefsrc": "192.168.77.30"}]).encode()
        raise AssertionError(command)


def test_read_native_requires_exact_unexpired_lease_before_tls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n")
    plan = {
        "task_id": "task", "baseline_address": "192.168.77.30",
        "static_candidate_address": "192.168.77.40", "ca_path": str(ca),
        "ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
        "peer_fixture": {"sha256": "a" * 64}, "rewired_runtime": {"sha256": "b" * 64},
    }
    fixture = {
        "peer_cidr": "192.168.77.1/24", "lease_address": "192.168.77.10",
        "appliance_mac": "00:50:56:aa:bb:cc", "appliance_vmx": "owned.vmx",
        "lan_segment_receipt_sha256": "c" * 64,
    }

    class FakeHTTPS:
        def __init__(self, host: str, **kwargs: object):
            assert host == "192.168.77.30"
            assert kwargs["target_ip"] == host

        def request(self, method: str, path: str) -> None:
            assert (method, path) == ("GET", "/openapi.json")

        def getresponse(self):
            return type("Response", (), {"status": 200, "read": lambda self, size: b"{}"})()

        def close(self) -> None:
            pass

    monkeypatch.setattr(proof.ssl, "create_default_context", lambda **kwargs: object())
    monkeypatch.setattr(proof, "PeerHTTPSConnection", FakeHTTPS)
    with pytest.raises(proof.Refusal, match="peer_original_mac_lease_expired_or_missing"):
        proof.read_native(plan, fixture, FakePeer(wrong_lease=True), FakeAppliance())
    result = proof.read_native(plan, fixture, FakePeer(), FakeAppliance())
    assert result["address_ownership_state"] == "proven-controlled"
    assert result["addresses"] == ["192.168.77.40", "192.168.77.10"]
    assert result["candidate_observation_limit"].startswith("candidate addresses are reserved")
