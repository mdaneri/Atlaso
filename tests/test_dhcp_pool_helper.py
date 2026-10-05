"""Verify bounded applied-pool selection and fresh ARP evidence admission."""

import hashlib
import importlib.machinery
import importlib.util
import json
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def helper():
    """Load the privileged helper without invoking host operations."""
    path = Path(__file__).resolve().parents[1] / "scripts/appliance/atlaso-helper"
    loader = importlib.machinery.SourceFileLoader("atlaso_pool_helper", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def pool_config(end="192.168.50.110"):
    """Describe one installed VLAN pool and an out-of-range reservation."""
    pool = {"scope_id": 7, "name": "Site A", "interface_name": "eth1.50", "address_family": "ipv4",
            "site_address": "192.168.50.1", "prefix_length": 24,
            "ranges": [["192.168.50.100", end]],
            "reservations": [{"ip_address": "192.168.50.20", "mac_address": "02:00:00:00:00:20"}]}
    return ("# atlaso-dhcp-pool=" + json.dumps(pool) + "\n"
            + f"dhcp-range=set:site-a,192.168.50.100,{end},12h\n"
            + "dhcp-host=02:00:00:00:00:20,192.168.50.20,reserved\n")


def test_applied_selection_includes_reservations_and_rejects_uninstalled_ranges(helper):
    """Do not scan arbitrary metadata or omit declared static use."""
    pool, addresses = helper._dhcp_pool_candidates(pool_config(), 7)
    assert pool["interface_name"] == "eth1.50"
    assert addresses == ["192.168.50.20"] + [f"192.168.50.{value}" for value in range(100, 111)]
    with pytest.raises(ValueError, match="installed DHCP range"):
        helper._dhcp_pool_candidates(pool_config().replace("dhcp-range=", "# retired-range="), 7)
    with pytest.raises(ValueError, match="unique"):
        helper._dhcp_pool_candidates(pool_config(), 8)
    with pytest.raises(ValueError):
        helper._dhcp_pool_candidates(pool_config("192.168.55.200"), 7)


def arp_frame(sender_ip="192.168.50.100", target_ip="192.168.50.1"):
    """Make a transient ARP reply to a selected gateway probe."""
    local = bytes.fromhex("020000000001")
    remote = bytes.fromhex("020000000020")
    return (local + remote + bytes.fromhex("08060001080006040002") + remote
            + socket.inet_aton(sender_ip) + local + socket.inet_aton(target_ip))


def test_arp_evidence_requires_exact_probe_target_and_hardware_identity(helper):
    """Ignore unrelated, malformed, multicast and mismatched frames."""
    local = bytes.fromhex("020000000001")
    args = ({"192.168.50.100"}, "192.168.50.1", local)
    packet = arp_frame()
    assert helper._dhcp_pool_arp_reply(packet, *args) == ("192.168.50.100", "02:00:00:00:00:20")
    for invalid in (packet[:20], arp_frame("192.168.50.101"), arp_frame(target_ip="192.168.50.2"),
                    packet[:22] + b"\x01" + packet[23:], b"\xff" * 6 + packet[6:]):
        assert helper._dhcp_pool_arp_reply(invalid, *args) is None


def test_verify_chunk_is_read_only_and_detects_mid_probe_config_change(helper, monkeypatch, capsys):
    """Discard observations when the applied configuration changes during probes."""
    raw = pool_config().encode()
    digest = hashlib.sha256(raw).hexdigest()
    reads = iter([raw, raw + b"# changed\n"])
    monkeypatch.setattr(helper, "_dhcp_pool_read", lambda _path: next(reads))
    monkeypatch.setattr(helper, "_dhcp_pool_link", lambda _pool: ("192.168.50.1", "02:00:00:00:00:01", {"192.168.50.1"}, 5))
    monkeypatch.setattr(helper, "_dhcp_pool_leases", lambda _addresses: [])
    chunks = []

    def probe(interface, _source, _mac, addresses):
        assert interface == "eth1.50" and len(addresses) <= 16
        chunks.append(addresses)
        return [{"ip_address": value, "status": "no_response", "mac_addresses": []} for value in addresses]

    monkeypatch.setattr(helper, "_dhcp_pool_probe", probe)
    assert helper._verify_dhcp_pool(["7", "0", digest]) == 0
    assert chunks and json.loads(capsys.readouterr().out)["status"] == "unknown"


def test_verify_chunks_exclude_local_addresses_and_report_actual_version(helper, monkeypatch, capsys):
    """Use installed identity and fixed bounds without probing another local address."""
    raw = pool_config("192.168.50.150").encode()
    monkeypatch.setattr(helper, "_dhcp_pool_read", lambda _path: raw)
    monkeypatch.setattr(helper, "_dhcp_pool_link", lambda _pool: ("192.168.50.1", "02:00:00:00:00:01", {"192.168.50.1", "192.168.50.100"}, 5))
    monkeypatch.setattr(helper, "_dhcp_pool_leases", lambda _addresses: [])
    monkeypatch.setattr(helper, "_dhcp_pool_probe", lambda _interface, _source, _mac, addresses:
                        [{"ip_address": value, "status": "no_response", "mac_addresses": []} for value in addresses])
    monkeypatch.setattr(helper.subprocess, "run", lambda command, **_kwargs:
                        SimpleNamespace(returncode=0, stdout="Dnsmasq version test\n"))
    assert helper._verify_dhcp_pool(["7", "0", hashlib.sha256(raw).hexdigest()]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "complete" and report["total"] == 51
    assert len(report["observations"]) == 16 and report["next_offset"] == 16
    assert "192.168.50.100" not in {row["ip_address"] for row in report["observations"]}
    assert report["dnsmasq_version"] == "Dnsmasq version test"


def test_pool_input_rejects_oversized_files(helper, tmp_path):
    """Fixed evidence input cannot consume unbounded content."""
    path = tmp_path / "config"
    path.write_bytes(b"a" * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match="bounded"):
        helper._dhcp_pool_read(path)
