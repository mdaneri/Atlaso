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
        """Initialize the validated client or test double.

        Args:
            wrong_lease: Wrong lease used by this operation."""
        self.wrong_lease = wrong_lease

    def command(self, command: str) -> bytes:
        """Handle command for certificate handoff verification.

        Args:
            command: Command to execute on the pinned peer."""
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
        """Handle command for certificate handoff verification.

        Args:
            command: Command to execute on the pinned peer."""
        if command == "cat /sys/class/net/eth0/address":
            return b"00:50:56:aa:bb:cc\n"
        if command == "ip -j -4 addr show dev eth0":
            return json.dumps([{"addr_info": [{"local": "192.168.77.30", "prefixlen": 24}]}]).encode()
        if command == "ip -j -4 route show dev eth0":
            return json.dumps([{"dev": "eth0", "prefsrc": "192.168.77.30"}]).encode()
        raise AssertionError(command)


def test_read_native_requires_exact_unexpired_lease_before_tls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Handle test read native requires exact unexpired lease before tls for certificate handoff verification.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides."""
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
            """Initialize the validated client or test double.

            Args:
                host: Host used by this operation.
                **kwargs: Kwargs used by this operation."""
            assert host == "192.168.77.30"
            assert kwargs["target_ip"] == host

        def request(self, method: str, path: str) -> None:
            """Handle request for certificate handoff verification.

            Args:
                method: Method used by this operation.
                path: Path to the resource being inspected."""
            assert (method, path) == ("GET", "/openapi.json")

        def getresponse(self):
            return type("Response", (), {"status": 200, "read": lambda self, size: b"{}"})()

        def close(self) -> None:
            pass

    class FakeContext:
        minimum_version = None

        def load_verify_locations(self, *, cafile: str) -> None:
            """Handle load verify locations for certificate handoff verification.

            Args:
                cafile: Path to the CA certificate file."""
            assert cafile == str(ca)

    context = FakeContext()
    monkeypatch.setattr(proof.ssl, "SSLContext", lambda protocol: context)
    monkeypatch.setattr(proof, "PeerHTTPSConnection", FakeHTTPS)
    with pytest.raises(proof.Refusal, match="peer_original_mac_lease_expired_or_missing"):
        proof.read_native(plan, fixture, FakePeer(wrong_lease=True), FakeAppliance())
    result = proof.read_native(plan, fixture, FakePeer(), FakeAppliance())
    assert context.minimum_version == proof.ssl.TLSVersion.TLSv1_2
    assert result["address_ownership_state"] == "unproven"
    assert result["addresses"] == ["192.168.77.40", "192.168.77.10"]
    assert "do not prove exclusive LAN attachment" in result["candidate_observation_limit"]


def test_original_peer_identity_rejects_changed_endpoint_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handle test original peer identity rejects changed endpoint before network for certificate handoff verification.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides."""
    root = tmp_path / "original"
    root.mkdir()
    refs = {name: {"path": str(root / f"{name}.json"), "sha256": name[0] * 64}
            for name in ("fixture", "bootstrap", "intent", "rewire")}
    refs["identity"] = {"path": str(root / "peer-identity.json"), "sha256": "e" * 64}
    fixture = {
        "schema": 1, "kind": "certificate-dhcp-peer-fixture", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pr": 871, "address_ownership_state": "awaiting-live-readback",
        "private_network": "lan:private", "source_commit": "a" * 40,
        "appliance_vmx": "appliance.vmx", "peer_vmx": "peer.vmx",
        "appliance_ownership_sha256": "a" * 64, "peer_ownership_sha256": "p" * 64,
        "client_vmdk_source": "disk.vmdk", "client_vmdk_sha256": "d" * 64,
        "client_vmdk_copy": "peer.vmdk", "client_vmdk_copy_preboot_sha256": "d" * 64,
        "client_vmdk_copy_identity": "00000001:0000000000000002",
        "lan_segment_receipt": str(root / "lan.json"), "lan_segment_receipt_sha256": "l" * 64,
        "lan_segment_id": "owned-id", "appliance_mac": "00:50:56:aa:bb:cc",
        "management_network": "VMnet8", "lease_address": "192.168.77.10",
    }
    identity = {
        "schema": 1, "kind": "certificate-peer-original-identity", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pr": 871, "peer_vmx": "peer.vmx",
        "peer_ownership_sha256": "p" * 64, "peer_fixture_sha256": refs["fixture"]["sha256"],
        "client_vmdk_copy_identity": fixture["client_vmdk_copy_identity"],
        "observation": "owned-vmware-guest-operations-before-management-rewire",
        "management_network": "VMnet8", "management_address": "192.168.167.42",
        "ssh_user": "alpine", "ssh_host_key": "SHA256:" + "A" * 43,
    }
    bootstrap = {"schema": 1, "vmx_path": "appliance.vmx", "vm_ownership_sha256": "a" * 64,
                 "predeployment_sha256": "a" * 64, "deployed_commit": "c" * 40}
    intent = {"kind": "certificate-management-rewire-intent", "bootstrap_runtime_sha256": refs["bootstrap"]["sha256"],
              "peer_fixture_sha256": refs["fixture"]["sha256"], "peer_identity_sha256": refs["identity"]["sha256"]}
    rewire = {"kind": "certificate-rewired-runtime", "rewire_intent_sha256": refs["intent"]["sha256"],
              "peer_identity_sha256": refs["identity"]["sha256"],
              "bootstrap_runtime_sha256": refs["bootstrap"]["sha256"],
              "predeployment_sha256": "a" * 64, "vmx_path": "appliance.vmx",
              "interface": "eth0", "mac": "00-50-56-aa-bb-cc", "observed_address": "192.168.77.10",
              "address_ownership_state": "unproven", "deployed_commit": "c" * 40}
    segment = {"schema": 1, "task_id": "task", "repository": "mdaneri/Atlaso", "pr": 871,
               "source_commit": "a" * 40, "name": "private", "pvn_id": "owned-id"}
    values = {refs["fixture"]["path"]: fixture, refs["identity"]["path"]: identity,
              refs["bootstrap"]["path"]: bootstrap, refs["intent"]["path"]: intent,
              refs["rewire"]["path"]: rewire, fixture["lan_segment_receipt"]: segment}
    monkeypatch.setattr(proof, "bound_json", lambda ref: values[ref["path"]])
    monkeypatch.setattr(proof, "original_vm", lambda plan, role, vmx: {"source_commit": "a" * 40})
    monkeypatch.setattr(proof, "file_digest", lambda path: "d" * 64)
    from scripts.completed_task_files import WindowsFiles
    monkeypatch.setattr(WindowsFiles, "__init__", lambda self: None)
    monkeypatch.setattr(WindowsFiles, "mutable_file_identity", lambda self, path: fixture["client_vmdk_copy_identity"])
    monkeypatch.setattr(proof, "vmx_adapter", lambda path, index: (
        {"connectiontype": "custom", "vnet": "VMnet8"} if index == 0 and path == "peer.vmx"
        else {"connectiontype": "pvn", "pvnid": "owned-id", "address": "00:50:56:aa:bb:cc"}))
    plan = {"task_id": "task", "deployed_commit": "c" * 40,
            "peer_fixture": refs["fixture"], "peer_identity": refs["identity"],
            "bootstrap_runtime": refs["bootstrap"], "rewire_intent": refs["intent"],
            "rewired_runtime": refs["rewire"],
            "appliance_ownership": {"sha256": "a" * 64}, "peer_ownership": {"sha256": "p" * 64},
            "peer_transport": {"host": "192.168.167.42", "user": "alpine", "ssh_host_key": identity["ssh_host_key"]}}
    with pytest.raises(proof.Refusal, match="exclusive_private_lan_and_candidate_ownership_unproven"):
        proof.admit_receipts(plan)
    monkeypatch.setattr(WindowsFiles, "mutable_file_identity", lambda self, path: "replaced")
    with pytest.raises(proof.Refusal, match="fixture_original_vm_mismatch"):
        proof.admit_receipts(plan)
    monkeypatch.setattr(WindowsFiles, "mutable_file_identity", lambda self, path: fixture["client_vmdk_copy_identity"])
    fixture["client_vmdk_copy_identity"] = "changed"
    with pytest.raises(proof.Refusal, match="peer_original_identity_mismatch"):
        proof.admit_receipts(plan)
    fixture["client_vmdk_copy_identity"] = identity["client_vmdk_copy_identity"]
    rewire["predeployment_sha256"] = "b" * 64
    with pytest.raises(proof.Refusal, match="runtime_rewire_chain_invalid"):
        proof.admit_receipts(plan)
    rewire["predeployment_sha256"] = "a" * 64
    for field, changed in (("host", "192.168.167.43"), ("ssh_host_key", "SHA256:" + "B" * 43),
                           ("user", "root")):
        altered = {**plan, "peer_transport": {**plan["peer_transport"], field: changed}}
        with pytest.raises(proof.Refusal, match="peer_original_identity_mismatch"):
            proof.admit_receipts(altered)


def test_preflight_refuses_exclusive_claim_before_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handle test preflight refuses exclusive claim before credentials for certificate handoff verification.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides."""
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"schema": 1, "pr": 871, "task_id": "task"}))
    monkeypatch.setattr(sys, "argv", [
        "proof", "--plan", str(plan_path), "--address-output", str(tmp_path / "address.json"),
        "--runtime-output", str(tmp_path / "runtime.json"), "--preflight-only",
    ])
    monkeypatch.setattr(proof, "admit_output", lambda *args: None)
    monkeypatch.setattr(proof, "admit_receipts", lambda plan: (_ for _ in ()).throw(
        proof.Refusal("exclusive_private_lan_and_candidate_ownership_unproven")))
    monkeypatch.setattr(proof, "PinnedPeerTransport", lambda *args: pytest.fail("network before exclusive proof"))
    assert proof.main() == 2
    assert not (tmp_path / "address.json").exists()
