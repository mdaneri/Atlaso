"""Focused fail-closed checks for the private certificate address producer."""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

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

    def __init__(self, *, route_fault: str | None = None):
        """Select an independently invalid management connected-route observation.

        Args:
            route_fault: Route ownership field to corrupt, or None for the native baseline.
        """
        self.route_fault = route_fault

    def command(self, command: str) -> bytes:
        """Handle command for certificate handoff verification.

        Args:
            command: Command to execute on the pinned peer."""
        if command == "cat /sys/class/net/eth0/address":
            return b"00:50:56:aa:bb:cc\n"
        if command == "ip -j -4 addr show dev eth0":
            return json.dumps([{"addr_info": [{"local": "192.168.77.30", "prefixlen": 24}]}]).encode()
        if command == "ip -j -4 route show dev eth0":
            # Native iproute2 omits dev when the query already filters by it.
            return json.dumps([{"dst": "192.168.77.0/24", "prefsrc": "192.168.77.30", "scope": "link"}]).encode()
        if command == "ip -j -4 route show table 100":
            route = {"dst": "192.168.77.0/24", "dev": "eth0", "prefsrc": "192.168.77.30", "scope": "link"}
            changes = {
                "interface": {"dev": "eth1"}, "source": {"prefsrc": "192.168.77.31"},
                "prefix": {"dst": "192.168.78.0/24"}, "scope": {"scope": "global"},
                "gateway": {"gateway": "192.168.77.1"}, "default": {"dst": "default"},
            }
            route.update(changes.get(self.route_fault, {}))
            return json.dumps([] if self.route_fault == "missing" else [route]).encode()
        raise AssertionError(command)


@pytest.mark.parametrize("route_fault", [None, "missing", "interface", "source", "prefix", "scope", "gateway", "default"])
def test_read_native_requires_exact_lease_and_management_route_before_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route_fault: str | None,
) -> None:
    """Admit the real route projection and refuse independent ownership mismatches.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides.
        route_fault: Management connected-route observation to corrupt.
    """
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
    if route_fault is not None:
        with pytest.raises(proof.Refusal, match="appliance_eth0_route_missing"):
            proof.read_native(plan, fixture, FakePeer(), FakeAppliance(route_fault=route_fault))
        return
    result = proof.read_native(plan, fixture, FakePeer(), FakeAppliance())
    assert context.minimum_version == proof.ssl.TLSVersion.TLSv1_2
    assert result["address_ownership_state"] == "unproven"
    assert result["addresses"] == ["192.168.77.40", "192.168.77.10"]
    assert "do not prove exclusive LAN attachment" in result["candidate_observation_limit"]


@pytest.mark.parametrize("route_fault", [None, "default", "extra", "ipv6_default", "extra_address"])
def test_read_native_observes_dhcp_management_baseline_without_static_rewire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route_fault: str | None,
) -> None:
    """Require a live fixed lease and its exact on-link route for DHCP mode.

    Args:
        tmp_path: Pytest-owned temporary directory for the public CA fixture.
        monkeypatch: Replace only the trusted topology and TLS observations.
        route_fault: Optional route mutation to refuse.
    """
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n")
    plan = {
        "scenario": "ordinary-ca-rotation", "ordinary_ca_baseline_mode": "dhcp",
        "trust_model": "trusted-host", "current_address": "192.168.77.10",
        "task_id": "task", "pr": 1118,
        "source_commit": "1" * 40, "deployed_commit": "2" * 40,
        "baseline_address": "192.168.77.30", "static_candidate_address": "192.168.77.40",
        "ca_path": str(ca), "ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
        "peer_fixture": {"sha256": "a" * 64}, "rewired_runtime": {"sha256": "b" * 64},
        "dhcp_baseline_observation": {"sha256": "c" * 64},
    }
    fixture = {
        "peer_cidr": "192.168.77.1/24", "lease_address": "192.168.77.10",
        "appliance_mac": "00:50:56:aa:bb:cc", "appliance_vmx": "owned.vmx",
        "lan_segment_receipt_sha256": "d" * 64,
    }

    class Appliance(FakeAppliance):
        """Expose the lease as the actual appliance management address."""

        def command(self, command: str) -> bytes:
            """Return the fixed DHCP interface, route, and public MAC observations.

            Args:
                command: Bounded public command issued to the appliance.
            """
            if command == "ip -j -4 addr show dev eth0":
                addresses = [{"local": "192.168.77.10", "prefixlen": 24}]
                if route_fault == "extra_address":
                    addresses.append({"local": "192.168.77.11", "prefixlen": 24})
                return json.dumps([{"addr_info": addresses}]).encode()
            if command == "ip -j -4 route show table 100":
                route = {"dst": "192.168.77.0/24", "dev": "eth0", "prefsrc": "192.168.77.10", "scope": "link"}
                routes = [route, {"dst": "192.168.77.0/25", "dev": "eth0"}] if route_fault == "extra" else [route]
                return json.dumps(routes).encode()
            if command == "ip -j -4 route show default":
                return json.dumps([{"dst": "default", "dev": "eth0"}] if route_fault == "default" else []).encode()
            if command == "ip -j -6 route show default":
                return json.dumps([{"dst": "default", "dev": "eth0"}] if route_fault == "ipv6_default" else []).encode()
            return super().command(command)

    class HTTPS:
        """Accept only a strict connection to the receipt-selected DHCP lease."""

        def __init__(self, host: str, **kwargs: object) -> None:
            """Bind the fake TLS connection to the selected current lease.

            Args:
                host: HTTPS hostname selected by the native proof.
                **kwargs: Pinned peer, target IP, and TLS context.
            """
            assert host == "192.168.77.10"
            assert kwargs["target_ip"] == host

        def request(self, method: str, path: str) -> None:
            """Accept the read-only health request.

            Args:
                method: HTTP method used by the native proof.
                path: Public path requested over strict TLS.
            """
            assert (method, path) == ("GET", "/openapi.json")

        def getresponse(self):
            """Return a bounded successful response."""
            return type("Response", (), {"status": 200, "read": lambda _self, _size: b"{}"})()

        def close(self) -> None:
            """Close the fake TLS connection."""

    monkeypatch.setattr(proof, "inspect_trusted_host", lambda _plan: {"topology": "same"})
    monkeypatch.setattr(proof, "verify_peer_isolation", lambda _peer: {"isolated": True})
    monkeypatch.setattr(proof, "verify_peer_tunnel_scope", lambda _peer, addresses: addresses)
    monkeypatch.setattr(proof, "assert_same_topology", lambda _before, _after: None)
    context = type("Context", (), {"minimum_version": None, "load_verify_locations": lambda _self, **_kwargs: None})()
    monkeypatch.setattr(proof.ssl, "SSLContext", lambda _protocol: context)
    monkeypatch.setattr(proof, "PeerHTTPSConnection", HTTPS)
    if route_fault:
        with pytest.raises(proof.Refusal, match="appliance_eth0_route_missing|appliance_dhcp_default_route_present|appliance_management_"):
            proof.read_native(plan, fixture, FakePeer(), Appliance())
        return

    result = proof.read_native(plan, fixture, FakePeer(), Appliance())

    assert result["phase"] == "dhcp-baseline-preflight"
    assert result["ordinary_ca_baseline_mode"] == "dhcp"
    assert result["baseline_address"] == fixture["lease_address"]
    assert result["dhcp_baseline_observation_sha256"] == "c" * 64
    assert result["address_ownership_state"] == "trusted-host-controlled"


def test_dhcp_receipt_admission_requires_observation_not_rewire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Admit DHCP only through its immutable no-mutation observation receipt.

    Args:
        monkeypatch: Replace receipt readers and trusted topology with fixed fixtures.
    """
    refs = {
        "fixture": {"path": "fixture.json", "sha256": "a" * 64},
        "bootstrap": {"path": "bootstrap.json", "sha256": "b" * 64},
        "observation": {"path": "observation.json", "sha256": "c" * 64},
        "identity": {"path": "identity.json", "sha256": "d" * 64},
    }
    fixture = {
        "appliance_vmx": "appliance.vmx", "peer_vmx": "peer.vmx",
        "appliance_ownership_sha256": "e" * 64, "appliance_mac": "00:50:56:aa:bb:cc",
        "lease_address": "192.168.77.10", "lan_segment_id": "segment-id",
        "peer_cidr": "192.168.77.1/24",
        "lan_segment_receipt": "lan.json", "lan_segment_receipt_sha256": "f" * 64,
    }
    bootstrap = {
        "schema": 1, "phase": "iso-dhcp-baseline-observed", "vmx_path": "appliance.vmx",
        "vm_ownership_sha256": "e" * 64, "deployed_commit": "2" * 40,
        "predeployment_sha256": "9" * 64,
    }
    observation = {
        "kind": "certificate-dhcp-baseline-observation", "phase": "iso-dhcp-baseline-observed",
        "ordinary_ca_baseline_mode": "dhcp", "apply_state": "clean-applied-baseline",
        "mutation_state": "none", "bootstrap_runtime_sha256": refs["bootstrap"]["sha256"],
        "predeployment_sha256": "9" * 64,
        "task_id": "task", "repository": "mdaneri/Atlaso", "pr": 1118,
        "source_commit": "1" * 40, "deployed_commit": "2" * 40,
        "vmx_path": "appliance.vmx", "vm_ownership_sha256": "e" * 64,
        "interface": "eth0", "mac": "00:50:56:aa:bb:cc", "observed_address": "192.168.77.10",
        "original_fields": {"ipv4_method": "dhcp", "ipv6_enabled": False},
        "native_observation": {
            "interface": "eth0", "mac": "00:50:56:aa:bb:cc", "address": "192.168.77.10",
            "prefixlen": 24, "lease_state": "unexpired_reserved_for_original_mac",
            "connected_route": "management_table_on_link", "default_routes": 0,
        },
    }
    values = {refs["fixture"]["path"]: fixture, refs["bootstrap"]["path"]: bootstrap,
              refs["observation"]["path"]: observation}
    monkeypatch.setattr(proof, "admit_fixture", lambda _plan: fixture)
    monkeypatch.setattr(proof, "bound_json", lambda ref: values[ref["path"]])
    monkeypatch.setattr(proof, "inspect_trusted_host", lambda _plan: {"topology": "same"})
    plan = {
        "ordinary_ca_baseline_mode": "dhcp", "scenario": "ordinary-ca-rotation",
        "trust_model": "trusted-host", "task_id": "task", "pr": 1118,
        "source_commit": "1" * 40, "deployed_commit": "2" * 40,
        "current_address": "192.168.77.10", "baseline_address": "192.168.77.30",
        "peer_fixture": refs["fixture"], "bootstrap_runtime": refs["bootstrap"],
        "dhcp_baseline_observation": refs["observation"], "peer_identity": refs["identity"],
        "trusted_host": {
            "appliance_vmx": fixture["appliance_vmx"], "peer_vmx": fixture["peer_vmx"],
            "segment_id": fixture["lan_segment_id"],
            "segment_receipt": {"path": fixture["lan_segment_receipt"],
                                "sha256": fixture["lan_segment_receipt_sha256"]},
        },
    }

    admitted_fixture, admitted_observation = proof.admit_receipts(plan)

    assert admitted_fixture is fixture
    assert admitted_observation is observation
    assert "rewire_intent" not in plan and "rewired_runtime" not in plan

    observation["mutation_state"] = "static-rewire-applied"
    with pytest.raises(proof.Refusal, match="dhcp_baseline_observation_invalid"):
        proof.admit_receipts(plan)


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
        "ssh_public_key": "ssh-ed25519 " + "A" * 44,
        "lan_segment_receipt": str(root / "lan.json"), "lan_segment_receipt_sha256": "l" * 64,
        "lan_segment_id": "owned-id", "appliance_mac": "00:50:56:aa:bb:cc",
        "management_network": "VMnet8", "lease_address": "192.168.77.10",
    }
    identity = {
        "schema": 1, "kind": "certificate-peer-original-identity", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pr": 871, "peer_vmx": "peer.vmx",
        "peer_ownership_sha256": "p" * 64, "peer_fixture_sha256": refs["fixture"]["sha256"],
        "client_vmdk_copy_identity": fixture["client_vmdk_copy_identity"],
        "observation": "owned-vmware-tools-and-agent-ssh-after-management-restart",
        "management_network": "VMnet8", "management_address": "192.168.167.42",
        "ssh_user": "alpine", "ssh_host_key": "SHA256:" + "A" * 43,
        "ssh_public_key": fixture["ssh_public_key"],
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
            "baseline_address": "192.168.77.30",
            "peer_fixture": refs["fixture"], "peer_identity": refs["identity"],
            "bootstrap_runtime": refs["bootstrap"], "rewire_intent": refs["intent"],
            "rewired_runtime": refs["rewire"],
            "appliance_ownership": {"sha256": "a" * 64}, "peer_ownership": {"sha256": "p" * 64},
            "peer_transport": {"host": "192.168.167.42", "user": "alpine", "ssh_host_key": identity["ssh_host_key"],
                               "ssh_public_key": fixture["ssh_public_key"]}}
    with pytest.raises(proof.Refusal, match="exclusive_private_lan_and_candidate_ownership_unproven"):
        proof.admit_receipts(plan)
    monkeypatch.setattr(proof, "original_vm", lambda plan, role, vmx: {
        "source_commit": ("b" if role == "appliance" else "a") * 40})
    for mode in (plan, dict(plan, trust_model="trusted-host")):
        with pytest.raises(proof.Refusal, match="fixture_original_vm_mismatch"):
            proof.admit_fixture(mode)
    monkeypatch.setattr(proof, "original_vm", lambda plan, role, vmx: {"source_commit": "a" * 40})
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
                           ("ssh_public_key", "ssh-ed25519 " + "B" * 44),
                           ("user", "root")):
        altered = {**plan, "peer_transport": {**plan["peer_transport"], field: changed}}
        with pytest.raises(proof.Refusal, match="peer_original_identity_mismatch"):
            proof.admit_receipts(altered)
    # A serial observation is admissible only in explicit trusted-host mode and
    # remains bound to the original peer, console endpoint and exact SSH pin.
    import base64

    peer_vmx = root / "peer.vmx"
    peer_vmx.write_text('serial0.fileName = "C:\\\\owned\\\\peer-public.log"\n')
    fixture["peer_vmx"] = str(peer_vmx)
    fixture["client_vmdk_copy"] = str(peer_vmx.with_suffix(".vmdk"))
    monkeypatch.setattr(proof, "vmx_adapter", lambda path, index: (
        {"connectiontype": "custom", "vnet": "VMnet8"} if index == 0 and path == str(peer_vmx)
        else {"connectiontype": "pvn", "pvnid": "owned-id", "address": "00:50:56:aa:bb:cc"}))
    public = "ssh-ed25519 " + base64.b64encode(b"synthetic public host key").decode()
    pin = "SHA256:" + base64.b64encode(hashlib.sha256(b"synthetic public host key").digest()).decode().rstrip("=")
    observation_ref = {"path": str(root / "console.json"), "sha256": "f" * 64}
    values[observation_ref["path"]] = {
        "schema": 1, "kind": "certificate-peer-console-public-key", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pr": 871, "peer_vmx": str(peer_vmx),
        "peer_ownership_sha256": fixture["peer_ownership_sha256"], "public_host_key": public,
        "serial_path": "C:\\\\owned\\\\peer-public.log",
    }
    identity.update(observation="owned-vmware-console-public-key", ssh_host_key=pin,
                    peer_vmx=str(peer_vmx), console_observation_sha256=observation_ref["sha256"])
    plan["peer_transport"]["ssh_host_key"] = pin
    plan["peer_console_observation"] = observation_ref
    with pytest.raises(proof.Refusal, match="peer_console_identity_invalid"):
        proof.admit_fixture(plan)
    trusted_plan = dict(plan, trust_model="trusted-host")
    assert proof.admit_fixture(trusted_plan) is fixture
    values[observation_ref["path"]]["public_host_key"] = "ssh-ed25519 " + base64.b64encode(b"changed public host key").decode()
    with pytest.raises(proof.Refusal, match="peer_console_identity_invalid"):
        proof.admit_fixture(trusted_plan)


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


def test_arbitrary_pr_is_opt_in_to_trusted_host_mode() -> None:
    """New trusted-host plans bind any positive PR; legacy evidence stays PR871-only."""
    assert proof.plan_pr({"pr": 1074, "trust_model": "trusted-host"}) == 1074
    with pytest.raises(proof.Refusal, match="proof_plan_invalid"):
        proof.plan_pr({"pr": 0, "trust_model": "trusted-host"})
    with pytest.raises(proof.Refusal, match="proof_plan_invalid"):
        proof.plan_pr({"pr": 1074})


def test_trusted_host_native_readback_is_explicitly_not_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Trusted-host observations retain their weaker, accurately labeled boundary.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides.
    """
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n")
    plan = {
        "task_id": "task", "pr": 1074, "trust_model": "trusted-host",
        "baseline_address": "192.168.77.30", "static_candidate_address": "192.168.77.40",
        "ca_path": str(ca), "ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
        "peer_fixture": {"sha256": "a" * 64}, "rewired_runtime": {"sha256": "b" * 64},
    }
    fixture = {
        "peer_cidr": "192.168.77.1/24", "lease_address": "192.168.77.10",
        "appliance_mac": "00:50:56:aa:bb:cc", "appliance_vmx": "owned.vmx",
        "lan_segment_receipt_sha256": "c" * 64,
    }
    topology = {"trust_model": "trusted-host", "kind": "certificate-trusted-host-topology"}

    class FakeHTTPS:
        def __init__(self, host: str, **kwargs: object):
            """Initialize the fake HTTPS connection.

            Args:
                host: Expected appliance management address.
                **kwargs: Connection options supplied by the proof client.
            """
            assert host == "192.168.77.30"

        def request(self, method: str, path: str) -> None:
            """Validate the native API request for this fixture.

            Args:
                method: HTTP method selected by the proof client.
                path: API path selected by the proof client.
            """
            assert (method, path) == ("GET", "/openapi.json")

        def getresponse(self):
            return type("Response", (), {"status": 200, "read": lambda self, size: b"{}"})()

        def close(self) -> None:
            pass

    class FakeContext:
        minimum_version = None

        def load_verify_locations(self, *, cafile: str) -> None:
            """Validate the CA path passed to the fake TLS context.

            Args:
                cafile: CA certificate path selected by the proof client.
            """
            assert cafile == str(ca)

    monkeypatch.setattr(proof.ssl, "SSLContext", lambda _protocol: FakeContext())
    monkeypatch.setattr(proof, "PeerHTTPSConnection", FakeHTTPS)
    monkeypatch.setattr(proof, "inspect_trusted_host", lambda _plan: topology)
    monkeypatch.setattr(proof, "assert_same_topology", lambda _before, _after: None)
    monkeypatch.setattr(proof, "verify_peer_isolation", lambda _peer: {"authenticated": True})
    monkeypatch.setattr(proof, "verify_peer_tunnel_scope", lambda _peer, addresses: {"local_forwarding_only": True})
    result = proof.read_native(plan, fixture, FakePeer(), FakeAppliance())
    assert result["pr"] == 1074
    assert result["trust_model"] == "trusted-host"
    assert result["address_ownership_state"] == "trusted-host-controlled"
    assert result["trusted_host_topology"] is topology
    assert result["candidate_observation_limit"] == (
        "Controlled lab on a trusted host; adversarial address exclusion is not established."
    )
    assert "exclusive_attachment_state" not in result
    assert "candidate_conflict_state" not in result


@pytest.mark.parametrize(
    "changed",
    [
        "task_id", "intent_task_id", "source_commit", "intent_hash",
        "original_receipt_sha256", "directory_identity", "boot", "pending_intent",
        "mac", "segment",
    ],
)
def test_original_iso_receipts_are_bound_to_task_source_hash_and_directory(
    changed: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISO install intent, boot receipt, source and original directory identity stay bound.

    Args:
        changed: Receipt binding to alter for this refusal case.
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated platform and process stubs.
    """
    from contextlib import contextmanager

    from scripts.completed_task_files import WindowsFiles

    monkeypatch.setattr(WindowsFiles, "__init__", lambda self: None)
    monkeypatch.setattr(proof.subprocess, "run", lambda args, **_kwargs:
                        SimpleNamespace(returncode=int("9" * 40 in args)))

    vmx = str(tmp_path / "appliance.vmx")
    root = str(tmp_path)
    intent = {
        "schema": 1, "phase": "installation-pending", "task_id": "task", "repository": "mdaneri/Atlaso",
        "pull_request_number": 1074, "vmx_path": vmx, "output_directory": root, "source_commit": "a" * 40,
    }
    ownership = {
        "schema": 1, "phase": "original-installation-vm-created", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pull_request_number": 1074, "vmx_path": vmx,
        "output_directory": root, "source_commit": "a" * 40, "intent_sha256": "b" * 64,
        "installation_iso": {"sha256": "c" * 64}, "original_identities": {"directory": "00000001:0000000200000003"},
    }
    boot = {
        "schema": 1, "phase": "installation-boot-without-media", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pull_request_number": 1074, "vmx_path": vmx,
        "output_directory": root, "source_commit": "a" * 40,
        "original_receipt_sha256": "d" * 64, "original_receipt_path": "original-ownership.json",
    }
    boot_ref = {"path": "staged/boot.json", "original_path": "original/boot.json", "sha256": "f" * 64}
    plan = {
        "task_id": "task", "pr": 1074, "trust_model": "trusted-host", "source_commit": "e" * 40,
        "appliance_intent": {"sha256": "b" * 64},
        "appliance_installed_boot": boot_ref,
        "iso_private_lan_rewire": {"path": "staged/transition.json", "original_path": "original/transition.json", "sha256": "g" * 64},
        "iso_private_lan_intent": {"path": "staged/pending.json", "original_path": "original/pending.json", "sha256": "h" * 64},
        "mac": "00:50:56:aa:bb:cc",
        "trusted_host": {
            "segment_id": "segment-1",
            "appliance_private_adapter": {"mac": "00:50:56:aa:bb:cc"},
        },
    }
    reference = {"sha256": "d" * 64, "path": "staged/ownership.json", "original_path": "original/ownership.json"}
    transition = {
        "schema": 1, "phase": "installation-private-lan-rewire", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pull_request_number": 1074, "vmx_path": vmx,
        "output_directory": root, "original_receipt_sha256": "d" * 64,
        "original_receipt_path": "original/ownership.json", "boot_receipt_sha256": "f" * 64,
        "boot_receipt_path": "original/boot.json", "original_directory_identity": ownership["original_identities"]["directory"],
        "mac": "00:50:56:aa:bb:cc", "segment_id": "segment-1",
        "intent_sha256": "h" * 64, "intent_path": "original/pending.json", "source_commit": "a" * 40,
    }
    pending = {
        **{key: value for key, value in transition.items() if key not in {"phase", "intent_sha256", "intent_path"}},
        "phase": "installation-private-lan-rewire-pending", "source_commit": "a" * 40,
    }
    values = {
        id(boot_ref): boot, id(plan["iso_private_lan_rewire"]): transition,
        id(plan["iso_private_lan_intent"]): pending,
    }

    @contextmanager
    def opened(_self, _path, directory=False):
        """Return a stable synthetic directory identity.

        Args:
            _self: Patched WindowsFiles instance, unused by this fixture.
            _path: Synthetic appliance directory selected by the proof.
            directory: Whether the proof requested directory identity.
        """
        assert directory is True
        yield None, (1, 2, 3), None

    monkeypatch.setattr(proof, "bound_json", lambda ref: values[id(ref)] if id(ref) in values else intent)
    monkeypatch.setattr(WindowsFiles, "opened", opened)
    if changed == "task_id":
        boot["task_id"] = "other-task"
    elif changed == "intent_task_id":
        intent["task_id"] = "other-task"
    elif changed == "source_commit":
        boot["source_commit"] = "9" * 40
    elif changed == "intent_hash":
        ownership["intent_sha256"] = "9" * 64
    elif changed == "original_receipt_sha256":
        boot["original_receipt_sha256"] = "9" * 64
    elif changed == "directory_identity":
        ownership["original_identities"]["directory"] = "00000001:0000000200000004"
    elif changed == "boot":
        transition["boot_receipt_sha256"] = "9" * 64
    elif changed == "pending_intent":
        transition["intent_sha256"] = "9" * 64
    elif changed == "mac":
        transition["mac"] = "00:50:56:aa:bb:cd"
    else:
        pending["segment_id"] = "other-segment"
    with pytest.raises(proof.Refusal):
        proof.original_iso_vm(plan, intent, ownership, reference, Path(root), vmx)


def test_original_iso_receipt_accepts_distinct_plan_and_installed_source_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reviewed source and the installed ISO source are separate, validated identities.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated platform and process stubs.
    """
    from contextlib import contextmanager

    from scripts.completed_task_files import WindowsFiles

    monkeypatch.setattr(WindowsFiles, "__init__", lambda self: None)
    monkeypatch.setattr(proof.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))

    vmx, root = str(tmp_path / "appliance.vmx"), str(tmp_path)
    intent = {"schema": 1, "phase": "installation-pending", "task_id": "task", "repository": "mdaneri/Atlaso",
              "pull_request_number": 1074, "vmx_path": vmx, "output_directory": root, "source_commit": "a" * 40}
    ownership = {"schema": 1, "phase": "original-installation-vm-created", "task_id": "task",
                 "repository": "mdaneri/Atlaso", "pull_request_number": 1074, "vmx_path": vmx,
                 "output_directory": root, "source_commit": "a" * 40, "intent_sha256": "b" * 64,
                 "installation_iso": {"sha256": "c" * 64}, "original_identities": {"directory": "00000001:0000000200000003"}}
    boot = {"schema": 1, "phase": "installation-boot-without-media", "task_id": "task",
            "repository": "mdaneri/Atlaso", "pull_request_number": 1074, "vmx_path": vmx,
            "output_directory": root, "source_commit": "a" * 40, "original_receipt_sha256": "d" * 64,
            "original_receipt_path": "original/ownership.json"}
    boot_ref = {"path": "staged/boot.json", "original_path": "original/boot.json", "sha256": "f" * 64}
    transition_ref = {"path": "staged/transition.json", "original_path": "original/transition.json", "sha256": "g" * 64}
    pending_ref = {"path": "staged/pending.json", "original_path": "original/pending.json", "sha256": "h" * 64}
    plan = {"task_id": "task", "pr": 1074, "trust_model": "trusted-host", "source_commit": "e" * 40,
            "appliance_intent": {"sha256": "b" * 64}, "appliance_installed_boot": boot_ref,
            "iso_private_lan_rewire": transition_ref, "iso_private_lan_intent": pending_ref,
            "mac": "00:50:56:aa:bb:cc",
            "trusted_host": {"segment_id": "segment-1", "appliance_private_adapter": {"mac": "00:50:56:aa:bb:cc"}}}
    reference = {"sha256": "d" * 64, "path": "staged/ownership.json", "original_path": "original/ownership.json"}
    common = {
        "schema": 1, "task_id": "task", "repository": "mdaneri/Atlaso", "pull_request_number": 1074,
        "vmx_path": vmx, "output_directory": root,
        "original_receipt_sha256": "d" * 64, "original_receipt_path": "original/ownership.json",
        "boot_receipt_sha256": "f" * 64, "boot_receipt_path": "original/boot.json",
        "original_directory_identity": ownership["original_identities"]["directory"],
        "mac": "00:50:56:aa:bb:cc", "segment_id": "segment-1", "source_commit": "a" * 40,
    }
    transition = {**common, "phase": "installation-private-lan-rewire",
                  "intent_sha256": "h" * 64, "intent_path": "original/pending.json"}
    pending = {**common, "phase": "installation-private-lan-rewire-pending"}

    @contextmanager
    def opened(_self, _path, directory=False):
        """Return a stable synthetic directory identity.

        Args:
            _self: Patched WindowsFiles instance, unused by this fixture.
            _path: Synthetic appliance directory selected by the proof.
            directory: Whether the proof requested directory identity.
        """
        yield None, (1, 2, 3), None

    values = {id(boot_ref): boot, id(transition_ref): transition, id(pending_ref): pending}
    monkeypatch.setattr(proof, "bound_json", lambda ref: values[id(ref)])
    monkeypatch.setattr(WindowsFiles, "opened", opened)
    assert proof.original_iso_vm(plan, intent, ownership, reference, Path(root), vmx) is ownership
    # Exercise the outer fixture gate too: its peer and LAN were created after
    # the original ISO appliance. Do not stub either VM's receipt admission.
    peer_vmx = str(tmp_path / "peer.vmx")
    plan["appliance_intent"]["path"] = "staged/appliance-intent.json"
    plan["appliance_ownership"] = reference
    peer_intent_ref = {"path": "staged/peer-intent.json", "sha256": "1" * 64}
    peer_owner_ref = {"path": "staged/peer-owner.json", "sha256": "2" * 64}
    fixture_ref = {"path": str(tmp_path / "fixture.json"), "sha256": "3" * 64}
    identity_ref = {"path": str(tmp_path / "peer-identity.json"), "sha256": "4" * 64}
    segment_ref = {"path": "staged/segment.json", "sha256": "5" * 64}
    peer_intent = {"schema": 1, "kind": "vm-creation-intent", "task_id": "task",
                   "repository": "mdaneri/Atlaso", "pr": 1074, "path": peer_vmx,
                   "root_path": root, "source_commit": plan["source_commit"]}
    peer_owner = {**peer_intent, "kind": "vm", "intent_sha256": peer_intent_ref["sha256"],
                  "root_identity": [1, 2, 3]}
    fixture = {
        "schema": 1, "kind": "certificate-dhcp-peer-fixture", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pr": 1074, "address_ownership_state": "awaiting-live-readback",
        "source_commit": plan["source_commit"], "private_network": "lan:private",
        "appliance_vmx": vmx, "peer_vmx": peer_vmx, "appliance_mac": plan["mac"],
        "appliance_ownership_sha256": reference["sha256"], "peer_ownership_sha256": peer_owner_ref["sha256"],
        "client_vmdk_copy": str(Path(peer_vmx).with_suffix(".vmdk")), "client_vmdk_copy_identity": "disk-id",
        "client_vmdk_source": "source.vmdk", "client_vmdk_sha256": "6" * 64,
        "client_vmdk_copy_preboot_sha256": "6" * 64, "ssh_public_key": "ssh-ed25519 " + "A" * 44,
        "lan_segment_receipt": segment_ref["path"], "lan_segment_receipt_sha256": segment_ref["sha256"],
        "lan_segment_id": "segment-1", "management_network": "vmnet8",
    }
    segment = {"schema": 1, "task_id": "task", "repository": "mdaneri/Atlaso", "pr": 1074,
               "source_commit": plan["source_commit"], "name": "private", "pvn_id": "segment-1"}
    identity = {
        "schema": 1, "kind": "certificate-peer-original-identity", "task_id": "task",
        "repository": "mdaneri/Atlaso", "pr": 1074, "peer_vmx": peer_vmx,
        "peer_ownership_sha256": peer_owner_ref["sha256"], "peer_fixture_sha256": fixture_ref["sha256"],
        "client_vmdk_copy_identity": "disk-id", "ssh_public_key": fixture["ssh_public_key"],
        "management_network": "vmnet8", "management_address": "192.168.167.42",
        "ssh_host_key": "SHA256:" + "A" * 43, "ssh_user": "alpine",
        "observation": "owned-vmware-tools-and-agent-ssh-after-management-restart",
    }
    plan.update(peer_intent=peer_intent_ref, peer_ownership=peer_owner_ref, peer_fixture=fixture_ref,
                peer_identity=identity_ref, resource_source_commit=ownership["source_commit"],
                peer_transport={"host": identity["management_address"], "ssh_host_key": identity["ssh_host_key"],
                                "user": "alpine", "ssh_public_key": fixture["ssh_public_key"]})
    receipts = {plan["appliance_intent"]["path"]: intent, reference["path"]: ownership,
                peer_intent_ref["path"]: peer_intent, peer_owner_ref["path"]: peer_owner,
                fixture_ref["path"]: fixture, identity_ref["path"]: identity, segment_ref["path"]: segment,
                boot_ref["path"]: boot, transition_ref["path"]: transition, pending_ref["path"]: pending}
    monkeypatch.setattr(proof, "bound_json", lambda ref: receipts[ref["path"]])
    monkeypatch.setattr(proof, "file_digest", lambda path: "6" * 64)
    monkeypatch.setattr(WindowsFiles, "mutable_file_identity", lambda self, path: "disk-id")
    monkeypatch.setattr(proof, "vmx_adapter", lambda path, index: (
        {"connectiontype": "custom", "vnet": "vmnet8"} if path == peer_vmx and index == 0
        else {"connectiontype": "pvn", "pvnid": "segment-1", "address": plan["mac"]}))
    assert proof.admit_fixture(plan) is fixture
    assert ownership["source_commit"] == "a" * 40
    for record in (peer_intent, peer_owner, fixture, segment):
        assert record["source_commit"] == "e" * 40
    plan["resource_source_commit"] = "f" * 40
    with pytest.raises(proof.Refusal, match="original_iso_creation_source_mismatch"):
        proof.admit_fixture(plan)
    plan["resource_source_commit"] = ownership["source_commit"]
    peer_intent["source_commit"] = peer_owner["source_commit"] = "f" * 40
    with pytest.raises(proof.Refusal, match="fixture_original_vm_mismatch"):
        proof.admit_fixture(plan)
    peer_intent["source_commit"] = peer_owner["source_commit"] = plan["source_commit"]
    # Installation can finish after the harness advances; preserve both original
    # resource and later boot receipt source identities without relabelling either.
    boot["source_commit"] = plan["source_commit"]
    assert proof.original_iso_vm(plan, intent, ownership, reference, Path(root), vmx) is ownership
    boot["source_commit"] = "unreviewed"
    with pytest.raises(proof.Refusal, match="original_iso_boot_source_invalid"):
        proof.original_iso_vm(plan, intent, ownership, reference, Path(root), vmx)
    # The boot receipt can share the creation commit without proving that either
    # belongs to the current harness. Bootstrap must reject this before access.
    boot["source_commit"] = ownership["source_commit"]
    calls = []

    def unrelated_source(arguments, **kwargs):
        """Reject ancestry for a resource not reviewed by the plan.

        Args:
            arguments: Git arguments issued by the source-admission check.
            **kwargs: Process options supplied by the source-admission check.
        """
        calls.append(arguments)
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(proof.subprocess, "run", unrelated_source)
    monkeypatch.setattr(WindowsFiles, "opened", lambda *args, **kwargs: pytest.fail("unrelated source reached live VM admission"))
    with pytest.raises(proof.Refusal, match="original_iso_source_not_reviewed_ancestor"):
        proof.admit_fixture(plan)
    assert calls[0][-4:] == ["merge-base", "--is-ancestor", ownership["source_commit"], plan["source_commit"]]


@pytest.mark.parametrize("fault", [None, "approval", "public_key", "owner", "ciphertext", "legacy"])
def test_protected_peer_key_requires_original_exception_binding(monkeypatch: pytest.MonkeyPatch, fault: str | None) -> None:
    """Refuse substitute credentials and legacy-mode exception reuse.

    Args:
        monkeypatch: Replaces immutable receipt reads without filesystem or guest access.
        fault: Independent approval, credential, resource, or trust-boundary mismatch.
    """
    fixture = {"peer_vmx": "peer.vmx", "peer_ownership_sha256": "o" * 64, "ssh_public_key": "ssh-ed25519 fixture"}
    plan = {"task_id": "task", "repository": "mdaneri/Atlaso", "pr": 1085,
            "source_commit": "a" * 40, "trust_model": "trusted-host",
            "peer_transport": {"authentication_mode": "dpapi-task-key"},
            "peer_key": {"path": "protected.dpapi", "sha256": "k" * 64},
            "peer_key_authorization": {"path": "approval.json", "sha256": "p" * 64},
            "peer_key_creation": {"path": "creation.json", "sha256": "c" * 64}}
    common = {"schema": 1, "task_id": "task", "repository": "mdaneri/Atlaso", "pr": 1085,
              "source_commit": "a" * 40, "peer_vmx": "peer.vmx", "peer_ownership_sha256": "o" * 64,
              "key_path": "protected.dpapi"}
    approval = dict(common, kind="certificate-peer-key-authorization", maintainer_approved=True,
                    credential_policy_exception="task-only-current-user-dpapi-peer-ssh-key")
    creation = dict(common, kind="certificate-peer-protected-key-created", authorization_sha256="p" * 64,
                    key_sha256="k" * 64, ssh_public_key=fixture["ssh_public_key"])
    if fault == "approval":
        approval["maintainer_approved"] = False
    elif fault == "public_key":
        creation["ssh_public_key"] = "ssh-ed25519 replacement"
    elif fault == "owner":
        creation["peer_ownership_sha256"] = "different"
    elif fault == "ciphertext":
        creation["key_sha256"] = "different"
    elif fault == "legacy":
        plan["trust_model"] = "independent"
    monkeypatch.setattr(proof, "bound_json", lambda reference: approval if reference["path"] == "approval.json" else creation)
    if fault:
        with pytest.raises(proof.Refusal):
            proof.admit_peer_key(plan, fixture)
    else:
        proof.admit_peer_key(plan, fixture)
