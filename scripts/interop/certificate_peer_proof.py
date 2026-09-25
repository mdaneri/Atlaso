#!/usr/bin/env python3
"""Prove private eth0 address control from original receipts and live peers.

This read-only producer records only allowlisted public facts. Credentials are
received from the bounded child environment and held in memory; neither guest configuration nor Atlaso
desired state is changed here.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from certificate_peer_transport import (  # noqa: E402 - The pinned sibling module lives beside this script.
    PeerHTTPSConnection,
    PeerTransportRefusal,
    PinnedApplianceSession,
    PinnedPeerTransport,
)


class Refusal(Exception):
    """Fixed non-secret reason that prevents any controlled-address claim."""


def digest(payload: bytes) -> str:
    """Return a canonical lowercase SHA-256 digest.

    Args:
        payload: Bytes included in the digest."""
    return hashlib.sha256(payload).hexdigest()


def file_digest(path: Path) -> str:
    """Hash a large source disk without loading it into memory.

    Args:
        path: Path to the resource being inspected."""
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def bound_json(reference: dict) -> dict:
    """Read one immutable receipt against an independent digest reference.

    Args:
        reference: Receipt reference to validate."""
    expected = reference.get("sha256", "").lower()
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise Refusal("receipt_digest_invalid")
    path = Path(reference["path"])
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
        raise Refusal("unsafe_receipt_reference")
    payload = path.read_bytes()
    if digest(payload) != expected:
        raise Refusal("receipt_digest_changed")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise Refusal("receipt_shape_invalid")
    return value


def original_vm(plan: dict, role: str, vmx_path: str) -> dict:
    """Bind live VM directory to a receipt made before VM creation.

    Args:
        plan: Validated task plan bound to the owned test resources.
        role: Role used by this operation.
        vmx_path: VMware configuration path for the owned VM."""
    intent_reference = plan[f"{role}_intent"]
    ownership_reference = plan[f"{role}_ownership"]
    intent = bound_json(intent_reference)
    ownership = bound_json(ownership_reference)
    root = Path(vmx_path).parent
    if (
        intent.get("schema") != 1
        or intent.get("kind") != "vm-creation-intent"
        or ownership.get("schema") != 1
        or ownership.get("kind") != "vm"
        or ownership.get("intent_sha256") != intent_reference["sha256"]
        or any(item.get("task_id") != plan["task_id"] for item in (intent, ownership))
        or any(item.get("repository") != "mdaneri/Atlaso" or item.get("pr") != 871 for item in (intent, ownership))
        or any(item.get("path") != vmx_path or item.get("root_path") != str(root) for item in (intent, ownership))
        or intent.get("source_commit") != ownership.get("source_commit")
    ):
        raise Refusal("original_vm_binding_mismatch")
    from scripts.completed_task_files import WindowsFiles

    with WindowsFiles().opened(root, directory=True) as (_, identity, _):
        if list(identity) != ownership.get("root_identity"):
            raise Refusal("original_vm_directory_changed")
    return ownership


def vmx_adapter(path: str, index: int) -> dict[str, str]:
    """Read a VMX adapter's identity fields without changing VMware state.

    Args:
        path: Path to the resource being inspected.
        index: Index used by this operation."""
    prefix = f"ethernet{index}."
    values: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.fullmatch(r'\s*(ethernet[01]\.[A-Za-z]+)\s*=\s*"([^"]*)"\s*', line, re.IGNORECASE)
        if match and match.group(1).lower().startswith(prefix):
            key = match.group(1).lower()[len(prefix) :]
            if key in values:
                raise Refusal("vmx_adapter_duplicate_key")
            values[key] = match.group(2)
    return values


def admit_receipts(plan: dict) -> tuple[dict, dict]:
    """Pin original VM/LAN creation, bootstrap deployment and rewire chain.

    Args:
        plan: Validated task plan bound to the owned test resources."""
    fixture = bound_json(plan["peer_fixture"])
    if (
        fixture.get("schema") != 1
        or fixture.get("kind") != "certificate-dhcp-peer-fixture"
        or fixture.get("task_id") != plan["task_id"]
        or fixture.get("repository") != "mdaneri/Atlaso"
        or fixture.get("pr") != 871
        or fixture.get("address_ownership_state") != "awaiting-live-readback"
        or not fixture.get("private_network", "").startswith("lan:")
    ):
        raise Refusal("peer_fixture_invalid")
    appliance = original_vm(plan, "appliance", fixture["appliance_vmx"])
    peer = original_vm(plan, "peer", fixture["peer_vmx"])
    from scripts.completed_task_files import FileRefusal, WindowsFiles

    copy_path = Path(str(fixture.get("client_vmdk_copy") or ""))
    if copy_path != Path(fixture["peer_vmx"]).with_suffix(".vmdk"):
        raise Refusal("fixture_copied_disk_path_invalid")
    try:
        copy_identity = WindowsFiles().mutable_file_identity(copy_path)
    except (FileRefusal, OSError) as exc:
        raise Refusal("fixture_copied_disk_identity_unavailable") from exc
    if (
        appliance.get("source_commit") != fixture["source_commit"]
        or peer.get("source_commit") != fixture["source_commit"]
        or plan["appliance_ownership"]["sha256"] != fixture["appliance_ownership_sha256"]
        or plan["peer_ownership"]["sha256"] != fixture["peer_ownership_sha256"]
        or file_digest(Path(fixture["client_vmdk_source"])) != fixture["client_vmdk_sha256"]
        or fixture.get("client_vmdk_copy_preboot_sha256") != fixture["client_vmdk_sha256"]
        or copy_identity != fixture.get("client_vmdk_copy_identity")
        or not str(fixture.get("ssh_public_key", "")).startswith("ssh-ed25519 ")
    ):
        raise Refusal("fixture_original_vm_mismatch")
    segment = bound_json(
        {"path": fixture["lan_segment_receipt"], "sha256": fixture["lan_segment_receipt_sha256"]}
    )
    if (
        segment.get("schema") != 1
        or segment.get("task_id") != plan["task_id"]
        or segment.get("repository") != "mdaneri/Atlaso"
        or segment.get("pr") != 871
        or segment.get("source_commit") != fixture["source_commit"]
        or segment.get("name") != fixture["private_network"][4:]
        or segment.get("pvn_id") != fixture["lan_segment_id"]
    ):
        raise Refusal("original_lan_segment_invalid")
    appliance_adapter = vmx_adapter(fixture["appliance_vmx"], 0)
    peer_adapter = vmx_adapter(fixture["peer_vmx"], 1)
    if any(
        adapter.get("connectiontype") != "pvn" or adapter.get("pvnid") != segment["pvn_id"]
        for adapter in (appliance_adapter, peer_adapter)
    ) or appliance_adapter.get("address", "").lower() != fixture["appliance_mac"].lower():
        raise Refusal("private_vmx_topology_mismatch")
    bootstrap = bound_json(plan["bootstrap_runtime"])
    rewire_intent = bound_json(plan["rewire_intent"])
    rewire = bound_json(plan["rewired_runtime"])
    identity_reference = plan["peer_identity"]
    if Path(identity_reference["path"]) != Path(plan["peer_fixture"]["path"]).parent / "peer-identity.json":
        raise Refusal("peer_identity_location_invalid")
    identity = bound_json(identity_reference)
    transport = plan["peer_transport"]
    peer_bootstrap_adapter = vmx_adapter(fixture["peer_vmx"], 0)
    if (
        identity.get("schema") != 1
        or identity.get("kind") != "certificate-peer-original-identity"
        or identity.get("task_id") != plan["task_id"]
        or identity.get("repository") != "mdaneri/Atlaso"
        or identity.get("pr") != 871
        or identity.get("peer_vmx") != fixture["peer_vmx"]
        or identity.get("peer_ownership_sha256") != fixture["peer_ownership_sha256"]
        or identity.get("peer_fixture_sha256") != plan["peer_fixture"]["sha256"]
        or identity.get("client_vmdk_copy_identity") != fixture.get("client_vmdk_copy_identity")
        or identity.get("ssh_public_key") != fixture.get("ssh_public_key")
        or transport.get("ssh_public_key") != fixture.get("ssh_public_key")
        or identity.get("observation") != "owned-vmware-tools-and-agent-ssh-after-management-restart"
        or identity.get("management_network") != fixture.get("management_network")
        or peer_bootstrap_adapter.get("connectiontype", "").lower() != "custom"
        or peer_bootstrap_adapter.get("vnet") != fixture.get("management_network")
        or transport.get("host") != identity.get("management_address")
        or transport.get("ssh_host_key") != identity.get("ssh_host_key")
        or transport.get("user") != identity.get("ssh_user")
        or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", identity.get("ssh_host_key", ""))
    ):
        raise Refusal("peer_original_identity_mismatch")
    try:
        if ipaddress.IPv4Address(identity["management_address"]).is_private is not True:
            raise Refusal("peer_original_address_not_private")
    except ipaddress.AddressValueError:
        raise Refusal("peer_original_address_invalid") from None
    if (
        bootstrap.get("schema") != 1
        or bootstrap.get("vmx_path") != fixture["appliance_vmx"]
        or bootstrap.get("vm_ownership_sha256") != fixture["appliance_ownership_sha256"]
        or rewire_intent.get("kind") != "certificate-management-rewire-intent"
        or rewire_intent.get("bootstrap_runtime_sha256") != plan["bootstrap_runtime"]["sha256"]
        or rewire_intent.get("peer_fixture_sha256") != plan["peer_fixture"]["sha256"]
        or rewire_intent.get("peer_identity_sha256") != identity_reference["sha256"]
        or rewire.get("kind") != "certificate-rewired-runtime"
        or rewire.get("rewire_intent_sha256") != plan["rewire_intent"]["sha256"]
        or rewire.get("peer_identity_sha256") != identity_reference["sha256"]
        or rewire.get("bootstrap_runtime_sha256") != plan["bootstrap_runtime"]["sha256"]
        or rewire.get("predeployment_sha256") != bootstrap.get("predeployment_sha256")
        or not re.fullmatch(r"[0-9a-f]{64}", str(rewire.get("predeployment_sha256") or ""))
        or rewire.get("vmx_path") != fixture["appliance_vmx"]
        or rewire.get("interface") != "eth0"
        or rewire.get("mac", "").lower() != fixture["appliance_mac"].replace(":", "-").lower()
        or rewire.get("observed_address") != fixture["lease_address"]
        or rewire.get("address_ownership_state") != "unproven"
        or bootstrap.get("deployed_commit") != plan["deployed_commit"]
        or rewire.get("deployed_commit") != plan["deployed_commit"]
    ):
        raise Refusal("runtime_rewire_chain_invalid")
    # The available VMX/lease evidence cannot enumerate every current PVN
    # attachment or detect a static-address/MAC impostor on that segment.
    # Refuse both the no-credential preflight and any handoff admission until
    # a supported native producer supplies those independent observations.
    raise Refusal("exclusive_private_lan_and_candidate_ownership_unproven")


def read_native(plan: dict, fixture: dict, peer: PinnedPeerTransport, appliance: PinnedApplianceSession) -> dict:
    """Collect native facts; never promote them to exclusive address ownership alone.

    Args:
        plan: Validated task plan bound to the owned test resources.
        fixture: Verified native fixture for this run.
        peer: Pinned private-LAN peer transport.
        appliance: Pinned appliance transport."""
    network = ipaddress.IPv4Interface(fixture["peer_cidr"])
    baseline = str(ipaddress.IPv4Address(plan["baseline_address"]))
    candidate = str(ipaddress.IPv4Address(plan["static_candidate_address"]))
    dhcp = str(ipaddress.IPv4Address(fixture["lease_address"]))
    if len({str(network.ip), baseline, candidate, dhcp}) != 4 or any(
        ipaddress.IPv4Address(value) not in network.network for value in (baseline, candidate, dhcp)
    ):
        raise Refusal("private_candidate_addresses_invalid")
    mac = fixture["appliance_mac"].lower()
    expected_config = [
        "port=0", "interface=eth1", "bind-interfaces", "except-interface=eth0",
        f"dhcp-range={network.network.network_address},static,{network.network.netmask},12h",
        f"dhcp-host={mac},{dhcp},12h", "dhcp-leasefile=/var/lib/misc/dnsmasq.leases",
        "dhcp-authoritative",
    ]
    config = peer.command("cat /etc/dnsmasq.conf").decode("utf-8")
    if config.splitlines() != expected_config:
        raise Refusal("peer_static_only_dhcp_changed")
    if "started" not in peer.command("rc-service dnsmasq status").decode("utf-8"):
        raise Refusal("peer_dhcp_daemon_inactive")
    peer_addr = json.loads(peer.command("ip -j -4 addr show dev eth1"))
    if len(peer_addr) != 1 or not any(
        item.get("local") == str(network.ip) and item.get("prefixlen") == network.network.prefixlen
        for item in peer_addr[0].get("addr_info", [])
    ):
        raise Refusal("peer_private_address_changed")
    leases = peer.command("cat /var/lib/misc/dnsmasq.leases").decode("utf-8").splitlines()
    matching = [line.split() for line in leases if len(line.split()) >= 3 and line.split()[1].lower() == mac]
    if len(matching) != 1 or matching[0][2] != dhcp or int(matching[0][0]) <= time.time():
        raise Refusal("peer_original_mac_lease_expired_or_missing")
    actual_mac = appliance.command("cat /sys/class/net/eth0/address").decode("ascii").strip().lower()
    if actual_mac != mac:
        raise Refusal("appliance_live_eth0_mac_changed")
    addr = json.loads(appliance.command("ip -j -4 addr show dev eth0"))
    if len(addr) != 1 or not any(
        item.get("local") == baseline and item.get("prefixlen") == network.network.prefixlen
        for item in addr[0].get("addr_info", [])
    ):
        raise Refusal("appliance_static_baseline_missing")
    routes = json.loads(appliance.command("ip -j -4 route show dev eth0"))
    if not any(
        route.get("dev") == "eth0" and route.get("prefsrc", route.get("src")) == baseline
        for route in routes
    ):
        raise Refusal("appliance_eth0_route_missing")
    ca_bytes = Path(plan["ca_path"]).read_bytes()
    if digest(ca_bytes) != plan["ca_sha256"].lower() or b"PRIVATE KEY" in ca_bytes or b"-----BEGIN CERTIFICATE-----" not in ca_bytes:
        raise Refusal("public_ca_pin_invalid")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=plan["ca_path"])
    connection = PeerHTTPSConnection(baseline, peer=peer, target_ip=baseline, context=context, timeout=12)
    try:
        connection.request("GET", "/openapi.json")
        response = connection.getresponse()
        if response.status != 200 or len(response.read(2_000_001)) > 2_000_000:
            raise Refusal("peer_routed_baseline_https_failed")
    finally:
        connection.close()
    return {
        "schema": 1, "kind": "certificate-private-address-proof", "phase": "static-baseline-preflight",
        "task_id": plan["task_id"], "repository": "mdaneri/Atlaso", "pr": 871,
        "vmx_path": fixture["appliance_vmx"], "addresses": [candidate, dhcp],
        "address_ownership_state": "unproven",
        "baseline_address": baseline, "baseline_interface": "eth0", "appliance_mac": mac,
        "dhcp_reservation": dhcp, "dhcp_server": str(network.ip),
        "dhcp_lease_observation": "unexpired-before-static-baseline",
        "candidate_observation_limit": "lease and topology do not prove exclusive LAN attachment or absence of static address and MAC conflicts",
        "peer_fixture_sha256": plan["peer_fixture"]["sha256"],
        "rewired_runtime_sha256": plan["rewired_runtime"]["sha256"],
        "lan_segment_receipt_sha256": fixture["lan_segment_receipt_sha256"].lower(),
        "peer_dhcp_config_sha256": digest(config.encode()),
        "ca_sha256": plan["ca_sha256"].lower(),
        "peer_routed_baseline_https": "explicit-ca-and-ip-hostname-verified",
    }


def admit_output(plan: dict, address_path: Path, runtime_path: Path) -> None:
    """Keep new immutable proofs beneath the original task-owned tree.

    Args:
        plan: Validated task plan bound to the owned test resources.
        address_path: Path to the address evidence receipt.
        runtime_path: Path to the runtime evidence receipt."""
    manifest = bound_json(plan["evidence_root_manifest"])
    from scripts.completed_task_files import WindowsFiles

    root = Path(manifest.get("path", ""))
    expected_parent = root / "certificate-native-evidence" / plan["lab_name"]
    if (
        manifest.get("kind") != "generated_tree"
        or manifest.get("task_id") != plan["task_id"]
        or manifest.get("repository") != "mdaneri/Atlaso"
        or address_path.parent != expected_parent
        or runtime_path.parent != expected_parent
        or address_path == runtime_path
        or not expected_parent.is_dir()
    ):
        raise Refusal("original_evidence_root_invalid")
    with WindowsFiles().opened(root, directory=True) as (_, identity, _):
        if list(identity) != manifest.get("root_identity"):
            raise Refusal("original_evidence_root_changed")


def publish(path: Path, value: dict) -> str:
    """Publish one never-replaced, fsynced, allowlisted JSON receipt.

    Args:
        path: Path to the resource being inspected.
        value: Value used by this operation."""
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return digest(encoded)


def main() -> int:
    """Execute read-only original-receipt and native-control checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--address-output", required=True)
    parser.add_argument("--runtime-output", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        if plan.get("schema") != 1 or plan.get("pr") != 871 or not plan.get("task_id"):
            raise Refusal("proof_plan_invalid")
        address_path = Path(args.address_output).resolve(strict=False)
        runtime_path = Path(args.runtime_output).resolve(strict=False)
        admit_output(plan, address_path, runtime_path)
        fixture, rewire = admit_receipts(plan)
        if args.preflight_only:
            print(json.dumps({"success": True, "stage": "original_receipts_admitted_no_network"}))
            return 0
        admin_password = os.environ.pop("ATLASO_NATIVE_ADMIN", None)
        if not admin_password or len(admin_password) < 12 or admin_password != admin_password.strip():
            raise Refusal("bounded_credential_bridge_required")
        peer_plan = plan["peer_transport"]
        with PinnedPeerTransport(
            peer_plan["host"], peer_plan["user"], peer_plan["ssh_public_key"],
            peer_plan["ssh_host_key"], peer_plan["private_subnet"],
        ) as peer:
            with PinnedApplianceSession(
                peer, plan["baseline_address"], plan["appliance_user"],
                admin_password, plan["appliance_ssh_host_key"],
            ) as appliance:
                proof = read_native(plan, fixture, peer, appliance)
        if (proof.get("address_ownership_state") != "proven-controlled"
                or proof.get("exclusive_attachment_state") != "verified-current"
                or proof.get("candidate_conflict_state") != "clear-current"):
            raise Refusal("exclusive_private_lan_and_candidate_ownership_unproven")
        proof_sha = publish(address_path, proof)
        controlled = dict(rewire)
        controlled.update(
            kind="certificate-controlled-runtime", url=f"https://{plan['baseline_address']}",
            observed_address=plan["baseline_address"], address_ownership_state="proven-controlled",
            address_proof_sha256=proof_sha, rewired_runtime_sha256=plan["rewired_runtime"]["sha256"],
        )
        runtime_sha = publish(runtime_path, controlled)
        print(json.dumps({"address_evidence": {"path": str(address_path), "sha256": proof_sha},
                          "runtime_evidence": {"path": str(runtime_path), "sha256": runtime_sha}}))
        return 0
    except (Refusal, PeerTransportRefusal, OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        reason = str(exc) if isinstance(exc, (Refusal, PeerTransportRefusal)) else "proof_input_or_readback_invalid"
        print(json.dumps({"success": False, "reason": reason}))
        return 2


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    sys.exit(main())
