#!/usr/bin/env python3
"""Prove private eth0 address control from original receipts and live peers.

This read-only producer records only allowlisted public facts. Credentials are
received from the bounded child environment and held in memory; neither guest configuration nor Atlaso
desired state is changed here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
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
from certificate_retirement import (
    Refusal as RetirementRefusal,  # noqa: E402 - Pinned sibling module.
)
from certificate_retirement import (
    verify_peer_isolation,  # noqa: E402 - Pinned sibling module.
)
from certificate_trusted_host import (
    Refusal as HostRefusal,  # noqa: E402 - Pinned sibling module.
)
from certificate_trusted_host import (  # noqa: E402 - Pinned sibling module.
    assert_same_topology,
    inspect_trusted_host,
)


class Refusal(Exception):
    """Fixed non-secret reason that prevents any controlled-address claim."""


def plan_pr(plan: dict) -> int:
    """Select a positive task PR only for explicit trusted-host admission.

    Args:
        plan: Original task-bound certificate plan.
    """
    number = plan.get("pr", 871)
    if (not isinstance(number, int) or isinstance(number, bool) or number <= 0
            or (plan.get("trust_model") != "trusted-host" and number != 871)):
        raise Refusal("proof_plan_invalid")
    return number


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
    if plan.get("trust_model") == "trusted-host" and role == "appliance" and ownership.get("phase") == "original-installation-vm-created":
        return original_iso_vm(plan, intent, ownership, ownership_reference, root, vmx_path)
    if (
        intent.get("schema") != 1
        or intent.get("kind") != "vm-creation-intent"
        or ownership.get("schema") != 1
        or ownership.get("kind") != "vm"
        or ownership.get("intent_sha256") != intent_reference["sha256"]
        or any(item.get("task_id") != plan["task_id"] for item in (intent, ownership))
        or any(item.get("repository") != "mdaneri/Atlaso" or item.get("pr") != plan_pr(plan) for item in (intent, ownership))
        or any(item.get("path") != vmx_path or item.get("root_path") != str(root) for item in (intent, ownership))
        or intent.get("source_commit") != ownership.get("source_commit")
    ):
        raise Refusal("original_vm_binding_mismatch")
    from scripts.completed_task_files import WindowsFiles

    with WindowsFiles().opened(root, directory=True) as (_, identity, _):
        if list(identity) != ownership.get("root_identity"):
            raise Refusal("original_vm_directory_changed")
    return ownership


def original_iso_vm(plan: dict, intent: dict, ownership: dict, reference: dict, root: Path, vmx: str) -> dict:
    """Admit original installer receipts without relabelling their identity.

    Args:
        plan: Task-bound plan containing the original installed-boot reference.
        intent: Original pre-creation installation intent.
        ownership: Original installation VM receipt.
        reference: Independently preserved original ownership path and digest.
        root: Exact recorded VM directory.
        vmx: Exact recorded VMX path.
    """
    boot = bound_json(plan["appliance_installed_boot"])
    transition = bound_json(plan["iso_private_lan_rewire"])
    transition_intent = bound_json(plan["iso_private_lan_intent"])
    for record in (intent, ownership, boot):
        if (record.get("schema") != 1 or record.get("task_id") != plan["task_id"]
                or record.get("repository") != "mdaneri/Atlaso"
                or record.get("pull_request_number") != plan_pr(plan)
                or record.get("vmx_path") != vmx or record.get("output_directory") != str(root)
                or (record is not boot and record.get("source_commit") != ownership.get("source_commit"))):
            raise Refusal("original_iso_vm_binding_mismatch")
    boot_source = boot.get("source_commit", "")
    if not isinstance(boot_source, str) or not re.fullmatch(r"[0-9a-f]{40}", boot_source):
        raise Refusal("original_iso_boot_source_invalid")
    if boot_source not in {ownership.get("source_commit"), plan.get("source_commit")}:
        environment = {key: value for key, value in os.environ.items() if not key.startswith("ATLASO_NATIVE_")}
        ancestry = subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parents[2]), "merge-base", "--is-ancestor", boot_source, plan["source_commit"]],
            capture_output=True, env=environment, timeout=15,
        )
        if ancestry.returncode:
            raise Refusal("original_iso_boot_source_invalid")
    if (intent.get("phase") != "installation-pending"
            or ownership.get("intent_sha256") != plan["appliance_intent"]["sha256"]
            or boot.get("phase") != "installation-boot-without-media"
            or boot.get("original_receipt_sha256") != reference["sha256"]
            or boot.get("original_receipt_path") != reference.get("original_path", reference["path"])
            or not ownership.get("installation_iso", {}).get("sha256")):
        raise Refusal("original_iso_boot_binding_mismatch")
    boot_reference = plan["appliance_installed_boot"]
    intent_reference = plan["iso_private_lan_intent"]
    for record in (transition, transition_intent):
        if (record.get("schema") != 1 or record.get("task_id") != plan["task_id"]
                or record.get("repository") != "mdaneri/Atlaso"
                or record.get("pull_request_number") != plan_pr(plan)
                or record.get("vmx_path") != vmx or record.get("output_directory") != str(root)
                or record.get("original_receipt_sha256") != reference["sha256"]
                or record.get("original_receipt_path") != reference.get("original_path", reference["path"])
                or record.get("boot_receipt_sha256") != boot_reference["sha256"]
                or record.get("boot_receipt_path") != boot_reference.get("original_path", boot_reference["path"])
                or record.get("original_directory_identity") != ownership.get("original_identities", {}).get("directory")
                or record.get("mac") != plan["trusted_host"]["appliance_private_adapter"]["mac"]
                or record.get("segment_id") != plan["trusted_host"]["segment_id"]):
            raise Refusal("original_iso_private_lan_binding_mismatch")
    if (transition.get("phase") != "installation-private-lan-rewire"
            or transition_intent.get("phase") != "installation-private-lan-rewire-pending"
            or transition.get("intent_sha256") != intent_reference["sha256"]
            or transition.get("intent_path") != intent_reference.get("original_path", intent_reference["path"])
            or transition.get("source_commit") != transition_intent.get("source_commit")
            or not re.fullmatch(r"[0-9a-f]{40}", str(transition.get("source_commit", "")))):
        raise Refusal("original_iso_private_lan_intent_mismatch")
    from scripts.completed_task_files import WindowsFiles
    with WindowsFiles().opened(root, directory=True) as (_, identity, _):
        formatted = f"{identity[0]:08X}:{identity[1]:08X}{identity[2]:08X}"
        if formatted != ownership.get("original_identities", {}).get("directory"):
            raise Refusal("original_iso_vm_directory_changed")
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


def admit_fixture(plan: dict) -> dict:
    """Pin original VM/LAN creation and the independently observed peer identity.

    Args:
        plan: Validated task plan bound to the owned test resources."""
    fixture = bound_json(plan["peer_fixture"])
    if (
        fixture.get("schema") != 1
        or fixture.get("kind") != "certificate-dhcp-peer-fixture"
        or fixture.get("task_id") != plan["task_id"]
        or fixture.get("repository") != "mdaneri/Atlaso"
        or fixture.get("pr") != plan_pr(plan)
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
        or segment.get("pr") != plan_pr(plan)
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
    ) or appliance_adapter.get("address", appliance_adapter.get("generatedaddress", "")).lower() != fixture["appliance_mac"].lower():
        raise Refusal("private_vmx_topology_mismatch")
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
        or identity.get("pr") != plan_pr(plan)
        or identity.get("peer_vmx") != fixture["peer_vmx"]
        or identity.get("peer_ownership_sha256") != fixture["peer_ownership_sha256"]
        or identity.get("peer_fixture_sha256") != plan["peer_fixture"]["sha256"]
        or identity.get("client_vmdk_copy_identity") != fixture.get("client_vmdk_copy_identity")
        or identity.get("ssh_public_key") != fixture.get("ssh_public_key")
        or transport.get("ssh_public_key") != fixture.get("ssh_public_key")
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
    if identity.get("observation") == "owned-vmware-console-public-key":
        observation = bound_json(plan["peer_console_observation"])
        public_key = observation.get("public_host_key", "")
        try:
            parts = public_key.split()
            if len(parts) != 2 or parts[0] != "ssh-ed25519":
                raise ValueError()
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(parts[1], validate=True)).digest()).decode().rstrip("=")
        except (ValueError, IndexError):
            raise Refusal("peer_console_identity_invalid") from None
        vmx_text = Path(fixture["peer_vmx"]).read_text(encoding="utf-8-sig")
        paths = re.findall(r'^serial0\.fileName\s*=\s*"([^"\r\n]+)"\s*$', vmx_text, re.MULTILINE)
        if (plan.get("trust_model") != "trusted-host"
                or observation.get("schema") != 1
                or observation.get("kind") != "certificate-peer-console-public-key"
                or observation.get("task_id") != plan["task_id"]
                or observation.get("repository") != "mdaneri/Atlaso"
                or observation.get("pr") != plan_pr(plan)
                or observation.get("peer_vmx") != fixture["peer_vmx"]
                or observation.get("peer_ownership_sha256") != fixture["peer_ownership_sha256"]
                or paths != [observation.get("serial_path")]
                or fingerprint != identity["ssh_host_key"]
                or identity.get("console_observation_sha256") != plan["peer_console_observation"]["sha256"]):
            raise Refusal("peer_console_identity_invalid")
    elif identity.get("observation") != "owned-vmware-tools-and-agent-ssh-after-management-restart":
        raise Refusal("peer_original_identity_mismatch")
    return fixture


def admit_receipts(plan: dict) -> tuple[dict, dict]:
    """Pin the observed fixture, bootstrap runtime and management transition.

    Args:
        plan: Validated task plan bound to the owned test resources.
    """
    fixture = admit_fixture(plan)
    bootstrap = bound_json(plan["bootstrap_runtime"])
    rewire_intent = bound_json(plan["rewire_intent"])
    rewire = bound_json(plan["rewired_runtime"])
    identity_reference = plan["peer_identity"]
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
        or rewire.get("observed_address") != (plan["baseline_address"] if plan.get("trust_model") == "trusted-host" else fixture["lease_address"])
        or rewire.get("address_ownership_state") != "unproven"
        or bootstrap.get("deployed_commit") != plan["deployed_commit"]
        or rewire.get("deployed_commit") != plan["deployed_commit"]
    ):
        raise Refusal("runtime_rewire_chain_invalid")
    if plan.get("trust_model") == "trusted-host":
        host = plan.get("trusted_host", {})
        if (host.get("appliance_vmx") != fixture["appliance_vmx"]
                or host.get("peer_vmx") != fixture["peer_vmx"]
                or host.get("segment_id") != fixture["lan_segment_id"]
                or host.get("segment_receipt") != {"path": fixture["lan_segment_receipt"], "sha256": fixture["lan_segment_receipt_sha256"]}):
            raise Refusal("trusted_host_fixture_binding_mismatch")
        try:
            inspect_trusted_host(plan)
        except HostRefusal:
            raise Refusal("trusted_host_topology_unproven") from None
        return fixture, rewire
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
    trusted = plan.get("trust_model") == "trusted-host"
    topology = inspect_trusted_host(plan) if trusted else None
    isolation = verify_peer_isolation(peer) if trusted else None
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
    result = {
        "schema": 1, "kind": "certificate-private-address-proof", "phase": "static-baseline-preflight",
        "task_id": plan["task_id"], "repository": "mdaneri/Atlaso", "pr": plan_pr(plan),
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
    if trusted:
        assert_same_topology(topology, inspect_trusted_host(plan))
        result.update(trust_model="trusted-host", address_ownership_state="trusted-host-controlled",
                      trusted_host_topology=topology, peer_isolation=isolation,
                      candidate_observation_limit="Controlled lab on a trusted host; adversarial address exclusion is not established.")
    return result


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
        if plan.get("schema") != 1 or not plan.get("task_id") or plan_pr(plan) != plan.get("pr"):
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
        trusted = plan.get("trust_model") == "trusted-host"
        if trusted:
            if proof.get("trust_model") != "trusted-host" or proof.get("address_ownership_state") != "trusted-host-controlled":
                raise Refusal("trusted_host_address_observations_unproven")
        elif (proof.get("address_ownership_state") != "proven-controlled"
                or proof.get("exclusive_attachment_state") != "verified-current"
                or proof.get("candidate_conflict_state") != "clear-current"):
            raise Refusal("exclusive_private_lan_and_candidate_ownership_unproven")
        proof_sha = publish(address_path, proof)
        controlled = dict(rewire)
        controlled.update(
            kind="certificate-controlled-runtime", url=f"https://{plan['baseline_address']}",
            observed_address=plan["baseline_address"], address_ownership_state=proof["address_ownership_state"],
            address_proof_sha256=proof_sha, rewired_runtime_sha256=plan["rewired_runtime"]["sha256"],
        )
        runtime_sha = publish(runtime_path, controlled)
        print(json.dumps({"address_evidence": {"path": str(address_path), "sha256": proof_sha},
                          "runtime_evidence": {"path": str(runtime_path), "sha256": runtime_sha}}))
        return 0
    except (Refusal, HostRefusal, RetirementRefusal, PeerTransportRefusal, OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        reason = str(exc) if isinstance(exc, (Refusal, HostRefusal, RetirementRefusal, PeerTransportRefusal)) else "proof_input_or_readback_invalid"
        print(json.dumps({"success": False, "reason": reason}))
        return 2


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    sys.exit(main())
