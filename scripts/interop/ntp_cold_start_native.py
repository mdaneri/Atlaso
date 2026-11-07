"""Verify a fresh, receipt-bound NTP fixture through ordinary global Apply."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from certificate_fixture_init import FixtureForm, replace_fields
from certificate_handoff_native import (
    Client,
    Page,
    clean_baseline,
    edit,
    saved_fields,
    wait_task,
)
from certificate_handoff_native import Refusal as ClientRefusal
from certificate_iso_bootstrap import guest_python_command, sudo_read, tls_name
from certificate_peer_proof import bound_json, original_vm, publish
from certificate_peer_time import verify_peer_time
from certificate_peer_transport import PinnedApplianceSession, PinnedPeerTransport
from certificate_retirement import verify_peer_isolation, verify_peer_tunnel_scope
from ntp_cold_start_topology import watched_topology
from time_source_guest import apply_review_fields, apply_review_path

_NTP_APPLY_ROOTS = frozenset({"appliance_settings", "network", "ca", "firewall", "public_services", "dnsmasq", "ntpd"})
_NTP_NETWORK_DEPENDENCIES = frozenset({"wan", "nat"})
_NTP_TRANSITION_ROOTS = frozenset({"firewall", "ntpd", "public_services"})


class Refusal(Exception):
    """Fixed public refusal; never include native output or credentials."""


def _new_source_id(used_ids: set[str]) -> str:
    """Allocate a new NTP source row id without colliding with retained rows.

    Args:
        used_ids: Existing source row ids that must remain unchanged.
    """
    for _ in range(8):
        source_id = f"ntp-cold-start-{secrets.token_hex(8)}"
        if source_id not in used_ids:
            return source_id
    raise Refusal("ntp_fixture_source_ids_invalid")


def _address(value: str) -> str:
    """Require an ordinary numeric unicast IPv4 fixture endpoint.

    Args:
        value: Explicit fixture address.
    """
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise Refusal("ntp_fixture_address_invalid") from None
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise Refusal("ntp_fixture_address_invalid")
    return str(address)


def save_ntp(client, address: str, mode: str = "ntp_client") -> dict:
    """Save only NTP desired state using the existing successful form controls.

    Args:
        client: Authenticated CA-validated UI transport.
        address: Admitted real peer or separately admitted unreachable candidate.
        mode: Client or server mode, without selecting a second clock controller.
    """
    address = _address(address)
    if mode not in {"ntp_client", "ntp_server"}:
        raise Refusal("ntp_fixture_mode_invalid")
    _, body = client.request("/ui/management/ntp")
    form = FixtureForm(body, "/ui/management/ntp/settings")
    try:
        sources = json.loads(dict(form.fields)["upstream_sources_json"])
        if not isinstance(sources, list) or not all(isinstance(row, dict) for row in sources):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise Refusal("ntp_fixture_sources_invalid") from None
    matching = [row for row in sources if row.get("source") == address]
    if len(matching) > 1:
        raise Refusal("ntp_fixture_sources_invalid")
    rows = [dict(row, enabled=False) for row in sources if row.get("source") != address]
    existing = matching[0] if matching else {}
    used_ids = {str(row["id"]) for row in rows if row.get("id")}
    existing_id = existing.get("id")
    source_id = str(existing_id) if existing_id else _new_source_id(used_ids)
    if source_id in used_ids:
        raise Refusal("ntp_fixture_source_ids_invalid")
    rows.append({**existing, "id": source_id, "source": address,
                 "enabled": True, "use_nts": False,
                 "description": existing.get("description", "Isolated real NTP acceptance peer")})
    changes = {"enabled": "on" if mode == "ntp_server" else "", "nts_server_enabled": "",
               "time_source": "ntp_client", "upstream_servers": address,
               "upstream_sources_json": json.dumps(rows, separators=(",", ":"))}
    if mode == "ntp_server":
        changes.update(listen_interfaces="eth1", listen_interfaces_present="1", listen_address="192.168.78.10",
                       listen_addresses="192.168.78.10", listen_addresses_present="1")
    fields = replace_fields(form.fields, changes,
                            {"upstream_source", "upstream_enabled", "upstream_use_nts", "upstream_description"})
    _, result = client.json(form.form_action, fields, autosave=True)
    if result.get("valid") is False:
        raise Refusal("ntp_fixture_desired_state_invalid")
    return {"mode": mode, "source": address}


def native_clock(session, password: str, peer_address: str, mode: str = "ntp_client") -> dict:
    """Require genuine selected-peer health, controller exclusion and native guard.

    Args:
        session: Strictly pinned appliance SSH transport.
        password: In-memory sudo credential confined to channel stdin.
        peer_address: Exact admitted real peer.
        mode: Expected applied NTP mode.
    """
    peer_address = _address(peer_address)
    if mode not in {"ntp_client", "ntp_server"}:
        raise Refusal("ntp_fixture_mode_invalid")
    try:
        raw = json.loads(sudo_read(session, "/opt/atlaso/bin/atlaso-helper ntpd status --real", password))
        evidence = raw["synchronization_evidence"]
        selected = evidence["selected"]
        controller = raw["selected_controller"]
        conflicts = raw["daemon_conflicts"]
        guard = raw["client_packet_guard" if mode == "ntp_client" else "server_packet_guard"]
        valid = (raw["mode"] == mode and raw["synchronization"]["healthy"] is True
                 and controller["name"] == "ntpd" and controller["active"] is True
                 and controller["enabled"] is True and guard["active"] is True
                 and set(conflicts) == {"chronyd", "systemd_timesyncd", "vmware_tools"}
                 and all(state["active"] is False and state["enabled"] is False for state in conflicts.values())
                 and evidence["healthy"] is True and evidence["query"] == "ok"
                 and evidence["leap"] == "leap_none" and evidence["source"] == "sync_ntp"
                 and type(evidence["stratum"]) is int and 1 <= evidence["stratum"] <= 15
                 and selected["address"] == peer_address and 1 <= int(selected["stratum"]) <= 14
                 and re.fullmatch(r"[0-7]{1,3}", selected["reach"]) is not None
                 and int(selected["reach"], 8) > 0)
    except (KeyError, TypeError, ValueError):
        raise Refusal("ntp_fixture_native_clock_unverified") from None
    if not valid:
        raise Refusal("ntp_fixture_native_clock_unverified")
    return {"mode": mode, "healthy": True, "leap": "leap_none", "source": "sync_ntp",
            "stratum": evidence["stratum"], "selected": {"address": peer_address,
            "stratum": int(selected["stratum"]), "reach": selected["reach"]},
            "single_controller": True, "packet_guard": True}


def admit_plan(plan: dict) -> dict:
    """Admit the new NTP fixture's own original receipts before authentication.

    Args:
        plan: Public source-pinned lifecycle plan; certificate/ISO plans are refused.
    """
    if (plan.get("schema") != 1 or plan.get("kind") != "ntp-cold-start-native-plan"
            or plan.get("trust_model") != "trusted-host"
            or plan.get("repository") != "mdaneri/Atlaso" or not plan.get("task_id")
            or type(plan.get("pr")) is not int or plan["pr"] <= 0
            or not re.fullmatch(r"[0-9a-f]{40}", str(plan.get("source_commit", "")))
            or plan.get("resource_source_commit") != plan["source_commit"]):
        raise Refusal("ntp_fixture_plan_invalid")
    fixed = {"current_address": "192.168.77.10", "baseline_address": "192.168.77.30",
             "static_candidate_address": "192.168.77.40", "negative_address": "192.168.77.11",
             "peer_address": "192.168.77.1", "private_subnet": "192.168.77.0/24"}
    if any(plan.get(key) != value for key, value in fixed.items()):
        raise Refusal("ntp_fixture_address_plan_invalid")
    reviewed_source(plan)
    fixture = bound_json(plan["peer_fixture"])
    host = plan["trusted_host"]
    if (fixture.get("kind") != "ntp-cold-start-peer-fixture" or fixture.get("schema") != 1
            or any(fixture.get(key) != plan[key] for key in ("task_id", "repository", "pr", "source_commit"))
            or fixture.get("appliance_ownership_sha256") != plan["appliance_ownership"]["sha256"]
            or fixture.get("peer_ownership_sha256") != plan["peer_ownership"]["sha256"]
            or fixture.get("appliance_vmx") != host.get("appliance_vmx")
            or fixture.get("peer_vmx") != host.get("peer_vmx")
            or fixture.get("private_network") != "lan:" + host["segment_name"]
            or fixture.get("lan_segment_id") != host["segment_id"]
            or fixture.get("lan_segment_receipt") != host["segment_receipt"]["path"]
            or fixture.get("lan_segment_receipt_sha256") != host["segment_receipt"]["sha256"]):
        raise Refusal("ntp_fixture_original_binding_invalid")
    peer_identity = bound_json(plan["peer_identity"])
    transport = plan["peer_transport"]
    if (any(peer_identity.get(key) != plan[key] for key in ("task_id", "repository", "pr"))
            or peer_identity.get("peer_vmx") != fixture["peer_vmx"]
            or peer_identity.get("peer_ownership_sha256") != plan["peer_ownership"]["sha256"]
            or peer_identity.get("peer_fixture_sha256") != plan["peer_fixture"]["sha256"]
            or peer_identity.get("management_address") != transport.get("host")
            or peer_identity.get("ssh_host_key") != transport.get("ssh_host_key")
            or peer_identity.get("ssh_public_key") != fixture.get("ssh_public_key")
            or transport.get("ssh_public_key") != fixture.get("ssh_public_key")
            or transport.get("private_subnet") != plan["private_subnet"]
            or peer_identity.get("observation") != "original-vmx-serial-console-and-strict-agent-ssh-after-restart"):
        raise Refusal("ntp_fixture_original_peer_identity_changed")
    for role in ("appliance", "peer"):
        owner = original_vm(plan, role, fixture[role + "_vmx"])
        if owner["source_commit"] != plan["source_commit"]:
            raise Refusal("ntp_fixture_original_source_changed")
        console = bound_json(plan[role + "_console"])
        if (console.get("kind") != "ntp-original-console-identity"
                or any(console.get(key) != plan[key] for key in ("task_id", "repository", "pr", "source_commit"))
                or console.get("vmx") != fixture[role + "_vmx"]):
            raise Refusal("ntp_fixture_console_binding_invalid")
        intent = bound_json({"path": str(Path(plan[role + "_console"]["path"]).with_name(role + "-console-intent.json")),
                             "sha256": console["console_intent_sha256"]})
        if (intent.get("vmx") != console["vmx"]
                or intent.get("vm_ownership_sha256") != plan[role + "_ownership"]["sha256"]
                or intent.get("observation") != "original-vmx-bound-public-serial-console"):
            raise Refusal("ntp_fixture_original_console_missing")
        key = console.get("ssh_public_key", "").split()
        if len(key) != 2 or key[0] != "ssh-ed25519":
            raise Refusal("ntp_fixture_console_pin_invalid")
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(key[1], validate=True)).digest()).decode().rstrip("=")
        expected = plan["appliance_ssh_host_key"] if role == "appliance" else plan["peer_transport"]["ssh_host_key"]
        if fingerprint != console.get("ssh_host_key") or fingerprint != expected:
            raise Refusal("ntp_fixture_console_pin_changed")
    from scripts.completed_task_files import WindowsFiles
    source = bound_json(plan["source_creation"])
    prepared = bound_json(plan["source_prepared"])
    if (source.get("repository") != plan["repository"]
            or any(source.get(key) != plan[key] or prepared.get(key) != plan[key] for key in ("task_id", "pr"))
            or source.get("source_commit") != prepared.get("source_commit")
            or prepared.get("path") != fixture["client_vmdk_source"]
            or prepared.get("sha256") != fixture["client_vmdk_sha256"]
            or fixture.get("client_vmdk_copy_preboot_sha256") != prepared["sha256"]
            or prepared.get("prepared_before_use") is not True or prepared.get("consumer_vms") != []
            or source_digest(Path(prepared["path"])) != prepared["sha256"]):
        raise Refusal("ntp_fixture_source_provenance_changed")
    with WindowsFiles().opened(Path(source["path"]), directory=True) as (_, identity, _):
        if list(identity) != source["root_identity"]:
            raise Refusal("ntp_fixture_original_source_root_changed")
    if WindowsFiles().mutable_file_identity(Path(fixture["client_vmdk_copy"])) != fixture["client_vmdk_copy_identity"]:
        raise Refusal("ntp_fixture_original_peer_disk_changed")
    deployed = bound_json(plan["deployed_runtime"])
    measurement = bound_json(plan["deployment_measurement"])
    helper = hashlib.sha256((Path(__file__).resolve().parents[1] / "appliance/atlaso-helper").read_bytes()).hexdigest()
    for receipt in (deployed, measurement):
        if (receipt.get("deployed_commit") != plan["source_commit"] or receipt.get("helper_sha256") != helper
                or receipt.get("wheel_sha256") != plan["wheel_sha256"]):
            raise Refusal("ntp_fixture_deployed_source_changed")
    if (helper != plan["helper_sha256"] or measurement.get("verified_payload_files", 0) <= 0
            or measurement.get("installed_payload_sha256") != measurement.get("wheel_payload_sha256")
            or hashlib.sha256(Path(plan["ca_path"]).read_bytes()).hexdigest() != plan["ca_sha256"]):
        raise Refusal("ntp_fixture_payload_or_ca_changed")
    retained_wheel_path(plan)
    return fixture


def reviewed_source(plan: dict) -> None:
    """Bind the executing consumer to the clean task checkout's admitted commit.

    Args:
        plan: Lifecycle source identity and original task worktree.
    """
    base = ["git", "-C", str(plan["worktree"])]
    head = subprocess.run([*base, "rev-parse", "HEAD"], capture_output=True, timeout=15, check=True).stdout.decode().strip()
    dirty = subprocess.run([*base, "status", "--porcelain", "--untracked-files=no"], capture_output=True, timeout=15, check=True).stdout
    if head != plan["source_commit"] or dirty:
        raise Refusal("ntp_fixture_reviewed_checkout_changed")
    for relative in ("ntp_cold_start_native.py", "ntp_cold_start_topology.py", "ntp_packet_capture.py"):
        blob = subprocess.run([*base, "cat-file", "blob", head + ":scripts/interop/" + relative],
                              capture_output=True, timeout=15, check=True).stdout
        if blob != Path(__file__).with_name(relative).read_bytes():
            raise Refusal("ntp_fixture_executing_consumer_changed")


def source_digest(path: Path) -> str:
    """Hash the pinned 2-GiB source disk without loading it into memory.

    Args:
        path: Originally prepared and pinned peer VMDK.
    """
    if path.stat().st_size > 2 * 1024**3:
        raise Refusal("ntp_fixture_source_disk_exceeds_bound")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def retained_wheel_path(plan: dict) -> str:
    """Admit the original pre-reboot wheel retention intent and measured result.

    Args:
        plan: Source-pinned plan with original appliance and deployment receipts.
    """
    wheel = plan["wheel_name"]
    if re.fullmatch(r"atlaso-[A-Za-z0-9_.+-]+\.whl", wheel) is None:
        raise Refusal("ntp_fixture_wheel_name_invalid")
    path = "/var/lib/atlaso/ntp-acceptance/" + wheel
    retained = bound_json(plan["retained_wheel"])
    intent = bound_json({
        "path": str(Path(plan["retained_wheel"]["path"]).with_name("ntp-wheel-retention-intent.json")),
        "sha256": retained["retention_intent_sha256"],
    })
    common = {key: plan[key] for key in ("task_id", "repository", "pr", "source_commit", "wheel_name", "wheel_sha256")}
    common.update(schema=1, appliance_vmx=plan["trusted_host"]["appliance_vmx"],
                  appliance_ownership_sha256=plan["appliance_ownership"]["sha256"],
                  deployed_runtime_sha256=plan["deployed_runtime"]["sha256"], guest_path=path)
    if (any(receipt.get(key) != value for receipt in (intent, retained) for key, value in common.items())
            or intent.get("kind") != "ntp-wheel-retention-intent"
            or intent.get("source_path") != "/tmp/" + wheel
            or retained.get("kind") != "ntp-retained-wheel"
            or retained.get("verified_before_reboot") is not True
            or any(retained.get(key) != value for key, value in {"owner_uid": 0, "owner_gid": 0,
                                                               "mode": "0600", "links": 1}.items())):
        raise Refusal("ntp_fixture_retained_wheel_binding_invalid")
    return path


def payload_identity(session, plan: dict, password: str) -> dict:
    """Re-measure the installed wheel payload and helper through pinned SSH.

    Args:
        session: Original appliance session.
        plan: Admitted runtime provenance.
        password: Sudo credential confined to stdin.
    """
    source = Path(__file__).with_name("routing_deployment_inspection.py").read_text(encoding="utf-8")
    wheel_path = retained_wheel_path(plan)
    program = ("import json,pathlib,stat\np=pathlib.Path(" + repr(wheel_path) + ")\ns=p.lstat()\nd=p.parent.lstat()\n"
               + "assert stat.S_ISDIR(d.st_mode) and stat.S_IMODE(d.st_mode)==0o700 and d.st_uid==d.st_gid==0\n"
               + "assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==s.st_gid==0 and s.st_nlink==1\n"
               + "n={'__name__':'ntp_read_only_inspection'}\nexec(" + repr(source) + ",n)\n"
               + "print(json.dumps(n['deployment_evidence'](p,'192.168.77.10')))\n")
    facts = json.loads(sudo_read(session, guest_python_command(program), password))
    expected = bound_json(plan["deployment_measurement"])
    keys = ("helper_sha256", "wheel_sha256", "wheel_payload_sha256", "installed_payload_sha256", "verified_payload_files")
    if any(facts.get(key) != expected.get(key) for key in keys):
        raise Refusal("ntp_fixture_installed_payload_changed")
    return {key: facts[key] for key in keys}


def wait_management_client(peer, plan: dict) -> tuple[Client, dict]:
    """Wait for the rebooted HTTPS login page before sending any credential.

    Only explicit TCP non-acceptance and HTTP gateway startup failures retry.
    CA, hostname, transport and topology failures remain immediate refusals.

    Args:
        peer: Original pinned and authenticated private-LAN transport.
        plan: Admitted private address and independently pinned public CA.
    """
    started = time.monotonic()
    deadline = started + 120
    attempts = 0
    client = None
    while True:
        guard = getattr(peer, "topology_guard", None)
        if guard is not None:
            guard()
        if client is None:
            if deadline - time.monotonic() < 24:
                raise Refusal("ntp_fixture_management_readiness_timeout")
            attempts += 1
            if not peer.tcp_reachable(plan["current_address"], 443):
                time.sleep(min(2, max(0, deadline - time.monotonic())))
                continue

            def bootstrap_socket(address: str):
                """Bound the existing CA-validated SAN discovery handshake.

                Args:
                    address: Exact already admitted management address.
                """
                raw = peer.open_socket(address)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raw.close()
                    raise Refusal("ntp_fixture_management_readiness_timeout")
                raw.settimeout(min(8, remaining))
                return raw

            name = tls_name(SimpleNamespace(open_socket=bootstrap_socket), plan["current_address"], plan["ca_path"])
            client = Client("https://" + name, plan["ca_path"], peer=peer, connect_ip=plan["current_address"])
        # Preserve Client.request's twelve-second request timeout and reserve
        # that budget rather than renewing the overall readiness deadline.
        if deadline - time.monotonic() < 12:
            raise Refusal("ntp_fixture_management_readiness_timeout")
        try:
            status, body = client.request("/ui/management/login")
        except ClientRefusal as exc:
            if str(exc) not in {"http_502", "http_503", "http_504"}:
                raise
        else:
            if status != 200 or not Page(body).csrf:
                raise Refusal("ntp_fixture_management_login_page_invalid")
            if time.monotonic() > deadline:
                raise Refusal("ntp_fixture_management_readiness_timeout")
            return client, {"tcp_attempts": attempts, "elapsed_seconds": round(time.monotonic() - started, 3),
                            "ca_and_hostname_verified": True, "login_page_ready": True}
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def prepare_baseline(client, plan: dict) -> dict:
    """Prepare first-run DNS/resolver and one unused access interface via UI.

    Args:
        client: Original authenticated CA-validated management client.
        plan: Admitted address and MAC plan.
    """
    original, _ = client.interface("eth0")
    if original.get("role") != "management" or original.get("ipv4_method") != "dhcp":
        raise Refusal("ntp_fixture_original_management_invalid")
    service, _ = client.interface("eth1")
    if service.get("role") != "unused" or service.get("ip_cidr") or service.get("ipv6_cidr"):
        raise Refusal("ntp_fixture_service_interface_not_unused")
    fields = saved_fields(service)
    fields.update(role="access", mode="access", ipv4_method="static", ip_cidr="192.168.78.10/24",
                  gateway="", ipv6_enabled=False, ipv6_cidr="", ipv6_gateway="", admin_state="up",
                  access_management_ui_enabled=False)
    edit(client, "eth1", fields, plan["trusted_host"]["appliance_service_mac"])
    for page, action, changes in (
        ("dns", "dns/settings", {"enabled": "", "upstream_servers": plan["peer_address"]}),
        ("settings", "settings", {"external_dns_servers": plan["peer_address"]}),
    ):
        _, body = client.request("/ui/management/" + page)
        form = FixtureForm(body, "/ui/management/" + action)
        _, saved = client.json(form.form_action, replace_fields(form.fields, changes), autosave=True)
        if saved.get("valid") is False:
            raise Refusal("ntp_fixture_initial_settings_invalid")
    save_ntp(client, plan["peer_address"])
    return saved_fields(original)


def initial_tls_baseline(client, plan: dict, output: Path, username: str, password: str) -> dict:
    """Settle the first Network/CA baseline before later NTP-only transitions.

    A cold review can still contain the bootstrap DHCP address. When needed,
    one separately journaled successful-baseline replay converges that review;
    it never retries a failed task. All subsequent TLS checks retain the same CA
    and hostname verification and require two equal applied-address leaf samples.

    Args:
        client: Original authenticated management client.
        plan: Admitted original CA and management address.
        output: Original append-only task journal directory.
        username: Original web identity for exact-task reconciliation.
        password: Web credential confined to authenticated channels.
    """
    deadline = time.monotonic() + 16

    def open_socket(address: str, port: int = 443):
        """Bound only the existing verified management TLS transport.

        Args:
            address: Original private management destination.
            port: Management HTTPS port.
        """
        if address != plan["current_address"] or port != 443:
            raise Refusal("ntp_fixture_tls_baseline_destination_changed")
        raw = client.peer.open_socket(address, port)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raw.close()
            raise Refusal("ntp_fixture_tls_baseline_timeout")
        raw.settimeout(min(8, remaining))
        return raw

    probe = Client(client.url, plan["ca_path"], peer=SimpleNamespace(open_socket=open_socket),
                   connect_ip=plan["current_address"])
    original = probe.tls_identity()
    convergence = None
    if plan["current_address"] not in original.get("ip_sans", []):
        convergence = apply_once(client, output, "ntp-native-baseline", username, password)
        if convergence["status"] != "succeeded":
            raise Refusal("ntp_fixture_initial_baseline_convergence_failed")
    started = time.monotonic()
    deadline = started + 120
    previous = None
    equal_samples = 0
    while deadline - time.monotonic() >= 16:
        guard = getattr(client.peer, "topology_guard", None)
        if guard is not None:
            guard()
        leaf = probe.tls_identity()
        if plan["current_address"] in leaf.get("ip_sans", []):
            equal_samples = equal_samples + 1 if leaf == previous else 1
            if equal_samples >= 2:
                return {"tls": leaf, "convergence_task": convergence, "equal_applied_leaf_samples": equal_samples,
                        "elapsed_seconds": round(time.monotonic() - started, 3)}
        else:
            equal_samples = 0
        previous = leaf
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise Refusal("ntp_fixture_tls_baseline_timeout")


def applied_config(session, password: str) -> dict:
    """Record only applied configuration digest and verified transaction state.

    Args:
        session: Original pinned appliance session.
        password: Sudo credential confined to stdin.
    """
    program = """import hashlib,json,pathlib
p=pathlib.Path('/etc/ntp.conf'); t=p.with_name('.atlaso-ntpd-transaction.json')
v=json.loads(t.read_text()) if t.exists() else None
print(json.dumps({'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
 'transaction_phase':v.get('phase') if v else 'absent'}))
"""
    facts = json.loads(sudo_read(session, guest_python_command(program), password))
    if not re.fullmatch(r"[0-9a-f]{64}", facts.get("sha256", "")) or facts.get("transaction_phase") not in {"absent", "verified"}:
        raise Refusal("ntp_fixture_applied_checkpoint_unverified")
    return facts


def journal_checkpoint(session, password: str) -> dict:
    """Capture only the latest native service journal cursor's monotonic identity.

    Args:
        session: Original pinned appliance transport.
        password: Sudo credential confined to stdin.
    """
    lines = sudo_read(session, "journalctl -u ntpd.service -n 1 -o json --no-pager", password).splitlines()
    if not lines:
        boot = session.command("cat /proc/sys/kernel/random/boot_id").decode().strip().replace("-", "")
        if re.fullmatch(r"[0-9a-f]{32}", boot) is None:
            raise Refusal("ntp_fixture_journal_checkpoint_invalid")
        return {"boot": boot, "monotonic": 0, "cursor": None}
    row = json.loads(lines[-1])
    boot = row["_BOOT_ID"]
    stamp = int(row["__MONOTONIC_TIMESTAMP"])
    cursor = row.get("__CURSOR")
    if (re.fullmatch(r"[0-9a-f]{32}", boot) is None or stamp < 0 or not isinstance(cursor, str)
            or not 1 <= len(cursor) <= 2048 or any(char in cursor for char in "\x00\r\n")):
        raise Refusal("ntp_fixture_journal_checkpoint_invalid")
    return {"boot": boot, "monotonic": stamp, "cursor": cursor}


def acquisition_failure(session, password: str, before: dict) -> dict:
    """Require a new failed real initializer before accepting the negative case.

    Args:
        session: Original pinned appliance transport.
        password: Sudo credential confined to stdin.
        before: Monotonic checkpoint captured before the unreachable candidate.
    """
    if (re.fullmatch(r"[0-9a-f]{32}", str(before.get("boot", ""))) is None
            or type(before.get("monotonic")) is not int or before["monotonic"] < 0
            or not isinstance(before.get("cursor"), str) or not 1 <= len(before["cursor"]) <= 2048
            or any(char in before["cursor"] for char in "\x00\r\n")):
        raise Refusal("ntp_fixture_negative_checkpoint_missing")
    # Filter inside the pinned guest. Full journal metadata can exceed the SSH
    # readback cap even for 100 ordinary entries; only fixed failure categories
    # cross that boundary. A 257th row refuses any possibly truncated window.
    program = f"""import json,re,subprocess
before={before!r}
p=subprocess.run(['journalctl','-u','ntpd.service','-n','257','-o','json','--no-pager',
 '--after-cursor='+before['cursor']],capture_output=True,timeout=8)
assert p.returncode==0 and len(p.stdout)<=2*1024**2
lines=p.stdout.splitlines();assert len(lines)<257
failures=[]
for line in lines:
 row=json.loads(line)
 if row.get('_BOOT_ID')!=before['boot'] or int(row.get('__MONOTONIC_TIMESTAMP',0))<=before['monotonic']:continue
 match=re.fullmatch(r'NTPsec initial clock acquisition failed \\((TimeoutExpired|OSError|exit code -?\\d{{1,3}})\\); Apply must roll back\\.',str(row.get('MESSAGE','')))
 if match:failures.append(match[1])
print(json.dumps({{'complete':True,'records':len(lines),'raw_bytes':len(p.stdout),'failures':failures}}))
"""
    facts = json.loads(sudo_read(session, guest_python_command(program), password))
    failures = facts.get("failures")
    if (facts.get("complete") is not True or type(facts.get("records")) is not int
            or not 0 <= facts["records"] <= 256 or type(facts.get("raw_bytes")) is not int
            or not 0 <= facts["raw_bytes"] <= 2 * 1024**2 or not isinstance(failures, list)
            or len(failures) != 1 or not isinstance(failures[0], str)
            or re.fullmatch(r"TimeoutExpired|OSError|exit code -?\d{1,3}", failures[0]) is None):
        raise Refusal("ntp_fixture_negative_acquisition_failure_unproven")
    return {"initializer_failed": True, "reason": failures[0], "after_original_checkpoint": True,
            "journal_records": facts["records"], "journal_bytes_filtered_in_guest": facts["raw_bytes"]}


def acquisition_observation(session, password: str, before: dict) -> dict:
    """Observe real NTPsec acquisition step/slew logs without changing any clock.

    Args:
        session: Original pinned appliance transport.
        password: Sudo credential confined to stdin.
        before: Native monotonic checkpoint preceding the first cold Apply.
    """
    events = []
    lines = sudo_read(session, "journalctl -u ntpd.service -n 100 -o json --no-pager", password).splitlines()
    for line in lines:
        row = json.loads(line)
        if row.get("_BOOT_ID") != before.get("boot") or int(row.get("__MONOTONIC_TIMESTAMP", 0)) <= before.get("monotonic", 0):
            continue
        match = re.fullmatch(r"CLOCK: time (set|slew) ([+-]\d{1,6}\.\d{1,9}) s", str(row.get("MESSAGE", "")))
        if match:
            offset = float(match[2])
            if not math.isfinite(offset) or abs(offset) > 86400 or len(events) >= 4:
                raise Refusal("ntp_fixture_native_acquisition_observation_invalid")
            events.append({"kind": "step" if match[1] == "set" else "slew", "seconds": offset})
    return {"native_events": events, "real_clock_step_observed": any(row["kind"] == "step" for row in events)}


def submit_initialization(client, *, cold_start: bool = True) -> tuple[str, str]:
    """Submit fixed NTP roots and only server-required network dependencies.

    The caller has already proved routing/NAT intent absent. A first network
    baseline can still require disabled WAN/NAT enforcement. Keep this NTP
    admission separate from the unchanged certificate initializer contract.

    Args:
        client: Original CA/hostname-validated authenticated management client.
        cold_start: Initial Network/CA setup or its single baseline convergence; false selects NTP-only roots.
    """
    roots = _NTP_APPLY_ROOTS if cold_start else _NTP_TRANSITION_ROOTS
    dependencies = _NTP_NETWORK_DEPENDENCIES
    _, original = client.json("/ui/management/appliance-apply/review")
    rows = original.get("units")
    if (original.get("active_task") or not isinstance(rows, list) or not rows
            or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows)):
        raise Refusal("ntp_fixture_apply_review_invalid")
    changed = {row["id"] for row in rows if row.get("changed", True)}
    if changed - roots - dependencies:
        raise Refusal("ntp_fixture_unrelated_pending_units")
    _, review = client.json(apply_review_path("/ui/management/appliance-apply/review", sorted(roots)))
    try:
        fields = apply_review_fields(review)
    except ValueError:
        raise Refusal("ntp_fixture_apply_review_invalid") from None
    reviewed_rows = review["units"]
    if (any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in reviewed_rows)
            or len({row["id"] for row in reviewed_rows}) != len(reviewed_rows)
            or any(row.get("selected") is not True or row.get("valid") is not True
                   for row in reviewed_rows if row.get("selected"))):
        raise Refusal("ntp_fixture_apply_review_invalid")
    selected = {row["id"]: row for row in reviewed_rows if row.get("selected")}
    if (set(review["requested_units"]) != roots
            or not roots.issubset(selected)
            or set(selected) - roots - dependencies
            or any(row.get("required_dependency") is not True
                   for key, row in selected.items() if key in dependencies)
            or not (changed - roots).issubset(selected)):
        raise Refusal("ntp_fixture_apply_scope_changed")
    _, body = client.request("/ui/management/physical-interfaces")
    csrf = Page(body).csrf
    if not csrf:
        raise Refusal("ntp_fixture_form_csrf_missing")
    form = {"csrf": csrf, "reviewed_plan": review["plan_token"], "requested_units": review["requested_units"],
            "selected_units": [value for key, value in fields if key == "selected_units"]}
    status, result = client.json("/ui/management/appliance-apply", form)
    job, path = result.get("job_id"), result.get("status_url")
    if (status != 202 or not isinstance(job, str) or not job
            or path not in (f"/tasks/{job}/status", f"/ui/management/tasks/{job}/status")):
        raise Refusal("ntp_fixture_apply_not_admitted")
    return job, path


def apply_once(client, output: Path, name: str, username: str, password: str) -> dict:
    """Journal one reviewed global Apply and reconcile only its exact task.

    Args:
        client: Authenticated original management origin.
        output: Originally owned append-only result namespace.
        name: Fixed case identifier.
        username: Same admitted web identity used for the initial login.
        password: In-memory web credential used only if the session expires.
    """
    started = time.monotonic()
    publish(output / (name + "-submission-intent.json"), {"case": name, "no_resubmission": True})
    job, path = submit_initialization(client, cold_start=name in {"ntp-native-cold", "ntp-native-baseline"})
    publish(output / (name + "-submitted.json"), {"job_id": job, "status_path": path})
    task, _ = wait_task([client], path, username, password)
    public = {"job_id": job, "status": task.get("status"), "elapsed_seconds": round(time.monotonic() - started, 3)}
    publish(output / (name + "-terminal.json"), public)
    return public


def packet_probe(session, peer, password: str, target: str, source: str, *, response_expected: bool) -> dict:
    """Prove ingress of one nonce-bearing query and the expected UDP response.

    Args:
        session: Pinned appliance transport used only for bounded ingress capture.
        peer: Pinned peer sending from its admitted private address.
        password: Sudo password confined to capture channel stdin.
        target: Original management or access interface address.
        source: Matching private peer address.
        response_expected: Require a real normal-leap nonce-matched response.
    """
    target, source = _address(target), _address(source)
    port = 40000 + secrets.randbelow(20000)
    capture = (Path(__file__).with_name("ntp_packet_capture.py").read_text(encoding="utf-8")
               + f"\ncapture({source!r}, {target!r}, {port})\n")
    request = f"""import json,socket,struct,time
stamp=time.time()+2208988800; nonce=struct.pack('!II',int(stamp),int((stamp%1)*2**32))
packet=b'\\x23'+b'\\0'*39+nonce
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
 s.bind(({source!r},{port}));s.settimeout(3);s.sendto(packet,({target!r},123))
 try:
  reply,remote=s.recvfrom(512)
 except socket.timeout:
  assert not {response_expected!r}
  result={{'response_received':False}}
 else:
  assert {response_expected!r} and remote==({target!r},123) and len(reply)>=48
  assert reply[0]&7==4 and reply[0]>>6!=3 and 1<=reply[1]<=15 and reply[24:32]==nonce
  seconds,fraction=struct.unpack('!II',reply[40:48])
  assert abs(seconds+fraction/2**32-2208988800-time.time())<2
  result={{'response_received':True,'stratum':reply[1],'nonce_matched':True}}
print(json.dumps(result))
"""
    channel = session.transport.open_session(timeout=8)
    try:
        channel.settimeout(25)
        channel.exec_command("sudo -S -p '' -- " + guest_python_command(capture))
        channel.sendall((password + "\n").encode())
        channel.shutdown_write()
        output = channel.makefile("rb")
        if output.readline(128).strip() != b"capture_ready":
            raise Refusal("ntp_fixture_ingress_capture_not_ready")
        result = json.loads(peer.command("python3 -I -B -", stdin=request.encode()))
        if output.read(1024).strip() != b"request_delivered" or channel.recv_exit_status() != 0:
            raise Refusal("ntp_fixture_packet_ingress_unproven")
        if result.get("response_received") is not response_expected:
            raise Refusal("ntp_fixture_packet_response_unverified")
        return {"target": target, "source": source, "request_delivered": True, **result}
    finally:
        channel.close()


def run(plan: dict, output: Path, password: str, *, appliance_password: str | None = None) -> dict:
    """Verify cold Apply, packet isolation and a failed-candidate rollback once.

    Args:
        plan: New NTP-only originally receipted plan.
        output: Existing task-owned result namespace, with no previous NTP attempt.
        password: Administrator credential confined to authenticated channels.
        appliance_password: Separate root SSH credential when root is selected.
    """
    admit_plan(plan)
    ssh_password = appliance_password if plan["appliance_user"] == "root" else password
    if not isinstance(ssh_password, str) or not ssh_password or len(ssh_password) > 4096:
        raise Refusal("ntp_fixture_protected_ssh_credential_missing")
    ownership = bound_json(plan["appliance_ownership"])
    if output.resolve() != Path(ownership["lab_root"]).resolve():
        raise Refusal("ntp_fixture_output_original_ownership_mismatch")
    if any(output.glob("ntp-native-*.json")):
        raise Refusal("ntp_fixture_prior_attempt_requires_reconciliation")
    result = {"schema": 1, "kind": "ntp-cold-start-native-result", "task_id": plan["task_id"],
              "pr": plan["pr"], "source_commit": plan["source_commit"], "success": False, "stage": "admitted"}
    publish(output / "ntp-native-started.json", result)
    try:
        with watched_topology(plan) as (topology, check):
            result["topology"] = topology
            p = plan["peer_transport"]
            with PinnedPeerTransport(p["host"], p["user"], p["ssh_public_key"], p["ssh_host_key"], p["private_subnet"]) as peer:
                peer.topology_guard = check
                verify_peer_isolation(peer)
                addresses = [plan["current_address"], plan["baseline_address"], plan["static_candidate_address"]]
                verify_peer_tunnel_scope(peer, addresses)
                result["peer_time"] = verify_peer_time(peer, plan["peer_address"], addresses)
                with PinnedApplianceSession(peer, plan["current_address"], plan["appliance_user"], ssh_password,
                                            plan["appliance_ssh_host_key"]) as session:
                    result["payload"] = payload_identity(session, plan, ssh_password)
                    ca = session.command("cat /etc/atlaso/ca/root.crt")
                    if hashlib.sha256(ca).hexdigest() != plan["ca_sha256"]:
                        raise Refusal("ntp_fixture_original_ca_changed")
                    initial = json.loads(sudo_read(session, "/opt/atlaso/bin/atlaso-helper ntpd status --real", ssh_password))
                    initial_controllers = initial.get("daemon_conflicts", {})
                    if (initial.get("mode") != "unmanaged" or initial.get("selected_controller", {}).get("active") is True
                            or set(initial_controllers) != {"ntpd", "chronyd", "systemd_timesyncd", "vmware_tools"}
                            or any(state.get("active") is not False or state.get("enabled") is not False
                                   for state in initial_controllers.values())):
                        raise Refusal("ntp_fixture_cold_state_not_proven")
                    result["cold_initial_state"] = {"mode": "unmanaged", "clock_controllers_inactive": True}
                    probe = Path(__file__).with_name("certificate_source_probe.py").read_text(encoding="utf-8")
                    routing = json.loads(sudo_read(session, guest_python_command(probe), ssh_password))
                    if routing.get("state") != "proven-absent":
                        raise Refusal("ntp_fixture_routing_intent_present")
                    result["routing_absence"] = {"state": "proven-absent"}
                    result["stage"] = "management_https_readiness"
                    client, result["management_readiness"] = wait_management_client(peer, plan)
                    client.login(plan["username"], password)
                    result["original_tls"] = client.tls_identity()
                    result["stage"] = "first_run_desired_state"
                    original = prepare_baseline(client, plan)
                    result["stage"] = "cold_apply"
                    cold_checkpoint = journal_checkpoint(session, ssh_password)
                    first = apply_once(client, output, "ntp-native-cold", plan["username"], password)
                    if first["status"] != "succeeded":
                        raise Refusal("ntp_fixture_cold_apply_failed")
                    result["cold_apply"] = first
                    result["cold_clock"] = native_clock(session, ssh_password, plan["peer_address"])
                    result["cold_acquisition"] = acquisition_observation(session, ssh_password, cold_checkpoint)
                    clean_baseline(client)
                    baseline = initial_tls_baseline(client, plan, output, plan["username"], password)
                    result["initial_tls_baseline"] = baseline
                    result["baseline_tls"] = baseline["tls"]
                    clean_baseline(client)
                    if baseline["convergence_task"] is not None:
                        result["baseline_clock"] = native_clock(session, ssh_password, plan["peer_address"])
                    result["client_refusal"] = packet_probe(session, peer, ssh_password, plan["current_address"], plan["peer_address"], response_expected=False)
                    result["stage"] = "server_apply"
                    save_ntp(client, plan["peer_address"], "ntp_server")
                    server = apply_once(client, output, "ntp-native-server", plan["username"], password)
                    if server["status"] != "succeeded":
                        raise Refusal("ntp_fixture_server_apply_failed")
                    result["server_clock"] = native_clock(session, ssh_password, plan["peer_address"], "ntp_server")
                    result["server_response"] = packet_probe(session, peer, ssh_password, "192.168.78.10", "192.168.78.1", response_expected=True)
                    result["server_unselected_refusal"] = packet_probe(session, peer, ssh_password, plan["current_address"], plan["peer_address"], response_expected=False)
                    prior = applied_config(session, ssh_password)
                    checkpoint = journal_checkpoint(session, ssh_password)
                    result["prior_applied_config"] = prior
                    result["negative_checkpoint"] = checkpoint
                    result["stage"] = "negative_candidate"
                    save_ntp(client, plan["negative_address"], "ntp_server")
                    failed = apply_once(client, output, "ntp-native-negative", plan["username"], password)
                    if failed["status"] != "failed":
                        raise Refusal("ntp_fixture_negative_candidate_did_not_fail")
                    result["negative_acquisition"] = acquisition_failure(session, ssh_password, checkpoint)
                    restored = applied_config(session, ssh_password)
                    if restored["sha256"] != prior["sha256"]:
                        raise Refusal("ntp_fixture_rollback_config_not_restored")
                    result["rollback_clock"] = native_clock(session, ssh_password, plan["peer_address"], "ntp_server")
                    result["negative_candidate"] = {**failed, "prior_configuration_restored": True}
                    if saved_fields(client.interface("eth0")[0]) != original:
                        raise Refusal("ntp_fixture_original_management_changed")
                    result["payload_after"] = payload_identity(session, plan, ssh_password)
                    result["final_tls"] = client.tls_identity()
                    if result["final_tls"] != result["baseline_tls"]:
                        raise Refusal("ntp_fixture_tls_changed")
                    result["stage"] = "final_context_validation"
        # Context exit includes the final topology check and observer shutdown.
        # No immutable acceptance claim may precede their successful completion.
        result.update(success=True, stage="verified_cold_apply_and_rollback", topology_sha256=topology["sha256"],
                      helper_startup_and_verification_budget_seconds=60,
                      remaining_desired_state="failed negative candidate retained; no automatic retry")
    except Exception:  # noqa: BLE001 - No raw HTTP, native or credential failure escapes the bounded child.
        result["failure"] = "ntp_fixture_acceptance_failed_preserve_and_reconcile"
        raise Refusal(result["failure"]) from None
    finally:
        publish(output / "ntp-native-result.json", result)
    return result


def main() -> int:
    """Read one bounded stdin credential envelope after public plan admission."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    password = None
    appliance_password = None
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        admit_plan(plan)
        envelope = json.loads(sys.stdin.readline(65537))
        password = envelope.pop("password", None)
        appliance_password = envelope.pop("appliance_ssh_password", None)
        envelope.clear()
        if not isinstance(password, str) or not password or len(password) > 4096:
            raise Refusal("ntp_fixture_protected_credential_missing")
        run(plan, args.output, password, appliance_password=appliance_password)
        print(json.dumps({"success": True, "kind": "ntp-cold-start-native-result"}))
        return 0
    except Exception:  # noqa: BLE001 - Public output deliberately excludes exception and native text.
        print(json.dumps({"success": False, "failure": "ntp_fixture_acceptance_failed_preserve_and_reconcile"}))
        return 2
    finally:
        password = None
        appliance_password = None


if __name__ == "__main__":
    raise SystemExit(main())
