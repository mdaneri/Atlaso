"""Establish an ISO appliance's static certificate-test baseline through reviewed Apply.

Run only in the source-pinned, bounded credential child. Original VM, console,
peer and LAN receipts precede both authentication and desired-state mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shlex
import ssl
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

from certificate_handoff_native import (
    Client,
    clean_baseline,
    dns_baseline,
    edit,
    saved_fields,
    submit,
    wait_task,
)
from certificate_handoff_native import Refusal as HandoffRefusal
from certificate_peer_proof import Refusal as ProofRefusal
from certificate_peer_proof import admit_fixture, admit_output, bound_json, publish
from certificate_peer_transport import (
    PeerTransportRefusal,
    PinnedApplianceSession,
    PinnedPeerTransport,
)
from certificate_retirement import Refusal as RetirementRefusal
from certificate_retirement import verify_peer_isolation
from certificate_trusted_host import Refusal as HostRefusal
from certificate_trusted_host import TrustedHostMonitor, inspect_trusted_host
from cryptography import x509


class Refusal(Exception):
    """A fixed public refusal; never include a response, command or credential."""


@contextmanager
def watched_topology(plan: dict, original: dict):
    """Keep sticky topology observation active throughout the bootstrap.

    Args:
        plan: Task-bound trusted-host plan used for repeat topology reads.
        original: Admitted topology snapshot that later observations must match.
    """
    monitor = TrustedHostMonitor(plan, original)
    try:
        monitor.start()
        yield monitor
    finally:
        monitor.stop()


def initial_review(client) -> None:
    """Refuse another Apply or unrelated pending work before desired editing.

    Args:
        client: Authenticated, CA-validated appliance UI client.
    """
    _, review = client.json("/ui/management/appliance-apply/review")
    protected = {"network", "ca", "firewall", "appliance_settings", "public_services"}
    if review.get("active_task"):
        raise Refusal("bootstrap_apply_already_active")
    if any(unit.get("changed", True) and unit.get("id") not in protected for unit in review.get("units", [])):
        raise Refusal("bootstrap_unrelated_pending_units")


def sudo_read(session, command: str, password: str) -> bytes:
    """Read a bounded public result with the admin password confined to stdin.

    Args:
        session: Authenticated pinned appliance SSH session.
        command: Fixed public inspection command to run with sudo.
        password: Appliance administrator password sent only through channel stdin.

    Returns:
        Bounded stdout bytes from the read-only guest command.
    """
    channel = session.transport.open_session(timeout=8)
    try:
        channel.settimeout(40)
        channel.exec_command("sudo -S -p '' -- " + command)
        channel.sendall((password + "\n").encode())
        channel.shutdown_write()
        result = channel.makefile("rb").read(65_537)
        errors = channel.makefile_stderr("rb").read(65_537)
        if len(result) > 65_536 or len(errors) > 65_536 or channel.recv_exit_status() != 0:
            raise Refusal("bootstrap_guest_readback_failed")
        return result
    finally:
        channel.close()


def guest_identity(session, plan: dict, password: str) -> dict:
    """Measure routing absence and the actual admitted ISO payload without changing it.

    Args:
        session: Authenticated pinned appliance SSH session.
        plan: Task-bound plan containing deployed source and installed inspection refs.
        password: Appliance administrator password used only by the bounded sudo read.

    Returns:
        Public routing, service, helper, and wheel facts measured from the guest.
    """
    probe = Path(__file__).with_name("certificate_source_probe.py").read_bytes()
    routing = json.loads(sudo_read(session, "python3 -c " + shlex.quote(probe.decode()), password))
    if routing.get("state") != "proven-absent":
        raise Refusal("bootstrap_routing_intent_present")
    routing["probe_sha256"] = hashlib.sha256(probe).hexdigest()
    service = session.command("systemctl show atlaso.service --property=LoadState --property=ActiveState").decode()
    states = dict(line.split("=", 1) for line in service.splitlines() if "=" in line)
    if states != {"LoadState": "loaded", "ActiveState": "active"}:
        raise Refusal("bootstrap_application_inactive")
    helper = session.command("sha256sum /opt/atlaso/bin/atlaso-helper").decode().split()[0]
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ATLASO_NATIVE_")}
    expected = subprocess.run(
        ["git", "-C", str(Path(__file__).resolve().parents[2]), "show", plan["deployed_commit"] + ":scripts/appliance/atlaso-helper"],
        capture_output=True, check=True, env=environment, timeout=15,
    ).stdout
    if helper != hashlib.sha256(expected).hexdigest():
        raise Refusal("bootstrap_reviewed_helper_mismatch")
    installed = bound_json(plan["installed_inspection"])
    if (installed.get("source_commit") != plan["deployed_commit"]
            or installed.get("host_key_sha256") != plan["appliance_ssh_host_key"]
            or installed.get("installed_payload_sha256") != installed.get("wheel_payload_sha256")):
        raise Refusal("bootstrap_iso_inspection_mismatch")
    wheel_probe = (
        "import hashlib,json,pathlib; "
        "p=pathlib.Path('/var/lib/atlaso/installation-inspection/software'); "
        "s=json.loads((p/'virtualization-source.json').read_text()); "
        "w=(p/s['application_wheel']).resolve(); "
        "assert w.is_relative_to(p) and w.is_file() and w.stat().st_size<268435456; "
        "print(hashlib.sha256(w.read_bytes()).hexdigest())"
    )
    wheel = sudo_read(session, "python3 -c " + shlex.quote(wheel_probe), password).decode().strip()
    if wheel != installed.get("wheel_sha256"):
        raise Refusal("bootstrap_installed_wheel_changed")
    return {"route_snapshot": routing, "app_service": states, "helper_sha256": helper, "wheel_sha256": wheel}


def tls_name(peer, address: str, ca: str) -> str:
    """Choose an observed SAN using a CA-validated bootstrap handshake.

    Subsequent HTTP uses Client's full CA and hostname verification. The CA is
    separately matched through the pinned appliance SSH session before this call.

    Args:
        peer: Authenticated pinned peer transport to the private appliance.
        address: Exact appliance IPv4 address used for the bootstrap handshake.
        ca: Public CA certificate file used to validate the handshake.

    Returns:
        CA-validated DNS subject name, or the address when it appears in the IP SAN.
    """
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    with context.wrap_socket(peer.open_socket(address), server_hostname=address) as sock:
        leaf = x509.load_der_x509_certificate(sock.getpeercert(binary_form=True))
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if ipaddress.IPv4Address(address) in sans.get_values_for_type(x509.IPAddress):
        return address
    names = sans.get_values_for_type(x509.DNSName)
    if not names or any(character in names[0] for character in "/*:@\\"):
        raise Refusal("bootstrap_certificate_name_unavailable")
    return names[0]


def setup(plan: dict, output: Path, password: str, *, execute: bool) -> dict:
    """Admit the original ISO fixture and establish its clean static baseline once.

    Args:
        plan: Trusted-host plan containing original ISO, peer, LAN, and inspection refs.
        output: Existing task-owned evidence directory for immutable bootstrap records.
        password: Appliance administrator password held in memory from the bounded bridge.
        execute: Whether to set and apply the initial static management baseline.

    Returns:
        Public bootstrap status and observations suitable for task evidence.
    """
    if plan.get("trust_model") != "trusted-host" or plan.get("interface") != "eth0":
        raise Refusal("bootstrap_requires_trusted_iso_fixture")
    admit_output(plan, output / "source.json", output / "bootstrap-runtime.json")
    fixture = admit_fixture(plan)
    if (plan.get("vmx_path") != fixture["appliance_vmx"]
            or plan.get("mac", "").replace("-", ":").lower() != fixture["appliance_mac"].lower()):
        raise Refusal("bootstrap_appliance_binding_mismatch")
    if bound_json(plan["appliance_ownership"]).get("phase") != "original-installation-vm-created":
        raise Refusal("bootstrap_requires_original_iso")
    current = str(ipaddress.IPv4Address(plan["current_address"]))
    baseline = str(ipaddress.IPv4Address(plan["baseline_address"]))
    if current != fixture["lease_address"] or current == baseline:
        raise Refusal("bootstrap_address_plan_invalid")
    peer_plan = plan["peer_transport"]
    network = ipaddress.IPv4Network(peer_plan["private_subnet"])
    if (ipaddress.IPv4Address(baseline) not in network
            or ipaddress.IPv4Address(baseline) in (network.network_address, network.broadcast_address)
            or str(ipaddress.ip_interface(fixture["peer_cidr"]).ip) == baseline):
        raise Refusal("bootstrap_address_plan_invalid")
    result = {"schema": 1, "kind": "certificate-iso-bootstrap-result", "success": False,
              "task_id": plan["task_id"], "source_commit": plan["source_commit"], "stage": "admission"}
    mutation_started = False
    task_terminal = True
    try:
        topology = inspect_trusted_host(plan)
        with watched_topology(plan, topology) as monitor, PinnedPeerTransport(
            peer_plan["host"], peer_plan["user"], peer_plan["ssh_public_key"],
            peer_plan["ssh_host_key"], peer_plan["private_subnet"],
        ) as peer:
            peer.topology_guard = monitor.check
            verify_peer_isolation(peer)
            with PinnedApplianceSession(peer, current, plan["appliance_user"], password, plan["appliance_ssh_host_key"]) as appliance:
                facts = guest_identity(appliance, plan, password)
                actual_ca = appliance.command("cat /etc/atlaso/ca/root.crt")
                if (b"PRIVATE KEY" in actual_ca or b"-----BEGIN CERTIFICATE-----" not in actual_ca
                        or hashlib.sha256(actual_ca).hexdigest() != plan["ca_sha256"]):
                    raise Refusal("bootstrap_public_ca_mismatch")
            source = {"schema": 1, "phase": "before-certificate-validation", "task_id": plan["task_id"],
                      "repository": "mdaneri/Atlaso", "pr": plan["pr"], "vmx_path": plan["vmx_path"],
                      "source_commit": bound_json(plan["appliance_ownership"])["source_commit"],
                      "deployed_commit": plan["deployed_commit"], "routing_intent_state": "proven-absent",
                      "routing_intent": None, "app_service": facts["app_service"], "route_snapshot": facts["route_snapshot"]}
            runtime = {"schema": 1, "phase": "iso-before-static-baseline", "vmx_path": plan["vmx_path"],
                       "vm_ownership_sha256": plan["appliance_ownership"]["sha256"],
                       "deployed_commit": plan["deployed_commit"], "helper_sha256": facts["helper_sha256"],
                       "wheel_sha256": facts["wheel_sha256"], "interface": "eth0", "mac": plan["mac"],
                       "observed_address": current, "address_ownership_state": "unproven"}
            name = tls_name(peer, current, plan["ca_path"])
            client = Client("https://" + name, plan["ca_path"], peer=peer, connect_ip=current)
            client.login(plan.get("username", "admin"), password)
            initial_review(client)
            original, _ = client.interface("eth0")
            if original.get("role") != "management":
                raise Refusal("bootstrap_requires_management_interface")
            fields = saved_fields(original)
            result.update(original_fields=fields, original_tls=client.tls_identity(), original_dns=dns_baseline(client))
            if not execute:
                result.update(success=True, stage="inspected_no_mutation", guest_identity=facts)
                return result
            source_sha = publish(output / "source.json", source)
            runtime["predeployment_sha256"] = source_sha
            bootstrap_sha = publish(output / "bootstrap-runtime.json", runtime)
            publish(output / "original-state.json", result)
            intent = {"schema": 1, "kind": "certificate-management-rewire-intent", "phase": "iso-static-baseline",
                      "task_id": plan["task_id"], "bootstrap_runtime_sha256": bootstrap_sha,
                      "peer_fixture_sha256": plan["peer_fixture"]["sha256"], "peer_identity_sha256": plan["peer_identity"]["sha256"],
                      "original_address": current, "baseline_address": baseline}
            intent_sha = publish(output / "management-rewire-intent.json", intent)
            changed = dict(fields, ipv4_method="static", ip_cidr=f"{baseline}/{network.prefixlen}", gateway="",
                           ipv6_enabled=False, ipv6_cidr="", ipv6_gateway="")
            # submit() refuses an existing task and unrelated changed units; the
            # journal precedes desired editing so an unknown task is never retried.
            result["stage"] = "desired_edit"
            publish(output / "mutation-started.json", {**result, "baseline_fields": changed})
            mutation_started = True
            edit(client, "eth0", changed, plan["mac"])
            task_terminal = False
            job, status_path = submit(client)
            result.update(stage="apply_wait", job_id=job, status_path=status_path)
            publish(output / "apply-submitted.json", {"schema": 1, "job_id": job, "status_path": status_path})
            target = Client("https://" + baseline, plan["ca_path"], peer=peer, connect_ip=baseline)
            task, _ = wait_task([client, target], status_path, plan.get("username", "admin"), password)
            task_terminal = True
            if task.get("status") != "succeeded":
                raise Refusal("bootstrap_apply_failed")
            target.login(plan.get("username", "admin"), password)
            observed, _ = target.interface("eth0")
            observed_fields = saved_fields(observed)
            if any(observed_fields[key] != changed[key] for key in ("ipv4_method", "ip_cidr", "gateway", "ipv6_enabled")):
                raise Refusal("bootstrap_static_readback_mismatch")
            target.json("/openapi.json")
            clean_baseline(target)
            with PinnedApplianceSession(peer, baseline, plan["appliance_user"], password, plan["appliance_ssh_host_key"]) as appliance:
                if guest_identity(appliance, plan, password) != facts:
                    raise Refusal("bootstrap_guest_identity_changed")
            monitor.check()
            runtime.update(kind="certificate-rewired-runtime", phase="iso-static-baseline-applied", url="https://" + baseline,
                           observed_address=baseline, mac=plan["mac"].replace(":", "-"),
                           rewired_runtime_source="original-iso-supported-ui-apply", rewire_intent_sha256=intent_sha,
                           peer_identity_sha256=plan["peer_identity"]["sha256"], bootstrap_runtime_sha256=bootstrap_sha)
            rewire_sha = publish(output / "rewired-runtime.json", runtime)
            compiled = dict(plan, helper_sha256=facts["helper_sha256"], wheel_sha256=facts["wheel_sha256"], url="https://" + baseline)
            for key, filename, checksum in (
                ("predeployment_evidence", "source.json", source_sha), ("bootstrap_runtime", "bootstrap-runtime.json", bootstrap_sha),
                ("rewire_intent", "management-rewire-intent.json", intent_sha), ("rewired_runtime", "rewired-runtime.json", rewire_sha),
            ):
                compiled[key] = {"path": str(output / filename), "sha256": checksum}
            publish(output / "proof-plan.json", compiled)
            result.update(success=True, stage="static_baseline_complete", baseline_tls=target.tls_identity(), job_id=job)
            mutation_started = False
            return result
    except Exception:
        result.update(stage=result["stage"], recovery=("preserve_unknown_apply_do_not_resubmit" if not task_terminal
                      else "preserve_original_state_and_reconcile") if mutation_started else "no_desired_mutation_started")
        raise
    finally:
        publish(output / ("bootstrap-result.json" if execute else "inspection-result.json"), result)


def main() -> int:
    """Consume the bounded bridge without returning credentials or response bodies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    try:
        plan = json.loads(Path(args.plan).read_text())
        output = Path(args.output_directory).resolve(strict=True)
        admit_output(plan, output / "source.json", output / "bootstrap-runtime.json")
        admit_fixture(plan)
        if args.preflight_only:
            return 0
        password = os.environ.pop("ATLASO_NATIVE_ADMIN", "")
        if len(password) < 12 or password != password.strip():
            raise Refusal("bounded_credential_bridge_required")
        setup(plan, output, password, execute=args.execute)
        return 0
    except (Refusal, HandoffRefusal, ProofRefusal, PeerTransportRefusal, RetirementRefusal, HostRefusal,
            OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, x509.ExtensionNotFound) as exc:
        print(json.dumps({"success": False, "reason": str(exc) if isinstance(exc, Refusal) else "iso_bootstrap_refused"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
