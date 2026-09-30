"""Run the private fixture through independently admitted provider observations."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import types
from pathlib import Path
from typing import Any

import paramiko

# The canonical wrapper pins this entire immutable source tree. Isolated Python
# must resolve only that tree's interop modules, never cwd or ambient PYTHONPATH.
if __package__ in {None, ""}:
    for package, directory in (("scripts", Path(__file__).resolve().parent.parent),
                               ("scripts.interop", Path(__file__).resolve().parent)):
        module = types.ModuleType(package)
        module.__path__ = [str(directory)]
        sys.modules[package] = module

from scripts.interop.routing_overlap import FixtureOwner, admit_topology
from scripts.interop.routing_overlap_transport import (
    FixtureHttpClient,
    PinnedFixtureGateway,
    pinned_client,
)


class ControllerFailure(ValueError):
    """Public role/action and digest of a private controller refusal."""


def bounded_json_command(client: paramiko.SSHClient, command: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Exchange one bounded controller command without exposing guest stderr.

    Args:
        client: Already pinned, authenticated control connection.
        command: Fixed controller interpreter and validated script path.
        payload: Public controller request containing no credentials.
    """
    transport = client.get_transport()
    if transport is None or not transport.is_authenticated():
        raise ValueError("fixture control transport is unavailable")
    channel = transport.open_session(timeout=10)
    deadline = time.monotonic() + 90
    output = bytearray()
    errors = 0
    try:
        channel.settimeout(10)
        channel.exec_command(command)
        channel.sendall(json.dumps(payload).encode() + b"\n")
        channel.shutdown_write()
        while True:
            if channel.recv_ready():
                output.extend(channel.recv(65536))
            if channel.recv_stderr_ready():
                errors += len(channel.recv_stderr(65536))
            if len(output) > 262144 or errors > 65536:
                raise ValueError("fixture controller output exceeds bound")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("fixture controller did not finish within its bound")
            time.sleep(0.05)
        if channel.recv_exit_status() != 0:
            try:
                failure = json.loads(output)
            except (ValueError, UnicodeDecodeError):
                failure = None
            if (isinstance(failure, dict) and failure.get("schema") == 1
                    and failure.get("ok") is False and isinstance(failure.get("error"), str)
                    and 0 < len(failure["error"]) <= 256):
                digest = hashlib.sha256(failure["error"].encode()).hexdigest()[:16]
                raise ControllerFailure(f"fixture controller refusal digest {digest}; preserve the owned VM")
            raise ValueError("fixture controller rejected the operation; preserve the owned VM")
        value = json.loads(output)
        if not isinstance(value, dict) or value.get("schema") != 1 or value.get("ok") is not True:
            raise ValueError("fixture controller returned an invalid result")
        return value
    finally:
        channel.close()


class FixtureSession:
    """Admit immutable public topology before connecting to either client."""

    def __init__(self, descriptor: dict[str, Any], owner: FixtureOwner, username: str, password: str) -> None:
        """Match provider records, live guest links, receipts and control peers.

        Args:
            descriptor: Canonical wrapper's pinned public observations.
            owner: Independent task and source bindings from wrapper arguments.
            username: Existing lifecycle client username.
            password: Existing secret supplied through standard input.
        """
        if descriptor.get("schema") != 1 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", username):
            raise ValueError("invalid fixture descriptor or username")
        self.descriptor = descriptor
        self.username, self.password = username, password
        self.clients: dict[str, paramiko.SSHClient] = {}
        self.topology = admit_topology(owner, descriptor["segments"],
            {key: base64.b64decode(value, validate=True) for key, value in descriptor["receipt_bytes"].items()},
            descriptor["provider_nics"], descriptor["guest_links"],
            control_network=descriptor["control_network"], control_prefixes=descriptor["control_prefixes"])
        self.digest = hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        controls = [ipaddress.ip_network(value, strict=False) for value in descriptor["control_prefixes"]]
        addresses = set()
        for role in ("client-a", "client-b"):
            peer = descriptor["peers"][role]
            address = ipaddress.ip_address(peer["host"])
            control = self.topology.link(role, 0)
            observed = [row for row in descriptor["guest_links"] if row["role"] == role and row["mac"] == control.mac]
            if (address.version != 4 or address.is_loopback or address.is_unspecified or address.is_multicast
                    or address in addresses or not any(address in prefix for prefix in controls if prefix.version == 4)
                    or len(observed) != 1 or not any(ipaddress.ip_interface(value).ip == address for value in observed[0]["addresses"])):
                raise ValueError("client control address lacks exact observed control-NIC ownership")
            if not re.fullmatch(r"/tmp/atlaso-overlap-[0-9a-f]{32}\.py", peer["controller"]):
                raise ValueError("fixture controller path is not canonical")
            addresses.add(address)

    def action(self, role: str, action: str) -> dict[str, Any]:
        """Invoke the admitted guest controller using a freshly checked binding.

        Args:
            role: Client role in the admitted topology.
            action: Explicit supported controller action.
        """
        if role not in {"client-a", "client-b"} or action not in {"start", "stop", "status", "pause-dhcp", "resume-dhcp", "pause-ra", "resume-ra"}:
            raise ValueError("unsupported fixture action")
        peer = self.descriptor["peers"][role]
        if role not in self.clients:
            client = pinned_client(peer["host"], peer["ssh_public_key"])
            try:
                client.connect(peer["host"], username=self.username, password=self.password, timeout=10,
                    auth_timeout=10, banner_timeout=10, look_for_keys=False, allow_agent=False)
            except (OSError, paramiko.SSHException):
                client.close()
                raise ValueError("pinned fixture client authentication failed") from None
            self.clients[role] = client
        owner = self.topology.owner
        control, private = self.topology.link(role, 0), self.topology.link(role, 1)
        request = {"schema": 1, "action": action, "role": role, "task_id": owner.task_id,
            "repository": owner.repository, "source_commit": owner.source_commit, "pr": owner.pr,
            "topology_sha256": self.digest, "control": {"name": control.interface, "mac": control.mac},
            "private": {"name": private.interface, "mac": private.mac},
            "ipv4_prefix": self.topology.ipv4_prefix, "ipv6_prefix": self.topology.ipv6_prefix,
            "appliance_mac": self.topology.link("appliance", 0).mac}
        try:
            result = bounded_json_command(self.clients[role], f"sudo -n python3 -I {peer['controller']}", request)
        except ControllerFailure as failure:
            raise ControllerFailure(f"{role} {action}: {failure}") from None
        if result.get("role") != role or result.get("topology_sha256") != self.digest:
            raise ValueError("fixture controller result lost its topology binding")
        return result

    def close(self) -> None:
        """Close authenticated transports without claiming guest restoration."""
        for client in self.clients.values():
            client.close()
        self.clients.clear()


def write_evidence(path: Path, value: dict[str, Any]) -> None:
    """Publish a new public result without replacing another run's evidence.

    Args:
        path: Task-owned result path admitted by the wrapper.
        value: Public result containing no credential fields.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def scenario_failure_result(failure: Exception, digest: str) -> tuple[dict[str, Any], int]:
    """Keep the private fixture when Apply or restoration lacks safe completion.

    Args:
        failure: Classified scenario prerequisite or restoration failure.
        digest: Proven topology digest for the result receipt.
    """
    from scripts.interop.routing_overlap_scenario import (
        ApplyOutcomeUnknown,
        RestorationIncomplete,
    )

    unknown = isinstance(failure, ApplyOutcomeUnknown)
    restoration_incomplete = isinstance(failure, RestorationIncomplete)
    preserve = unknown or restoration_incomplete
    return ({"schema": 1, "phase": "scenario", "ok": False,
             "apply_outcome_unknown": unknown, "restoration_incomplete": restoration_incomplete,
             "preserve_fixture": preserve, "error": str(failure), "topology_sha256": digest},
            3 if preserve else 2)


def run_client_phase(fixture: FixtureSession, phase: str) -> dict[str, dict[str, Any]]:
    """Start or stop admitted clients without leaving a known started peer behind.

    Args:
        fixture: Session bound to the canonical task-owned clients.
        phase: Bootstrap or stop phase selected by the wrapper.

    Returns:
        Verified per-client results for successful phase operations.
    """
    states: dict[str, dict[str, Any]] = {}
    if phase == "bootstrap":
        try:
            for role in ("client-b", "client-a"):
                states[role] = fixture.action(role, "start")
        except Exception:
            # Only a validated start receipt proves ownership of a running
            # controller. A failed start might have run remotely, but guessing
            # its state is not authority to mutate that guest.
            rollback_failed = False
            for role in reversed(states):
                try:
                    fixture.action(role, "stop")
                except Exception:  # noqa: BLE001 - continue rollback after any controller failure
                    rollback_failed = True
            if rollback_failed:
                raise ValueError("fixture bootstrap rollback failed; preserve owned clients") from None
            raise
    elif phase == "stop":
        failures: list[str] = []
        for role in ("client-a", "client-b"):
            try:
                states[role] = fixture.action(role, "stop")
            except Exception as failure:  # noqa: BLE001 - both owned guests must be attempted
                failures.append(str(failure) if isinstance(failure, ControllerFailure) else role)
        if failures:
            raise ValueError(f"fixture client stop failed ({', '.join(failures)}); preserve owned clients")
    else:
        raise ValueError("unsupported fixture phase")
    return states


def main() -> int:
    """Consume the canonical wrapper's bindings and credential stdin envelope."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("bootstrap", "probe", "scenario", "stop"), required=True)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--descriptor-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--lab-root", required=True)
    parser.add_argument("--client-user", required=True)
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--trust", type=Path)
    args = parser.parse_args()
    raw = args.descriptor.read_bytes()
    if len(raw) > 1048576 or hashlib.sha256(raw).hexdigest() != args.descriptor_sha256:
        raise ValueError("fixture descriptor digest mismatch")
    secrets = json.loads(sys.stdin.readline(65537))
    owner = FixtureOwner(args.task_id, "mdaneri/Atlaso", args.source_commit, args.pr, args.lab_root)
    fixture = FixtureSession(json.loads(raw), owner, args.client_user, secrets["ssh_password"])
    try:
        if args.action in {"bootstrap", "stop"}:
            states = run_client_phase(fixture, args.action)
            evidence = {"schema": 1, "phase": args.action, "topology_sha256": fixture.digest, "states": states}
        else:
            if args.trust is None:
                raise ValueError("provider-observed public appliance trust is required")
            trust = json.loads(args.trust.read_bytes())
            management = fixture.topology.link("appliance", 0)
            matching = [row for row in trust["links"] if row["mac"] == management.mac and row["interface"] == management.interface]
            if (trust.get("ssh_public_key") != fixture.descriptor["appliance_ssh_public_key"] or len(matching) != 1
                    or not any(ipaddress.ip_interface(value).ip == ipaddress.ip_address("192.0.2.10") for value in matching[0]["addresses"])):
                raise ValueError("appliance public trust observation lost management-NIC ownership")
            peer = fixture.descriptor["peers"]["client-a"]
            gateway = PinnedFixtureGateway(peer["host"], "192.0.2.10", peer["ssh_public_key"],
                fixture.descriptor["appliance_ssh_public_key"], trust["ca_pem"])
            try:
                gateway.connect(args.client_user, secrets["ssh_password"])
                if args.action == "probe":
                    status, _, _ = gateway.request("GET", "/openapi.json", timeout=20)
                    if status != 200:
                        raise ValueError("private HTTPS service is not ready")
                    evidence = {"schema": 1, "phase": "probe", "status": status, "topology_sha256": fixture.digest}
                else:
                    from scripts.interop.routing_overlap import OverlapPrerequisiteError
                    from scripts.interop.routing_overlap_scenario import run_scenario
                    try:
                        evidence = run_scenario(client=FixtureHttpClient(gateway),
                            connect_appliance=lambda: gateway.connect_appliance("root", secrets["appliance_ssh_password"]),
                            topology=fixture.topology, server_action=lambda action: fixture.action("client-a", action),
                            username=args.admin_user, password=secrets["password"])
                    except OverlapPrerequisiteError as failure:
                        result, exit_code = scenario_failure_result(failure, fixture.digest)
                        write_evidence(args.output, result)
                        return exit_code
            finally:
                gateway.close()
        write_evidence(args.output, evidence)
        return 0
    finally:
        fixture.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, paramiko.SSHException) as failure:
        detail = f" ({failure})" if isinstance(failure, ControllerFailure) else ""
        print(f"Private lifecycle operation failed{detail}; preserve canonical artifacts for diagnosis.", file=sys.stderr)
        raise SystemExit(2) from None
