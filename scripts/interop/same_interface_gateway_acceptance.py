"""Collect bounded packet evidence for same-interface gateway acceptance."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import select
import time
from contextlib import suppress
from typing import Any, Callable

import paramiko

_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_MAX_GUEST_PROGRAM = 16_384
_MAX_SSH_OUTPUT = 32_768


class SameInterfaceGatewayAcceptanceError(RuntimeError):
    """Fixed, non-secret failure reported by the gateway evidence helpers."""


def _fingerprint(key: paramiko.PKey) -> str:
    """Return the SSH host-key SHA-256 fingerprint in OpenSSH notation."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class PinnedEd25519HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept one Ed25519 key fingerprint for one exact IPv4 host."""

    def __init__(self, host: str, fingerprint: str) -> None:
        self.host = host
        self.fingerprint = fingerprint
        if not fingerprint.startswith("SHA256:") or len(fingerprint) != 50:
            raise SameInterfaceGatewayAcceptanceError("The pinned SSH host-key identity is invalid.")

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        if hostname != self.host or key.get_name() != "ssh-ed25519" or _fingerprint(key) != self.fingerprint:
            raise paramiko.SSHException("Pinned gateway acceptance host-key verification failed.")
        client.get_host_keys().add(self.host, key.get_name(), key)


def run_pinned_ssh_command(
    host: str,
    username: str,
    password: str,
    fingerprint: str,
    command: str,
    *,
    stdin_data: bytes = b"",
    timeout: float = 20.0,
    on_ready: Callable[[], None] | None = None,
) -> bytes:
    """Run a bounded Python stdin program over a pinned, password-only SSH session.

    The remote command is restricted to Python reading a program from stdin. This
    keeps program data out of shell arguments and bounds output and execution.
    """
    try:
        host = str(ipaddress.IPv4Address(host))
    except ValueError as exc:
        raise SameInterfaceGatewayAcceptanceError("The SSH host must be an IPv4 literal.") from exc
    if (
        not username
        or len(username) > 64
        or not username.replace("_", "a").replace("-", "a").isalnum()
        or not password
        or "\n" in password
        or "\r" in password
        or command not in {"python3 -", "/usr/bin/python3 -", "sudo -n python3 -", "sudo -n /usr/bin/python3 -", "sudo -n /opt/atlaso/.venv/bin/python -I -", "/opt/atlaso/.venv/bin/python -I -"}
        or len(stdin_data) > _MAX_GUEST_PROGRAM
        or timeout <= 0
        or timeout > 60
    ):
        raise SameInterfaceGatewayAcceptanceError("The bounded SSH command input is invalid.")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedEd25519HostKeyPolicy(host, fingerprint))
    channel: paramiko.Channel | None = None
    try:
        client.connect(
            host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        remote_stdin, remote_stdout, _remote_stderr = client.exec_command(command, timeout=timeout, get_pty=False)
        channel = remote_stdout.channel
        remote_stdin.write(stdin_data)
        remote_stdin.flush()
        channel.shutdown_write()
        deadline = time.monotonic() + timeout
        output = bytearray()
        readiness_checked = on_ready is None
        while not channel.exit_status_ready():
            if time.monotonic() >= deadline:
                raise SameInterfaceGatewayAcceptanceError("The bounded SSH command timed out.")
            if channel.recv_ready():
                output.extend(channel.recv(4096))
                if len(output) > _MAX_SSH_OUTPUT:
                    raise SameInterfaceGatewayAcceptanceError("The bounded SSH command exceeded its output limit.")
                if not readiness_checked and b"\n" in output:
                    first_line = bytes(output).split(b"\n", 1)[0]
                    if first_line != b'{"ready":true}':
                        raise SameInterfaceGatewayAcceptanceError("The guest capture did not report readiness.")
                    readiness_checked = True
                    on_ready()
                    if time.monotonic() >= deadline:
                        raise SameInterfaceGatewayAcceptanceError("The bounded SSH command timed out.")
            if channel.recv_stderr_ready():
                _ = channel.recv_stderr(4096)
            select.select([channel], [], [], 0.05)
        if not readiness_checked:
            raise SameInterfaceGatewayAcceptanceError("The guest capture did not report readiness.")
        while channel.recv_ready():
            output.extend(channel.recv(4096))
            if len(output) > _MAX_SSH_OUTPUT:
                raise SameInterfaceGatewayAcceptanceError("The bounded SSH command exceeded its output limit.")
        if channel.recv_exit_status() != 0:
            raise SameInterfaceGatewayAcceptanceError("The bounded SSH command failed on the guest.")
        return bytes(output)
    except SameInterfaceGatewayAcceptanceError:
        raise
    except Exception as exc:
        raise SameInterfaceGatewayAcceptanceError("The pinned SSH command could not be completed safely.") from exc
    finally:
        if channel is not None:
            with suppress(Exception):
                channel.close()
        with suppress(Exception):
            client.close()


def _canonical_ipv4(value: str, label: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as exc:
        raise ValueError(f"{label} must be an IPv4 literal.") from exc


def _canonical_mac(value: str, label: str) -> str:
    if not _MAC_RE.fullmatch(value):
        raise ValueError(f"{label} must be a six-octet Ethernet address.")
    return value.lower()


def _decode_ethernet_ipv4_tcp_frame(payload: bytes, packet_type: int) -> dict[str, Any] | None:
    """Decode one bounded Ethernet IPv4 TCP frame; ignore other traffic."""
    if packet_type not in {0, 4} or len(payload) < 14 or int.from_bytes(payload[12:14], "big") != 0x0800:
        return None
    ip_offset = 14
    version_ihl = payload[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(payload) < ip_offset + ip_header_length:
        return None
    total_length = int.from_bytes(payload[ip_offset + 2 : ip_offset + 4], "big")
    if total_length < ip_header_length + 20 or len(payload) < ip_offset + total_length:
        return None
    if int.from_bytes(payload[ip_offset + 6 : ip_offset + 8], "big") & 0x3FFF:
        return None
    if payload[ip_offset + 9] != 6:
        return None
    tcp_offset = ip_offset + ip_header_length
    tcp_header_length = (payload[tcp_offset + 12] >> 4) * 4
    if tcp_header_length < 20 or total_length < ip_header_length + tcp_header_length:
        return None
    return {
        "packet_type": packet_type,
        "direction": "outgoing" if packet_type == 4 else "incoming",
        "src_mac": payload[6:12].hex(":").lower(),
        "dst_mac": payload[0:6].hex(":").lower(),
        "src_ip": str(ipaddress.IPv4Address(payload[ip_offset + 12 : ip_offset + 16])),
        "dst_ip": str(ipaddress.IPv4Address(payload[ip_offset + 16 : ip_offset + 20])),
        "src_port": int.from_bytes(payload[tcp_offset : tcp_offset + 2], "big"),
        "dst_port": int.from_bytes(payload[tcp_offset + 2 : tcp_offset + 4], "big"),
        "ttl": payload[ip_offset + 8],
        "ipv4_id": int.from_bytes(payload[ip_offset + 4 : ip_offset + 6], "big"),
    }


def guest_capture_program(client_ip: str, probe_ip: str, interface: str, duration: int = 8) -> str:
    """Build a bounded, payload-free guest program that emits TCP/443 frame records."""
    client = _canonical_ipv4(client_ip, "Client address")
    probe = _canonical_ipv4(probe_ip, "Probe address")
    if client == probe:
        raise ValueError("Client and probe addresses must differ.")
    if not _INTERFACE_RE.fullmatch(interface) or duration < 1 or duration > 30:
        raise ValueError("Capture interface or duration is invalid.")
    # Keep one decoder implementation for host tests and the guest capture.
    import inspect

    decoder = inspect.getsource(_decode_ethernet_ipv4_tcp_frame)
    decoder = decoder.replace("_decode_ethernet_ipv4_tcp_frame", "decode_frame", 1)
    source = f'''import ipaddress, json, socket, struct, time
from typing import Any
{decoder}
client_ip = {client!r}
probe_ip = {probe!r}
interface = {interface!r}
duration = {duration!r}
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.bind((interface, 0))
sock.settimeout(0.2)
print(json.dumps({{"ready": True}}, separators=(",", ":")), flush=True)
deadline = time.monotonic() + duration
emitted = 0
while time.monotonic() < deadline and emitted < 64:
    try:
        packet, address = sock.recvfrom(2048)
    except socket.timeout:
        continue
    record = decode_frame(packet, int(address[2]))
    if record and record["src_ip"] == client_ip and record["dst_ip"] == probe_ip and record["dst_port"] == 443:
        print(json.dumps({{"event": "frame", **record}}, separators=(",", ":")), flush=True)
        emitted += 1
sock.close()
print(json.dumps({{"event": "complete", "frame_count": emitted}}), flush=True)
'''
    if len(source.encode("utf-8")) > _MAX_GUEST_PROGRAM:
        raise ValueError("Capture program exceeded its size limit.")
    return source


def validate_forward_capture(
    frames: list[dict[str, Any]],
    *,
    client_mac: str,
    router_mac: str,
    gateway_mac: str,
    client_ip: str,
    probe_ip: str,
    expected_forwarded: bool,
) -> dict[str, Any]:
    """Require matching ingress and same-interface egress evidence, or its absence."""
    if type(expected_forwarded) is not bool:
        raise ValueError("Expected forwarding state must be a boolean.")
    client_mac = _canonical_mac(client_mac, "Client MAC")
    router_mac = _canonical_mac(router_mac, "Router MAC")
    gateway_mac = _canonical_mac(gateway_mac, "Gateway MAC")
    client_ip = _canonical_ipv4(client_ip, "Client address")
    probe_ip = _canonical_ipv4(probe_ip, "Probe address")
    if len(frames) > 64:
        raise ValueError("Capture contains too many frames.")

    ingress: list[dict[str, Any]] = []
    egress: list[dict[str, Any]] = []
    for frame in frames:
        try:
            packet_type = frame["packet_type"]
            direction = frame["direction"]
            source = _canonical_ipv4(frame["src_ip"], "Frame source")
            destination = _canonical_ipv4(frame["dst_ip"], "Frame destination")
            src_mac = _canonical_mac(frame["src_mac"], "Frame source MAC")
            dst_mac = _canonical_mac(frame["dst_mac"], "Frame destination MAC")
            source_port = frame["src_port"]
            dest_port = frame["dst_port"]
            ttl = frame["ttl"]
            ipv4_id = frame["ipv4_id"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Capture contains an invalid packet record.") from exc
        if (
            type(packet_type) is not int
            or direction not in {"incoming", "outgoing"}
            or type(source_port) is not int
            or type(dest_port) is not int
            or type(ttl) is not int
            or type(ipv4_id) is not int
            or not 1 <= source_port <= 65535
            or dest_port != 443
            or not 1 <= ttl <= 255
            or not 0 <= ipv4_id <= 65535
            or source != client_ip
            or destination != probe_ip
        ):
            continue
        record = {"packet_type": packet_type, "direction": direction, "src_mac": src_mac, "dst_mac": dst_mac,
                  "src_ip": source, "dst_ip": destination, "src_port": source_port, "dst_port": dest_port,
                  "ttl": ttl, "ipv4_id": ipv4_id}
        if direction == "incoming" and packet_type == 0 and src_mac == client_mac and dst_mac == router_mac:
            ingress.append(record)
        if direction == "outgoing" and packet_type == 4:
            egress.append(record)

    if not ingress:
        raise SameInterfaceGatewayAcceptanceError("No matching client packet reached the router interface.")
    if not expected_forwarded:
        if egress:
            raise SameInterfaceGatewayAcceptanceError("A client packet left the router while forwarding was disabled.")
        return {"forwarded": False, "ingress_frames": len(ingress), "egress_frames": 0}

    for incoming in ingress:
        for outgoing in egress:
            if (
                outgoing["src_mac"] == router_mac
                and outgoing["dst_mac"] == gateway_mac
                and outgoing["src_ip"] == incoming["src_ip"]
                and outgoing["dst_ip"] == incoming["dst_ip"]
                and outgoing["src_port"] == incoming["src_port"]
                and outgoing["dst_port"] == incoming["dst_port"]
                and outgoing["ipv4_id"] == incoming["ipv4_id"]
                and outgoing["ttl"] == incoming["ttl"] - 1
            ):
                return {"forwarded": True, "ingress_frames": len(ingress), "egress_frames": len(egress),
                        "ipv4_id": incoming["ipv4_id"], "ttl_before": incoming["ttl"],
                        "ttl_after": outgoing["ttl"], "source_port": incoming["src_port"]}
    raise SameInterfaceGatewayAcceptanceError("No same-interface forwarded packet matched the client ingress tuple.")
