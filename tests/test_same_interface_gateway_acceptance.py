"""Packet parsing and path-proof tests for same-interface gateway acceptance."""

from __future__ import annotations

import ipaddress
import struct
from typing import Any

import pytest

from scripts.interop import same_interface_gateway_acceptance as gateway

CLIENT_MAC = "02:00:00:00:00:10"
ROUTER_MAC = "02:00:00:00:00:20"
GATEWAY_MAC = "02:00:00:00:00:01"
CLIENT_IP = "192.168.1.10"
PROBE_IP = "1.1.1.1"


def _wire_frame(
    *,
    source_mac: str = CLIENT_MAC,
    destination_mac: str = ROUTER_MAC,
    source_ip: str = CLIENT_IP,
    destination_ip: str = PROBE_IP,
    source_port: int = 49152,
    destination_port: int = 443,
    ttl: int = 64,
    ipv4_id: int = 0x1234,
    packet_type: int = 0,
    protocol: int = 6,
    fragment: int = 0,
    ethertype: int = 0x0800,
) -> bytes:
    """Build one Ethernet IPv4 TCP packet for host-side tests.

    Args:
        source_mac: Ethernet source address in the generated frame.
        destination_mac: Ethernet destination address in the generated frame.
        source_ip: IPv4 source address in the generated packet.
        destination_ip: IPv4 destination address in the generated packet.
        source_port: TCP source port in the generated packet.
        destination_port: TCP destination port in the generated packet.
        ttl: IPv4 hop limit value encoded in the packet.
        ipv4_id: IPv4 identification value encoded in the packet.
        packet_type: Included for caller convenience; not encoded in frame bytes.
        protocol: IPv4 protocol number encoded in the header.
        fragment: IPv4 fragment flags and offset encoded in the header.
        ethertype: Ethernet protocol identifier for the generated payload.
    """
    tcp = struct.pack("!HHIIHHHH", source_port, destination_port, 0, 0, 5 << 12, 0, 0, 0)
    source = ipaddress.IPv4Address(source_ip).packed
    destination = ipaddress.IPv4Address(destination_ip).packed
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ipv4_id, fragment, ttl, protocol, 0,
                            source, destination)
    ethernet = bytes.fromhex(destination_mac.replace(":", "")) + bytes.fromhex(source_mac.replace(":", ""))
    return ethernet + struct.pack("!H", ethertype) + ip_header + tcp


def _frame(**kwargs: Any) -> dict[str, object]:
    """Build and decode one valid Ethernet IPv4 TCP packet.

    Args:
        **kwargs: Packet-field overrides passed to the wire-frame builder.
    """
    packet_type = int(kwargs.get("packet_type", 0))
    decoded = gateway._decode_ethernet_ipv4_tcp_frame(_wire_frame(**kwargs), packet_type)
    assert decoded is not None
    return decoded


def _forwarded_pair() -> list[dict[str, object]]:
    return [
        _frame(),
        _frame(
            source_mac=ROUTER_MAC,
            destination_mac=GATEWAY_MAC,
            ttl=63,
            packet_type=4,
        ),
    ]


def _validate(frames: list[dict[str, object]], *, forwarded: bool) -> dict[str, object]:
    """Validate packet metadata against the shared test fixture identities.

    Args:
        frames: Decoded frame records to evaluate.
        forwarded: Whether matching router egress is expected.
    """
    return gateway.validate_forward_capture(
        frames,
        client_mac=CLIENT_MAC,
        router_mac=ROUTER_MAC,
        gateway_mac=GATEWAY_MAC,
        client_ip=CLIENT_IP,
        probe_ip=PROBE_IP,
        expected_forwarded=forwarded,
    )


def test_decoder_extracts_payload_free_ipv4_tcp_identity():
    """The decoder returns only L2/L3/L4 metadata needed to prove forwarding."""
    decoded = _frame()

    assert decoded == {
        "packet_type": 0,
        "direction": "incoming",
        "src_mac": CLIENT_MAC,
        "dst_mac": ROUTER_MAC,
        "src_ip": CLIENT_IP,
        "dst_ip": PROBE_IP,
        "src_port": 49152,
        "dst_port": 443,
        "ttl": 64,
        "ipv4_id": 0x1234,
    }


@pytest.mark.parametrize("packet_type", [-1, 1, 3, 5, 7])
def test_decoder_rejects_unknown_packet_direction(packet_type: int):
    """Only host AF_PACKET incoming and outgoing packet types are accepted.

    Args:
        packet_type: Unsupported packet direction value supplied to the decoder.
    """
    assert gateway._decode_ethernet_ipv4_tcp_frame(b"\x00" * 64, packet_type) is None


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00" * 13,
        b"\x00" * 14,
        b"\x00" * 34,
    ],
)
def test_decoder_rejects_short_or_non_ipv4_frames(payload: bytes):
    """Short frames and wrong Ethernet types are ignored safely.

    Args:
        payload: Ethernet frame bytes that are truncated or use an unsupported type.
    """
    assert gateway._decode_ethernet_ipv4_tcp_frame(payload, 0) is None


@pytest.mark.parametrize(
    ("kwargs", "packet_type"),
    [
        ({"ethertype": 0x86DD}, 0),
        ({"protocol": 17}, 0),
        ({"fragment": 0x2000}, 0),
        ({}, 1),
    ],
    ids=["ipv6", "udp", "fragment", "otherhost"],
)
def test_decoder_ignores_non_tcp_fragments_and_bypass_packets(kwargs: dict[str, int], packet_type: int):
    """Packets that cannot prove a client-originated TCP path are ignored.

    Args:
        kwargs: Wire-frame fields that make the packet unsuitable as evidence.
        packet_type: AF_PACKET direction value for the frame.
    """
    assert gateway._decode_ethernet_ipv4_tcp_frame(_wire_frame(**kwargs), packet_type) is None


def test_decoder_rejects_invalid_ihl_total_length_and_tcp_header():
    """Malformed header lengths cannot be interpreted as path evidence."""
    base = bytearray(14 + 40)
    base[12:14] = b"\x08\x00"
    base[14] = 0x44
    assert gateway._decode_ethernet_ipv4_tcp_frame(bytes(base), 0) is None
    base[14] = 0x45
    base[16:18] = struct.pack("!H", 19)
    assert gateway._decode_ethernet_ipv4_tcp_frame(bytes(base), 0) is None
    base[16:18] = struct.pack("!H", 40)
    base[46] = 0x40
    assert gateway._decode_ethernet_ipv4_tcp_frame(bytes(base), 0) is None


def test_allowed_forward_requires_matching_tuple_identity_and_ttl_decrement():
    """The accepted proof pairs the same client packet across the router."""
    result = _validate(_forwarded_pair(), forwarded=True)

    assert result == {
        "forwarded": True,
        "ingress_frames": 1,
        "egress_frames": 1,
        "ipv4_id": 0x1234,
        "ttl_before": 64,
        "ttl_after": 63,
        "source_port": 49152,
    }


@pytest.mark.parametrize(
    "outgoing",
    [
        {"source_port": 49153},
        {"ipv4_id": 0x4321},
        {"ttl": 64},
        {"source_mac": GATEWAY_MAC},
        {"destination_mac": CLIENT_MAC},
        {"destination_ip": "8.8.8.8"},
    ],
    ids=["wrong-tuple", "wrong-ip-id", "no-hop", "wrong-router-mac", "wrong-gateway-mac", "wrong-target"],
)
def test_unrelated_or_bypass_egress_cannot_satisfy_allow_proof(outgoing: dict[str, object]):
    """An unrelated packet or direct-bypass destination is not router forwarding.

    Args:
        outgoing: One egress packet field changed to invalidate the matching proof.
    """
    packet = {"source_mac": ROUTER_MAC, "destination_mac": GATEWAY_MAC, "ttl": 63, **outgoing}
    frames = [_frame(), _frame(**packet, packet_type=4)]

    with pytest.raises(gateway.SameInterfaceGatewayAcceptanceError, match="No same-interface"):
        _validate(frames, forwarded=True)


def test_allowed_forward_requires_router_ingress():
    """An outgoing frame alone cannot prove a client packet traversed the router."""
    with pytest.raises(gateway.SameInterfaceGatewayAcceptanceError, match="No matching client packet"):
        _validate([_forwarded_pair()[1]], forwarded=True)


def test_denied_forward_requires_ingress_and_no_egress():
    """A disabled permission is proven by ingress plus absence of matching egress."""
    result = _validate([_frame()], forwarded=False)
    assert result == {"forwarded": False, "ingress_frames": 1, "egress_frames": 0}

    with pytest.raises(gateway.SameInterfaceGatewayAcceptanceError, match="left the router"):
        _validate(_forwarded_pair(), forwarded=False)


def test_bypass_or_unrelated_records_do_not_count_as_router_ingress():
    """Otherhost and wrong-client records cannot stand in for the router's ingress."""
    bypass = {**_frame(), "packet_type": 1}
    unrelated = _frame(source_ip="192.168.1.11")

    with pytest.raises(gateway.SameInterfaceGatewayAcceptanceError, match="No matching client packet"):
        _validate([bypass, unrelated], forwarded=False)


def test_capture_program_filters_probe_and_validates_inputs():
    """The guest capture is bounded, payload-free, and only records TCP/443."""
    source = gateway.guest_capture_program(CLIENT_IP, PROBE_IP, "eth0", duration=5)
    assert 'record["dst_port"] == 443' in source
    assert "emitted < 64" in source
    assert '"ready": True' in source
    assert '"event": "complete"' in source
    assert "AF_PACKET" in source
    compile(source, "gateway-capture.py", "exec")

    for args in [
        ("not-an-ip", PROBE_IP, "eth0", 5),
        (CLIENT_IP, CLIENT_IP, "eth0", 5),
        (CLIENT_IP, PROBE_IP, "bad interface", 5),
        (CLIENT_IP, PROBE_IP, "eth0", 0),
        (CLIENT_IP, PROBE_IP, "eth0", 31),
    ]:
        with pytest.raises(ValueError):
            gateway.guest_capture_program(*args)


def test_forward_validator_rejects_invalid_capture_records_and_bounds():
    """Malformed, oversized, and non-boolean evidence cannot pass validation."""
    with pytest.raises(ValueError, match="invalid packet record"):
        _validate([{"direction": "incoming"}], forwarded=False)
    with pytest.raises(ValueError, match="too many frames"):
        _validate([{}] * 65, forwarded=False)
    with pytest.raises(ValueError, match="boolean"):
        gateway.validate_forward_capture(
            [], client_mac=CLIENT_MAC, router_mac=ROUTER_MAC, gateway_mac=GATEWAY_MAC,
            client_ip=CLIENT_IP, probe_ip=PROBE_IP, expected_forwarded=1,
        )


def test_pinned_ssh_helper_invokes_readiness_callback_once(monkeypatch):
    """A capture can trigger its client probe after the guest confirms readiness.

    Args:
        monkeypatch: Pytest fixture for replacing the SSH client and socket selector.
    """
    output = b'{"ready":true}\n{"event":"frame"}\n'
    calls: list[object] = []

    class FakeChannel:
        def __init__(self):
            """Initialize the channel with its bounded standard-output fixture."""
            self.remaining = output

        def shutdown_write(self):
            """Record the end of the guest program input stream."""
            pass

        def exit_status_ready(self):
            """Report completion after all fixture output has been read."""
            return not self.remaining

        def recv_ready(self):
            """Report whether the channel has standard output to read."""
            return bool(self.remaining)

        def recv(self, size):
            """Return at most the requested bytes from the fixture output.

            Args:
                size: Maximum number of output bytes to return.
            """
            chunk, self.remaining = self.remaining[:size], self.remaining[size:]
            return chunk

        def recv_stderr_ready(self):
            """Report that the fixture has no standard-error bytes."""
            return False

        def recv_exit_status(self):
            """Return a successful fixture command status."""
            return 0

        def close(self):
            """Close the fake channel without additional effects."""
            pass

    class FakeStdin:
        def write(self, data):
            """Record bytes written to the guest program input.

            Args:
                data: Guest program bytes sent by the helper.
            """
            calls.append(("stdin", data))

        def flush(self):
            """Complete the fake input write operation."""
            pass

    class FakeStdout:
        def __init__(self, channel):
            """Expose the fake channel through Paramiko's stdout wrapper.

            Args:
                channel: Fake channel used by the SSH helper test.
            """
            self.channel = channel

    class FakeClient:
        def set_missing_host_key_policy(self, policy):
            """Record the host-key policy configured by the SSH helper.

            Args:
                policy: Pinned host-key policy installed on this fake client.
            """
            calls.append(("policy", policy))

        def connect(self, host, **kwargs):
            """Record the connection target and authentication options.

            Args:
                host: IPv4 SSH endpoint supplied by the helper.
                **kwargs: Connection and authentication options.
            """
            calls.append(("connect", host, kwargs))

        def exec_command(self, command, **kwargs):
            """Return fake stdin/stdout channels for the requested command.

            Args:
                command: Fixed Python stdin command selected by the helper.
                **kwargs: Command transport options supplied to Paramiko.
            """
            calls.append(("command", command, kwargs))
            return FakeStdin(), FakeStdout(FakeChannel()), object()

        def close(self):
            """Record closure of the fake SSH client."""
            calls.append(("close",))

    monkeypatch.setattr(gateway.paramiko, "SSHClient", FakeClient)
    monkeypatch.setattr(gateway.select, "select", lambda *args: ([], [], []))
    ready_calls = []

    result = gateway.run_pinned_ssh_command(
        "192.0.2.1", "atlaso", "secret", "SHA256:" + "a" * 43, "python3 -",
        stdin_data=b"print('ready')", on_ready=lambda: ready_calls.append("probe"),
    )

    assert result == output
    assert ready_calls == ["probe"]
    connect = next(call for call in calls if call[0] == "connect")
    assert connect[2]["look_for_keys"] is False
    assert connect[2]["allow_agent"] is False


def test_pinned_ssh_helper_requires_exact_readiness_line_when_callback_is_requested(monkeypatch):
    """A capture that does not emit the exact readiness event cannot race a probe.

    Args:
        monkeypatch: Pytest fixture for replacing the SSH client and socket selector.
    """

    class FakeChannel:
        def __init__(self):
            """Initialize the channel with an invalid readiness record."""
            self.remaining = b'{"ready":false}\n'

        def shutdown_write(self):
            """Record the end of the guest program input stream."""
            pass

        def exit_status_ready(self):
            """Report completion after the invalid readiness line is read."""
            return not self.remaining

        def recv_ready(self):
            """Report whether the channel has standard output to read."""
            return bool(self.remaining)

        def recv(self, size):
            """Return at most the requested bytes from the invalid readiness line.

            Args:
                size: Maximum number of output bytes to return.
            """
            chunk, self.remaining = self.remaining[:size], self.remaining[size:]
            return chunk

        def recv_stderr_ready(self):
            """Report that the fixture has no standard-error bytes."""
            return False

        def close(self):
            """Close the fake channel without additional effects."""
            pass

    class FakeStdin:
        def write(self, data):
            """Accept the guest program bytes sent by the helper.

            Args:
                data: Guest program bytes sent by the helper.
            """
            pass

        def flush(self):
            """Complete the fake input write operation."""
            pass

    class FakeStdout:
        def __init__(self):
            """Expose the invalid-readiness channel as stdout."""
            self.channel = FakeChannel()

    class FakeClient:
        def set_missing_host_key_policy(self, policy):
            """Accept the SSH host-key policy installed by the helper.

            Args:
                policy: Pinned host-key policy installed on this fake client.
            """
            pass

        def connect(self, host, **kwargs):
            """Accept the validated SSH endpoint and connection options.

            Args:
                host: IPv4 SSH endpoint supplied by the helper.
                **kwargs: Connection and authentication options.
            """
            pass

        def exec_command(self, command, **kwargs):
            """Return fake channels that emit an invalid readiness line.

            Args:
                command: Fixed Python stdin command selected by the helper.
                **kwargs: Command transport options supplied to Paramiko.
            """
            return FakeStdin(), FakeStdout(), object()

        def close(self):
            """Close the fake SSH client without additional effects."""
            pass

    monkeypatch.setattr(gateway.paramiko, "SSHClient", FakeClient)
    monkeypatch.setattr(gateway.select, "select", lambda *args: ([], [], []))

    with pytest.raises(gateway.SameInterfaceGatewayAcceptanceError, match="did not report readiness"):
        gateway.run_pinned_ssh_command(
            "192.0.2.1", "atlaso", "secret", "SHA256:" + "a" * 43, "python3 -",
            on_ready=lambda: pytest.fail("readiness callback ran for an invalid event"),
        )


@pytest.mark.parametrize(
    ("host", "username", "command", "stdin_data", "timeout"),
    [
        ("example.com", "atlaso", "python3 -", b"", 1),
        ("192.0.2.1", "bad user", "python3 -", b"", 1),
        ("192.0.2.1", "atlaso", "python3 -; id", b"", 1),
        ("192.0.2.1", "atlaso", "python3 -", b"x" * 16_385, 1),
        ("192.0.2.1", "atlaso", "python3 -", b"", 61),
    ],
)
def test_pinned_ssh_helper_rejects_unsafe_inputs_before_connect(host, username, command, stdin_data, timeout):
    """The helper validates literal hosts and a fixed Python stdin command set.

    Args:
        host: Candidate address tested against the IPv4-literal requirement.
        username: Candidate account name tested against the safe-name requirement.
        command: Candidate remote command tested against the fixed allowlist.
        stdin_data: Guest program bytes tested against the input-size bound.
        timeout: Command timeout tested against the permitted range.
    """
    with pytest.raises(gateway.SameInterfaceGatewayAcceptanceError):
        gateway.run_pinned_ssh_command(
            host, username, "secret", "SHA256:" + "a" * 43, command,
            stdin_data=stdin_data, timeout=timeout,
        )
