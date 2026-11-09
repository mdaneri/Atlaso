"""Offline packet and deadline checks for the passive native ingress observer."""

import socket
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_packet_capture as capture  # noqa: E402 - Guest program under test.

SOURCE = "192.168.77.1"
TARGET = "192.168.77.10"
PORT = 45678


def request_packet(*, options=False):
    """Build a complete cooked IPv4/UDP query independently of the observer.

    Args:
        options: Include a four-byte IPv4 options area.
    """
    extra = b"\x01" * 4 if options else b""
    header = struct.pack("!BBHHHBBH4s4s", 0x46 if options else 0x45, 0, 76 + len(extra), 1234, 0x4000,
                         64, 17, 0, socket.inet_aton(SOURCE), socket.inet_aton(TARGET))
    return header + extra + struct.pack("!HHHH", PORT, 123, 56, 0) + b"\x23" + bytes(39) + b"12345678"


@pytest.mark.parametrize("options", [False, True])
def test_only_exact_incoming_query_matches_with_or_without_ip_options(options):
    """Cooked packet parsing honors the IPv4 header length.

    Args:
        options: Whether this real wire layout includes IPv4 options.
    """
    assert capture.matches_request(request_packet(options=options), 0,
                                   socket.inet_aton(SOURCE), socket.inet_aton(TARGET), PORT)


@pytest.mark.parametrize("mutation", [
    "outgoing", "broadcast", "version", "short-header", "fragment-offset", "more-fragments", "tcp",
    "short-total", "large-total", "source", "target", "source-port", "target-port", "udp-length",
    "server-mode", "empty-nonce", "truncated",
])
def test_unrelated_malformed_fragmented_or_outgoing_bytes_never_prove_ingress(mutation):
    """A response, stale tuple or partial packet cannot satisfy request delivery.

    Args:
        mutation: Invalid native packet property to substitute.
    """
    packet = bytearray(request_packet())
    packet_type = 0
    if mutation == "outgoing":
        packet_type = 4
    elif mutation == "broadcast":
        packet_type = 1
    elif mutation == "version":
        packet[0] = 0x65
    elif mutation == "short-header":
        packet[0] = 0x44
    elif mutation == "fragment-offset":
        struct.pack_into("!H", packet, 6, 1)
    elif mutation == "more-fragments":
        struct.pack_into("!H", packet, 6, 0x2000)
    elif mutation == "tcp":
        packet[9] = 6
    elif mutation in {"short-total", "large-total"}:
        struct.pack_into("!H", packet, 2, 75 if mutation == "short-total" else 77)
    elif mutation == "source":
        packet[12:16] = socket.inet_aton("192.168.77.2")
    elif mutation == "target":
        packet[16:20] = socket.inet_aton("192.168.77.11")
    elif mutation == "source-port":
        struct.pack_into("!H", packet, 20, PORT + 1)
    elif mutation == "target-port":
        struct.pack_into("!H", packet, 22, 124)
    elif mutation == "udp-length":
        struct.pack_into("!H", packet, 24, 55)
    elif mutation == "server-mode":
        packet[28] = 0x24
    elif mutation == "empty-nonce":
        packet[-8:] = bytes(8)
    else:
        del packet[-1:]
    assert not capture.matches_request(bytes(packet), packet_type,
                                       socket.inet_aton(SOURCE), socket.inet_aton(TARGET), PORT)


@pytest.fixture
def observer(monkeypatch):
    """Substitute only the privileged socket and monotonic clock.

    Args:
        monkeypatch: Scoped Linux socket and clock stand-ins for Windows testing.
    """
    stream = MagicMock()
    stream.__enter__.return_value = stream
    stream.recvfrom.return_value = (request_packet(), ("eth0", 0x0800, 0, 1, bytes(6)))
    factory = Mock(return_value=stream)
    monkeypatch.setattr(capture, "socket", SimpleNamespace(AF_PACKET=17, SOCK_DGRAM=2,
                                                         htons=socket.htons, socket=factory))
    clock = Mock(return_value=0.0)
    monkeypatch.setattr(capture, "time", SimpleNamespace(monotonic=clock))
    return SimpleNamespace(stream=stream, factory=factory, clock=clock)


def test_capture_observes_without_binding_transmitting_or_changing_membership(observer, capsys):
    """Only two fixed markers leave the passive observer; no bytes are published.

    Args:
        observer: Privileged socket stand-in receiving the exact query.
        capsys: Captures the observer's fixed public markers.
    """
    capture.capture(SOURCE, TARGET, PORT)
    observer.factory.assert_called_once_with(17, 2, socket.htons(0x0800))
    for method in ("bind", "send", "sendto", "setsockopt"):
        getattr(observer.stream, method).assert_not_called()
    observer.stream.__exit__.assert_called_once()
    assert capsys.readouterr().out == "capture_ready\nrequest_delivered\n"


@pytest.mark.parametrize("failure", ["timeout", "packet-budget", "byte-budget", "late-packet"])
def test_capture_deadlines_and_resource_caps_cannot_publish_delivery(observer, capsys, failure):
    """Timeout, noise and late arrivals remain failed ingress observations.

    Args:
        observer: Native socket and private clock stand-ins.
        capsys: Captures the allowlisted observer output.
        failure: Exhausted deadline or resource bound.
    """
    if failure == "timeout":
        observer.stream.recvfrom.side_effect = TimeoutError()
    elif failure == "packet-budget":
        observer.stream.recvfrom.return_value = (b"", ("eth0", 0x0800, 0, 1, bytes(6)))
    elif failure == "byte-budget":
        observer.stream.recvfrom.return_value = (bytes(65535), ("eth0", 0x0800, 0, 1, bytes(6)))
    else:
        observer.clock.side_effect = [0.0, 0.0, 9.0]
    with pytest.raises(RuntimeError, match="ntp_capture_"):
        capture.capture(SOURCE, TARGET, PORT)
    assert observer.stream.recvfrom.call_count <= 4096
    observer.stream.__exit__.assert_called_once()
    assert capsys.readouterr().out == "capture_ready\n"
