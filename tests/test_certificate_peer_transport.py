"""Focused checks for the task-owned private HTTPS transport boundary."""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
from certificate_peer_transport import (  # noqa: E402 - Local script import.
    PeerTransportRefusal,
    PinnedPeerTransport,
)


class FakeTransport:
    """A fake direct-tcpip endpoint without SSH or a VM."""

    def is_active(self) -> bool:
        return True

    def open_channel(self, kind: str, destination: tuple[str, int], origin: tuple[str, int], timeout: int):
        assert kind == "direct-tcpip"
        assert destination == ("192.168.77.10", 443)
        assert origin == ("127.0.0.1", 0)
        assert timeout == 8
        proxy, server = socket.socketpair()

        def serve() -> None:
            try:
                data = server.recv(4096)
                server.sendall(data.upper())
            finally:
                server.close()

        threading.Thread(target=serve, daemon=True).start()
        return proxy


def test_private_socket_forwards_only_inside_owned_subnet() -> None:
    peer = PinnedPeerTransport("192.168.167.20", "alpine", "unused", "SHA256:" + "A" * 43, "192.168.77.0/24")
    peer.transport = FakeTransport()  # type: ignore[assignment]  # Local fake implements the exercised transport methods.
    with pytest.raises(PeerTransportRefusal, match="target_outside_owned_private_subnet"):
        peer.open_socket("192.168.167.172")
    with pytest.raises(PeerTransportRefusal, match="target_outside_owned_private_subnet"):
        peer.open_socket("192.168.77.10", 80)
    connection = peer.open_socket("192.168.77.10")
    try:
        connection.settimeout(2)
        connection.sendall(b"hello")
        assert connection.recv(4096) == b"HELLO"
    finally:
        connection.close()


def test_host_key_pin_is_required() -> None:
    with pytest.raises(PeerTransportRefusal, match="peer_host_key_pin_invalid"):
        PinnedPeerTransport("192.168.167.20", "alpine", "unused", "", "192.168.77.0/24")
