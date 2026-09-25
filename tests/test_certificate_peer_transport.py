"""Focused checks for the task-owned private HTTPS transport boundary."""

from __future__ import annotations

import base64
import hashlib
import socket
import sys
import threading
from pathlib import Path

import paramiko
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
        """Handle open channel for certificate handoff verification.

        Args:
            kind: Kind used by this operation.
            destination: Destination endpoint of the transport.
            origin: Origin endpoint of the transport.
            timeout: Timeout used by this operation."""
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
    peer = PinnedPeerTransport("192.168.167.20", "alpine", "ssh-ed25519 " + "A" * 44,
                               "SHA256:" + "A" * 43, "192.168.77.0/24")
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
        PinnedPeerTransport("192.168.167.20", "alpine", "ssh-ed25519 " + "A" * 44, "", "192.168.77.0/24")


def test_peer_uses_only_matching_agent_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """An untrusted peer receives an SSH signature, never a password.

    Args:
        monkeypatch: Replaces socket and agent operations without opening a network connection.
    """
    public_blob = b"selected-ed25519-public-blob"
    host_blob = b"peer-host-key"
    selected = type("Key", (), {"get_name": lambda self: "ssh-ed25519",
                                 "asbytes": lambda self: public_blob})()
    other = type("Key", (), {"get_name": lambda self: "ssh-ed25519",
                              "asbytes": lambda self: b"different-key"})()
    called: list[object] = []

    class Transport:
        def __init__(self, _socket: object) -> None:
            """Create a fake peer transport.

            Args:
                _socket: Ignored network socket.
            """
            pass

        def start_client(self, *, timeout: int) -> None:
            """Record the bounded handshake.

            Args:
                timeout: Maximum handshake time.
            """
            assert timeout == 8

        def get_remote_server_key(self) -> object:
            """Return the pinned test host key."""
            return type("HostKey", (), {"asbytes": lambda self: host_blob})()

        def auth_publickey(self, username: str, key: object) -> None:
            """Record the selected agent authentication.

            Args:
                username: Peer SSH account.
                key: Agent key offered to the peer.
            """
            called.append((username, key))

        def is_authenticated(self) -> bool:
            """Report successful key authentication."""
            return True

        def close(self) -> None:
            """Close the fake SSH connection."""
            pass

    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(paramiko, "Transport", Transport)
    monkeypatch.setattr(paramiko, "Agent", lambda: type("Agent", (), {"get_keys": lambda self: [other, selected]})())
    host_pin = "SHA256:" + base64.b64encode(hashlib.sha256(host_blob).digest()).decode("ascii").rstrip("=")
    public_key = "ssh-ed25519 " + base64.b64encode(public_blob).decode("ascii")
    with PinnedPeerTransport("192.168.167.20", "alpine", public_key, host_pin, "192.168.77.0/24"):
        assert called == [("alpine", selected)]
