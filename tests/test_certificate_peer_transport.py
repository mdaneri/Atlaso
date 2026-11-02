"""Focused checks for the task-owned private HTTPS transport boundary."""

from __future__ import annotations

import base64
import hashlib
import os
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


@pytest.mark.parametrize("authentication_mode", ["agent", "dpapi-task-key"])
def test_peer_uses_only_matching_selected_key(monkeypatch: pytest.MonkeyPatch, authentication_mode: str) -> None:
    """An untrusted peer receives an SSH signature, never a password.

    Args:
        monkeypatch: Replaces socket and agent operations without opening a network connection.
        authentication_mode: Explicit key provider exercised by this case.
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
    if authentication_mode == "dpapi-task-key":
        monkeypatch.setenv("ATLASO_NATIVE_PEER_KEY", "synthetic-test-fixture")
        monkeypatch.setattr(paramiko.Ed25519Key, "from_private_key", lambda stream: selected)
        monkeypatch.setattr(paramiko, "Agent", lambda: pytest.fail("Protected mode must not access the agent"))
    host_pin = "SHA256:" + base64.b64encode(hashlib.sha256(host_blob).digest()).decode("ascii").rstrip("=")
    public_key = "ssh-ed25519 " + base64.b64encode(public_blob).decode("ascii")
    with PinnedPeerTransport("192.168.167.20", "alpine", public_key, host_pin, "192.168.77.0/24",
                             authentication_mode=authentication_mode):
        assert called == [("alpine", selected)]
        assert "ATLASO_NATIVE_PEER_KEY" not in os.environ


@pytest.mark.parametrize("failure", ["required", "invalid", "mismatch"])
def test_protected_mode_never_falls_back_on_missing_key(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    """Reject absent protected credentials before any signing request.

    Args:
        monkeypatch: Replaces handshake and agent without opening a network connection.
        failure: Missing, malformed, or mismatched protected credential.
    """
    host = b"host-key"
    class Transport:
        def start_client(self, **kwargs):
            """Accept a synthetic handshake.

            Args:
                **kwargs: Ignored handshake options.
            """
        def get_remote_server_key(self):
            """Return the independently pinned synthetic host key."""
            return type("Key", (), {"asbytes": lambda self: host})()
        def close(self):
            """Release the synthetic transport."""
    monkeypatch.delenv("ATLASO_NATIVE_PEER_KEY", raising=False)
    if failure != "required":
        monkeypatch.setenv("ATLASO_NATIVE_PEER_KEY", "synthetic-invalid-key")
    if failure == "mismatch":
        monkeypatch.setattr(paramiko.Ed25519Key, "from_private_key", lambda stream: type("Key", (), {"asbytes": lambda self: b"substitute"})())
    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: object())
    monkeypatch.setattr(paramiko, "Transport", lambda sock: Transport())
    monkeypatch.setattr(paramiko, "Agent", lambda: pytest.fail("No agent fallback"))
    pin = "SHA256:" + base64.b64encode(hashlib.sha256(host).digest()).decode().rstrip("=")
    with pytest.raises(PeerTransportRefusal, match="peer_protected_key_" + failure):
        with PinnedPeerTransport("192.168.167.20", "alpine", "ssh-ed25519 " + "A" * 44,
                                 pin, "192.168.77.0/24", authentication_mode="dpapi-task-key"):
            pytest.fail("Missing key admitted")


@pytest.mark.parametrize(
    ("failure_code", "active_after", "authenticated_after", "expected"),
    [
        (paramiko.OPEN_FAILED_CONNECT_FAILED, True, True, False),
        (paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, True, True, "refuse"),
        (paramiko.OPEN_FAILED_CONNECT_FAILED, False, True, "refuse"),
        (paramiko.OPEN_FAILED_CONNECT_FAILED, True, False, "refuse"),
    ],
)
def test_tcp_probe_counts_only_authenticated_live_connect_failure_as_closed(
    failure_code: int, active_after: bool, authenticated_after: bool, expected: bool | str,
) -> None:
    """Do not treat administrative denial or loss of the authenticated peer as a closed port.

    Args:
        failure_code: SSH channel refusal simulated by the authenticated peer.
        active_after: Whether the peer transport remains active after refusal.
        authenticated_after: Whether the peer remains authenticated after refusal.
        expected: Closed-port observation or an explicit refusal expectation.
    """
    peer = PinnedPeerTransport(
        "192.168.167.20", "alpine", "ssh-ed25519 " + "A" * 44,
        "SHA256:" + "A" * 43, "192.168.77.0/24",
    )

    class ProbeTransport:
        active = True
        authenticated = True

        def is_active(self) -> bool:
            return self.active

        def is_authenticated(self) -> bool:
            return self.authenticated

        def open_channel(self, *_args, **_kwargs):
            """Simulate the specified failure after updating transport state.

            Args:
                *_args: Ignored requested channel endpoint arguments.
                **_kwargs: Ignored channel timeout options.
            """
            self.active = active_after
            self.authenticated = authenticated_after
            raise paramiko.ChannelException(failure_code, "test refusal")

    peer.transport = ProbeTransport()  # type: ignore[assignment]  # Fake exercises the probe's transport checks.
    if expected == "refuse":
        with pytest.raises(PeerTransportRefusal, match="peer_tcp_probe_unproven"):
            peer.tcp_reachable("192.168.77.40")
    else:
        assert peer.tcp_reachable("192.168.77.40") is expected


def test_tcp_probe_reports_open_and_requires_active_authenticated_ssh() -> None:
    peer = PinnedPeerTransport(
        "192.168.167.20", "alpine", "ssh-ed25519 " + "A" * 44,
        "SHA256:" + "A" * 43, "192.168.77.0/24",
    )

    class OpenChannel:
        closed = False

        def close(self) -> None:
            self.closed = True

    class ActiveTransport:
        active = True
        authenticated = True
        channel = OpenChannel()

        def is_active(self) -> bool:
            return self.active

        def is_authenticated(self) -> bool:
            return self.authenticated

        def open_channel(self, *_args, **_kwargs):
            """Return the simulated accepted TCP channel.

            Args:
                *_args: Ignored requested channel endpoint arguments.
                **_kwargs: Ignored channel timeout options.
            """
            return self.channel

    transport = ActiveTransport()
    peer.transport = transport  # type: ignore[assignment]  # Fake exercises the probe only.
    assert peer.tcp_reachable("192.168.77.40") is True
    assert transport.channel.closed
    transport.authenticated = False
    with pytest.raises(PeerTransportRefusal, match="peer_transport_inactive"):
        peer.tcp_reachable("192.168.77.40")
