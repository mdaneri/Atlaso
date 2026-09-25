"""Pinned VMware peer SSH transport for private management HTTPS probes.

TLS terminates on the host with the caller's explicit CA and original target
hostname. The peer only forwards bytes over its task-owned private adapter.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import ipaddress
import socket
import ssl
import threading
import urllib.request
from contextlib import AbstractContextManager

import paramiko


class PeerTransportRefusal(Exception):
    """Fixed non-secret transport refusal."""


def _forward(source: socket.socket | paramiko.Channel, destination: socket.socket | paramiko.Channel) -> None:
    """Handle forward for certificate handoff verification.

    Args:
        source: Source resource bound to the test plan.
        destination: Destination endpoint of the transport."""
    try:
        while chunk := source.recv(16_384):
            destination.sendall(chunk)
    except (OSError, EOFError, paramiko.SSHException):
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except (OSError, EOFError, paramiko.SSHException):
            pass


def _run_bridge(bridge: socket.socket, channel: paramiko.Channel) -> None:
    """Handle run bridge for certificate handoff verification.

    Args:
        bridge: Socket bridge for the private transport.
        channel: SSH channel carrying the private transport."""
    left = threading.Thread(target=_forward, args=(bridge, channel), daemon=True)
    right = threading.Thread(target=_forward, args=(channel, bridge), daemon=True)
    left.start()
    right.start()
    left.join()
    right.join()
    bridge.close()
    channel.close()


class PinnedPeerTransport(AbstractContextManager["PinnedPeerTransport"]):
    """Open only private-subnet TCP channels through one pinned peer SSH key."""

    def __init__(self, peer_ip: str, username: str, public_key: str, host_key: str, subnet: str):
        """Initialize the validated client or test double.

        Args:
            peer_ip: Private-LAN peer address.
            username: Account name for this request.
            public_key: Exact public key selected from the local SSH agent.
            host_key: Expected SSH host key for the peer.
            subnet: Expected private-LAN subnet."""
        self.peer_ip = str(ipaddress.IPv4Address(peer_ip))
        self.username = username
        self.public_key = public_key
        self.host_key = host_key
        self.subnet = ipaddress.IPv4Network(subnet, strict=False)
        self.transport: paramiko.Transport | None = None
        if not host_key.startswith("SHA256:") or len(host_key) != 50:
            raise PeerTransportRefusal("peer_host_key_pin_invalid")
        parts = public_key.split()
        if len(parts) < 2 or parts[0] != "ssh-ed25519":
            raise PeerTransportRefusal("peer_agent_public_key_invalid")
        try:
            self.public_blob = base64.b64decode(parts[1], validate=True)
        except (ValueError, binascii.Error):
            raise PeerTransportRefusal("peer_agent_public_key_invalid") from None

    def __enter__(self) -> PinnedPeerTransport:
        sock = None
        transport = None
        try:
            sock = socket.create_connection((self.peer_ip, 22), timeout=8)
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=8)
            observed = "SHA256:" + base64.b64encode(
                hashlib.sha256(transport.get_remote_server_key().asbytes()).digest()
            ).decode("ascii").rstrip("=")
            if observed != self.host_key:
                raise PeerTransportRefusal("peer_host_key_changed")
            matching_keys = [key for key in paramiko.Agent().get_keys()
                             if key.get_name() == "ssh-ed25519" and key.asbytes() == self.public_blob]
            if len(matching_keys) != 1:
                raise PeerTransportRefusal("peer_agent_identity_unavailable")
            transport.auth_publickey(self.username, matching_keys[0])
            if not transport.is_authenticated():
                raise PeerTransportRefusal("peer_authentication_failed")
            self.transport = transport
            return self
        except PeerTransportRefusal:
            raise
        except (OSError, EOFError, paramiko.SSHException):
            raise PeerTransportRefusal("peer_connection_failed") from None
        finally:
            if self.transport is None:
                if transport is not None:
                    transport.close()
                elif sock is not None:
                    sock.close()

    def __exit__(self, *args: object) -> None:
        """Handle exit for certificate handoff verification.

        Args:
            *args: Args used by this operation."""
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def open_socket(self, target_ip: str, port: int = 443) -> socket.socket:
        """Return a real local socket whose remote bytes cross the pinned peer.

        Args:
            target_ip: Pinned destination address for the connection.
            port: TCP port of the target service."""
        address = ipaddress.IPv4Address(target_ip)
        if address not in self.subnet or port not in (22, 443):
            raise PeerTransportRefusal("target_outside_owned_private_subnet")
        if self.transport is None or not self.transport.is_active():
            raise PeerTransportRefusal("peer_transport_inactive")
        local, bridge = socket.socketpair()
        channel = None
        try:
            channel = self.transport.open_channel(
                "direct-tcpip", (str(address), port), ("127.0.0.1", 0), timeout=8
            )
            if channel is None:
                raise PeerTransportRefusal("peer_private_channel_refused")
            threading.Thread(target=_run_bridge, args=(bridge, channel), daemon=True).start()
            return local
        except PeerTransportRefusal:
            raise
        except (OSError, EOFError, paramiko.SSHException):
            raise PeerTransportRefusal("peer_private_channel_refused") from None
        finally:
            if channel is None:
                bridge.close()
                local.close()

    def command(self, command: str, stdin: bytes = b"") -> bytes:
        """Read bounded peer output without persisting credentials or response text.

        Args:
            command: Command to execute on the pinned peer.
            stdin: Optional input sent to the command."""
        if self.transport is None or not self.transport.is_active():
            raise PeerTransportRefusal("peer_transport_inactive")
        try:
            channel = self.transport.open_session(timeout=8)
            channel.settimeout(30)
            channel.exec_command(command)
            if stdin:
                channel.sendall(stdin)
            channel.shutdown_write()
            output = channel.makefile("rb").read(65_537)
            if len(output) > 65_536 or channel.recv_exit_status() != 0:
                raise PeerTransportRefusal("peer_readback_failed")
            return output
        except PeerTransportRefusal:
            raise
        except (OSError, EOFError, paramiko.SSHException):
            raise PeerTransportRefusal("peer_readback_failed") from None
        finally:
            if "channel" in locals():
                channel.close()


class PinnedApplianceSession(AbstractContextManager["PinnedApplianceSession"]):
    """Read guest state via the peer while pinning the appliance SSH key too."""

    def __init__(self, peer: PinnedPeerTransport, private_ip: str, user: str, password: str, host_key: str):
        """Initialize the validated client or test double.

        Args:
            peer: Pinned private-LAN peer transport.
            private_ip: Private-LAN address used by the peer.
            user: User used by this operation.
            password: Credential held in memory for this request.
            host_key: Expected SSH host key for the peer."""
        self.peer = peer
        self.private_ip = private_ip
        self.user = user
        self.password = password
        self.host_key = host_key
        self.transport: paramiko.Transport | None = None
        if not host_key.startswith("SHA256:") or len(host_key) != 50:
            raise PeerTransportRefusal("appliance_host_key_pin_invalid")

    def __enter__(self) -> PinnedApplianceSession:
        sock = self.peer.open_socket(self.private_ip, 22)
        transport = None
        try:
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=8)
            observed = "SHA256:" + base64.b64encode(
                hashlib.sha256(transport.get_remote_server_key().asbytes()).digest()
            ).decode("ascii").rstrip("=")
            if observed != self.host_key:
                raise PeerTransportRefusal("appliance_host_key_changed")
            transport.auth_password(self.user, self.password)
            if not transport.is_authenticated():
                raise PeerTransportRefusal("appliance_authentication_failed")
            self.transport = transport
            return self
        except PeerTransportRefusal:
            raise
        except (OSError, EOFError, paramiko.SSHException):
            raise PeerTransportRefusal("appliance_connection_failed") from None
        finally:
            if self.transport is None:
                if transport is not None:
                    transport.close()
                else:
                    sock.close()

    def __exit__(self, *args: object) -> None:
        """Handle exit for certificate handoff verification.

        Args:
            *args: Args used by this operation."""
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def command(self, command: str) -> bytes:
        """Return allowlist-sized read-only guest output.

        Args:
            command: Command to execute on the pinned peer."""
        if self.transport is None or not self.transport.is_active():
            raise PeerTransportRefusal("appliance_transport_inactive")
        try:
            channel = self.transport.open_session(timeout=8)
            channel.settimeout(30)
            channel.exec_command(command)
            channel.shutdown_write()
            output = channel.makefile("rb").read(65_537)
            if len(output) > 65_536 or channel.recv_exit_status() != 0:
                raise PeerTransportRefusal("appliance_readback_failed")
            return output
        except PeerTransportRefusal:
            raise
        except (OSError, EOFError, paramiko.SSHException):
            raise PeerTransportRefusal("appliance_readback_failed") from None
        finally:
            if "channel" in locals():
                channel.close()


class PeerHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS origin connection routed over a peer channel with normal SNI."""

    def __init__(self, host: str, *, peer: PinnedPeerTransport, target_ip: str, **kwargs: object):
        """Initialize the validated client or test double.

        Args:
            host: Host used by this operation.
            peer: Pinned private-LAN peer transport.
            target_ip: Pinned destination address for the connection.
            **kwargs: Kwargs used by this operation."""
        super().__init__(host, **kwargs)
        self.peer = peer
        self.target_ip = target_ip

    def connect(self) -> None:
        if self._tunnel_host:
            raise PeerTransportRefusal("nested_http_tunnel_forbidden")
        raw = self.peer.open_socket(self.target_ip, self.port)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class PeerHTTPSHandler(urllib.request.HTTPSHandler):
    """Use peer transport for every urllib HTTPS request to one private IP."""

    def __init__(self, *, peer: PinnedPeerTransport, target_ip: str, context: ssl.SSLContext):
        """Initialize the validated client or test double.

        Args:
            peer: Pinned private-LAN peer transport.
            target_ip: Pinned destination address for the connection.
            context: Context used by this operation."""
        super().__init__(context=context)
        self.peer = peer
        self.target_ip = target_ip

    def https_open(self, request: urllib.request.Request):
        """Handle https open for certificate handoff verification.

        Args:
            request: HTTP request being processed."""
        def connection(host: str, **kwargs: object) -> PeerHTTPSConnection:
            """Handle connection for certificate handoff verification.

            Args:
                host: Host used by this operation.
                **kwargs: Kwargs used by this operation."""
            return PeerHTTPSConnection(host, peer=self.peer, target_ip=self.target_ip, **kwargs)

        return self.do_open(connection, request, context=self._context)
