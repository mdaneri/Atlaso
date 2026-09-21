"""Pinned in-process SSH channels for a private lifecycle appliance.

No host listener, credential file, agent, or ambient known-hosts file is used.
HTTPS retains its private target authority and validates an explicit public CA.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import io
import ipaddress
import re
import ssl
import time
from typing import Any

import paramiko


class FixtureTransportError(RuntimeError):
    """Report a bounded non-secret fixture transport failure."""


class _TLSReader(io.RawIOBase):
    """Expose TLS plaintext to the standard HTTP response parser."""

    def __init__(self, channel: TLSChannel) -> None:
        """Retain one active TLS channel.

        Args:
            channel: Authenticated TLS stream.
        """
        self.channel = channel

    def readable(self) -> bool:
        """Declare the stream readable."""
        return True

    def readinto(self, buffer: Any) -> int:
        """Fill the HTTP parser buffer from authenticated TLS plaintext.

        Args:
            buffer: Mutable destination supplied by BufferedReader.
        """
        data = self.channel.recv(len(buffer))
        buffer[:len(data)] = data
        return len(data)


class TLSChannel:
    """TLS over a bounded SSH channel without a socket-listener bridge."""

    def __init__(self, channel: Any, context: ssl.SSLContext, hostname: str, *, timeout: float = 30) -> None:
        """Authenticate a target over an already admitted SSH forwarding channel.

        Args:
            channel: Restricted direct-tcpip Paramiko channel.
            context: Explicit trusted-CA context requiring hostname verification.
            hostname: Original private appliance address, never a loopback substitute.
            timeout: Whole-operation deadline in seconds.
        """
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise FixtureTransportError("fixture HTTPS requires certificate and hostname verification")
        if not 0 < timeout <= 120:
            raise FixtureTransportError("invalid fixture transport deadline")
        self.channel = channel
        self.deadline = time.monotonic() + timeout
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=False, server_hostname=hostname)
        try:
            self._operation(self.tls.do_handshake)
        except (OSError, ValueError):
            channel.close()
            raise

    def _flush(self) -> None:
        """Drain encrypted bytes within the original operation deadline."""
        while self.outgoing.pending:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("fixture HTTPS deadline exceeded")
            self.channel.settimeout(remaining)
            self.channel.sendall(self.outgoing.read())

    def _operation(self, operation: Any) -> Any:
        """Drive bounded TLS record exchange for one stream operation.

        Args:
            operation: SSLObject handshake/read/write method.
        """
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("fixture HTTPS deadline exceeded")
            self.channel.settimeout(remaining)
            try:
                result = operation()
                self._flush()
                return result
            except ssl.SSLWantWriteError:
                self._flush()
            except ssl.SSLWantReadError:
                self._flush()
                incoming = self.channel.recv(65536)
                if not incoming:
                    raise ssl.SSLEOFError("fixture TLS peer closed without a complete record") from None
                self.incoming.write(incoming)

    def sendall(self, data: bytes) -> None:
        """Encrypt all supplied HTTP request bytes.

        Args:
            data: HTTP request bytes.
        """
        remaining = memoryview(data)
        while remaining:
            written = self._operation(lambda chunk=remaining: self.tls.write(chunk))
            remaining = remaining[written:]

    def recv(self, size: int) -> bytes:
        """Return decrypted response bytes.

        Args:
            size: Maximum requested byte count.
        """
        try:
            return self._operation(lambda: self.tls.read(size))
        except ssl.SSLZeroReturnError:
            return b""

    def makefile(self, mode: str, buffering: int | None = None) -> io.BufferedReader:
        """Provide the read-only adapter used by HTTPResponse.

        Args:
            mode: Requested file mode; only binary reads are admitted.
            buffering: Optional buffer size.
        """
        if mode != "rb":
            raise FixtureTransportError("fixture TLS supports binary response reads only")
        return io.BufferedReader(_TLSReader(self), buffer_size=buffering or io.DEFAULT_BUFFER_SIZE)

    def close(self) -> None:
        """Close the underlying SSH channel without an unbounded TLS shutdown."""
        self.channel.close()


def pinned_client(host: str, public_key: str) -> paramiko.SSHClient:
    """Create a client that accepts only a provider-observed public host key.

    Args:
        host: Exact literal IP targeted by the SSH connection.
        public_key: Public key read using the owned guest-operations boundary.

    Returns:
        Unconnected client with a single in-memory host key and reject policy.
    """
    ipaddress.ip_address(host)
    fields = public_key.split()
    if len(fields) < 2 or len(public_key) > 16384:
        raise FixtureTransportError("provider SSH public key is missing or invalid")
    try:
        key = paramiko.PKey.from_type_string(fields[0], base64.b64decode(fields[1], validate=True))
    except (ValueError, binascii.Error, paramiko.SSHException) as exc:
        raise FixtureTransportError("provider SSH public key is invalid") from exc
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.get_host_keys().add(host, key.get_name(), key)
    return client


class PinnedFixtureGateway:
    """Own bounded channels through a pinned client VM to one private appliance."""

    def __init__(self, gateway: str, target: str, gateway_key: str, target_key: str, ca_pem: str) -> None:
        """Record public connection identities without authenticating yet.

        Args:
            gateway: Admitted control-client address.
            target: Admitted fixed DHCP reservation address on its private NIC.
            gateway_key: Provider-observed client SSH public key.
            target_key: Provider-observed appliance SSH public key.
            ca_pem: Provider-observed appliance public CA certificate.
        """
        for value in (gateway, target):
            address = ipaddress.ip_address(value)
            if address.is_loopback or address.is_multicast or address.is_unspecified:
                raise FixtureTransportError("fixture peers require admitted unicast addresses")
        if gateway == target or not ca_pem.strip():
            raise FixtureTransportError("fixture target and explicit trust anchor are required")
        self.gateway = gateway
        self.target = target
        self.client = pinned_client(gateway, gateway_key)
        self.appliance = pinned_client(target, target_key)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(cadata=ca_pem)
        self.channels: list[Any] = []

    def connect(self, username: str, password: str) -> None:
        """Authenticate without files, subprocess arguments, or ambient agents.

        Args:
            username: Control guest username from the canonical runner.
            password: Existing lifecycle secret supplied through bounded stdin.
        """
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", username):
            raise FixtureTransportError("invalid fixture SSH username")
        try:
            self.client.connect(self.gateway, username=username, password=password, look_for_keys=False,
                                allow_agent=False, timeout=10, auth_timeout=10, banner_timeout=10)
        except (OSError, paramiko.SSHException) as exc:
            self.close()
            raise FixtureTransportError("pinned fixture gateway authentication failed") from exc

    def channel(self, port: int) -> Any:
        """Open only an admitted appliance SSH or HTTPS forwarding channel.

        Args:
            port: Appliance port 22 or 443; callers cannot select another target.
        """
        if type(port) is not int or port not in {22, 443}:
            raise FixtureTransportError("fixture forwarding port is not admitted")
        transport = self.client.get_transport()
        if transport is None or not transport.is_authenticated():
            raise FixtureTransportError("fixture gateway is not authenticated")
        channel = transport.open_channel("direct-tcpip", (self.target, port), ("127.0.0.1", 0), timeout=10)
        self.channels.append(channel)
        return channel

    def request(self, method: str, path: str, *, body: bytes | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
        """Perform one CA-validated private-origin HTTPS request with no redirects.

        Args:
            method: HTTP request method.
            path: Origin-relative path; alternate origins are refused.
            body: Optional request body.
            headers: Request headers; Host and Connection overrides are refused.
        """
        if (not path.startswith("/") or path.startswith("//") or "://" in path
                or any(character in path for character in "\r\n")
                or not re.fullmatch(r"[A-Z]+", method)
                or any(key.lower() in {"host", "connection"} for key in (headers or {}))):
            raise FixtureTransportError("fixture request must retain the private HTTPS origin")
        connection = http.client.HTTPSConnection(self.target, context=self.context, timeout=30)
        channel = self.channel(443)
        try:
            connection.sock = TLSChannel(channel, self.context, self.target)
            connection.request(method, path, body=body, headers={**(headers or {}), "Connection": "close"})
            response = connection.getresponse()
            content = response.read(8 * 1024 * 1024 + 1)
            if len(content) > 8 * 1024 * 1024:
                raise FixtureTransportError("fixture HTTPS response exceeds evidence limit")
            return response.status, content, dict(response.getheaders())
        finally:
            connection.close()
            channel.close()
            self.channels.remove(channel)

    def connect_appliance(self, username: str, password: str) -> paramiko.SSHClient:
        """Authenticate appliance SSH using its separately pinned host key.

        Args:
            username: Existing appliance SSH identity.
            password: Existing appliance secret supplied through bounded stdin.
        """
        channel = self.channel(22)
        try:
            self.appliance.connect(self.target, username=username, password=password, sock=channel,
                                   look_for_keys=False, allow_agent=False, timeout=10, auth_timeout=10, banner_timeout=10)
        except (OSError, paramiko.SSHException) as exc:
            channel.close()
            self.channels.remove(channel)
            raise FixtureTransportError("pinned appliance authentication failed") from exc
        return self.appliance

    def close(self) -> None:
        """Close all owned channels and authenticated transports."""
        self.appliance.close()
        for channel in self.channels:
            channel.close()
        self.channels.clear()
        self.client.close()
