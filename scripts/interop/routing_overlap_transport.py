"""Pinned in-process SSH channels for a private lifecycle appliance.

No host listener, credential file, agent, or ambient known-hosts file is used.
HTTPS retains its private target authority and validates an explicit public CA.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import http.cookiejar
import io
import ipaddress
import json
import re
import ssl
import time
import urllib.parse
import urllib.request
from email.message import Message
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
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("fixture HTTPS deadline exceeded") from None
                self.channel.settimeout(remaining)
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
        if gateway == target or not isinstance(ca_pem, str) or not ca_pem.strip():
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
                headers: dict[str, str] | None = None, timeout: float = 30) -> tuple[int, bytes, Message]:
        """Perform one CA-validated private-origin HTTPS request with no redirects.

        Args:
            method: HTTP request method.
            path: Origin-relative path; alternate origins are refused.
            body: Optional request body.
            headers: Request headers; Host and Connection overrides are refused.
            timeout: Maximum TLS operation duration in seconds.
        """
        if (not path.startswith("/") or path.startswith("//") or "://" in path
                or any(character in path for character in "\r\n")
                or not re.fullmatch(r"[A-Z]+", method)
                or any(key.lower() in {"host", "connection"} for key in (headers or {}))):
            raise FixtureTransportError("fixture request must retain the private HTTPS origin")
        connection = http.client.HTTPSConnection(self.target, context=self.context, timeout=30)
        channel = self.channel(443)
        try:
            connection.sock = TLSChannel(channel, self.context, self.target, timeout=timeout)
            connection.request(method, path, body=body, headers={**(headers or {}), "Connection": "close"})
            # HTTPConnection.getresponse closes its socket immediately for a
            # Connection: close response. Own the parser lifetime explicitly:
            # this SSH-backed stream has no socket.makefile reference counting.
            with http.client.HTTPResponse(connection.sock, method=method) as response:
                response.begin()
                content = response.read(8 * 1024 * 1024 + 1)
                if len(content) > 8 * 1024 * 1024:
                    raise FixtureTransportError("fixture HTTPS response exceeds evidence limit")
                return response.status, content, response.headers
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


class FixtureHttpClient:
    """Keep lifecycle cookies and tokens inside the pinned private HTTPS origin."""

    def __init__(self, gateway: PinnedFixtureGateway) -> None:
        """Bind one previously admitted transport without ambient HTTP handlers.

        Args:
            gateway: Authenticated private fixture transport.
        """
        self.gateway = gateway
        self.base_url = f"https://{gateway.target}"
        self.bearer_token = ""
        self.cookie_jar = http.cookiejar.CookieJar()

    def request_bytes(
        self, method: str, path: str, *, json_body: dict[str, Any] | None = None,
        form: dict[str, Any] | list[tuple[str, Any]] | None = None, body: bytes | None = None,
        headers: dict[str, str] | None = None, follow_redirects: bool = True, timeout: int = 30,
    ) -> tuple[int, bytes, dict[str, str]]:
        """Perform bounded authenticated requests with only same-origin redirects.

        Args:
            method: HTTP method passed to the pinned transport.
            path: Origin-relative request path.
            json_body: Optional JSON object.
            form: Optional form fields.
            body: Optional raw body.
            headers: Additional request headers.
            follow_redirects: Whether same-origin redirects may be followed.
            timeout: Whole redirect-chain deadline, at most 120 seconds.
        """
        if not 0 < timeout <= 120:
            raise FixtureTransportError("invalid fixture HTTP deadline")
        if not path.startswith("/") or path.startswith("//") or "://" in path:
            raise FixtureTransportError("fixture request must be origin-relative")
        request_headers = dict(headers or {})
        if self.bearer_token:
            request_headers.setdefault("Authorization", f"Bearer {self.bearer_token}")
        if json_body is not None:
            body = json.dumps(json_body).encode()
            request_headers["Content-Type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form, doseq=True).encode()
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        deadline = time.monotonic() + timeout
        for _attempt in range(6):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("fixture HTTP deadline exceeded")
            request = urllib.request.Request(self.base_url + path, data=body, headers=request_headers, method=method)
            self.cookie_jar.add_cookie_header(request)
            status, content, response_headers = self.gateway.request(
                method, path, body=body, headers=dict(request.header_items()), timeout=remaining,
            )
            self.cookie_jar.extract_cookies(_CookieResponse(response_headers), request)
            location = response_headers.get("Location", "")
            if follow_redirects and status in {301, 302, 303, 307, 308} and location:
                redirect = urllib.parse.urlsplit(urllib.parse.urljoin(self.base_url + path, location))
                if (redirect.scheme != "https" or redirect.netloc != self.gateway.target
                        or redirect.username is not None or redirect.password is not None):
                    raise FixtureTransportError("fixture redirect changes the pinned private origin")
                path = urllib.parse.urlunsplit(("", "", redirect.path or "/", redirect.query, ""))
                if status in {301, 302, 303} and method not in {"GET", "HEAD"}:
                    method, body = "GET", None
                    request_headers = {key: value for key, value in request_headers.items()
                                       if key.lower() not in {"content-type", "content-length"}}
                continue
            return status, content, dict(response_headers.items())
        raise FixtureTransportError("fixture HTTP redirect limit exceeded")

    def request(self, method: str, path: str, **kwargs: Any) -> tuple[int, str, dict[str, str]]:
        """Decode bounded lifecycle text responses.

        Args:
            method: HTTP method.
            path: Origin-relative target.
            **kwargs: Supported request_bytes options.
        """
        status, content, headers = self.request_bytes(method, path, **kwargs)
        return status, content.decode("utf-8", errors="replace"), headers

    def json_request(self, method: str, path: str, *, json_body: dict[str, Any] | None = None) -> Any:
        """Decode successful API JSON without echoing secret-bearing errors.

        Args:
            method: HTTP method.
            path: Origin-relative API target.
            json_body: Optional request object.
        """
        status, content, _headers = self.request_bytes(method, path, json_body=json_body)
        if status >= 400:
            raise FixtureTransportError(f"fixture API request failed with HTTP {status}")
        try:
            return json.loads(content)
        except ValueError:
            raise FixtureTransportError("fixture API returned invalid JSON") from None


class _CookieResponse:
    """Expose repeated Set-Cookie headers to the standard cookie policy."""

    def __init__(self, headers: Message) -> None:
        """Keep the original multi-value response headers.

        Args:
            headers: Headers from the actual verified HTTPS response.
        """
        self.headers = headers

    def info(self) -> Message:
        """Return all response headers without collapsing repeated cookies."""
        return self.headers
