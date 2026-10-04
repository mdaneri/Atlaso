"""Verify pinned SSH and real TLS identity checks without external networking."""

import base64
import json
import shutil
import ssl
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from email.message import Message
from ipaddress import ip_address
from unittest.mock import Mock

import paramiko
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts.interop.routing_overlap_transport import (
    FixtureHttpClient,
    FixtureTransportError,
    PinnedFixtureGateway,
    PinnedRootSuReadOnlyClient,
    TLSChannel,
    pinned_client,
)


class MemoryPeer:
    """Exchange genuine TLS records through an in-memory SSH-channel substitute."""

    def __init__(self, context, *, delayed_body=None, fail_body=False):
        """Initialize a TLS server endpoint.

        Args:
            context: Synthetic server certificate configuration.
            delayed_body: Optional response sent in separate later TLS records.
            fail_body: Raise a channel error after delivering the headers.
        """
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.closed = False
        self.ready = False
        self.received = b""
        self.timeout = None
        self.delayed_body = delayed_body
        self.fail_body = fail_body
        self.headers_sent = False

    def settimeout(self, timeout):
        """Record bounded channel deadlines.

        Args:
            timeout: Remaining operation timeout.
        """
        self.timeout = timeout

    def sendall(self, data):
        """Process real client TLS bytes and return a fixed HTTP response.

        Args:
            data: Encrypted client records.
        """
        self.incoming.write(data)
        try:
            if not self.ready:
                self.tls.do_handshake()
                self.ready = True
            self.received += self.tls.read(65536)
            if b"\r\n\r\n" in self.received:
                if self.delayed_body is None:
                    self.tls.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                else:
                    self.tls.write((f"HTTP/1.1 200 OK\r\nContent-Length: {len(self.delayed_body)}\r\n"
                                    "Connection: close\r\n\r\n").encode())
                    self.headers_sent = True
        except ssl.SSLWantReadError:
            pass

    def recv(self, size):
        """Return encrypted server records.

        Args:
            size: Requested byte count.
        """
        if self.closed:
            raise OSError("channel closed before body read")
        if self.headers_sent and not self.outgoing.pending and self.delayed_body:
            if self.fail_body:
                raise OSError("synthetic body channel failure")
            chunk, self.delayed_body = self.delayed_body[:4096], self.delayed_body[4096:]
            self.tls.write(chunk)
        return self.outgoing.read(size)

    def close(self):
        """Record exact channel closure."""
        self.closed = True


@pytest.fixture
def tls_material(tmp_path):
    """Create synthetic public CA/leaf identities in the owned test directory.

    Args:
        tmp_path: Owned pytest directory, never a user credential location.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture root")])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().issuer_name(issuer).public_key(key.public_key())
               .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1)))
    root = (builder.subject_name(issuer).serial_number(1)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    leaf = (builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture leaf")])).serial_number(2)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address("192.0.2.10"))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "synthetic.crt", tmp_path / "synthetic.key"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    root_pem = root.public_bytes(serialization.Encoding.PEM).decode()
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cadata=root_pem)
    return server, client, root_pem


def test_tls_channel_verifies_identity_and_transfers_response(tls_material):
    """Exercise a real TLS handshake and HTTPResponse parser over SSH bytes.

    Args:
        tls_material: Synthetic TLS server/client identities.
    """
    import http.client

    server, context, _root = tls_material
    peer = MemoryPeer(server)
    channel = TLSChannel(peer, context, "192.0.2.10")
    channel.sendall(b"GET /openapi.json HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n")
    response = http.client.HTTPResponse(channel)
    response.begin()
    assert response.status == 200 and response.read() == b"OK"
    assert 0 < peer.timeout <= 30
    channel.close()
    assert peer.closed


@pytest.mark.parametrize("fault", ["hostname", "untrusted-ca", "disabled-verification"])
def test_tls_rejects_identity_bypass(tls_material, fault):
    """Reject stale SANs, untrusted roots, and insecure contexts.

    Args:
        tls_material: Synthetic TLS identities.
        fault: Invalid trust configuration.
    """
    server, context, _root = tls_material
    hostname = "192.0.2.11" if fault == "hostname" else "192.0.2.10"
    if fault == "untrusted-ca":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    elif fault == "disabled-verification":
        context.check_hostname = False
    peer = MemoryPeer(server)
    with pytest.raises((ssl.SSLError, FixtureTransportError)):
        TLSChannel(peer, context, hostname)
    if fault != "disabled-verification":
        assert peer.closed


def public_ssh_key():
    """Return a synthetic SSH public key with no private serialization."""
    key = paramiko.RSAKey.generate(2048)
    return f"{key.get_name()} {key.get_base64()}"


@pytest.mark.parametrize("fail_body", [False, True])
def test_gateway_retains_channel_until_delayed_response_body_finishes(tls_material, fail_body):
    """Keep a Connection: close stream alive through multi-record body parsing.

    Args:
        tls_material: Synthetic trusted TLS identities.
        fail_body: Inject a read error to prove channel cleanup on failure.
    """
    server, _context, root = tls_material
    body = b"bounded response " * 4096
    peer = MemoryPeer(server, delayed_body=body, fail_body=fail_body)
    key = public_ssh_key()
    gateway = PinnedFixtureGateway("192.168.167.50", "192.0.2.10", key, key, root)
    gateway.client = Mock()
    gateway.client.get_transport.return_value.open_channel.return_value = peer
    try:
        if fail_body:
            with pytest.raises(OSError, match="synthetic body"):
                gateway.request("GET", "/api/v1/tasks")
        else:
            status, content, headers = gateway.request("GET", "/api/v1/tasks")
            assert status == 200 and content == body and headers["Connection"] == "close"
        assert peer.closed and not gateway.channels
    finally:
        gateway.close()


def test_ssh_reject_policy_and_exact_public_key():
    """Use exactly one provider-supplied key without ambient key discovery."""
    client = pinned_client("192.168.167.50", public_ssh_key())
    assert isinstance(client._policy, paramiko.RejectPolicy)
    assert list(client.get_host_keys()) == ["192.168.167.50"]
    assert not client._system_host_keys
    client.close()


def test_gateway_refuses_missing_first_boot_ca_without_traceback():
    """An unready appliance cannot supply a private HTTPS trust anchor."""
    key = public_ssh_key()
    with pytest.raises(FixtureTransportError, match="explicit trust anchor"):
        PinnedFixtureGateway("192.168.167.50", "192.0.2.10", key, key, None)


def test_gateway_has_fixed_targets_and_cleans_channels(tls_material):
    """Never forward an arbitrary address/port or leave owned channels alive.

    Args:
        tls_material: Synthetic public CA.
    """
    _server, _context, root = tls_material
    key = public_ssh_key()
    gateway = PinnedFixtureGateway("192.168.167.50", "192.0.2.10", key, key, root)
    gateway.client = Mock()
    transport = gateway.client.get_transport.return_value
    transport.is_authenticated.return_value = True
    for port in (0, 80, 445, 3389, True):
        with pytest.raises(FixtureTransportError):
            gateway.channel(port)
    channel = gateway.channel(443)
    transport.open_channel.assert_called_once_with("direct-tcpip", ("192.0.2.10", 443), ("127.0.0.1", 0), timeout=10)
    gateway.close()
    channel.close.assert_called_once()
    gateway.client.close.assert_called_once()


@pytest.mark.parametrize("path,headers", [("//other/", {}), ("https://other/", {}), ("/ok", {"Host": "other"}),
                                          ("/ok\r\nInjected: true", {})])
def test_gateway_rejects_changed_http_origin(tls_material, path, headers):
    """Refuse alternate targets before opening any SSH channel.

    Args:
        tls_material: Synthetic public CA.
        path: Request target.
        headers: Caller headers.
    """
    key = public_ssh_key()
    gateway = PinnedFixtureGateway("192.168.167.50", "192.0.2.10", key, key, tls_material[2])
    gateway.client = Mock()
    with pytest.raises(FixtureTransportError):
        gateway.request("GET", path, headers=headers)
    gateway.client.get_transport.assert_not_called()
    gateway.close()


def test_http_client_retains_repeated_cookies_and_same_origin_auth():
    """Both session cookies survive a same-origin redirect without replaying POST."""
    first = Message()
    first.add_header("Set-Cookie", "session=one; Secure; Path=/; HttpOnly")
    first.add_header("Set-Cookie", "csrf=two; Secure; Path=/")
    first.add_header("Location", "/ui/management")
    gateway = Mock(target="192.0.2.10")
    gateway.request.side_effect = [(303, b"", first), (200, b'{"ok": true}', Message())]
    client = FixtureHttpClient(gateway)
    client.bearer_token = "synthetic-token"
    status, content, _headers = client.request("POST", "/login", form={"username": "admin"})
    assert status == 200 and content == '{"ok": true}'
    first_call, second_call = gateway.request.call_args_list
    assert first_call.args == ("POST", "/login")
    assert second_call.args == ("GET", "/ui/management")
    assert second_call.kwargs["body"] is None
    headers = second_call.kwargs["headers"]
    assert set(headers["Cookie"].split("; ")) == {"session=one", "csrf=two"}
    assert headers["Authorization"] == "Bearer synthetic-token"
    assert "Content-type" not in headers
    assert 0 < second_call.kwargs["timeout"] <= first_call.kwargs["timeout"] <= 30


@pytest.mark.parametrize("location", ["https://other/", "//other/", "http://192.0.2.10/",
                                      "https://user@192.0.2.10/", "https://192.0.2.11/"])
def test_http_client_refuses_cross_origin_redirect_before_forwarding(location):
    """Never forward a credential-bearing redirect outside the pinned target.

    Args:
        location: Untrusted redirect target from the private server.
    """
    headers = Message()
    headers["Location"] = location
    gateway = Mock(target="192.0.2.10")
    gateway.request.return_value = 307, b"", headers
    client = FixtureHttpClient(gateway)
    with pytest.raises(FixtureTransportError, match="pinned private origin"):
        client.request("POST", "/login", form={"password": "synthetic-value"})
    assert gateway.request.call_count == 1


def test_http_api_failure_does_not_echo_secret_payload_or_target():
    """Keep an API error's potentially sensitive body and query out of errors."""
    gateway = Mock(target="192.0.2.10")
    gateway.request.return_value = 401, b"synthetic-secret", Message()
    with pytest.raises(FixtureTransportError) as error:
        FixtureHttpClient(gateway).json_request("POST", "/login?password=synthetic-secret")
    assert str(error.value) == "fixture API request failed with HTTP 401"


class RootReadChannel:
    """Emulate the bounded SSH channel around the remote su bridge."""

    def __init__(self, initial, final, *, status=0, stays_open=False):
        """Retain synthetic readiness and response bytes.

        Args:
            initial: Chunks returned before root-password readiness.
            final: Chunks returned after the protected password input.
            status: Remote command exit status.
            stays_open: Keep the channel open to exercise its timeout.
        """
        self.chunks = list(initial)
        self.final = list(final)
        self.status = status
        self.stays_open = stays_open
        self.command = ""
        self.stdin = bytearray()
        self.read_output = bytearray()
        self.ready_marker = b""
        self.shutdown = False
        self.closed = False

    def settimeout(self, _timeout):
        """Accept the finite channel polling timeout.

        Args:
            _timeout: Bounded synthetic channel timeout.
        """

    def exec_command(self, command):
        """Retain the remote command for secret-exclusion assertions.

        Args:
            command: Fixed bridge command without credentials.
        """
        self.command = command
        nonce = command.rsplit(" ", 1)[-1]
        self.ready_marker = f"ATLASO_SU_READY:{nonce}\n".encode()
        self.chunks = [chunk.replace(b"ATLASO_SU_READY:<nonce>\n", self.ready_marker)
                       for chunk in self.chunks]

    def sendall(self, data):
        """Record protected stdin only after the bridge readiness marker.

        Args:
            data: Root credential bytes sent over the SSH channel.
        """
        assert self.ready_marker in self.read_output
        self.stdin.extend(data)
        self.chunks.extend(self.final)

    def shutdown_write(self):
        """Record end of the one-shot root credential input."""
        self.shutdown = True

    def recv_ready(self):
        """Report queued synthetic SSH stdout."""
        return bool(self.chunks)

    def recv(self, _size):
        """Return one queued stdout chunk.

        Args:
            _size: Maximum chunk requested by the bounded reader.
        """
        chunk = self.chunks.pop(0)
        self.read_output.extend(chunk)
        return chunk

    def recv_stderr_ready(self):
        """Report no remote diagnostic stream in these fixtures."""
        return False

    def recv_stderr(self, _size):
        """Return no diagnostic bytes.

        Args:
            _size: Maximum requested diagnostic chunk.
        """
        return b""

    def exit_status_ready(self):
        """Report completion after all queued bytes have been consumed."""
        return not self.stays_open and not self.chunks

    def recv_exit_status(self):
        """Return the configured synthetic exit status."""
        return self.status

    def close(self):
        """Record channel cleanup."""
        self.closed = True


class RootReadTransport:
    """Provide one authenticated synthetic SSH session."""

    def __init__(self, channel):
        """Retain the channel and its open-session timeout.

        Args:
            channel: Synthetic protected su exchange.
        """
        self.channel = channel
        self.timeout = None

    def is_authenticated(self):
        """Report the fixture's pinned admin session as authenticated."""
        return True

    def open_session(self, *, timeout):
        """Return the exchange channel under its configured deadline.

        Args:
            timeout: Maximum channel-open duration.
        """
        self.timeout = timeout
        return self.channel


def _root_observer(initial, final, *, status=0, stays_open=False):
    """Create a synthetic root observer and its inspectable SSH channel.

    Args:
        initial: Output available before password exchange.
        final: Output available after password exchange.
        status: Remote command status.
        stays_open: Whether the remote channel remains open indefinitely.
    """
    channel = RootReadChannel(initial, final, status=status, stays_open=stays_open)
    transport = RootReadTransport(channel)
    client = Mock()
    client.get_transport.return_value = transport
    return PinnedRootSuReadOnlyClient(client, "synthetic-root-secret"), channel


def test_root_su_bridge_sends_distinct_secret_only_after_echo_safe_prompt():
    """Require the remote bridge to disable and verify echo before readiness."""
    source = __import__("scripts.interop.routing_overlap_transport", fromlist=["_ROOT_SU_BRIDGE"])._ROOT_SU_BRIDGE

    assert source.index("settings[3] &= ~(termios.ECHO | termios.ECHONL)") < source.index("os.execve(su")
    first_echo_check = source.index("if current & (termios.ECHO | termios.ECHONL):")
    ready = source.index('print("ATLASO_SU_READY:"')
    secret_read = source.index("chunk = os.read(sys.stdin.fileno()")
    second_echo_check = source.index("current = termios.tcgetattr(terminal)[3]", secret_read)
    secret_write = source.index("os.write(terminal, raw)")
    assert first_echo_check < ready < secret_read < second_echo_check < secret_write
    assert source.index("if uid != 0: raise SystemExit(125)") < source.index("exec(compile(base64.b64decode")


def test_root_observer_releases_secret_only_after_remote_readiness():
    """Keep the root secret off command arguments and wait for safe PTY readiness."""
    result = b'{"schema":1,"ok":true,"euid":0,"result":{"links":[]}}\n'
    observer, channel = _root_observer([b"ATLASO_SU_READY:<nonce>\n"], [result])
    try:
        encoded = base64.b64encode(b"print('{}')").decode("ascii")
        command = f'python3 -c \'import base64;exec(base64.b64decode("{encoded}"))\''
        _stdin, stdout, stderr = observer.exec_command(command)
        assert json.loads(stdout.read()) == {"links": []}
        assert stderr.read() == b""
        assert stdout.channel.recv_exit_status() == 0
        assert channel.stdin == b"synthetic-root-secret\n"
        assert channel.shutdown and channel.closed
        assert "synthetic-root-secret" not in channel.command
    finally:
        observer.close()


def test_root_observer_uses_fresh_prompt_nonce_for_each_exchange():
    """Bind each secret release to the current exchange's unpredictable marker."""
    result = b'{"schema":1,"ok":true,"euid":0,"result":{"ok":true}}\n'
    first, first_channel = _root_observer([b"ATLASO_SU_READY:<nonce>\n"], [result])
    second, second_channel = _root_observer([b"ATLASO_SU_READY:<nonce>\n"], [result])
    try:
        first.read_program("print('{}')")
        second.read_program("print('{}')")
        first_nonce = first_channel.command.rsplit(" ", 1)[-1]
        second_nonce = second_channel.command.rsplit(" ", 1)[-1]
        assert len(first_nonce) == len(second_nonce) == 32
        assert first_nonce != second_nonce
    finally:
        first.close()
        second.close()


def test_root_bridge_survives_powershell_login_shell(monkeypatch):
    """Execute the SSH bootstrap through the appliance's PowerShell shell.

    Args:
        monkeypatch: Substitute a harmless bridge before invoking the real shell.
    """
    shell = shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell is unavailable on this test host")
    marker = "single ' and double \" quotes; $value `backtick`"
    bridge = f"import json,sys;print(json.dumps({{'marker':{marker!r},'args':sys.argv[1:]}}))"
    monkeypatch.setattr("scripts.interop.routing_overlap_transport._ROOT_SU_BRIDGE", bridge)
    response = b'{"schema":1,"ok":true,"euid":0,"result":{}}\n'
    observer, channel = _root_observer([b"ATLASO_SU_READY:<nonce>\n"], [response])
    try:
        observer.read_program("print('{}')", timeout=5)
        command = channel.command.replace("python3 ", f'& "{sys.executable}" ', 1)
        completed = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command],
                                   capture_output=True, text=True, timeout=15, check=True)
        result = json.loads(completed.stdout)
        assert result["marker"] == marker
        assert base64.b64decode(result["args"][0]).decode() == "print('{}')"
        assert result["args"][1:] == ["5", channel.command.rsplit(" ", 1)[-1]]
    finally:
        observer.close()


def test_root_observer_does_not_send_secret_when_echo_race_prevents_readiness():
    """Do not send root credentials when the broker refuses its echo check."""
    failure = b'{"schema":1,"ok":false,"error":"echo"}\n'
    observer, channel = _root_observer([b"Password:", failure], [], status=1)
    try:
        with pytest.raises(FixtureTransportError):
            observer.read_program("print('{}')")
        assert channel.stdin == b""
        assert "synthetic-root-secret" not in channel.command
    finally:
        observer.close()


def test_root_observer_rejects_euid_mismatch_and_unbounded_output():
    """Reject a non-root result and a response exceeding the fixed output budget."""
    wrong_euid = b'{"schema":1,"ok":true,"euid":1000,"result":{}}\n'
    observer, channel = _root_observer([b"ATLASO_SU_READY:<nonce>\n"], [wrong_euid])
    with pytest.raises(FixtureTransportError, match="root identity"):
        observer.read_program("print('{}')")
    observer.close()
    assert channel.closed

    observer, channel = _root_observer([b"x" * (524288 + 1)], [])
    with pytest.raises(FixtureTransportError, match="output bound"):
        observer.read_program("print('{}')")
    observer.close()
    assert channel.closed


def test_root_observer_enforces_whole_exchange_deadline(monkeypatch):
    """Stop an authenticated read whose su readiness handshake never completes.

    Args:
        monkeypatch: Replace the monotonic clock with a bounded synthetic clock.
    """
    observer, channel = _root_observer([], [], stays_open=True)
    ticks = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr("scripts.interop.routing_overlap_transport.time.monotonic", lambda: next(ticks))
    with pytest.raises(FixtureTransportError, match="time bound"):
        observer.read_program("print('{}')", timeout=1)
    observer.close()
    assert channel.closed
