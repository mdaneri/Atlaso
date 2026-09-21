"""Verify pinned SSH and real TLS identity checks without external networking."""

import ssl
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from unittest.mock import Mock

import paramiko
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts.interop.routing_overlap_transport import (
    FixtureTransportError,
    PinnedFixtureGateway,
    TLSChannel,
    pinned_client,
)


class MemoryPeer:
    """Exchange genuine TLS records through an in-memory SSH-channel substitute."""

    def __init__(self, context):
        """Initialize a TLS server endpoint.

        Args:
            context: Synthetic server certificate configuration.
        """
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.closed = False
        self.ready = False
        self.received = b""
        self.timeout = None

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
                self.tls.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        except ssl.SSLWantReadError:
            pass

    def recv(self, size):
        """Return encrypted server records.

        Args:
            size: Requested byte count.
        """
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


def test_ssh_reject_policy_and_exact_public_key():
    """Use exactly one provider-supplied key without ambient key discovery."""
    client = pinned_client("192.168.167.50", public_ssh_key())
    assert isinstance(client._policy, paramiko.RejectPolicy)
    assert list(client.get_host_keys()) == ["192.168.167.50"]
    assert not client._system_host_keys
    client.close()


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
