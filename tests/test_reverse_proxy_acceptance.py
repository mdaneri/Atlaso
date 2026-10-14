"""Verify native proxy fixture behavior and focused lifecycle admission."""

import http.client
import importlib.util
import io
import json
import os
import shutil
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def load_module(name, filename):
    """Load an admitted lifecycle source without writing bytecode.

    Args:
        name: Unique module registry name.
        filename: Checked-in interop filename.
    """
    path = Path(__file__).parents[1] / "scripts" / "interop" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_focused_mode_secrets_and_plan():
    """Admit the focused password envelope without unrelated VCF credentials."""
    lifecycle = load_module("proxy_lifecycle_test", "lifecycle_test.py")
    args = lifecycle.parse_args(["--reverse-proxy-only", "--reverse-proxy-upstream-host", "192.0.2.2"])
    lifecycle.load_lifecycle_secrets(args, io.StringIO(json.dumps({"password": "fixture", "appliance_ssh_password": "fixture", "ssh_password": "fixture"})))
    plan = lifecycle.lifecycle_plan(args)
    assert plan["reverse_proxy_only"]
    assert not plan["client_checks_enabled"]
    assert "dnsmasq" in plan["apply_units"]
    with pytest.raises(SystemExit):
        lifecycle.parse_args(["--reverse-proxy-only", "--time-source-only"])


def test_fixture_challenge_and_bounded_echo():
    """Serve the real fixture socket and preserve the application's challenge."""
    module = load_module("proxy_acceptance_test", "reverse_proxy_acceptance.py")
    server = module.FixtureServer(("127.0.0.1", 0), module.FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        module.websocket_exchange("127.0.0.1", server.server_address[1], "fixture.example.test")
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("GET", "/value?q=1", headers={"X-Forwarded-Proto": "https"})
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["path"] == "/value?q=1"
        connection.close()
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("GET", "/auth")
        response = connection.getresponse()
        assert response.status == 401
        assert response.getheader("WWW-Authenticate")
        assert response.read() == b""
        connection.close()
        server.unavailable.set()
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("HEAD", "/")
        with pytest.raises(http.client.RemoteDisconnected):
            connection.getresponse()
        connection.close()
        server.unavailable.clear()
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("HEAD", "/")
        assert connection.getresponse().status == 200
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_tls_fixture_keeps_one_leaf_and_verifies_before_forwarding(tmp_path):
    """Use real TLS connections for the same immutable positive and negative leaf."""
    import hashlib
    import socket
    import ssl
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from atlaso.app.services.reverse_proxy_transport import verify_peer

    fixture = os.environ.get("ATLASO_TEST_TLS_FIXTURE_DIRECTORY")
    directory = Path(fixture) if fixture else tmp_path
    if not fixture:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral proxy test")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
                .not_valid_after(now+timedelta(hours=1)).sign(key, hashes.SHA256()))
        with (directory / "private-key.pem").open("xb") as output:
            output.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
        with (directory / "certificate.pem").open("xb") as output:
            output.write(cert.public_bytes(serialization.Encoding.PEM))
    module = load_module("proxy_owned_tls_fixture_test", "reverse_proxy_acceptance.py")
    context, fingerprint = module.fixture_tls_context(directory)
    server = module.FixtureServer(("127.0.0.1", 0), module.FixtureHandler, tls_context=context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    try:
        for pin in (fingerprint, fingerprint, "0" * 64):
            with socket.create_connection(server.server_address, timeout=5) as raw:
                with client_context.wrap_socket(raw, server_hostname="fixture.test") as peer:
                    assert hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() == fingerprint
                    writer = Mock()
                    writer.get_extra_info.return_value = peer
                    if pin == "0" * 64:
                        with pytest.raises(ssl.SSLCertVerificationError, match="pin mismatch"):
                            verify_peer({"trust_mode": "fingerprint", "fingerprint": pin}, writer)
                        writer.write.assert_not_called()
                    else:
                        verify_peer({"trust_mode": "fingerprint", "fingerprint": pin}, writer)
                        peer.sendall(b"GET /stable HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n")
                        response = http.client.HTTPResponse(peer)
                        response.begin()
                        assert response.status == 200
                        assert json.loads(response.read())["path"] == "/stable"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=15)
        assert not thread.is_alive()


def test_tls_fixture_matches_public_host_to_each_origin_without_dns_or_redirects():
    """Exercise trust modes with origin-compatible Hosts while retaining exact pins."""
    module = load_module("proxy_trust_virtual_hosts_test", "reverse_proxy_acceptance.py")
    fingerprint = "a" * 64
    payloads = module.trust_proxy_payloads("192.0.2.44", "eth1", fingerprint, "198.51.100.44", "192.0.2.1", 54321)
    assert [(row["hostname"], row["port"]) for row in payloads] == [
        ("example.com", 8445), ("self-signed.proxy.atlaso.internal", 8446), ("badssl.com", 8447),
        ("pinned.proxy.atlaso.internal", 8448),
    ]
    routes = {route["path_prefix"]: route for row in payloads for route in row["routes"]}
    assert routes["/trusted/"]["trust_mode"] == "trusted_ca"
    assert routes["/pinned/"]["fingerprint"] == fingerprint
    assert routes["/wrong-pin/"]["fingerprint"] == "0" * 64
    assert routes["/self-signed/"]["trust_mode"] == "trusted_ca"
    assert routes["/insecure/"]["insecure_acknowledged"] is True
    assert routes["/insecure/"]["upstream_host"] == "198.51.100.44"
    assert routes["/self-signed/"]["upstream_host"] == "self-signed.badssl.com"
    for row in payloads:
        assert row["listeners"] == [{"interface": "eth1", "address": "192.0.2.44"}]
        assert not row["redirect_http"] and not row["managed_dns"] and not row["public_listing"]
        assert all(route["upstream_host"] != row["hostname"]
                   and route["upstream_port"] == (54321 if route["trust_mode"] == "fingerprint" else 443)
                   and route["upstream_scheme"] == "https" for route in row["routes"])
    assert routes["/pinned/"]["upstream_host"] == routes["/wrong-pin/"]["upstream_host"] == "192.0.2.1"


def test_dns_payload_only_changes_authoritative_ipv4_listener():
    """Preserve DNS settings while never posting DHCP or IPv6 defaults."""
    module = load_module("proxy_dns_acceptance_test", "reverse_proxy_acceptance.py")
    current = {
        "enabled": False, "listen_interface": "eth0", "listen_address": "192.0.2.10",
        "domain": "old.example.test", "upstream_servers": ["192.0.2.53"],
        "conditional_forwarders": [], "cache_size": 1234, "expand_hosts": True,
        "authoritative": False, "authoritative_server": "ns.old.example.test",
        "authoritative_contact": "hostmaster.old.example.test", "authoritative_ttl": 1800,
        "authoritative_refresh": 1200, "authoritative_retry": 180, "authoritative_expire": 1209600,
        "dnssec_enabled": False, "rebind_protection_enabled": True,
        "rebind_domain_exemptions": "internal.example.test", "query_logging_mode": "off",
        "authoritative_serial": 17, "config_path": "/ignored", "updated_at": "ignored",
    }
    payload = module.dns_settings_payload(current, domain="site.example.test", interface="eth1", address="192.0.2.44")
    assert payload["listen_address"] == "192.0.2.44"
    assert payload["listen_interface"] == "eth1"
    assert payload["authoritative"] is True
    assert payload["authoritative_server"] == "ns1.site.example.test"
    assert payload["upstream_servers"] == ["192.0.2.53"]
    assert "authoritative_serial" not in payload and "config_path" not in payload
    assert not {"range_start", "range_end", "domain_name", "dns_server", "enabled_scope"}.intersection(payload)


def test_dns_configuration_calls_only_dns_settings_endpoint():
    """Save the managed zone and address without touching DHCP state."""
    module = load_module("proxy_dns_configure_test", "reverse_proxy_acceptance.py")
    class Client:
        def __init__(self):
            self.calls = []

        def json_request(self, method, path, *, json_body=None):
            """Simulate json request for the focused fixture.

            Args:
                method: HTTP method expected by the simulated operation.
                path: Exact fixture filesystem or HTTP path.
                json_body: Desired-state payload submitted to the simulated API.
            """
            self.calls.append((method, path, json_body))
            assert method == "PATCH", "Fresh disabled DNS must not require a GET response."
            return json_body

    client = Client()
    args = SimpleNamespace(domain="site.example.test", site_interface="eth1")
    result = module.configure_proxy_dns(client, args, "192.0.2.44")
    assert [call[:2] for call in client.calls] == [
        ("PATCH", "/api/v1/dns/settings"),
    ]
    assert client.calls[0][2]["listen_address"] == "192.0.2.44"
    assert result == {"authoritative": True, "listener_address": "192.0.2.44", "domain": "site.example.test"}


def test_proxy_dns_owner_record_requires_exact_identity_and_address():
    """Recognize only the proxy ID's exact managed A record."""
    module = load_module("proxy_dns_owner_test", "reverse_proxy_acceptance.py")
    proxy = {"id": 9, "hostname": "dns-hidden.example.test"}

    class Client:
        def json_request(self, method, path):
            """Simulate json request for the focused fixture.

            Args:
                method: HTTP method expected by the simulated operation.
                path: Exact fixture filesystem or HTTP path.
            """
            assert method == "GET" and path == "/api/v1/dns/records"
            return [{
                "hostname": proxy["hostname"], "record_type": "A", "address": "192.0.2.44",
                "description": f"{module.DNS_OWNER_PREFIX}9", "enabled": True,
            }]

    module.assert_proxy_dns_record(Client(), proxy, "192.0.2.44", expected=True)
    with pytest.raises(RuntimeError, match="exact enabled owner record"):
        module.assert_proxy_dns_record(Client(), proxy, "192.0.2.45", expected=True)
    with pytest.raises(RuntimeError, match="managed DNS disabled"):
        module.assert_proxy_dns_record(Client(), proxy, "192.0.2.44", expected=False)


def test_wire_dns_query_is_bounded_and_read_only(monkeypatch):
    """Use the shared authoritative wire parser without a guest shell or dig.

    Args:
        monkeypatch: Fixture replacing the wire transport with deterministic answers.
    """
    module = load_module("proxy_dns_wire_test", "reverse_proxy_acceptance.py")
    reader = module.dns_readback_module()
    owner = "dns-hidden.example.test."
    query = Mock(return_value=({(owner, 1): {"192.0.2.44"}}, 0))
    monkeypatch.setattr(reader, "_query", query)
    monkeypatch.setattr(module, "dns_readback_module", lambda: reader)
    args = SimpleNamespace(appliance_ssh_host="192.0.2.10")
    module.verify_proxy_dns_wire(None, args, owner, "192.0.2.44", expected=True)
    query.assert_called_once_with(
        "192.0.2.44", 53, 2.0, owner, "A", allow_nxdomain=False, require_authoritative=True,
    )
    with pytest.raises(RuntimeError, match="bounded authoritative DNS query"):
        module.verify_proxy_dns_wire(None, args, owner, "192.0.2.44", expected=False)
    query.return_value = ({}, 3)
    module.verify_proxy_dns_wire(None, args, owner, "192.0.2.44", expected=False)
    assert query.call_args.kwargs == {"allow_nxdomain": True, "require_authoritative": True}
    query.return_value = ({(owner, 5): {"other.example.test."}}, 0)
    with pytest.raises(RuntimeError, match="bounded authoritative DNS query"):
        module.verify_proxy_dns_wire(None, args, owner, "192.0.2.44", expected=False)


@pytest.mark.parametrize("answers", [
    {},
    {("other.example.test.", 1): {"192.0.2.44"}},
    {("dns-hidden.example.test.", 1): {"192.0.2.45"}},
    {("dns-hidden.example.test.", 1): {"192.0.2.44", "192.0.2.45"}},
])
def test_wire_dns_rejects_missing_wrong_or_extra_owned_addresses(monkeypatch, answers):
    """Require the exact queried owner and complete saved address set.

    Args:
        monkeypatch: Fixture replacing the DNS transport.
        answers: Parsed records that do not match the saved proxy intent.
    """
    module = load_module("proxy_dns_exact_answers_test", "reverse_proxy_acceptance.py")
    reader = module.dns_readback_module()
    monkeypatch.setattr(reader, "_query", Mock(return_value=(answers, 0)))
    monkeypatch.setattr(module, "dns_readback_module", lambda: reader)
    with pytest.raises(RuntimeError, match="bounded authoritative DNS query"):
        module.verify_proxy_dns_wire(None, None, "dns-hidden.example.test", "192.0.2.44", expected=True)


def test_public_directory_visibility_checks_site_public_path():
    """Require the opted-in service and omit its DNS-only counterpart."""
    module = load_module("proxy_public_directory_test", "reverse_proxy_acceptance.py")

    class PublicClient:
        def __init__(self):
            self.path = None

        def request(self, method, path):
            """Simulate request for the focused fixture.

            Args:
                method: HTTP method expected by the simulated operation.
                path: Exact fixture filesystem or HTTP path.
            """
            self.path = path
            return 200, '<a>Directory listing without managed DNS</a>', {}

    client = PublicClient()
    evidence = module.verify_public_directory(
        client, listed="Directory listing without managed DNS", hidden="Managed DNS without directory listing",
    )
    assert client.path == "/ui/public"
    assert evidence["status"] == 200
    with pytest.raises(RuntimeError, match="visibility"):
        module.verify_public_directory(client, listed="missing", hidden="Managed DNS without directory listing")


def test_settings_archive_roundtrip_keeps_bytes_in_memory_and_reports_no_archive_body(tmp_path):
    """Use authenticated UI helpers and multipart memory bytes without creating an archive file.

    Args:
        tmp_path: Isolated filesystem root supplied by pytest.
    """
    module = load_module("proxy_archive_acceptance_test", "reverse_proxy_acceptance.py")
    archive_bytes = json.dumps({
        "data": {
            "reverse_proxies": [{
                "id": 3, "name": "Fixture proxy", "hostname": "proxy.example.test",
                "managed_dns": True, "public_listing": False,
            }],
            "reverse_proxy_routes": [{"proxy_name": "Fixture proxy", "position": 0, "path_prefix": "/"}],
            "opaque_settings": "archive-body-canary",
        },
    }).encode()

    class UiClient:
        def __init__(self):
            self.multipart = None

        def request(self, method, path):
            """Simulate request for the focused fixture.

            Args:
                method: HTTP method expected by the simulated operation.
                path: Exact fixture filesystem or HTTP path.
            """
            assert method == "GET" and path == "/backup-restore"
            return 200, "csrf page", {}

        def request_bytes(self, method, path, *, form, timeout):
            """Simulate request bytes for the focused fixture.

            Args:
                method: HTTP method expected by the simulated operation.
                path: Exact fixture filesystem or HTTP path.
                form: Fixture input for request bytes.
                timeout: Maximum command or request duration.
            """
            assert method == "POST" and path == "/backup-restore/export" and form == {"csrf": "csrf"} and timeout == 30
            return 200, archive_bytes, {}

        def multipart_request(self, method, path, *, fields, files):
            """Simulate multipart request for the focused fixture.

            Args:
                method: HTTP method expected by the simulated operation.
                path: Exact fixture filesystem or HTTP path.
                fields: Fixture input for multipart request.
                files: Fixture input for multipart request.
            """
            self.multipart = (method, path, fields, files)
            return 200, "Settings restored", {}

    ui_client = UiClient()
    calls = []

    class Lifecycle:
        @staticmethod
        def authenticated_ui_client(client, args):
            """Simulate authenticated ui client for the focused fixture.

            Args:
                client: Initialized appliance test fixture.
                args: Fixture input for authenticated ui client.
            """
            return ui_client

        @staticmethod
        def extract_csrf(page):
            """Simulate extract csrf for the focused fixture.

            Args:
                page: Fixture input for extract csrf.
            """
            assert page == "csrf page"
            return "csrf"

        @staticmethod
        def reauthenticate_after_restore(client, args):
            """Simulate reauthenticate after restore for the focused fixture.

            Args:
                client: Initialized appliance test fixture.
                args: Fixture input for reauthenticate after restore.
            """
            calls.append("reauth")

    client = object()
    args = object()
    exported, metadata = module.export_archive_in_memory(Lifecycle, client, args)
    assert exported == archive_bytes
    assert metadata["proxy_count"] == 1 and metadata["route_count"] == 1
    assert "archive-body-canary" not in repr(metadata)
    assert metadata["proxy_flags"] == [{
        "id": 3, "name": "Fixture proxy", "hostname": "proxy.example.test",
        "managed_dns": True, "public_listing": False,
    }]
    restored = module.restore_archive_from_memory(Lifecycle, client, args, exported)
    method, path, fields, files = ui_client.multipart
    assert (method, path, fields) == ("POST", "/backup-restore/restore", {"csrf": "csrf"})
    assert files["archive_file"] == ("atlaso-settings.json", archive_bytes, "application/json")
    assert restored == {"http_status": 200, "archive_bytes": len(archive_bytes), "reauthed": True}
    assert calls == ["reauth"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "nt" or not shutil.which("node"), reason="Windows Node job boundary")
def test_browser_failure_terminates_its_owned_job(tmp_path):
    """Launch the actual stdin-gated Node consumer and prove failure cleanup.

    Args:
        tmp_path: Test-owned lifecycle result root.
    """
    module = load_module("proxy_browser_test", "reverse_proxy_browser.py")
    client = SimpleNamespace(base_url="http://invalid.example.test", cookie_jar=[])
    args = SimpleNamespace(result_dir=str(tmp_path), reverse_proxy_screenshot_dir=str(tmp_path / "screenshots"),
                           reverse_proxy_screenshot_node=shutil.which("node"), reverse_proxy_screenshot_packages="unused",
                           reverse_proxy_screenshot_browser="unused")
    with pytest.raises(RuntimeError, match="^Reverse-proxy browser capture failed\\.$"):
        module.capture_ui(client, args)
    assert list((tmp_path / "screenshots").iterdir()) == []
