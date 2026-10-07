"""Verify managed reverse proxies through the admitted native lifecycle consumer."""

from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import os
import shlex
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address, ip_interface
from pathlib import Path
from typing import Any

API = "/api/v1/traffic-publishing/reverse-proxies"
UNITS = ["network", "firewall", "ca", "appliance_settings", "dnsmasq", "public_services"]
DNS_API = "/api/v1/dns"
DNS_OWNER_PREFIX = "Atlaso-managed reverse proxy DNS: "
DNS_UPDATE_FIELDS = (
    "enabled", "listen_interface", "listen_address", "domain", "upstream_servers",
    "conditional_forwarders", "cache_size", "expand_hosts", "authoritative",
    "authoritative_server", "authoritative_contact", "authoritative_ttl",
    "authoritative_refresh", "authoritative_retry", "authoritative_expire",
    "dnssec_enabled", "rebind_protection_enabled", "rebind_domain_exemptions",
    "query_logging_mode",
)


def dns_settings_payload(current: dict[str, Any], *, domain: str, interface: str, address: str) -> dict[str, Any]:
    """Build the DNS-only authoritative listener update without touching DHCP.

    Args:
        current: Current DNS settings to preserve outside the selected listener fields.
        domain: Authoritative zone used by the owned fixture.
        interface: Admitted physical Site A interface name.
        address: Exact selected Site A IPv4 listener address.
    """
    payload = {field: current[field] for field in DNS_UPDATE_FIELDS if field in current}
    payload.update({
        "enabled": True,
        "listen_interface": interface,
        "listen_address": address,
        "domain": domain,
        "authoritative": True,
        "authoritative_server": f"ns1.{domain}",
        "authoritative_contact": f"hostmaster.{domain}",
    })
    return payload


def configure_proxy_dns(client: Any, args: Any, address: str) -> dict[str, Any]:
    """Enable authoritative DNS on the owned IPv4 Site A listener only.

    Args:
        client: Initialized appliance HTTP client or test fixture.
        args: Admitted lifecycle credentials and network selections.
        address: Exact selected Site A IPv4 listener address.
    """
    current = client.json_request("GET", f"{DNS_API}/settings")
    updated = client.json_request(
        "PATCH", f"{DNS_API}/settings",
        json_body=dns_settings_payload(current, domain=args.domain, interface=args.site_interface, address=address),
    )
    if not updated.get("enabled") or not updated.get("authoritative") or updated.get("listen_address") != address:
        raise RuntimeError("Authoritative DNS did not retain the bounded Site A listener configuration.")
    return {"authoritative": True, "listener_address": address, "domain": args.domain}


def assert_proxy_dns_record(client: Any, proxy: dict[str, Any], address: str, *, expected: bool) -> None:
    """Require an exact enabled owner-managed A record, or its absence.

    Args:
        client: Initialized appliance HTTP client or test fixture.
        proxy: Saved proxy identity and desired-state projection.
        address: Exact selected Site A IPv4 listener address.
        expected: Expected presence or runtime outcome.
    """
    rows = client.json_request("GET", f"{DNS_API}/records")
    owned = [
        row for row in rows
        if row.get("hostname") == proxy["hostname"] and row.get("description") == f"{DNS_OWNER_PREFIX}{proxy['id']}"
    ]
    if expected:
        if len(owned) != 1 or owned[0].get("record_type") != "A" or owned[0].get("address") != address or not owned[0].get("enabled"):
            raise RuntimeError("Managed proxy DNS did not produce its exact enabled owner record.")
    elif owned:
        raise RuntimeError("A proxy with managed DNS disabled created an owner-managed DNS record.")


def verify_proxy_dns_wire(lifecycle: Any, args: Any, hostname: str, address: str, *, expected: bool) -> None:
    """Check the authoritative Site A DNS listener with one bounded read-only dig.

    Args:
        lifecycle: Supported lifecycle operations used by the fixture.
        args: Admitted lifecycle credentials and network selections.
        hostname: Canonical proxy hostname to verify.
        address: Exact selected Site A IPv4 listener address.
        expected: Expected presence or runtime outcome.
    """
    command = (
        f"dig +time=2 +tries=1 +short A {shlex.quote(hostname)} @{shlex.quote(address)}"
    )
    result = lifecycle.ssh_command(args.appliance_ssh_host, args, command, role="appliance", appliance_as_root=False)
    answers = {line.strip() for line in result.get("stdout", "").splitlines() if line.strip()}
    if result.get("returncode") != 0 or ((address in answers) != expected):
        raise RuntimeError("The bounded authoritative DNS query did not match the saved proxy DNS intent.")


def verify_public_directory(public_client: Any, *, listed: str, hidden: str) -> dict[str, Any]:
    """Prove listing eligibility independently through the Site A Public Services listener.

    Args:
        public_client: CA-verified HTTP client bound to the public listener.
        listed: Expected visible Public Services proxy name.
        hidden: Proxy name that must be absent from the public directory.
    """
    status, body, _headers = public_client.request("GET", "/ui/public")
    if status != 200 or listed not in body or hidden in body:
        raise RuntimeError("Public Services directory visibility did not match the independent listing flags.")
    return {"listed_proxy": listed, "hidden_proxy": hidden, "status": status}


def export_archive_in_memory(lifecycle: Any, client: Any, args: Any) -> tuple[bytes, dict[str, Any]]:
    """Export desired state into bounded process memory and return sanitized metadata only.

    Args:
        lifecycle: Supported lifecycle operations used by the fixture.
        client: Initialized appliance HTTP client or test fixture.
        args: Admitted lifecycle credentials and network selections.
    """
    ui_client = lifecycle.authenticated_ui_client(client, args)
    status, page, _headers = ui_client.request("GET", "/backup-restore")
    if status >= 400:
        raise RuntimeError(f"Settings archive page failed with HTTP {status}.")
    csrf = lifecycle.extract_csrf(page)
    status, archive_bytes, _headers = ui_client.request_bytes(
        "POST", "/backup-restore/export", form={"csrf": csrf}, timeout=30,
    )
    if status >= 400 or not archive_bytes or len(archive_bytes) > 3_000_000:
        raise RuntimeError(f"Settings archive export failed its bounded response check (HTTP {status}).")
    try:
        archive = json.loads(archive_bytes.decode("utf-8-sig"))
        data = archive["data"]
        proxies = data["reverse_proxies"]
        route_count = len(data["reverse_proxy_routes"])
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError("Settings archive did not contain the expected proxy desired-state sections.") from exc
    if not isinstance(proxies, list) or not isinstance(data.get("reverse_proxy_routes"), list):
        raise RuntimeError("Settings archive proxy desired-state sections were malformed.")
    metadata = {
        "bytes": len(archive_bytes),
        "proxy_count": len(proxies),
        "route_count": route_count,
        "proxy_flags": [
            {"id": row.get("id"), "name": row.get("name"), "hostname": row.get("hostname"),
             "managed_dns": row.get("managed_dns"), "public_listing": row.get("public_listing")}
            for row in proxies if isinstance(row, dict)
        ],
    }
    return archive_bytes, metadata


def restore_archive_from_memory(lifecycle: Any, client: Any, args: Any, archive_bytes: bytes) -> dict[str, Any]:
    """Restore bounded desired-state bytes with the existing authenticated UI flow.

    Args:
        lifecycle: Supported lifecycle operations used by the fixture.
        client: Initialized appliance HTTP client or test fixture.
        args: Admitted lifecycle credentials and network selections.
        archive_bytes: Process-local settings archive bytes, never written to disk.
    """
    ui_client = lifecycle.authenticated_ui_client(client, args)
    status, page, _headers = ui_client.request("GET", "/backup-restore")
    if status >= 400:
        raise RuntimeError(f"Settings archive page failed with HTTP {status}.")
    csrf = lifecycle.extract_csrf(page)
    status, body, _headers = ui_client.multipart_request(
        "POST", "/backup-restore/restore", fields={"csrf": csrf},
        files={"archive_file": ("atlaso-settings.json", archive_bytes, "application/json")},
    )
    if status >= 400 or "Settings restored" not in body:
        raise RuntimeError(f"In-memory settings archive restore failed with HTTP {status}.")
    lifecycle.reauthenticate_after_restore(client, args)
    return {"http_status": status, "archive_bytes": len(archive_bytes), "reauthed": True}


class FixtureHandler(BaseHTTPRequestHandler):
    """Return bounded public fixture evidence without recording request data."""

    def log_message(self, _format: str, *args: Any) -> None:
        """Suppress request logs, including potentially authenticated headers.

        Args:
            _format: Input selecting the log message fixture behavior.
            *args: Additional positional arguments passed unchanged to the original operation.
        """

    def do_HEAD(self) -> None:
        """Answer the runtime's bounded health probe."""
        if self.server.unavailable.is_set():
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        """Echo non-secret path and managed forwarding headers or challenge auth."""
        if self.server.unavailable.is_set():
            self.close_connection = True
            return
        if self.path.endswith("/auth"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Atlaso acceptance fixture"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers.get("Sec-WebSocket-Key", "")
            try:
                if len(base64.b64decode(key, validate=True)) != 16:
                    raise ValueError("invalid websocket key")
            except ValueError:
                self.send_error(400)
                return
            digest = hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(), usedforsecurity=False).digest()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", base64.b64encode(digest).decode())
            self.end_headers()
            header = self.rfile.read(2)
            if len(header) != 2 or header[0] != 0x81 or not header[1] & 0x80 or header[1] & 0x7F > 125:
                return
            mask = self.rfile.read(4)
            payload = self.rfile.read(header[1] & 0x7F)
            if len(mask) != 4 or len(payload) != header[1] & 0x7F:
                return
            decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            self.wfile.write(bytes([0x81, len(decoded)]) + decoded)
            self.wfile.flush()
            self.close_connection = True
            return
        body = json.dumps({
            "path": self.path[:2048],
            "host": self.headers.get("Host", "")[:253],
            "forwarded_proto": self.headers.get("X-Forwarded-Proto", "")[:16],
            "forwarded_host": self.headers.get("X-Forwarded-Host", "")[:253],
            "forwarded_for": self.headers.get("X-Forwarded-For", "")[:253],
            "real_ip": self.headers.get("X-Real-IP", "")[:253],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FixtureServer(ThreadingHTTPServer):
    """Bound concurrent fixture requests and close worker sockets on exit."""

    daemon_threads = True
    request_queue_size = 8

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Own an explicit availability switch without replacing the socket.

        Args:
            *args: Additional positional arguments passed unchanged to the original operation.
            **kwargs: Additional keyword arguments passed unchanged to the original operation.
        """
        self.unavailable = threading.Event()
        super().__init__(*args, **kwargs)

    def get_request(self) -> tuple[socket.socket, Any]:
        """Set a finite timeout before a request worker consumes the socket."""
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address


def listener_request(address: str, port: int, hostname: str, path: str, *, context: ssl.SSLContext | None = None) -> tuple[int, bytes, dict[str, str]]:
    """Connect to an exact listener while independently selecting Host and SNI.

    Args:
        address: Exact selected Site A IPv4 listener address.
        port: Selected public listener port.
        hostname: Canonical proxy hostname to verify.
        path: Filesystem path or request path under test.
        context: Input selecting the listener request fixture behavior.
    """
    connection = socket.create_connection((address, port), timeout=15)
    if context is not None:
        try:
            connection = context.wrap_socket(connection, server_hostname=hostname)
        except BaseException:
            connection.close()
            raise
    with connection:
        connection.sendall(f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nX-Forwarded-For: 203.0.113.99\r\nX-Forwarded-Host: spoof.example.test\r\nX-Forwarded-Proto: spoof\r\nConnection: close\r\n\r\n".encode("ascii"))
        response = http.client.HTTPResponse(connection)
        response.begin()
        body = response.read(65537)
        if len(body) > 65536:
            raise RuntimeError("Listener response exceeded the evidence bound.")
        return response.status, body, dict(response.getheaders())


def proxy_payload(
    name: str, hostname: str, address: str, interface: str, upstream_host: str, upstream_port: int,
    *, scheme: str = "http", port: int = 8080, managed_dns: bool = False, public_listing: bool = True,
) -> dict[str, Any]:
    """Return complete public fixture desired state without credentials.

    Args:
        name: Stable fixture or module identity.
        hostname: Canonical proxy hostname to verify.
        address: Exact selected Site A IPv4 listener address.
        interface: Admitted physical Site A interface name.
        upstream_host: Fixture application address reachable from the appliance.
        upstream_port: Bound fixture application TCP port.
        scheme: Public listener HTTP or HTTPS scheme.
        port: Selected public listener port.
        managed_dns: Whether Atlaso owns the authoritative DNS record.
        public_listing: Whether the public directory should show this proxy.
    """
    return {
        "name": name, "description": "Native appliance acceptance fixture", "hostname": hostname,
        "scheme": scheme, "port": port, "redirect_http": scheme == "https", "redirect_port": 8081,
        "enabled": True, "public_listing": public_listing, "managed_dns": managed_dns,
        "listeners": [{"interface": interface, "address": address}],
        "routes": [{"path_prefix": prefix, "upstream_scheme": "http", "upstream_host": upstream_host,
                    "upstream_port": upstream_port, "path_behavior": behavior, "trust_mode": "trusted_ca"}
                   for prefix, behavior in (("/preserve/", "preserve"), ("/strip/", "strip"))],
    }


def websocket_exchange(address: str, port: int, hostname: str, *, context: ssl.SSLContext | None = None) -> None:
    """Verify a real bounded upgrade and masked frame exchange through a route.

    Args:
        address: Exact owned listener address.
        port: Public listener port.
        hostname: Host and TLS SNI selected independently of the TCP address.
        context: Applied CA verification context for an HTTPS listener.
    """
    key = base64.b64encode(b"0123456789abcdef").decode()
    connection = socket.create_connection((address, port), timeout=15)
    if context is not None:
        try:
            connection = context.wrap_socket(connection, server_hostname=hostname)
        except BaseException:
            connection.close()
            raise
    with connection:
        request = f"GET /strip/websocket HTTP/1.1\r\nHost: {hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        connection.sendall(request.encode())
        response = http.client.HTTPResponse(connection)
        response.begin()
        digest = hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(), usedforsecurity=False).digest()
        if response.status != 101 or response.getheader("Sec-WebSocket-Accept") != base64.b64encode(digest).decode():
            raise RuntimeError("WebSocket upgrade was not preserved.")
        data = b"atlaso-public-fixture"
        mask = os.urandom(4)
        connection.sendall(bytes([0x81, 0x80 | len(data)]) + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(data)))
        expected = bytes([0x81, len(data)]) + data
        actual = b""
        while len(actual) < len(expected):
            chunk = connection.recv(len(expected) - len(actual))
            if not chunk:
                break
            actual += chunk
        if actual != expected:
            raise RuntimeError("WebSocket frame exchange differs from the public fixture.")


def run_reverse_proxy_acceptance(lifecycle: Any, results: list[Any], client: Any, args: Any) -> None:
    """Run host-facing checks on the wrapper-owned appliance via normal Apply.

    Args:
        lifecycle: Admitted lifecycle module supplying authentication and Apply.
        results: Safe lifecycle step evidence collection.
        client: Management client whose secrets remain in process memory.
        args: Validated owned appliance and host fixture selection.
    """
    address = str(ip_interface(args.site_cidr).ip)
    host = str(IPv4Address(args.reverse_proxy_upstream_host))
    if host == address or IPv4Address(host).is_loopback or IPv4Address(host).is_unspecified:
        raise lifecycle.LifecycleError("The upstream must be the selected remote host adapter.")
    step = lifecycle.run_step
    step(results, "appliance-health", lifecycle.appliance_health, client, args)
    step(results, "configure-proxy-listener", lifecycle.configure_oidc_listener, client, args)
    step(results, "apply-proxy-network", lifecycle.apply_units, client, ["network", "firewall"], args)
    step(results, "configure-proxy-authoritative-dns", configure_proxy_dns, client, args, address)
    step(results, "configure-proxy-ca", lifecycle.configure_ca, client, args)
    server = FixtureServer((host, 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, name="atlaso-proxy-fixture", daemon=True)
    thread.start()
    try:
        fixture_port = server.server_address[1]
        http_payload = proxy_payload("Native HTTP application", "http.proxy.atlaso.internal", address, args.site_interface, host, fixture_port)
        https_payload = proxy_payload("Native HTTPS application", "https.proxy.atlaso.internal", address, args.site_interface, host, fixture_port, scheme="https", port=8443)
        standard_http = proxy_payload("Standard HTTP application", "http.standard.atlaso.internal", address, args.site_interface, host, fixture_port, port=80)
        standard_https = proxy_payload("Standard HTTPS application", "https.standard.atlaso.internal", address, args.site_interface, host, fixture_port, scheme="https", port=443)
        standard_https["redirect_port"] = 80
        dns_not_listed = proxy_payload(
            "Managed DNS without directory listing", f"dns-hidden.{args.domain}", address,
            args.site_interface, host, fixture_port, port=8082, managed_dns=True, public_listing=False,
        )
        listed_without_dns = proxy_payload(
            "Directory listing without managed DNS", f"external-listed.{args.domain}", address,
            args.site_interface, host, fixture_port, port=8083, managed_dns=False, public_listing=True,
        )
        upstream_context = ssl.create_default_context()
        upstream_context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(("example.com", 443), timeout=15) as raw:
            with upstream_context.wrap_socket(raw, server_hostname="example.com") as upstream:
                fingerprint = hashlib.sha256(upstream.getpeercert(binary_form=True)).hexdigest()
        trust_routes = [
            ("/trusted/", "example.com", "trusted_ca", ""),
            ("/pinned/", "example.com", "fingerprint", fingerprint),
            ("/wrong-pin/", "example.com", "fingerprint", "0" * 64),
            ("/self-signed/", "self-signed.badssl.com", "trusted_ca", ""),
            ("/insecure/", "self-signed.badssl.com", "insecure", ""),
        ]
        for prefix, upstream_host, trust, digest in trust_routes:
            https_payload["routes"].append({"path_prefix": prefix, "upstream_scheme": "https",
                                            "upstream_host": upstream_host, "upstream_port": 443,
                                            "path_behavior": "strip", "trust_mode": trust,
                                            "fingerprint": digest, "insecure_acknowledged": trust == "insecure"})
        http_proxy = client.json_request("POST", API, json_body=http_payload)
        https_proxy = client.json_request("POST", API, json_body=https_payload)
        client.json_request("POST", API, json_body=standard_http)
        client.json_request("POST", API, json_body=standard_https)
        dns_proxy = client.json_request("POST", API, json_body=dns_not_listed)
        listing_proxy = client.json_request("POST", API, json_body=listed_without_dns)
        step(results, "apply-managed-proxies", lifecycle.apply_units, client, UNITS, args)
        status, root, _headers = client.request("GET", "/certificate-authority/downloads/root-ca.pem")
        if status != 200 or "BEGIN CERTIFICATE" not in root:
            raise lifecycle.LifecycleError("Applied proxy CA root is unavailable.")
        context = ssl.create_default_context(cadata=root)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        def verify_dns_and_directory_independence() -> dict[str, Any]:
            """Verify owner rows, Site A DNS answers, and independent listing flags."""
            assert_proxy_dns_record(client, dns_proxy, address, expected=True)
            assert_proxy_dns_record(client, listing_proxy, address, expected=False)
            verify_proxy_dns_wire(lifecycle, args, dns_not_listed["hostname"], address, expected=True)
            verify_proxy_dns_wire(lifecycle, args, listed_without_dns["hostname"], address, expected=False)
            # configure_ca binds the admitted Site A address on the fixed CA portal port.
            # Verify that listener with its applied root rather than unrelated OIDC state.
            public_client = lifecycle.HttpClient(f"https://{address}:443", trusted_ca_pem=root)
            directory = verify_public_directory(
                public_client, listed=listed_without_dns["name"], hidden=dns_not_listed["name"],
            )
            return {
                "managed_dns_proxy": dns_not_listed["hostname"],
                "managed_dns_record": True,
                "listed_without_managed_dns": listed_without_dns["hostname"],
                "directory": directory,
            }

        step(results, "proxy-dns-and-directory-independence", verify_dns_and_directory_independence)

        def verify_publication() -> dict[str, Any]:
            """Verify TLS identity, both mappings, auth challenge and exact host."""
            observations = []
            for payload, tls in ((http_payload, None), (https_payload, context), (standard_http, None), (standard_https, context)):
                websocket_exchange(address, payload["port"], payload["hostname"], context=tls)
                for prefix, expected in (("/preserve/", "/preserve/value?q=1"), ("/strip/", "/value?q=1")):
                    code, body, _ = listener_request(address, payload["port"], payload["hostname"], prefix + "value?q=1", context=tls)
                    if code != 200:
                        raise lifecycle.LifecycleError(f"Proxy mapping returned HTTP {code}.")
                    observed = json.loads(body)
                    if observed["path"] != expected or observed["forwarded_proto"] != payload["scheme"]:
                        raise lifecycle.LifecycleError("Proxy path mapping or forwarded protocol differs from intent.")
                    if observed["host"] != payload["hostname"] or observed["forwarded_host"] != payload["hostname"]:
                        raise lifecycle.LifecycleError("Public Host normalization differs from intent.")
                    if observed["forwarded_for"] != host or observed["real_ip"] != host:
                        raise lifecycle.LifecycleError("Proxy forwarding headers did not preserve the observed client address.")
                    observations.append({"scheme": payload["scheme"], "mapping": prefix, "status": code})
                code, _body, headers = listener_request(address, payload["port"], payload["hostname"], "/strip/auth", context=tls)
                if code != 401 or not headers.get("WWW-Authenticate"):
                    raise lifecycle.LifecycleError("Upstream authentication challenge was not preserved.")
                code, _body, _ = listener_request(address, payload["port"], payload["hostname"], "/api/v1/version", context=tls)
                if code not in {403, 404}:
                    raise lifecycle.LifecycleError("Reserved API path was not isolated.")
            try:
                code, _body, _ = listener_request(address, 8080, "unknown.proxy.atlaso.internal", "/preserve/value")
            except http.client.RemoteDisconnected:
                code = 444
            if code not in {400, 403, 404, 421, 444}:
                raise lifecycle.LifecycleError("Unknown Host reached a proxy route.")
            code, _body, headers = listener_request(address, 8081, https_payload["hostname"], "/preserve/value")
            if code not in {301, 302, 307, 308} or headers.get("Location") != "https://https.proxy.atlaso.internal:8443/preserve/value":
                raise lifecycle.LifecycleError("Custom-port HTTPS redirect differs from intent.")
            code, _body, headers = listener_request(address, 80, standard_https["hostname"], "/preserve/value")
            if code not in {301, 302, 307, 308} or headers.get("Location") != "https://https.standard.atlaso.internal/preserve/value":
                raise lifecycle.LifecycleError("Standard-port HTTPS redirect differs from intent.")
            return {"mappings": observations, "ca_sha256": hashlib.sha256(root.encode()).hexdigest(), "authentication": "challenge preserved", "reserved_paths": "isolated"}

        step(results, "host-facing-proxy-publication", verify_publication)

        def verify_upstream_trust() -> dict[str, Any]:
            """Exercise trusted, connected-leaf pin, rejection and insecure paths."""
            observations = []
            for prefix, _host, trust, _digest in trust_routes:
                code, _body, _ = listener_request(address, 8443, https_payload["hostname"], prefix, context=context)
                expected = {502, 503, 504} if prefix in {"/wrong-pin/", "/self-signed/"} else {200}
                if code not in expected:
                    raise lifecycle.LifecycleError(f"Upstream trust mode {prefix} returned HTTP {code}.")
                observations.append({"path": prefix, "trust": trust, "status": code})
            return {"observations": observations, "upstream_leaf_sha256": fingerprint}

        step(results, "https-upstream-trust", verify_upstream_trust)
        conflicting = dict(http_payload, name="Conflicting proxy", hostname="https.proxy.atlaso.internal")
        code, _body, _ = client.request_bytes("POST", API, json_body=conflicting)
        if code not in {409, 422}:
            raise lifecycle.LifecycleError("Duplicate proxy hostname was accepted.")
        def verify_cached_health() -> dict[str, Any]:
            """Wait for applied cached probes without initiating upstream traffic."""
            expected = {http_proxy["id"], https_proxy["id"]}
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                rows = client.json_request("GET", API + "/health")["items"]
                selected = [row for row in rows if row["proxy_id"] in expected and row["path_prefix"] in {"/preserve/", "/strip/"}]
                if len(selected) == 4 and all(row["applied"] and not row["pending"] and row["status"] == "healthy" and row["http_status"] == 200 for row in selected):
                    return {"proxy_ids": sorted(expected), "routes": 4, "status": "healthy", "applied": True}
                time.sleep(2)
            raise lifecycle.LifecycleError("Applied cached HTTP route observations did not become healthy.")

        step(results, "proxy-cached-health", verify_cached_health)
        def verify_trust_health() -> dict[str, Any]:
            """Require explicit cached trust outcomes including insecure degradation."""
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                rows = {row["path_prefix"]: row for row in client.json_request("GET", API + "/health")["items"] if row["proxy_id"] == https_proxy["id"]}
                expected_tls = {"/trusted/": "trusted_ca", "/pinned/": "fingerprint", "/wrong-pin/": "failed", "/self-signed/": "failed", "/insecure/": "insecure"}
                if all(prefix in rows and rows[prefix]["applied"] and not rows[prefix]["pending"] and rows[prefix]["tls_status"] == tls for prefix, tls in expected_tls.items()):
                    insecure = rows["/insecure/"]
                    if insecure["status"] != "degraded" or not insecure["warning"] or insecure["failure_class"] != "insecure_verification":
                        raise lifecycle.LifecycleError("Insecure upstream trust was not explicitly reported as degraded.")
                    return {"tls": expected_tls, "insecure_status": "degraded", "warning_present": True}
                time.sleep(2)
            raise lifecycle.LifecycleError("Cached upstream TLS outcomes did not match trust intent.")

        step(results, "https-upstream-cached-health", verify_trust_health)
        server.unavailable.set()
        step(results, "apply-with-unavailable-upstream", lifecycle.apply_units, client, UNITS, args)

        def verify_unavailable_health() -> dict[str, Any]:
            """Prove outage degradation while valid applied publication remains live."""
            code, _body, _headers = listener_request(address, 8080, http_payload["hostname"], "/strip/value")
            if code not in {502, 503, 504}:
                raise lifecycle.LifecycleError("Unavailable upstream did not produce a bounded gateway failure.")
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                selected = [row for row in client.json_request("GET", API + "/health")["items"]
                            if row["proxy_id"] in {http_proxy["id"], https_proxy["id"]}
                            and row["path_prefix"] in {"/preserve/", "/strip/"}]
                if len(selected) == 4 and all(row["applied"] and not row["pending"]
                                             and row["status"] == "degraded" and row["failure_class"] == "unavailable"
                                             for row in selected):
                    return {"routes": 4, "status": "degraded", "apply_succeeded": True, "gateway_status": code}
                time.sleep(2)
            raise lifecycle.LifecycleError("Unavailable upstream did not publish degraded cached health.")

        step(results, "unavailable-proxy-cached-health", verify_unavailable_health)
        server.unavailable.clear()
        step(results, "proxy-publication-after-recovery", verify_publication)
        step(results, "proxy-health-after-recovery", verify_cached_health)
        step(results, "proxy-appliance-reboot", lifecycle._reboot_appliance_and_wait, client, args)
        lifecycle.api_login(client, args)
        lifecycle.ui_login(client, args)
        step(results, "proxy-publication-after-reboot", verify_publication)
        step(results, "proxy-health-after-reboot", verify_cached_health)
        step(results, "proxy-trust-after-reboot", verify_trust_health)

        archive_bytes = b""
        archive_metadata: dict[str, Any] = {}

        def export_archive_step() -> dict[str, Any]:
            """Keep archive bytes in memory and expose only bounded proxy metadata."""
            nonlocal archive_bytes, archive_metadata
            archive_bytes, archive_metadata = export_archive_in_memory(lifecycle, client, args)
            return archive_metadata

        step(results, "proxy-settings-archive-export-in-memory", export_archive_step)
        client.json_request("DELETE", f"{API}/{dns_proxy['id']}")
        client.json_request("DELETE", f"{API}/{listing_proxy['id']}")
        step(results, "apply-before-proxy-archive-restore", lifecycle.apply_units, client, UNITS, args)

        def restore_archive_step() -> dict[str, Any]:
            """Restore from the process-local archive buffer with session renewal."""
            return restore_archive_from_memory(lifecycle, client, args, archive_bytes)

        step(results, "proxy-settings-archive-restore-in-memory", restore_archive_step)

        def verify_restored_proxy_intent() -> dict[str, Any]:
            """Verify archived identity/flags and rebind runtime IDs after restore."""
            nonlocal http_proxy, https_proxy, dns_proxy, listing_proxy
            rows = client.json_request("GET", API)
            by_name = {row["name"]: row for row in rows if isinstance(row, dict) and row.get("name")}
            expected_names = {
                http_payload["name"], https_payload["name"],
                dns_not_listed["name"], listed_without_dns["name"],
            }
            expectations = {
                row["name"]: row for row in archive_metadata["proxy_flags"]
                if row.get("name") in expected_names
            }
            if len(expectations) != len(expected_names):
                raise lifecycle.LifecycleError("The in-memory archive omitted an expected proxy identity.")
            for name, expected in expectations.items():
                actual = by_name.get(name)
                fields = ("hostname", "managed_dns", "public_listing")
                if not actual or any(actual.get(field) != expected.get(field) for field in fields):
                    raise lifecycle.LifecycleError("Restored proxy desired state differs from the in-memory archive.")
            http_proxy = by_name[http_payload["name"]]
            https_proxy = by_name[https_payload["name"]]
            dns_proxy = by_name[dns_not_listed["name"]]
            listing_proxy = by_name[listed_without_dns["name"]]
            return {"restored_proxy_count": len(expectations), "flags_verified": True, "ids_rebound": True}

        step(results, "proxy-settings-archive-restored-intent", verify_restored_proxy_intent)
        step(results, "apply-restored-proxy-archive", lifecycle.apply_units, client, UNITS, args)
        status, root, _headers = client.request("GET", "/certificate-authority/downloads/root-ca.pem")
        if status != 200 or "BEGIN CERTIFICATE" not in root:
            raise lifecycle.LifecycleError("Restored proxy CA root is unavailable.")
        context = ssl.create_default_context(cadata=root)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        step(results, "proxy-publication-after-archive-restore", verify_publication)
        step(results, "proxy-upstream-trust-after-archive-restore", verify_upstream_trust)
        step(results, "proxy-health-after-archive-restore", verify_cached_health)
        step(results, "proxy-trust-health-after-archive-restore", verify_trust_health)
        step(results, "proxy-dns-and-directory-after-archive-restore", verify_dns_and_directory_independence)
        if args.reverse_proxy_screenshot_dir:
            module_path = Path(__file__).with_name("reverse_proxy_browser.py")
            spec = importlib.util.spec_from_file_location("atlaso_reverse_proxy_browser", module_path)
            if spec is None or spec.loader is None:
                raise lifecycle.LifecycleError("Browser capture consumer is unavailable.")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            step(results, "reverse-proxy-ui-capture", module.capture_ui, client, args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise lifecycle.LifecycleError("Owned upstream fixture did not terminate.")
