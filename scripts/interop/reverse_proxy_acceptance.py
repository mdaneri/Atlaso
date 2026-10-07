"""Verify managed reverse proxies through the admitted native lifecycle consumer."""

from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import os
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


class FixtureHandler(BaseHTTPRequestHandler):
    """Return bounded public fixture evidence without recording request data."""

    def log_message(self, _format: str, *args: Any) -> None:
        """Suppress request logs, including potentially authenticated headers."""

    def do_HEAD(self) -> None:
        """Answer the runtime's bounded health probe."""
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        """Echo non-secret path and managed forwarding headers or challenge auth."""
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

    def get_request(self) -> tuple[socket.socket, Any]:
        """Set a finite timeout before a request worker consumes the socket."""
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address


def listener_request(address: str, port: int, hostname: str, path: str, *, context: ssl.SSLContext | None = None) -> tuple[int, bytes, dict[str, str]]:
    """Connect to an exact listener while independently selecting Host and SNI."""
    connection = socket.create_connection((address, port), timeout=15)
    if context is not None:
        try:
            connection = context.wrap_socket(connection, server_hostname=hostname)
        except BaseException:
            connection.close()
            raise
    with connection:
        connection.sendall(f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode("ascii"))
        response = http.client.HTTPResponse(connection)
        response.begin()
        body = response.read(65537)
        if len(body) > 65536:
            raise RuntimeError("Listener response exceeded the evidence bound.")
        return response.status, body, dict(response.getheaders())


def proxy_payload(name: str, hostname: str, address: str, interface: str, upstream_host: str, upstream_port: int, *, scheme: str = "http", port: int = 8080) -> dict[str, Any]:
    """Return complete public fixture desired state without credentials."""
    return {
        "name": name, "description": "Native appliance acceptance fixture", "hostname": hostname,
        "scheme": scheme, "port": port, "redirect_http": scheme == "https", "redirect_port": 8081,
        "enabled": True, "public_listing": True, "managed_dns": False,
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
    step(results, "configure-proxy-ca", lifecycle.configure_ca, client, args)
    server = FixtureServer((host, 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, name="atlaso-proxy-fixture", daemon=True)
    thread.start()
    try:
        fixture_port = server.server_address[1]
        http_payload = proxy_payload("Native HTTP application", "http.proxy.atlaso.internal", address, args.site_interface, host, fixture_port)
        https_payload = proxy_payload("Native HTTPS application", "https.proxy.atlaso.internal", address, args.site_interface, host, fixture_port, scheme="https", port=8443)
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
        step(results, "apply-managed-proxies", lifecycle.apply_units, client, UNITS, args)
        status, root, _headers = client.request("GET", "/certificate-authority/downloads/root-ca.pem")
        if status != 200 or "BEGIN CERTIFICATE" not in root:
            raise lifecycle.LifecycleError("Applied proxy CA root is unavailable.")
        context = ssl.create_default_context(cadata=root)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        def verify_publication() -> dict[str, Any]:
            """Verify TLS identity, both mappings, auth challenge and exact host."""
            observations = []
            for payload, tls in ((http_payload, None), (https_payload, context)):
                websocket_exchange(address, payload["port"], payload["hostname"], context=tls)
                for prefix, expected in (("/preserve/", "/preserve/value?q=1"), ("/strip/", "/value?q=1")):
                    code, body, _ = listener_request(address, payload["port"], payload["hostname"], prefix + "value?q=1", context=tls)
                    if code != 200:
                        raise lifecycle.LifecycleError(f"Proxy mapping returned HTTP {code}.")
                    observed = json.loads(body)
                    if observed["path"] != expected or observed["forwarded_proto"] != payload["scheme"]:
                        raise lifecycle.LifecycleError("Proxy path mapping or forwarded protocol differs from intent.")
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
