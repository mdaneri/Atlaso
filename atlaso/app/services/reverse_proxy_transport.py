"""Relay bounded streams after verifying the actual upstream TLS connection.

nginx owns HTTP parsing, routing, limits and public listeners. This unprivileged
transport owns only outbound connections and cannot render or install nginx.
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import struct
import sys
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any

CONFIG_ROOT = Path("/etc/atlaso/traffic-publishing/reverse-proxies")
SOCKET_ROOT = Path("/run/atlaso-rp")
MAX_CONNECTIONS = 128
MAX_ROUTES = 256
BUFFER_LIMIT = 65536


def manifest_generation(manifest: dict[str, Any]) -> str:
    """Bind a generation to its complete non-secret transport intent."""
    content = {key: value for key, value in manifest.items() if key != "generation"}
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_manifest(manifest: dict[str, Any]) -> None:
    """Refuse malformed or unbounded data independently of the management API."""
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "generation", "routes", "forbidden_addresses"} or type(manifest["schema"]) is not int or manifest["schema"] != 1:
        raise ValueError("Unsupported reverse-proxy transport manifest.")
    if manifest["generation"] != manifest_generation(manifest):
        raise ValueError("Reverse-proxy generation does not match its intent.")
    if not isinstance(manifest["routes"], list) or len(manifest["routes"]) > MAX_ROUTES:
        raise ValueError("Reverse-proxy route limit exceeded.")
    if not isinstance(manifest["forbidden_addresses"], list) or len(manifest["forbidden_addresses"]) > 4096:
        raise ValueError("Invalid appliance address inventory.")
    for address in manifest["forbidden_addresses"]:
        if not isinstance(address, str):
            raise ValueError("Invalid appliance address inventory.")
        ip_address(address)
    seen: set[str] = set()
    for route in manifest["routes"]:
        if not isinstance(route, dict) or set(route) != {"socket_id", "upstream_scheme", "upstream_host", "upstream_port", "trust_mode", "fingerprint", "connect_timeout", "read_timeout", "send_timeout", "probe_host", "probe_path"}:
            raise ValueError("Unexpected transport route fields.")
        if (not isinstance(route["probe_host"], str) or len(route["probe_host"]) > 253
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", route["probe_host"])
                or not isinstance(route["probe_path"], str) or len(route["probe_path"]) > 9216
                or not re.fullmatch(r"/[A-Za-z0-9._~/%-]*", route["probe_path"])):
            raise ValueError("Invalid bounded public route health target.")
        if any(not isinstance(route[field], str) for field in ("upstream_scheme", "trust_mode", "fingerprint")):
            raise ValueError("Transport scheme and trust fields must be strings.")
        key = route["socket_id"]
        if not isinstance(key, str) or not re.fullmatch(r"[1-9][0-9]{0,9}-[1-9][0-9]{0,9}", key) or key in seen:
            raise ValueError("Invalid or duplicate transport socket identity.")
        seen.add(key)
        host = route["upstream_host"]
        if not isinstance(host, str) or len(host) > 253 or any(char in host for char in "@/\\%?#;{}\"' \t\r\n"):
            raise ValueError("Invalid upstream host.")
        try:
            ip_address(host)
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", host):
                raise ValueError("Invalid upstream DNS hostname.") from None
        if type(route["upstream_port"]) is not int or not 1 <= route["upstream_port"] <= 65535:
            raise ValueError("Invalid upstream port.")
        if route["upstream_scheme"] not in {"http", "https"} or route["trust_mode"] not in {"trusted_ca", "fingerprint", "insecure"}:
            raise ValueError("Invalid upstream scheme or trust mode.")
        if route["upstream_scheme"] == "http" and route["trust_mode"] != "trusted_ca":
            raise ValueError("TLS trust choices require HTTPS.")
        if route["trust_mode"] == "fingerprint" and not re.fullmatch(r"[0-9a-f]{64}", route["fingerprint"]):
            raise ValueError("An exact SHA-256 certificate fingerprint is required.")
        if route["trust_mode"] != "fingerprint" and route["fingerprint"]:
            raise ValueError("A fingerprint is meaningful only in fingerprint mode.")
        for field, maximum in (("connect_timeout", 30), ("read_timeout", 300), ("send_timeout", 300)):
            if type(route[field]) is not int or not 1 <= route[field] <= maximum:
                raise ValueError("Transport timeout is outside its bounded range.")


def native_addresses() -> set[str]:
    """Read every Linux local address using a bounded kernel netlink dump.

    Failure refuses outbound connections; hostname resolution alone cannot prove
    that a newly assigned alias is not an appliance management listener.
    """
    if not hasattr(socket, "AF_NETLINK"):
        raise OSError("Native local-address observation is unavailable.")
    addresses: set[str] = set()
    # NETLINK_ROUTE is zero in the Linux UAPI; Windows socket stubs omit the name.
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as observer:
        observer.settimeout(0.5)
        observer.bind((0, 0))
        observer.send(struct.pack("IHHII", 24, 22, 0x301, 1, 0) + struct.pack("BBBBI", socket.AF_UNSPEC, 0, 0, 0, 0))
        total = 0
        while total < 1048576:
            data = observer.recv(65536)
            total += len(data)
            offset = 0
            while offset + 16 <= len(data):
                length, kind, _flags, sequence, _pid = struct.unpack_from("IHHII", data, offset)
                if length < 16 or offset + length > len(data) or sequence != 1:
                    raise OSError("Invalid native local-address observation.")
                if kind == 3:
                    return addresses
                if kind == 2:
                    raise OSError("Native local-address observation failed.")
                if kind == 20 and length >= 24:
                    family = data[offset + 16]
                    position = offset + 24
                    while position + 4 <= offset + length:
                        size, attribute = struct.unpack_from("HH", data, position)
                        if size < 4 or position + size > offset + length:
                            raise OSError("Invalid native address attribute.")
                        packed = data[position + 4:position + size]
                        if attribute in {1, 2} and family in {socket.AF_INET, socket.AF_INET6}:
                            expected = 4 if family == socket.AF_INET else 16
                            if len(packed) != expected:
                                raise OSError("Invalid native address length.")
                            addresses.add(socket.inet_ntop(family, packed))
                        position += (size + 3) & ~3
                offset += (length + 3) & ~3
    raise OSError("Native local-address observation exceeded its limit.")


def safe_destination(address: str, forbidden: set[str]) -> bool:
    """Exclude appliance and special addresses after DNS resolution."""
    value = ip_address(address)
    return not (str(value) in forbidden or value.is_loopback or value.is_link_local
                or value.is_multicast or value.is_unspecified or value.is_reserved
                or getattr(value, "ipv4_mapped", None) is not None or "%" in address)


def tls_context(route: dict[str, Any]) -> ssl.SSLContext | None:
    """Select explicit TLS policy without weakening the trusted default."""
    if route["upstream_scheme"] == "http":
        return None
    context = ssl.create_default_context()
    if route["trust_mode"] in {"fingerprint", "insecure"}:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def verify_peer(route: dict[str, Any], writer: asyncio.StreamWriter) -> None:
    """Compare the leaf of the connected TLS stream before forwarding bytes."""
    if route["trust_mode"] != "fingerprint":
        return
    peer = writer.get_extra_info("ssl_object")
    certificate = peer.getpeercert(binary_form=True) if peer else None
    if not certificate or not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), route["fingerprint"]):
        raise ssl.SSLCertVerificationError("Upstream certificate pin mismatch.")


async def open_upstream(route: dict[str, Any], forbidden: set[str]) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Resolve once and connect to a validated literal under one deadline."""
    writer = None
    async with asyncio.timeout(route["connect_timeout"]):
        local = await asyncio.to_thread(native_addresses)
        blocked = forbidden | local
        results = await asyncio.get_running_loop().getaddrinfo(route["upstream_host"], route["upstream_port"], type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(str(item[4][0]) for item in results))
        if not addresses or len(addresses) > 32 or any(not safe_destination(address, blocked) for address in addresses):
            raise OSError("Upstream resolves to an excluded address.")
        context = tls_context(route)
        last_error: OSError | None = None
        for address in addresses:
            try:
                reader, writer = await asyncio.open_connection(address, route["upstream_port"], ssl=context,
                    server_hostname=route["upstream_host"] if context else None, limit=BUFFER_LIMIT,
                    ssl_handshake_timeout=route["connect_timeout"] if context else None)
                verify_peer(route, writer)
                return reader, writer
            except ssl.SSLCertVerificationError:
                if writer:
                    writer.close()
                raise
            except OSError as exc:
                if writer:
                    writer.close()
                last_error = exc
        raise OSError("Upstream connection unavailable.") from last_error


async def relay(source: asyncio.StreamReader, target: asyncio.StreamWriter, read_timeout: int, send_timeout: int) -> None:
    """Copy a fixed-size buffer with backpressure and bounded idle time."""
    while True:
        async with asyncio.timeout(read_timeout):
            data = await source.read(BUFFER_LIMIT)
        if not data:
            if target.can_write_eof():
                target.write_eof()
            return
        target.write(data)
        async with asyncio.timeout(send_timeout):
            await target.drain()


async def serve(manifest: dict[str, Any]) -> None:
    """Serve the immutable generation using sockets accessible only to nginx."""
    validate_manifest(manifest)
    root = SOCKET_ROOT / manifest["generation"]
    if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
        raise OSError("Reverse-proxy runtime directory must be created empty by its systemd owner.")
    forbidden = {str(ip_address(address)) for address in manifest["forbidden_addresses"]}
    active = 0
    servers: list[asyncio.Server] = []
    health_task: asyncio.Task[None] | None = None

    async def connection(route: dict[str, Any], reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal active
        if active >= MAX_CONNECTIONS:
            writer.close()
            return
        active += 1
        upstream_writer = None
        tasks: list[asyncio.Task[None]] = []
        try:
            upstream_reader, upstream_writer = await open_upstream(route, forbidden)
            tasks = [asyncio.create_task(relay(reader, upstream_writer, route["read_timeout"], route["send_timeout"])),
                     asyncio.create_task(relay(upstream_reader, writer, route["read_timeout"], route["send_timeout"]))]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                task.result()
        except (OSError, TimeoutError, ssl.SSLError):
            # No request, response, upstream exception text or TLS material is logged.
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            for stream in (writer, upstream_writer):
                if stream:
                    stream.close()
            active -= 1

    try:
        for route in manifest["routes"]:
            async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, selected: dict[str, Any] = route) -> None:
                await connection(selected, reader, writer)
            path = root / (route["socket_id"] + ".sock")
            unix_server_factory = getattr(asyncio, "start_unix_server")  # noqa: B009 - Windows asyncio stubs omit this Linux-only API.
            servers.append(await unix_server_factory(handler, path=path, limit=BUFFER_LIMIT))
            path.chmod(0o660)
        health_task = asyncio.create_task(observe_health(manifest, root))
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        if health_task:
            health_task.cancel()
            await asyncio.gather(health_task, return_exceptions=True)
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        # The privileged generation owner reconciles socket directories after stop.


async def observe_health(manifest: dict[str, Any], root: Path) -> None:
    """Publish bounded observations independently of management HTTP requests."""
    semaphore = asyncio.Semaphore(8)
    previous: dict[str, Any] = {}

    async def observe(route: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        async with semaphore:
            try:
                async with asyncio.timeout(10):
                    result = await probe(route, set(manifest["forbidden_addresses"]))
            except TimeoutError:
                result = {"status": "degraded", "last_success": None, "failure_class": "unavailable",
                          "http_status": None, "tls_status": "not_probed"}
            key = route["socket_id"]
            if result["last_success"] is None:
                result["last_success"] = previous.get(key, {}).get("last_success")
            result["observed_at"] = datetime.now(timezone.utc).isoformat()
            return key, result

    while True:
        routes = manifest["routes"]
        for start in range(0, max(1, len(routes)), 8):
            previous.update(await asyncio.gather(*(observe(route) for route in routes[start:start + 8])))
            payload = {"schema": 1, "generation": manifest["generation"], "health": previous,
                       "observed_at": datetime.now(timezone.utc).isoformat()}
            temporary = root / "health.pending"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o640)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            temporary.replace(root / "health.json")
        await asyncio.sleep(30)


async def probe(route: dict[str, Any], forbidden: set[str]) -> dict[str, Any]:
    """Probe TLS and an HTTP HEAD status without retaining response content."""
    writer = None
    result: dict[str, Any] = {"status": "degraded", "last_success": None, "failure_class": None,
                              "http_status": None, "tls_status": "not_probed"}
    try:
        reader, writer = await open_upstream(route, forbidden)
        result["tls_status"] = "not_applicable" if route["upstream_scheme"] == "http" else route["trust_mode"]
        host = route["probe_host"]
        writer.write(f"HEAD {route['probe_path']} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
        async with asyncio.timeout(min(route["read_timeout"], 5)):
            await writer.drain()
            line = await reader.readuntil(b"\r\n")
        if len(line) > 1024 or not re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?\r\n", line):
            result["failure_class"] = "invalid_http"
            return result
        result["http_status"] = int(line.split(b" ")[1])
        result["status"] = "healthy" if result["http_status"] < 500 else "degraded"
        result["failure_class"] = None if result["status"] == "healthy" else "upstream_http"
        result["last_success"] = datetime.now(timezone.utc).isoformat() if result["status"] == "healthy" else None
        if route["trust_mode"] == "insecure":
            result["status"] = "degraded"
            result["failure_class"] = "insecure_verification"
    except ssl.SSLCertVerificationError:
        result.update(failure_class="tls_verification", tls_status="failed")
    except (OSError, TimeoutError, ssl.SSLError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        result["failure_class"] = "unavailable"
    finally:
        if writer:
            writer.close()
    return result


def main() -> None:
    """Load only a fixed-path, size-bounded immutable generation."""
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--generation")
    action.add_argument("--validate-manifest", action="store_true")
    args = parser.parse_args()
    if args.validate_manifest:
        try:
            raw = sys.stdin.buffer.read(1048577)
            if len(raw) > 1048576:
                raise ValueError("Manifest exceeds its size bound.")
            validate_manifest(json.loads(raw))
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise SystemExit("Reverse-proxy manifest is invalid.") from None
        return
    if not re.fullmatch(r"[0-9a-f]{64}", args.generation):
        raise SystemExit("Invalid reverse-proxy generation.")
    path = CONFIG_ROOT / (args.generation + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1048576:
        raise SystemExit("Reverse-proxy manifest is unavailable or unsafe.")
    manifest = json.loads(path.read_text())
    validate_manifest(manifest)
    read_uid = getattr(os, "geteuid", None)
    if manifest["generation"] != args.generation or read_uid is None or read_uid() == 0:
        raise SystemExit("Reverse-proxy transport requires its unprivileged generation identity.")
    asyncio.run(serve(manifest))


if __name__ == "__main__":
    main()
