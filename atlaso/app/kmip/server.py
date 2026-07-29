"""Mutually authenticated, bounded TCP server for the Atlaso KMIP service."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import socket
import socketserver
import ssl
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from atlaso.app.kmip.protocol import (
    CRYPTOGRAPHIC_ALGORITHM_AES,
    KmipDispatcher,
    Operation,
    ResultReason,
    ResultStatus,
    Tag,
)
from atlaso.app.kmip.store import KeyStoreError, WrappedKeyStore
from atlaso.app.kmip.trace import TraceValidationError, validate_trace
from atlaso.app.kmip.ttlv import MAX_MESSAGE_BYTES, Ttlv, TtlvError, TtlvType, decode, encode


LOGGER = logging.getLogger("atlaso.kmip")
CONFIG_FIELDS = {
    "schema_version",
    "enabled",
    "listen",
    "tls",
    "store",
    "limits",
    "providers",
    "interop_trace_path",
}
PROVIDER_FIELDS = {"id", "name", "client_fingerprints", "client_certificate_paths"}
OPERATION_NAMES = {
    Operation.CREATE: "Create",
    Operation.LOCATE: "Locate",
    Operation.GET: "Get",
    Operation.GET_ATTRIBUTES: "Get Attributes",
    Operation.GET_ATTRIBUTE_LIST: "Get Attribute List",
    Operation.ACTIVATE: "Activate",
    Operation.QUERY: "Query",
    Operation.DISCOVER_VERSIONS: "Discover Versions",
}
RESULT_REASON_NAMES = {
    ResultReason.ITEM_NOT_FOUND: "Item Not Found",
    ResultReason.INVALID_MESSAGE: "Invalid Message",
    ResultReason.OPERATION_NOT_SUPPORTED: "Operation Not Supported",
    ResultReason.MISSING_DATA: "Missing Data",
    ResultReason.INVALID_FIELD: "Invalid Field",
    ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED: "Key Format Type Not Supported",
    ResultReason.GENERAL_FAILURE: "General Failure",
}


class ConfigurationError(ValueError):
    """Raised when KMIP service configuration fails closed."""


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    client_fingerprints: tuple[str, ...]


@dataclass(frozen=True)
class ServiceLimits:
    max_request_bytes: int = MAX_MESSAGE_BYTES
    max_connections: int = 32
    idle_timeout_seconds: int = 30
    max_requests_per_connection: int = 128


@dataclass(frozen=True)
class ServiceConfig:
    enabled: bool
    host: str
    port: int
    certificate_path: Path
    private_key_path: Path
    ca_path: Path
    database_path: Path
    kek_path: Path
    limits: ServiceLimits
    providers: tuple[Provider, ...]
    interop_trace_path: Path | None = None

    @property
    def fingerprint_providers(self) -> dict[str, str]:
        return {
            fingerprint: provider.id
            for provider in self.providers
            for fingerprint in provider.client_fingerprints
        }


def certificate_sha256(path: Path) -> str:
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ConfigurationError(f"KMIP client certificate is invalid: {path}") from exc
    der = certificate.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def _fingerprint(value: object) -> str:
    if not isinstance(value, str):
        raise ConfigurationError("KMIP client fingerprint must be a string.")
    normalized = value.replace(":", "").strip().casefold()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ConfigurationError("KMIP client fingerprint must be a SHA-256 digest.")
    return normalized


def _exact_fields(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    missing = sorted(expected - value.keys())
    extra = sorted(value.keys() - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise ConfigurationError(f"{label} fields are invalid: {'; '.join(details)}.")


def _path(value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{label} must be a nonempty absolute path.")
    path = Path(value)
    if not path.is_absolute():
        raise ConfigurationError(f"{label} must be an absolute path.")
    return path


def _integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{label} must be an integer.")
    return value


def _provider(value: object) -> Provider:
    if not isinstance(value, dict):
        raise ConfigurationError("KMIP provider must be an object.")
    _exact_fields(value, PROVIDER_FIELDS, label="KMIP provider")
    raw_provider_id = value["id"]
    if not isinstance(raw_provider_id, str):
        raise ConfigurationError("KMIP provider ID must be a UUID string.")
    try:
        provider_id = str(uuid.UUID(raw_provider_id))
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("KMIP provider ID must be a UUID.") from exc
    if not isinstance(value["name"], str):
        raise ConfigurationError("KMIP provider name must be a string.")
    name = value["name"].strip()
    if not name or len(name) > 120:
        raise ConfigurationError("KMIP provider name must contain 1 to 120 characters.")
    configured = value["client_fingerprints"]
    certificate_paths = value["client_certificate_paths"]
    if not isinstance(configured, list) or not isinstance(certificate_paths, list):
        raise ConfigurationError("KMIP provider client identities must be lists.")
    fingerprints = [_fingerprint(item) for item in configured]
    fingerprints.extend(
        certificate_sha256(_path(item, label="KMIP client certificate path"))
        for item in certificate_paths
    )
    if not fingerprints:
        raise ConfigurationError("KMIP provider requires at least one trusted client fingerprint.")
    if len(fingerprints) != len(set(fingerprints)):
        raise ConfigurationError("KMIP provider client fingerprints must be unique.")
    return Provider(id=provider_id, name=name, client_fingerprints=tuple(sorted(fingerprints)))


def parse_config(document: object) -> ServiceConfig:
    if not isinstance(document, dict):
        raise ConfigurationError("KMIP configuration must be an object.")
    _exact_fields(document, CONFIG_FIELDS, label="KMIP configuration")
    if _integer(document["schema_version"], label="KMIP configuration schema_version") != 1:
        raise ConfigurationError("KMIP configuration schema_version must be 1.")
    if not isinstance(document["enabled"], bool):
        raise ConfigurationError("KMIP enabled must be true or false.")

    listen = document["listen"]
    tls = document["tls"]
    store = document["store"]
    limits = document["limits"]
    if not all(isinstance(item, dict) for item in (listen, tls, store, limits)):
        raise ConfigurationError("KMIP listen, TLS, store, and limits must be objects.")
    _exact_fields(listen, {"host", "port"}, label="KMIP listen")
    _exact_fields(
        tls,
        {"certificate_path", "private_key_path", "ca_path"},
        label="KMIP TLS",
    )
    _exact_fields(store, {"database_path", "kek_path"}, label="KMIP store")
    _exact_fields(
        limits,
        {
            "max_request_bytes",
            "max_connections",
            "idle_timeout_seconds",
            "max_requests_per_connection",
        },
        label="KMIP limits",
    )
    if not isinstance(listen["host"], str):
        raise ConfigurationError("KMIP listen host must be a string.")
    host = listen["host"].strip()
    if not host:
        raise ConfigurationError("KMIP listen host is required.")
    port = _integer(listen["port"], label="KMIP listen port")
    if not 1 <= port <= 65535:
        raise ConfigurationError("KMIP listen port must be between 1 and 65535.")
    parsed_limits = ServiceLimits(
        max_request_bytes=_integer(
            limits["max_request_bytes"],
            label="KMIP max_request_bytes",
        ),
        max_connections=_integer(
            limits["max_connections"],
            label="KMIP max_connections",
        ),
        idle_timeout_seconds=_integer(
            limits["idle_timeout_seconds"],
            label="KMIP idle_timeout_seconds",
        ),
        max_requests_per_connection=_integer(
            limits["max_requests_per_connection"],
            label="KMIP max_requests_per_connection",
        ),
    )
    if not 1024 <= parsed_limits.max_request_bytes <= MAX_MESSAGE_BYTES:
        raise ConfigurationError("KMIP max_request_bytes must be between 1024 and 1048576.")
    if not 1 <= parsed_limits.max_connections <= 256:
        raise ConfigurationError("KMIP max_connections must be between 1 and 256.")
    if not 1 <= parsed_limits.idle_timeout_seconds <= 300:
        raise ConfigurationError("KMIP idle_timeout_seconds must be between 1 and 300.")
    if not 1 <= parsed_limits.max_requests_per_connection <= 1024:
        raise ConfigurationError("KMIP max_requests_per_connection must be between 1 and 1024.")

    provider_values = document["providers"]
    if not isinstance(provider_values, list):
        raise ConfigurationError("KMIP providers must be a list.")
    if document["enabled"] and not provider_values:
        raise ConfigurationError("Enabled KMIP configuration requires at least one provider.")
    providers = tuple(_provider(item) for item in provider_values)
    if len({provider.id for provider in providers}) != len(providers):
        raise ConfigurationError("KMIP provider IDs must be unique.")
    fingerprints = [
        fingerprint
        for provider in providers
        for fingerprint in provider.client_fingerprints
    ]
    if len(fingerprints) != len(set(fingerprints)):
        raise ConfigurationError("A KMIP client fingerprint cannot map to multiple providers.")

    if not isinstance(document["interop_trace_path"], str):
        raise ConfigurationError("KMIP interop trace path must be a string.")
    trace_value = document["interop_trace_path"].strip()
    return ServiceConfig(
        enabled=document["enabled"],
        host=host,
        port=port,
        certificate_path=_path(tls["certificate_path"], label="KMIP server certificate"),
        private_key_path=_path(tls["private_key_path"], label="KMIP server private key"),
        ca_path=_path(tls["ca_path"], label="KMIP CA certificate"),
        database_path=_path(store["database_path"], label="KMIP database"),
        kek_path=_path(store["kek_path"], label="KMIP KEK envelope"),
        limits=parsed_limits,
        providers=providers,
        interop_trace_path=(
            _path(trace_value, label="KMIP interop trace") if trace_value else None
        ),
    )


def load_config(path: Path) -> ServiceConfig:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("KMIP configuration could not be read.") from exc
    return parse_config(document)


def tls_context(config: ServiceConfig) -> ssl.SSLContext:
    for path, label in (
        (config.certificate_path, "KMIP server certificate"),
        (config.private_key_path, "KMIP server private key"),
        (config.ca_path, "KMIP CA certificate"),
    ):
        if not path.is_file():
            raise ConfigurationError(f"{label} does not exist: {path}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(config.certificate_path, config.private_key_path)
    context.load_verify_locations(cafile=config.ca_path)
    return context


class InteropTraceWriter:
    """Append exact-schema, metadata-only events for an explicitly enabled acceptance run."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _operation(item: Ttlv) -> tuple[str, int]:
        node = item.child(Tag.OPERATION, required=False)
        value = node.value if node is not None else 0
        if isinstance(value, bool) or not isinstance(value, int):
            return "Unknown", 0
        try:
            operation = Operation(value)
        except ValueError:
            return "Unknown", value
        return OPERATION_NAMES[operation], value

    @staticmethod
    def _object_type(item: Ttlv) -> str | None:
        stack = [item]
        while stack:
            node = stack.pop()
            if node.tag == Tag.OBJECT_TYPE and node.value == 2:
                return "Symmetric Key"
            if node.type is TtlvType.STRUCTURE:
                stack.extend(node.children())
        return None

    @staticmethod
    def _attribute_names(item: Ttlv) -> list[str]:
        names: set[str] = set()
        stack = [item]
        while stack:
            node = stack.pop()
            if node.tag == Tag.ATTRIBUTE_NAME and isinstance(node.value, str):
                names.add(node.value)
            if node.type is TtlvType.STRUCTURE:
                stack.extend(node.children())
        return sorted(names)

    @classmethod
    def _cryptographic_parameters(
        cls,
        item: Ttlv,
        operation: str,
    ) -> tuple[str | None, int | None, str | None]:
        if operation != "Create":
            return None, None, None
        values: dict[str, object] = {}
        stack = [item]
        while stack:
            node = stack.pop()
            if node.tag == Tag.ATTRIBUTE and node.type is TtlvType.STRUCTURE:
                try:
                    name = node.child(Tag.ATTRIBUTE_NAME)
                    value = node.child(Tag.ATTRIBUTE_VALUE)
                except TtlvError:
                    continue
                if name is not None and isinstance(name.value, str) and value is not None:
                    values[name.value] = value.value
            if node.type is TtlvType.STRUCTURE:
                stack.extend(node.children())
        algorithm = values.get("Cryptographic Algorithm")
        key_length = values.get("Cryptographic Length")
        return (
            "AES" if algorithm == CRYPTOGRAPHIC_ALGORITHM_AES else None,
            key_length if isinstance(key_length, int) and not isinstance(key_length, bool) else None,
            "Raw" if algorithm == CRYPTOGRAPHIC_ALGORITHM_AES else None,
        )

    def record(
        self,
        *,
        connection_id: str,
        client_cert_sha256: str,
        provider_id: str,
        request: Ttlv,
        response: Ttlv,
        request_bytes: bytes,
    ) -> None:
        request_items = request.children(Tag.BATCH_ITEM)
        response_items = response.children(Tag.BATCH_ITEM)
        events: list[str] = []
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        for request_item, response_item in zip(request_items, response_items, strict=True):
            operation_name, _operation_value = self._operation(request_item)
            algorithm, key_length, key_format_type = self._cryptographic_parameters(
                request_item,
                operation_name,
            )
            status_node = response_item.child(Tag.RESULT_STATUS)
            assert status_node is not None and isinstance(status_node.value, int)
            reason_node = response_item.child(Tag.RESULT_REASON, required=False)
            reason = None
            if reason_node is not None and isinstance(reason_node.value, int):
                try:
                    reason = RESULT_REASON_NAMES[ResultReason(reason_node.value)]
                except (KeyError, ValueError):
                    reason = None
            event = {
                "schema_version": 1,
                "timestamp": timestamp,
                "connection_id": connection_id,
                "client_cert_sha256": client_cert_sha256,
                "provider_id": provider_id,
                "protocol_version": "1.4",
                "operation": operation_name,
                "object_type": self._object_type(request_item),
                "algorithm": algorithm,
                "key_length": key_length,
                "key_format_type": key_format_type,
                "attribute_names": self._attribute_names(request_item),
                "result_status": (
                    "Success"
                    if status_node.value == ResultStatus.SUCCESS
                    else "Operation Failed"
                ),
                "result_reason": reason,
                "request_digest": hashlib.sha256(request_bytes).hexdigest(),
            }
            rendered = json.dumps(event, separators=(",", ":"), sort_keys=True)
            try:
                validate_trace([rendered])
            except TraceValidationError:
                continue
            events.append(rendered)
        if not events:
            return
        with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as stream:
            for event in events:
                stream.write(event)
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(self.path, 0o600)


def _receive_exact(sock: ssl.SSLSocket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            if not result:
                return b""
            raise TtlvError("KMIP connection closed during a message.")
        result.extend(chunk)
    return bytes(result)


class KmipRequestHandler(socketserver.BaseRequestHandler):
    server: "KmipTcpServer"
    request: ssl.SSLSocket

    def handle(self) -> None:
        try:
            self.request.do_handshake()
            peer_der = self.request.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError, TimeoutError):
            return
        if not peer_der:
            return
        fingerprint = hashlib.sha256(peer_der).hexdigest()
        provider_id = self.server.config.fingerprint_providers.get(fingerprint)
        if provider_id is None:
            LOGGER.warning("Rejected an unmapped KMIP client certificate.")
            return
        self.request.settimeout(self.server.config.limits.idle_timeout_seconds)
        connection_id = str(uuid.uuid4())
        for _request_number in range(self.server.config.limits.max_requests_per_connection):
            try:
                header = _receive_exact(self.request, 8)
                if not header:
                    return
                if header[:3] != Tag.REQUEST_MESSAGE.to_bytes(3, "big"):
                    raise TtlvError("KMIP root tag must be Request Message.")
                if header[3] != TtlvType.STRUCTURE:
                    raise TtlvError("KMIP Request Message must be a structure.")
                length = int.from_bytes(header[4:8], "big")
                padded_length = length + ((8 - length % 8) % 8)
                total = 8 + padded_length
                if total > self.server.config.limits.max_request_bytes:
                    raise TtlvError("KMIP request exceeds the configured maximum size.")
                body = _receive_exact(self.request, padded_length)
                if len(body) != padded_length:
                    raise TtlvError("KMIP request is truncated.")
                request_bytes = header + body
                request = decode(request_bytes)
                response = self.server.dispatcher.dispatch(provider_id, request)
                response_bytes = encode(response)
                if self.server.trace_writer is not None:
                    self.server.trace_writer.record(
                        connection_id=connection_id,
                        client_cert_sha256=fingerprint,
                        provider_id=provider_id,
                        request=request,
                        response=response,
                        request_bytes=request_bytes,
                    )
                self.request.sendall(response_bytes)
            except (ConnectionError, OSError, TimeoutError, TtlvError):
                return


class KmipTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = False

    def __init__(
        self,
        config: ServiceConfig,
        dispatcher: KmipDispatcher,
        context: ssl.SSLContext,
    ) -> None:
        self.config = config
        self.dispatcher = dispatcher
        self.context = context
        self.trace_writer = (
            InteropTraceWriter(config.interop_trace_path)
            if config.interop_trace_path is not None
            else None
        )
        self._connection_slots = threading.BoundedSemaphore(config.limits.max_connections)
        self.address_family = socket.AF_INET6 if ip_address(config.host).version == 6 else socket.AF_INET
        super().__init__((config.host, config.port), KmipRequestHandler)

    def get_request(self) -> tuple[ssl.SSLSocket, Any]:
        raw_socket, address = super().get_request()
        if not self._connection_slots.acquire(blocking=False):
            raw_socket.close()
            raise ConnectionAbortedError("KMIP connection limit reached.")
        try:
            raw_socket.settimeout(self.config.limits.idle_timeout_seconds)
            wrapped = self.context.wrap_socket(
                raw_socket,
                server_side=True,
                do_handshake_on_connect=False,
            )
            return wrapped, address
        except Exception:
            raw_socket.close()
            self._connection_slots.release()
            raise

    def process_request(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        LOGGER.error("KMIP request failed unexpectedly; connection closed.")

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            self.dispatcher.store.close()


def build_server(config: ServiceConfig, *, secrets_key: str) -> KmipTcpServer:
    context = tls_context(config)
    store = WrappedKeyStore(
        config.database_path,
        config.kek_path,
        secrets_key=secrets_key,
    )
    return KmipTcpServer(config, KmipDispatcher(store), context)


def check_config(config: ServiceConfig, *, secrets_key: str) -> None:
    tls_context(config)
    database_exists = config.database_path.exists()
    kek_exists = config.kek_path.exists()
    if database_exists != kek_exists:
        raise ConfigurationError("KMIP operational store and KEK envelope must exist together.")
    if database_exists:
        store = WrappedKeyStore(
            config.database_path,
            config.kek_path,
            secrets_key=secrets_key,
        )
        store.close()


def _load_secrets_key() -> str:
    credential_path = os.environ.get("ATLASO_SECRETS_KEY_FILE", "").strip()
    if not credential_path:
        return os.environ.get("ATLASO_SECRETS_KEY", "")
    try:
        return Path(credential_path).read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise ConfigurationError("KMIP runtime credential is unavailable.") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="Validate TLS, identity, and store configuration.")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s atlaso-kmip %(message)s",
    )
    try:
        config = load_config(args.config)
        secrets_key = _load_secrets_key()
        if args.check:
            check_config(config, secrets_key=secrets_key)
            print(json.dumps({"atlaso_kmip": "configuration valid"}, sort_keys=True))
            return 0
        if not config.enabled:
            raise ConfigurationError("KMIP service configuration is disabled.")
        server = build_server(config, secrets_key=secrets_key)
    except (ConfigurationError, KeyStoreError, OSError, ssl.SSLError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 2
    try:
        LOGGER.info("Atlaso KMIP service started.")
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
