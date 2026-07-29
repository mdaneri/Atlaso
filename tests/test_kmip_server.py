from __future__ import annotations

import hashlib
import json
import socket
import ssl
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from atlaso.app.kmip.protocol import (
    CRYPTOGRAPHIC_ALGORITHM_AES,
    OBJECT_TYPE_SYMMETRIC_KEY,
    KmipDispatcher,
    Operation,
    ResultStatus,
    Tag,
)
from atlaso.app.kmip.server import (
    ConfigurationError,
    InteropTraceWriter,
    Provider,
    ServiceConfig,
    ServiceLimits,
    build_server,
    certificate_sha256,
    parse_config,
)
from atlaso.app.kmip.store import WrappedKeyStore
from atlaso.app.kmip.ttlv import decode, encode, enumeration, integer, structure, text_string
from atlaso.app.kmip.trace import validate_trace


def certificate(
    tmp_path: Path,
    name: str,
    *,
    issuer_key: rsa.RSAPrivateKey | None = None,
    issuer_certificate: x509.Certificate | None = None,
    client: bool = False,
) -> tuple[Path, Path, rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer_key = issuer_key or key
    issuer = issuer_certificate.subject if issuer_certificate else subject
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
    )
    if issuer_certificate is None:
        builder = (
            builder.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
        )
    else:
        usage = ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        builder = (
            builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=not client,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                critical=False,
            )
        )
        if not client:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
    cert = builder.sign(issuer_key, hashes.SHA256())
    cert_path = tmp_path / f"{name}.crt"
    key_path = tmp_path / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, key, cert


def material(tmp_path: Path) -> dict[str, Path]:
    ca_cert, _ca_key_path, ca_key, ca = certificate(tmp_path, "ca")
    server_cert, server_key, _server_private, _server = certificate(
        tmp_path,
        "server",
        issuer_key=ca_key,
        issuer_certificate=ca,
    )
    client_cert, client_key, _client_private, _client = certificate(
        tmp_path,
        "client",
        issuer_key=ca_key,
        issuer_certificate=ca,
        client=True,
    )
    untrusted_cert, untrusted_key, _untrusted_private, _untrusted = certificate(
        tmp_path,
        "untrusted",
        issuer_key=ca_key,
        issuer_certificate=ca,
        client=True,
    )
    return {
        "ca_cert": ca_cert,
        "server_cert": server_cert,
        "server_key": server_key,
        "client_cert": client_cert,
        "client_key": client_key,
        "untrusted_cert": untrusted_cert,
        "untrusted_key": untrusted_key,
    }


def service_config(tmp_path: Path, materials: dict[str, Path]) -> ServiceConfig:
    provider_id = str(uuid.uuid4())
    return ServiceConfig(
        enabled=True,
        host="127.0.0.1",
        port=0,
        certificate_path=materials["server_cert"],
        private_key_path=materials["server_key"],
        ca_path=materials["ca_cert"],
        database_path=tmp_path / "store.db",
        kek_path=tmp_path / "kek.json",
        limits=ServiceLimits(
            max_request_bytes=1_048_576,
            max_connections=4,
            idle_timeout_seconds=2,
            max_requests_per_connection=4,
        ),
        providers=(
            Provider(
                id=provider_id,
                name="VCF 9.1",
                client_fingerprints=(certificate_sha256(materials["client_cert"]),),
            ),
        ),
        interop_trace_path=tmp_path / "trace.jsonl",
    )


def discover_versions_request() -> bytes:
    return encode(
        structure(
            Tag.REQUEST_MESSAGE,
            structure(
                Tag.REQUEST_HEADER,
                structure(
                    Tag.PROTOCOL_VERSION,
                    integer(Tag.PROTOCOL_VERSION_MAJOR, 1),
                    integer(Tag.PROTOCOL_VERSION_MINOR, 4),
                ),
                integer(Tag.BATCH_COUNT, 1),
            ),
            structure(
                Tag.BATCH_ITEM,
                enumeration(Tag.OPERATION, Operation.DISCOVER_VERSIONS),
                structure(
                    Tag.REQUEST_PAYLOAD,
                    structure(
                        Tag.PROTOCOL_VERSION,
                        integer(Tag.PROTOCOL_VERSION_MAJOR, 1),
                        integer(Tag.PROTOCOL_VERSION_MINOR, 4),
                    ),
                ),
            ),
        )
    )


def create_request() -> bytes:
    return encode(
        structure(
            Tag.REQUEST_MESSAGE,
            structure(
                Tag.REQUEST_HEADER,
                structure(
                    Tag.PROTOCOL_VERSION,
                    integer(Tag.PROTOCOL_VERSION_MAJOR, 1),
                    integer(Tag.PROTOCOL_VERSION_MINOR, 4),
                ),
                integer(Tag.BATCH_COUNT, 1),
            ),
            structure(
                Tag.BATCH_ITEM,
                enumeration(Tag.OPERATION, Operation.CREATE),
                structure(
                    Tag.REQUEST_PAYLOAD,
                    enumeration(Tag.OBJECT_TYPE, OBJECT_TYPE_SYMMETRIC_KEY),
                    structure(
                        Tag.TEMPLATE_ATTRIBUTE,
                        structure(
                            Tag.ATTRIBUTE,
                            text_string(Tag.ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                            enumeration(
                                Tag.ATTRIBUTE_VALUE,
                                CRYPTOGRAPHIC_ALGORITHM_AES,
                            ),
                        ),
                        structure(
                            Tag.ATTRIBUTE,
                            text_string(Tag.ATTRIBUTE_NAME, "Cryptographic Length"),
                            integer(Tag.ATTRIBUTE_VALUE, 256),
                        ),
                    ),
                ),
            ),
        )
    )


def client_context(materials: dict[str, Path], *, trusted: bool) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=materials["ca_cert"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    prefix = "client" if trusted else "untrusted"
    context.load_cert_chain(materials[f"{prefix}_cert"], materials[f"{prefix}_key"])
    return context


def test_mtls_server_accepts_mapped_fingerprint_and_writes_redacted_trace(tmp_path: Path) -> None:
    materials = material(tmp_path)
    server = build_server(service_config(tmp_path, materials), secrets_key="appliance-secrets-key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        with socket.create_connection((host, port), timeout=3) as raw:
            with client_context(materials, trusted=True).wrap_socket(
                raw,
                server_hostname="localhost",
            ) as secured:
                secured.sendall(discover_versions_request())
                response_bytes = secured.recv(4096)
        response = decode(response_bytes)
        status = response.children(Tag.BATCH_ITEM)[0].child(Tag.RESULT_STATUS)

        assert status is not None
        assert status.value == ResultStatus.SUCCESS
        trace_lines = (tmp_path / "trace.jsonl").read_text(encoding="utf-8").splitlines()
        assert validate_trace(trace_lines).event_count == 1
        trace = json.loads(trace_lines[0])
        assert trace["operation"] == "Discover Versions"
        assert trace["provider_id"] == server.config.providers[0].id
        assert "payload" not in trace
        assert "key_material" not in trace
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_mtls_server_rejects_ca_valid_but_unmapped_client(tmp_path: Path) -> None:
    materials = material(tmp_path)
    server = build_server(service_config(tmp_path, materials), secrets_key="appliance-secrets-key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        with socket.create_connection((host, port), timeout=3) as raw:
            with client_context(materials, trusted=False).wrap_socket(
                raw,
                server_hostname="localhost",
            ) as secured:
                secured.sendall(discover_versions_request())
                assert secured.recv(4096) == b""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_stalled_tls_handshake_does_not_block_other_connections(tmp_path: Path) -> None:
    materials = material(tmp_path)
    server = build_server(service_config(tmp_path, materials), secrets_key="appliance-secrets-key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    stalled = socket.create_connection((host, port), timeout=3)
    try:
        with socket.create_connection((host, port), timeout=3) as raw:
            with client_context(materials, trusted=True).wrap_socket(
                raw,
                server_hostname="localhost",
            ) as secured:
                secured.sendall(discover_versions_request())
                response = decode(secured.recv(4096))

        status = response.children(Tag.BATCH_ITEM)[0].child(Tag.RESULT_STATUS)
        assert status is not None
        assert status.value == ResultStatus.SUCCESS
    finally:
        stalled.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_server_close_waits_for_request_threads_before_zeroing_kek(tmp_path: Path) -> None:
    materials = material(tmp_path)
    server = build_server(service_config(tmp_path, materials), secrets_key="appliance-secrets-key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    raw = socket.create_connection((host, port), timeout=3)
    secured = client_context(materials, trusted=True).wrap_socket(
        raw,
        server_hostname="localhost",
    )
    server.shutdown()
    thread.join(timeout=3)
    close_thread = threading.Thread(target=server.server_close)
    close_thread.start()
    try:
        time.sleep(0.05)
        assert close_thread.is_alive()
        assert len(server.dispatcher.store._kek) == 32
    finally:
        secured.close()
        close_thread.join(timeout=3)

    assert not close_thread.is_alive()
    assert len(server.dispatcher.store._kek) == 0


def test_configuration_rejects_ambiguous_client_provider_mapping(tmp_path: Path) -> None:
    materials = material(tmp_path)
    fingerprint = certificate_sha256(materials["client_cert"])
    document = {
        "schema_version": 1,
        "enabled": True,
        "listen": {"host": "127.0.0.1", "port": 5696},
        "tls": {
            "certificate_path": str(materials["server_cert"]),
            "private_key_path": str(materials["server_key"]),
            "ca_path": str(materials["ca_cert"]),
        },
        "store": {
            "database_path": str(tmp_path / "store.db"),
            "kek_path": str(tmp_path / "kek.json"),
        },
        "limits": {
            "max_request_bytes": 1_048_576,
            "max_connections": 32,
            "idle_timeout_seconds": 30,
            "max_requests_per_connection": 128,
        },
        "providers": [
            {
                "id": str(uuid.uuid4()),
                "name": "one",
                "client_fingerprints": [fingerprint],
                "client_certificate_paths": [],
            },
            {
                "id": str(uuid.uuid4()),
                "name": "two",
                "client_fingerprints": [fingerprint],
                "client_certificate_paths": [],
            },
        ],
        "interop_trace_path": "",
    }

    with pytest.raises(ConfigurationError, match="cannot map to multiple providers"):
        parse_config(document)


def test_certificate_fingerprint_is_der_sha256(tmp_path: Path) -> None:
    materials = material(tmp_path)
    certificate_value = x509.load_pem_x509_certificate(materials["client_cert"].read_bytes())

    assert certificate_sha256(materials["client_cert"]) == hashlib.sha256(
        certificate_value.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def test_disabled_configuration_accepts_no_provider(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "enabled": False,
        "listen": {"host": "127.0.0.1", "port": 5696},
        "tls": {
            "certificate_path": str(tmp_path / "server.crt"),
            "private_key_path": str(tmp_path / "server.key"),
            "ca_path": str(tmp_path / "ca.crt"),
        },
        "store": {
            "database_path": str(tmp_path / "store.db"),
            "kek_path": str(tmp_path / "kek.json"),
        },
        "limits": {
            "max_request_bytes": 1_048_576,
            "max_connections": 32,
            "idle_timeout_seconds": 30,
            "max_requests_per_connection": 128,
        },
        "providers": [],
        "interop_trace_path": "",
    }

    assert parse_config(document).providers == ()


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("schema_version",), True, "schema_version must be an integer"),
        (("listen", "host"), 127, "listen host must be a string"),
        (("listen", "port"), "5696", "listen port must be an integer"),
        (("limits", "max_connections"), 32.0, "max_connections must be an integer"),
        (("interop_trace_path",), None, "interop trace path must be a string"),
        (("providers", 0, "name"), 1, "provider name must be a string"),
        (
            ("providers", 0, "client_fingerprints", 0),
            1,
            "client fingerprint must be a string",
        ),
    ],
)
def test_configuration_rejects_coerced_json_types(
    tmp_path: Path,
    path: tuple[str | int, ...],
    value: object,
    message: str,
) -> None:
    materials = material(tmp_path)
    document: dict[str, object] = {
        "schema_version": 1,
        "enabled": True,
        "listen": {"host": "127.0.0.1", "port": 5696},
        "tls": {
            "certificate_path": str(materials["server_cert"]),
            "private_key_path": str(materials["server_key"]),
            "ca_path": str(materials["ca_cert"]),
        },
        "store": {
            "database_path": str(tmp_path / "store.db"),
            "kek_path": str(tmp_path / "kek.json"),
        },
        "limits": {
            "max_request_bytes": 1_048_576,
            "max_connections": 32,
            "idle_timeout_seconds": 30,
            "max_requests_per_connection": 128,
        },
        "providers": [
            {
                "id": str(uuid.uuid4()),
                "name": "VCF 9.1",
                "client_fingerprints": ["ab" * 32],
                "client_certificate_paths": [],
            }
        ],
        "interop_trace_path": "",
    }
    target: object = document
    for segment in path[:-1]:
        target = target[segment]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(ConfigurationError, match=message):
        parse_config(document)


def test_trace_records_create_parameters_from_request(tmp_path: Path) -> None:
    provider_id = str(uuid.uuid4())
    store = WrappedKeyStore(
        tmp_path / "store.db",
        tmp_path / "kek.json",
        secrets_key="appliance-secrets-key",
    )
    dispatcher = KmipDispatcher(store)
    request_bytes = create_request()
    request = decode(request_bytes)
    response = dispatcher.dispatch(provider_id, request)
    trace_path = tmp_path / "trace.jsonl"

    InteropTraceWriter(trace_path).record(
        connection_id=str(uuid.uuid4()),
        client_cert_sha256="ab" * 32,
        provider_id=provider_id,
        request=request,
        response=response,
        request_bytes=request_bytes,
    )

    event = json.loads(trace_path.read_text(encoding="utf-8"))
    assert event["algorithm"] == "AES"
    assert event["key_length"] == 256
    assert event["key_format_type"] == "Raw"
    assert validate_trace([json.dumps(event)]).event_count == 1
