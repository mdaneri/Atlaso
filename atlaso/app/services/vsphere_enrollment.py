"""Read a vCenter KMIP client identity without granting it KMIP access."""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from atlaso.app.services.vsphere_key_providers import (
    normalize_vcenter_hostname,
    parse_public_certificate,
)

VSPHERE_API_RELEASE = "9.1.0.0"
_OBJECT_ID = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_CLUSTER_ID = re.compile(r"[^\x00-\x1f\x7f]{1,160}\Z")


class EnrollmentError(ValueError):
    """A bounded, secret-free vCenter enrollment failure."""


MISSING_CLIENT_CERTIFICATE_GUIDANCE = (
    "No active vCenter KMIP client certificate is configured for this cluster. "
    "In vCenter, open Configure > Security > Key Providers and select the existing standard provider. "
    "Use Establish Trust > Make KMS trust vCenter > vCenter Certificate. "
    "Create a client certificate only if one is missing and complete the workflow to activate it; "
    "generation alone is insufficient. Keep the private key in vCenter. "
    "Return to this Atlaso wizard and click Next to retry inspection, review and approve the public "
    "fingerprint, then run global Appliance Apply for KMS. Verify trust in both directions."
)


@dataclass(frozen=True)
class DiscoveredClient:
    """Public certificate and checked vCenter endpoint metadata."""

    certificate_pem: str
    fingerprint_sha256: str
    subject: str
    not_valid_after: str
    cluster_id: str
    vcenter_host: str


@dataclass(frozen=True)
class DiscoveredInventory:
    """Configured instance name (empty if unavailable) and all KMS cluster IDs."""

    name: str
    cluster_ids: tuple[str, ...]


def vcenter_https_endpoint(uri: str) -> tuple[str, int]:
    """Resolve a saved credential-free HTTPS URI to its exact TLS endpoint.

    Args:
        uri: Saved Vault URI selected for enrollment.
    """
    try:
        parsed = urlsplit(uri)
        host = normalize_vcenter_hostname(parsed.hostname or "")
        port = parsed.port if parsed.port is not None else 443
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or not host
            or not 1 <= port <= 65535
        ):
            raise ValueError
    except ValueError as exc:
        raise EnrollmentError("Choose a saved HTTPS URI for this vCenter.") from exc
    return host, port


def vcenter_https_leaf(host: str, *, port: int = 443, timeout: float = 8.0) -> bytes:
    """Probe only the public HTTPS leaf; callers must confirm its fingerprint.

    Args:
        host: Normalized vCenter hostname or address.
        port: Saved HTTPS endpoint port.
        timeout: Maximum seconds allowed for the public certificate probe.
    """
    host = normalize_vcenter_hostname(host)
    if not host:
        raise EnrollmentError("Enter a vCenter hostname or address.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as connection:
                leaf = connection.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        raise EnrollmentError(
            "Could not inspect the vCenter HTTPS certificate."
        ) from exc
    if not leaf:
        raise EnrollmentError("vCenter supplied no HTTPS certificate.")
    return leaf


def certificate_fingerprint(leaf: bytes) -> str:
    """Return an uppercase, colon-separated SHA-256 fingerprint.

    Args:
        leaf: Public DER-encoded HTTPS certificate.
    """
    digest = hashlib.sha256(leaf).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def normalize_https_fingerprint(value: str) -> str:
    """Canonicalize a confirmed SHA-256 value with optional colon separators.

    Args:
        value: Public certificate fingerprint supplied by the caller.

    Raises:
        EnrollmentError: If the value is not exactly one SHA-256 digest.
    """
    digest = value.strip().replace(":", "").upper()
    if re.fullmatch(r"[0-9A-F]{64}", digest) is None:
        raise EnrollmentError("Confirm the current vCenter HTTPS fingerprint before using credentials.")
    return ":".join(digest[index : index + 2] for index in range(0, 64, 2))


def _reference(content: dict, field: str, expected_type: str) -> str:
    """Validate and return a managed-object reference from service metadata.

    Args:
        content: Decoded service metadata.
        field: Metadata field containing the managed-object reference.
        expected_type: Required managed-object type.
    """
    value = content.get(field)
    if not isinstance(value, dict) or value.get("type") != expected_type:
        raise EnrollmentError(
            "vCenter did not expose the required KMIP management API."
        )
    object_id = value.get("value")
    if not isinstance(object_id, str) or not _OBJECT_ID.fullmatch(object_id):
        raise EnrollmentError("vCenter returned an invalid managed-object reference.")
    return object_id


def _json(response: httpx.Response) -> object:
    """Decode a bounded successful vCenter response.

    Args:
        response: Bounded vCenter HTTP response.
    """
    if response.status_code < 200 or response.status_code >= 300:
        raise EnrollmentError("The vCenter KMIP discovery request failed.")
    if len(response.content) > 262_144:
        raise EnrollmentError("The vCenter KMIP discovery response is too large.")
    try:
        return response.json()
    except ValueError as exc:
        raise EnrollmentError("vCenter returned invalid KMIP discovery data.") from exc


def _pinned_context(leaf: bytes) -> ssl.SSLContext:
    """Trust only the inspected public leaf for the discovery session.

    Args:
        leaf: Public DER-encoded HTTPS certificate.
    """
    certificate = x509.load_der_x509_certificate(leaf)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_verify_locations(
        cadata=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    )
    return context


@contextmanager
def _vcenter_session(
    *, host: str, port: int, username: str, password: str,
    confirmed_https_fingerprint: str,
) -> Iterator[tuple[httpx.Client, str, dict]]:
    """Open a bounded authenticated session only after checking the TLS pin.

    Args:
        host: Normalized vCenter endpoint.
        port: HTTPS endpoint port.
        username: Request-local account name.
        password: Request-local password.
        confirmed_https_fingerprint: Independently confirmed public TLS fingerprint.
    """
    leaf = vcenter_https_leaf(host, port=port)
    if certificate_fingerprint(leaf) != normalize_https_fingerprint(confirmed_https_fingerprint):
        raise EnrollmentError("The vCenter HTTPS fingerprint differs from the confirmed value.")
    if not username or not password:
        raise EnrollmentError("Enter a vCenter username and password.")
    base = f"/sdk/vim25/{VSPHERE_API_RELEASE}"
    api_host = f"[{host}]" if ":" in host else host
    try:
        with httpx.Client(
            base_url=f"https://{api_host}:{port}", verify=_pinned_context(leaf),
            follow_redirects=False, trust_env=False, timeout=10.0,
        ) as client:
            content = _json(client.get(f"{base}/ServiceInstance/ServiceInstance/content"))
            if not isinstance(content, dict):
                raise EnrollmentError("vCenter returned invalid service metadata.")
            session_id = _reference(content, "sessionManager", "SessionManager")
            _reference(content, "cryptoManager", "CryptoManagerKmip")
            login = client.post(
                f"{base}/SessionManager/{session_id}/Login",
                json={"userName": username, "password": password},
            )
            if login.status_code != 200:
                raise EnrollmentError("vCenter rejected the supplied credential.")
            token = login.headers.get("vmware-api-session-id", "")
            if not token or len(token) > 1024:
                raise EnrollmentError("vCenter returned no valid API session.")
            client.headers["vmware-api-session-id"] = token
            try:
                yield client, base, content
            finally:
                try:
                    client.post(f"{base}/SessionManager/{session_id}/Logout")
                except httpx.HTTPError:
                    pass
    except httpx.HTTPError as exc:
        raise EnrollmentError("The authenticated vCenter KMIP discovery request failed.") from exc


def _instance_name(client: httpx.Client, base: str, content: dict) -> str:
    """Read only the configured instance name, never a product or host fallback.

    Args:
        client: The pinned authenticated vCenter session.
        base: Versioned VI JSON API path.
        content: Service metadata containing the settings manager reference.
    """
    try:
        setting_id = _reference(content, "setting", "OptionManager")
        options = _json(client.post(
            f"{base}/OptionManager/{setting_id}/QueryOptions",
            json={"name": "VirtualCenter.InstanceName"},
        ))
    except (EnrollmentError, httpx.HTTPError):
        return ""
    if not isinstance(options, list) or len(options) != 1:
        return ""
    option = options[0]
    if not isinstance(option, dict) or option.get("key") != "VirtualCenter.InstanceName":
        return ""
    value = option.get("value")
    # VI JSON serializes OptionValue's xsd:anyType as a typed scalar wrapper.
    if not isinstance(value, dict) or value.get("_typeName") != "string":
        return ""
    name = value.get("_value")
    if (
        not isinstance(name, str) or not name.strip() or len(name) > 120
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        return ""
    return name.strip()


def discover_vcenter_inventory(
    *, host: str, username: str, password: str,
    confirmed_https_fingerprint: str, port: int = 443,
) -> DiscoveredInventory:
    """Read the configured instance name and all KMS clusters without mutation.

    VirtualCenter.InstanceName is read through ServiceContent.setting. Missing
    names remain empty for operator entry. Neither AboutInfo's product label,
    instance UUID nor the connection hostname substitutes for this setting.
    No management-type or status filters omit clusters.

    Args:
        host: vCenter hostname or address.
        username: Request-local account name.
        password: Password held only for the pinned session.
        confirmed_https_fingerprint: Independently confirmed public TLS fingerprint.
        port: Saved vCenter HTTPS port.
    """
    host = normalize_vcenter_hostname(host)
    if not host:
        raise EnrollmentError("Enter a vCenter hostname or address.")
    with _vcenter_session(
        host=host, port=port, username=username, password=password,
        confirmed_https_fingerprint=confirmed_https_fingerprint,
    ) as (client, base, content):
        manager_id = _reference(content, "cryptoManager", "CryptoManagerKmip")
        name = _instance_name(client, base, content)
        clusters = _json(client.post(
            f"{base}/CryptoManagerKmip/{manager_id}/ListKmsClusters",
            json={"includeKmsServers": False},
        ))
        if not isinstance(clusters, list):
            raise EnrollmentError("vCenter returned invalid KMIP cluster data.")
        ids = []
        for item in clusters:
            cluster = item.get("clusterId") if isinstance(item, dict) else None
            cluster_id = cluster.get("id") if isinstance(cluster, dict) else None
            if (
                not isinstance(cluster_id, str)
                or not cluster_id.strip()
                or cluster_id != cluster_id.strip()
                or not _CLUSTER_ID.fullmatch(cluster_id)
                or cluster_id in ids
            ):
                raise EnrollmentError("vCenter returned invalid or ambiguous KMIP cluster IDs.")
            ids.append(cluster_id)
        return DiscoveredInventory(name=name.strip(), cluster_ids=tuple(ids))


def _check_cluster_endpoint(
    servers: object, host: str, port: int, *, listener_addresses: frozenset[str] = frozenset(),
) -> None:
    """Require every member to match without reflecting remote response values.

    Args:
        servers: Untrusted server inventory from the selected vCenter cluster.
        host: Normalized configured Atlaso KMIP hostname.
        port: Configured Atlaso KMIP port, not an observed runtime assertion.
        listener_addresses: Independently admitted applied and observed listener IPs.
    """
    expected = f"Expected configured Atlaso endpoint: {host}, port {port}. "
    repair = (
        "Compare every member in vCenter with the hostname and port in Atlaso's "
        "vSphere Key Providers listener settings, or select the intended cluster, "
        "then retry. IP addresses require successful KMIP Apply, recorded listener ownership, "
        "and fresh native observation on that applied interface. Missing or stale evidence "
        "does not admit an IP; use the configured hostname or verify and apply the listener settings. "
        "A matching KMS server name or DNS resolution does not prove the address. "
        "Do not remove servers or replace an in-use provider to bypass this check."
    )
    # The remote endpoint has already received credentials. Keep every rejection
    # identical: even counts, positions and field comparisons can carry its data.
    if (
        not isinstance(servers, list)
        or not servers
        or any(
            not isinstance(server, dict)
            or not isinstance(server.get("address"), str)
            or not _matches_cluster_address(server["address"], host, listener_addresses)
            or type(server.get("port")) is not int
            or server["port"] != port
            for server in servers
        )
    ):
        raise EnrollmentError(
            "The vCenter KMIP cluster does not point only to this Atlaso endpoint. "
            + expected + repair
        )


def _matches_cluster_address(address: str, host: str, listener_addresses: frozenset[str]) -> bool:
    """Compare the transport address; the remote server name is only a label.

    Args:
        address: Untrusted remote KMIP transport address.
        host: Normalized configured Atlaso hostname.
        listener_addresses: Independently proven listener IPs in canonical form.
    """
    try:
        return str(ip_address(address.strip())) in listener_addresses
    except ValueError:
        return address.strip().casefold().rstrip(".") == host


def discover_vcenter_client(
    *,
    host: str,
    cluster_id: str,
    username: str,
    password: str,
    confirmed_https_fingerprint: str,
    atlaso_host: str,
    atlaso_port: int,
    listener_addresses: frozenset[str] = frozenset(),
    port: int = 443,
) -> DiscoveredClient:
    """Read one registered cluster's client cert over a pinned vCenter session.

    The returned certificate remains untrusted until an administrator approves
    its exact fingerprint for one Atlaso provider and applies desired state.

    Args:
        host: Normalized vCenter hostname or address.
        cluster_id: Registered Atlaso KMIP cluster identifier.
        username: Request-local account name used for discovery.
        password: Password held in memory for the pinned session.
        confirmed_https_fingerprint: Out-of-band confirmed HTTPS certificate fingerprint.
        atlaso_host: Expected Atlaso KMIP endpoint hostname.
        atlaso_port: Expected Atlaso KMIP listener port.
        listener_addresses: Applied listener IPs with independently verified current ownership.
        port: Saved vCenter HTTPS endpoint port.
    """
    host = normalize_vcenter_hostname(host)
    atlaso_host = normalize_vcenter_hostname(atlaso_host)
    cluster_id = cluster_id.strip()
    if not host or not atlaso_host or not _CLUSTER_ID.fullmatch(cluster_id):
        raise EnrollmentError(
            "Enter a valid vCenter, Atlaso endpoint, and KMIP cluster ID."
        )
    with _vcenter_session(
        host=host, port=port, username=username, password=password,
        confirmed_https_fingerprint=confirmed_https_fingerprint,
    ) as (client, base, content):
        manager_id = _reference(content, "cryptoManager", "CryptoManagerKmip")
        clusters = _json(
            client.post(
                f"{base}/CryptoManagerKmip/{manager_id}/ListKmsClusters",
                json={"includeKmsServers": True},
            )
        )
        if not isinstance(clusters, list):
            raise EnrollmentError("vCenter returned invalid KMIP cluster data.")
        matches = [
            item
            for item in clusters
            if isinstance(item, dict)
            and isinstance(item.get("clusterId"), dict)
            and item["clusterId"].get("id") == cluster_id
        ]
        if len(matches) != 1:
            raise EnrollmentError(
                "The named KMIP cluster is missing or ambiguous in vCenter."
            )
        _check_cluster_endpoint(
            matches[0].get("servers"), atlaso_host, atlaso_port,
            listener_addresses=listener_addresses,
        )
        certificate = _json(
            client.post(
                f"{base}/CryptoManagerKmip/{manager_id}/RetrieveClientCert",
                json={
                    "cluster": {"_typeName": "KeyProviderId", "id": cluster_id}
                },
            )
        )
    if not isinstance(certificate, str):
        raise EnrollmentError("vCenter returned no public KMIP client certificate.")
    if not certificate.strip():
        raise EnrollmentError(MISSING_CLIENT_CERTIFICATE_GUIDANCE)
    try:
        parsed = parse_public_certificate(certificate)
    except ValueError as exc:
        raise EnrollmentError(
            "vCenter returned an unusable public KMIP client certificate."
        ) from exc
    return DiscoveredClient(
        certificate_pem=str(parsed["certificate_pem"]),
        fingerprint_sha256=str(parsed["fingerprint_sha256"]),
        subject=str(parsed["subject"]),
        not_valid_after=str(parsed["not_valid_after"]),
        cluster_id=cluster_id,
        vcenter_host=host,
    )
