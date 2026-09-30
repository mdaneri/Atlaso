"""Read a vCenter KMIP client identity without granting it KMIP access."""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
from dataclasses import dataclass

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from atlaso.app.services.vsphere_key_providers import (
    normalize_vcenter_hostname,
    parse_public_certificate,
)

VSPHERE_API_RELEASE = "9.1.0.0"
_OBJECT_ID = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_CLUSTER_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")


class EnrollmentError(ValueError):
    """A bounded, secret-free vCenter enrollment failure."""


@dataclass(frozen=True)
class DiscoveredClient:
    """Public certificate and checked vCenter endpoint metadata."""

    certificate_pem: str
    fingerprint_sha256: str
    subject: str
    not_valid_after: str
    cluster_id: str
    vcenter_host: str


def vcenter_https_leaf(host: str, *, timeout: float = 8.0) -> bytes:
    """Probe only the public HTTPS leaf; callers must confirm its fingerprint.

    Args:
        host: Normalized vCenter hostname or address.
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
        with socket.create_connection((host, 443), timeout=timeout) as raw:
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


def discover_vcenter_client(
    *,
    host: str,
    cluster_id: str,
    username: str,
    password: str,
    confirmed_https_fingerprint: str,
    atlaso_host: str,
    atlaso_port: int,
) -> DiscoveredClient:
    """Read one registered cluster's client cert over a pinned vCenter session.

    The returned certificate remains untrusted until an administrator approves
    its exact fingerprint for one Atlaso provider and applies desired state.

    Args:
        host: Normalized vCenter hostname or address.
        cluster_id: Registered Atlaso KMIP cluster identifier.
        username: Vault account name used for discovery.
        password: Password held in memory for the pinned session.
        confirmed_https_fingerprint: Out-of-band confirmed HTTPS certificate fingerprint.
        atlaso_host: Expected Atlaso KMIP endpoint hostname.
        atlaso_port: Expected Atlaso KMIP listener port.
    """
    host = normalize_vcenter_hostname(host)
    atlaso_host = normalize_vcenter_hostname(atlaso_host)
    cluster_id = cluster_id.strip()
    if not host or not atlaso_host or not _CLUSTER_ID.fullmatch(cluster_id):
        raise EnrollmentError(
            "Enter a valid vCenter, Atlaso endpoint, and KMIP cluster ID."
        )
    leaf = vcenter_https_leaf(host)
    observed = certificate_fingerprint(leaf)
    if observed != confirmed_https_fingerprint.strip().upper():
        raise EnrollmentError(
            "The vCenter HTTPS fingerprint differs from the confirmed value."
        )
    if not username or not password:
        raise EnrollmentError("The selected Vault entry needs a username and password.")
    base = f"/sdk/vim25/{VSPHERE_API_RELEASE}"
    api_host = f"[{host}]" if ":" in host else host
    try:
        with httpx.Client(
            base_url=f"https://{api_host}",
            verify=_pinned_context(leaf),
            follow_redirects=False,
            trust_env=False,
            timeout=10.0,
        ) as client:
            content = _json(
                client.get(f"{base}/ServiceInstance/ServiceInstance/content")
            )
            if not isinstance(content, dict):
                raise EnrollmentError("vCenter returned invalid service metadata.")
            session_id = _reference(content, "sessionManager", "SessionManager")
            manager_id = _reference(content, "cryptoManager", "CryptoManagerKmip")
            login = client.post(
                f"{base}/SessionManager/{session_id}/Login",
                json={"userName": username, "password": password},
            )
            if login.status_code != 200:
                raise EnrollmentError("vCenter rejected the selected Vault credential.")
            token = login.headers.get("vmware-api-session-id", "")
            if not token or len(token) > 1024:
                raise EnrollmentError("vCenter returned no valid API session.")
            client.headers["vmware-api-session-id"] = token
            try:
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
                servers = matches[0].get("servers")
                if (
                    not isinstance(servers, list)
                    or not servers
                    or any(
                        not isinstance(server, dict)
                        or str(server.get("address", "")).strip().casefold().rstrip(".")
                        != atlaso_host
                        or server.get("port") != atlaso_port
                        for server in servers
                    )
                ):
                    raise EnrollmentError(
                        "The vCenter KMIP cluster does not point only to this Atlaso endpoint."
                    )
                certificate = _json(
                    client.post(
                        f"{base}/CryptoManagerKmip/{manager_id}/RetrieveClientCert",
                        json={
                            "cluster": {"_typeName": "KeyProviderId", "id": cluster_id}
                        },
                    )
                )
            finally:
                try:
                    client.post(f"{base}/SessionManager/{session_id}/Logout")
                except httpx.HTTPError:
                    pass
    except httpx.HTTPError as exc:
        raise EnrollmentError(
            "The authenticated vCenter KMIP discovery request failed."
        ) from exc
    if not isinstance(certificate, str):
        raise EnrollmentError("vCenter returned no public KMIP client certificate.")
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
