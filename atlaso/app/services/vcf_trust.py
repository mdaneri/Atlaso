"""Implement vcf trust service behavior."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address
from typing import Any, Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from atlaso.app.models import CaSettings
from atlaso.app.services.vcf_sddc_deployment import tls_sha256_fingerprint


VCF_SUPPORTED_ROLES = {"VcfInstaller", "SddcManager"}


class VcfTrustError(RuntimeError):
    """Report a vcf trust error."""
    pass


@dataclass(frozen=True)
class VcfTrustCredentials:
    """Represent vcf trust credentials.

    Attributes:
        api_username: Api username maintained by this vcftrustcredentials.
        api_password: Api password maintained by this vcftrustcredentials.
    """
    api_username: str
    api_password: str


@dataclass(frozen=True)
class RootCaInfo:
    """Represent root ca info.

    Attributes:
        pem: Pem maintained by this rootcainfo.
        subject: Subject maintained by this rootcainfo.
        expires_at: UTC timestamp after which the resource is no longer valid.
        fingerprint: Fingerprint maintained by this rootcainfo.
    """
    pem: str
    subject: str
    expires_at: str
    fingerprint: str


def colon_fingerprint(raw: bytes) -> str:
    """Return colon fingerprint."""
    return ":".join(f"{value:02X}" for value in raw)


def root_ca_info(settings: CaSettings) -> RootCaInfo:
    """Return root ca info.

    Raises:
        VcfTrustError: If the operation encounters an invalid state.
    """
    if not settings.enabled:
        raise VcfTrustError("The Atlaso certificate authority must be enabled.")
    pem = (settings.root_certificate_pem or "").strip()
    if not pem or pem.count("-----BEGIN CERTIFICATE-----") != 1 or "PRIVATE KEY" in pem:
        raise VcfTrustError("The active Atlaso root CA must contain exactly one public PEM certificate.")
    try:
        certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise VcfTrustError("The active Atlaso root CA is not a valid CA certificate.") from exc
    if not constraints.ca or certificate.issuer != certificate.subject:
        raise VcfTrustError("The active Atlaso certificate is not a self-signed root CA.")
    canonical_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip()
    if pem != canonical_pem:
        raise VcfTrustError("The active Atlaso root CA contains data other than its public PEM certificate.")
    now = datetime.now(timezone.utc)
    if certificate.not_valid_after_utc <= now:
        raise VcfTrustError("The active Atlaso root CA has expired.")
    return RootCaInfo(
        pem=pem + "\n",
        subject=certificate.subject.rfc4514_string(),
        expires_at=certificate.not_valid_after_utc.isoformat(),
        fingerprint=colon_fingerprint(certificate.fingerprint(hashes.SHA256())),
    )


def pem_fingerprint(pem: str) -> str:
    """Return pem fingerprint.

    Raises:
        VcfTrustError: If the operation encounters an invalid state.
    """
    try:
        certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except ValueError as exc:
        raise VcfTrustError("VCF returned an invalid trusted certificate.") from exc
    return colon_fingerprint(certificate.fingerprint(hashes.SHA256()))


class VcfApiClient:
    """Represent vcf api client.

    Attributes:
        base_url: URL used for base.
        username: Username maintained by this vcfapiclient.
        password: Password maintained by this vcfapiclient.
        client: Client maintained by this vcfapiclient.
        token: Token maintained by this vcfapiclient.
    """
    def __init__(
        self,
        address: str,
        username: str,
        password: str,
        *,
        port: int = 443,
        timeout: float = 30.0,
        expected_fingerprint: str = "",
    ):
        """Initialize the vcf api client.

        Args:
            address: Network address of the target service or interface.
            username: Account name used for authentication or lookup.
            password: Password supplied for the immediate authenticated operation.
            port: TCP or UDP port of the target service.
            timeout: Maximum time to wait for completion.
            expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.

        Raises:
            VcfTrustError: If the operation encounters an invalid state.
        """
        normalized = address.strip().strip("[]")
        if expected_fingerprint and tls_sha256_fingerprint(normalized, port).upper() != expected_fingerprint.upper():
            raise VcfTrustError("The VCF appliance TLS certificate changed after confirmation.")
        try:
            parsed_address = ip_address(normalized)
        except ValueError:
            parsed_address = None
        api_host = f"[{normalized}]" if isinstance(parsed_address, IPv6Address) else normalized
        port_suffix = "" if port == 443 else f":{port}"
        self.base_url = f"https://{api_host}{port_suffix}"
        self.username = username
        self.password = password
        # VCF appliances commonly begin with a private/self-signed HTTPS certificate.
        # Operators confirm the endpoint TLS fingerprint before Atlaso calls the API.
        self.client = httpx.Client(base_url=self.base_url, verify=False, timeout=timeout)
        self.token = ""

    def __enter__(self) -> "VcfApiClient":
        """Enter the managed context.

        Returns:
            The enter result.

        Raises:
            VcfTrustError: If the operation encounters an invalid state.
        """
        response = self.client.post("/v1/tokens", json={"username": self.username, "password": self.password})
        self._raise(response, "VCF API authentication failed")
        self.token = str(response.json().get("accessToken") or "")
        if not self.token:
            raise VcfTrustError("VCF API authentication returned no access token.")
        self.client.headers["Authorization"] = f"Bearer {self.token}"
        return self

    def __exit__(self, *_args: object) -> None:
        """Exit the managed context without suppressing exceptions."""
        self.client.close()

    @staticmethod
    def _raise(response: httpx.Response, message: str) -> None:
        """Handle raise.

        Raises:
            VcfTrustError: If the operation encounters an invalid state.
        """
        if response.is_success:
            return
        detail = ""
        try:
            payload = response.json()
            detail = str(payload.get("message") or payload.get("errorCode") or "")
        except (ValueError, AttributeError):
            pass
        suffix = f" ({response.status_code}{': ' + detail if detail else ''})"
        raise VcfTrustError(message + suffix)

    def appliance_info(self) -> dict[str, str]:
        """Return appliance info.

        Raises:
            VcfTrustError: If the operation encounters an invalid state.
        """
        response = self.client.get("/v1/system/appliance-info")
        self._raise(response, "Could not read VCF appliance information")
        payload = response.json()
        role = str(payload.get("role") or "")
        version = str(payload.get("version") or "")
        if role not in VCF_SUPPORTED_ROLES:
            raise VcfTrustError(f"Unsupported VCF appliance role: {role or 'unknown'}.")
        if not version.startswith("9."):
            raise VcfTrustError(f"Unsupported VCF version: {version or 'unknown'}; only VCF 9.x is supported.")
        return {"role": role, "version": version}

    def trusted_certificates(self) -> list[dict[str, Any]]:
        """Return trusted certificates."""
        response = self.client.get("/v1/sddc-manager/trusted-certificates")
        self._raise(response, "Could not read the VCF trusted-certificate store")
        payload = response.json()
        return list(payload.get("elements") or [])

    def add_trusted_certificate(self, pem: str) -> None:
        """Create trusted certificate."""
        response = self.client.post(
            "/v1/sddc-manager/trusted-certificates",
            json={"certificate": pem, "certificateUsageType": "TRUSTED_FOR_OUTBOUND"},
        )
        self._raise(response, "VCF rejected the Atlaso root CA")


def find_trusted_certificate(certificates: list[dict[str, Any]], fingerprint: str) -> dict[str, Any] | None:
    """Return trusted certificate."""
    for item in certificates:
        pem = str(item.get("certificate") or "")
        if not pem:
            continue
        try:
            if pem_fingerprint(pem) == fingerprint:
                return item
        except VcfTrustError:
            continue
    return None


def inspect_vcf_trust_target(
    address: str,
    port: int,
    credentials: VcfTrustCredentials,
    *,
    expected_fingerprint: str = "",
) -> dict[str, Any]:
    """Return inspect vcf trust target.

    Args:
        address: Network address of the target service or interface.
        port: TCP or UDP port of the target service.
        credentials: Credential bundle used for the immediate external request.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.
    """
    with VcfApiClient(
        address,
        credentials.api_username,
        credentials.api_password,
        port=port,
        expected_fingerprint=expected_fingerprint,
    ) as api:
        return api.appliance_info()


def execute_vcf_trust(
    *,
    address: str,
    port: int = 443,
    expected_tls_fingerprint: str = "",
    credentials: VcfTrustCredentials,
    ca: RootCaInfo,
    progress: Callable[[int, str], None] | None = None,
) -> dict[str, Any]:
    """Run vcf trust.

    Args:
        address: Network address of the target service or interface.
        port: TCP or UDP port of the target service.
        expected_tls_fingerprint: Expected tls fingerprint supplied by the caller.
        credentials: Credential bundle used for the immediate external request.
        ca: Ca supplied by the caller.
        progress: Progress supplied by the caller.

    Returns:
        The execute vcf trust result.

    Raises:
        VcfTrustError: If the operation encounters an invalid state.
    """
    update = progress or (lambda _percent, _state: None)
    update(10, "authenticating")
    with VcfApiClient(
        address,
        credentials.api_username,
        credentials.api_password,
        port=port,
        expected_fingerprint=expected_tls_fingerprint,
    ) as api:
        appliance = api.appliance_info()
        update(35, "checking-trust")
        if find_trusted_certificate(api.trusted_certificates(), ca.fingerprint):
            return {**appliance, "outcome": "no-op", "restart": "not-required", "verified": True}
        update(65, "importing")
        api.add_trusted_certificate(ca.pem)
        update(90, "verifying")
        if not find_trusted_certificate(api.trusted_certificates(), ca.fingerprint):
            raise VcfTrustError("VCF did not return the imported Atlaso root CA during verification.")
    return {**appliance, "outcome": "installed", "restart": "not-required", "verified": True}


def sanitized_result(*, address: str, port: int, ca: RootCaInfo, state: str, **values: Any) -> str:
    """Return sanitized result.

    Args:
        address: Network address of the target service or interface.
        port: TCP or UDP port of the target service.
        ca: Ca supplied by the caller.
        state: Lifecycle or job state to persist.
        values: Values to normalize, validate, or persist.
    """
    return json.dumps(
        {
            "target": address,
            "port": port,
            "ca_subject": ca.subject,
            "ca_expires_at": ca.expires_at,
            "ca_fingerprint": ca.fingerprint,
            "state": state,
            **values,
        },
        indent=2,
    )
