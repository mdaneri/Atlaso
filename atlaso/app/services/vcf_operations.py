"""Bounded VCF Operations 9.1.1.0 certificate-management client.

The SDK is used as read-only contract evidence. Requests go through the shared
fingerprint-pinned HTTPS transport so generated SDK networking cannot bypass
Atlaso's endpoint identity check or response limits.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlencode

from cryptography import x509

from .vcf_certificate_remote import Credentials, PinnedHTTPS, RemoteError, Target

_BASE = "/suite-api/api"
_PAGE_SIZE = 100
_MAX_PAGES = 50
_MAX_RECORDS = _PAGE_SIZE * _MAX_PAGES
_MAX_CSR_SIZE = 64 * 1024
_MAX_CHAIN_SIZE = 900_000
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_SAFE_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)
_CERTIFICATE_FIELDS = frozenset(
    {
        "appliance",
        "applianceFqdn",
        "autoRenewInfo",
        "autoRenewState",
        "category",
        "categoryDisplayName",
        "certificateMetadata",
        "certificateResourceKey",
        "daysToExpire",
        "displayApplianceType",
        "displayAutoRenewState",
        "displayStatus",
        "domainId",
        "expiryDate",
        "issuedBy",
        "issuedTo",
        "issuedToCommonName",
        "redirectAvailable",
        "status",
        "subjectAlternativeNames",
        "type",
    }
)
_CSR_FIELDS = frozenset(
    {
        "applianceHostname",
        "applianceType",
        "certificateId",
        "certificateType",
        "commonName",
        "csr",
        "id",
        "publicKey",
    }
)
_CSR_SPEC_FIELDS = frozenset(
    {
        "commonName",
        "country",
        "email",
        "keyAlgorithm",
        "keySize",
        "locality",
        "orgUnit",
        "organization",
        "state",
        "subjectAltNames",
    }
)
_WORKFLOW_STATES = {
    "COMPLETED": "COMPLETED",
    "FAILED": "FAILED",
    "CANCELLED": "FAILED",
    "CANCELED": "FAILED",
    "CREATED": "IN_PROGRESS",
    "QUEUED": "IN_PROGRESS",
    "PENDING": "IN_PROGRESS",
    "SUBMITTED": "IN_PROGRESS",
    "IN_PROGRESS": "IN_PROGRESS",
    "RUNNING": "IN_PROGRESS",
}


def _safe_identifier(value: Any, label: str) -> str:
    """Validate a bounded native resource identifier.

    Args:
        value: Candidate value to validate or serialize.
        label: Public field label used in sanitized validation errors.
    """
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise RemoteError(f"VCF Operations returned an invalid {label}")
    return value


def _safe_host(value: Any, label: str) -> str:
    """Validate and normalize a public appliance hostname.

    Args:
        value: Candidate value to validate or serialize.
        label: Public field label used in sanitized validation errors.
    """
    if not isinstance(value, str) or not _SAFE_HOST.fullmatch(value):
        raise RemoteError(f"VCF Operations returned an invalid {label}")
    return value.rstrip(".").lower()


def _page_info(payload: dict[str, Any], page: int) -> tuple[int, int]:
    """Validate exact pagination metadata before collecting another page.

    Args:
        payload: Decoded public response or synthetic response under validation.
        page: Requested zero-based inventory page.
    """
    info = payload.get("pageInfo")
    if not isinstance(info, dict):
        raise RemoteError("VCF Operations returned incomplete pagination data")
    current, page_size, total = (
        info.get("page"),
        info.get("pageSize"),
        info.get("totalCount"),
    )
    if (
        type(current) is not int
        or current != page
        or type(page_size) is not int
        or not 1 <= page_size <= _PAGE_SIZE
        or type(total) is not int
        or not 0 <= total <= _MAX_RECORDS
    ):
        raise RemoteError("VCF Operations returned inconsistent pagination data")
    return page_size, total


def _validate_chain(chain: str) -> str:
    """Reject malformed, oversized or private certificate material.

    Args:
        chain: Public PEM certificate chain to validate before submission.
    """
    if not isinstance(chain, str) or not chain or len(chain.encode("utf-8")) > _MAX_CHAIN_SIZE:
        raise RemoteError("Replacement chain is empty or exceeds the request limit")
    if "PRIVATE KEY" in chain or not re.fullmatch(
        r"\s*(?:-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+",
        chain,
    ):
        raise RemoteError("Replacement chain must contain public PEM certificates only")
    try:
        certificates = x509.load_pem_x509_certificates(chain.encode("ascii"))
    except (UnicodeEncodeError, ValueError):
        raise RemoteError("Replacement chain contains invalid PEM certificates") from None
    if not 1 <= len(certificates) <= 16:
        raise RemoteError("Replacement chain has an unsupported certificate count")
    return chain


class OperationsClient:
    """Use the pinned Operations endpoint and the locked 9.1.1.0 API contract."""

    def __init__(self, target: Target):
        """Bind a request-local client to the confirmed endpoint.

        Args:
            target: Operator-confirmed HTTPS endpoint and expected TLS identity.
        """
        self.target = target
        self.transport = PinnedHTTPS(target)
        self._token: str | None = None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(target={self.target!r}, authenticated={self._token is not None})"

    def __enter__(self) -> OperationsClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        """Release the short-lived token when leaving the client context.

        Args:
            exc_type: Exception type raised inside the client context, if any.
            exc: Exception raised inside the client context, if any.
            traceback: Context exception traceback, if any.
        """
        try:
            self.logout()
        except RemoteError:
            if exc_type is None:
                raise

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        expected_status: int = 200,
        token: str | None = None,
    ) -> Any:
        """Send a bounded pinned request and require its exact success status.

        Args:
            method: HTTP method for the documented Operations resource.
            path: Relative documented Operations API path.
            body: Request-local JSON payload; credentials are never persisted.
            expected_status: Exact HTTP success status required by this contract.
            token: Optional request-local authentication override.
        """
        auth_token = self._token if token is None else token
        if auth_token is None and path != f"{_BASE}/auth/token/acquire":
            raise RemoteError("Authenticate before requesting VCF Operations data")
        header = ("Authorization", f"OpsToken {auth_token}") if auth_token else None
        status, result = self.transport.request(
            method, path, body=body, session_header=header
        )
        if status != expected_status:
            raise RemoteError("VCF Operations returned an unexpected operation status")
        return result

    def login(self, credentials: Credentials) -> None:
        """Acquire a request-local OpsToken through the pinned HTTPS transport.

        Args:
            credentials: Request-local login credentials, excluded from retained state.
        """
        if not isinstance(credentials, Credentials):
            raise TypeError("VCF Operations credentials must use Credentials")
        self._token = None
        payload = self._request(
            "POST",
            f"{_BASE}/auth/token/acquire",
            body={"username": credentials.username, "password": credentials.password},
            expected_status=200,
        )
        token = payload.get("token") if isinstance(payload, dict) else None
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= 4096
            or any(character in token for character in "\r\n")
        ):
            raise RemoteError("VCF Operations authentication returned an invalid token")
        self._token = token

    def logout(self) -> None:
        """Revoke and forget the request-local OpsToken, when one was acquired."""
        token, self._token = self._token, None
        if token is not None:
            self._request(
                "POST",
                f"{_BASE}/auth/token/release",
                expected_status=200,
                token=token,
            )

    def version(self) -> dict[str, Any]:
        """Require the exact VCF Operations 9.1.1.0 contract family."""
        payload = self._request("GET", f"{_BASE}/versions/current")
        if not isinstance(payload, dict):
            raise RemoteError("VCF Operations returned an invalid version response")
        version = tuple(payload.get(field) for field in ("major", "minor", "minorMinor", "patch"))
        if any(type(value) is not int for value in version) or version != (9, 1, 1, 0):
            raise RemoteError("Only the VCF Operations 9.1.1.0 API contract is supported")
        release_name = payload.get("releaseName")
        if release_name is not None and (not isinstance(release_name, str) or not release_name.strip() or len(release_name) > 128):
            raise RemoteError("VCF Operations version identity is ambiguous")
        result = {key: payload[key] for key in ("major", "minor", "minorMinor", "patch")}
        if isinstance(release_name, str):
            result["releaseName"] = release_name
        build = payload.get("buildNumber")
        if build is not None:
            if type(build) is not int or build <= 0:
                raise RemoteError("VCF Operations returned an invalid build identifier")
            result["buildNumber"] = build
        return result

    def inventory(self) -> list[dict[str, Any]]:
        """Return the complete bounded VCF certificate inventory as public fields."""
        rows: list[dict[str, Any]] = []
        page = 0
        expected_total: int | None = None
        while page < _MAX_PAGES:
            payload = self._request(
                "POST",
                f"{_BASE}/fleet-management/certificate-management/certificates/query"
                f"?page={page}&pageSize={_PAGE_SIZE}",
                body={"appliance": "VCENTER"},
            )
            if not isinstance(payload, dict) or not isinstance(
                payload.get("vcfCertificateModels"), list
            ):
                raise RemoteError("VCF Operations returned an invalid certificate inventory")
            page_size, total = _page_info(payload, page)
            models = payload["vcfCertificateModels"]
            if expected_total is not None and total != expected_total:
                raise RemoteError("VCF Operations certificate inventory changed during pagination")
            expected_total = total
            if total == 0:
                if models:
                    raise RemoteError("VCF Operations returned inconsistent certificate inventory")
                return []
            if not models or len(models) > page_size or len(rows) + len(models) > total:
                raise RemoteError("VCF Operations returned inconsistent certificate inventory")
            rows.extend(self._public_certificate(model) for model in models)
            if len(rows) == total:
                break
            if len(models) < page_size:
                raise RemoteError("VCF Operations returned a truncated certificate inventory")
            page += 1
        if expected_total is None or len(rows) != expected_total:
            raise RemoteError("VCF Operations certificate inventory exceeds the page limit")
        ids = [row["certificateResourceKey"] for row in rows]
        if len(ids) != len(set(ids)):
            raise RemoteError("VCF Operations certificate inventory has ambiguous identities")
        return rows

    @staticmethod
    def _public_certificate(model: Any) -> dict[str, Any]:
        """Project and validate allowlisted public certificate metadata.

        Args:
            model: Decoded certificate model containing public inventory metadata.
        """
        if not isinstance(model, dict):
            raise RemoteError("VCF Operations returned a malformed certificate record")
        result = {key: model[key] for key in _CERTIFICATE_FIELDS if key in model}
        result["certificateResourceKey"] = _safe_identifier(
            model.get("certificateResourceKey"), "certificate identity"
        )
        for field in ("appliance", "category", "type", "status", "autoRenewState"):
            if field in result and result[field] is not None and not isinstance(result[field], str):
                raise RemoteError("VCF Operations returned malformed certificate metadata")
        if "applianceFqdn" in result and result["applianceFqdn"] is not None:
            result["applianceFqdn"] = _safe_host(result["applianceFqdn"], "appliance FQDN")
        metadata = result.get("certificateMetadata")
        if metadata is not None:
            if not isinstance(metadata, dict):
                raise RemoteError("VCF Operations returned malformed certificate metadata")
            allowed_metadata = {
                "certificateChainGroupId",
                "certificateChainPosition",
                "certificateChainRole",
                "certificatePurpose",
                "managementLevel",
            }
            metadata = {key: metadata[key] for key in allowed_metadata if key in metadata}
            for key, value in metadata.items():
                if value is not None and (
                    (key == "certificateChainPosition" and type(value) is not int)
                    or (key != "certificateChainPosition" and not isinstance(value, str))
                ):
                    raise RemoteError("VCF Operations returned malformed certificate metadata")
            result["certificateMetadata"] = metadata
        names = result.get("subjectAlternativeNames")
        if names is not None:
            if not isinstance(names, dict):
                raise RemoteError("VCF Operations returned malformed certificate names")
            normalized: dict[str, list[str]] = {}
            for key in ("dns", "ip"):
                values = names.get(key, [])
                if not isinstance(values, list) or len(values) > 256 or any(
                    not isinstance(item, str) or len(item) > 253 for item in values
                ):
                    raise RemoteError("VCF Operations returned malformed certificate names")
                normalized[key] = values
            result["subjectAlternativeNames"] = normalized
        auto_info = result.get("autoRenewInfo")
        if auto_info is not None:
            if not isinstance(auto_info, dict):
                raise RemoteError("VCF Operations returned malformed auto-renew metadata")
            result["autoRenewInfo"] = {
                key: auto_info[key]
                for key in ("autoRenewOperationStatus", "autoRenewStatus")
                if key in auto_info and isinstance(auto_info[key], str)
            }
        return result

    def csrs(self, certificate_id: str) -> list[dict[str, Any]]:
        """Return bounded CSR rows whose documented certificate identity matches.

        Args:
            certificate_id: Exact native certificate identity to inspect or operate on.
        """
        cert_id = _safe_identifier(certificate_id, "certificate identity")
        rows: list[dict[str, Any]] = []
        page = 0
        expected_total: int | None = None
        while page < _MAX_PAGES:
            query = urlencode({"certificateId": cert_id, "page": page, "pageSize": _PAGE_SIZE})
            payload = self._request(
                "GET",
                f"{_BASE}/fleet-management/certificate-management/csrs?{query}",
            )
            if not isinstance(payload, dict) or not isinstance(
                payload.get("certificateSignatureInfo"), list
            ):
                raise RemoteError("VCF Operations returned an invalid CSR inventory")
            page_size, total = _page_info(payload, page)
            records = payload["certificateSignatureInfo"]
            if expected_total is not None and total != expected_total:
                raise RemoteError("VCF Operations CSR inventory changed during pagination")
            expected_total = total
            if total == 0:
                if records:
                    raise RemoteError("VCF Operations returned inconsistent CSR inventory")
                return []
            if not records or len(records) > page_size or len(rows) + len(records) > total:
                raise RemoteError("VCF Operations returned inconsistent CSR inventory")
            for record in records:
                row = self._public_csr(record, cert_id)
                rows.append(row)
            if len(rows) == total:
                break
            if len(records) < page_size:
                raise RemoteError("VCF Operations returned a truncated CSR inventory")
            page += 1
        if expected_total is None or len(rows) != expected_total:
            raise RemoteError("VCF Operations CSR inventory exceeds the page limit")
        ids = [row["id"] for row in rows]
        if len(ids) != len(set(ids)):
            raise RemoteError("VCF Operations CSR inventory has ambiguous identities")
        return rows

    @staticmethod
    def _public_csr(record: Any, certificate_id: str) -> dict[str, Any]:
        """Public csr.

        Args:
            record: Public native record whose shape and identity are validated.
            certificate_id: Exact native certificate identity to inspect or operate on.
        """
        if not isinstance(record, dict):
            raise RemoteError("VCF Operations returned a malformed CSR record")
        record_id = _safe_identifier(record.get("id"), "CSR identity")
        if record.get("certificateId") != certificate_id:
            raise RemoteError("VCF Operations returned a CSR for a different certificate")
        csr = record.get("csr")
        if (
            not isinstance(csr, str)
            or not 1 <= len(csr.encode("utf-8")) <= _MAX_CSR_SIZE
            or "PRIVATE KEY" in csr
        ):
            raise RemoteError("VCF Operations returned an invalid public CSR")
        result = {key: record[key] for key in _CSR_FIELDS if key in record}
        result["id"] = record_id
        result["certificateId"] = certificate_id
        result["csr"] = csr
        host = result.get("applianceHostname")
        if host is not None:
            result["applianceHostname"] = _safe_host(host, "CSR appliance hostname")
        return result

    def generate_csr(self, certificate_id: str, spec: dict[str, Any]) -> str:
        """Ask VCF Operations to generate a target-owned CSR and return its workflow ID.

        Args:
            certificate_id: Exact native certificate identity to inspect or operate on.
            spec: Allowlisted target-owned CSR subject and SAN request.
        """
        cert_id = _safe_identifier(certificate_id, "certificate identity")
        if not isinstance(spec, dict) or set(spec) - _CSR_SPEC_FIELDS:
            raise RemoteError("CSR specification has unsupported fields")
        if not isinstance(spec.get("commonName"), str) or not spec["commonName"].strip():
            raise RemoteError("CSR specification requires a common name")
        body_spec = dict(spec)
        names = body_spec.get("subjectAltNames")
        if names is not None:
            if not isinstance(names, dict) or set(names) - {"dns", "ip"}:
                raise RemoteError("CSR specification has invalid subject alternative names")
            for _key, values in names.items():
                if not isinstance(values, list) or len(values) > 256 or any(
                    not isinstance(value, str) or not value or len(value) > 253
                    for value in values
                ):
                    raise RemoteError("CSR specification has invalid subject alternative names")
        for key, value in body_spec.items():
            if key == "subjectAltNames":
                continue
            if not isinstance(value, str) or len(value) > 512 or any(
                character in value for character in "\r\n\x00"
            ):
                raise RemoteError("CSR specification contains an invalid field")
        payload = self._request(
            "POST",
            f"{_BASE}/fleet-management/certificate-management/csrs",
            body={"certificateId": cert_id, "generateCsrSpec": body_spec},
            expected_status=202,
        )
        return self._request_id(payload)

    def replace(self, certificate_id: str, full_chain: str) -> str:
        """Submit a public PEM chain through VCF's external-CA replacement operation.

        Args:
            certificate_id: Exact native certificate identity to inspect or operate on.
            full_chain: Exact reviewed public PEM chain for external-CA replacement.
        """
        cert_id = _safe_identifier(certificate_id, "certificate identity")
        chain = _validate_chain(full_chain)
        payload = self._request(
            "PUT",
            f"{_BASE}/fleet-management/certificate-management/certificates/{quote(cert_id, safe='')}",
            body={"caType": "EXTERNAL_CA", "certificateChain": chain},
            expected_status=202,
        )
        return self._request_id(payload)

    @staticmethod
    def _request_id(payload: Any) -> str:
        """Extract an unambiguous asynchronous workflow identity.

        Args:
            payload: Decoded public response or synthetic response under validation.
        """
        if not isinstance(payload, dict):
            raise RemoteError("VCF Operations returned an invalid workflow response")
        return _safe_identifier(payload.get("requestId"), "workflow request identity")

    def workflow(self, request_id: str) -> dict[str, str]:
        """Return a minimal canonical workflow state without raw remote error text.

        Args:
            request_id: Retained asynchronous native workflow identity.
        """
        workflow_id = _safe_identifier(request_id, "workflow request identity")
        payload = self._request(
            "GET",
            f"{_BASE}/workflows/requests/{quote(workflow_id, safe='')}",
        )
        if not isinstance(payload, dict) or payload.get("requestId") != workflow_id:
            raise RemoteError("VCF Operations returned an ambiguous workflow response")
        state = payload.get("state")
        if not isinstance(state, str) or state.upper() not in _WORKFLOW_STATES:
            raise RemoteError("VCF Operations returned an unsupported workflow state")
        result = {"requestId": workflow_id, "state": _WORKFLOW_STATES[state.upper()]}
        for key in ("category", "requestType"):
            value = payload.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise RemoteError("VCF Operations returned malformed workflow metadata")
                result[key] = value
        if result.get("category") not in (None, "VCF_CERTIFICATE_MANAGEMENT"):
            raise RemoteError("VCF Operations returned a non-certificate workflow")
        return result

    def component_health(self, record: dict[str, Any]) -> bool:
        """Fail closed: SDK data does not bind a fleet certificate to a health resource.

        Args:
            record: Public native record whose shape and identity are validated.
        """
        del record
        raise RemoteError(
            "VCF Operations component health is unknown without a verified resource identity mapping"
        )
