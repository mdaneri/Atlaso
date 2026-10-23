"""Pinned native API adapter for standalone VCF SDDC Manager 9.x."""

from __future__ import annotations

import re
import socket
import time
from dataclasses import replace
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .vcf_certificate_remote import Credentials, NativeAdapter, RemoteError, Target

_PAGE_LIMIT = 50
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,199}$")


class SddcAdapter(NativeAdapter):
    """Use the shared pinned transport with SDDC Manager's native API contract."""

    def __init__(self, target: Target):
        super().__init__(target, "vcenter")
        self.product = "sddc"
        self._access_token: str | None = None
        self._binding: dict[str, str] | None = None
        self._appliance: dict[str, str] | None = None

    def login(self, credentials: Credentials) -> str:
        status, payload = self.transport.request(
            "POST",
            "/v1/tokens",
            body={"username": credentials.username, "password": credentials.password},
        )
        token = payload.get("accessToken") if isinstance(payload, dict) else None
        if (
            status != 200
            or not isinstance(token, str)
            or not 1 <= len(token) <= 4096
            or any(c in token for c in "\r\n")
        ):
            raise RemoteError("SDDC Manager authentication returned an invalid token")
        self._access_token = token
        return token

    def logout(self) -> None:
        self._access_token = None
        self.session = None

    def __exit__(self, *_error: Any) -> None:
        self.logout()

    def _request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        expected_status: int | None = 200,
    ) -> Any:
        if not self._access_token:
            raise RemoteError("Authenticate before requesting SDDC Manager state")
        status, result = self.transport.request(
            method,
            path,
            body=body,
            session_header=("Authorization", "Bearer " + self._access_token),
        )
        if expected_status is not None and status != expected_status:
            raise RemoteError(
                "SDDC Manager returned an unexpected native operation status"
            )
        return result

    def _pages(self, path: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        page, total_pages, total_elements = 0, None, None
        while total_pages is None or page < total_pages:
            result = self._request(
                "GET", f"{path}?pageNumber={page}&pageSize={_PAGE_LIMIT}"
            )
            if (
                not isinstance(result, dict)
                or not isinstance(result.get("elements"), list)
                or not isinstance(result.get("pageMetadata"), dict)
            ):
                raise RemoteError("SDDC Manager returned incomplete paginated data")
            meta, elements = result["pageMetadata"], result["elements"]
            pages, total = meta.get("totalPages"), meta.get("totalElements")
            if (
                type(meta.get("pageNumber")) is not int
                or meta["pageNumber"] != page
                or type(pages) is not int
                or type(total) is not int
                or not 0 <= pages <= 100
                or not 0 <= total <= 5000
            ):
                raise RemoteError("SDDC Manager pagination is inconsistent")
            if page == 0 and total == 0 and pages in {0, 1} and elements == []:
                return []
            if (
                pages < 1
                or not elements
                or any(not isinstance(item, dict) for item in elements)
                or (
                    total_pages is not None
                    and (pages != total_pages or total != total_elements)
                )
            ):
                raise RemoteError("SDDC Manager returned inconsistent paginated data")
            rows.extend(elements)
            if len(rows) > total:
                raise RemoteError("SDDC Manager pagination exceeds the reported total")
            total_pages, total_elements = pages, total
            page += 1
        if len(rows) != total_elements:
            raise RemoteError("SDDC Manager returned a truncated inventory")
        return rows

    def product_info(self) -> dict[str, Any]:
        info = self._request("GET", "/v1/system/appliance-info")
        if not isinstance(info, dict) or info.get("role") != "SddcManager":
            raise RemoteError("Target is not an initialized SDDC Manager appliance")
        server_time = getattr(self.transport, "server_time", None)
        if server_time is None or abs(server_time - time.time()) > 300:
            raise RemoteError(
                "Correct the SDDC Manager time source; its clock differs by more than five minutes"
            )
        version = info.get("version")
        if not isinstance(version, str) or not re.match(r"^9\.[0-9]+(?:\.|$)", version):
            raise RemoteError("Only SDDC Manager 9.x is supported")
        managers = self._pages("/v1/sddc-managers")
        candidates = []
        try:
            target_ips = {
                str(record[4][0])
                for record in socket.getaddrinfo(
                    self.target.host, self.target.port, type=socket.SOCK_STREAM
                )
            }
        except OSError:
            target_ips = set()
        ip_addresses = info.get("ipAddresses")
        management_entries = (
            [
                entry
                for entry in ip_addresses
                if isinstance(entry, dict)
                and entry.get("type") == "MANAGEMENT"
                and isinstance(entry.get("ipAddress"), str)
            ]
            if isinstance(ip_addresses, list)
            else []
        )
        if len(management_entries) != 1:
            raise RemoteError("SDDC Manager management address is missing or ambiguous")
        management_ip = management_entries[0]["ipAddress"]
        if management_ip not in target_ips:
            raise RemoteError(
                "SDDC Manager management address does not match the confirmed target"
            )
        for item in managers:
            ip = item.get("ipAddress")
            fqdn = item.get("fqdn")
            domain = item.get("domain")
            if (
                isinstance(domain, dict)
                and isinstance(ip, str)
                and isinstance(fqdn, str)
                and ip == management_ip
                and domain.get("id")
                and domain.get("type") == "MANAGEMENT"
            ):
                candidates.append(item)
        if len(candidates) != 1:
            raise RemoteError("SDDC Manager resource identity is absent or ambiguous")
        row = candidates[0]
        domain_id, resource_id, identity = (
            row["domain"]["id"],
            row.get("id"),
            row["fqdn"],
        )
        if not all(
            isinstance(v, str) and _SAFE_ID.fullmatch(v)
            for v in (domain_id, resource_id)
        ) or not isinstance(identity, str):
            raise RemoteError("SDDC Manager resource identity is invalid")
        domain = self._request("GET", f"/v1/domains/{domain_id}")
        if (
            not isinstance(domain, dict)
            or domain.get("id") != domain_id
            or domain.get("type") != "MANAGEMENT"
            or str(domain.get("status", "")).upper() != "ACTIVE"
        ):
            raise RemoteError("SDDC Manager management domain is not active")
        try:
            fqdn_ips = {
                str(record[4][0])
                for record in socket.getaddrinfo(
                    identity, self.target.port, type=socket.SOCK_STREAM
                )
            }
        except OSError:
            fqdn_ips = set()
        if management_ip not in fqdn_ips:
            raise RemoteError(
                "SDDC Manager FQDN does not resolve to its management address"
            )
        self._binding = {
            "domain_id": str(domain_id),
            "resource_id": str(resource_id),
            "identity": str(identity),
        }
        self._appliance = {
            "role": "SddcManager",
            "version": version,
            "identity": str(identity),
            "domain_id": str(domain_id),
            "resource_id": str(resource_id),
        }
        return dict(self._appliance)

    def configure_binding(self, public_info: dict[str, str]) -> None:
        required = ("domain_id", "resource_id", "identity")
        if any(not isinstance(public_info.get(key), str) for key in required) or any(
            not _SAFE_ID.fullmatch(public_info[key]) for key in required[:2]
        ):
            raise RemoteError("Recorded SDDC Manager binding is invalid")
        if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", public_info["identity"]
        ):
            raise RemoteError("Recorded SDDC Manager FQDN is invalid")
        self._binding = {key: public_info[key] for key in required}
        self._appliance = dict(public_info)

    def _bound(self) -> dict[str, str]:
        if self._binding is None:
            raise RemoteError(
                "Discover and bind the SDDC Manager resource before certificate operations"
            )
        return self._binding

    def current_certificate(self) -> dict[str, Any]:
        binding = self._bound()
        certs = self._pages(f"/v1/domains/{binding['domain_id']}/resource-certificates")
        own = [
            row
            for row in certs
            if row.get("resourceType") == "SDDC_MANAGER"
            and row.get("issuedTo") == binding["identity"]
            and row.get("isInstalled") is True
        ]
        if len(own) != 1:
            raise RemoteError(
                "Installed SDDC Manager certificate is absent or ambiguous"
            )
        operation_status = (
            str(own[0].get("operationStatus", ""))
            .replace("_", "")
            .replace(" ", "")
            .upper()
        )
        if operation_status in {"PENDING", "INPROGRESS", "QUEUED"}:
            raise RemoteError(
                "A native SDDC Manager certificate task is active. Reconcile it before preparing another operation"
            )
        pem = own[0].get("pemEncoded")
        try:
            if (
                not isinstance(pem, str)
                or x509.load_pem_x509_certificate(pem.encode())
                .fingerprint(hashes.SHA256())
                .hex()
                != self.target.fingerprint
            ):
                raise ValueError
        except ValueError, TypeError:
            raise RemoteError(
                "SDDC Manager certificate inventory differs from the confirmed TLS identity"
            ) from None
        self._csr_rows()  # Verify read capability without creating a target-side key.
        return own[0]

    def vcenter_permissions(self, credentials: Credentials) -> bool:
        users = self._pages("/v1/users")
        roles = self._pages("/v1/roles")
        matches = [
            u
            for u in users
            if u.get("type") == "USER"
            and isinstance(u.get("name"), str)
            and (
                u["name"].casefold() == credentials.username.casefold()
                or (u["name"] + "@" + str(u.get("domain", ""))).casefold()
                == credentials.username.casefold()
            )
        ]
        if len(matches) != 1 or not isinstance(matches[0].get("role"), dict):
            raise RemoteError(
                "Use a directly assigned SDDC Manager administrator user; inherited group roles cannot be verified here"
            )
        role_id = matches[0]["role"].get("id")
        selected = [role for role in roles if role.get("id") == role_id]
        return len(selected) == 1 and str(selected[0].get("name", "")).casefold() in {
            "admin",
            "administrator",
        }

    def health(self) -> dict[str, list[dict[str, str]]]:
        services = self._pages("/v1/vcf-services")
        if not services or len({row.get("id") for row in services}) != len(services):
            raise RemoteError(
                "SDDC Manager service health inventory is empty or ambiguous"
            )
        normalized = []
        for row in services:
            status = str(row.get("status", "")).upper()
            if (
                not isinstance(row.get("id"), str)
                or not row["id"]
                or status not in {"UP", "RUNNING", "ACTIVE"}
            ):
                raise RemoteError("SDDC Manager service health is incomplete")
            normalized.append({"id": row["id"], "status": status})
        return {"list": normalized}

    def _csr_rows(self) -> list[dict[str, Any]]:
        binding = self._bound()
        rows = self._pages(f"/v1/domains/{binding['domain_id']}/csrs")
        own = []
        for row in rows:
            resource = row.get("resource")
            if not isinstance(resource, dict):
                raise RemoteError("SDDC Manager returned a malformed CSR inventory")
            if resource.get("type") == "SDDC_MANAGER" and (
                resource.get("resourceId") == binding["resource_id"]
                or resource.get("fqdn") == binding["identity"]
            ):
                if (
                    resource.get("resourceId") != binding["resource_id"]
                    or resource.get("fqdn") != binding["identity"]
                ):
                    raise RemoteError("SDDC Manager CSR resource identity changed")
                own.append(row)
        if len(own) > 1:
            raise RemoteError("SDDC Manager CSR identity is ambiguous")
        return own

    def start_csr(self, spec: dict[str, Any]) -> str:
        binding = self._bound()
        resources = spec.get("resources")
        if (
            not isinstance(resources, list)
            or len(resources) != 1
            or not isinstance(resources[0], dict)
            or any(
                resources[0].get(key) != value
                for key, value in {
                    "resourceId": binding["resource_id"],
                    "fqdn": binding["identity"],
                    "type": "SDDC_MANAGER",
                }.items()
            )
        ):
            raise RemoteError("Select only the bound SDDC Manager resource")
        current = self.current_certificate()
        prior = self._csr_rows()
        if prior:
            try:
                csr = x509.load_pem_x509_csr(prior[0]["csrEncodedContent"].encode())
                cert = x509.load_pem_x509_certificate(current["pemEncoded"].encode())
                if not csr.is_signature_valid or csr.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ) != cert.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ):
                    raise ValueError
            except ValueError, KeyError, TypeError, AttributeError:
                raise RemoteError(
                    "SDDC Manager already has an unresolved CSR. Reconcile it through its native certificate workflow before preparing another"
                ) from None
        result = self._request(
            "PUT", f"/v1/domains/{binding['domain_id']}/csrs", spec, expected_status=202
        )
        return _task_id(result)

    def wait_csr(self, task_id: str, deadline: float) -> str:
        previous = self.transport.target
        self.transport.target = replace(
            previous, deadline=min(deadline, previous.deadline or float("inf"))
        )
        try:
            self._poll_task(task_id, deadline)
            rows = self._csr_rows()
            if (
                len(rows) != 1
                or not isinstance(rows[0].get("csrEncodedContent"), str)
                or len(rows[0]["csrEncodedContent"].encode()) > 65536
            ):
                raise RemoteError("Generated SDDC Manager CSR is absent or ambiguous")
            return str(rows[0]["csrEncodedContent"])
        finally:
            self.transport.target = previous

    def start_validation(self, leaf: str, chain: list[str]) -> str:
        binding = self._bound()
        if len(chain) != 1:
            raise RemoteError(
                "SDDC Manager certificate validation requires the reviewed root certificate"
            )
        root = chain[0]
        body = [
            {
                "resourceId": binding["resource_id"],
                "resourceFqdn": binding["identity"],
                "resourceCertificate": leaf,
                "caCertificate": root,
                "certificateChain": leaf.rstrip() + "\n" + root.lstrip(),
            }
        ]
        result = self._request(
            "PUT",
            f"/v1/domains/{binding['domain_id']}/resource-certificates/validations",
            body,
            expected_status=201,
        )
        return _task_id(result, "validationId")

    def wait_validation(self, validation_id: str, deadline: float) -> bool:
        binding = self._bound()
        validation_id = _validate_id(validation_id)
        previous = self.transport.target
        self.transport.target = replace(
            previous, deadline=min(deadline, previous.deadline or float("inf"))
        )
        try:
            while time.monotonic() < deadline:
                result = self._request(
                    "GET",
                    f"/v1/domains/{binding['domain_id']}/resource-certificates/validations/{validation_id}",
                )
                if (
                    not isinstance(result, dict)
                    or result.get("validationId") != validation_id
                    or not isinstance(result.get("completed"), bool)
                    or not isinstance(result.get("validations"), list)
                ):
                    raise RemoteError("SDDC Manager validation response is malformed")
                values = result["validations"]
                if len(values) > 1 or (
                    values
                    and (
                        not isinstance(values[0], dict)
                        or values[0].get("resourceId") != binding["resource_id"]
                        or values[0].get("resourceFqdn") != binding["identity"]
                    )
                ):
                    raise RemoteError(
                        "SDDC Manager validation resource identity changed"
                    )
                if result["completed"]:
                    if (
                        len(values) != 1
                        or values[0].get("validationStatus") != "SUCCESSFUL"
                    ):
                        raise RemoteError(
                            "SDDC Manager rejected the reviewed certificate"
                        )
                    return True
                time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
            raise RemoteError(
                "SDDC Manager validation timed out; reconcile the recorded validation"
            )
        finally:
            self.transport.target = previous

    def start_install(self, leaf: str, chain: list[str]) -> str:
        binding = self._bound()
        if len(chain) != 1:
            raise RemoteError(
                "SDDC Manager install requires the reviewed root certificate"
            )
        body = [
            {
                "resourceId": binding["resource_id"],
                "resourceFqdn": binding["identity"],
                "resourceCertificate": leaf,
                "caCertificate": chain[0],
                "certificateChain": leaf.rstrip() + "\n" + chain[0].lstrip(),
            }
        ]
        return _task_id(
            self._request(
                "PUT",
                f"/v1/domains/{binding['domain_id']}/resource-certificates",
                body,
                expected_status=202,
            )
        )

    def task_complete(self, task_id: str) -> bool:
        result = self._request("GET", f"/v1/tasks/{_validate_id(task_id)}")
        if (
            not isinstance(result, dict)
            or result.get("id") != task_id
            or not isinstance(result.get("status"), str)
        ):
            raise RemoteError("SDDC Manager task identity or status is invalid")
        status = result["status"].replace("_", "").replace(" ", "").upper()
        if status in {"PENDING", "INPROGRESS", "QUEUED"}:
            return False
        if status == "SUCCESSFUL":
            return True
        raise RemoteError(
            "SDDC Manager certificate task failed or returned an unknown state"
        )

    def _poll_task(self, task_id: str, deadline: float) -> None:
        task_id = _validate_id(task_id)
        previous = self.transport.target
        self.transport.target = replace(
            previous, deadline=min(deadline, previous.deadline or float("inf"))
        )
        try:
            while time.monotonic() < deadline:
                if self.task_complete(task_id):
                    return
                time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
            raise RemoteError(
                "SDDC Manager certificate operation timed out; reconcile before retrying"
            )
        finally:
            self.transport.target = previous

    def generate_csr(self, spec: dict[str, Any]) -> str:
        raise RemoteError("Use SDDC Manager's task-based CSR operation")

    def install_csr(self, leaf: str, chain: list[str]) -> None:
        raise RemoteError(
            "Use SDDC Manager's validated certificate installation operation"
        )


def _validate_id(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise RemoteError("SDDC Manager task identifier is invalid")
    return value


def _task_id(result: Any, key: str = "id") -> str:
    if not isinstance(result, dict):
        raise RemoteError("SDDC Manager returned an invalid task identifier")
    value = result.get(key)
    if not isinstance(value, str):
        raise RemoteError("SDDC Manager returned an invalid task identifier")
    return _validate_id(value)
