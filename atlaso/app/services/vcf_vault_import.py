from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from atlaso.app.services.vcf_depot_target import VcfDepotApiClient, VcfDepotTargetError


@dataclass(frozen=True)
class VcfPasswordCandidate:
    candidate_id: str
    key: str
    description: str
    secret_type: str
    username: str
    resource_name: str
    value: str

    def sanitized(self) -> dict[str, str]:
        return {
            "candidate_id": self.candidate_id,
            "key": self.key,
            "description": self.description,
            "secret_type": self.secret_type,
            "username": self.username,
            "resource_name": self.resource_name,
        }


def _segment(value: object, fallback: str = "password") -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")
    if not normalized:
        normalized = fallback
    if normalized[0].isdigit():
        normalized = f"item_{normalized}"
    return normalized


def _usable_password(value: object) -> str:
    password = str(value or "")
    if not password or re.fullmatch(r"[*xX•]+", password):
        return ""
    return password


def _sddc_manager_candidates(api: VcfDepotApiClient) -> list[VcfPasswordCandidate]:
    response = api.client.get("/v1/credentials", params={"pageSize": 0})
    api._raise(response, "Could not read SDDC Manager credentials")
    payload = response.json()
    rows = payload.get("elements") or payload.get("credentials") or payload
    if not isinstance(rows, list):
        raise VcfDepotTargetError("SDDC Manager returned an invalid credentials response.")
    result: list[VcfPasswordCandidate] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        password = _usable_password(row.get("password"))
        if not password:
            continue
        resource = row.get("resource") if isinstance(row.get("resource"), dict) else {}
        resource_name = str(resource.get("resourceName") or row.get("resourceName") or row.get("id") or f"credential-{index + 1}")
        resource_type = str(resource.get("resourceType") or row.get("resourceType") or "")
        username = str(row.get("username") or "")
        candidate_id = str(row.get("id") or f"{resource_type}:{resource_name}:{username}:{index}")
        secret_type = "esx_password" if resource_type.upper() in {"ESXI", "ESX_HOST", "HOST"} else "vcf_password"
        prefix = "esx" if secret_type == "esx_password" else "vcf"
        key = f"{prefix}.{_segment(resource_name)}.{_segment(username, 'password')}"
        result.append(
            VcfPasswordCandidate(
                candidate_id=candidate_id,
                key=key,
                description=f"Imported SDDC Manager {resource_type or 'VCF'} credential for {resource_name}.",
                secret_type=secret_type,
                username=username,
                resource_name=resource_name,
                value=password,
            )
        )
    return result


def _installer_password_nodes(value: object, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], str]]:
    result: list[tuple[tuple[str, ...], str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, str(key))
            if "password" in str(key).lower():
                password = _usable_password(child)
                if password:
                    result.append((child_path, password))
            else:
                result.extend(_installer_password_nodes(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            label = ""
            if isinstance(child, dict):
                label = str(
                    child.get("hostname")
                    or child.get("hostName")
                    or child.get("name")
                    or child.get("id")
                    or ""
                )
            result.extend(_installer_password_nodes(child, (*path, label or str(index))))
    return result


def _vcf_installer_candidates(api: VcfDepotApiClient) -> list[VcfPasswordCandidate]:
    latest_response = api.client.get("/v1/sddcs/latest")
    api._raise(latest_response, "Could not find the latest VCF Installer deployment")
    latest = latest_response.json()
    sddc_id = str(latest.get("id") or latest.get("sddcId") or "")
    if not sddc_id:
        raise VcfDepotTargetError("VCF Installer returned no latest SDDC identifier.")
    spec_response = api.client.get(f"/v1/sddcs/{sddc_id}/spec")
    api._raise(spec_response, "Could not read the latest VCF Installer SDDC specification")
    spec = spec_response.json()
    result: list[VcfPasswordCandidate] = []
    for index, (path, password) in enumerate(_installer_password_nodes(spec)):
        lowered = ".".join(path).lower()
        secret_type = "esx_password" if any(marker in lowered for marker in ("hostspec", "esx", "host.")) else "vcf_password"
        prefix = "esx" if secret_type == "esx_password" else "vcf"
        meaningful = [_segment(item) for item in path if item.lower() not in {"credentials", "password"}]
        key = ".".join([prefix, *meaningful[-3:], "password"])
        resource_name = next((item for item in reversed(path[:-1]) if not item.isdigit()), "VCF Installer")
        candidate_id = f"{sddc_id}:{'.'.join(path)}:{index}"
        result.append(
            VcfPasswordCandidate(
                candidate_id=candidate_id,
                key=key,
                description=f"Imported VCF Installer password from {'.'.join(path)}.",
                secret_type=secret_type,
                username="root" if secret_type == "esx_password" else "",
                resource_name=resource_name,
                value=password,
            )
        )
    return result


def discover_vcf_passwords(
    *,
    source_type: str,
    address: str,
    port: int,
    username: str,
    password: str,
    expected_fingerprint: str,
) -> list[VcfPasswordCandidate]:
    expected_role = {"sddc_manager": "SddcManager", "vcf_installer": "VcfInstaller"}.get(source_type)
    if expected_role is None:
        raise VcfDepotTargetError("Choose SDDC Manager or VCF Installer.")
    with VcfDepotApiClient(
        address,
        username,
        password,
        port=port,
        expected_fingerprint=expected_fingerprint,
    ) as api:
        appliance = api.appliance_info()
        if appliance["role"] != expected_role:
            raise VcfDepotTargetError(
                f"The selected source type does not match the detected appliance role {appliance['role']}."
            )
        candidates = (
            _sddc_manager_candidates(api)
            if source_type == "sddc_manager"
            else _vcf_installer_candidates(api)
        )
    key_counts: dict[str, int] = {}
    unique_candidates: list[VcfPasswordCandidate] = []
    for candidate in candidates:
        key_counts[candidate.key] = key_counts.get(candidate.key, 0) + 1
        count = key_counts[candidate.key]
        unique_candidates.append(
            candidate if count == 1 else replace(candidate, key=f"{candidate.key}_{count}")
        )
    if not unique_candidates:
        raise VcfDepotTargetError("The VCF source returned no supported password values.")
    return unique_candidates
