"""Implement vcf vault import service behavior."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field, replace
from hashlib import sha256
from ipaddress import ip_address
from urllib.parse import quote

import httpx

from atlaso.app.services.vaults import normalize_vault_uris, redact_secret_values
from atlaso.app.services.vcf_depot_target import VcfDepotApiClient, VcfDepotTargetError


@dataclass(frozen=True, repr=False)
class VcfPasswordCandidate:
    """Represent vcf password candidate.

    Attributes:
        candidate_id: Identifier of the associated candidate.
        key: Key maintained by this vcfpasswordcandidate.
        description: Operator-facing purpose or context for the resource.
        secret_type: Secret type maintained by this vcfpasswordcandidate.
        username: Username maintained by this vcfpasswordcandidate.
        resource_name: Resource name maintained by this vcfpasswordcandidate.
        value: Value maintained by this vcfpasswordcandidate.
    """
    candidate_id: str
    key: str
    description: str
    secret_type: str
    username: str
    resource_name: str
    value: str = field(repr=False)
    uris: tuple[str, ...] = ()

    @property
    def selection_id(self) -> str:
        """Return a stable opaque browser selection token derived only from source identity."""
        return "vcf-" + sha256(self.candidate_id.encode("utf-8")).hexdigest()

    def sanitized(self) -> dict[str, object]:
        """Return sanitized."""
        metadata = {
            "candidate_id": self.candidate_id,
            "key": self.key,
            "description": self.description,
            "secret_type": self.secret_type,
            "username": self.username,
            "resource_name": self.resource_name,
            "uris": list(self.uris),
            "uri_status": "available" if self.uris else "Add a verified endpoint in the Vault URI editor after import.",
        }
        sanitized = {key: [redact_secret_values(item, [self.value]) for item in value]
                if isinstance(value, list) else redact_secret_values(value, [self.value])
                for key, value in metadata.items() if key != "candidate_id"}
        sanitized["candidate_id"] = self.selection_id
        return sanitized


class VcfPasswordDiscovery(list[VcfPasswordCandidate]):
    """Keep safe discovery coverage alongside the request-local candidates."""

    def __init__(self, *, scope: str):
        """Initialize an empty discovery with its supported source scope.

        Args:
            scope: Operator-facing description of the source coverage.
        """
        super().__init__()
        self.scope = scope
        self.skipped: Counter[str] = Counter()

    def summary(self) -> dict[str, object]:
        """Return counts and fixed reasons, without source values or diagnostics."""
        return {"scope": self.scope, "available": len(self), "skipped": dict(self.skipped)}


def _endpoint_host(value: object, *, allow_short: bool = False) -> str:
    """Accept only an endpoint hostname or IP, never a URL or opaque identifier.

    Args:
        value: Source endpoint metadata to validate.
        allow_short: Accept a short DNS name only from an explicit Installer endpoint field.
    """
    if not isinstance(value, str):
        return ""
    host = value.strip().rstrip(".")
    if "%" in host:
        return ""
    try:
        address = ip_address(host.strip("[]"))
        return f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        pass
    # Generic resource labels need a FQDN; explicit Installer hostnames may be short.
    if len(host) > 253 or (not allow_short and "." not in host):
        return ""
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", item) for item in labels):
        return ""
    return host.lower()


def _resource_uris(resource: dict, credential_type: str) -> tuple[str, ...]:
    """Map documented resource endpoints to the credential's supported protocol.

    Args:
        resource: Credential resource metadata from SDDC Manager.
        credential_type: Source credential protocol or account category.
    """
    hosts = [_endpoint_host(resource.get("resourceName")), _endpoint_host(resource.get("resourceIp"))]
    web_types = {"ESXI", "VCENTER", "PSC", "NSX_MANAGER", "NSXT_MANAGER", "VRLI", "VROPS",
                 "VRA", "WSA", "VRSLCM", "VXRAIL_MANAGER", "NSX_ALB", "SDDC_MANAGER"}
    if credential_type == "SSH":
        scheme = "ssh"
    elif credential_type in {"", "API", "SSO", "AUDIT"} and str(resource.get("resourceType") or "").upper() in web_types:
        scheme = "https"
    else:
        # FTP does not prove SFTP; unknown services need an operator association.
        return ()
    uris = tuple(dict.fromkeys(f"{scheme}://{host}" for host in hosts if host))
    return normalize_vault_uris(uris)


def _read_json(api: VcfDepotApiClient, path: str, **kwargs: object) -> object:
    """Read a source response without reflecting vendor messages or secret values.

    Args:
        api: Authenticated source API client.
        path: Source API path to read.
        **kwargs: Additional HTTP request options.
    """
    try:
        response = api.client.get(path, **kwargs)
        if not response.is_success:
            raise VcfDepotTargetError(f"VCF credential read failed (HTTP {response.status_code}).")
        return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise VcfDepotTargetError("VCF credential read failed; verify source availability and permissions.") from exc


def _credential_rows(api: VcfDepotApiClient) -> list[dict]:
    """Read the documented zero-based pages, refusing incomplete or repeated pages.

    Args:
        api: Authenticated SDDC Manager API client.
    """
    rows: list[dict] = []
    page = 0
    page_size = 0  # Documented all-records request, with metadata traversal if paged.
    seen: set[str] = set()
    while page < 1000:
        payload = _read_json(api, "/v1/credentials", params={"pageSize": page_size, "pageNumber": page})
        if isinstance(payload, list):
            elements, metadata = payload, {}
        elif isinstance(payload, dict):
            elements = payload.get("elements", payload.get("credentials", []))
            metadata = payload.get("pageMetadata") or {}
        else:
            raise VcfDepotTargetError("SDDC Manager returned an invalid credentials response.")
        if not isinstance(elements, list) or not isinstance(metadata, dict):
            raise VcfDepotTargetError("SDDC Manager returned an invalid credentials response.")
        for row in elements:
            if not isinstance(row, dict):
                raise VcfDepotTargetError("SDDC Manager returned an invalid credential row.")
            identifier = row.get("id")
            if isinstance(identifier, str) and identifier:
                if identifier in seen:
                    raise VcfDepotTargetError("The VCF credential pages changed or repeated; inspect again.")
                seen.add(identifier)
            rows.append(row)
            if len(rows) > 100000:
                raise VcfDepotTargetError("The VCF credential inventory exceeds the supported record limit.")
        if not metadata:
            return rows
        numbers = [metadata.get(name, default) for name, default in
                   (("pageNumber", page), ("pageSize", 0), ("totalPages", 1), ("totalElements", len(rows)))]
        if any(type(number) is not int or number < 0 for number in numbers):
            raise VcfDepotTargetError("SDDC Manager returned invalid credential pagination.")
        current, size, total_pages, total_elements = numbers
        if current != page or total_pages > 1000 or total_elements > 100000:
            raise VcfDepotTargetError("SDDC Manager returned unsupported credential pagination.")
        if page + 1 >= total_pages:
            if total_elements != len(rows):
                raise VcfDepotTargetError("The VCF credential inventory changed or was incomplete; inspect again.")
            return rows
        if not elements or not size:
            raise VcfDepotTargetError("SDDC Manager returned incomplete credential pagination.")
        page, page_size = page + 1, size
    raise VcfDepotTargetError("The VCF credential inventory exceeds the supported page limit.")


def _segment(value: object, fallback: str = "password") -> str:
    """Return segment.

    Args:
        value: Candidate value consumed by segment.
        fallback: Fallback consumed by segment.
    """
    normalized = re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")
    if not normalized:
        normalized = fallback
    if normalized[0].isdigit():
        normalized = f"item_{normalized}"
    return normalized


def _usable_password(value: object) -> str:
    """Return usable password.

    Args:
        value: Candidate value consumed by usable password.
    """
    password = value if isinstance(value, str) else ""
    if not password or re.fullmatch(r"[*xX•]+", password):
        return ""
    return password


def _sddc_manager_candidates(api: VcfDepotApiClient) -> list[VcfPasswordCandidate]:
    """Return sddc manager candidates.

    Args:
        api: Api consumed by SDDC manager candidates.


    Raises:
        VcfDepotTargetError: If the operation encounters an invalid state.
    """
    rows = _credential_rows(api)
    result = VcfPasswordDiscovery(scope="Credentials accessible to this SDDC Manager account; permission-hidden records cannot be enumerated.")
    for index, row in enumerate(rows):
        password = _usable_password(row.get("password"))
        identifier = row.get("id")
        if not password and isinstance(identifier, str) and identifier:
            try:
                encoded_id = quote(identifier, safe="").replace(".", "%2E")
                detail = _read_json(api, f"/v1/credentials/{encoded_id}")
            except VcfDepotTargetError:
                result.skipped["Credential retrieval unavailable or permission-limited"] += 1
                continue
            if not isinstance(detail, dict) or detail.get("id") != identifier:
                result.skipped["Credential detail identity unavailable or changed"] += 1
                continue
            # Bind a fresh detail to the listed account/resource, never combine mismatched identities.
            listed_resource = row.get("resource") if isinstance(row.get("resource"), dict) else {}
            detail_resource = detail.get("resource") if isinstance(detail.get("resource"), dict) else {}
            if (any(row.get(name) and detail.get(name) != row[name] for name in ("username", "credentialType"))
                    or any(listed_resource.get(name) and detail_resource.get(name) != listed_resource[name]
                           for name in ("resourceId", "resourceName", "resourceType", "resourceIp"))):
                result.skipped["Credential detail identity unavailable or changed"] += 1
                continue
            row = detail
            password = _usable_password(row.get("password"))
        if not password:
            result.skipped["Password missing or masked by the source"] += 1
            continue
        resource = row.get("resource") if isinstance(row.get("resource"), dict) else {}
        resource_name = str(resource.get("resourceName") or row.get("resourceName") or row.get("id") or f"credential-{index + 1}")
        resource_type = str(resource.get("resourceType") or row.get("resourceType") or "")
        username = str(row.get("username") or "")
        credential_type = str(row.get("credentialType") or "").upper()
        if credential_type not in {"", "SSO", "SSH", "API", "FTP", "AUDIT"}:
            result.skipped["Unsupported credential type"] += 1
            continue
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
                uris=_resource_uris(resource, credential_type),
            )
        )
    return result


def _installer_password_nodes(
    value: object, path: tuple[str, ...] = (), *, endpoint: str = "", username: str = "",
    skipped: Counter[str] | None = None,
) -> list[tuple[tuple[str, ...], str, str, str, str, str]]:
    """Return installer password nodes.

    Args:
        value: Value to process.
        path: Filesystem or URL path to read, validate, or update.
        endpoint: Validated endpoint inherited within the current component.
        username: Account inherited within the current component.
        skipped: Optional counter for fixed discovery skip reasons.
    """
    result: list[tuple[tuple[str, ...], str, str, str, str, str]] = []
    if isinstance(value, dict):
        component = path[-1].lower() if path else ""
        manager_identifiers: dict[str, str] = {}
        if component == "nsxtspec" and isinstance(value.get("nsxtManagers"), list):
            # Compute identifiers directly from hostname metadata before reading passwords.
            for manager in value["nsxtManagers"]:
                if isinstance(manager, dict):
                    host = _endpoint_host(manager.get("hostname"), allow_short=True)
                    if host:
                        manager_identifiers[host] = sha256(host.encode("utf-8")).hexdigest()
        local_endpoint = next((_endpoint_host(value.get(field), allow_short=field in
                                             {"vcenterHostname", "hostname", "hostName"}) for field in
                               ("vcenterHostname", "vipFqdn", "hostname", "hostName", "fqdn", "ipAddress")
                               if _endpoint_host(value.get(field), allow_short=field in
                                                 {"vcenterHostname", "hostname", "hostName"})), "")
        endpoint = local_endpoint or endpoint
        username = str(value.get("username") or value.get("userName") or username)
        for key, child in value.items():
            child_path = (*path, str(key))
            # Identity metadata is hashed before reading any password value.
            path_identifier = sha256(".".join(child_path).encode("utf-8")).hexdigest()
            if "password" in str(key).lower() and not isinstance(child, (dict, list)):
                password = _usable_password(child)
                if password:
                    account = "root" if str(key).lower() == "rootpassword" else username
                    endpoints = [endpoint]
                    if component == "vcenterspec":
                        if key == "rootVcenterPassword":
                            account = "root"
                        elif key == "adminUserSsoPassword":
                            account = str(value.get("adminUserSsoUsername") or "").strip()
                            if not account:
                                domain = _endpoint_host(value.get("ssoDomain"), allow_short=True)
                                account = f"administrator@{domain}" if domain else "administrator"
                    elif component == "nsxtspec":
                        if key == "rootNsxtManagerPassword":
                            account = "root"
                            endpoints = list(manager_identifiers)
                            # The cluster VIP does not identify an individual SSH node.
                            endpoints = endpoints or [""]
                        elif key == "nsxtAdminPassword":
                            account = "admin"
                        elif key == "nsxtAuditPassword":
                            account = "audit"
                    elif component == "sddcmanagerspec" and key == "sshPassword":
                        account = "vcf"
                    elif component == "sddcmanagerspec" and key == "localUserPassword":
                        account = "admin@local"
                    elif component == "vspclusterspec" and key == "systemUserPassword":
                        platform = _endpoint_host(value.get("platformFqdn"))
                        for identity in ("vmware-system-user", "admin@vsp.local"):
                            result.append(((*child_path, identity), password, platform, identity, "", path_identifier))
                        continue
                    elif component in {"vcfoperationsspec", "vcfautomationspec"} and key == "adminUserPassword":
                        account = "admin"
                        if component == "vcfoperationsspec":
                            web_endpoint = _endpoint_host(value.get("loadBalancerFqdn"))
                            nodes = value.get("nodes")
                            if not web_endpoint and isinstance(nodes, list):
                                targets = [node for node in nodes if isinstance(node, dict)
                                           and (len(nodes) == 1 or str(node.get("type") or "").lower() == "master")]
                                if len(targets) == 1:
                                    web_endpoint = _endpoint_host(targets[0].get("hostname"), allow_short=True)
                            endpoints = [web_endpoint]
                    elif key == "rootUserPassword" and (
                        component == "vcfoperationscollectorspec"
                        or (len(path) >= 3 and path[-3:-1] == ("vcfOperationsSpec", "nodes"))
                    ):
                        account = "root"
                    for host in endpoints:
                        # One shared NSX password expands to individually named managers.
                        # Bind identity to the host so reorder/removal cannot rotate another key.
                        node_path = (*path, host, str(key)) if (
                            component == "nsxtspec" and key == "rootNsxtManagerPassword" and host
                        ) else child_path
                        result.append((node_path, password, host, account, manager_identifiers.get(host, "")
                                       if component == "nsxtspec" and key == "rootNsxtManagerPassword" else "",
                                       path_identifier))
                elif skipped is not None:
                    skipped["Password missing, masked, or unsupported in the latest specification"] += 1
            else:
                # A sibling component spec must identify its own endpoint.
                nested_endpoint = "" if str(key).lower().endswith("spec") else endpoint
                nested_username = "" if str(key).lower().endswith("spec") else username
                nested = _installer_password_nodes(child, child_path, endpoint=nested_endpoint,
                                                   username=nested_username, skipped=skipped)
                if "password" in str(key).lower() and isinstance(child, (dict, list)) and not nested and skipped is not None:
                    skipped["Unsupported password container in the latest specification"] += 1
                result.extend(nested)
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
            result.extend(_installer_password_nodes(child, (*path, label or str(index)), skipped=skipped))
    return result


def _vcf_installer_candidates(api: VcfDepotApiClient) -> list[VcfPasswordCandidate]:
    """Return vcf installer candidates.

    Args:
        api: Api consumed by VCF installer candidates.


    Raises:
        VcfDepotTargetError: If the operation encounters an invalid state.
    """
    latest = _read_json(api, "/v1/sddcs/latest")
    if not isinstance(latest, dict):
        raise VcfDepotTargetError("VCF Installer returned an invalid latest SDDC response.")
    sddc_id = str(latest.get("id") or latest.get("sddcId") or "")
    if not sddc_id:
        raise VcfDepotTargetError("VCF Installer returned no latest SDDC identifier.")
    spec = _read_json(api, f"/v1/sddcs/{quote(sddc_id, safe='')}/spec")
    if not isinstance(spec, dict):
        raise VcfDepotTargetError("VCF Installer returned an invalid SDDC specification.")
    result = VcfPasswordDiscovery(scope="Passwords in the latest VCF Installer SDDC specification only; this is not a complete live credential inventory.")
    for path, password, endpoint, username, host_identifier, path_identifier in _installer_password_nodes(spec, skipped=result.skipped):
        lowered = ".".join(path).lower()
        secret_type = "esx_password" if any(item.lower() in {"hostspec", "hostspecs", "hosts", "esx", "esxi"}
                                             for item in path[:-1]) else "vcf_password"
        prefix = "esx" if secret_type == "esx_password" else "vcf"
        meaningful = [_segment(item) for item in path if item.lower() not in {"credentials", "password"}]
        if host_identifier:
            # DNS punctuation can normalize to the same key segment for distinct hosts.
            meaningful[-2] = "host_" + host_identifier
        key = ".".join([prefix, *meaningful[-3:], "password"])
        if len(key) > 180:
            key = f"{prefix}.resource_{path_identifier}.{_segment(username)[:40]}.password"
        resource_name = next((item for item in reversed(path[:-1]) if not item.isdigit()), "VCF Installer")
        candidate_id = f"{sddc_id}:{'.'.join(path)}"
        scheme = ""
        if (username == "root" or secret_type == "esx_password"
                or path[-2:] == ("sddcManagerSpec", "sshPassword")
                or ("vspClusterSpec" in path and username == "vmware-system-user")):
            scheme = "ssh"
        elif any(marker in lowered for marker in ("vcenter", "sddcmanager", "nsx", "vrops", "vra", "vrslcm",
                                                  "vspclusterspec", "vcfoperationsspec", "vcfautomationspec")):
            scheme = "https"
        uris = normalize_vault_uris((f"{scheme}://{endpoint}",)) if endpoint and scheme else ()
        result.append(
            VcfPasswordCandidate(
                candidate_id=candidate_id,
                key=key,
                description=f"Imported VCF Installer password from {'.'.join(path)}.",
                secret_type=secret_type,
                username=username or ("root" if secret_type == "esx_password" else ""),
                resource_name=resource_name,
                value=password,
                uris=uris,
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
    """Return discover vcf passwords.

    Args:
        source_type: Source type supplied by the caller.
        address: Network address of the target service or interface.
        port: TCP or UDP port of the target service.
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.

    Raises:
        VcfDepotTargetError: If the operation encounters an invalid state.
    """
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
    if isinstance(candidates, VcfPasswordDiscovery):
        candidates[:] = unique_candidates
        return candidates
    return unique_candidates
