from __future__ import annotations

import time
from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from typing import Any, Callable

import httpx

from atlaso.app.services.vcf_sddc_deployment import tls_sha256_fingerprint


Progress = Callable[[int, str], None]
SUPPORTED_ROLES = {"VcfInstaller", "SddcManager"}


class VcfDepotTargetError(RuntimeError):
    pass


class VcfDepotTargetPartialError(VcfDepotTargetError):
    pass


@dataclass(frozen=True)
class LocalDepotEndpoint:
    hostname: str
    port: int
    url: str
    username: str

    def sanitized(self) -> dict[str, Any]:
        return {"hostname": self.hostname, "port": self.port, "url": self.url, "username": self.username}


def sanitize_remote_depot(payload: dict[str, Any]) -> dict[str, Any]:
    configuration = payload.get("depotConfiguration") or {}
    account = payload.get("offlineAccount") or {}
    return {
        "is_offline": bool(configuration.get("isOfflineDepot")),
        "hostname": str(configuration.get("hostname") or ""),
        "port": int(configuration.get("port") or 0),
        "url": str(configuration.get("url") or ""),
        "username": str(account.get("username") or ""),
        "status": str(account.get("status") or ""),
        "message": str(account.get("message") or ""),
    }


def depot_matches(remote: dict[str, Any], local: LocalDepotEndpoint) -> bool:
    sanitized = sanitize_remote_depot(remote)
    remote_url = sanitized["url"].rstrip("/").lower()
    return bool(
        sanitized["is_offline"]
        and sanitized["hostname"].rstrip(".").lower() == local.hostname.rstrip(".").lower()
        and sanitized["port"] == local.port
        and (not remote_url or remote_url == local.url.rstrip("/").lower())
        and sanitized["username"] == local.username
    )


class VcfDepotApiClient:
    def __init__(self, address: str, username: str, password: str, *, port: int = 443, timeout: float = 30.0, expected_fingerprint: str = ""):
        if expected_fingerprint and tls_sha256_fingerprint(address, port).upper() != expected_fingerprint.upper():
            raise VcfDepotTargetError("The VCF appliance TLS certificate changed after confirmation.")
        normalized = address.strip().strip("[]")
        try:
            parsed_address = ip_address(normalized)
        except ValueError:
            parsed_address = None
        api_host = f"[{normalized}]" if isinstance(parsed_address, IPv6Address) else normalized
        port_suffix = "" if port == 443 else f":{port}"
        self.client = httpx.Client(base_url=f"https://{api_host}{port_suffix}", verify=False, timeout=timeout)
        self.username = username
        self.password = password

    def __enter__(self) -> "VcfDepotApiClient":
        response = self.client.post("/v1/tokens", json={"username": self.username, "password": self.password})
        self._raise(response, "VCF API authentication failed")
        token = str(response.json().get("accessToken") or "")
        if not token:
            raise VcfDepotTargetError("VCF API authentication returned no access token.")
        self.client.headers["Authorization"] = f"Bearer {token}"
        return self

    def __exit__(self, *_args: object) -> None:
        self.client.close()

    @staticmethod
    def _raise(response: httpx.Response, message: str) -> None:
        if response.is_success:
            return
        detail = ""
        try:
            payload = response.json()
            detail = str(payload.get("message") or payload.get("errorCode") or "")
        except (ValueError, AttributeError):
            pass
        raise VcfDepotTargetError(f"{message} ({response.status_code}{': ' + detail if detail else ''})")

    def appliance_info(self) -> dict[str, str]:
        response = self.client.get("/v1/system/appliance-info")
        self._raise(response, "Could not read VCF appliance information")
        payload = response.json()
        role = str(payload.get("role") or "")
        version = str(payload.get("version") or "")
        if role not in SUPPORTED_ROLES:
            raise VcfDepotTargetError(f"Unsupported VCF appliance role: {role or 'unknown'}.")
        if not version.startswith("9."):
            raise VcfDepotTargetError(f"Unsupported VCF version: {version or 'unknown'}; only VCF 9.x is supported.")
        return {"role": role, "version": version}

    def depot_settings(self) -> dict[str, Any]:
        response = self.client.get("/v1/system/settings/depot")
        self._raise(response, "Could not read VCF depot settings")
        return dict(response.json())

    def update_depot(self, local: LocalDepotEndpoint, password: str) -> dict[str, Any]:
        response = self.client.put(
            "/v1/system/settings/depot",
            json={
                "offlineAccount": {"username": local.username, "password": password},
                "depotConfiguration": {
                    "isOfflineDepot": True,
                    "hostname": local.hostname,
                    "port": local.port,
                },
            },
        )
        self._raise(response, "VCF rejected the Atlaso offline depot configuration")
        return dict(response.json())

    def sync_info(self) -> dict[str, Any]:
        response = self.client.get("/v1/system/settings/depot/depot-sync-info")
        self._raise(response, "Could not read VCF depot sync status")
        return dict(response.json())

    def start_sync(self) -> dict[str, Any]:
        response = self.client.patch("/v1/system/settings/depot/depot-sync-info")
        self._raise(response, "VCF rejected the depot metadata sync request")
        return dict(response.json())


def inspect_target_depot(address: str, api_username: str, api_password: str, *, port: int = 443, expected_fingerprint: str = "") -> dict[str, Any]:
    with VcfDepotApiClient(address, api_username, api_password, port=port, expected_fingerprint=expected_fingerprint) as api:
        return {"appliance": api.appliance_info(), "depot": sanitize_remote_depot(api.depot_settings())}


def configure_target_depot(
    address: str,
    api_username: str,
    api_password: str,
    local: LocalDepotEndpoint,
    depot_password: str,
    *,
    replace_existing: bool,
    timeout: float = 3600.0,
    poll_interval: float = 10.0,
    progress: Progress | None = None,
    port: int = 443,
    expected_fingerprint: str = "",
) -> dict[str, Any]:
    with VcfDepotApiClient(address, api_username, api_password, port=port, expected_fingerprint=expected_fingerprint) as api:
        appliance = api.appliance_info()
        current = api.depot_settings()
        matched = depot_matches(current, local)
        sanitized_current = sanitize_remote_depot(current)
        configured = False
        if not matched:
            has_existing = bool(sanitized_current["hostname"] or sanitized_current["url"] or sanitized_current["username"])
            if has_existing and not replace_existing:
                raise VcfDepotTargetError("The target already uses a different depot; confirm replacement before continuing.")
            if progress:
                progress(25, "configuring-depot")
            response = api.update_depot(local, depot_password)
            configured = True
            returned = sanitize_remote_depot(response)
            if returned["status"] and returned["status"] != "DEPOT_CONNECTION_SUCCESSFUL":
                raise VcfDepotTargetError(returned["message"] or f"VCF reported depot status {returned['status']}.")
        if progress:
            progress(50, "starting-metadata-sync")
        before = api.sync_info()
        api.start_sync()
        started = time.monotonic()
        latest: dict[str, Any] = {}
        while time.monotonic() - started < timeout:
            latest = api.sync_info()
            error = str(latest.get("errorMessage") or "").strip()
            if error:
                raise VcfDepotTargetPartialError(f"Depot configuration succeeded, but metadata sync failed: {error}")
            status = str(latest.get("syncStatus") or "").upper()
            old_timestamp = str(before.get("lastSyncCompletionTimestamp") or "")
            new_timestamp = str(latest.get("lastSyncCompletionTimestamp") or "")
            in_progress = any(value in status for value in ("PENDING", "RUNNING", "PROGRESS", "SYNCING", "START"))
            if new_timestamp and new_timestamp != old_timestamp and not in_progress:
                break
            if progress:
                elapsed_fraction = min(1.0, (time.monotonic() - started) / max(timeout, 1))
                progress(55 + int(elapsed_fraction * 35), "syncing-metadata")
            time.sleep(poll_interval)
        else:
            raise VcfDepotTargetPartialError("Depot configuration succeeded, but metadata sync did not complete before the timeout.")
        verified = api.depot_settings()
        sanitized_verified = sanitize_remote_depot(verified)
        if not depot_matches(verified, local):
            raise VcfDepotTargetPartialError("Depot configuration succeeded, but the target did not return the expected Atlaso depot settings.")
        if sanitized_verified["status"] != "DEPOT_CONNECTION_SUCCESSFUL":
            raise VcfDepotTargetPartialError(sanitized_verified["message"] or f"VCF reported depot status {sanitized_verified['status'] or 'unknown'}.")
        if progress:
            progress(100, "succeeded")
        return {
            "appliance": appliance,
            "depot": sanitized_verified,
            "sync": {
                "status": str(latest.get("syncStatus") or ""),
                "last_completed_at": str(latest.get("lastSyncCompletionTimestamp") or ""),
            },
            "configuration": "updated" if configured else "unchanged",
        }
