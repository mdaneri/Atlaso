"""Implement vcf depot target service behavior."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv6Address, ip_address
from typing import Any, Callable

import httpx

from atlaso.app.services.vcf_sddc_deployment import tls_sha256_fingerprint

Progress = Callable[[int, str], None]
SUPPORTED_ROLES = {"VcfInstaller", "SddcManager"}


class VcfDepotTargetError(RuntimeError):
    """Report a vcf depot target error."""
    pass


class VcfDepotTargetPartialError(VcfDepotTargetError):
    """Retain independent configuration and sync evidence after partial completion."""

    def __init__(self, message: str, *, outcome: dict[str, Any] | None = None):
        """Initialize the failure with a safe message and independently read outcome.

        Args:
            message: Safe explanation of the incomplete operation.
            outcome: Sanitized configuration and synchronization evidence.
        """
        super().__init__(message)
        self.outcome = outcome or {}


def _sync_running(payload: dict[str, Any]) -> bool:
    """Identify active sync states without interpreting retained error text.

    Args:
        payload: Target depot synchronization response.
    """
    return str(payload.get("syncStatus") or "").upper() in {
        "PENDING", "RUNNING", "IN_PROGRESS", "SYNCING", "STARTING", "STARTED",
    }


def _new_sync_completion(before: dict[str, Any], latest: dict[str, Any]) -> bool:
    """Require changed completion evidence and reject older comparable timestamps.

    Args:
        before: Snapshot immediately before the accepted request.
        latest: Latest observed target response.
    """
    old = str(before.get("lastSyncCompletionTimestamp") or "")
    new = str(latest.get("lastSyncCompletionTimestamp") or "")
    if not new or new == old:
        return False
    # The vendor contract specifies a string, not a date format. Preserve opaque
    # completion markers, while refusing a regressed timestamp when both parse.
    try:
        return datetime.fromisoformat(new) > datetime.fromisoformat(old)
    except (ValueError, TypeError):
        return True


def _sync_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Project bounded lifecycle evidence without retaining free-form vendor errors.

    Args:
        payload: Observed target synchronization response.
    """
    status = str(payload.get("syncStatus") or "").upper()
    if status not in {"PENDING", "RUNNING", "IN_PROGRESS", "SYNCING", "STARTING", "STARTED",
                      "COMPLETED", "SUCCESS", "SUCCEEDED", "FAILED", "FAILURE", "ERROR"}:
        status = "UNKNOWN"
    try:
        completed = datetime.fromisoformat(str(payload.get("lastSyncCompletionTimestamp") or "")).isoformat()
    except ValueError:
        completed = ""
    return {"status": status, "last_completed_at": completed, "error_present": bool(payload.get("errorMessage"))}


def _configuration_readback(api: VcfDepotApiClient, local: LocalDepotEndpoint) -> dict[str, Any]:
    """Read configuration independently of metadata success without changing it.

    Args:
        api: Authenticated target API client.
        local: Expected local depot endpoint.
    """
    try:
        remote = api.depot_settings()
        depot = sanitize_remote_depot(remote)
        # Vendor messages are not required for this projection and may contain
        # credentials or URLs. Retain only the connection status and endpoint.
        depot.pop("message", None)
        matches = depot_matches(remote, local)
        connected = depot["status"] == "DEPOT_CONNECTION_SUCCESSFUL"
        return {"depot": depot, "configuration_verified": matches and connected,
                "configuration_readback": "verified" if matches and connected else "mismatch"}
    except (VcfDepotTargetError, httpx.HTTPError, ValueError, TypeError):
        return {"configuration_verified": False, "configuration_readback": "unavailable"}


@dataclass(frozen=True)
class LocalDepotEndpoint:
    """Represent local depot endpoint.

    Attributes:
        hostname: Hostname maintained by this localdepotendpoint.
        port: Port maintained by this localdepotendpoint.
        url: Url maintained by this localdepotendpoint.
        username: Username maintained by this localdepotendpoint.
    """
    hostname: str
    port: int
    url: str
    username: str

    def sanitized(self) -> dict[str, Any]:
        """Return sanitized."""
        return {"hostname": self.hostname, "port": self.port, "url": self.url, "username": self.username}


def sanitize_remote_depot(payload: dict[str, Any]) -> dict[str, Any]:
    """Return sanitize remote depot.

    Args:
        payload: Validated request or task payload consumed by the operation.
    """
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
    """Return depot matches.

    Args:
        remote: Remote consumed by depot matches.
        local: Local consumed by depot matches.
    """
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
    """Represent vcf depot api client.

    Attributes:
        client: Client maintained by this vcfdepotapiclient.
        username: Username maintained by this vcfdepotapiclient.
        password: Password maintained by this vcfdepotapiclient.
    """
    def __init__(self, address: str, username: str, password: str, *, port: int = 443, timeout: float = 30.0, expected_fingerprint: str = ""):
        """Initialize the vcf depot api client.

        Args:
            address: Network address of the target service or interface.
            username: Account name used for authentication or lookup.
            password: Password supplied for the immediate authenticated operation.
            port: TCP or UDP port of the target service.
            timeout: Maximum time to wait for completion.
            expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.

        Raises:
            VcfDepotTargetError: If the operation encounters an invalid state.
        """
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
        """Enter the managed context.

        Returns:
            The enter result.

        Raises:
            VcfDepotTargetError: If the operation encounters an invalid state.
        """
        response = self.client.post("/v1/tokens", json={"username": self.username, "password": self.password})
        self._raise(response, "VCF API authentication failed")
        token = str(response.json().get("accessToken") or "")
        if not token:
            raise VcfDepotTargetError("VCF API authentication returned no access token.")
        self.client.headers["Authorization"] = f"Bearer {token}"
        return self

    def __exit__(self, *_args: object) -> None:
        """Exit the managed context without suppressing exceptions.

        Args:
            *_args: Additional positional arguments accepted by the callable.
        """
        self.client.close()

    @staticmethod
    def _raise(response: httpx.Response, message: str) -> None:
        """Handle raise.

        Args:
            response: HTTP or command response being inspected.
            message: Human-readable message associated with the operation.


        Raises:
            VcfDepotTargetError: If the operation encounters an invalid state.
        """
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
        """Return appliance info.

        Raises:
            VcfDepotTargetError: If the operation encounters an invalid state.
        """
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
        """Return depot settings."""
        response = self.client.get("/v1/system/settings/depot")
        self._raise(response, "Could not read VCF depot settings")
        return dict(response.json())

    def update_depot(self, local: LocalDepotEndpoint, password: str) -> dict[str, Any]:
        """Update depot.

        Args:
            local: Local supplied by the caller.
            password: Password supplied for the immediate authenticated operation.

        Returns:
            The update depot result.
        """
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
        """Return sync info."""
        response = self.client.get("/v1/system/settings/depot/depot-sync-info")
        self._raise(response, "Could not read VCF depot sync status")
        return dict(response.json())

    def start_sync(self) -> dict[str, Any]:
        """Return start sync."""
        response = self.client.patch("/v1/system/settings/depot/depot-sync-info")
        self._raise(response, "VCF rejected the depot metadata sync request")
        return dict(response.json())


def inspect_target_depot(address: str, api_username: str, api_password: str, *, port: int = 443, expected_fingerprint: str = "") -> dict[str, Any]:
    """Return inspect target depot.

    Args:
        address: Network address of the target service or interface.
        api_username: Api username supplied by the caller.
        api_password: Api password supplied by the caller.
        port: TCP or UDP port of the target service.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.
    """
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
    """Update target depot.

    Args:
        address: Network address of the target service or interface.
        api_username: Api username supplied by the caller.
        api_password: Api password supplied by the caller.
        local: Local supplied by the caller.
        depot_password: Depot password supplied by the caller.
        replace_existing: Replace existing supplied by the caller.
        timeout: Maximum time to wait for completion.
        poll_interval: Poll interval supplied by the caller.
        progress: Progress supplied by the caller.
        port: TCP or UDP port of the target service.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.

    Returns:
        The configure target depot result.

    Raises:
        VcfDepotTargetError: If the operation encounters an invalid state.
        VcfDepotTargetPartialError: If the operation encounters an invalid state.
    """
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
            if _sync_running(api.sync_info()):
                raise VcfDepotTargetError("A metadata sync is already active. Wait for it to finish before changing the target depot; no configuration was changed.")
            if progress:
                progress(25, "configuring-depot")
            response = api.update_depot(local, depot_password)
            configured = True
            returned = sanitize_remote_depot(response)
            if returned["status"] and returned["status"] != "DEPOT_CONNECTION_SUCCESSFUL":
                raise VcfDepotTargetError(returned["message"] or f"VCF reported depot status {returned['status']}.")
        if progress:
            progress(50, "starting-metadata-sync")
        configuration = "updated" if configured else "unchanged"
        sync_outcome = "unknown"
        request_accepted = False
        before: dict[str, Any] = {}
        latest: dict[str, Any] = {}
        try:
            before = api.sync_info()
            if _sync_running(before):
                sync_outcome = "already-running"
                raise VcfDepotTargetPartialError("A metadata sync is already active. No additional sync was requested; inspect its completion before retrying.")
            api.start_sync()
            request_accepted = True
            started = time.monotonic()
            while time.monotonic() - started < timeout:
                latest = api.sync_info()
                status = str(latest.get("syncStatus") or "").upper()
                # An error can describe the previous completion while the new
                # request is pending. Neither that error nor an old completion
                # proves a result for the accepted request.
                if not _sync_running(latest) and _new_sync_completion(before, latest):
                    error = str(latest.get("errorMessage") or "").strip()
                    if error or status in {"FAILED", "FAILURE", "ERROR"}:
                        sync_outcome = "failed"
                        component = "Compatibility metadata download" if "compatibility" in error.lower() else "Metadata synchronization"
                        raise VcfDepotTargetPartialError(f"{component} failed on the target. Inspect the target sync diagnostics before retrying.")
                    if status in {"COMPLETED", "SUCCESS", "SUCCEEDED"}:
                        sync_outcome = "succeeded"
                        break
                if progress:
                    elapsed_fraction = min(1.0, (time.monotonic() - started) / max(timeout, 1))
                    progress(55 + int(elapsed_fraction * 35), "syncing-metadata")
                time.sleep(min(max(poll_interval, 0), max(0, timeout - (time.monotonic() - started))))
            else:
                sync_outcome = "unconfirmed"
                raise VcfDepotTargetPartialError("The requested metadata sync did not reach a confirmed terminal result before the timeout. Read target status before retrying; the remote sync may still be running.")
        except (VcfDepotTargetError, httpx.HTTPError, ValueError) as exc:
            readback = _configuration_readback(api, local)
            outcome = {
                "appliance": appliance,
                "configuration": configuration,
                **readback,
                "sync": {"outcome": sync_outcome, "request_accepted": request_accepted,
                         "before_request": _sync_evidence(before), "latest_observation": _sync_evidence(latest)},
                "manual_recovery_required": readback["configuration_readback"] == "mismatch",
                "next_step": "Inspect target metadata sync status before retrying. A matching depot is preserved on retry.",
            }
            message = str(exc) if isinstance(exc, VcfDepotTargetPartialError) else "Metadata sync could not be requested or observed. Inspect target status before retrying."
            raise VcfDepotTargetPartialError(message, outcome=outcome) from exc
        readback = _configuration_readback(api, local)
        outcome = {
            "appliance": appliance,
            "configuration": configuration,
            **readback,
            "sync": {
                "status": str(latest.get("syncStatus") or ""),
                "last_completed_at": str(latest.get("lastSyncCompletionTimestamp") or ""),
                "outcome": sync_outcome,
                "request_accepted": request_accepted,
            },
            "manual_recovery_required": readback["configuration_readback"] == "mismatch",
        }
        if not readback["configuration_verified"]:
            raise VcfDepotTargetPartialError("Metadata synchronized, but the expected depot configuration and connection could not be verified. Inspect target depot settings before retrying.", outcome=outcome)
        if progress:
            progress(100, "succeeded")
        return outcome
