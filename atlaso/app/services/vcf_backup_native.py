"""Pinned native VCF backup API adapter for the initial backup wizard."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import quote, urlsplit
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from atlaso.app.services.vcf_certificate_remote import (
    _VIM25_NAMESPACE,
    Credentials,
    PinnedHTTPS,
    RemoteError,
    Target,
    _parse_vim25_xml,
)

_VERSION_RE = re.compile(r"^9\.1(?:\.\d+){0,3}$")
_MAX_PAGES = 100
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_SAFE_FQDN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SAFE_BASE_PATH = re.compile(r"^[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*$")
_SHA256_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_PRODUCTS = {"fleet", "sddc", "vcenter", "nsx"}


class _TransientPollUnavailable(Exception):
    """Exact HTTP 503 from a read-only native status poll."""


class NativeBackup:
    """Read and configure VCF 9.1 native backups over fingerprint-pinned HTTPS.

    Public ``current`` and ``proposed`` settings use only ``host``, ``port``,
    ``user``, ``directory``, ``ecdsa_fingerprint``, ``schedule_enabled``,
    ``full_time``, ``interval_minutes``, ``state_change``, ``retention_mode``,
    ``retention_value``, and secret-presence booleans. Fleet additionally uses
    ``schedule_timezone``, ``fleet_schedule_mode``, and the exact allowlisted
    ``fleet_schedule`` snapshot so recurrence can be reviewed and preserved.
    SDDC Manager may add ``sddc_most_recent``, ``sddc_hourly_days``, and
    ``sddc_daily_days``.
    Fleet proposals use ``ssh_fingerprint`` for the vendor-selected verified
    RSA or ECDSA key. Fleet and NSX proposals also carry its public ``host_key``
    line for verification or the native host-key algorithm field.
    SFTP/encryption secrets are sent only in native request bodies and never
    cached or included in results or raised errors.
    """

    def __init__(
        self,
        source: dict[str, Any],
        credentials: Credentials,
        *,
        transport_factory: Callable[[Target], Any] = PinnedHTTPS,
    ) -> None:
        """Initialize a native adapter for one confirmed product endpoint.

            Args:
                source: Confirmed native endpoint identity and connection metadata.
                credentials: Request-local credentials for the selected native API.
                transport_factory: Factory that creates the fingerprint-pinned transport for a resolved target.
        """
        self.source = dict(source)
        self.credentials = credentials
        self.kind = str(source.get("kind", ""))
        if self.kind not in _PRODUCTS:
            raise ValueError("Unsupported VCF backup source")
        self._validate_target(source)
        self._factory = transport_factory
        self.transport = self._new_transport(source)
        self._fleet_transport: Any | None = None
        self._fleet_service: dict[str, Any] | None = None
        self._ops_token: str | None = None
        self._fleet_token: str | None = None
        self._session: str | None = None
        self._version: str | None = None
        self._sddc_system: dict[str, Any] | None = None
        self._sddc_appliance_info: dict[str, Any] | None = None
        self._sddc_manager: dict[str, Any] | None = None
        self._nsx_cluster_id: str | None = None
        self._vcenter_instance_uuid: str | None = None
        self._inventory: dict[str, Any] | None = None
        self._fleet_backup_baseline: dict[str, set[tuple[str, str]]] = {}
        self._nsx_backup_baseline: dict[str, set[str]] = {}

    @staticmethod
    def _validate_target(source: dict[str, Any]) -> None:
        """Reject incomplete or conflicting native target details.

            Args:
                source: Target fields that must identify a previously confirmed native endpoint.
        """
        for key in ("address", "fingerprint"):
            if not isinstance(source.get(key), str) or not source[key]:
                raise ValueError("A confirmed native API target is required")
        port = source.get("port", 443)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Invalid native API port")
        if source.get("kind") == "fleet":
            if any(key in source for key in ("fleet_address", "fleet_fingerprint", "fleet_port")):
                raise ValueError("Fleet LCM target is discovered from VCF Operations")

    @staticmethod
    def _new_transport_for(
        target_data: dict[str, Any], factory: Callable[[Target], Any]
    ) -> Any:
        """Create a transport for a confirmed TLS-pinned native target.

            Args:
                target_data: Confirmed host, port, and certificate fingerprint.
                factory: Constructor called with the validated Target.
        """
        target = Target(
            host=str(target_data["address"]),
            port=int(target_data.get("port", 443)),
            fingerprint=str(target_data["fingerprint"]),
        )
        return factory(target)

    def _new_transport(self, target_data: dict[str, Any]) -> Any:
        """Create this adapter’s transport for the confirmed native target.

            Args:
                target_data: Confirmed connection data used to construct this adapter’s transport.
        """
        return self._new_transport_for(target_data, self._factory)

    def __enter__(self) -> NativeBackup:
        return self

    def __exit__(self, *_error: Any) -> None:
        """Clear request authentication state when leaving the adapter context.

            Args:
                *_error: Context-manager exception details; authentication state is cleared regardless.
        """
        self._session = None
        self._ops_token = None
        self._fleet_token = None

    @staticmethod
    def _request(
        transport: Any,
        method: str,
        path: str,
        *,
        credentials: Credentials | None = None,
        header: tuple[str, str] | None = None,
        body: Any = None,
        expected: set[int] | None = None,
        include_status: bool = False,
    ) -> Any:
        """Send one bounded request through the pinned native transport.

            Args:
                transport: Pinned HTTPS transport that sends the request.
                method: HTTP method for the native endpoint.
                path: Relative path on the confirmed target.
                credentials: Optional endpoint credentials.
                header: Optional session or bearer header.
                body: Optional JSON request body.
                expected: Optional allowed HTTP status codes.
                include_status: Whether to return status with the decoded response.
        """
        status, result = transport.request(
            method,
            path,
            credentials=credentials,
            session_header=header,
            body=body,
        )
        if expected is not None and status not in expected:
            raise RemoteError("Native backup operation returned an unexpected status")
        if include_status:
            return status, result
        return result

    def _ops_login(self) -> str:
        result = self._request(
            self.transport,
            "POST",
            "/suite-api/api/auth/token/acquire",
            body={"username": self.credentials.username, "password": self.credentials.password},
            expected={200},
        )
        token = result.get("token", result.get("accessToken")) if isinstance(result, dict) else None
        if not isinstance(token, str) or not 1 <= len(token) <= 8192:
            raise RemoteError("VCF Operations returned an invalid authentication token")
        self._ops_token = token
        return token

    def _fleet_login(self) -> str:
        # Refresh the service registry and TLS identity on every login. A
        # previously reviewed Fleet endpoint must not survive a relogin.
        self._fleet_token = None
        self._fleet_transport = None
        self._fleet_service = None
        self._version = None
        self._inventory = None
        ops = self._ops_login()
        registry = self._request(
            self.transport,
            "GET",
            "/suite-api/api/integrations/services",
            header=("Authorization", f"OpsToken {ops}"),
            expected={200},
        )
        services = registry.get("servicesDetails") if isinstance(registry, dict) else None
        if not isinstance(services, list) or len(services) > 1000:
            raise RemoteError("VCF Operations returned an invalid service registry")
        matching = [
            service for service in services
            if isinstance(service, dict) and service.get("type") == "VCF_FLEET_LCM"
        ]
        if len(matching) != 1:
            raise RemoteError("VCF Operations must advertise exactly one Fleet LCM service")
        service, advertised_pins = _fleet_service_metadata(matching[0])
        probe_target = Target(
            host=service["address"],
            port=service["port"],
            fingerprint=next(iter(sorted(advertised_pins))),
        )
        probe_transport = self._factory(probe_target)
        probe_method = getattr(probe_transport, "probe", None)
        if not callable(probe_method):
            raise RemoteError("Fleet LCM service transport cannot verify TLS identity")
        try:
            probe = probe_method()
        except RemoteError:
            raise RemoteError("Fleet LCM service TLS identity could not be verified") from None
        presented = probe.get("sha256") if isinstance(probe, dict) else None
        if isinstance(presented, str):
            presented = presented.replace(":", "").lower()
        if not isinstance(presented, str) or not _SHA256_HEX.fullmatch(presented):
            raise RemoteError("Fleet LCM service TLS probe returned an invalid certificate identity")
        if presented not in advertised_pins:
            raise RemoteError("Fleet LCM certificate is not advertised by VCF Operations")
        service["fingerprint"] = presented
        pinned_target = Target(service["address"], service["port"], presented)
        self._fleet_transport = (
            probe_transport
            if probe_target.fingerprint == presented
            else self._factory(pinned_target)
        )
        self._fleet_service = service
        result = self._request(
            self.transport,
            "POST",
            "/suite-api/api/auth/token/exchange",
            header=("Authorization", f"OpsToken {ops}"),
            body={"serviceKeys": [service["key"]]},
            expected={200},
        )
        token = result.get("jwtToken") if isinstance(result, dict) else None
        if not isinstance(token, str) or not 1 <= len(token) <= 8192:
            raise RemoteError("VCF Operations returned an invalid Fleet token")
        self._fleet_token = token
        return token

    def login(self) -> None:
        """Authenticate to the selected native API after the transport pin check."""
        if self.kind == "fleet":
            self._fleet_login()
            return
        if self.kind == "sddc":
            result = self._request(
                self.transport,
                "POST",
                "/v1/tokens",
                body={"username": self.credentials.username, "password": self.credentials.password},
                expected={200},
            )
            token = result.get("accessToken") if isinstance(result, dict) else None
        elif self.kind == "vcenter":
            status, token = self.transport.request(
                "POST", "/api/session", credentials=self.credentials
            )
            if status != 201:
                raise RemoteError("vCenter login returned an unexpected status")
        else:
            # NSX supports Basic auth on the pinned TLS connection.
            self._session = "basic"
            self._load_version()
            return
        if not isinstance(token, str) or not 1 <= len(token) <= 8192:
            raise RemoteError("Native backup API returned an invalid session")
        self._session = token
        self._load_version()

    def _header(self) -> tuple[str, str] | None:
        if self.kind == "fleet":
            return (
                ("Authorization", f"Bearer {self._fleet_token}")
                if self._fleet_token
                else None
            )
        if self.kind == "sddc":
            return ("Authorization", f"Bearer {self._session}") if self._session else None
        if self.kind == "vcenter":
            return (
                ("vmware-api-session-id", self._session)
                if self._session and self._session != "basic"
                else None
            )
        return None

    def _call(
        self, method: str, path: str, body: Any = None, *, fleet: bool = False,
        include_status: bool = False,
    ) -> Any:
        """Select the native service and send one API request.

            Args:
                method: HTTP method to send.
                path: Relative native API path.
                body: Optional JSON request body.
                fleet: Whether to route through the discovered Fleet service.
                include_status: Whether to return status with the response.
        """
        transport = self._fleet_transport if fleet else self.transport
        if transport is None:
            raise RemoteError("Fleet LCM target is unavailable")
        if fleet:
            service = self._fleet_service
            if service is None:
                raise RemoteError("Fleet LCM service has not been discovered through VCF Operations")
            path = f"/{service['base_path']}{path}"
        if self.kind == "nsx":
            return self._request(
                transport, method, path, credentials=self.credentials, body=body,
                include_status=include_status,
            )
        header = ("Authorization", f"Bearer {self._fleet_token}") if fleet else self._header()
        return self._request(
            transport, method, path, header=header, body=body,
            include_status=include_status,
        )

    def _refresh_fleet_poll_auth(self) -> None:
        """Refresh Fleet credentials only if Operations still advertises the reviewed service."""
        reviewed_service = dict(self._fleet_service or {})
        inventory = self._inventory
        version = self._version
        inventory_service = inventory.get("service") if isinstance(inventory, dict) else None
        if not reviewed_service or not isinstance(inventory_service, dict) or inventory_service != reviewed_service:
            raise RemoteError("The reviewed Fleet LCM service identity is unavailable; review the source again")
        try:
            self._fleet_login()
            if self._fleet_service != reviewed_service:
                raise RemoteError("The Fleet LCM service identity changed; review the source again")
        except Exception:
            # Never let a token minted for a changed Operations registry entry
            # reach a Fleet endpoint, and preserve only the last reviewed snapshot.
            self._fleet_token = None
            self._fleet_transport = None
            self._fleet_service = None
            self._version = version
            self._inventory = inventory
            raise
        self._version = version
        self._inventory = inventory

    def _poll_call(
        self, path: str, *, fleet: bool = False, fleet_auth_refresh: list[bool] | None = None,
    ) -> Any:
        """Read one poll endpoint with at most one Fleet credential refresh/retry.

            Args:
                path: Read-only endpoint being polled.
                fleet: Whether this request uses Fleet authentication.
                fleet_auth_refresh: Shared one-item marker limiting token refreshes for this poll.
        """
        try:
            status, result = self._call("GET", path, fleet=fleet, include_status=True)
        except RemoteError as exc:
            # PinnedHTTPS raises this fixed, sanitized error before returning
            # a response tuple. Never classify vendor text or TLS failures.
            if str(exc) == "Appliance API returned HTTP 503":
                raise _TransientPollUnavailable from None
            if str(exc) == "Appliance API returned HTTP 401":
                status, result = 401, None
            else:
                raise
        if status == 401 and fleet and fleet_auth_refresh is not None and not fleet_auth_refresh[0]:
            fleet_auth_refresh[0] = True
            self._refresh_fleet_poll_auth()
            try:
                status, result = self._call("GET", path, fleet=True, include_status=True)
            except RemoteError as exc:
                if str(exc) == "Appliance API returned HTTP 503":
                    raise _TransientPollUnavailable from None
                if str(exc) == "Appliance API returned HTTP 401":
                    status, result = 401, None
                else:
                    raise
        if status == 503:
            raise _TransientPollUnavailable
        if status == 401:
            raise RemoteError("Native backup status poll returned HTTP 401")
        if not 200 <= status < 300:
            raise RemoteError(f"Native backup status poll returned HTTP {status}")
        return result

    def _load_version(self) -> str:
        if self._version:
            return self._version
        if self.kind == "fleet":
            info = self._call("GET", "/v1/system", fleet=True)
            candidates = [
                info.get("currentVersion"), info.get("version")
            ] if isinstance(info, dict) else []
        elif self.kind == "sddc":
            appliance = self._call("GET", "/v1/system/appliance-info")
            if (
                not isinstance(appliance, dict)
                or appliance.get("role") != "SddcManager"
            ):
                raise RemoteError("Target is not an initialized SDDC Manager appliance")
            version = appliance.get("version")
            if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
                raise RemoteError("Native backup adapter supports VCF 9.1.x only")
            self._sddc_appliance_info = appliance
            self._sddc_system = self._call("GET", "/v1/system")
            candidates = [version]
        elif self.kind == "vcenter":
            info = self._call("GET", "/api/appliance/system/version")
            candidates = [info.get("version")] if isinstance(info, dict) else []
        else:
            info = self._call("GET", "/api/v1/node/version")
            candidates = [info.get("product_version")] if isinstance(info, dict) else []
        version = next((item for item in candidates if isinstance(item, str)), None)
        if not version or not _VERSION_RE.fullmatch(version):
            raise RemoteError("Native backup adapter supports VCF 9.1.x only")
        self._version = version
        return version

    def _pages(
        self, path: str, *, fleet: bool = False, poll: bool = False,
        fleet_auth_refresh: list[bool] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all bounded pages from a documented native collection.

            Args:
                path: Collection endpoint whose pages are read.
                fleet: Whether the collection belongs to Fleet LCM.
                poll: Whether this read is part of transient-aware status polling.
                fleet_auth_refresh: Shared marker limiting token refresh across all pages.
        """
        collected: list[dict[str, Any]] = []
        for page in range(1, _MAX_PAGES + 1):
            separator = "&" if "?" in path else "?"
            page_number = page if fleet else page - 1
            page_size = 100 if fleet else 50
            page_path = f"{path}{separator}pageNumber={page_number}&pageSize={page_size}"
            payload = (
                self._poll_call(page_path, fleet=fleet, fleet_auth_refresh=fleet_auth_refresh)
                if poll else self._call("GET", page_path, fleet=fleet)
            )
            if isinstance(payload, list):
                items: Any = payload
                has_more = len(items) == 100
            elif isinstance(payload, dict):
                metadata = payload.get("pageMetadata")
                items = next(
                    (payload[key] for key in (
                        "elements", "items", "results", "sddcLcms", "components",
                        "backups", "domains", "vcenters", "nsxtClusters",
                    ) if key in payload),
                    [],
                )
                if isinstance(metadata, dict) and isinstance(metadata.get("totalPages"), int):
                    if metadata["totalPages"] > _MAX_PAGES:
                        raise RemoteError("Native backup inventory exceeds the page limit")
                    has_more = page < metadata["totalPages"]
                else:
                    has_more = bool(payload.get("hasNextPage", payload.get("hasMore", False)))
            else:
                raise RemoteError("Native backup inventory is invalid")
            if not isinstance(items, list) or len(items) > 100:
                raise RemoteError("Native backup inventory is invalid")
            if any(not isinstance(item, dict) for item in items):
                raise RemoteError("Native backup inventory is invalid")
            collected.extend(items)
            if not has_more and len(items) < 100:
                return collected
            if not has_more and isinstance(payload, dict):
                return collected
        raise RemoteError("Native backup inventory exceeds the page limit")

    def _fleet_backup_records(
        self, group: str, component_id: str, *, poll: bool = False,
        fleet_auth_refresh: list[bool] | None = None,
    ) -> list[dict[str, Any]]:
        """Read backup history for one eligible Fleet component.

            Args:
                group: Reviewed SDDC-LCM group identifier.
                component_id: Eligible component whose backup records are requested.
                poll: Whether this history read is part of status polling.
                fleet_auth_refresh: Shared one-refresh marker for the Fleet token.
        """
        return self._pages(
            f"/v1/sddc-lcms/{quote(group, safe='')}/backups?componentId={quote(component_id, safe='')}",
            fleet=True, poll=poll, fleet_auth_refresh=fleet_auth_refresh,
        )

    def _fleet_current(self, group: str) -> dict[str, Any]:
        """Read group settings and prove an omitted config is unconfigured.

            Args:
                group: Selected SDDC-LCM group whose settings are inspected.
        """
        raw = self._call("GET", f"/v1/sddc-lcms/{quote(group, safe='')}", fleet=True)
        if not isinstance(raw, dict) or self._pick(raw, "id", "sddcLcmId") != group:
            raise RemoteError("Fleet LCM did not return the selected SDDC-LCM configuration")
        config = raw.get("backupConfig")
        if isinstance(config, dict):
            normalized = self._safe_fleet_settings(config)
            schedule = config.get("fullSchedule")
            schedule = schedule if isinstance(schedule, dict) else {}
            schedule_spec = schedule.get("schedule")
            schedule_spec = schedule_spec if isinstance(schedule_spec, dict) else {}
            start_time = schedule_spec.get("startTime")
            if isinstance(start_time, str):
                parsed_time = _fleet_time_parts(start_time)
                if parsed_time is None:
                    raise RemoteError("Fleet LCM returned an unsupported full backup time format")
                normalized["full_time"], normalized["schedule_timezone"] = parsed_time
            else:
                normalized["schedule_timezone"] = None
            return {
                **normalized,
                "fleet_schedule": self._safe_fleet_schedule(config),
                "configured": True,
            }
        if config is not None:
            raise RemoteError("Fleet LCM returned an unreadable backup configuration")

        # The documented collection filters distinguish groups with neither
        # schedule nor storage. Require an exact group match before treating an
        # omitted optional detail field as an unconfigured backup.
        matches = self._pages(
            "/v1/sddc-lcms?backupScheduleEnabled=false&backupStorageConfigured=false",
            fleet=True,
        )
        matching_ids = [self._pick(item, "id", "sddcLcmId") for item in matches]
        if matching_ids.count(group) == 1:
            return {
                **self._safe_fleet_settings({}), "schedule_timezone": None,
                "fleet_schedule": {}, "configured": False,
            }
        raise RemoteError(
            "Fleet LCM omitted this group's backup configuration and could not prove it has no existing schedule or storage; refusing configuration changes"
        )

    @staticmethod
    def _safe_fleet_settings(raw: Any) -> dict[str, Any]:
        """Remove secrets and unsupported fields from Fleet backup settings.

            Args:
                raw: Fleet response reduced to public backup fields.
        """
        normalized = NativeBackup._safe_settings(raw)
        normalized["ssh_fingerprint"] = normalized.pop("ecdsa_fingerprint", None)
        return normalized

    @staticmethod
    def _safe_fleet_schedule(raw: Any) -> dict[str, Any]:
        """Return the complete allowlisted Fleet schedule without normalizing it.

            Args:
                raw: Native schedule object whose documented fields are validated and retained exactly.
        """
        if not isinstance(raw, dict):
            raise RemoteError("Fleet LCM returned an unreadable backup schedule")
        result: dict[str, Any] = {}
        full = raw.get("fullSchedule")
        if full is not None:
            if not isinstance(full, dict) or set(full) - {"enabled", "schedule"}:
                raise RemoteError("Fleet LCM returned an unsupported full backup schedule")
            if "enabled" in full and not isinstance(full["enabled"], bool):
                raise RemoteError("Fleet LCM returned an invalid full backup schedule state")
            safe_full: dict[str, Any] = {}
            if "enabled" in full:
                safe_full["enabled"] = full["enabled"]
            schedule = full.get("schedule")
            if schedule is not None:
                if not isinstance(schedule, dict) or set(schedule) - {"days", "startTime"}:
                    raise RemoteError("Fleet LCM returned an unsupported full backup schedule")
                safe_schedule: dict[str, Any] = {}
                if "days" in schedule:
                    days = schedule["days"]
                    if (
                        not isinstance(days, list)
                        or not days
                        or any(
                            not isinstance(day, str)
                            or day not in {"MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"}
                            for day in days
                        )
                        or len(set(days)) != len(days)
                    ):
                        raise RemoteError("Fleet LCM returned invalid full backup schedule days")
                    safe_schedule["days"] = list(days)
                if "startTime" in schedule:
                    start_time = schedule["startTime"]
                    if not isinstance(start_time, str) or _fleet_time_parts(start_time) is None:
                        raise RemoteError("Fleet LCM returned an invalid full backup schedule time")
                    safe_schedule["startTime"] = start_time
                if full.get("enabled") is True and not {"days", "startTime"} <= set(safe_schedule):
                    raise RemoteError("Fleet LCM omitted an enabled full backup schedule")
                safe_full["schedule"] = safe_schedule
            elif full.get("enabled") is True:
                raise RemoteError("Fleet LCM omitted an enabled full backup schedule")
            result["fullSchedule"] = safe_full

        incremental = raw.get("incrementalSchedule")
        if incremental is not None:
            if not isinstance(incremental, dict) or set(incremental) - {"enabled", "interval", "fallbackToFull"}:
                raise RemoteError("Fleet LCM returned an unsupported incremental backup schedule")
            if "enabled" in incremental and not isinstance(incremental["enabled"], bool):
                raise RemoteError("Fleet LCM returned an invalid incremental backup schedule state")
            if "fallbackToFull" in incremental and not isinstance(incremental["fallbackToFull"], bool):
                raise RemoteError("Fleet LCM returned an invalid incremental backup fallback policy")
            if "interval" in incremental and (
                not isinstance(incremental["interval"], int)
                or isinstance(incremental["interval"], bool)
                or incremental["interval"] < 1
            ):
                raise RemoteError("Fleet LCM returned an invalid incremental backup interval")
            if incremental.get("enabled") is True and "interval" not in incremental:
                raise RemoteError("Fleet LCM omitted the enabled incremental backup interval")
            result["incrementalSchedule"] = dict(incremental)

        if (
            result.get("incrementalSchedule", {}).get("enabled") is True
            and result.get("fullSchedule", {}).get("enabled") is not True
        ):
            raise RemoteError("Fleet LCM returned incremental backups without enabled full backups")
        return result

    def _fleet_receiver_key(self, receiver: dict[str, Any]) -> tuple[str, str]:
        """Bind Fleet's advertised SSH thumbprint to one locally verified receiver key.

            Args:
                receiver: Confirmed receiver endpoint and verified public SSH keys.
        """
        host = receiver.get("host")
        port = receiver.get("port", 22)
        if not isinstance(host, str) or not host or not isinstance(port, int) or isinstance(port, bool):
            raise ValueError("Fleet backup receiver address is invalid")
        ecdsa_key = receiver.get("host_key")
        rsa_key = receiver.get("rsa_host_key")
        candidates: list[tuple[str, str]] = []
        if isinstance(ecdsa_key, str):
            ecdsa_fingerprint = _openssh_sha256_fingerprint(ecdsa_key, "ecdsa-sha2-nistp256")
            if receiver.get("ecdsa_fingerprint") != ecdsa_fingerprint:
                raise ValueError("The verified receiver ECDSA key does not match its fingerprint")
            candidates.append((ecdsa_fingerprint, ecdsa_key))
        if isinstance(rsa_key, str):
            rsa_fingerprint = _openssh_sha256_fingerprint(rsa_key, "ssh-rsa")
            candidates.append((rsa_fingerprint, rsa_key))
        if not candidates:
            raise ValueError("The verified receiver has no supported SSH host key")
        observed = self._fleet_ssh_thumbprint(host, port)
        matches = [(fingerprint, key) for fingerprint, key in candidates if fingerprint == observed]
        if len(matches) != 1:
            raise RemoteError("Fleet LCM SSH thumbprint does not match a verified receiver host key")
        return matches[0]

    def _fleet_ssh_thumbprint(self, host: str, port: int) -> str:
        """Ask Fleet to verify the selected receiver SSH key.

            Args:
                host: Receiver hostname sent to Fleet for thumbprint lookup.
                port: Receiver SSH port paired with that hostname.
        """
        result = self._call(
            "POST", "/v1/address-attributes?type=SSH_THUMBPRINT",
            [{"address": host, "port": port}], fleet=True,
        )
        if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
            raise RemoteError("Fleet LCM returned an ambiguous SSH thumbprint response")
        record = result[0]
        if record.get("address") != host or record.get("port") != port or record.get("error") is not None:
            raise RemoteError("Fleet LCM could not verify the selected receiver SSH thumbprint")
        observed = record.get("value")
        if not isinstance(observed, str) or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", observed):
            raise RemoteError("Fleet LCM returned an unsupported SSH thumbprint format")
        return observed

    def _fleet_require_reviewed_key(self, proposed: dict[str, Any]) -> None:
        """Ensure Fleet will use the reviewed, verified receiver key.

            Args:
                proposed: Reviewed Fleet destination and host-key selection.
        """
        host = proposed.get("host")
        port = proposed.get("port")
        key = proposed.get("host_key")
        if (
            not isinstance(host, str) or not host
            or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
            or not isinstance(key, str)
        ):
            raise ValueError("Reviewed Fleet backup receiver key details are invalid")
        key_type = key.split(None, 1)[0] if key.split() else ""
        if key_type not in {"ecdsa-sha2-nistp256", "ssh-rsa"}:
            raise ValueError("Reviewed Fleet backup receiver key algorithm is unsupported")
        fingerprint = _openssh_sha256_fingerprint(key, key_type)
        observed = self._fleet_ssh_thumbprint(host, port)
        if proposed.get("ssh_fingerprint") != fingerprint or observed != fingerprint:
            raise RemoteError("Fleet LCM receiver SSH thumbprint changed after review")

    @staticmethod
    def _public_id(value: Any) -> str:
        """Validate and bound an identifier before using it in a native path.

            Args:
                value: Native identifier that must satisfy the bounded public-ID format.
        """
        if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
            raise RemoteError("Native backup inventory has an invalid identifier")
        return value

    @staticmethod
    def _pick(item: dict[str, Any], *keys: str) -> Any:
        """Select the first present native response field alias.

            Args:
                item: Response object being searched.
                *keys: Ordered response-field aliases to check.
        """
        for key in keys:
            if key in item:
                return item[key]
        return None

    @staticmethod
    def _safe_settings(raw: Any) -> dict[str, Any]:
        """Normalize a native backup response into the public settings allowlist.

            Args:
                raw: Native backup response reduced to non-secret wizard settings.
        """
        if not isinstance(raw, dict):
            return {}
        for key, label in (
            ("backupLocations", "destinations"),
            ("backup_locations", "destinations"),
            ("backupSchedules", "schedules"),
            ("backup_schedules", "schedules"),
        ):
            if key in raw and not isinstance(raw[key], list):
                raise RemoteError(f"Native backup configuration has invalid {label}")
        locations = raw.get("backupLocations", raw.get("backup_locations"))
        if isinstance(locations, list) and (
            len(locations) > 1 or any(not isinstance(item, dict) for item in locations)
        ):
            raise RemoteError("Native backup configuration has multiple or invalid destinations")
        storage = raw.get("storage", {})
        storage = storage if isinstance(storage, dict) else {}
        destination = (
            locations[0]
            if isinstance(locations, list) and locations
            else {}
            if isinstance(locations, list)
            else raw.get("backupLocation", raw.get("backup_location", storage.get("sftp", raw.get("sftp"))))
        )
        destination = destination if isinstance(destination, dict) else {}
        full_schedule = raw.get("fullSchedule", {})
        full_schedule = full_schedule if isinstance(full_schedule, dict) else {}
        full_schedule_details = full_schedule.get("schedule", {})
        full_schedule_details = full_schedule_details if isinstance(full_schedule_details, dict) else {}
        schedules = raw.get("backupSchedules", raw.get("backup_schedules"))
        if isinstance(schedules, list):
            if len(schedules) > 1 or any(not isinstance(item, dict) for item in schedules):
                raise RemoteError("Native backup configuration has multiple or invalid schedules")
            if schedules and schedules[0].get("resourceType") != "SDDC_MANAGER":
                raise RemoteError("Native backup configuration contains an unsupported schedule resource")
            schedule = schedules[0] if schedules else {}
        else:
            schedule = raw.get("schedule", raw.get("fullBackupSchedule", raw.get("backupSchedule", {})))
        schedule = schedule if isinstance(schedule, dict) else {}
        if full_schedule:
            schedule = {**full_schedule_details, "enabled": full_schedule.get("enabled")}
        incremental = raw.get("incrementalSchedule", raw.get("incrementalBackupSchedule", {}))
        incremental = incremental if isinstance(incremental, dict) else {}
        retention = raw.get("retention", raw.get("retentionInfo", {}))
        retention = retention if isinstance(retention, dict) else {}
        if isinstance(schedule.get("retentionPolicy"), dict):
            retention = schedule["retentionPolicy"]
        encryption = raw.get("encryption")
        encryption = encryption if isinstance(encryption, dict) else {}
        full_time = NativeBackup._pick(schedule, "startTime", "start_time", "time")
        if full_time is None and isinstance(schedule.get("hourOfDay"), int):
            full_time = f"{schedule['hourOfDay']:02d}:{int(schedule.get('minuteOfHour') or 0):02d}"
        raw_days = schedule.get("days", schedule.get("daysOfWeek", []))
        days = sorted(item for item in raw_days if isinstance(item, str)) if isinstance(raw_days, list) else []
        # Never serialize native models wholesale; these are the complete public fields.
        return {
            "host": NativeBackup._pick(destination, "host", "server", "hostname"),
            "port": _normalized_port(NativeBackup._pick(destination, "port")),
            "user": NativeBackup._pick(destination, "username", "user"),
            "directory": NativeBackup._pick(destination, "directory", "directoryPath", "directory_path", "folder", "location"),
            "ecdsa_fingerprint": NativeBackup._pick(destination, "thumbprint", "sshFingerprint", "ssh_fingerprint", "fingerprint"),
            "schedule_enabled": NativeBackup._pick(schedule, "enabled", "enable", "takeScheduledBackups"),
            "full_time": _normalized_time(full_time),
            "days": days,
            "interval_minutes": NativeBackup._pick(incremental, "interval", "intervalMinutes"),
            "incremental_enabled": NativeBackup._pick(incremental, "enabled"),
            "state_change": NativeBackup._pick(schedule, "stateChange", "state_change", "takeBackupOnStateChange"),
            "retention_mode": (
                "count" if "maxBackups" in retention and "maxAgeBackups" not in retention else
                "days" if "maxAgeBackups" in retention and "maxBackups" not in retention else
                "policy" if isinstance(schedule.get("retentionPolicy"), dict)
                else NativeBackup._pick(retention, "mode", "type")
            ),
            "retention_value": (
                None if isinstance(schedule.get("retentionPolicy"), dict)
                else NativeBackup._pick(retention, "value", "maxBackups", "maxAgeBackups", "numberOfMostRecentBackups")
            ),
            "secret_configured": bool(raw.get("encryptionPassphrase") or raw.get("backup_password") or encryption.get("passphrase")),
            "sftp_secret_configured": bool(destination.get("password") or destination.get("location_password")),
            "sddc_most_recent": retention.get("numberOfMostRecentBackups"),
            "sddc_hourly_days": retention.get("numberOfDaysOfHourlyBackups"),
            "sddc_daily_days": retention.get("numberOfDaysOfDailyBackups"),
        }

    def discover(self) -> dict[str, Any]:
        """Return allowlisted native component and backup-group inventory."""
        if not self._session and not self._fleet_token:
            self.login()
        version = self._load_version()
        components: list[dict[str, Any]] = []
        groups: list[dict[str, Any]] = []
        gaps: list[dict[str, Any]] = []
        if self.kind == "fleet":
            lc_ms = self._pages("/v1/sddc-lcms", fleet=True)
            for lcm in lc_ms:
                group_id = self._public_id(self._pick(lcm, "id", "sddcLcmId"))
                current = self._fleet_current(group_id)
                component_path = f"/v1/components?sddcLcmId={quote(group_id, safe='')}"
                comp_items = self._pages(component_path, fleet=True)
                eligible_ids = {
                    self._public_id(self._pick(item, "id", "componentId"))
                    for item in self._pages(f"{component_path}&backupAllowed=true", fleet=True)
                }
                comp_ids: list[str] = []
                for item in comp_items:
                    cid = self._public_id(self._pick(item, "id", "componentId"))
                    eligible = cid in eligible_ids
                    if eligible:
                        comp_ids.append(cid)
                    product = str(self._pick(item, "componentType", "productType", "product", "type") or "Unknown")
                    components.append({
                        "id": cid, "group_id": group_id,
                        "name": str(self._pick(item, "componentTypeDescription", "name", "componentName") or product)[:160],
                        "product": product, "version": str(item.get("version") or "")[:80],
                        "supported": eligible, "current": current,
                        "warnings": ["Fleet backup configuration and schedule are shared by this entire SDDC-LCM group."] if eligible else [],
                        "native_identity": {"fqdn": item.get("fqdn"), "component_type": product},
                        **({} if eligible else {"coverage_gap": "Fleet reports backupAllowed=false for this component."}),
                    })
                management_fqdns = sorted({
                    str(item["fqdn"]).lower() for item in comp_items
                    if str(self._pick(item, "componentType", "productType", "product", "type") or "").upper() == "SDDC_MANAGER"
                    and isinstance(item.get("fqdn"), str) and item["fqdn"]
                })
                groups.append({
                    "id": group_id, "product": "fleet", "component_ids": comp_ids,
                    "current": current,
                    "native_identity": {
                        "sddc_lcm_id": group_id,
                        "sddc_manager_fqdns": management_fqdns,
                    },
                    "reservation_keys": [f"sddc-manager-fqdn:{value}" for value in management_fqdns],
                })
            if not components:
                gaps.append({"product": "fleet", "reason": "No components advertised backupAllowed=true."})
        elif self.kind == "sddc":
            manager_rows = self._pages("/v1/sddc-managers")
            appliance = self._sddc_appliance_info
            addresses = appliance.get("ipAddresses") if isinstance(appliance, dict) else None
            management_ips = {
                row.get("ipAddress") for row in addresses
                if isinstance(row, dict) and row.get("type") == "MANAGEMENT" and isinstance(row.get("ipAddress"), str)
            } if isinstance(addresses, list) else set()
            matches = [
                row for row in manager_rows
                if row.get("ipAddress") in management_ips
                and isinstance(row.get("domain"), dict)
                and row["domain"].get("type") == "MANAGEMENT"
            ]
            system_id = self._sddc_system.get("id") if isinstance(self._sddc_system, dict) else None
            if len(matches) == 1 and isinstance(matches[0].get("id"), str):
                manager = matches[0]
            elif isinstance(system_id, str) and system_id:
                appliance_name = self._pick(appliance or {}, "fqdn", "hostName", "hostname")
                manager = {
                    "id": system_id,
                    "fqdn": appliance_name if isinstance(appliance_name, str) else None,
                    "ipAddress": next(iter(management_ips), None),
                }
            else:
                raise RemoteError("SDDC Manager native resource identity is absent or ambiguous")
            self._sddc_manager = manager
            current = self._call("GET", "/v1/system/backup-configuration")
            normalized = self._safe_settings(current)
            manager_identity = {
                "resource_type": "SDDC_MANAGER",
                "sddc_manager_id": manager["id"],
                "system_id": system_id,
                "fqdn": manager.get("fqdn"),
                "ip_address": manager.get("ipAddress"),
            }
            components.append({
                "id": "sddc-manager", "group_id": "sddc-manager", "name": "SDDC Manager",
                "product": "sddc_manager", "version": version, "supported": True,
                "current": normalized, "warnings": ["The SDDC Manager backup destination is also shared with co-managed NSX.", "Direct vCenter backup is a separate component connection."],
                "native_identity": manager_identity,
                "reservation_keys": [
                    f"sddc-manager-id:{manager['id']}",
                    *([f"sddc-system-id:{system_id}"] if isinstance(system_id, str) else []),
                    *([f"sddc-manager-fqdn:{manager['fqdn'].lower()}"] if isinstance(manager.get("fqdn"), str) else []),
                ],
                "side_effects": [{
                    "product": "nsx",
                    "scope": "co-managed NSX appliances",
                    "changes": ["backup destination", "backup schedule/cadence"],
                    "limitation": "SDDC Manager has no NSX retention setting; native NSX retention is unavailable.",
                }],
            })
            groups.append({
                "id": "sddc-manager", "product": "sddc_manager",
                "component_ids": ["sddc-manager"], "current": normalized,
                "native_identity": manager_identity,
                "reservation_keys": [
                    f"sddc-manager-id:{manager['id']}",
                    *([f"sddc-system-id:{system_id}"] if isinstance(system_id, str) else []),
                    *([f"sddc-manager-fqdn:{manager['fqdn'].lower()}"] if isinstance(manager.get("fqdn"), str) else []),
                ],
                "side_effects": [{
                    "product": "nsx", "scope": "co-managed NSX appliances",
                    "changes": ["backup destination", "backup schedule/cadence"],
                    "limitation": "SDDC Manager has no NSX retention setting; native NSX retention is unavailable.",
                }],
            })
            gaps.append({"product": "nsx", "reason": "SDDC Manager backup configuration also changes the co-managed NSX destination; NSX has no native retention setting."})
            gaps.append({"product": "vcenter", "reason": "vCenter backup must be configured through a separate direct vCenter connection."})
            for path, product, name_key, id_keys in (
                ("/v1/domains", "domain", "name", ("id", "domainId")),
                ("/v1/vcenters", "vcenter", "name", ("id", "vcenterId")),
                ("/v1/nsxt-clusters", "nsx", "name", ("id", "nsxtClusterId", "clusterId")),
            ):
                for entry in self._pages(path):
                    raw_id = self._pick(entry, *id_keys)
                    if not isinstance(raw_id, str) or not raw_id:
                        continue
                    cid = self._public_id(raw_id)
                    components.append({
                        "id": cid,
                        "group_id": "sddc-manager",
                        "name": str(entry.get(name_key) or product)[:160],
                        "product": product,
                        "version": str(entry.get("version") or "")[:80],
                        "supported": False,
                        "current": {},
                        "warnings": ["This discovered resource requires a direct native appliance connection."],
                        "coverage_gap": "Not configured by the SDDC Manager backup API.",
                        "native_identity": {
                            "fqdn": entry.get("fqdn"), "ip_address": entry.get("ipAddress"),
                            **({"sddc_nsxt_cluster_id": cid} if product == "nsx" else {}),
                            **({"native_cluster_id": entry["nativeId"]} if product == "nsx" and isinstance(entry.get("nativeId"), str) else {}),
                            **({"vip_fqdn": entry["vipFqdn"]} if product == "nsx" and isinstance(entry.get("vipFqdn"), str) else {}),
                            **({"vip": entry["vip"]} if product == "nsx" and isinstance(entry.get("vip"), str) else {}),
                        },
                        **({"reservation_keys": [f"nsx-cluster-id:{entry['nativeId']}"]}
                           if product == "nsx" and isinstance(entry.get("nativeId"), str) and entry["nativeId"] else {}),
                    })
        elif self.kind == "vcenter":
            instance_uuid = self._vcenter_instance_identity()
            reservation_key = f"vcenter-instance-uuid:{instance_uuid}"
            schedules = self._vcenter_schedule_map()
            parts = self._call("GET", "/api/appliance/recovery/backup/parts")
            if not isinstance(parts, list) or not parts or len(parts) > 100:
                raise RemoteError("vCenter backup part capabilities are unavailable")
            part_ids = sorted(self._public_id(part.get("id")) for part in parts if isinstance(part, dict))
            if len(part_ids) != len(parts) or len(set(part_ids)) != len(part_ids):
                raise RemoteError("vCenter backup part capabilities are ambiguous")
            schedule_ids = list(schedules)
            for raw_id in schedule_ids:
                if not isinstance(raw_id, str):
                    raise RemoteError("vCenter backup schedule inventory is invalid")
                sid = self._public_id(raw_id)
                raw = schedules[sid]
                if not isinstance(raw, dict):
                    raise RemoteError("vCenter backup schedule inventory is invalid")
                current = self._safe_vcenter_schedule(raw)
                component = "vcenter"
                components.append({"id": component, "group_id": sid, "name": "vCenter Appliance", "product": component, "version": version, "supported": True, "current": current, "warnings": ["vCenter Recovery API has no SSH host-key fingerprint field; Atlaso verifies the receiver's ECDSA key locally, but native SFTP destination checks cannot enforce that pin."], "coverage_gap": "Native vCenter does not bind the configured SFTP ECDSA fingerprint.", "native_identity": {"instance_uuid": instance_uuid}, "reservation_keys": [reservation_key]})
                groups.append({"id": sid, "product": component, "component_ids": [component], "current": current, "native_identity": {"schedule_id": sid, "exists": True, "instance_uuid": instance_uuid}, "reservation_keys": [reservation_key]})
            if not schedule_ids:
                sid = "atlaso-vcf-backup"
                current = self._safe_vcenter_schedule({})
                components.append({"id": "vcenter", "group_id": sid, "name": "vCenter Appliance", "product": "vcenter", "version": version, "supported": True, "current": current, "warnings": ["vCenter Recovery API has no SSH host-key fingerprint field; Atlaso verifies the receiver's ECDSA key locally, but native SFTP destination checks cannot enforce that pin."], "native_identity": {"instance_uuid": instance_uuid}, "reservation_keys": [reservation_key]})
                groups.append({"id": sid, "product": "vcenter", "component_ids": ["vcenter"], "current": current, "native_identity": {"schedule_id": sid, "exists": False, "instance_uuid": instance_uuid}, "reservation_keys": [reservation_key]})
                gaps.append({"product": "vcenter", "reason": "Native API has no SFTP ECDSA host-key fingerprint field and job status has no artifact path; verify the receiver key locally and match new files independently."})
            for group in groups:
                group["backup_parts"] = part_ids
        else:
            cluster_status = self._call("GET", "/api/v1/cluster/status")
            cluster_id = (
                self._pick(cluster_status, "cluster_id", "clusterId")
                if isinstance(cluster_status, dict)
                else None
            )
            if not isinstance(cluster_id, str) or not cluster_id:
                raise RemoteError("NSX native cluster identity is absent")
            self._nsx_cluster_id = self._public_id(cluster_id)
            raw = self._call("GET", "/policy/api/v1/cluster/backups/config")
            current = self._safe_nsx(raw)
            components.append({"id": "nsx-cluster", "group_id": "nsx-cluster", "name": "NSX Cluster", "product": "nsx", "version": version, "supported": True, "current": current, "warnings": ["NSX backup API exposes no retention policy setting."]})
            groups.append({
                "id": "nsx-cluster", "product": "nsx",
                "component_ids": ["nsx-cluster"], "current": current,
                "native_identity": {"cluster_id": self._nsx_cluster_id},
                "reservation_keys": [f"nsx-cluster-id:{self._nsx_cluster_id}"],
            })
            gaps.append({"product": "nsx", "reason": "Native NSX backup API has no retention configuration; retention cannot be promised."})
        native_identity = (
            self._sddc_system.get("id")
            if self.kind == "sddc" and self._sddc_system
            else self._nsx_cluster_id
            if self.kind == "nsx"
            else self._vcenter_instance_uuid
            if self.kind == "vcenter"
            else None
        )
        if self.kind == "fleet":
            if self._fleet_service is None:
                raise RemoteError("Fleet LCM service metadata is unavailable")
            identity_material = {
                **self._fleet_service,
                "group_ids": sorted(group["id"] for group in groups),
            }
            identity_digest = hashlib.sha256(
                json.dumps(identity_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            identity = f"fleet:{self._fleet_service['address']}:{self._fleet_service['fingerprint']}:{identity_digest}"
        else:
            identity = f"{self.kind}:{native_identity or self.source['address']}"
        self._inventory = {
            "identity": identity,
            "version": version,
            "components": components,
            "groups": groups,
            "coverage_gaps": gaps,
            **({"service": dict(self._fleet_service)} if self.kind == "fleet" and self._fleet_service else {}),
        }
        return self._inventory

    def _vcenter_schedule_map(self) -> dict[str, dict[str, Any]]:
        schedules = self._call("GET", "/api/appliance/recovery/backup/schedules")
        if not isinstance(schedules, dict) or len(schedules) > 1:
            raise RemoteError("vCenter must expose an unambiguous native backup schedule map")
        normalized: dict[str, dict[str, Any]] = {}
        for raw_id, schedule in schedules.items():
            if not isinstance(raw_id, str) or not isinstance(schedule, dict):
                raise RemoteError("vCenter backup schedule inventory is invalid")
            normalized[self._public_id(raw_id)] = schedule
        return normalized

    def _vcenter_instance_identity(self) -> str:
        """Read stable vCenter identity from the documented vSphere SOAP ServiceContent."""
        if self._vcenter_instance_uuid is not None:
            return self._vcenter_instance_uuid
        envelope = (
            f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:vim25="{_VIM25_NAMESPACE}"><soapenv:Body>'
            '<vim25:RetrieveServiceContent><_this type="ServiceInstance">ServiceInstance</_this>'
            '</vim25:RetrieveServiceContent></soapenv:Body></soapenv:Envelope>'
        )
        _status, content = self.transport.request(
            "POST", "/sdk", xml_body=envelope, soap_namespace="vim25"
        )
        if not isinstance(content, str):
            raise RemoteError("vCenter service content did not include a stable instance identity")
        response = _parse_vim25_xml(content, "RetrieveServiceContentResponse")
        about = next(
            (node for node in response.iter() if node.tag.rsplit("}", 1)[-1] == "about"),
            None,
        )
        instance_uuid = next(
            (node for node in about.iter() if node.tag.rsplit("}", 1)[-1] == "instanceUuid"),
            None,
        ) if about is not None else None
        raw_value = (instance_uuid.text or "").strip() if instance_uuid is not None else ""
        try:
            normalized = str(UUID(raw_value))
        except (ValueError, AttributeError):
            raise RemoteError("vCenter service content did not include a valid instance identity") from None
        self._vcenter_instance_uuid = normalized
        return normalized

    @staticmethod
    def _safe_vcenter_schedule(raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize the documented vCenter Recovery schedule fields.

            Args:
                raw: vCenter schedule response to normalize without exposing secrets.
        """
        recurrence = raw.get("recurrence_info") or raw.get("recurrenceInfo") or {}
        retention = raw.get("retention_info") or raw.get("retentionInfo") or {}
        if not isinstance(recurrence, dict):
            recurrence = {}
        if not isinstance(retention, dict):
            retention = {}
        location = raw.get("location")
        parsed = urlsplit(location) if isinstance(location, str) else None
        return {
            "host": parsed.hostname if parsed else None,
            "port": parsed.port if parsed and parsed.port else 22,
            "user": raw.get("location_user", raw.get("locationUser")),
            "directory": parsed.path if parsed else location,
            "ecdsa_fingerprint": None,
            "schedule_enabled": raw.get("enable"),
            "full_time": (
                f"{int(recurrence.get('hour') or 0):02d}:{int(recurrence.get('minute') or 0):02d}"
                if recurrence
                else None
            ), "interval_minutes": None,
            "state_change": None, "retention_mode": "count" if retention else None,
            "retention_value": retention.get("max_count") if isinstance(retention, dict) else None,
            "incremental_enabled": None,
            "parts": sorted(raw.get("parts", [])) if isinstance(raw.get("parts", []), list) else [],
            "days": sorted(recurrence.get("days", [])) if isinstance(recurrence.get("days", []), list) else [],
            "secret_configured": bool(raw.get("backup_password", raw.get("backupPassword"))),
            "sftp_secret_configured": bool(raw.get("location_password", raw.get("locationPassword"))),
        }

    @staticmethod
    def _safe_nsx(raw: Any) -> dict[str, Any]:
        """Normalize the documented NSX backup configuration fields.

            Args:
                raw: NSX backup configuration response to normalize without exposing credentials.
        """
        if not isinstance(raw, dict):
            raise RemoteError("NSX backup configuration is invalid")
        server = raw.get("remote_file_server", raw.get("remoteFileServer", {})) or {}
        if not isinstance(server, dict):
            raise RemoteError("NSX backup configuration is invalid")
        protocol = server.get("protocol") or {}
        if not isinstance(protocol, dict):
            raise RemoteError("NSX backup configuration is invalid")
        auth = protocol.get("authentication_scheme", protocol.get("authenticationScheme", {})) or {}
        schedule = raw.get("backup_schedule", raw.get("backupSchedule", {})) or {}
        if not isinstance(auth, dict) or not isinstance(schedule, dict):
            raise RemoteError("NSX backup configuration is invalid")
        resource_type = schedule.get("resource_type", schedule.get("resourceType"))
        interval_seconds = schedule.get("seconds_between_backups", schedule.get("secondsBetweenBackups"))
        if resource_type == "WeeklyBackupSchedule":
            hour = schedule.get("hour_of_day", schedule.get("hourOfDay", 0))
            minute = schedule.get("minute_of_day", schedule.get("minuteOfDay", 0))
            hour_value = hour if isinstance(hour, int) else 0
            minute_value = minute if isinstance(minute, int) else 0
            full_time = f"{hour_value:02d}:{minute_value:02d}"
        else:
            full_time = None
        return {
            "host": server.get("server"), "port": server.get("port"),
            "user": auth.get("username"), "directory": server.get("directory_path", server.get("directoryPath")),
            "ecdsa_fingerprint": protocol.get("ssh_fingerprint", protocol.get("sshFingerprint")), "schedule_enabled": raw.get("backup_enabled", raw.get("backupEnabled")),
            "full_time": full_time, "interval_minutes": (int(interval_seconds) // 60 if isinstance(interval_seconds, int) else None),
            "state_change": bool(raw.get("after_inventory_update_interval", raw.get("afterInventoryUpdateInterval"))),
            "incremental_enabled": None,
            "retention_mode": None, "retention_value": None,
            "secret_configured": bool(raw.get("passphrase")),
            "sftp_secret_configured": bool(auth.get("password")),
        }

    def proposed(self, group: str, policy: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
        """Build a normalized public proposal; secret values are accepted only by configure.

            Args:
                group: Selected native backup group.
                policy: Operator choices for recurrence and retention.
                receiver: Applied receiver endpoint and verified public SSH keys.
        """
        current_group = self._group(group)
        product = current_group["product"]
        retention_mode = None if product == "nsx" else policy.get("retention_mode", "count")
        if retention_mode is not None and retention_mode not in {"count", "days"}:
            raise ValueError("Retention mode must be count or days")
        retention_value = None if retention_mode is None else policy.get("retention_value", 14)
        if retention_value is not None and (not isinstance(retention_value, int) or not 1 <= retention_value <= 365):
            raise ValueError("Retention value must be between 1 and 365")
        full_time = policy.get("full_time", "02:00")
        if not isinstance(full_time, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", full_time):
            raise ValueError("Backup time must use 24-hour HH:MM format")
        host = receiver.get("host")
        user = receiver.get("username", receiver.get("user"))
        directory = receiver.get("directory")
        fingerprint = receiver.get("ecdsa_fingerprint")
        port = receiver.get("port", 22)
        if not all(isinstance(item, str) and item for item in (host, user, directory, fingerprint)):
            raise ValueError("Backup receiver details are incomplete")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Invalid backup receiver port")
        value = {
            "host": host, "port": port, "user": user, "directory": directory,
            "ecdsa_fingerprint": fingerprint, "schedule_enabled": True,
            "full_time": full_time, "interval_minutes": policy.get("nsx_interval_minutes", 60),
            "state_change": bool(policy.get("state_change", True)),
            "incremental_enabled": None,
            "retention_mode": retention_mode, "retention_value": retention_value,
            "secret_configured": True, "sftp_secret_configured": True,
        }
        if product == "sddc_manager":
            value["retention_mode"] = "policy"
            value["retention_value"] = None
            value["interval_minutes"] = None
            value["days"] = sorted(["SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY"])
        elif product == "nsx":
            value["full_time"] = None
        elif product == "fleet":
            current_schedule = current_group["current"].get("fleet_schedule", {})
            value["fleet_schedule_mode"] = policy.get("fleet_schedule_mode", "preserve")
            if (
                not isinstance(value["fleet_schedule_mode"], str)
                or value["fleet_schedule_mode"] not in {"preserve", "daily", "disabled"}
            ):
                raise ValueError("Fleet schedule mode must be preserve, daily, or disabled")
            current_full = current_schedule.get("fullSchedule", {}) if isinstance(current_schedule, dict) else {}
            current_full_schedule = current_full.get("schedule", {}) if isinstance(current_full, dict) else {}
            current_start = current_full_schedule.get("startTime") if isinstance(current_full_schedule, dict) else None
            current_time = _fleet_time_parts(current_start) if isinstance(current_start, str) else None
            value["schedule_timezone"] = (
                "UTC" if value["fleet_schedule_mode"] == "daily"
                else current_time[1] if current_time else None
            )
            value["state_change"] = None
            value["ssh_fingerprint"], value["host_key"] = self._fleet_receiver_key(receiver)
            value.pop("ecdsa_fingerprint", None)
            schedule_proposal = {
                **value,
                "fleet_schedule": current_schedule,
                "fleet_incremental_mode": policy.get("fleet_incremental_mode", "preserve"),
                "fleet_incremental_interval_minutes": policy.get("fleet_incremental_interval_minutes", 240),
                "fleet_incremental_fallback_to_full": policy.get("fleet_incremental_fallback_to_full", True),
            }
            value["fleet_schedule"] = self._fleet_schedule_spec(schedule_proposal)
            full = value["fleet_schedule"].get("fullSchedule", {})
            full_schedule = full.get("schedule", {}) if isinstance(full, dict) else {}
            full_schedule = full_schedule if isinstance(full_schedule, dict) else {}
            incremental = value["fleet_schedule"].get("incrementalSchedule", {})
            incremental = incremental if isinstance(incremental, dict) else {}
            raw_time = full_schedule.get("startTime")
            parsed_time = _fleet_time_parts(raw_time) if isinstance(raw_time, str) else None
            value["schedule_enabled"] = full.get("enabled") if isinstance(full, dict) else None
            value["full_time"] = parsed_time[0] if parsed_time else None
            value["schedule_timezone"] = parsed_time[1] if parsed_time else None
            value["days"] = sorted(full_schedule.get("days", []))
            value["interval_minutes"] = incremental.get("interval")
            value["incremental_enabled"] = incremental.get("enabled")
        elif product == "vcenter":
            if retention_mode != "count":
                raise ValueError("vCenter native retention supports backup count only")
            value["interval_minutes"] = None
            value["state_change"] = None
            value["ecdsa_fingerprint"] = None
            value["parts"] = current_group["backup_parts"]
            value["days"] = sorted(["SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY"])
        if product != "fleet" and isinstance(receiver.get("host_key"), str):
            value["host_key"] = receiver["host_key"][:1024]
        if product == "sddc_manager":
            limits = (("sddc_most_recent", 10, 1, 600), ("sddc_hourly_days", 2, 0, 14), ("sddc_daily_days", 15, 0, 30))
            for key, default, lower, upper in limits:
                selected = policy.get(key, default)
                if not isinstance(selected, int) or not lower <= selected <= upper:
                    raise ValueError(f"{key} must be between {lower} and {upper}")
                value[key] = selected
        return value

    def _group(self, group: str) -> dict[str, Any]:
        """Find an inspected native backup group by its stable identifier.

            Args:
                group: Native group identifier to retrieve from inspected inventory.
        """
        if self._inventory is None:
            self.discover()
        assert self._inventory is not None
        for item in self._inventory["groups"]:
            if isinstance(item, dict) and item.get("id") == group:
                return dict(item)
        raise ValueError("Unknown native backup group")

    def current(self, group: str) -> dict[str, Any]:
        """Perform the native backup operation described by this method name.

            Args:
                group: Native group whose current settings are read.
        """
        item = self._group(group)
        if self.kind == "fleet":
            return self._fleet_current(group)
        if self.kind == "sddc":
            return self._safe_settings(self._call("GET", "/v1/system/backup-configuration"))
        if self.kind == "nsx":
            return self._safe_nsx(self._call("GET", "/policy/api/v1/cluster/backups/config"))
        if item["native_identity"].get("exists") is not True:
            schedules = self._vcenter_schedule_map()
            schedule_id = item["native_identity"]["schedule_id"]
            if not schedules:
                return self._safe_vcenter_schedule({})
            if schedule_id not in schedules:
                raise RemoteError("A different vCenter backup schedule appeared after discovery; review the changed native state before making changes")
            raw = self._call("GET", f"/api/appliance/recovery/backup/schedules/{quote(schedule_id, safe='')}")
            if not isinstance(raw, dict):
                raise RemoteError("vCenter did not return the newly discovered native backup schedule")
            return self._safe_vcenter_schedule(raw)
        raw = self._call("GET", f"/api/appliance/recovery/backup/schedules/{quote(item['native_identity']['schedule_id'], safe='')}")
        return self._safe_vcenter_schedule(raw if isinstance(raw, dict) else {})

    def configure(self, group: str, proposed: dict[str, Any], sftp_password: str, encryption_passphrase: str) -> dict[str, Any]:
        """Update only the selected native group's backup destination and schedule.

            Args:
                group: Selected native group whose destination and policy are changed.
                proposed: Reviewed public proposal bound to inspected state.
                sftp_password: Transient receiver password sent only in the native write.
                encryption_passphrase: Transient recovery passphrase sent only in the native write.
        """
        item = self._group(group)
        self._load_version()
        if not isinstance(sftp_password, str) or not sftp_password or not isinstance(encryption_passphrase, str) or not encryption_passphrase:
            raise ValueError("Backup SFTP and encryption secrets are required")
        _validate_encryption_passphrase(self.kind, encryption_passphrase)
        if self.kind == "fleet":
            group_components = set(item["component_ids"])
            if set(proposed.get("component_ids", item["component_ids"])) != group_components:
                raise ValueError("Fleet backup settings apply to every component in the selected SDDC-LCM group")
            self._fleet_require_reviewed_key(proposed)
            body = self._fleet_config_body(proposed, sftp_password, encryption_passphrase)
            result = self._call("PATCH", f"/v1/sddc-lcms/{quote(group, safe='')}", {"backupConfigSpec": body}, fleet=True)
            task_id = _extract_task_id(result)
            if task_id is None:
                raise RemoteError("Fleet backup configuration returned no task reference")
            return {"native_task_id": task_id}
        if self.kind == "sddc":
            body = self._sddc_config_body(proposed, sftp_password, encryption_passphrase)
            self._call("PUT", "/v1/system/backup-configuration", body)
            return {}
        if self.kind == "nsx":
            interval = int(proposed.get("interval_minutes", 60))
            if not 5 <= interval <= 1440:
                raise ValueError("NSX backup interval must be between 5 minutes and 24 hours")
            public_key = proposed.get("host_key")
            if not isinstance(public_key, str) or not public_key.strip():
                raise ValueError("NSX backup configuration requires the receiver ECDSA public host key")
            nsx_body: dict[str, Any] = {
                "backup_enabled": True,
                "backup_schedule": {
                    "resource_type": "IntervalBackupSchedule",
                    "seconds_between_backups": interval * 60,
                },
                "inventory_summary_interval": 3600,
                "remote_file_server": {
                    "server": proposed["host"], "port": proposed["port"],
                    "protocol": {
                        "protocol_name": "sftp",
                        "ssh_fingerprint": proposed["ecdsa_fingerprint"],
                        "host_key_algorithm": public_key.split(None, 1)[0],
                        "authentication_scheme": {
                            "scheme_name": "PASSWORD", "username": proposed["user"],
                            "password": sftp_password,
                        },
                    },
                    "directory_path": proposed["directory"],
                },
                "passphrase": encryption_passphrase,
            }
            if proposed.get("state_change", True):
                nsx_body["after_inventory_update_interval"] = 3600
            self._call("PUT", "/policy/api/v1/cluster/backups/config", nsx_body)
            return {}
        if self.kind == "vcenter":
            if proposed.get("retention_mode") != "count":
                raise ValueError("vCenter native backup retention supports backup count only")
            schedule_id = item["native_identity"]["schedule_id"]
            spec = self._vcenter_schedule_spec(proposed, sftp_password, encryption_passphrase)
            if item["native_identity"].get("exists") is True:
                self._call("PATCH", f"/api/appliance/recovery/backup/schedules/{quote(schedule_id, safe='')}", spec)
            else:
                if self._vcenter_schedule_map():
                    raise RemoteError("A vCenter backup schedule appeared after discovery; refusing to create or replace it")
                self._call("POST", "/api/appliance/recovery/backup/schedules", {"schedule": schedule_id, "spec": spec})
            return {}
        raise RemoteError("Unsupported native backup product")

    def configuration_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Poll asynchronous Fleet configuration tasks; report sync writes complete.

            Args:
                group: Selected native group for the recorded configuration task.
                reference: Persisted task reference from the single native configuration write.
        """
        self._group(group)
        if (
            not isinstance(reference, dict)
            or reference.get("kind") not in (None, self.kind)
            or reference.get("group_id") not in (None, group)
        ):
            raise ValueError("Native configuration reference does not match this group")
        task_id = reference.get("native_task_id")
        if self.kind != "fleet" or not isinstance(task_id, str):
            return {"state": "succeeded"}
        fleet_auth_refresh = [False]
        try:
            raw = self._poll_call(
                f"/v1/tasks/{quote(self._public_id(task_id), safe='')}",
                fleet=True, fleet_auth_refresh=fleet_auth_refresh,
            )
        except _TransientPollUnavailable:
            return {
                "state": "running",
                "warning": "Fleet configuration status is temporarily unavailable (HTTP 503); polling will continue using the recorded task reference.",
            }
        return {"state": _state(self._pick(raw, "status", "state")) if isinstance(raw, dict) else "running"}

    @staticmethod
    def _vcenter_schedule_spec(proposed: dict[str, Any], sftp_password: str, passphrase: str) -> dict[str, Any]:
        """Build the vCenter Recovery schedule request body.

            Args:
                proposed: Reviewed vCenter destination, recurrence, and retention.
                sftp_password: Transient SFTP password for the vCenter schedule.
                passphrase: Transient backup encryption passphrase for the vCenter schedule.
        """
        hour, minute = (int(part) for part in proposed["full_time"].split(":"))
        return {
            "parts": proposed["parts"],
            "location": _vcenter_location(proposed),
            "location_user": proposed["user"],
            "location_password": sftp_password,
            "backup_password": passphrase,
            "enable": True,
            "recurrence_info": {
                "hour": hour, "minute": minute,
                "days": proposed.get("days", sorted(["SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY"])),
            },
            "retention_info": {"max_count": proposed["retention_value"]},
        }

    @staticmethod
    def _fleet_schedule_spec(proposed: dict[str, Any]) -> dict[str, Any]:
        """Build Fleet's reviewed recurring schedule payload from intent and its current snapshot.

            Args:
                proposed: Reviewed Fleet recurrence intent and inspected schedule snapshot.
        """
        schedule_mode = proposed.get("fleet_schedule_mode")
        if schedule_mode is None:
            # Legacy reviewed operations predate explicit schedule intent.
            if proposed.get("schedule_timezone") != "UTC":
                raise ValueError("Fleet backup schedule times must be reviewed and configured in UTC")
            full_time = proposed.get("full_time")
            if not isinstance(full_time, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", full_time):
                raise ValueError("Fleet backup time must use 24-hour HH:MM format")
            schedule_spec: dict[str, Any] = {
                "fullSchedule": {
                    "enabled": True,
                    "schedule": {
                        "days": ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"],
                        "startTime": str(proposed.get("full_time", "02:00")) + ":00Z",
                    },
                },
            }
            if isinstance(proposed.get("interval_minutes"), int) and isinstance(proposed.get("incremental_enabled"), bool):
                schedule_spec["incrementalSchedule"] = {
                    "enabled": proposed["incremental_enabled"],
                    "interval": proposed["interval_minutes"],
                    "fallbackToFull": True,
                }
        else:
            if not isinstance(schedule_mode, str) or schedule_mode not in {"preserve", "daily", "disabled"}:
                raise ValueError("Fleet schedule mode must be preserve, daily, or disabled")
            incremental_mode = proposed.get("fleet_incremental_mode", "preserve")
            if not isinstance(incremental_mode, str) or incremental_mode not in {"preserve", "enabled", "disabled"}:
                raise ValueError("Fleet incremental mode must be preserve, enabled, or disabled")
            if schedule_mode != "daily" and incremental_mode != "preserve":
                raise ValueError("Changing Fleet incremental backups requires daily full backups")
            current = NativeBackup._safe_fleet_schedule(proposed.get("fleet_schedule", {}))
            if schedule_mode == "preserve":
                schedule_spec = dict(current)
                schedule_spec.setdefault("fullSchedule", {"enabled": False})
                schedule_spec.setdefault("incrementalSchedule", {"enabled": False})
            elif schedule_mode == "daily":
                if proposed.get("schedule_timezone") != "UTC":
                    raise ValueError("Fleet daily backup times must be reviewed and configured in UTC")
                full_time = proposed.get("full_time")
                if not isinstance(full_time, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", full_time):
                    raise ValueError("Fleet backup time must use 24-hour HH:MM format")
                schedule_spec = {
                    "fullSchedule": {
                        "enabled": True,
                        "schedule": {
                            "days": ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"],
                            "startTime": full_time + ":00Z",
                        },
                    },
                }
                if "incrementalSchedule" in current:
                    schedule_spec["incrementalSchedule"] = current["incrementalSchedule"]
                if incremental_mode == "enabled":
                    interval = proposed.get("fleet_incremental_interval_minutes", 240)
                    fallback = proposed.get("fleet_incremental_fallback_to_full", True)
                    if type(interval) is not int or not 240 <= interval <= 2147483647:
                        raise ValueError("Fleet incremental interval must be a whole number of at least 240 minutes")
                    if not isinstance(fallback, bool):
                        raise ValueError("Fleet incremental fallback must be a boolean")
                    schedule_spec["incrementalSchedule"] = {
                        "enabled": True, "interval": interval, "fallbackToFull": fallback,
                    }
                elif incremental_mode == "disabled":
                    schedule_spec["incrementalSchedule"] = {
                        **current.get("incrementalSchedule", {}), "enabled": False,
                    }
            else:
                full = dict(current.get("fullSchedule", {}))
                full["enabled"] = False
                schedule_spec = {"fullSchedule": full}
                if "incrementalSchedule" in current:
                    incremental = dict(current["incrementalSchedule"])
                    incremental["enabled"] = False
                    schedule_spec["incrementalSchedule"] = incremental
                else:
                    schedule_spec["incrementalSchedule"] = {"enabled": False}
        return schedule_spec

    @staticmethod
    def _fleet_config_body(proposed: dict[str, Any], sftp_password: str, passphrase: str) -> dict[str, Any]:
        """Build the Fleet destination and recurrence write body.

            Args:
                proposed: Reviewed Fleet destination, recurrence, and retention.
                sftp_password: Transient receiver password for the Fleet request body.
                passphrase: Transient encryption passphrase for the Fleet request body.
        """
        schedule_spec = NativeBackup._fleet_schedule_spec(proposed)
        body: dict[str, Any] = {
            "encryptionPassphrase": passphrase,
            "storage": {"sftp": {
                "host": proposed["host"], "port": str(proposed["port"]),
                "username": proposed["user"], "password": sftp_password,
                "directory": proposed["directory"],
                "thumbprint": proposed.get("ssh_fingerprint", proposed.get("ecdsa_fingerprint")),
            }},
            "retention": ({"maxBackups": proposed["retention_value"]} if proposed["retention_mode"] == "count" else {"maxAgeBackups": proposed["retention_value"]}),
        }
        body.update(schedule_spec)
        return body

    @staticmethod
    def _sddc_config_body(proposed: dict[str, Any], sftp_password: str, passphrase: str) -> dict[str, Any]:
        """Build the SDDC Manager destination and schedule write body.

            Args:
                proposed: Reviewed SDDC Manager destination, recurrence, and retention.
                sftp_password: Transient receiver password for the SDDC Manager request body.
                passphrase: Transient encryption passphrase for the SDDC Manager request body.
        """
        return {
            "encryption": {"passphrase": passphrase},
            "backupLocations": [{
                "server": proposed["host"], "port": proposed["port"], "protocol": "SFTP",
                "username": proposed["user"], "password": sftp_password,
                "directoryPath": proposed["directory"], "sshFingerprint": proposed["ecdsa_fingerprint"],
            }],
            "backupSchedules": [{
                "resourceType": "SDDC_MANAGER", "takeScheduledBackups": True,
            "frequency": "WEEKLY", "daysOfWeek": ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"],
                "hourOfDay": int(proposed["full_time"].split(":")[0]),
                "minuteOfHour": int(proposed["full_time"].split(":")[1]),
                "takeBackupOnStateChange": bool(proposed.get("state_change", True)),
                "retentionPolicy": {
                    "numberOfMostRecentBackups": proposed.get("sddc_most_recent", 10),
                    "numberOfDaysOfHourlyBackups": proposed.get("sddc_hourly_days", 2),
                    "numberOfDaysOfDailyBackups": proposed.get("sddc_daily_days", 15),
                },
            }],
        }

    def validate(self, group: str, proposed: dict[str, Any], sftp_password: str, encryption_passphrase: str) -> dict[str, Any]:
        """Run the vendor's documented non-mutating destination validation when available.

            Args:
                group: Selected native group to validate.
                proposed: Reviewed destination settings to check without mutation.
                sftp_password: Transient receiver password used only by the validation request.
                encryption_passphrase: Transient backup passphrase used only by the validation request.
        """
        self._group(group)
        self._load_version()
        if not sftp_password or not encryption_passphrase:
            raise ValueError("Backup SFTP and encryption secrets are required")
        _validate_encryption_passphrase(self.kind, encryption_passphrase)
        if self.kind == "sddc":
            result = self._call(
                "POST", "/v1/system/backup-configuration/validations",
                self._sddc_config_body(proposed, sftp_password, encryption_passphrase),
            )
            return _validation_result(result)
        if self.kind == "vcenter":
            body = {
                "parts": proposed["parts"],
                "location_type": "SFTP", "location": _vcenter_location(proposed),
                "location_user": proposed["user"], "location_password": sftp_password,
                "backup_password": encryption_passphrase,
            }
            return _validation_result(self._call("POST", "/api/appliance/recovery/backup?action=validate", body))
        if self.kind == "fleet":
            self._fleet_require_reviewed_key(proposed)
            return {
                "supported": False,
                "warning": "Fleet LCM SSH thumbprint matches the reviewed receiver key; native destination authentication is not validated until the first backup.",
            }
        return {
            "supported": False,
            "warning": "This product has no documented native destination-validation endpoint; its initial backup is the first end-to-end validation.",
        }

    def start_backup(self, group: str, component_ids: list[str]) -> dict[str, Any]:
        """Start the explicitly selected native backup operation once.

            Args:
                group: Selected native group for the one initial backup.
                component_ids: Exact eligible component IDs included in the native request.
        """
        item = self._group(group)
        self._load_version()
        allowed = set(item["component_ids"])
        if not component_ids or len(set(component_ids)) != len(component_ids) or not set(component_ids) <= allowed:
            raise ValueError("Select valid components from the backup group")
        baseline_ref: dict[str, Any] = {}
        if self.kind == "fleet":
            if set(component_ids) != allowed:
                raise ValueError("Fleet backup operation must include every eligible component in its shared group")
            baseline: set[tuple[str, str]] = set()
            for component_id in component_ids:
                baseline.update(
                    (component_id, key)
                    for record in self._fleet_backup_records(group, component_id)
                    if (key := _fleet_record_identity(record)) is not None
                )
            self._fleet_backup_baseline[group] = baseline
            baseline_ref = {
                "fleet_artifacts": [
                    {"component_id": component_id, "key": key}
                    for component_id, key in sorted(baseline)
                ]
            }
            result = self._call("POST", f"/v1/sddc-lcms/{quote(group, safe='')}/backups", {"actionType": "ComponentsBackupSpec", "componentIds": component_ids}, fleet=True)
        elif self.kind == "sddc":
            if component_ids != ["sddc-manager"]:
                raise ValueError("Only the SDDC_MANAGER backup resource is currently verified")
            result = self._call("POST", "/v1/backups/tasks", {"elements": [{"resourceType": "SDDC_MANAGER"}]})
        elif self.kind == "nsx":
            if component_ids != ["nsx-cluster"]:
                raise ValueError("Select the NSX cluster backup component")
            history = self._call("GET", "/policy/api/v1/cluster/backups/history")
            ids = _nsx_backup_ids(history)
            if len(ids) > 500:
                raise RemoteError("NSX backup history exceeds the baseline limit")
            self._nsx_backup_baseline[group] = ids
            baseline_ref = {"nsx_backup_ids": sorted(ids)}
            result = self._call("POST", "/policy/api/v1/cluster?action=backup_to_remote", {})
        else:
            schedule_id = item["native_identity"]["schedule_id"]
            result = self._call(
                "POST",
                f"/api/appliance/recovery/backup/schedules/{quote(schedule_id, safe='')}?action=run",
                {},
            )
        task_id = _extract_task_id(result)
        if self.kind in {"fleet", "sddc", "vcenter"} and task_id is None:
            raise RemoteError("Native backup start returned no task reference")
        reference: dict[str, Any] = {"kind": self.kind, "group_id": group}
        if task_id is not None:
            reference["native_task_id"] = task_id
        reference["component_ids"] = list(component_ids)
        reference["started_at"] = datetime.now(timezone.utc).isoformat()
        reference.update(baseline_ref)
        return {"reference": reference}

    def backup_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Perform the native backup operation described by this method name.

            Args:
                group: Selected native group being reconciled.
                reference: Persisted task and artifact baseline for read-only status checks.
        """
        if not isinstance(reference, dict) or reference.get("kind") not in (None, self.kind) or reference.get("group_id") not in (None, group):
            raise ValueError("Native backup reference does not match this group")
        item = self._group(group)
        component_ids = reference.get("component_ids")
        if not isinstance(component_ids, list) or component_ids != item["component_ids"]:
            raise ValueError("Native backup reference has invalid component coverage")
        started_at = reference.get("started_at")
        if not isinstance(started_at, str) or not started_at:
            raise ValueError("Native backup reference has no start timestamp")
        raw_ref = reference.get("native_task_id")
        if self.kind != "nsx" and not isinstance(raw_ref, str):
            raise ValueError("Native backup reference is missing its task ID")
        ref = self._public_id(raw_ref) if isinstance(raw_ref, str) else ""
        if self.kind == "fleet":
            baseline_items = reference.get("fleet_artifacts")
            if not isinstance(baseline_items, list) or len(baseline_items) > 10000:
                raise ValueError("Fleet backup reference has an invalid artifact baseline")
            if any(
                not isinstance(entry, dict)
                or entry.get("component_id") not in component_ids
                or not isinstance(entry.get("key"), str)
                for entry in baseline_items
            ):
                raise ValueError("Fleet backup reference has an invalid artifact baseline")
            try:
                fleet_auth_refresh = [False]
                raw = self._poll_call(
                    f"/v1/tasks/{quote(ref, safe='')}",
                    fleet=True, fleet_auth_refresh=fleet_auth_refresh,
                )
            except _TransientPollUnavailable:
                return {
                    **_pending_poll_result(ref, "Fleet backup status is temporarily unavailable (HTTP 503); polling will continue using the recorded task reference."),
                    "native_task_state": "running",
                    "native_task_terminal": False,
                    "native_task_status": None,
                }
            raw_task_status = self._pick(raw, "status", "state") if isinstance(raw, dict) else None
            native_task_state = _state(raw_task_status)
            task_status = str(raw_task_status or "").upper()
            terminal_statuses = {
                "SUCCEEDED", "SUCCESS", "COMPLETED", "COMPLETED_WITH_WARNINGS", "FINISHED",
                "FAILED", "ERROR", "CANCELLED", "CANCELED",
            }
            native_task_terminal = task_status in terminal_statuses
            public_task_status = task_status if task_status in terminal_statuses | {"RUNNING", "PENDING", "SCHEDULED", "QUEUED"} else None
            state = native_task_state
            if state == "failed":
                return {
                    "state": "failed",
                    "native_task_state": native_task_state,
                    "native_task_terminal": native_task_terminal,
                    "native_task_status": public_task_status,
                    "artifacts": [],
                    "native_task_id": ref,
                }
            records: list[dict[str, Any]] = []
            for component_id in item["component_ids"]:
                try:
                    entries = self._fleet_backup_records(
                        group, component_id, poll=True,
                        fleet_auth_refresh=fleet_auth_refresh,
                    )
                except _TransientPollUnavailable:
                    return {
                        **_pending_poll_result(ref, "Fleet backup history is temporarily unavailable (HTTP 503); polling will continue using the recorded task reference."),
                        "native_task_state": native_task_state,
                        "native_task_terminal": native_task_terminal,
                        "native_task_status": public_task_status,
                    }
                for record in entries:
                    key = _fleet_record_identity(record)
                    baseline = {
                        (entry.get("component_id"), entry.get("key"))
                        for entry in baseline_items
                        if isinstance(entry, dict)
                    } if isinstance(baseline_items, list) else set()
                    artifact_path = _fleet_artifact_key(record)
                    if (
                        key is not None and artifact_path is not None
                        and (component_id, key) not in baseline
                        and _fleet_record_succeeded(record)
                    ):
                        points = _fleet_valid_restore_points(record)
                        created_at = self._pick(record, "name", "createdAt", "creationTime") or points[-1]
                        records.append({"component_id": component_id, "path": artifact_path, "created_at": _bounded_text(created_at)})
            covered = {record["component_id"] for record in records}
            if state != "failed" and not set(component_ids) <= covered:
                state = "running"
            return {
                "state": state,
                "native_task_state": native_task_state,
                "native_task_terminal": native_task_terminal,
                "native_task_status": public_task_status,
                "artifacts": records,
                "native_task_id": ref,
            }
        if self.kind == "sddc":
            try:
                raw = self._poll_call(f"/v1/tasks/{quote(ref, safe='')}")
            except _TransientPollUnavailable:
                return _pending_poll_result(ref, "SDDC backup status is temporarily unavailable (HTTP 503); polling will continue using the recorded task reference.")
            state = _state(self._pick(raw, "status", "state")) if isinstance(raw, dict) else "running"
            return {"state": state, "artifacts": [], "native_task_id": ref}
        if self.kind == "nsx":
            try:
                history = self._poll_call("/policy/api/v1/cluster/backups/history")
            except _TransientPollUnavailable:
                return _pending_poll_result(ref or None, "NSX backup history is temporarily unavailable (HTTP 503); polling will continue using the recorded backup reference.")
            current_ids = _nsx_backup_ids(history)
            baseline_ids = reference.get("nsx_backup_ids")
            if not isinstance(baseline_ids, list) or len(baseline_ids) > 500 or any(not isinstance(value, str) for value in baseline_ids):
                raise ValueError("NSX backup reference has invalid history baseline")
            new_ids = current_ids - set(baseline_ids)
            if not new_ids:
                state = "running"
            else:
                state = _state(_nsx_newest_state(history, new_ids))
            return {
                "state": state,
                "artifacts": [],
                "native_task_id": ref or None,
                "artifact_warning": "NSX backup history identifies backup operations but does not return SFTP artifact paths; verify the receiver's new files independently.",
            }
        try:
            raw = self._poll_call(f"/api/appliance/recovery/backup/job/{quote(ref, safe='')}")
        except _TransientPollUnavailable:
            return _pending_poll_result(ref, "vCenter backup status is temporarily unavailable (HTTP 503); polling will continue using the recorded task reference.")
        state = _state(self._pick(raw, "status", "state")) if isinstance(raw, dict) else "running"
        return {
            "state": state,
            "artifacts": [],
            "native_task_id": ref,
            "artifact_warning": "vCenter job status does not return an SFTP artifact path; verify the receiver's new files independently.",
        }


def _fleet_service_metadata(value: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    """Validate Operations-discovered Fleet target metadata and its public cert chain.

        Args:
            value: Operations-discovered Fleet descriptor whose endpoint and public certificate chain are checked.
    """
    address = value.get("address")
    if value.get("addressType") != "FQDN" or not isinstance(address, str) or not 1 <= len(address) <= 253:
        raise RemoteError("VCF Operations returned an invalid Fleet LCM hostname")
    parsed = urlsplit(f"//{address}")
    host = address[:-1] if address.endswith(".") else address
    labels = host.split(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if (
        is_ip
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname != host.lower()
        or len(labels) < 2
        or any(not _SAFE_FQDN_LABEL.fullmatch(label) for label in labels)
    ):
        raise RemoteError("VCF Operations returned an unsafe Fleet LCM hostname")
    port = value.get("port", 443)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise RemoteError("VCF Operations returned an invalid Fleet LCM port")
    base_path = value.get("basePath")
    if (
        not isinstance(base_path, str)
        or not 1 <= len(base_path) <= 256
        or not _SAFE_BASE_PATH.fullmatch(base_path)
        or any(segment in {".", ".."} for segment in base_path.split("/"))
    ):
        raise RemoteError("VCF Operations returned an unsafe Fleet LCM base path")
    key = value.get("key")
    if not isinstance(key, str) or not _SAFE_ID.fullmatch(key):
        raise RemoteError("VCF Operations returned an invalid Fleet LCM service key")
    version = value.get("version")
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise RemoteError("VCF Operations advertises an unsupported Fleet LCM version")
    certificates = value.get("certificates")
    if not isinstance(certificates, list) or not certificates or len(certificates) > 20:
        raise RemoteError("VCF Operations returned an invalid Fleet LCM certificate chain")
    pins: set[str] = set()
    for certificate_pem in certificates:
        if not isinstance(certificate_pem, str) or not 1 <= len(certificate_pem) <= 65536:
            raise RemoteError("VCF Operations returned an invalid Fleet LCM certificate")
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise RemoteError("VCF Operations returned an invalid Fleet LCM certificate") from None
        pins.add(certificate.fingerprint(hashes.SHA256()).hex())
    return {
        "address": host.lower(),
        "port": port,
        "base_path": base_path,
        "key": key,
        "version": version,
    }, pins


def _bounded_text(value: Any, limit: int = 1024) -> str | None:
    """Sanitize an untrusted message and enforce its display bound.

        Args:
            value: Untrusted diagnostic text to sanitize and shorten.
            limit: Maximum number of characters retained.
    """
    return value[:limit] if isinstance(value, str) else None


def _pending_poll_result(reference: str | None, warning: str) -> dict[str, Any]:
    """Represent an unresolved status read without losing its task reference.

        Args:
            reference: Native task or history reference that remains unresolved.
            warning: Sanitized explanation that the status read can be retried later.
    """
    return {
        "state": "running",
        "artifacts": [],
        "native_task_id": reference,
        "warning": warning,
    }


def _validate_encryption_passphrase(kind: str, value: str) -> None:
    """Enforce the selected product’s backup passphrase constraints.

        Args:
            kind: Native product whose passphrase rules apply.
            value: Transient passphrase to validate without returning or logging it.
    """
    if kind == "vcenter":
        valid = (
            8 <= len(value) <= 20
            and value.isascii()
            and not any(ord(char) < 33 or ord(char) == 127 for char in value)
            and any(char.isupper() for char in value)
            and any(char.islower() for char in value)
            and any(char.isdigit() for char in value)
            and any(not char.isalnum() for char in value)
        )
        if not valid:
            raise ValueError("vCenter backup passphrases must be 8 to 20 ASCII characters with upper/lowercase letters, a digit, and a symbol.")
        return
    valid = (
        12 <= len(value) <= 128
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        and any(char.isupper() for char in value)
        and sum(char.isdigit() for char in value) >= 2
        and any(not char.isalnum() and not char.isspace() for char in value)
    )
    if not valid:
        raise ValueError("Backup passphrases must be 12 to 128 characters with an uppercase letter, two digits, and a symbol.")


def _normalized_port(value: Any) -> int | None:
    """Convert a native port value to an integer when valid.

        Args:
            value: Port field from a native response, possibly represented as text.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return None


def _normalized_time(value: Any) -> str | None:
    """Normalize a supported appliance time string for display.

        Args:
            value: Appliance time-of-day string to normalize when supported.
    """
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"([01]\d|2[0-3]):([0-5]\d)(?::[0-5]\d(?:\.\d+)?)?", value)
    return f"{match.group(1)}:{match.group(2)}" if match else value


def _fleet_time_parts(value: str) -> tuple[str, str] | None:
    """Normalize RFC3339 full-time without losing its explicit offset.

        Args:
            value: Fleet time-of-day string whose clock and UTC offset are separated.
    """
    match = re.fullmatch(
        r"([01]\d|2[0-3]):([0-5]\d)(?::[0-5]\d(?:\.\d+)?)?(Z|[+-](?:0\d|1\d|2[0-3]):[0-5]\d)?",
        value,
    )
    if match is None:
        return None
    timezone = match.group(3)
    if timezone is None:
        label = "Unspecified timezone"
    elif timezone == "Z" or timezone == "+00:00":
        label = "UTC"
    elif timezone == "-00:00":
        label = "Unknown offset (-00:00)"
    else:
        label = f"UTC{timezone}"
    return f"{match.group(1)}:{match.group(2)}", label


def _fleet_artifact_key(value: dict[str, Any]) -> str | None:
    """Extract a bounded path identity from a Fleet artifact record.

        Args:
            value: Fleet record used to derive a bounded artifact identity.
    """
    candidate = value.get("path") or value.get("filePath") or value.get("location")
    return candidate[:1024] if isinstance(candidate, str) and candidate else None


def _fleet_valid_restore_points(value: dict[str, Any]) -> list[str]:
    """Extract only Fleet’s documented restore-point strings.

        Args:
            value: Fleet record from which documented restore points are extracted.
    """
    points = value.get("points")
    if not isinstance(points, list):
        return []
    # Fleet LCM RestoreBackupSpec documents this exact point format.
    return [
        point for point in points
        if isinstance(point, str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z", point)
    ]


def _fleet_record_identity(value: dict[str, Any]) -> str | None:
    """Build the stable identity used to compare Fleet backup records.

        Args:
            value: Fleet record reduced to a stable component-and-path identity.
    """
    path = _fleet_artifact_key(value)
    if path is None:
        return None
    name = value.get("name")
    points = _fleet_valid_restore_points(value)
    name_marker = name[:80] if isinstance(name, str) and name else ""
    marker = f"{name_marker}|{','.join(points)}"
    # Record name/restore points distinguish a new backup even if the server
    # reuses a component's backup directory path.
    return f"{path}|{marker}" if name_marker or points else path


def _fleet_record_succeeded(value: dict[str, Any]) -> bool:
    """Check whether a Fleet record documents successful completion.

        Args:
            value: Fleet record whose documented completion status is interpreted.
    """
    if _fleet_artifact_key(value) is None or not _fleet_valid_restore_points(value):
        return False
    if value.get("success") is False:
        return False
    status = value.get("status", value.get("state", value.get("backupStatus", value.get("backup_status"))))
    if status is None:
        return True
    return isinstance(status, str) and status.upper() in {"SUCCEEDED", "SUCCESS", "COMPLETED", "FINISHED"}


def _extract_task_id(value: Any) -> str | None:
    """Extract a safe task identifier from a native write response.

        Args:
            value: Native write response that may contain a task ID.
    """
    if isinstance(value, dict):
        for key in ("id", "taskId", "task_id", "task", "taskId"):
            item = value.get(key)
            if isinstance(item, str) and _SAFE_ID.fullmatch(item):
                return item
    return None


def _state(value: Any) -> str:
    """Map a native task status to the workflow state vocabulary.

        Args:
            value: Native state mapped to the bounded workflow-state vocabulary.
    """
    normalized = str(value or "RUNNING").upper()
    if normalized in {"SUCCEEDED", "SUCCESS", "COMPLETED", "COMPLETED_WITH_WARNINGS", "FINISHED"}:
        return "succeeded"
    if normalized in {"FAILED", "ERROR", "CANCELLED", "CANCELED"}:
        return "failed"
    return "running"


def _openssh_sha256_fingerprint(public_key: str, expected_algorithm: str) -> str:
    """Compute the standard OpenSSH SHA256 fingerprint of an allowlisted host key.

        Args:
            public_key: OpenSSH public-key line whose key blob is fingerprinted.
            expected_algorithm: Allowed algorithm required for the receiver key.
    """
    if not isinstance(public_key, str) or len(public_key) > 1024 or any(ord(char) < 0x20 for char in public_key):
        raise ValueError("The receiver SSH host key is invalid")
    parts = public_key.split()
    if len(parts) < 2 or parts[0] != expected_algorithm:
        raise ValueError("The receiver SSH host key algorithm is unsupported")
    try:
        key_blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("The receiver SSH host key encoding is invalid") from None
    if not key_blob:
        raise ValueError("The receiver SSH host key encoding is invalid")
    digest = base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _validation_result(value: Any) -> dict[str, Any]:
    """Reduce validation responses to success plus non-sensitive status codes.

        Args:
            value: Vendor response reduced to safe validation status and diagnostic codes.
    """
    if value is None:
        return {
            "supported": True, "valid": False,
            "diagnostics": ["Native validation returned no terminal success result."],
        }
    if not isinstance(value, dict):
        raise RemoteError("Native backup validation returned an invalid response")
    result_status = str(value.get("resultStatus", value.get("result_status", value.get("status", "")))).upper()
    execution_status = str(value.get("executionStatus", value.get("execution_status", ""))).upper()
    errors = value.get("errors", value.get("validationChecks", value.get("validation_checks", value.get("messages", []))))
    if errors is None:
        errors = []
    if not isinstance(errors, list) or len(errors) > 100:
        raise RemoteError("Native backup validation returned an invalid response")
    diagnostics: list[str] = []
    for error in errors:
        if isinstance(error, dict):
            code = error.get("code") or error.get("errorCode") or error.get("type")
            diagnostics.append(str(code)[:100] if isinstance(code, (str, int)) else "Native validation reported a problem")
        elif isinstance(error, str):
            # Vendor text may echo destination details or secrets; do not return it.
            diagnostics.append("Native validation reported a problem")
        else:
            diagnostics.append("Native validation reported a problem")
    explicit = value.get("valid", value.get("isValid"))
    if execution_status in {"IN_PROGRESS", "PENDING", "RUNNING", "QUEUED", "STARTING"}:
        return {"supported": True, "valid": False, "diagnostics": ["Native validation is still in progress; retry before applying backup settings."]}
    if execution_status in {"FAILED", "FAILURE", "ERROR", "CANCELLED", "CANCELED"}:
        valid = False
        if not diagnostics:
            diagnostics.append("Native validation execution failed.")
    elif isinstance(explicit, bool):
        valid = explicit
    elif result_status in {"SUCCEEDED", "OK", "WARNING", "PASS", "PASSED"}:
        valid = True
    elif result_status in {"FAILED", "FAIL", "ERROR"}:
        valid = False
    else:
        valid = False
        if not diagnostics:
            diagnostics.append("Native validation returned no terminal success result.")
    return {"supported": True, "valid": valid, "diagnostics": diagnostics}


def _vcenter_location(proposed: dict[str, Any]) -> str:
    """Format the reviewed receiver as a vCenter SFTP location.

        Args:
            proposed: Reviewed receiver host, SSH port, and directory for the vCenter SFTP URL.
    """
    host = str(proposed["host"])
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address):
            if address.scope_id is not None:
                raise ValueError("vCenter backup destinations require an IPv6 address without a zone identifier")
            host = f"[{host}]"
    return f"sftp://{host}:{proposed['port']}{proposed['directory']}"


def _nsx_backup_status_entries(value: Any) -> list[dict[str, Any]]:
    """Select NSX cluster-level backup history entries.

        Args:
            value: NSX history response from which cluster-level entries are selected.
    """
    if not isinstance(value, dict):
        return []
    result: list[dict[str, Any]] = []
    for key in ("cluster_backup_statuses", "clusterBackupStatuses"):
        items = value.get(key, [])
        if not isinstance(items, list):
            continue
        result.extend(item for item in items if isinstance(item, dict))
    return result


def _nsx_backup_ids(value: Any) -> set[str]:
    """Collect stable backup identifiers from NSX history.

        Args:
            value: NSX history response whose stable backup IDs are collected.
    """
    return {
        item["backup_id"]
        for item in _nsx_backup_status_entries(value)
        if isinstance(item.get("backup_id"), str)
    } | {
        item["backupId"]
        for item in _nsx_backup_status_entries(value)
        if isinstance(item.get("backupId"), str)
    }


def _nsx_newest_state(value: Any, new_ids: set[str]) -> str:
    """Return the state of the newest NSX backup created after baseline.

        Args:
            value: NSX history response containing candidate backup records.
            new_ids: IDs created after the persisted history baseline.
    """
    candidates = [
        item for item in _nsx_backup_status_entries(value)
        if item.get("backup_id", item.get("backupId")) in new_ids
    ]
    if not candidates:
        return "RUNNING"
    item = candidates[-1]
    if item.get("success") is True:
        return "SUCCEEDED"
    if item.get("success") is False:
        return "FAILED"
    status = item.get("status")
    if isinstance(status, str) and status.upper() in {"SUCCEEDED", "SUCCESS", "COMPLETED", "FINISHED"}:
        return "SUCCEEDED"
    if isinstance(status, str) and status.upper() in {"FAILED", "ERROR", "CANCELLED", "CANCELED"}:
        return "FAILED"
    return "RUNNING"
