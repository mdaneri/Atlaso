"""Focused tests for pinned VCF native backup API contracts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from atlaso.app.services.vcf_backup_native import (
    NativeBackup,
    _fleet_time_parts,
    _validation_result,
)
from atlaso.app.services.vcf_certificate_remote import Credentials, RemoteError


class FakeTransport:
    def __init__(self, target: Any, responses: list[tuple[int, Any]]) -> None:
        self.target = target
        self.responses = list(responses)
        self.requests: list[tuple[str, str, Any, Any, Any]] = []
        self.presented_fingerprint: str | None = None

    def probe(self) -> dict[str, str]:
        if self.target is None:
            raise AssertionError("Probe requires a pinned target")
        return {"sha256": self.presented_fingerprint or self.target.fingerprint}

    def request(
        self,
        method: str,
        path: str,
        *,
        credentials: Any = None,
        session_header: Any = None,
        body: Any = None,
    ) -> tuple[int, Any]:
        self.requests.append((method, path, credentials, session_header, body))
        if not self.responses:
            raise AssertionError(f"Unexpected request {method} {path}")
        return self.responses.pop(0)


def source(kind: str = "fleet") -> dict[str, Any]:
    base = {
        "kind": kind,
        "address": "ops.example.test",
        "port": 443,
        "fingerprint": "a" * 64,
    }
    return base


def credentials() -> Credentials:
    return Credentials("svc-account", "top-secret-password")


def fleet_certificate(host: str = "fleet.example.test") -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        cert.fingerprint(hashes.SHA256()).hex(),
    )


def fleet_service(certificate: str, **overrides: Any) -> dict[str, Any]:
    return {
        "type": "VCF_FLEET_LCM",
        "key": "fleet-service-key",
        "address": "fleet.example.test",
        "addressType": "FQDN",
        "port": 443,
        "basePath": "fleet-lcm",
        "version": "9.1.1.0100.25761871",
        "certificates": [certificate],
        **overrides,
    }


def ops_responses(
    certificate: str,
    *,
    fleet_token: str = "fleet-token-value",
    services: list[dict[str, Any]] | None = None,
) -> list[tuple[int, Any]]:
    return [
        (200, {"accessToken": "ops-token-value"}),
        (200, {"servicesDetails": services if services is not None else [fleet_service(certificate)]}),
        (200, {"jwtToken": fleet_token}),
    ]


def attach_fleet_transport(adapter: NativeBackup, transport: FakeTransport) -> None:
    adapter._fleet_transport = transport
    adapter._fleet_token = "fleet-token"
    adapter._fleet_service = {
        "address": "fleet.example.test", "port": 443, "base_path": "fleet-lcm",
        "key": "fleet-service-key", "version": "9.1.1.0100.25761871", "fingerprint": "c" * 64,
    }


def test_fleet_auth_is_discovered_and_pinned_through_operations_registry() -> None:
    certificate, fingerprint = fleet_certificate()
    transports: dict[str, FakeTransport] = {}

    def factory(target: Any) -> FakeTransport:
        host = target.host
        if host == "ops.example.test":
            transport = FakeTransport(target, ops_responses(certificate))
        else:
            transport = FakeTransport(target, [(200, {"currentVersion": "9.1.1.0100.25761871"})])
        transports[host] = transport
        return transport

    adapter = NativeBackup(source(), credentials(), transport_factory=factory)
    adapter.login()
    assert adapter._load_version() == "9.1.1.0100.25761871"
    ops_requests = transports["ops.example.test"].requests
    assert ops_requests[0][:2] == ("POST", "/suite-api/api/auth/token/acquire")
    assert ops_requests[0][2] is None
    assert ops_requests[0][4] == {"username": "svc-account", "password": "top-secret-password"}
    assert ops_requests[1][:2] == ("GET", "/suite-api/api/integrations/services")
    assert ops_requests[1][3] == ("Authorization", "OpsToken ops-token-value")
    assert ops_requests[2][1] == "/suite-api/api/auth/token/exchange"
    assert ops_requests[2][3] == ("Authorization", "OpsToken ops-token-value")
    assert ops_requests[2][4] == {"serviceKeys": ["fleet-service-key"]}
    fleet_requests = transports["fleet.example.test"].requests
    assert fleet_requests[0][1] == "/fleet-lcm/v1/system"
    assert fleet_requests[0][3] == ("Authorization", "Bearer fleet-token-value")
    assert fleet_requests[0][2] is None
    assert transports["fleet.example.test"].target.fingerprint == fingerprint
    assert adapter._fleet_service == {
        "address": "fleet.example.test", "port": 443, "base_path": "fleet-lcm",
        "key": "fleet-service-key", "version": "9.1.1.0100.25761871", "fingerprint": fingerprint,
    }


@pytest.mark.parametrize("services", [[], None])
def test_fleet_requires_exactly_one_operations_registry_service(services: list[dict[str, Any]] | None) -> None:
    certificate, _ = fleet_certificate()
    rows = services if services is not None else [fleet_service(certificate), fleet_service(certificate)]
    ops = FakeTransport(None, ops_responses(certificate, services=rows))
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: ops)
    with pytest.raises(RemoteError, match="exactly one Fleet LCM service"):
        adapter.login()
    assert [request[1] for request in ops.requests] == [
        "/suite-api/api/auth/token/acquire", "/suite-api/api/integrations/services"
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("address", "https://fleet.example.test"),
        ("address", "user@fleet.example.test"),
        ("address", "fleet.example.test/path"),
        ("address", "127.0.0.1"),
        ("address", "fleet..example.test"),
        ("basePath", "../fleet-lcm"),
        ("basePath", "/fleet-lcm"),
        ("basePath", "fleet-lcm?x=1"),
    ],
)
def test_fleet_registry_rejects_unsafe_host_or_base_path_before_exchange(field: str, value: str) -> None:
    certificate, _ = fleet_certificate()
    service = fleet_service(certificate)
    service[field] = value
    ops = FakeTransport(None, ops_responses(certificate, services=[service]))
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: ops)
    with pytest.raises(RemoteError, match="Fleet LCM"):
        adapter.login()
    assert len(ops.requests) == 2


def test_fleet_registry_certificate_mismatch_stops_before_token_exchange() -> None:
    certificate, _ = fleet_certificate()
    ops = FakeTransport(None, ops_responses(certificate))
    service_transports: list[FakeTransport] = []

    def factory(target: Any) -> FakeTransport:
        if target.host == "ops.example.test":
            return ops
        service_transport = FakeTransport(target, [])
        service_transport.presented_fingerprint = "f" * 64
        service_transports.append(service_transport)
        return service_transport

    adapter = NativeBackup(source(), credentials(), transport_factory=factory)
    with pytest.raises(RemoteError, match="not advertised"):
        adapter.login()
    assert len(ops.requests) == 2
    assert service_transports
    assert all(not transport.requests for transport in service_transports)


def test_fleet_relogin_refreshes_registry_and_pinned_service_identity() -> None:
    certificate_a, fingerprint_a = fleet_certificate("fleet-a.example.test")
    certificate_b, fingerprint_b = fleet_certificate("fleet-b.example.test")
    services_a = [fleet_service(certificate_a, address="fleet-a.example.test", version="9.1.1.0")]
    services_b = [fleet_service(certificate_b, address="fleet-b.example.test", version="9.1.1.1", basePath="fleet-new")]
    ops = FakeTransport(
        None,
        [
            (200, {"accessToken": "ops-a"}), (200, {"servicesDetails": services_a}), (200, {"jwtToken": "fleet-a"}),
            (200, {"accessToken": "ops-b"}), (200, {"servicesDetails": services_b}), (200, {"jwtToken": "fleet-b"}),
        ],
    )
    service_transports: dict[str, FakeTransport] = {}

    def factory(target: Any) -> FakeTransport:
        if target.host == "ops.example.test":
            return ops
        service_transport = FakeTransport(target, [])
        service_transports[target.host] = service_transport
        return service_transport

    adapter = NativeBackup(source(), credentials(), transport_factory=factory)
    adapter.login()
    assert adapter._fleet_service is not None
    assert adapter._fleet_service["fingerprint"] == fingerprint_a
    first_identity = adapter._fleet_service.copy()
    adapter.login()
    assert adapter._fleet_service is not None
    assert adapter._fleet_service["address"] == "fleet-b.example.test"
    assert adapter._fleet_service["base_path"] == "fleet-new"
    assert adapter._fleet_service["fingerprint"] == fingerprint_b
    assert adapter._fleet_service != first_identity
    assert adapter._fleet_token == "fleet-b"


def test_fleet_service_uses_operations_advertised_dynamic_base_path() -> None:
    certificate, _ = fleet_certificate()
    service = fleet_service(certificate, basePath="custom/fleet-root")
    ops = FakeTransport(None, ops_responses(certificate, services=[service]))

    def factory(target: Any) -> FakeTransport:
        return ops if target.host == "ops.example.test" else FakeTransport(
            target, [(200, {"currentVersion": "9.1.1.0100.25761871"})]
        )

    adapter = NativeBackup(source(), credentials(), transport_factory=factory)
    adapter.login()
    assert adapter._load_version() == "9.1.1.0100.25761871"
    assert adapter._fleet_transport is not None
    assert adapter._fleet_transport.requests[0][1] == "/custom/fleet-root/v1/system"


def test_fleet_rejects_legacy_user_supplied_fleet_target() -> None:
    legacy_source = source()
    legacy_source["fleet_address"] = "fleet.example.test"
    legacy_source["fleet_fingerprint"] = "b" * 64
    with pytest.raises(ValueError, match="discovered from VCF Operations"):
        NativeBackup(legacy_source, credentials(), transport_factory=lambda _target: pytest.fail("no transport"))


def test_fleet_discovery_and_trigger_require_whole_backup_group() -> None:
    certificate, _fingerprint = fleet_certificate()
    transports: dict[str, FakeTransport] = {}

    def factory(target: Any) -> FakeTransport:
        if target.host == "ops.example.test":
            t = FakeTransport(target, ops_responses(certificate, fleet_token="fleet"))
        else:
            t = FakeTransport(
                target,
                [
                    (200, {"currentVersion": "9.1.1.0100.25761871"}),
                    (200, {"elements": [{"id": "lcm-1", "backupConfigSpec": {"sftp": {"host": "wrong-field.example.test"}}}]}),
                    (200, {"id": "lcm-1", "backupConfig": {"storage": {"sftp": {"host": "backup.example.test", "port": "22", "username": "backup-user", "directory": "/backups/vcf", "thumbprint": "SHA256:pin"}}, "fullSchedule": {"enabled": True, "schedule": {"days": ["MON"], "startTime": "02:30:00Z"}}, "retention": {"maxBackups": 14}}}),
                    (200, {"elements": [{"id": "comp-a", "name": "SDDC Manager", "productType": "SDDC_MANAGER", "version": "9.1.1", "backupAllowed": True}, {"id": "comp-b", "name": "NSX", "productType": "NSX", "version": "4.2", "backupAllowed": True}]}),
                    (200, {"elements": [{"id": "comp-a", "name": "SDDC Manager", "productType": "SDDC_MANAGER", "version": "9.1.1"}, {"id": "comp-b", "name": "NSX", "productType": "NSX", "version": "4.2"}]}),
                    (200, {"elements": []}),
                    (200, {"elements": []}),
                    (202, {"id": "task-1"}),
                ],
            )
        transports[target.host] = t
        return t

    adapter = NativeBackup(source(), credentials(), transport_factory=factory)
    inventory = adapter.discover()
    assert inventory["version"] == "9.1.1.0100.25761871"
    assert inventory["service"]["address"] == "fleet.example.test"
    assert inventory["service"]["base_path"] == "fleet-lcm"
    assert inventory["service"]["key"] == "fleet-service-key"
    assert inventory["identity"].startswith(
        f"fleet:fleet.example.test:{inventory['service']['fingerprint']}:"
    )
    assert inventory["groups"][0]["component_ids"] == ["comp-a", "comp-b"]
    assert inventory["groups"][0]["current"]["host"] == "backup.example.test"
    assert inventory["groups"][0]["current"]["configured"] is True
    assert inventory["groups"][0]["current"]["schedule_timezone"] == "UTC"
    assert "password" not in str(inventory)
    with pytest.raises(ValueError, match="every eligible component"):
        adapter.start_backup("lcm-1", ["comp-a"])
    result = adapter.start_backup("lcm-1", ["comp-a", "comp-b"])
    assert result["reference"]["kind"] == "fleet"
    assert result["reference"]["group_id"] == "lcm-1"
    assert result["reference"]["native_task_id"] == "task-1"
    assert result["reference"]["component_ids"] == ["comp-a", "comp-b"]
    assert result["reference"]["fleet_artifacts"] == []
    request = transports["fleet.example.test"].requests[-1]
    assert request[0:2] == ("POST", "/fleet-lcm/v1/sddc-lcms/lcm-1/backups")
    assert request[4] == {"actionType": "ComponentsBackupSpec", "componentIds": ["comp-a", "comp-b"]}


def test_rejects_unsupported_version_before_any_write() -> None:
    certificate, _fingerprint = fleet_certificate()
    transports: dict[str, FakeTransport] = {}

    def factory(target: Any) -> FakeTransport:
        if target.host == "ops.example.test":
            t = FakeTransport(target, ops_responses(certificate, fleet_token="fleet"))
        else:
            t = FakeTransport(target, [(200, {"currentVersion": "9.2.0.0"})])
        transports[target.host] = t
        return t

    adapter = NativeBackup(source(), credentials(), transport_factory=factory)
    with pytest.raises(RemoteError, match="9.1.x only"):
        adapter.discover()
    assert all(method == "GET" for method, *_ in transports["fleet.example.test"].requests)


@pytest.mark.parametrize(
    ("kind", "version"),
    [
        ("sddc", "9.1.1.0.25713928"),
        ("nsx", "9.1.1.0.25691509"),
    ],
)
def test_accepts_vendor_91_build_version_suffixes(kind: str, version: str) -> None:
    if kind == "sddc":
        transport = FakeTransport(
            None,
            [
                (200, {"accessToken": "native-token"}),
                (200, {"role": "SddcManager", "version": version, "ipAddresses": []}),
                (200, {"id": "system-1"}),
            ],
        )
    else:
        transport = FakeTransport(None, [(200, {"product_version": version})])
    adapter = NativeBackup(source(kind), credentials(), transport_factory=lambda _target: transport)
    adapter.login()
    assert adapter._load_version() == version


def test_vcenter_discovery_maps_schedule_resource_and_native_backup_parts() -> None:
    transport = FakeTransport(
        None,
        [
            (201, "vc-session"),
            (200, {"version": "9.1.1.0"}),
            (200, {}),
            (200, [{"id": "common"}, {"id": "seat"}, {"id": "supervisors"}]),
        ],
    )
    adapter = NativeBackup(
        source("vcenter"), credentials(), transport_factory=lambda _target: transport
    )
    inventory = adapter.discover()
    assert inventory["version"] == "9.1.1.0"
    assert len(inventory["groups"]) == 1
    group = inventory["groups"][0]
    assert group["native_identity"] == {
        "schedule_id": "atlaso-vcf-backup", "exists": False
    }
    assert group["backup_parts"] == ["common", "seat", "supervisors"]
    proposed = adapter.proposed(
        group["id"], {"full_time": "03:15", "retention_mode": "count", "retention_value": 14},
        {"host": "backup.example.test", "port": 22, "username": "backup-user",
         "directory": "/backups/vcf", "ecdsa_fingerprint": "SHA256:receiver"},
    )
    assert proposed["parts"] == ["common", "seat", "supervisors"]
    assert proposed["days"] == [
        "FRIDAY", "MONDAY", "SATURDAY", "SUNDAY", "THURSDAY", "TUESDAY", "WEDNESDAY"
    ]
    assert transport.requests[2][1] == "/api/appliance/recovery/backup/schedules"
    assert transport.requests[3][1] == "/api/appliance/recovery/backup/parts"


def test_public_config_allowlist_and_receiver_username_alias() -> None:
    adapter = NativeBackup(source("nsx"), credentials(), transport_factory=lambda target: FakeTransport(target, []))
    adapter._inventory = {
        "groups": [{"id": "nsx-cluster", "product": "nsx", "component_ids": ["nsx-cluster"]}]
    }
    proposed = adapter.proposed(
        "nsx-cluster",
        {"full_time": "03:15"},
        {"host": "backup.example.test", "port": 22, "username": "backup", "directory": "/vcf", "ecdsa_fingerprint": "ssh-ed25519 AAAA"},
    )
    assert proposed["user"] == "backup"
    assert proposed["retention_mode"] is None
    assert proposed["retention_value"] is None


def test_validation_diagnostics_do_not_return_native_text_or_secret() -> None:
    # The helper is exercised through the SDDC documented validation endpoint.
    transport = FakeTransport(
        None,
        [
            (200, {"accessToken": "native-token"}),
            (200, {"role": "SddcManager", "version": "9.1.1.0", "ipAddresses": []}),
            (200, {"id": "system-1"}),
            (200, {"errors": [{"code": "INVALID_DESTINATION", "message": "top-secret-password"}]}),
        ],
    )
    adapter = NativeBackup(source("sddc"), credentials(), transport_factory=lambda _target: transport)
    adapter.login()
    adapter._inventory = {"groups": [{"id": "sddc-manager", "product": "sddc_manager", "component_ids": ["sddc-manager"]}]}
    result = adapter.validate(
        "sddc-manager",
        {"host": "backup.example.test", "port": 22, "user": "backup", "directory": "/vcf", "ecdsa_fingerprint": "aa", "full_time": "03:00", "sddc_most_recent": 10, "sddc_hourly_days": 2, "sddc_daily_days": 15},
        "top-secret-password",
        "SecureBackupPassAB12!",
    )
    assert result == {"supported": True, "valid": False, "diagnostics": ["INVALID_DESTINATION"]}
    assert "top-secret" not in str(result)
    assert transport.requests[-1][1] == "/v1/system/backup-configuration/validations"


def test_fleet_configuration_body_sends_secrets_only_to_native_write() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(None, [(200, {"id": "task-config"})])
    adapter = NativeBackup(
        source(), credentials(), transport_factory=lambda _target: root_transport
    )
    attach_fleet_transport(adapter, fleet_transport)
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a", "b"]}]
    }
    proposed = {
        "host": "backup.example.test", "port": 22, "user": "backup-user",
        "directory": "/backups/vcf", "ecdsa_fingerprint": "SHA256:public-key-fingerprint",
        "full_time": "02:30", "interval_minutes": 60, "state_change": True,
        "schedule_timezone": "UTC",
        "retention_mode": "count", "retention_value": 14, "component_ids": ["a", "b"],
    }
    result = adapter.configure("lcm-1", proposed, "sftp-secret", "SecureBackupPassAB12!")
    assert result == {
        "native_task_id": "task-config"
    }
    method, path, _credentials, _header, body = fleet_transport.requests[0]
    assert (method, path) == ("PATCH", "/fleet-lcm/v1/sddc-lcms/lcm-1")
    assert body["backupConfigSpec"]["storage"]["sftp"]["password"] == "sftp-secret"
    assert body["backupConfigSpec"]["encryptionPassphrase"] == "SecureBackupPassAB12!"
    assert body["backupConfigSpec"]["retention"] == {"maxBackups": 14}
    assert body["backupConfigSpec"]["fullSchedule"]["schedule"]["startTime"] == "02:30:00Z"
    assert "incrementalSchedule" not in body["backupConfigSpec"]


def test_fleet_configuration_status_503_then_success_never_replays_write() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (202, {"id": "task-config"}),
            (503, {"detail": "transient service unavailable"}),
            (200, {"status": "SUCCEEDED"}),
        ],
    )
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a"]}]
    }
    proposed = {
        "host": "backup.example.test", "port": 22, "user": "backup-user",
        "directory": "/backups/vcf", "ecdsa_fingerprint": "SHA256:pin",
        "schedule_timezone": "UTC", "full_time": "02:30", "days": ["MON"],
        "retention_mode": "count", "retention_value": 14, "component_ids": ["a"],
    }

    reference = adapter.configure("lcm-1", proposed, "sftp-secret", "SecureBackupPassAB12!")
    first_poll = adapter.configuration_status("lcm-1", {"kind": "fleet", "group_id": "lcm-1", **reference})
    second_poll = adapter.configuration_status("lcm-1", {"kind": "fleet", "group_id": "lcm-1", **reference})

    assert reference == {"native_task_id": "task-config"}
    assert first_poll["state"] == "running"
    assert "HTTP 503" in first_poll["warning"]
    assert second_poll == {"state": "succeeded"}
    assert [request[:2] for request in fleet_transport.requests] == [
        ("PATCH", "/fleet-lcm/v1/sddc-lcms/lcm-1"),
        ("GET", "/fleet-lcm/v1/tasks/task-config"),
        ("GET", "/fleet-lcm/v1/tasks/task-config"),
    ]


def test_fleet_backup_history_503_stays_running_without_artifacts_or_write_retry() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (200, {"backups": []}),  # baseline
            (202, {"id": "task-backup"}),  # one dispatch
            (200, {"status": "SUCCEEDED"}),  # task status
            (503, {"detail": "transient service unavailable"}),  # history poll
        ],
    )
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a"]}]
    }

    reference = adapter.start_backup("lcm-1", ["a"])["reference"]
    status = adapter.backup_status("lcm-1", reference)

    assert status["state"] == "running"
    assert status["artifacts"] == []
    assert status["native_task_id"] == reference["native_task_id"] == "task-backup"
    assert "HTTP 503" in status["warning"]
    assert sum(request[0] == "POST" for request in fleet_transport.requests) == 1


def test_fleet_configuration_status_auth_failure_is_not_treated_as_transient() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(None, [(401, {"detail": "do not expose"})])
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {
        "groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a"]}]
    }

    with pytest.raises(RemoteError, match="HTTP 401") as failure:
        adapter.configuration_status(
            "lcm-1", {"kind": "fleet", "group_id": "lcm-1", "native_task_id": "task-config"}
        )

    assert "do not expose" not in str(failure.value)


@pytest.mark.parametrize("http_status", [503, 401])
def test_configuration_poll_handles_raised_pinned_transport_status(http_status: int) -> None:
    class RaisingTransport(FakeTransport):
        def request(self, *args: Any, **kwargs: Any) -> tuple[int, Any]:
            super().request(*args, **kwargs)
            raise RemoteError(f"Appliance API returned HTTP {http_status}")

    root_transport = FakeTransport(None, [])
    fleet_transport = RaisingTransport(None, [(http_status, None)])
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {
        "groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a"]}]
    }
    reference = {"native_task_id": "task-config", "kind": "fleet", "group_id": "lcm-1"}
    if http_status == 503:
        status = adapter.configuration_status("lcm-1", reference)
        assert status["state"] == "running"
        assert "HTTP 503" in status["warning"]
    else:
        with pytest.raises(RemoteError, match="HTTP 401"):
            adapter.configuration_status("lcm-1", reference)
    assert [request[:2] for request in fleet_transport.requests] == [
        ("GET", "/fleet-lcm/v1/tasks/task-config")
    ]


def test_nsx_backup_history_503_stays_running_with_recorded_reference() -> None:
    transport = FakeTransport(
        None,
        [
            (200, {"cluster_backup_statuses": []}),  # baseline
            (200, {"accepted": True}),  # one dispatch
            (503, {"detail": "transient service unavailable"}),  # status poll
        ],
    )
    adapter = NativeBackup(source("nsx"), credentials(), transport_factory=lambda _target: transport)
    adapter._session = "basic"
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{"id": "nsx-cluster", "product": "nsx", "component_ids": ["nsx-cluster"]}]
    }

    reference = adapter.start_backup("nsx-cluster", ["nsx-cluster"])["reference"]
    status = adapter.backup_status("nsx-cluster", reference)

    assert status["state"] == "running"
    assert status["artifacts"] == []
    assert status["native_task_id"] is None
    assert status["warning"] and "HTTP 503" in status["warning"]
    assert [request[0] for request in transport.requests] == ["GET", "POST", "GET"]


def test_fleet_current_time_and_days_normalize_rfc3339_time_shape() -> None:
    current = NativeBackup._safe_settings({
        "fullSchedule": {
            "enabled": True,
            "schedule": {"startTime": "02:30:00", "days": ["SUN", "MON"]},
        }
    })
    assert current["full_time"] == "02:30"
    assert current["days"] == ["MON", "SUN"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("14:23:05Z", ("14:23", "UTC")),
        ("14:23:05+00:00", ("14:23", "UTC")),
        ("14:23:05-08:00", ("14:23", "UTC-08:00")),
        ("14:23:05-00:00", ("14:23", "Unknown offset (-00:00)")),
        ("14:23:05", ("14:23", "Unspecified timezone")),
        ("14:23:05+25:00", None),
    ],
)
def test_fleet_time_readback_preserves_timezone_semantics(
    value: str, expected: tuple[str, str] | None,
) -> None:
    assert _fleet_time_parts(value) == expected


def test_sddc_manual_backup_uses_verified_resource_spec_shape() -> None:
    transport = FakeTransport(None, [(202, {"id": "sddc-task-1"})])
    adapter = NativeBackup(
        source("sddc"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._session = "access-token"
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{"id": "sddc-manager", "product": "sddc_manager", "component_ids": ["sddc-manager"]}]
    }
    result = adapter.start_backup("sddc-manager", ["sddc-manager"])
    assert result["reference"]["kind"] == "sddc"
    assert result["reference"]["group_id"] == "sddc-manager"
    assert result["reference"]["native_task_id"] == "sddc-task-1"
    assert result["reference"]["component_ids"] == ["sddc-manager"]
    assert transport.requests[0][1] == "/v1/backups/tasks"
    assert transport.requests[0][4] == {
        "elements": [{"resourceType": "SDDC_MANAGER"}]
    }


def test_sddc_discovery_uses_native_version_and_one_authoritative_manager_group() -> None:
    transport = FakeTransport(
        None,
        [
            (200, {"accessToken": "native-token"}),
            (200, {
                "role": "SddcManager", "version": "9.1.1.0",
                "ipAddresses": [{"type": "MANAGEMENT", "ipAddress": "192.0.2.10"}],
            }),
            (200, {"id": "system-1"}),
            (200, {"elements": [{
                "id": "manager-1", "fqdn": "sddc.example.test",
                "ipAddress": "192.0.2.10", "version": "9.1.1.0",
                "domain": {"type": "MANAGEMENT"},
            }]}),
            (200, {"backupLocations": [], "backupSchedules": []}),
            (200, {"elements": []}),
            (200, {"elements": []}),
            (200, {"elements": [{
                "id": "sddc-nsxt-record", "nativeId": "nsx-native-uuid",
                "vipFqdn": "nsx-vip.example.test", "vip": "192.0.2.30",
                "name": "NSX Cluster", "version": "9.1.1.0",
            }]}),
        ],
    )
    source_data = source("sddc")
    source_data["version"] = "8.0.0"
    adapter = NativeBackup(source_data, credentials(), transport_factory=lambda _target: transport)
    inventory = adapter.discover()
    assert inventory["version"] == "9.1.1.0"
    assert len(inventory["groups"]) == 1
    group = inventory["groups"][0]
    assert group["reservation_keys"] == [
        "sddc-manager-id:manager-1", "sddc-system-id:system-1",
        "sddc-manager-fqdn:sddc.example.test"
    ]
    assert group["side_effects"][0]["product"] == "nsx"
    assert group["side_effects"][0]["changes"] == [
        "backup destination", "backup schedule/cadence"
    ]
    nsx_record = next(component for component in inventory["components"] if component["product"] == "nsx")
    assert nsx_record["native_identity"] == {
        "fqdn": None, "ip_address": None,
        "sddc_nsxt_cluster_id": "sddc-nsxt-record",
        "native_cluster_id": "nsx-native-uuid",
        "vip_fqdn": "nsx-vip.example.test", "vip": "192.0.2.30",
    }
    assert nsx_record["reservation_keys"] == ["nsx-cluster-id:nsx-native-uuid"]


def test_sddc_discovery_falls_back_to_verified_system_id_if_manager_catalog_does_not_match() -> None:
    transport = FakeTransport(
        None,
        [
            (200, {"accessToken": "native-token"}),
            (200, {
                "role": "SddcManager", "version": "9.1.1.0.25713928",
                "ipAddresses": [{"type": "MANAGEMENT", "ipAddress": "192.0.2.10"}],
            }),
            (200, {"id": "system-identity"}),
            (200, {"elements": [{
                "id": "unmatched-manager", "fqdn": "different.example.test",
                "ipAddress": "192.0.2.99", "domain": {"type": "MANAGEMENT"},
            }]}),
            (200, {"backupLocations": [], "backupSchedules": []}),
            (200, {"elements": []}),
            (200, {"elements": []}),
            (200, {"elements": []}),
        ],
    )
    adapter = NativeBackup(source("sddc"), credentials(), transport_factory=lambda _target: transport)
    inventory = adapter.discover()
    assert inventory["identity"] == "sddc:system-identity"
    assert inventory["groups"][0]["native_identity"]["sddc_manager_id"] == "system-identity"
    assert inventory["groups"][0]["reservation_keys"] == [
        "sddc-manager-id:system-identity", "sddc-system-id:system-identity"
    ]


def test_nsx_discovery_uses_vendor_cluster_id_for_alias_reservation() -> None:
    transport = FakeTransport(
        None,
        [
            (200, {"product_version": "9.1.1.0.25691509"}),
            (200, {"cluster_id": "cluster-uuid-1", "overall_status": "STABLE"}),
            (200, {}),
        ],
    )
    adapter = NativeBackup(
        source("nsx"), credentials(), transport_factory=lambda _target: transport
    )
    inventory = adapter.discover()
    assert inventory["identity"] == "nsx:cluster-uuid-1"
    assert inventory["groups"][0]["native_identity"] == {"cluster_id": "cluster-uuid-1"}
    assert inventory["groups"][0]["reservation_keys"] == ["nsx-cluster-id:cluster-uuid-1"]
    assert transport.requests[1][1] == "/api/v1/cluster/status"


def test_nsx_status_uses_persisted_history_baseline_not_global_prior_success() -> None:
    transport = FakeTransport(
        None,
        [
            (200, {"cluster_backup_statuses": [
                {"backup_id": "old-success", "success": True},
            ]}),
            (200, {"accepted": True}),
            (200, {
                "overall_backup_status": "SUCCESS",
                "cluster_backup_statuses": [
                    {"backup_id": "old-success", "success": True},
                    {"backup_id": "new-cluster", "status": "RUNNING"},
                ],
                "node_backup_statuses": [
                    {"backup_id": "new-node", "success": True},
                ],
                "inventory_backup_statuses": [
                    {"backup_id": "new-inventory", "success": True},
                ],
            }),
        ],
    )
    adapter = NativeBackup(
        source("nsx"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._session = "basic"
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{
            "id": "nsx-cluster", "product": "nsx",
            "component_ids": ["nsx-cluster"],
        }]
    }
    started = adapter.start_backup("nsx-cluster", ["nsx-cluster"])["reference"]
    assert started["nsx_backup_ids"] == ["old-success"]
    assert started["component_ids"] == ["nsx-cluster"]
    status = adapter.backup_status("nsx-cluster", started)
    assert status["state"] == "running"
    assert status["artifacts"] == []


def test_nsx_node_and_inventory_success_do_not_complete_cluster_backup() -> None:
    transport = FakeTransport(
        None,
        [
            (200, {"cluster_backup_statuses": []}),
            (200, {"accepted": True}),
            (200, {
                "overall_backup_status": "SUCCESS",
                "cluster_backup_statuses": [
                    {"backup_id": "new-cluster", "status": "RUNNING"},
                ],
                "node_backup_statuses": [
                    {"backup_id": "new-cluster", "success": True},
                ],
                "inventory_backup_statuses": [
                    {"backup_id": "new-cluster", "success": True},
                ],
            }),
        ],
    )
    adapter = NativeBackup(
        source("nsx"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._session = "basic"
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{"id": "nsx-cluster", "product": "nsx", "component_ids": ["nsx-cluster"]}]
    }
    reference = adapter.start_backup("nsx-cluster", ["nsx-cluster"])["reference"]
    status = adapter.backup_status("nsx-cluster", reference)
    assert status["state"] == "running"
    assert status["artifacts"] == []


def test_nsx_native_config_uses_ecdsa_fingerprint_without_claiming_retention() -> None:
    transport = FakeTransport(None, [(200, {"result": "accepted"})])
    adapter = NativeBackup(
        source("nsx"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._session = "basic"
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{"id": "nsx-cluster", "product": "nsx", "component_ids": ["nsx-cluster"]}]
    }
    proposed = {
        "host": "backup.example.test", "port": 22, "user": "backup-user",
        "directory": "/backups/vcf", "ecdsa_fingerprint": "SHA256:abc123",
        "host_key": "ecdsa-sha2-nistp256 AAAA public-key", "interval_minutes": 60,
        "state_change": True, "retention_mode": None, "retention_value": None,
    }
    assert adapter.configure("nsx-cluster", proposed, "sftp-secret", "SecureBackupPassAB12!") == {}
    method, path, _credentials, _header, body = transport.requests[0]
    assert (method, path) == ("PUT", "/policy/api/v1/cluster/backups/config")
    assert body["remote_file_server"]["protocol"]["ssh_fingerprint"] == "SHA256:abc123"
    assert body["remote_file_server"]["protocol"]["host_key_algorithm"] == "ecdsa-sha2-nistp256"
    assert body["remote_file_server"]["protocol"]["authentication_scheme"]["password"] == "sftp-secret"
    assert body["passphrase"] == "SecureBackupPassAB12!"
    assert "retention" not in body


def test_fleet_status_requires_and_uses_public_reference_dict() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (200, {"status": "SUCCEEDED"}),
            (200, {"backups": [{"componentId": "comp-a", "name": "2026-10-28T10-00-00Z", "path": "/backups/vcf", "points": ["2026-10-28T10-00-00Z"]}]}),
        ],
    )
    adapter = NativeBackup(
        source(), credentials(), transport_factory=lambda _target: root_transport
    )
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {
        "groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["comp-a"]}]
    }
    reference = {
        "kind": "fleet", "group_id": "lcm-1", "native_task_id": "task-1",
        "component_ids": ["comp-a"], "fleet_artifacts": [],
        "started_at": "2026-10-28T10:00:00+00:00",
    }
    with pytest.raises(ValueError, match="does not match"):
        adapter.backup_status("different-group", reference)
    status = adapter.backup_status("lcm-1", reference)
    assert status == {
        "state": "succeeded",
        "artifacts": [{
            "component_id": "comp-a", "path": "/backups/vcf",
            "created_at": "2026-10-28T10-00-00Z",
        }],
        "native_task_id": "task-1",
    }


def test_fleet_task_warnings_do_not_complete_without_successful_artifact_per_component() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (200, {"status": "COMPLETED_WITH_WARNINGS"}),
            (200, {"backups": [{"name": "2026-10-28T10-00-00Z", "path": "/backups/a", "points": ["2026-10-28T10-00-00Z"]}]}),
            (200, {"backups": [{"name": "2026-10-28T10-01-00Z", "path": "/backups/b", "points": ["2026-10-28T10-01-00Z"], "status": "RUNNING"}]}),
        ],
    )
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {"groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a", "b"]}]}
    reference = {
        "kind": "fleet", "group_id": "lcm-1", "native_task_id": "task-1",
        "component_ids": ["a", "b"], "fleet_artifacts": [],
        "started_at": "2026-10-28T10:00:00+00:00",
    }
    status = adapter.backup_status("lcm-1", reference)
    assert status["state"] == "running"
    assert [artifact["component_id"] for artifact in status["artifacts"]] == ["a"]


def test_fleet_task_warnings_complete_only_with_successful_artifact_per_component() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (200, {"status": "COMPLETED_WITH_WARNINGS"}),
            (200, {"backups": [{"name": "2026-10-28T10-00-00Z", "path": "/backups/a", "points": ["2026-10-28T10-00-00Z"]}]}),
            (200, {"backups": [{"name": "2026-10-28T10-01-00Z", "path": "/backups/b", "points": ["2026-10-28T10-01-00Z"]}]}),
        ],
    )
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {"groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a", "b"]}]}
    reference = {
        "kind": "fleet", "group_id": "lcm-1", "native_task_id": "task-1",
        "component_ids": ["a", "b"], "fleet_artifacts": [],
        "started_at": "2026-10-28T10:00:00+00:00",
    }
    status = adapter.backup_status("lcm-1", reference)
    assert status["state"] == "succeeded"
    assert [artifact["component_id"] for artifact in status["artifacts"]] == ["a", "b"]


def test_fleet_task_success_without_a_documented_restore_point_stays_running() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (200, {"status": "SUCCEEDED"}),
            (200, {"backups": [{"name": "2026-10-28T10-00-00Z", "path": "/backups/a", "points": []}]}),
        ],
    )
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {"groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a"]}]}
    reference = {
        "kind": "fleet", "group_id": "lcm-1", "native_task_id": "task-1",
        "component_ids": ["a"], "fleet_artifacts": [],
        "started_at": "2026-10-28T10:00:00+00:00",
    }

    status = adapter.backup_status("lcm-1", reference)

    assert status["state"] == "running"
    assert status["artifacts"] == []


def test_fleet_detects_new_restorepoint_when_backup_directory_is_reused() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (200, {"status": "SUCCEEDED"}),
            (200, {"backups": [{"name": "2026-10-28T10-01-00Z", "path": "/backups/shared", "points": ["2026-10-28T10-01-00Z"]}]}),
        ],
    )
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {"groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a"]}]}
    reference = {
        "kind": "fleet", "group_id": "lcm-1", "native_task_id": "task-1",
        "component_ids": ["a"],
        "fleet_artifacts": [{"component_id": "a", "key": "/backups/shared|2026-10-28T09-01-00Z"}],
        "started_at": "2026-10-28T10:00:00+00:00",
    }

    status = adapter.backup_status("lcm-1", reference)

    assert status["state"] == "succeeded"
    assert status["artifacts"] == [{
        "component_id": "a", "path": "/backups/shared", "created_at": "2026-10-28T10-01-00Z",
    }]


def test_fleet_missing_detail_config_requires_exact_unconfigured_filter_match() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (200, {"id": "lcm-1"}),
            (200, {"sddcLcms": [{"id": "lcm-1"}]}),
        ],
    )
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {"groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a"]}]}

    current = adapter.current("lcm-1")

    assert current["configured"] is False
    assert current["host"] is None
    assert fleet_transport.requests[1][1].startswith(
        "/fleet-lcm/v1/sddc-lcms?backupScheduleEnabled=false&backupStorageConfigured=false"
    )


def test_fleet_missing_detail_config_without_filter_match_is_unreviewable() -> None:
    root_transport = FakeTransport(None, [])
    fleet_transport = FakeTransport(
        None,
        [
            (200, {"id": "lcm-1"}),
            (200, {"sddcLcms": [{"id": "other-lcm"}]}),
        ],
    )
    adapter = NativeBackup(source(), credentials(), transport_factory=lambda _target: root_transport)
    attach_fleet_transport(adapter, fleet_transport)
    adapter._inventory = {"groups": [{"id": "lcm-1", "product": "fleet", "component_ids": ["a"]}]}

    with pytest.raises(RemoteError, match="refusing configuration changes"):
        adapter.current("lcm-1")


@pytest.mark.parametrize(
    "config",
    [
        {"backupLocations": [{}, {}], "backupSchedules": []},
        {"backupLocations": [], "backupSchedules": [{"resourceType": "NSXT_CLUSTER"}]},
        {"backupLocations": [], "backupSchedules": [{"resourceType": "SDDC_MANAGER"}, {"resourceType": "SDDC_MANAGER"}]},
    ],
)
def test_sddc_configuration_rejects_unreviewable_destinations_or_schedules(config: dict[str, Any]) -> None:
    with pytest.raises(RemoteError, match="Native backup configuration"):
        NativeBackup._safe_settings(config)


def test_sddc_configuration_allows_empty_destination_and_schedule_lists() -> None:
    current = NativeBackup._safe_settings({"backupLocations": [], "backupSchedules": []})
    assert current["host"] is None
    assert current["schedule_enabled"] is None


def test_vcenter_native_schedule_create_uses_pinned_vapi_contract() -> None:
    transport = FakeTransport(None, [(200, {}), (204, None)])
    adapter = NativeBackup(
        source("vcenter"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._session = "vc-session"
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{
            "id": "atlaso-vcf-backup", "product": "vcenter",
            "component_ids": ["vcenter"],
            "native_identity": {"schedule_id": "atlaso-vcf-backup", "exists": False},
        }]
    }
    proposed = {
        "host": "backup.example.test", "port": 22, "user": "backup-user",
        "directory": "/backups/vcf", "ecdsa_fingerprint": "SHA256:public-key",
        "full_time": "02:15", "retention_mode": "count", "retention_value": 14,
        "parts": ["seat"],
        "days": ["FRIDAY", "MONDAY", "SATURDAY", "SUNDAY", "THURSDAY", "TUESDAY", "WEDNESDAY"],
    }
    assert adapter.configure("atlaso-vcf-backup", proposed, "sftp-secret", "SecureAB12!") == {}
    assert transport.requests[0][0:2] == (
        "GET", "/api/appliance/recovery/backup/schedules"
    )
    method, path, _credentials, session_header, envelope = transport.requests[1]
    assert (method, path) == (
        "POST", "/api/appliance/recovery/backup/schedules"
    )
    assert envelope["schedule"] == "atlaso-vcf-backup"
    body = envelope["spec"]
    assert session_header == ("vmware-api-session-id", "vc-session")
    assert body["location"] == "sftp://backup.example.test:22/backups/vcf"
    assert body["recurrence_info"] == {
        "hour": 2, "minute": 15,
        "days": ["FRIDAY", "MONDAY", "SATURDAY", "SUNDAY", "THURSDAY", "TUESDAY", "WEDNESDAY"],
    }
    assert body["parts"] == ["seat"]
    assert body["retention_info"] == {"max_count": 14}
    assert body["location_password"] == "sftp-secret"
    assert body["backup_password"] == "SecureAB12!"
    assert "ecdsa_fingerprint" not in body


def test_vcenter_first_schedule_creation_reads_back_authoritative_created_schedule() -> None:
    schedule_id = "atlaso-vcf-backup"
    native_schedule = {
        "location": "sftp://backup.example.test:22/backups/vcf",
        "location_user": "backup-user", "enable": True,
        "recurrence_info": {
            "hour": 2, "minute": 15,
            "days": ["FRIDAY", "MONDAY", "SATURDAY", "SUNDAY", "THURSDAY", "TUESDAY", "WEDNESDAY"],
        },
        "retention_info": {"max_count": 14},
        "parts": ["seat"],
        "location_password": "write-only", "backup_password": "write-only",
    }
    transport = FakeTransport(
        None,
        [
            (200, {}),  # pre-create collision check
            (204, None),  # acknowledged POST create
            (200, {schedule_id: {}}),  # authoritative schedule map after create
            (200, native_schedule),  # authoritative detail readback
        ],
    )
    adapter = NativeBackup(
        source("vcenter"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{
            "id": schedule_id, "product": "vcenter", "component_ids": ["vcenter"],
            "backup_parts": ["seat"],
            "native_identity": {"schedule_id": schedule_id, "exists": False},
        }]
    }
    proposed = {
        "host": "backup.example.test", "port": 22, "user": "backup-user",
        "directory": "/backups/vcf", "ecdsa_fingerprint": None,
        "full_time": "02:15", "retention_mode": "count", "retention_value": 14,
        "parts": ["seat"],
        "days": ["FRIDAY", "MONDAY", "SATURDAY", "SUNDAY", "THURSDAY", "TUESDAY", "WEDNESDAY"],
        "interval_minutes": None, "state_change": None,
    }

    assert adapter.configure(schedule_id, proposed, "sftp-secret", "SecureAB12!") == {}
    current = adapter.current(schedule_id)
    assert current == {
        "host": "backup.example.test", "port": 22, "user": "backup-user",
        "directory": "/backups/vcf", "ecdsa_fingerprint": None,
        "schedule_enabled": True, "full_time": "02:15", "interval_minutes": None,
        "state_change": None, "retention_mode": "count", "retention_value": 14,
        "incremental_enabled": None, "parts": ["seat"], "days": proposed["days"],
        "secret_configured": True, "sftp_secret_configured": True,
    }
    assert [request[:2] for request in transport.requests] == [
        ("GET", "/api/appliance/recovery/backup/schedules"),
        ("POST", "/api/appliance/recovery/backup/schedules"),
        ("GET", "/api/appliance/recovery/backup/schedules"),
        ("GET", "/api/appliance/recovery/backup/schedules/atlaso-vcf-backup"),
    ]
    assert "write-only" not in str(current)


def test_vcenter_first_schedule_create_refuses_new_competing_schedule() -> None:
    transport = FakeTransport(None, [(200, {"another-schedule": {}})])
    adapter = NativeBackup(
        source("vcenter"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{
            "id": "atlaso-vcf-backup", "product": "vcenter", "component_ids": ["vcenter"],
            "native_identity": {"schedule_id": "atlaso-vcf-backup", "exists": False},
        }]
    }
    proposed = {
        "host": "backup.example.test", "port": 22, "user": "backup-user",
        "directory": "/backups/vcf", "full_time": "02:15", "retention_mode": "count",
        "retention_value": 14, "parts": ["seat"],
    }

    with pytest.raises(RemoteError, match="appeared after discovery"):
        adapter.configure("atlaso-vcf-backup", proposed, "sftp-secret", "SecureAB12!")
    assert [request[:2] for request in transport.requests] == [
        ("GET", "/api/appliance/recovery/backup/schedules")
    ]


def test_vcenter_validation_uses_modern_backup_action_and_part_envelope() -> None:
    transport = FakeTransport(None, [(200, {"valid": True})])
    adapter = NativeBackup(
        source("vcenter"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{
            "id": "atlaso-vcf-backup", "product": "vcenter",
            "component_ids": ["vcenter"], "backup_parts": ["common", "seat"],
            "native_identity": {"schedule_id": "atlaso-vcf-backup", "exists": False},
        }]
    }
    result = adapter.validate(
        "atlaso-vcf-backup",
        {"host": "backup.example.test", "port": 22, "user": "backup-user",
         "directory": "/backups/vcf", "parts": ["common", "seat"]},
        "sftp-secret", "SecureAB12!",
    )
    assert result == {"supported": True, "valid": True, "diagnostics": []}
    method, path, _credentials, _header, body = transport.requests[0]
    assert (method, path) == (
        "POST", "/api/appliance/recovery/backup?action=validate"
    )
    assert body == {
        "parts": ["common", "seat"],
        "location_type": "SFTP",
        "location": "sftp://backup.example.test:22/backups/vcf",
        "location_user": "backup-user",
        "location_password": "sftp-secret",
        "backup_password": "SecureAB12!",
    }


@pytest.mark.parametrize(
    "passphrase",
    [
        "Short1!",
        "ThisPasswordIsFarTooLongForTheAppliance1!",
        "NoDigitsABC!",
        "NoSymbolAB12",
        "NonAscii\u00c9A12!",
    ],
)
def test_vcenter_passphrase_constraints_fail_before_remote_validation(passphrase: str) -> None:
    transport = FakeTransport(None, [])
    adapter = NativeBackup(
        source("vcenter"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{
            "id": "atlaso-vcf-backup", "product": "vcenter",
            "component_ids": ["vcenter"], "backup_parts": ["common"],
            "native_identity": {"schedule_id": "atlaso-vcf-backup", "exists": False},
        }]
    }
    with pytest.raises(ValueError, match="8 to 20 ASCII characters"):
        adapter.validate(
            "atlaso-vcf-backup",
            {"host": "backup.example.test", "user": "backup-user", "parts": ["common"]},
            "sftp-secret", passphrase,
        )
    assert transport.requests == []


def test_products_without_native_validation_report_gap_without_blocking() -> None:
    transport = FakeTransport(None, [])
    adapter = NativeBackup(
        source("nsx"), credentials(), transport_factory=lambda _target: transport
    )
    adapter._version = "9.1.1.0"
    adapter._inventory = {
        "groups": [{"id": "nsx-cluster", "product": "nsx", "component_ids": ["nsx-cluster"]}]
    }
    result = adapter.validate(
        "nsx-cluster", {"host": "backup.example.test"}, "sftp-secret", "SecureBackupPassAB12!"
    )
    assert result["supported"] is False
    assert "no documented native destination-validation endpoint" in result["warning"]
    assert transport.requests == []


@pytest.mark.parametrize("payload", [None, {}, {"errors": []}, {"executionStatus": "COMPLETED"}])
def test_unknown_native_validation_response_is_fail_closed(payload: Any) -> None:
    result = _validation_result(payload)
    assert result["supported"] is True
    assert result["valid"] is False


@pytest.mark.parametrize(
    "payload",
    [
        {"resultStatus": "SUCCEEDED", "executionStatus": "IN_PROGRESS"},
        {"resultStatus": "SUCCEEDED", "executionStatus": "PENDING"},
        {"valid": True, "executionStatus": "RUNNING"},
        {"resultStatus": "SUCCEEDED", "executionStatus": "FAILED"},
        {"valid": True, "executionStatus": "ERROR"},
    ],
)
def test_native_validation_execution_status_overrides_result_success(payload: dict[str, Any]) -> None:
    result = _validation_result(payload)
    assert result["supported"] is True
    assert result["valid"] is False
