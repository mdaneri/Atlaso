"""Contract tests for composite VCF Operations backup scopes."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from atlaso.app.services import vcf_operations_backup as operations
from atlaso.app.services.vcf_backup_native import _openssh_sha256_fingerprint
from atlaso.app.services.vcf_certificate_remote import Credentials, RemoteError, Target
from atlaso.app.services.vcf_operations_backup import (
    ManagedSddcBackup,
    OperationsBackup,
)

MANAGER_RESOURCE_ID = "d9e6cb38-4aad-4d70-863a-0d09b5536059"
MANAGER_UUID = "7fb33718-c559-4442-86e4-1e08f8fca7a3"
SYSTEM_UUID = "5723c8bb-9857-4f64-9f96-ef2f5a2b1f7c"
DOMAIN_ID = "ba3761c1-72c4-4090-8549-0997b32c63fe"


@pytest.mark.parametrize("finish", ["SUCCEEDED", "FAILED", "wrong-identity", "disconnected"])
def test_manager_validation_polls_one_async_request_without_configuration_or_replay(monkeypatch, finish):
    """Bind asynchronous validation to one ID and never retry its POST.

    Args:
        monkeypatch: Fixture replacing network and waiting only.
        finish: Terminal validation state or uncertain transport result.
    """
    child = ManagedSddcBackup(_source(["sddc"]), Credentials("admin", "test-password"), ManagerRequestFixture(), _manager())
    monkeypatch.setattr(child, "_group", lambda _group: {})
    monkeypatch.setattr(child, "_load_version", lambda: "9.1.1")
    monkeypatch.setattr(child, "_receiver_key", lambda _proposed: "SHA256:verified")
    monkeypatch.setattr(operations.time, "sleep", lambda _seconds: None)
    calls = []
    polls = 0

    def request(method, path, body=None):
        """Simulate delayed validation and an independently verified terminal response.

        Args:
            method: Native validation request method.
            path: Native validation route.
            body: Transient native payload.
        """
        nonlocal polls
        calls.append((method, path))
        if method == "POST":
            assert "password" in body["backupLocations"][0]
            assert set(body) == {"encryption", "backupLocations"}
            return {"id": "validation-1"}
        polls += 1
        if finish == "disconnected":
            raise RemoteError("Operations session request failed")
        return {"id": "another-id" if finish == "wrong-identity" else "validation-1",
                "executionStatus": "IN_PROGRESS" if polls == 1 else "COMPLETED",
                "resultStatus": finish}

    monkeypatch.setattr(child, "_call", request)
    proposed = {"host": "receiver.example.test", "port": 22, "user": "backup", "directory": "/backups/test",
                "ecdsa_fingerprint": "SHA256:verified", "full_time": "02:00"}
    if finish in {"wrong-identity", "disconnected"}:
        with pytest.raises(RemoteError):
            child.validate("sddc-manager", proposed, "test-password", "SecureBackupAB12!")
    else:
        result = child.validate("sddc-manager", proposed, "test-password", "SecureBackupAB12!")
        assert result["valid"] is (finish == "SUCCEEDED")
        assert polls == 2
    assert calls[0] == ("POST", "/v1/system/backup-configuration/validations?useAsyncValidation=true")
    assert sum(method == "POST" for method, _ in calls) == 1
    assert all(method in {"GET", "POST"} and "/validations" in path for method, path in calls)


@pytest.mark.parametrize("response,valid", [
    ({"resultStatus": "SUCCEEDED", "description": "completed"}, True),
    ({"resultStatus": "FAILED"}, False),
    ({"resultStatus": "SUCCEEDED", "executionStatus": "IN_PROGRESS"}, False),
    ({}, None),
])
def test_manager_validation_accepts_only_explicit_synchronous_terminal_result(monkeypatch, response, valid):
    """Handle the live 9.1 synchronous result without mistaking acceptance for success.

    Args:
        monkeypatch: Fixture replacing native requests and receiver verification.
        response: Manager response without an asynchronous validation identity.
        valid: Expected success or absence of an admissible result.
    """
    child = ManagedSddcBackup(_source(["sddc"]), Credentials("admin", "test-password"), ManagerRequestFixture(), _manager())
    monkeypatch.setattr(child, "_group", lambda _group: {})
    monkeypatch.setattr(child, "_load_version", lambda: "9.1.1")
    monkeypatch.setattr(child, "_receiver_key", lambda _proposed: "SHA256:verified")
    calls = []

    def request(method, path, body=None):
        """Return one immediate response and record that no write is retried.

        Args:
            method: Native request method.
            path: Native validation route.
            body: Request-local validation payload.
        """
        calls.append((method, path))
        return response

    monkeypatch.setattr(child, "_call", request)
    proposed = {"host": "receiver.example.test", "port": 22, "user": "backup", "directory": "/backups/test",
                "ecdsa_fingerprint": "SHA256:verified", "full_time": "02:00"}
    if valid is None:
        with pytest.raises(RemoteError, match="validation identity"):
            child.validate("sddc-manager", proposed, "test-password", "SecureBackupAB12!")
    else:
        assert child.validate("sddc-manager", proposed, "test-password", "SecureBackupAB12!")["valid"] is valid
    assert len(calls) == 1 and calls[0][0] == "POST"


def test_manager_configuration_waits_for_its_recorded_task_and_rejects_another_task(monkeypatch):
    """A configuration acceptance response is not native configuration completion.

    Args:
        monkeypatch: Fixture replacing native requests and public receiver verification.
    """
    child = ManagedSddcBackup(_source(["sddc"]), Credentials("admin", "test-password"), ManagerRequestFixture(), _manager())
    monkeypatch.setattr(child, "_group", lambda _group: {})
    monkeypatch.setattr(child, "_load_version", lambda: "9.1.1")
    monkeypatch.setattr(child, "_receiver_key", lambda _proposed: "SHA256:verified")
    responses = [{"id": "configuration-1", "status": "IN_PROGRESS"},
                 {"id": "configuration-1", "status": "IN_PROGRESS"},
                 {"id": "configuration-1", "status": "SUCCESSFUL"},
                 {"id": "unrelated-task", "status": "SUCCESSFUL"}]
    calls = []

    def request(method, path, body=None):
        """Return acceptance and native task states without repeating configuration.

        Args:
            method: Native HTTP method.
            path: Exact native route.
            body: Request-local native settings.
        """
        calls.append((method, path))
        return responses.pop(0)

    monkeypatch.setattr(child, "_call", request)
    proposed = {"host": "receiver.example.test", "port": 22, "user": "backup", "directory": "/backups/test",
                "ecdsa_fingerprint": "SHA256:verified", "full_time": "02:00"}
    reference = child.configure("sddc-manager", proposed, "test-password", "SecureBackupAB12!")
    assert child.configuration_status("sddc-manager", reference)["state"] == "running"
    assert child.configuration_status("sddc-manager", reference)["state"] == "succeeded"
    with pytest.raises(RemoteError, match="different"):
        child.configuration_status("sddc-manager", reference)
    assert sum(method == "PUT" for method, _ in calls) == 1
    assert calls[1:] == [("GET", "/v1/tasks/configuration-1")] * 3


def _source(scopes: list[str]) -> dict[str, Any]:
    """Build a confirmed synthetic Operations source.

    Args:
        scopes: Backup areas selected in the first step.
    """
    return {
        "kind": "fleet",
        "address": "ops.lab.internal",
        "port": 443,
        "fingerprint": "a" * 64,
        "operations_scopes": scopes,
    }


def _manager() -> dict[str, Any]:
    """Build an Operations inventory manager selected by its resource UUID."""
    return {
        "resource_id": MANAGER_RESOURCE_ID,
        "manager_uuid": MANAGER_UUID,
        "name": "sddcm-lab-01",
        "address": "sddcm.lab.internal",
        "port": 443,
        "domains": [
            {
                "resource_id": "cceb9fce-49c5-40a1-9a33-7f05544c0979",
                "domain_id": DOMAIN_ID,
                "name": "management-domain",
                "type": "MANAGEMENT",
                "vcenter_address": "vc01.lab.internal",
                "vcenter_port": 443,
            }
        ],
    }


def _lifecycle_inventory() -> dict[str, Any]:
    """Return one synthetic lifecycle scheduler and its eligible component."""
    return {
        "identity": "fleet-identity",
        "version": "9.1.1",
        "service": {"key": "fleet-lcm"},
        "groups": [
            {
                "id": "lcm-group-01",
                "product": "fleet",
                "component_ids": ["fleet-component-01"],
                "reservation_keys": ["sddc-manager-fqdn:sddcm.lab.internal"],
                "current": {"schedule_enabled": True},
                "native_identity": {"sddc_lcm_id": "lcm-group-01"},
            }
        ],
        "components": [
            {
                "id": "fleet-component-01",
                "group_id": "lcm-group-01",
                "name": "Operations Component",
                "product": "operations",
                "supported": True,
                "current": {"schedule_enabled": True},
            }
        ],
        "coverage_gaps": [],
    }


def _sddc_inventory(manager: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return one synthetic SDDC Manager scheduler and eligible component.

    Args:
        manager: Operations manager identity associated with this inventory.
    """
    selected = manager or _manager()
    native_identity = {
        "resource_type": "SDDC_MANAGER",
        "sddc_manager_id": selected["manager_uuid"],
    }
    return {
        "identity": "sddc-identity",
        "version": "9.1.1",
        "groups": [
            {
                "id": "sddc-manager",
                "product": "sddc_manager",
                "component_ids": ["sddc-manager"],
                "reservation_keys": [f"sddc-manager-id:{selected['manager_uuid']}"],
                "native_identity": native_identity,
                "current": {"schedule_enabled": True},
            }
        ],
        "components": [
            {
                "id": "sddc-manager",
                "group_id": "sddc-manager",
                "name": "SDDC Manager",
                "product": "sddc_manager",
                "supported": True,
                "current": {"schedule_enabled": True},
                "warnings": [],
            }
        ],
        "coverage_gaps": [],
    }


class FakeLifecycle:
    """Injectable lifecycle adapter that records authentication and dispatch."""

    def __init__(self, source: dict[str, Any], credentials: Credentials) -> None:
        """Bind the supplied synthetic source and credentials.

        Args:
            source: Confirmed Operations source passed by the composite.
            credentials: One request-local Operations credential object.
        """
        self.source = source
        self.credentials = credentials
        self.kind = "fleet"
        self.login_count = 0
        self.exit_count = 0
        self.discover_count = 0
        self.operations_inventory_count = 0
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def login(self) -> None:
        """Record a lifecycle API login."""
        self.login_count += 1

    def __exit__(self, *_args: Any) -> None:
        """Record closure of the fake lifecycle adapter.

        Args:
            *_args: Context manager exception state.
        """
        self.exit_count += 1

    def operations_inventory(self) -> dict[str, Any]:
        """Return synthetic connected manager inventory."""
        self.operations_inventory_count += 1
        return {"managers": [_manager()], "vcenters": []}

    def discover(self) -> dict[str, Any]:
        """Return synthetic lifecycle settings and coverage."""
        self.discover_count += 1
        return _lifecycle_inventory()

    def proposed(self, group: str, policy: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
        """Record and return the delegated proposal.

        Args:
            group: Native group forwarded by the composite.
            policy: Reviewed scheduling policy.
            receiver: Reviewed receiver details.
        """
        self.calls.append(("proposed", (group, policy, receiver)))
        return {"native_group": group, "policy": policy}

    def current(self, group: str) -> dict[str, Any]:
        """Record and return the selected native group's settings.

        Args:
            group: Native group forwarded by the composite.
        """
        self.calls.append(("current", (group,)))
        return {"native_group": group}

    def validate(self, group: str, proposed: dict[str, Any], password: str, passphrase: str) -> dict[str, Any]:
        """Record and return destination preflight delegation.

        Args:
            group: Native group forwarded by the composite.
            proposed: Reviewed public proposal.
            password: Synthetic request-local receiver password.
            passphrase: Synthetic request-local backup passphrase.
        """
        self.calls.append(("validate", (group, proposed, password, passphrase)))
        return {"valid": True, "native_group": group}

    def configure(self, group: str, proposed: dict[str, Any], password: str, passphrase: str) -> dict[str, Any]:
        """Record a configuration dispatch and return its native reference.

        Args:
            group: Native group forwarded by the composite.
            proposed: Reviewed public proposal.
            password: Synthetic request-local receiver password.
            passphrase: Synthetic request-local backup passphrase.
        """
        self.calls.append(("configure", (group, proposed, password, passphrase)))
        return {"configuration_id": "configuration-1"}

    def configuration_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Record polling of a native configuration reference.

        Args:
            group: Native group forwarded by the composite.
            reference: Unwrapped native reference.
        """
        self.calls.append(("configuration_status", (group, reference)))
        return {"state": "succeeded", "native_group": group}

    def start_backup(self, group: str, component_ids: list[str]) -> dict[str, Any]:
        """Record initial backup dispatch and return an artifact reference.

        Args:
            group: Native group forwarded by the composite.
            component_ids: Unwrapped native component IDs.
        """
        self.calls.append(("start_backup", (group, component_ids)))
        return {"reference": {"native_task_id": "backup-task-1"}}

    def backup_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Record read-only backup polling and return native artifact ownership.

        Args:
            group: Native group forwarded by the composite.
            reference: Unwrapped native task reference.
        """
        self.calls.append(("backup_status", (group, reference)))
        return {
            "state": "succeeded",
            "artifacts": [{"component_id": "sddc-manager", "path": "/backup/item"}],
        }

    def backup_task_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Record read-only task termination polling.

        Args:
            group: Native group forwarded by the composite.
            reference: Unwrapped native task reference.
        """
        self.calls.append(("backup_task_status", (group, reference)))
        return {"state": "succeeded"}


class FakeProxy:
    """Operations proxy double that records one shared session and requests."""

    def __init__(self, target: Target, credentials: Credentials) -> None:
        """Bind target and credential identity supplied by the composite.

        Args:
            target: Confirmed Operations TLS target.
            credentials: Same synthetic Operations credential used for lifecycle.
        """
        self.target = target
        self.credentials = credentials
        self.plugin_key = "plugin-key"
        self.login_count = 0
        self.close_count = 0
        self.calls: list[tuple[str, str, str, Any]] = []
        self.responses: dict[str, Any] = {}

    def login(self) -> None:
        """Record opening the Operations proxy session."""
        self.login_count += 1

    def close(self) -> None:
        """Record closure of the Operations proxy session."""
        self.close_count += 1

    def request(self, resource_id: str, method: str, path: str, body: Any) -> tuple[int, Any]:
        """Record an Operations resource-context request.

        Args:
            resource_id: Operations resource whose API is proxied.
            method: Native HTTP method.
            path: Native relative API path.
            body: Optional native request body.
        """
        self.calls.append((resource_id, method, path, body))
        return 200, self.responses.get(path, {})


class FakeManager:
    """Manager adapter double for mapping operations across scheduler groups."""

    def __init__(self, source: dict[str, Any], credentials: Credentials, proxy: FakeProxy, manager: dict[str, Any]) -> None:
        """Bind selected manager context.

        Args:
            source: Confirmed Operations source.
            credentials: Same request-local Operations account.
            proxy: Shared authenticated Operations proxy.
            manager: Selected connected manager record.
        """
        self.source = source
        self.credentials = credentials
        self.proxy = proxy
        self.manager = manager
        self.login_count = 0
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def login(self) -> None:
        """Record proxy-bound manager initialization."""
        self.login_count += 1

    def __exit__(self, *_args: Any) -> None:
        """Allow the composite to close the manager adapter.

        Args:
            *_args: Context manager exception state.
        """

    def discover(self) -> dict[str, Any]:
        """Return the matching synthetic manager scheduler."""
        return _sddc_inventory(self.manager)

    def proposed(self, group: str, policy: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
        """Record native proposal delegation.

        Args:
            group: Selected native scheduler.
            policy: Reviewed scheduling intent.
            receiver: Verified synthetic backup receiver.
        """
        self.calls.append(("proposed", (group, policy, receiver)))
        return {"native_group": group}

    def current(self, group: str) -> dict[str, Any]:
        """Record native current-settings delegation.

        Args:
            group: Selected native scheduler.
        """
        self.calls.append(("current", (group,)))
        return {"native_group": group}

    def validate(self, group: str, proposed: dict[str, Any], password: str, passphrase: str) -> dict[str, Any]:
        """Record native preflight delegation.

        Args:
            group: Selected native scheduler.
            proposed: Reviewed native settings.
            password: Synthetic receiver password.
            passphrase: Synthetic encryption passphrase.
        """
        self.calls.append(("validate", (group, proposed, password, passphrase)))
        return {"valid": True}

    def configure(self, group: str, proposed: dict[str, Any], password: str, passphrase: str) -> dict[str, Any]:
        """Record a manager configuration update.

        Args:
            group: Selected native scheduler.
            proposed: Reviewed native settings.
            password: Synthetic receiver password.
            passphrase: Synthetic encryption passphrase.
        """
        self.calls.append(("configure", (group, proposed, password, passphrase)))
        return {"native_task_id": "configuration-task-1"}

    def configuration_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Record native configuration-status reads.

        Args:
            group: Selected native scheduler.
            reference: Recorded native task reference.
        """
        self.calls.append(("configuration_status", (group, reference)))
        return {"state": "succeeded"}

    def start_backup(self, group: str, component_ids: list[str]) -> dict[str, Any]:
        """Record native backup dispatch.

        Args:
            group: Selected native scheduler.
            component_ids: Exact native component selection.
        """
        self.calls.append(("start_backup", (group, component_ids)))
        return {"reference": {"native_task_id": "manager-backup-1"}}

    def backup_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Record native artifact reads.

        Args:
            group: Selected native scheduler.
            reference: Recorded native task reference.
        """
        self.calls.append(("backup_status", (group, reference)))
        return {
            "state": "succeeded",
            "artifacts": [{"component_id": "sddc-manager", "path": "/backup/manager"}],
        }

    def backup_task_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Record native task termination reads.

        Args:
            group: Selected native scheduler.
            reference: Recorded native task reference.
        """
        self.calls.append(("backup_task_status", (group, reference)))
        return {"state": "succeeded"}


def _build_composite(scopes: list[str]) -> tuple[OperationsBackup, FakeLifecycle, list[FakeProxy], list[FakeManager], Credentials]:
    """Construct a composite with spies for each owned connection.

    Args:
        scopes: Selected Operations backup scopes.
    """
    source = _source(scopes)
    credentials = Credentials("ops-test-user", "Synthetic-Test-Password-992!")
    lifecycle = FakeLifecycle(source, credentials)
    proxies: list[FakeProxy] = []
    managers: list[FakeManager] = []

    def native_factory(received_source: dict[str, Any], received_credentials: Credentials) -> FakeLifecycle:
        """Bind the selected Operations test context.

        Args:
            received_source: Confirmed Operations endpoint.
            received_credentials: Shared request-local Operations credential.
        """
        assert received_source == source
        assert received_credentials is credentials
        return lifecycle

    def proxy_factory(target: Target, received_credentials: Credentials) -> FakeProxy:
        """Bind the selected Operations test context.

        Args:
            target: Confirmed Operations TLS target.
            received_credentials: Shared request-local Operations credential.
        """
        assert received_credentials is credentials
        proxy = FakeProxy(target, received_credentials)
        proxies.append(proxy)
        return proxy

    def manager_factory(
        received_source: dict[str, Any], received_credentials: Credentials,
        proxy: FakeProxy, manager: dict[str, Any],
    ) -> FakeManager:
        """Bind the selected Operations test context.

        Args:
            received_source: Confirmed Operations endpoint.
            received_credentials: Shared request-local Operations credential.
            proxy: Shared owned Operations session.
            manager: Discovered native manager identity.
        """
        assert received_source == source
        assert received_credentials is credentials
        child = FakeManager(received_source, received_credentials, proxy, manager)
        managers.append(child)
        return child

    composite = OperationsBackup(
        source,
        credentials,
        native_factory=native_factory,
        proxy_factory=proxy_factory,
        manager_factory=manager_factory,
    )
    return composite, lifecycle, proxies, managers, credentials


def test_both_scopes_share_operations_credentials_and_keep_scheduler_keys_separate():
    composite, lifecycle, proxies, managers, credentials = _build_composite(
        ["lifecycle", "sddc"]
    )

    composite.login()
    inventory = composite.discover()

    assert composite.kind == "fleet"
    assert composite.credentials is credentials
    assert lifecycle.credentials is credentials
    assert lifecycle.login_count == 1
    assert lifecycle.operations_inventory_count == 1
    assert lifecycle.discover_count == 1
    assert len(proxies) == 1
    assert proxies[0].credentials is credentials
    assert proxies[0].login_count == 1
    assert len(managers) == 1
    assert managers[0].credentials is credentials
    assert managers[0].proxy is proxies[0]
    assert managers[0].login_count == 1

    fleet_group = next(group for group in inventory["groups"] if group["backup_kind"] == "fleet")
    sddc_group = next(group for group in inventory["groups"] if group["backup_kind"] == "sddc")
    assert fleet_group["id"] == "lcm-group-01"
    assert sddc_group["id"] == f"sddc:{MANAGER_UUID}:sddc-manager"
    assert fleet_group["native_identity"]["operations_binding"] == {
        "scope": "lifecycle",
        "group_id": "lcm-group-01",
    }
    assert sddc_group["native_identity"]["operations_binding"] == {
        "scope": "sddc",
        "group_id": "sddc-manager",
        "resource_id": MANAGER_RESOURCE_ID,
        "manager_uuid": MANAGER_UUID,
    }
    assert fleet_group["reservation_keys"] == [
        "fleet-lifecycle:sddc-manager-fqdn:sddcm.lab.internal"
    ]
    assert sddc_group["reservation_keys"] == [f"sddc-manager-id:{MANAGER_UUID}"]
    assert set(fleet_group["reservation_keys"]).isdisjoint(sddc_group["reservation_keys"])

    components = {component["id"]: component for component in inventory["components"]}
    fleet_component = components["fleet-component-01"]
    sddc_component_id = f"sddc:{MANAGER_UUID}:sddc-manager"
    assert fleet_component["backup_scope"] == "lifecycle"
    assert components[sddc_component_id]["backup_scope"] == "sddc"
    assert components[sddc_component_id]["group_id"] == sddc_group["id"]
    assert inventory["managed_inventory"]["managers"] == [_manager()]


def test_sddc_only_needs_inventory_but_never_logs_into_or_discovers_fleet():
    composite, lifecycle, proxies, managers, _credentials = _build_composite(["sddc"])

    composite.login()
    inventory = composite.discover()

    assert lifecycle.login_count == 0
    assert lifecycle.discover_count == 0
    assert lifecycle.operations_inventory_count == 1
    assert len(proxies) == 1 and proxies[0].login_count == 1
    assert len(managers) == 1
    assert [group["backup_kind"] for group in inventory["groups"]] == ["sddc"]


def test_lifecycle_only_does_not_open_operations_proxy():
    composite, lifecycle, proxies, managers, _credentials = _build_composite(["lifecycle"])

    composite.login()
    inventory = composite.discover()

    assert lifecycle.login_count == 1
    assert lifecycle.operations_inventory_count == 1
    assert lifecycle.discover_count == 1
    assert proxies == []
    assert managers == []
    assert [group["backup_kind"] for group in inventory["groups"]] == ["fleet"]


def test_group_dispatch_wraps_references_and_maps_component_ids_back_to_public_ids():
    composite, lifecycle, _proxies, managers, _credentials = _build_composite(
        ["lifecycle", "sddc"]
    )
    inventory = composite.discover()
    sddc_group = f"sddc:{MANAGER_UUID}:sddc-manager"
    public_component = f"sddc:{MANAGER_UUID}:sddc-manager"
    policy = {"full_time": "02:00"}
    receiver = {"host": "backup.lab.internal"}
    proposed = {"native": "proposal"}

    assert composite.proposed(sddc_group, policy, receiver) == {"native_group": "sddc-manager"}
    assert composite.current(sddc_group) == {"native_group": "sddc-manager"}
    assert composite.validate(sddc_group, proposed, "test-sftp", "test-passphrase") == {
        "valid": True
    }
    wrapped_configuration = composite.configure(
        sddc_group, proposed, "test-sftp", "test-passphrase"
    )
    expected_binding = {
        "scope": "sddc",
        "group_id": "sddc-manager",
        "resource_id": MANAGER_RESOURCE_ID,
        "manager_uuid": MANAGER_UUID,
    }
    assert wrapped_configuration == {
        "operations_binding": expected_binding,
        "native_reference": {"native_task_id": "configuration-task-1"},
    }
    assert composite.configuration_status(sddc_group, wrapped_configuration) == {
        "state": "succeeded"
    }

    started = composite.start_backup(sddc_group, [public_component])
    wrapped_backup = started["reference"]
    assert wrapped_backup == {
        "operations_binding": expected_binding,
        "native_reference": {"native_task_id": "manager-backup-1"},
    }
    status = composite.backup_status(sddc_group, wrapped_backup)
    assert status["state"] == "succeeded"
    assert status["artifacts"] == [
        {"component_id": public_component, "path": "/backup/manager"}
    ]
    assert composite.backup_task_status(sddc_group, wrapped_backup) == {
        "state": "succeeded"
    }
    assert managers[0].calls == [
        ("proposed", ("sddc-manager", policy, receiver)),
        ("current", ("sddc-manager",)),
        ("validate", ("sddc-manager", proposed, "test-sftp", "test-passphrase")),
        ("configure", ("sddc-manager", proposed, "test-sftp", "test-passphrase")),
        (
            "configuration_status",
            ("sddc-manager", {"native_task_id": "configuration-task-1"}),
        ),
        ("start_backup", ("sddc-manager", ["sddc-manager"])),
        (
            "backup_status",
            ("sddc-manager", {"native_task_id": "manager-backup-1"}),
        ),
        (
            "backup_task_status",
            ("sddc-manager", {"native_task_id": "manager-backup-1"}),
        ),
    ]
    # A managed SDDC dispatch must not leak into the lifecycle scheduler.
    assert not any(call[0] in {"configure", "start_backup"} for call in lifecycle.calls)
    assert inventory["managed_inventory"]["managers"][0]["manager_uuid"] == MANAGER_UUID


def test_lifecycle_group_dispatches_only_to_lifecycle_adapter():
    composite, lifecycle, _proxies, managers, _credentials = _build_composite(
        ["lifecycle", "sddc"]
    )
    composite.discover()
    group = "lcm-group-01"
    public_component = "fleet-component-01"

    assert composite.start_backup(group, [public_component]) == {
        "reference": {
            "operations_binding": {"scope": "lifecycle", "group_id": group},
            "native_reference": {"native_task_id": "backup-task-1"},
        }
    }
    assert lifecycle.calls[-1] == ("start_backup", (group, [public_component]))
    assert managers[0].calls == []


class ManagerRequestFixture:
    """Supply deterministic native SDDC API responses through the Operations proxy."""

    def __init__(self, receiver_fingerprint: str | None = None) -> None:
        """Initialize exact identity and endpoint responses for one manager.

        Args:
            receiver_fingerprint: Optional RSA fingerprint for a read-only proposed check.
        """
        self.receiver_fingerprint = receiver_fingerprint
        self.calls: list[tuple[str, str, str, Any]] = []

    def request(self, resource_id: str, method: str, path: str, body: Any) -> tuple[int, Any]:
        """Return route-shaped responses and record resource-bound access.

        Args:
            resource_id: Operations manager resource selected for this request.
            method: Proxied native HTTP method.
            path: Proxied native API path.
            body: Proxied optional native JSON request.
        """
        self.calls.append((resource_id, method, path, body))
        if path == "/v1/system/appliance-info":
            return 200, {
                "role": "SddcManager",
                "version": "9.1.1",
                "ipAddresses": [{"type": "MANAGEMENT", "ipAddress": "192.0.2.10"}],
            }
        if path == "/v1/system":
            return 200, {"id": SYSTEM_UUID}
        if path.startswith("/v1/sddc-managers?"):
            return 200, [
                {
                    "id": MANAGER_UUID,
                    "ipAddress": "192.0.2.10",
                }
            ]
        if path == "/v1/system/backup-configuration":
            return 200, {}
        if path == "/v1/domains?pageNumber=0&pageSize=50":
            return 200, [{"id": DOMAIN_ID, "name": "Management Domain"}]
        if path == "/v1/vcenters?pageNumber=0&pageSize=50":
            return 200, [{"id": "vc01-id", "name": "vc01.lab.internal"}]
        if path == "/v1/nsxt-clusters?pageNumber=0&pageSize=50":
            return 200, [{"id": "nsxt-01", "name": "nsx.lab.internal"}]
        if path.startswith("/v1/system/backup-configuration/backup-locations?"):
            return 200, {
                "server": "backup.lab.internal",
                "port": 22,
                "sshFingerprint": self.receiver_fingerprint,
            }
        raise AssertionError(f"Unexpected fake native route: {path}")


def test_managed_sddc_discovery_matches_operations_uuid_and_management_ip():
    proxy = ManagerRequestFixture()
    child = ManagedSddcBackup(
        _source(["sddc"]),
        Credentials("ops-test-user", "Synthetic-Test-Password-992!"),
        proxy,
        _manager(),
    )

    child.login()
    inventory = child.discover()

    assert child._sddc_manager == {
        "id": MANAGER_UUID,
        "ipAddress": "192.0.2.10",
    }
    assert child._sddc_system == {"id": SYSTEM_UUID}
    assert child._sddc_system["id"] != child._sddc_manager["id"]
    assert inventory["groups"][0]["id"] == "sddc-manager"
    assert inventory["components"][0]["id"] == "sddc-manager"
    assert {component["product"] for component in inventory["components"]} == {
        "sddc_manager",
        "domain",
        "vcenter",
        "nsx",
    }
    assert [call[2] for call in proxy.calls] == [
        "/v1/system/appliance-info",
        "/v1/system",
        "/v1/sddc-managers?pageNumber=0&pageSize=50",
        "/v1/system/backup-configuration",
        "/v1/domains?pageNumber=0&pageSize=50",
        "/v1/vcenters?pageNumber=0&pageSize=50",
        "/v1/nsxt-clusters?pageNumber=0&pageSize=50",
    ]
    assert {call[0] for call in proxy.calls} == {MANAGER_RESOURCE_ID}


def test_managed_sddc_proposal_uses_receiver_rsa_key_and_checks_operations_fingerprint():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public_key = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    rsa_fingerprint = _openssh_sha256_fingerprint(rsa_public_key, "ssh-rsa")
    proxy = ManagerRequestFixture(rsa_fingerprint)
    child = ManagedSddcBackup(
        _source(["sddc"]),
        Credentials("ops-test-user", "Synthetic-Test-Password-992!"),
        proxy,
        _manager(),
    )
    child.login()
    child.discover()
    receiver = {
        "host": "backup.lab.internal",
        "port": 22,
        "username": "backup-user",
        "directory": "/backups/vcf",
        "ecdsa_fingerprint": "SHA256:synthetic-verified-ecdsa",
        "host_key": "ssh-ed25519 synthetic-verified-key",
        "rsa_host_key": rsa_public_key,
    }

    proposal = child.proposed(
        "sddc-manager",
        {"full_time": "02:00"},
        receiver,
    )

    assert proposal["host_key"] == rsa_public_key
    assert proposal["ecdsa_fingerprint"] == rsa_fingerprint
    assert proposal["host"] == "backup.lab.internal"
    assert proxy.calls[-1] == (
        MANAGER_RESOURCE_ID,
        "GET",
        "/v1/system/backup-configuration/backup-locations?serverIp=backup.lab.internal&port=22",
        None,
    )
