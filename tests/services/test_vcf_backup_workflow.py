"""Durable workflow contracts for reviewed native VCF backup plans."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from itsdangerous import SignatureExpired

from atlaso.app.database import SessionLocal
from atlaso.app.models import Job, JobStep, Setting, User, Vault, VaultEntry
from atlaso.app.secrets import encrypt_secret
from atlaso.app.services import vcf_backup_workflow as workflow

RECEIVER = {
    "host": "backup.example.test",
    "port": 22,
    "username": "backup-user",
    "directory": "/backups",
    "host_key": "ecdsa-sha2-nistp256 AAAA",
    "rsa_host_key": "ssh-rsa AAAA",
    "ecdsa_fingerprint": "SHA256:receiver-pin",
    "interfaces": ["eth0"],
    "volume": "/srv/vcf-backups",
}
SFTP_SECRET = "sftp-secret-never-persist"
PASSPHRASE = "SecureBackupAB12!"
API_PASSWORD = "api-password-never-persist"


@pytest.mark.parametrize("changes", [
    {"fleet_incremental_mode": "unsupported"},
    {"fleet_incremental_mode": []},
    {"fleet_incremental_mode": "enabled"},
    {"fleet_schedule_mode": "disabled", "fleet_incremental_mode": "enabled"},
    {"fleet_incremental_interval_minutes": 239},
    {"fleet_incremental_interval_minutes": True},
    {"fleet_incremental_interval_minutes": 240.5},
    {"fleet_incremental_interval_minutes": "240"},
    {"fleet_incremental_interval_minutes": 2147483648},
    {"fleet_incremental_fallback_to_full": "false"},
])
def test_policy_rejects_invalid_operations_incremental_settings(changes):
    """Reject invalid incremental intent before reviewing a configuration.

    Args:
        changes: Unsupported policy values submitted by the browser.
    """
    with pytest.raises(workflow.BackupOperationError):
        workflow._policy(changes)


def test_policy_keeps_explicit_incremental_choices_and_safe_defaults():
    """Retain editable incremental intent while preserving schedules by default."""
    defaults = workflow._policy({})
    assert defaults["fleet_incremental_mode"] == "preserve"
    enabled = workflow._policy({
        "fleet_schedule_mode": "daily", "fleet_incremental_mode": "enabled",
        "fleet_incremental_interval_minutes": 240, "fleet_incremental_fallback_to_full": False,
    })
    assert enabled["fleet_incremental_interval_minutes"] == 240
    assert enabled["fleet_incremental_fallback_to_full"] is False


class FakeBackend:
    def __init__(self, *, kind: str = "sddc", fleet_size: int = 0) -> None:
        """Support init.

        Args:
            kind: Native product whose capability and scheduler behavior is simulated.
            fleet_size: Number of eligible components exposed by the fake Fleet group.
        """
        self.kind = kind
        self.initial = {
            "host": "old-backup.example.test",
            "port": 22,
            "user": "old-user",
            "directory": "/old",
            "ecdsa_fingerprint": "SHA256:old",
            "schedule_enabled": True,
            "full_time": "01:00",
            "interval_minutes": None,
            "incremental_enabled": None,
            "state_change": True,
            "retention_mode": "policy" if kind == "sddc" else "count",
            "retention_value": None if kind == "sddc" else 5,
            "secret_configured": False,
            "sftp_secret_configured": False,
        }
        if kind == "sddc":
            self.initial.update({
                "sddc_most_recent": 10,
                "sddc_hourly_days": 2,
                "sddc_daily_days": 15,
            })
        self.current_by_group: dict[str, dict[str, Any]] = {}
        self.config_writes: list[tuple[str, dict[str, Any]]] = []
        self.backup_starts: list[tuple[str, list[str]]] = []
        self.validations: list[tuple[str, dict[str, Any]]] = []
        self.validation_result: dict[str, Any] = {"supported": True, "valid": True}
        self.require_prepared_directory = False
        self.prepared_directories: set[str] = set()
        self.fail_prepare = False
        self.receiver_expected_password: str | None = None
        self.reject_native_login = False
        self.appliance_identities: dict[str, str] = {}
        self.login_passwords: list[str] = []
        self.after_configuration_status: Any = None
        self.after_validate: Any = None
        self.inventory_drift = False
        self.artifact_components: set[str] | None = None
        self.files: dict[str, tuple[int, int]] = {}
        self.baseline_files: dict[str, tuple[int, int]] = {}
        self.native_state = "succeeded"
        self.status_references: list[Any] = []
        self.native_task_terminal: bool | None = None
        self.native_task_state = "succeeded"
        self.native_task_status = "SUCCEEDED"
        self.component_ids = (
            ["component-a", "component-b"] if fleet_size == 2
            else ["vcenter"] if kind == "vcenter"
            else ["sddc-manager"]
        )
        self.group_id = "lcm-1" if kind == "fleet" else "vcenter-backup" if kind == "vcenter" else "sddc-manager"

    def inventory(self, address: str = "") -> dict[str, Any]:
        """Support inventory.

        Args:
            address: Source endpoint used to select the fake appliance identity.
        """
        current = dict(self.initial)
        if self.inventory_drift:
            current["host"] = "changed-after-review.example.test"
        appliance_id = self.appliance_identities.get(address, "manager-1")
        components = [
            {
                "id": native_id,
                "group_id": self.group_id,
                "name": f"Component {native_id}",
                "product": "SDDC_MANAGER" if self.kind == "fleet" else self.kind,
                "version": "9.1.1.0",
                "supported": True,
                "current": current,
                "warnings": [],
            }
            for native_id in self.component_ids
        ]
        identity = "fleet:lcm-manager.example.test" if self.kind == "fleet" else f"{self.kind}:{appliance_id}"
        return {
            "identity": identity,
            "version": "9.1.1.0",
            "components": components,
            "groups": [{
                "id": self.group_id,
                "product": self.kind if self.kind == "fleet" else self.kind,
                "component_ids": list(self.component_ids),
                "current": current,
                "native_identity": ({"sddc_manager_id": appliance_id} if self.kind != "vcenter" else
                                     {"schedule_id": self.group_id, "exists": False}),
                "reservation_keys": [f"{'vcenter-instance-uuid' if self.kind == 'vcenter' else 'sddc-manager-id'}:{appliance_id}"],
                "side_effects": [],
            }],
            "coverage_gaps": [],
        }


class FakeNative:
    backend: FakeBackend

    def __init__(self, source: dict[str, Any], credentials: Any) -> None:
        """Support init.

        Args:
            source: Confirmed native source metadata and credential reference.
            credentials: Invocation-local API credentials supplied to the fake adapter.
        """
        self.source = source
        self.credentials = credentials
        self.backend = FakeNative.backend
        self.logged_in = False

    def __enter__(self):
        return self

    def __exit__(self, *_args: Any) -> None:
        """Support exit.

        Args:
            *_args: Unused positional arguments accepted by this protocol stub.
        """
        return None

    def login(self) -> None:
        if self.backend.reject_native_login:
            raise workflow.RemoteError("native authentication failed")
        self.backend.login_passwords.append(self.credentials.password)
        self.logged_in = True

    def discover(self) -> dict[str, Any]:
        return self.backend.inventory(self.source["address"])

    def current(self, group: str) -> dict[str, Any]:
        """Support current.

        Args:
            group: Native scheduler group selected by the reviewed plan.
        """
        return dict(self.backend.current_by_group.get(group, self.backend.initial))

    def proposed(self, group: str, policy: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
        """Support proposed.

        Args:
            group: Native scheduler group selected by the reviewed plan.
            policy: Reviewed recurrence and retention inputs for the proposed configuration.
            receiver: Applied SFTP endpoint and reviewed per-group destination.
        """
        value = {
            "host": receiver["host"],
            "port": receiver["port"],
            "user": receiver["username"],
            "directory": receiver["directory"],
            "ecdsa_fingerprint": receiver["ecdsa_fingerprint"],
            "schedule_enabled": True,
            "full_time": policy["full_time"],
            "interval_minutes": None,
            "incremental_enabled": None,
            "state_change": policy["state_change"],
            "retention_mode": "policy" if self.backend.kind == "sddc" else policy["retention_mode"],
            "retention_value": None if self.backend.kind == "sddc" else policy["retention_value"],
            "secret_configured": True,
            "sftp_secret_configured": True,
        }
        if self.backend.kind == "sddc":
            value.update({
                "sddc_most_recent": policy["sddc_most_recent"],
                "sddc_hourly_days": policy["sddc_hourly_days"],
                "sddc_daily_days": policy["sddc_daily_days"],
            })
        return value

    def validate(self, group: str, proposed: dict[str, Any], *_secrets: str) -> dict[str, Any]:
        """Support validate.

        Args:
            group: Native scheduler group selected by the reviewed plan.
            proposed: Normalized public native configuration approved in review.
            *_secrets: Unused invocation-local SFTP and encryption secrets accepted by the stub.
        """
        self.backend.validations.append((group, dict(proposed)))
        if self.backend.require_prepared_directory and proposed["directory"] not in self.backend.prepared_directories:
            return {"supported": True, "valid": False, "diagnostics": ["MISSING_RECEIVER_DIRECTORY"]}
        if self.backend.after_validate is not None:
            self.backend.after_validate()
        return dict(self.backend.validation_result)

    def configure(self, group: str, proposed: dict[str, Any], *_secrets: str) -> dict[str, Any]:
        """Support configure.

        Args:
            group: Native scheduler group selected by the reviewed plan.
            proposed: Normalized public native configuration approved in review.
            *_secrets: Unused invocation-local SFTP and encryption secrets accepted by the stub.
        """
        self.backend.config_writes.append((group, dict(proposed)))
        self.backend.current_by_group[group] = dict(proposed)
        return {"native_task_id": "configuration-task-1"} if self.backend.kind == "fleet" else {}

    def configuration_status(self, _group: str, _reference: dict[str, Any]) -> dict[str, str]:
        """Support configuration status.

        Args:
            _group: Unused scheduler identity accepted by the configuration-status stub.
            _reference: Unused secret or native reference for the controlled failure stub.
        """
        if self.backend.after_configuration_status is not None:
            self.backend.after_configuration_status()
        return {"state": "succeeded"}

    def start_backup(self, group: str, component_ids: list[str]) -> dict[str, Any]:
        """Support start backup.

        Args:
            group: Native scheduler group selected by the reviewed plan.
            component_ids: Exact eligible native components requested for the initial backup.
        """
        self.backend.backup_starts.append((group, list(component_ids)))
        directory = self.current(group)["directory"]
        selected = self.backend.artifact_components
        if selected is None:
            selected = set(component_ids)
        self.backend.files = {
            f"{directory}/{component}.zip": (128, 1_798_000_000)
            for component in selected
        }
        return {
            "reference": {
                "kind": self.backend.kind,
                "group_id": group,
                "native_task_id": "backup-task-1",
                "component_ids": list(component_ids),
                "started_at": "2026-10-28T12:00:00+00:00",
            }
        }

    def backup_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Support backup status.

        Args:
            group: Native scheduler group selected by the reviewed plan.
            reference: Recorded native backup reference inspected without replaying it.
        """
        self.backend.status_references.append(reference)
        component_ids = self.backend.component_ids
        selected = self.backend.artifact_components
        artifacts = [] if self.backend.kind != "fleet" else [
            {
                "component_id": component,
                "path": f"{self.current(group)['directory']}/{component}.zip",
                "created_at": "2026-10-28T12:01:00Z",
            }
            for component in component_ids
            if selected is None or component in selected
        ]
        result = {"state": self.backend.native_state, "artifacts": artifacts}
        if self.backend.native_task_terminal is not None:
            result.update(
                native_task_terminal=self.backend.native_task_terminal,
                native_task_state=self.backend.native_task_state,
                native_task_status=self.backend.native_task_status,
            )
        return result


class FakeReceiverSession:
    backend: FakeBackend

    def __init__(self, _receiver: dict[str, Any], password: str) -> None:
        """Support init.

        Args:
            _receiver: Receiver metadata accepted by the fake storage session.
            password: Invocation-local SFTP password checked against the expected receiver credential.
        """
        self.backend = FakeReceiverSession.backend
        self.password = password

    def __enter__(self):
        if self.backend.receiver_expected_password is not None and self.password != self.backend.receiver_expected_password:
            raise workflow.ReceiverError("receiver authentication failed")
        self.backend.files = dict(self.backend.baseline_files)
        return self

    def __exit__(self, *_args: Any) -> None:
        """Support exit.

        Args:
            *_args: Unused positional arguments accepted by this protocol stub.
        """
        return None

    def prepare(self, directory: str) -> None:
        """Support prepare.

        Args:
            directory: Reviewed SFTP directory prepared before native destination validation.
        """
        if self.backend.fail_prepare:
            raise workflow.ReceiverError("receiver directory preparation failed")
        self.backend.prepared_directories.add(directory)

    def manifest(self, _directory: str) -> dict[str, tuple[int, int]]:
        """Support manifest.

        Args:
            _directory: Reviewed directory whose fake artifact manifest is returned.
        """
        return dict(self.backend.files)


class CapturedDispatcher:
    def __init__(self) -> None:
        self.call: tuple[Any, tuple[Any, ...], dict[str, Any]] | None = None

    def add_task(self, func: Any, *args: Any, **kwargs: Any) -> None:
        """Support add task.

        Args:
            func: Admitted background worker captured for explicit execution by the test.
            *args: Positional inputs retained for one admitted background invocation.
            **kwargs: Keyword inputs retained for one admitted background invocation.
        """
        self.call = (func, args, kwargs)

    def run(self) -> None:
        assert self.call is not None
        func, args, kwargs = self.call
        func(*args, **kwargs)


def settled_reconcile(db, actor, action, values, dispatcher):
    """Drain one admitted reconciliation for assertions about its final outcome.

    Args:
        db: Caller session reloaded after the background invocation.
        actor: Submitting operation owner.
        action: Reconcile action under test.
        values: Request-local recovery inputs.
        dispatcher: Captured background invocation to execute synchronously.
    """
    result = workflow.dispatch(db, actor, action, values, dispatcher)
    if dispatcher.call is not None:
        dispatcher.run()
        db.expire_all()
        result = workflow.operation_status(db, actor, values["operation_id"])
        if result.get("reconciliation_state") == "failed":
            raise workflow.BackupOperationError(result["reconciliation_error"])
    return result


@pytest.fixture()
def harness(client, monkeypatch) -> dict[str, Any]:
    """Support harness.

    Args:
        client: Isolated management application client and database fixture.
        monkeypatch: Fixture replacing native integrations and operation timing.
    """
    backend = FakeBackend()
    FakeNative.backend = backend
    FakeReceiverSession.backend = backend
    monkeypatch.setattr(workflow, "NativeBackup", FakeNative)
    monkeypatch.setattr(workflow, "ReceiverSession", FakeReceiverSession)
    monkeypatch.setattr(workflow, "require_receiver", lambda _db: dict(RECEIVER))
    monkeypatch.setattr(
        workflow,
        "receiver_revision",
        lambda receiver: {
            **{key: receiver[key] for key in (
                "host", "port", "username", "directory", "host_key",
                "rsa_host_key", "ecdsa_fingerprint", "interfaces", "volume",
            )},
            "revision": "revision-1",
        },
    )
    monkeypatch.setattr(workflow, "acquire_network_objects_write_lock", lambda _db: None)
    monkeypatch.setattr(
        workflow,
        "_secret_reference",
        lambda _db, value: {
            "vault_id": int(value["vault_id"]),
            "entry_id": int(value["entry_id"]),
            "label": str(value.get("label", f"key-{value['entry_id']}")),
            "revision": str(value.get("revision", "revision-1")),
        },
    )
    monkeypatch.setattr(workflow, "_secret", lambda _db, reference: SFTP_SECRET if reference["entry_id"] == 1 else PASSPHRASE)
    clock = {"now": 0.0}
    class FastClock:
        @staticmethod
        def monotonic() -> float:
            clock["now"] += 0.2
            return clock["now"]

        @staticmethod
        def sleep(_seconds: float) -> None:
            """Support sleep.

            Args:
                _seconds: Sleep duration skipped by the deterministic test clock.
            """
            return None

    monkeypatch.setattr(workflow, "time", FastClock)
    monkeypatch.setattr(workflow, "BACKUP_SECONDS", 1.0)
    with SessionLocal() as db:
        assert db.scalar(__import__("sqlalchemy").select(User).where(User.username == "admin")) is not None
    return {"client": client, "backend": backend, "monkeypatch": monkeypatch}


def source_values(kind: str = "sddc") -> dict[str, Any]:
    """Support source values.

    Args:
        kind: Native product whose capability and scheduler behavior is simulated.
    """
    values: dict[str, Any] = {
        "source_kind": kind,
        "address": "sddc.example.test" if kind != "fleet" else "ops.example.test",
        "port": 443,
        "confirmed_tls_fingerprint": "a" * 64,
        "confirmed": True,
        "username": "administrator",
        "password": API_PASSWORD,
    }
    return values


def secret_refs(*, sftp_revision: str = "revision-1", pass_revision: str = "revision-1") -> tuple[dict[str, Any], dict[str, Any]]:
    """Support secret refs.

    Args:
        sftp_revision: Ciphertext revision bound to the test SFTP password reference.
        pass_revision: Ciphertext revision bound to the test encryption-passphrase reference.
    """
    return (
        {"vault_id": 1, "entry_id": 1, "label": "SFTP password", "revision": sftp_revision},
        {"vault_id": 1, "entry_id": 2, "label": "Backup passphrase", "revision": pass_revision},
    )


def inspect_operation(db, *, kind: str = "sddc") -> tuple[dict[str, Any], dict[str, Any]]:
    """Support inspect operation.

    Args:
        db: Isolated database session containing operation checkpoints and task rows.
        kind: Native product whose capability and scheduler behavior is simulated.
    """
    result = workflow.dispatch(db, "admin", "inspect", source_values(kind), CapturedDispatcher())
    source_id = result["source_id"]
    inspected_source = {**source_values(kind), "source_id": source_id}
    return result, inspected_source


def inspect_vault_source(db, *, address: str = "sddc.example.test") -> tuple[dict[str, Any], dict[str, Any], int]:
    """Support inspect vault source.

    Args:
        db: Isolated database session containing operation checkpoints and task rows.
        address: Source endpoint used to select the fake appliance identity.
    """
    vault = Vault(name="vcf-backup-source", created_by="admin")
    db.add(vault)
    db.flush()
    uri = f"https://{address}"
    entry = VaultEntry(
        vault_id=vault.id,
        key="sddc-api-admin",
        secret_type="vcf_password",
        uris_json=json.dumps([uri]),
        username="administrator",
        encrypted_value=encrypt_secret(API_PASSWORD),
        created_by="admin",
    )
    db.add(entry)
    db.flush()
    values = {
        **source_values("sddc"),
        "address": address,
        "credential_vault_id": vault.id,
        "credential_entry_id": entry.id,
        "credential_uri": uri,
    }
    result = workflow.dispatch(db, "admin", "inspect", values, CapturedDispatcher())
    return result, {**values, "source_id": result["source_id"]}, entry.id


def review_operation(db, inspected: dict[str, Any], inspected_source: dict[str, Any], selected: list[str] | None = None) -> dict[str, Any]:
    """Support review operation.

    Args:
        db: Isolated database session containing operation checkpoints and task rows.
        inspected: Public discovery response with its current operation revision.
        inspected_source: Confirmed connection inputs for the inspected native source.
        selected: Optional exact component selection overriding all supported components.
    """
    sftp, passphrase = secret_refs()
    selected = selected or [item["id"] for item in inspected["components"] if item["supported"]]
    return workflow.dispatch(db, "admin", "review", {
        "operation_id": inspected["operation_id"],
        "revision": inspected["revision"],
        "sources": [inspected_source],
        "policy": {
            "full_time": "02:30",
            "retention_mode": "count",
            "retention_value": 14,
            "state_change": True,
            "sddc_most_recent": 10,
            "sddc_hourly_days": 2,
            "sddc_daily_days": 15,
        },
        "selected_ids": selected,
        "sftp_secret": sftp,
        "encryption_secret": passphrase,
    }, CapturedDispatcher())


def review_source_set(db, inspected: dict[str, Any], sources: list[dict[str, Any]]) -> dict[str, Any]:
    """Support review source set.

    Args:
        db: Isolated database session containing operation checkpoints and task rows.
        inspected: Public discovery response with its current operation revision.
        sources: Explicit source connection inputs for the combined review.
    """
    sftp, passphrase = secret_refs()
    return workflow.dispatch(db, "admin", "review", {
        "operation_id": inspected["operation_id"],
        "revision": inspected["revision"],
        "sources": sources,
        "policy": {
            "full_time": "02:30",
            "retention_mode": "count",
            "retention_value": 14,
            "state_change": True,
            "sddc_most_recent": 10,
            "sddc_hourly_days": 2,
            "sddc_daily_days": 15,
        },
        "selected_ids": [item["id"] for item in inspected["components"] if item["supported"]],
        "sftp_secret": sftp,
        "encryption_secret": passphrase,
    }, CapturedDispatcher())


def execute_operation(
    db,
    inspected: dict[str, Any],
    inspected_source: dict[str, Any],
    review: dict[str, Any],
    *,
    dispatcher: CapturedDispatcher | None = None,
    selected: list[str] | None = None,
    sftp_revision: str = "revision-1",
    pass_revision: str = "revision-1",
) -> tuple[dict[str, Any], CapturedDispatcher]:
    """Support execute operation.

    Args:
        db: Isolated database session containing operation checkpoints and task rows.
        inspected: Public discovery response with its current operation revision.
        inspected_source: Confirmed connection inputs for the inspected native source.
        review: Signed single-use review response consumed by execution.
        dispatcher: Optional background invocation collector used by the test.
        selected: Optional exact component selection overriding all supported components.
        sftp_revision: Ciphertext revision bound to the test SFTP password reference.
        pass_revision: Ciphertext revision bound to the test encryption-passphrase reference.
    """
    sftp, passphrase = secret_refs(sftp_revision=sftp_revision, pass_revision=pass_revision)
    dispatcher = dispatcher or CapturedDispatcher()
    result = workflow.dispatch(db, "admin", "execute", {
        "operation_id": inspected["operation_id"],
        "sources": [inspected_source],
        "policy": {
            "full_time": "02:30",
            "retention_mode": "count",
            "retention_value": 14,
            "state_change": True,
            "sddc_most_recent": 10,
            "sddc_hourly_days": 2,
            "sddc_daily_days": 15,
        },
        "selected_ids": selected or [item["id"] for item in inspected["components"] if item["supported"]],
        "sftp_secret": sftp,
        "encryption_secret": passphrase,
        "review_token": review["review_token"],
        "acknowledged": True,
        "replacements_confirmed": True,
        "recovery_ready": True,
    }, dispatcher)
    return result, dispatcher


def read_operation(db, operation_id: str) -> dict[str, Any]:
    """Support read operation.

    Args:
        db: Isolated database session containing operation checkpoints and task rows.
        operation_id: Owner-bound operation identifier whose durable state is loaded.
    """
    row = db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == workflow.PREFIX + operation_id))
    assert row is not None
    return json.loads(row.value)


def test_inspect_review_execute_is_actor_bound_single_use_and_secret_free(harness):
    """Verify inspect review execute is actor bound single use and secret free.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        state = read_operation(db, inspected["operation_id"])
        serialized = json.dumps(state)
        assert API_PASSWORD not in serialized
        assert SFTP_SECRET not in serialized
        assert PASSPHRASE not in serialized
        assert state["sources"][0]["credential_reference"] == {"mode": "manual", "username": "administrator"}

        queued, dispatcher = execute_operation(db, inspected, source, reviewed)
        assert queued["state"] == "queued"
        assert dispatcher.call is not None
        with pytest.raises(workflow.BackupOperationError, match="current changes"):
            execute_operation(db, inspected, source, reviewed)

        other = User(username="other-admin", role="admin", roles_json='["admin"]', enabled=True)
        db.add(other)
        db.commit()
        with pytest.raises(workflow.BackupOperationError, match="belongs to another administrator"):
            workflow.dispatch(db, "other-admin", "reconcile", {
                "operation_id": inspected["operation_id"], "sources": [source],
            }, CapturedDispatcher())


def test_operation_list_is_owner_filtered_safe_and_keyset_paginated(harness):
    """Verify operation list is owner filtered safe and keyset paginated.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    base = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
    operation_ids = []
    with SessionLocal() as db:
        for index in range(3):
            operation_id = f"{index + 1:032x}"
            job_id = f"job_list_{index:04d}"
            created_at = base + timedelta(seconds=index)
            operation_ids.append(operation_id)
            db.add(Job(
                id=job_id,
                type=workflow.JOB_TYPE,
                status="failed",
                created_by="admin",
                created_at=created_at,
                started_at=created_at,
                finished_at=created_at + timedelta(seconds=1),
                task_config_json=json.dumps({"operation_id": operation_id}),
            ))
            db.add(Setting(
                key=workflow.PREFIX + operation_id,
                value=json.dumps({
                    "operation_id": operation_id,
                    "actor": "admin",
                    "state": "needs_recovery",
                    "checkpoint": "backup_submitted",
                    "job_id": job_id,
                    "sources": [{"kind": "sddc", "address": "sddc.example.test", "port": 443}],
                    "plan": [{"component_ids": ["one", "two"]}],
                    "review_token": "must-not-leak",
                    "sftp_secret": {"revision": "secret-revision"},
                    "credential_reference": {"password": "plaintext-must-not-leak"},
                }),
                updated_at=created_at + timedelta(seconds=1),
            ))
        other_operation = "f" * 32
        other_job = "job_other_admin"
        db.add(Job(
            id=other_job,
            type=workflow.JOB_TYPE,
            status="failed",
            created_by="other-admin",
            created_at=base + timedelta(seconds=4),
            task_config_json=json.dumps({"operation_id": other_operation}),
        ))
        db.add(Setting(
            key=workflow.PREFIX + other_operation,
            value=json.dumps({
                "operation_id": other_operation, "actor": "other-admin", "job_id": other_job,
                "state": "needs_recovery", "checkpoint": "backup_submitted", "sources": [], "plan": [],
            }),
        ))
        # Discovery drafts without admitted jobs must not appear in the list.
        db.add(Setting(key=workflow.PREFIX + "e" * 32, value=json.dumps({"actor": "admin", "state": "draft"})))
        db.commit()

        first = workflow.list_operations(db, "admin", limit=1)
        assert [item["operation_id"] for item in first["items"]] == [operation_ids[2]]
        assert first["next_cursor"]
        item = first["items"][0]
        assert item["sources"] == [{"kind": "sddc", "address": "sddc.example.test", "port": 443}]
        assert item["component_count"] == 2
        assert item["created_at"] and item["updated_at"] and item["started_at"] and item["finished_at"]
        assert item["created_at"] == (base + timedelta(seconds=2)).isoformat()
        assert item["updated_at"] == (base + timedelta(seconds=3)).isoformat()
        for field in ("created_at", "updated_at", "started_at", "finished_at"):
            assert datetime.fromisoformat(item[field]).utcoffset() == timedelta(0)
        first_json = json.dumps(first)
        assert all(secret not in first_json for secret in ("must-not-leak", "secret-revision", "plaintext-must-not-leak"))
        assert set(item) == {
            "operation_id", "state", "checkpoint", "job_id", "sources", "component_count",
            "created_at", "updated_at", "started_at", "finished_at",
        }

        second = workflow.list_operations(db, "admin", limit=1, cursor=first["next_cursor"])
        third = workflow.list_operations(db, "admin", limit=1, cursor=second["next_cursor"])
        assert [second["items"][0]["operation_id"], third["items"][0]["operation_id"]] == operation_ids[1::-1]
        assert third["next_cursor"] is None
        with pytest.raises(workflow.BackupOperationError, match="cursor is invalid"):
            workflow.list_operations(db, "admin", cursor=first["next_cursor"] + "tampered")


def test_review_token_expiry_is_rejected_before_reservation_or_dispatch(harness):
    """Verify review token expiry is rejected before reservation or dispatch.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)

        class Expired:
            @staticmethod
            def loads(*_args: Any, **_kwargs: Any) -> Any:
                """Support loads.

                Args:
                    *_args: Unused positional arguments accepted by this protocol stub.
                    **_kwargs: Unused keyword arguments accepted by this protocol stub.
                """
                raise SignatureExpired("expired")

        harness["monkeypatch"].setattr(workflow, "_serializer", lambda: Expired())
        with pytest.raises(workflow.BackupOperationError, match="expired or is invalid"):
            execute_operation(db, inspected, source, reviewed)
        assert harness["backend"].config_writes == []
        assert db.scalar(__import__("sqlalchemy").select(Job)) is None


@pytest.mark.parametrize("change", ["policy", "selected", "sftp_revision", "pass_revision", "receiver"])
def test_review_revision_changes_are_rejected(harness, change):
    """Verify review revision changes are rejected.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
        change: Reviewed input mutation used to exercise revision refusal.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        values = {
            "operation_id": inspected["operation_id"],
            "sources": [source],
            "policy": {
                "full_time": "02:30", "retention_mode": "count", "retention_value": 14,
                "state_change": True, "sddc_most_recent": 10, "sddc_hourly_days": 2, "sddc_daily_days": 15,
            },
            "selected_ids": [item["id"] for item in inspected["components"] if item["supported"]],
            "sftp_secret": secret_refs()[0],
            "encryption_secret": secret_refs()[1],
            "review_token": reviewed["review_token"],
            "acknowledged": True, "replacements_confirmed": True, "recovery_ready": True,
        }
        if change == "policy":
            values["policy"]["full_time"] = "03:30"
        elif change == "selected":
            values["selected_ids"] = []
        elif change == "sftp_revision":
            values["sftp_secret"] = secret_refs(sftp_revision="revision-2")[0]
        elif change == "pass_revision":
            values["encryption_secret"] = secret_refs(pass_revision="revision-2")[1]
        else:
            harness["monkeypatch"].setattr(
                workflow, "receiver_revision", lambda _receiver: {"receiver": "revision-2"}
            )
        with pytest.raises(workflow.BackupOperationError):
            workflow.dispatch(db, "admin", "execute", values, CapturedDispatcher())
        assert harness["backend"].config_writes == []


def test_native_inventory_drift_blocks_writes_in_worker(harness):
    """Verify native inventory drift blocks writes in worker.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        harness["backend"].inventory_drift = True
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert "inventory or backup settings changed" in state["error"]
        assert harness["backend"].config_writes == []
        assert harness["backend"].backup_starts == []


def test_native_identity_change_after_preflight_blocks_configuration(harness):
    """Verify native identity change after preflight blocks configuration.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = FakeBackend(kind="vcenter")
    FakeNative.backend = backend
    FakeReceiverSession.backend = backend
    harness["backend"] = backend
    address = "vcenter-a.example.test"
    backend.appliance_identities[address] = "canonical-vcenter-a"
    values = {**source_values("vcenter"), "address": address, "confirmed_tls_fingerprint": "a" * 64}
    with SessionLocal() as db:
        inspected = workflow.dispatch(db, "admin", "inspect", values, CapturedDispatcher())
        source = {**values, "source_id": inspected["source_id"]}
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)

        def change_identity() -> None:
            backend.appliance_identities[address] = "different-vcenter-identity"

        backend.after_validate = change_identity
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert "identity changed after review" in state["error"]
        assert backend.validations
        assert backend.config_writes == []
        assert backend.backup_starts == []


def test_native_identity_change_after_configuration_blocks_backup_dispatch(harness):
    """Verify native identity change after configuration blocks backup dispatch.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = FakeBackend(kind="vcenter")
    FakeNative.backend = backend
    FakeReceiverSession.backend = backend
    harness["backend"] = backend
    address = "vcenter-a.example.test"
    backend.appliance_identities[address] = "canonical-vcenter-a"
    values = {**source_values("vcenter"), "address": address, "confirmed_tls_fingerprint": "a" * 64}
    with SessionLocal() as db:
        inspected = workflow.dispatch(db, "admin", "inspect", values, CapturedDispatcher())
        source = {**values, "source_id": inspected["source_id"]}
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        backend.after_configuration_status = lambda: backend.appliance_identities.__setitem__(address, "different-vcenter-identity")
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert "identity changed after review" in state["error"]
        assert len(backend.config_writes) == 1
        assert backend.backup_starts == []


def test_native_validation_failure_blocks_every_write(harness):
    """Verify native validation failure blocks every write.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    harness["backend"].validation_result = {
        "supported": True, "valid": False, "diagnostics": ["INVALID_DESTINATION"],
    }
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert len(harness["backend"].validations) == 1
        assert harness["backend"].config_writes == []
        assert harness["backend"].backup_starts == []


def test_receiver_directory_is_prepared_before_native_validation(harness):
    """Verify receiver directory is prepared before native validation.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    harness["backend"].require_prepared_directory = True
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()

        state = read_operation(db, inspected["operation_id"])
        destination = reviewed["review"]["components"][0]["receiver_directory"]
        assert state["state"] == "succeeded"
        assert destination in harness["backend"].prepared_directories
        assert harness["backend"].validations
        assert len(harness["backend"].config_writes) == 1
        assert len(harness["backend"].backup_starts) == 1


def test_receiver_preparation_failure_blocks_native_preflight_and_writes(harness):
    """Verify receiver preparation failure blocks native preflight and writes.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    harness["backend"].fail_prepare = True
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()

        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert "receiver directory preparation failed" in state["error"]
        assert harness["backend"].validations == []
        assert harness["backend"].config_writes == []
        assert harness["backend"].backup_starts == []


@pytest.mark.parametrize("invalid_passphrase", [
    "ShortAB12!",                 # fewer than 12 characters
    "SecureBackupABCD1234!",       # more than 20 characters
    "SECUREBACKUPAB12!",           # no lowercase letter
    "securebackupab12!",           # no uppercase letter
    "SecureBackupAB1!",            # fewer than two digits
    "SecureBackupAB12",            # no symbol
    "SecureBackupAB12É!",          # non-ASCII character
    "SecureBackupAB12 !",          # non-visible ASCII space
])
def test_invalid_shared_passphrase_blocks_native_calls_and_is_not_persisted(harness, invalid_passphrase):
    """Verify invalid shared passphrase blocks native calls and is not persisted.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
        invalid_passphrase: Passphrase that violates the shared native compatibility policy.
    """
    harness["monkeypatch"].setattr(
        workflow, "_secret",
        lambda _db, reference: SFTP_SECRET if reference["entry_id"] == 1 else invalid_passphrase,
    )
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        queued, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()

        state = read_operation(db, inspected["operation_id"])
        job = db.get(Job, queued["job_id"])
        assert state["state"] == "needs_recovery"
        assert "passphrase" in state["error"]
        assert invalid_passphrase not in json.dumps(state)
        assert job is not None and invalid_passphrase not in (job.error or "")
        assert harness["backend"].validations == []
        assert harness["backend"].config_writes == []
        assert harness["backend"].backup_starts == []
        assert job.steps
        assert all(step.status == "failed" and step.finished_at is not None for step in job.steps)


def test_successful_initial_backup_records_verified_fresh_receiver_artifacts(harness):
    """Verify successful initial backup records verified fresh receiver artifacts.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "succeeded"
        assert state["plan"][0]["checkpoint"] == "verified"
        assert state["plan"][0]["verified_components"]["sddc-manager"]
        assert len(harness["backend"].config_writes) == 1
        assert len(harness["backend"].backup_starts) == 1
        assert all(secret not in json.dumps(state) for secret in (API_PASSWORD, SFTP_SECRET, PASSPHRASE))


@pytest.mark.parametrize(
    ("task_state", "task_status", "message"),
    [("failed", "FAILED", "backup task failed"),
     ("succeeded", "COMPLETED_WITH_WARNINGS", "completed with warnings")],
)
def test_terminal_native_failure_or_warnings_stops_worker_without_proof(harness, task_state, task_status, message):
    """Verify terminal native failure or warnings stops worker without proof.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
        task_state: Normalized terminal native task state reported by the fake backend.
        task_status: Raw native task status distinguishing success from warnings.
        message: Expected sanitized failure text for the native outcome.
    """
    backend = harness["backend"]
    backend.native_state = "running"  # No complete per-component restorepoint proof.
    backend.native_task_terminal = True
    backend.native_task_state = task_state
    backend.native_task_status = task_status
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        queued, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert state["plan"][0]["checkpoint"] == "backup_submitted"
        assert message in state["error"].lower()
        assert len(backend.status_references) == 1
        assert backend.backup_starts
        assert backend.config_writes
        assert all(db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is not None for key in state["reservation_keys"])


def test_terminal_native_success_without_history_keeps_polling_and_reservation(harness):
    """Verify terminal native success without history keeps polling and reservation.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = harness["backend"]
    backend.native_state = "running"
    backend.native_task_terminal = True
    backend.native_task_state = "succeeded"
    backend.native_task_status = "SUCCEEDED"
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert "verification did not finish" in state["error"].lower()
        assert len(backend.status_references) > 1
        assert all(db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is not None for key in state["reservation_keys"])


def test_preexisting_files_are_not_treated_as_fresh_backup_evidence(harness):
    """Verify preexisting files are not treated as fresh backup evidence.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    harness["backend"].baseline_files = {"/backups/vcf/sddc-manager.zip": (128, 1_798_000_000)}
    harness["backend"].files = dict(harness["backend"].baseline_files)
    # The fake start produces the same metadata, so a native success cannot prove freshness.
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        receiver_directory = reviewed["review"]["components"][0]["receiver_directory"]
        harness["backend"].baseline_files = {
            receiver_directory + "/sddc-manager.zip": (128, 1_798_000_000)
        }
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert state["plan"][0]["checkpoint"] == "backup_submitted"
        assert harness["backend"].backup_starts


def test_interrupted_job_recovery_keeps_scheduler_reservation(harness):
    """Verify interrupted job recovery keeps scheduler reservation.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        queued, _dispatcher = execute_operation(db, inspected, source, reviewed)
        state = read_operation(db, inspected["operation_id"])
        locks = list(state["reservation_keys"])
        assert locks
        job = db.get(Job, queued["job_id"])
        assert job is not None
        completed = job.steps[0]
        completed.status = "succeeded"
        completed.result = json.dumps({"proof": "preserved"})
        pending = JobStep(
            id=f"{job.id}:pending-recovery-regression",
            job_id=job.id,
            component_key="pending-recovery-regression",
            label="Pending recovery regression",
            position=len(job.steps),
            status="pending",
        )
        job.steps.append(pending)
        db.commit()
        assert workflow.recover_interrupted_jobs(db) == 1
        db.refresh(job)
        recovered = read_operation(db, inspected["operation_id"])
        assert recovered["state"] == "needs_recovery"
        for key in locks:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is not None
        assert job.status == "failed"
        assert completed.status == "succeeded"
        assert completed.result == json.dumps({"proof": "preserved"})
        pending = next(step for step in job.steps if step.component_key == "pending-recovery-regression")
        assert pending.status == "failed" and pending.finished_at is not None


def test_active_scheduler_reservation_blocks_a_second_reviewed_operation(harness):
    """Verify active scheduler reservation blocks a second reviewed operation.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        first, first_source = inspect_operation(db)
        first_review = review_operation(db, first, first_source)
        first_queued, _ = execute_operation(db, first, first_source, first_review)

        second, second_source = inspect_operation(db)
        second_review = review_operation(db, second, second_source)
        with pytest.raises(workflow.BackupOperationError, match="reserves this native scheduler"):
            execute_operation(db, second, second_source, second_review)
        assert db.get(Job, first_queued["job_id"]) is not None
        assert harness["backend"].config_writes == []


def test_source_endpoint_change_after_review_is_rejected(harness):
    """Verify source endpoint change after review is rejected.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        changed = {**source, "address": "different.example.test"}
        with pytest.raises(workflow.BackupOperationError, match="address or confirmed fingerprint changed"):
            execute_operation(db, inspected, changed, reviewed)
        assert harness["backend"].config_writes == []


@pytest.mark.parametrize(
    ("second_identity", "duplicate"),
    [("same-vcenter-uuid", True), ("different-vcenter-uuid", False)],
)
def test_scheduler_assets_use_native_appliance_identity(harness, second_identity, duplicate):
    """Verify scheduler assets use native appliance identity.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
        second_identity: Verified identity presented by the second native appliance.
        duplicate: Whether both connections refer to the same native appliance.
    """
    backend = FakeBackend(kind="vcenter")
    FakeNative.backend = backend
    FakeReceiverSession.backend = backend
    harness["backend"] = backend
    first_address, second_address = "vc-a.example.test", "vc-b.example.test"
    backend.appliance_identities.update({
        first_address: "same-vcenter-uuid",
        second_address: second_identity,
    })
    fingerprint = "a" * 64  # Both appliances share the same wildcard certificate.
    first_values = {**source_values("vcenter"), "address": first_address, "confirmed_tls_fingerprint": fingerprint}
    second_values = {**source_values("vcenter"), "address": second_address, "confirmed_tls_fingerprint": fingerprint}
    with SessionLocal() as db:
        first = workflow.dispatch(db, "admin", "inspect", first_values, CapturedDispatcher())
        first_source = {**first_values, "source_id": first["source_id"]}
        second = workflow.dispatch(db, "admin", "inspect", {
            **second_values, "operation_id": first["operation_id"],
        }, CapturedDispatcher())
        second_source = {**second_values, "source_id": second["source_id"]}
        if duplicate:
            with pytest.raises(workflow.BackupOperationError, match="same native scheduler"):
                review_source_set(db, second, [first_source, second_source])
            return
        reviewed = review_source_set(db, second, [first_source, second_source])
        components = reviewed["review"]["components"]
        assert len(components) == 2
        assert components[0]["asset"] != components[1]["asset"]
        assert components[0]["receiver_directory"] != components[1]["receiver_directory"]


def test_revoked_actor_cannot_start_native_writes_from_queued_task(harness):
    """Verify revoked actor cannot start native writes from queued task.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        admin = db.scalar(__import__("sqlalchemy").select(User).where(User.username == "admin"))
        assert admin is not None
        admin.enabled = False
        db.commit()
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert "enabled administrator" in state["error"]
        assert harness["backend"].config_writes == []
        assert harness["backend"].backup_starts == []


def test_native_backup_failure_is_not_recorded_as_verified_success(harness):
    """Verify native backup failure is not recorded as verified success.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    harness["backend"].native_state = "failed"
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert state["plan"][0]["checkpoint"] == "backup_submitted"
        assert state["plan"][0].get("verified_components") is None
        assert "native initial backup failed" in state["error"]


def _install_two_group_inventory(harness):
    """Expose two independently configured Fleet LCM groups on one Operations source.

    Args:
        harness: Workflow fixtures whose native backend will provide the inventory.
    """
    backend = harness["backend"]
    backend.kind = "fleet"
    backend.group_id = "group-a"
    backend.component_ids = ["component-a", "component-b"]
    backend.current_by_group = {"group-a": dict(backend.initial), "group-b": dict(backend.initial)}

    def inventory(address=""):
        """Return two scheduler groups with their independently current settings.

        Args:
            address: Native endpoint accepted for parity with the fake inventory adapter.
        """
        current_a = dict(backend.current_by_group["group-a"])
        current_b = dict(backend.current_by_group["group-b"])
        service = {
            "address": "fleet.example.test", "port": 443, "base_path": "suite-api",
            "key": "fleet-lcm", "version": "9.1.1.0",
        }
        return {
            "identity": "fleet:fleet.example.test:pin:stable-groups-a-b",
            "version": "9.1.1.0",
            "components": [
                {"id": "component-a", "group_id": "group-a", "name": "Component A", "product": "SDDC_MANAGER",
                 "version": "9.1.1.0", "supported": True, "current": current_a, "warnings": []},
                {"id": "component-b", "group_id": "group-b", "name": "Component B", "product": "SDDC_MANAGER",
                 "version": "9.1.1.0", "supported": True, "current": current_b, "warnings": []},
            ],
            "groups": [
                {"id": "group-a", "product": "fleet", "component_ids": ["component-a"], "current": current_a,
                 "native_identity": {"sddc_lcm_id": "group-a", "sddc_manager_fqdns": ["manager-a.example.test"]},
                 "reservation_keys": ["sddc-manager-fqdn:manager-a.example.test"],
                 "side_effects": []},
                {"id": "group-b", "product": "fleet", "component_ids": ["component-b"], "current": current_b,
                 "native_identity": {"sddc_lcm_id": "group-b", "sddc_manager_fqdns": ["manager-b.example.test"]},
                 "reservation_keys": ["sddc-manager-fqdn:manager-b.example.test"],
                 "side_effects": []},
            ],
            "coverage_gaps": [],
            "service": service,
        }

    harness["monkeypatch"].setattr(FakeBackend, "inventory", lambda _self, address="": inventory(address))
    return backend


def test_multiple_native_groups_configure_and_backup_after_each_readback(harness):
    """Verify one group's config change does not look like drift in another group.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = _install_two_group_inventory(harness)
    with SessionLocal() as db:
        inspected, source = inspect_operation(db, kind="fleet")
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])

    assert state["state"] == "succeeded"
    assert [group for group, _ in backend.config_writes] == ["group-a", "group-b"]
    assert [group for group, _ in backend.backup_starts] == ["group-a", "group-b"]
    assert all(backend.current_by_group[group] == proposed for group, proposed in backend.config_writes)


def test_pending_group_external_drift_stops_before_its_configuration_write(harness):
    """Verify mutable drift in the next group is caught after the prior group completes.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = _install_two_group_inventory(harness)
    original_status = FakeNative.backup_status

    def drift_pending_group(native, group, reference):
        """Change the second group's reviewed settings after the first backup.

        Args:
            native: Fake adapter used by the running workflow.
            group: Group whose backup status is being checked.
            reference: Native task reference for that backup.
        """
        status = original_status(native, group, reference)
        if group == "group-a":
            backend.current_by_group["group-b"]["full_time"] = "03:45"
        return status

    harness["monkeypatch"].setattr(FakeNative, "backup_status", drift_pending_group)
    with SessionLocal() as db:
        inspected, source = inspect_operation(db, kind="fleet")
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])

    assert state["state"] == "needs_recovery"
    assert [group for group, _ in backend.config_writes] == ["group-a"]
    assert [group for group, _ in backend.backup_starts] == ["group-a"]
    assert "settings changed after preflight" in state["error"]


def test_fleet_review_rejects_partial_native_backup_group(harness):
    """Verify fleet review rejects partial native backup group.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = FakeBackend(kind="fleet", fleet_size=2)
    FakeNative.backend = backend
    FakeReceiverSession.backend = backend
    harness["backend"] = backend
    with SessionLocal() as db:
        inspected, source = inspect_operation(db, kind="fleet")
        supported = [item["id"] for item in inspected["components"] if item["supported"]]
        assert len(supported) == 2
        with pytest.raises(workflow.BackupOperationError, match="select every eligible component"):
            review_operation(db, inspected, source, supported[:1])
        assert backend.config_writes == []
        assert backend.backup_starts == []


def test_full_fleet_success_requires_native_artifact_for_every_component(harness):
    """Verify full fleet success requires native artifact for every component.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = FakeBackend(kind="fleet", fleet_size=2)
    FakeNative.backend = backend
    FakeReceiverSession.backend = backend
    harness["backend"] = backend
    backend.artifact_components = {"component-a", "component-b"}
    with SessionLocal() as db:
        inspected, source = inspect_operation(db, kind="fleet")
        selected = [item["id"] for item in inspected["components"] if item["supported"]]
        reviewed = review_operation(db, inspected, source, selected)
        _, dispatcher = execute_operation(db, inspected, source, reviewed, selected=selected)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "succeeded"
        assert set(state["plan"][0]["verified_components"]) == {"component-a", "component-b"}
        assert harness["backend"].backup_starts == [("lcm-1", ["component-a", "component-b"])]


def test_fleet_sftp_artifact_uris_verify_fresh_files_for_all_components():
    root = "/backups/vcf/2c3e1221bea57d5398e60adf/vcf/backups"
    components = [f"component-{index}" for index in range(8)]
    group = {
        "kind": "fleet",
        "receiver_directory": root,
        "native_component_ids": components,
        "proposed": {"host": "192.168.1.242", "port": 22, "user": "vcf-backup"},
        "artifact_baseline": {},
    }
    records = []
    files = {}
    for index, component in enumerate(components):
        uri = (
            "sftp://vcf-backup@192.168.1.242:22"
            f"{root}/runtime-{index}/9.1/vcfa/{component}/9.1/2026-10-29T21-57-56Z"
        )
        local_artifact = f"{uri.split(':22', 1)[1]}/backup.zip"
        group["artifact_baseline"][local_artifact] = (10, 100)
        files[local_artifact] = (1024 + index, 200 + index)
        records.append({"component_id": component, "path": uri})

    verified = workflow._verified_artifacts(group, {"state": "succeeded", "artifacts": records}, files)

    assert set(verified) == set(components)
    assert all(verified[component][0]["bytes"] == 1024 + index for index, component in enumerate(components))
    assert all(verified[component][0]["mtime"] == 200 + index for index, component in enumerate(components))
    assert all(verified[component][0]["path"] == path for component, path in zip(components, files, strict=True))


@pytest.mark.parametrize(
    "uri",
    [
        "https://vcf-backup@192.168.1.242:22/backups/vcf/a",
        "sftp://wrong-user@192.168.1.242:22/backups/vcf/a",
        "sftp://vcf-backup@192.168.1.243:22/backups/vcf/a",
        "sftp://vcf-backup@192.168.1.242.:22/backups/vcf/a",
        "sftp://vcf-backup@192.168.1.242:23/backups/vcf/a",
        "sftp://vcf-backup:secret@192.168.1.242:22/backups/vcf/a",
        "sftp://vcf-backup@192.168.1.242:bad/backups/vcf/a",
        "sftp://vcf-backup@192.168.1.242:22/backups/vcf/a?download=1",
        "sftp://vcf-backup@192.168.1.242:22/backups/vcf/a#fragment",
        "sftp://vcf-backup@192.168.1.242:22/backups/vcf/%2e%2e/outside",
        "sftp://vcf-backup@192.168.1.242:22/backups/vcf/%252e%252e/outside",
        "sftp://vcf-backup@192.168.1.242:22/backups/vcf/a%5cb",
        "sftp://vcf-backup@192.168.1.242:22/backups/vcf/%0ab",
        "sftp://vcf-backup@192.168.1.242:22/backups/vcf/a%2",
        "sftp://vcf-backup@192.168.1.242:22/backups/vcf-other/a",
    ],
)
def test_fleet_sftp_artifact_uri_rejects_untrusted_authority_and_path(uri):
    """Verify fleet sftp artifact uri rejects untrusted authority and path.

    Args:
        uri: Native artifact URI with the authority or path boundary under test.
    """
    group = {
        "kind": "fleet",
        "receiver_directory": "/backups/vcf",
        "proposed": {"host": "192.168.1.242", "port": 22, "user": "vcf-backup"},
    }

    assert workflow._fleet_artifact_path(uri, group) is None


def test_fleet_sftp_artifact_uri_double_encoded_separator_cannot_adopt_other_file():
    root = "/backups/vcf"
    artifact = f"{root}/foo/bar/backup.zip"
    group = {
        "kind": "fleet",
        "receiver_directory": root,
        "native_component_ids": ["component-1"],
        "proposed": {"host": "192.168.1.242", "port": 22, "user": "vcf-backup"},
        "artifact_baseline": {artifact: (10, 100)},
    }
    native_artifact = f"sftp://vcf-backup@192.168.1.242:22{root}/foo%252Fbar"
    fresh_files = {artifact: (2048, 200)}

    verified = workflow._verified_artifacts(
        group,
        {"state": "succeeded", "artifacts": [{"component_id": "component-1", "path": native_artifact}]},
        fresh_files,
    )

    assert verified == {}


def test_fleet_native_success_without_one_component_artifact_is_not_full_success(harness):
    """Verify fleet native success without one component artifact is not full success.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = FakeBackend(kind="fleet", fleet_size=2)
    FakeNative.backend = backend
    FakeReceiverSession.backend = backend
    harness["backend"] = backend
    backend.artifact_components = {"component-a"}
    harness["monkeypatch"].setattr(workflow, "BACKUP_SECONDS", 1)
    clock = {"now": 0.0}

    class FastClock:
        @staticmethod
        def monotonic() -> float:
            clock["now"] += 0.4
            return clock["now"]

        @staticmethod
        def sleep(_seconds: float) -> None:
            """Support sleep.

            Args:
                _seconds: Sleep duration skipped by the deterministic test clock.
            """
            return None

    harness["monkeypatch"].setattr(workflow, "time", FastClock)
    with SessionLocal() as db:
        inspected, source = inspect_operation(db, kind="fleet")
        selected = [item["id"] for item in inspected["components"] if item["supported"]]
        reviewed = review_operation(db, inspected, source, selected)
        _, dispatcher = execute_operation(db, inspected, source, reviewed, selected=selected)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert state["plan"][0]["checkpoint"] == "backup_submitted"
        assert state["plan"][0].get("verified_components") is None


def test_save_rejects_stale_row_after_concurrent_durable_writer(harness):
    """Verify save rejects stale row after concurrent durable writer.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, _source = inspect_operation(db)
        row = db.scalar(
            __import__("sqlalchemy").select(Setting).where(
                Setting.key == workflow.PREFIX + inspected["operation_id"]
            )
        )
        assert row is not None
        stale_state = json.loads(row.value)
        stale_state["checkpoint"] = "stale-writer-must-not-win"

        concurrent_state = json.loads(row.value)
        concurrent_state["checkpoint"] = "concurrent-writer-wins"
        with SessionLocal() as concurrent:
            persisted = concurrent.get(Setting, row.id)
            assert persisted is not None
            persisted.value = json.dumps(concurrent_state, sort_keys=True, separators=(",", ":"))
            concurrent.commit()

        with pytest.raises(workflow.BackupOperationError, match="changed concurrently"):
            workflow._save(db, row, stale_state)

    with SessionLocal() as verifier:
        persisted_state = read_operation(verifier, inspected["operation_id"])
        assert persisted_state["checkpoint"] == "concurrent-writer-wins"


def test_repeated_review_uses_returned_revision_and_revokes_earlier_token(harness):
    """Verify repeated review uses returned revision and revokes earlier token.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        first_review = review_operation(db, inspected, source)
        assert first_review["revision"] != inspected["revision"]

        second_review = review_operation(
            db, {**inspected, "revision": first_review["revision"]}, source
        )
        assert second_review["revision"] == first_review["revision"]
        assert second_review["review_token"] != first_review["review_token"]

        with pytest.raises(workflow.BackupOperationError, match="review was consumed"):
            execute_operation(db, inspected, source, first_review)
        assert db.scalar(__import__("sqlalchemy").select(Job)) is None

        result, dispatcher = execute_operation(db, inspected, source, second_review)
        assert result["state"] == "queued"
        assert dispatcher.call is not None


def _leave_backup_submitted_for_recovery(harness) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Run one task to its durable backup-submitted checkpoint without completion.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = harness["backend"]
    backend.native_state = "running"
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
    with SessionLocal() as db:
        state = read_operation(db, inspected["operation_id"])
    assert state["state"] == "needs_recovery"
    assert state["plan"][0]["checkpoint"] == "backup_submitted"
    return inspected, source, state


def test_reconcile_is_queued_without_native_calls_and_duplicate_is_not_dispatched(harness):
    """Admit promptly, keep credentials ephemeral, and deduplicate concurrent reads.

    Args:
        harness: Pinned fake native and receiver integrations.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    counts = (len(backend.config_writes), len(backend.backup_starts), len(backend.login_passwords))
    first, duplicate = CapturedDispatcher(), CapturedDispatcher()
    with SessionLocal() as db:
        queued = workflow.dispatch(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, first)
        assert queued["reconciliation_state"] == "queued"
        assert queued["state"] == "needs_recovery"
        assert first.call is not None
        again = workflow.dispatch(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, duplicate)
        assert again["reconciliation_job_id"] == queued["reconciliation_job_id"]
        assert duplicate.call is None
        persisted = json.dumps(read_operation(db, inspected["operation_id"]))
        assert API_PASSWORD not in persisted
        assert SFTP_SECRET not in persisted
        assert PASSPHRASE not in persisted
    assert counts == (len(backend.config_writes), len(backend.backup_starts), len(backend.login_passwords))
    first.run()
    with SessionLocal() as db:
        finished = workflow.operation_status(db, "admin", inspected["operation_id"])
        assert finished["reconciliation_state"] == "succeeded"
        assert finished["reconciliation_error"] == ""
        assert finished["state"] == "needs_recovery"  # Native task still running.
        assert read_operation(db, inspected["operation_id"])["reservation_keys"] == state["reservation_keys"]
    assert counts[:2] == (len(backend.config_writes), len(backend.backup_starts))


def test_reconcile_failure_is_durable_and_never_replays_native_work(harness):
    """Keep uncertain native state intact when an admitted read fails.

    Args:
        harness: Fake native adapters with controllable login failures.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    dispatcher = CapturedDispatcher()
    with SessionLocal() as db:
        workflow.dispatch(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, dispatcher)
    backend.reject_native_login = True
    dispatcher.run()
    with SessionLocal() as db:
        failed = workflow.operation_status(db, "admin", inspected["operation_id"])
        assert failed["reconciliation_state"] == "failed"
        assert failed["reconciliation_error"] == "native authentication failed"
        assert failed["state"] == state["state"]
        assert failed["checkpoint"] == state["checkpoint"]
        assert failed["reconciliation_finished_at"].endswith("+00:00")
    assert len(backend.config_writes) == len(backend.backup_starts) == 1


def test_reconcile_worker_rechecks_actor_and_does_not_use_revoked_credentials(harness):
    """Reject a queued read when its administrator loses authority.

    Args:
        harness: Owner-bound fake native and receiver integrations.
    """
    inspected, source, _state = _leave_backup_submitted_for_recovery(harness)
    dispatcher = CapturedDispatcher()
    with SessionLocal() as db:
        workflow.dispatch(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, dispatcher)
        actor = db.scalar(__import__("sqlalchemy").select(User).where(User.username == "admin"))
        actor.enabled = False
        db.commit()
    calls = len(harness["backend"].login_passwords)
    dispatcher.run()
    with SessionLocal() as db:
        failed = read_operation(db, inspected["operation_id"])
        assert failed["reconciliation_state"] == "failed"
        assert "enabled administrator" in failed["reconciliation_error"]
    assert len(harness["backend"].login_passwords) == calls


def test_reconcile_restart_invalidates_old_generation_without_changing_native_state(harness):
    """A restart permits a fresh read without reviving an old background run.

    Args:
        harness: Persisted uncertain native task and fake integrations.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    stale, fresh = CapturedDispatcher(), CapturedDispatcher()
    with SessionLocal() as db:
        old = workflow.dispatch(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, stale)
        assert workflow.recover_interrupted_jobs(db) == 1
        recovered = read_operation(db, inspected["operation_id"])
        assert recovered["reconciliation_state"] == "failed"
        assert recovered["state"] == state["state"]
        assert recovered["checkpoint"] == state["checkpoint"]
        new = workflow.dispatch(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, fresh)
        assert old["reconciliation_job_id"] != new["reconciliation_job_id"]
    calls = len(harness["backend"].login_passwords)
    stale.run()
    assert len(harness["backend"].login_passwords) == calls
    with SessionLocal() as db:
        assert workflow.operation_status(db, "admin", inspected["operation_id"])["reconciliation_state"] == "queued"
    fresh.run()
    with SessionLocal() as db:
        assert workflow.operation_status(db, "admin", inspected["operation_id"])["reconciliation_state"] == "succeeded"


def test_reconcile_adopts_exact_backup_reference_and_fresh_files_without_replaying(harness):
    """Verify reconcile adopts exact backup reference and fresh files without replaying.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    assert backend.files
    config_count = len(backend.config_writes)
    backup_count = len(backend.backup_starts)
    expected_reference = state["plan"][0]["backup_reference"]["reference"]
    backend.native_state = "succeeded"
    harness["monkeypatch"].setattr(FakeReceiverSession, "__enter__", lambda self: self)

    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, CapturedDispatcher())

    recovered = read_operation(SessionLocal(), inspected["operation_id"])
    assert backend.status_references[-1] == expected_reference
    assert recovered["state"] == "succeeded"
    assert recovered["plan"][0]["checkpoint"] == "verified"
    assert recovered["plan"][0]["verified_components"]["sddc-manager"]
    assert result["reconciliation"][0]["verified"] is True
    assert result["error"] == ""
    assert recovered["error"] == ""
    assert len(backend.config_writes) == config_count
    assert len(backend.backup_starts) == backup_count


def test_successful_reconciliation_preserves_recorded_completion_times(harness):
    """Keep elapsed task time stable when a successful backup is checked later.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "succeeded"
        job = db.get(Job, state["job_id"])
        finished = workflow._utc_iso(job.finished_at)
        step_finished = {step.id: workflow._utc_iso(step.finished_at) for step in job.steps}
        harness["monkeypatch"].setattr(FakeReceiverSession, "__enter__", lambda self: self)
        future = datetime.now(timezone.utc) + timedelta(days=2)
        harness["monkeypatch"].setattr(workflow, "utcnow", lambda: future)
        for _ in range(2):
            result = settled_reconcile(db, "admin", "reconcile", {
                "operation_id": inspected["operation_id"], "sources": [source],
            }, CapturedDispatcher())
            assert result["state"] == "succeeded"
            assert workflow._utc_iso(job.finished_at) == finished
            assert {step.id: workflow._utc_iso(step.finished_at) for step in job.steps} == step_finished
            item = workflow.list_operations(db, "admin")["items"][0]
            assert item["finished_at"] == finished


def test_reconcile_accepts_rotated_api_secret_at_same_vault_identity(harness):
    """Verify reconcile accepts rotated api secret at same vault identity.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = harness["backend"]
    backend.native_state = "running"
    with SessionLocal() as db:
        inspected, source, entry_id = inspect_vault_source(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        state = read_operation(db, inspected["operation_id"])
        assert state["state"] == "needs_recovery"
        assert state["plan"][0]["checkpoint"] == "backup_submitted"
        entry = db.get(VaultEntry, entry_id)
        assert entry is not None
        entry.encrypted_value = encrypt_secret("rotated-api-password")
        db.commit()

    backend.native_state = "succeeded"
    harness["monkeypatch"].setattr(FakeReceiverSession, "__enter__", lambda self: self)
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, CapturedDispatcher())
        assert result["state"] == "succeeded"
        assert result["reconciliation"][0]["verified"] is True
    assert backend.login_passwords[-1] == "rotated-api-password"


def test_execute_still_rejects_rotated_api_secret_after_review(harness):
    """Verify execute still rejects rotated api secret after review.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source, entry_id = inspect_vault_source(db)
        reviewed = review_operation(db, inspected, source)
        entry = db.get(VaultEntry, entry_id)
        assert entry is not None
        entry.encrypted_value = encrypt_secret("rotated-api-password")
        db.commit()
        with pytest.raises(workflow.BackupOperationError, match="credential selection changed"):
            execute_operation(db, inspected, source, reviewed)
        assert db.scalar(__import__("sqlalchemy").select(Job)) is None
        assert harness["backend"].config_writes == []
        assert harness["backend"].backup_starts == []


def test_reconcile_accepts_explicit_vault_replacement_for_same_endpoint(harness):
    """Verify reconcile accepts explicit vault replacement for same endpoint.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, source, entry_id = inspect_vault_source(db)
        _row, state = workflow._state(db, "admin", inspected["operation_id"])
        previous = db.get(VaultEntry, entry_id)
        assert previous is not None
        replacement = VaultEntry(
            vault_id=previous.vault_id,
            key="sddc-api-admin-rotated",
            secret_type="vcf_password",
            uris_json=previous.uris_json,
            username=previous.username,
            encrypted_value=encrypt_secret("replacement-api-password"),
            created_by="admin",
        )
        db.add(replacement)
        db.flush()
        replacement_source = {
            **source,
            "credential_vault_id": replacement.vault_id,
            "credential_entry_id": replacement.id,
        }
        resolved = workflow._recovery_source_inputs(db, state, {"sources": [replacement_source]})
        assert resolved[source["source_id"]][1].password == "replacement-api-password"
        assert state["sources"][0]["credential_reference"]["entry_id"] == entry_id
        assert state["sources"][0]["credential_reference"]["revision"] != workflow._reference(db, replacement_source, state["sources"][0])["revision"]


def test_running_native_backup_cannot_close_recovery(harness):
    """Verify running native backup cannot close recovery.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, _state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "running"
    backend.receiver_expected_password = "rotated-sftp-password"
    with pytest.raises(workflow.BackupOperationError, match="native task is still running"):
        with SessionLocal() as db:
            settled_reconcile(db, "admin", "reconcile", {
                "operation_id": inspected["operation_id"], "sources": [source],
                "close_reviewed": True,
            }, CapturedDispatcher())
    recovered = read_operation(SessionLocal(), inspected["operation_id"])
    assert recovered["state"] == "needs_recovery"
    assert recovered["checkpoint"] == "backup_submitted"


def test_terminal_native_task_can_close_unverified_artifact_history(harness):
    """Verify terminal native task can close unverified artifact history.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "running"  # Artifact history is still missing.
    backend.native_task_terminal = True
    backend.native_task_state = "succeeded"
    backend.native_task_status = "SUCCEEDED"
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source], "close_reviewed": True,
        }, CapturedDispatcher())
        assert result["state"] == "reconciled"
        assert result["reconciliation"][0]["native_backup"]["state"] == "running"
        assert "verified" not in result["reconciliation"][0]
        for key in state["reservation_keys"]:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is None


def test_failed_native_backup_can_close_without_receiver_auth(harness):
    """Verify failed native backup can close without receiver auth.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "failed"
    backend.receiver_expected_password = "rotated-sftp-password"
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source], "close_reviewed": True,
        }, CapturedDispatcher())
        assert result["state"] == "reconciled"
        assert result["reconciliation"][0]["native_backup"]["state"] == "failed"
        for key in state["reservation_keys"]:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is None


def test_reconciliation_cannot_adopt_success_after_policy_drift(harness):
    """Verify reconciliation cannot adopt success after policy drift.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, _state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "succeeded"
    backend.current_by_group[backend.group_id] = dict(backend.initial)
    harness["monkeypatch"].setattr(FakeReceiverSession, "__enter__", lambda self: self)
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, CapturedDispatcher())
        assert result["state"] == "needs_recovery"
        assert result["reconciliation"][0]["verified"] is False
        assert result["reconciliation"][0]["artifacts_verified"] is True
        assert result["reconciliation"][0]["configuration_matches_review"] is False
        assert "no longer matches" in result["reconciliation"][0]["warning"]
        assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == workflow.LOCK_PREFIX + "global")) is not None


def test_final_readback_detects_policy_changed_after_initial_backup(harness):
    """Verify final readback detects policy changed after initial backup.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    original_status = FakeNative.backup_status

    def drift_after_completion(native, group, reference):
        """Support drift after completion.

        Args:
            native: Fake adapter whose readback is changed at the selected checkpoint.
            group: Native scheduler group selected by the reviewed plan.
            reference: Recorded native backup reference inspected without replaying it.
        """
        status = original_status(native, group, reference)
        native.backend.current_by_group[group] = dict(native.backend.initial)
        return status

    harness["monkeypatch"].setattr(FakeNative, "backup_status", drift_after_completion)
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        _, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
    with SessionLocal() as db:
        current = read_operation(db, inspected["operation_id"])
        assert current["state"] == "needs_recovery"
        assert "before final verification" in current["error"]


def test_sddc_and_direct_nsx_require_separate_reviews_before_any_write(harness):
    """Verify sddc and direct nsx require separate reviews before any write.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    with SessionLocal() as db:
        inspected, sddc_source = inspect_operation(db)
        nsx_values = {**source_values("nsx"), "address": "nsx.example.test"}
        combined = workflow.dispatch(db, "admin", "inspect", {
            **nsx_values, "operation_id": inspected["operation_id"],
        }, CapturedDispatcher())
        nsx_source = {**nsx_values, "source_id": combined["source_id"]}
        sftp, passphrase = secret_refs()
        with pytest.raises(workflow.BackupOperationError, match="Configure SDDC Manager first"):
            workflow.dispatch(db, "admin", "review", {
                "operation_id": combined["operation_id"], "revision": combined["revision"],
                "sources": [sddc_source, nsx_source],
                "selected_ids": [item["id"] for item in combined["components"]],
                "policy": {"full_time": "02:30", "retention_mode": "count", "retention_value": 14},
                "sftp_secret": sftp, "encryption_secret": passphrase,
            }, CapturedDispatcher())
    assert harness["backend"].config_writes == []
    assert harness["backend"].backup_starts == []


@pytest.mark.parametrize("checkpoint", ["configuration_dispatch_pending", "backup_dispatch_pending"])
def test_unknown_native_dispatch_cannot_release_recovery_reservation(harness, checkpoint):
    """Verify unknown native dispatch cannot release recovery reservation.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
        checkpoint: Uncertain dispatch boundary whose reservation must remain held.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    with SessionLocal() as db:
        row, current = workflow._state(db, "admin", inspected["operation_id"])
        group = current["plan"][0]
        group["checkpoint"] = checkpoint
        group.pop("backup_reference", None)
        group.pop("configuration_reference", None)
        current["checkpoint"] = checkpoint
        workflow._save(db, row, current)
    counts = (len(harness["backend"].config_writes), len(harness["backend"].backup_starts))
    harness["backend"].receiver_expected_password = "rotated-sftp-password"
    harness["backend"].reject_native_login = True
    with SessionLocal() as db:
        with pytest.raises(workflow.BackupOperationError, match="no recorded outcome"):
            settled_reconcile(db, "admin", "reconcile", {
                "operation_id": inspected["operation_id"], "sources": [source], "close_reviewed": True,
            }, CapturedDispatcher())
    with SessionLocal() as db:
        assert read_operation(db, inspected["operation_id"])["state"] == "needs_recovery"
        for key in state["reservation_keys"]:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is not None
    assert counts == (len(harness["backend"].config_writes), len(harness["backend"].backup_starts))


def test_pre_dispatch_failure_can_close_without_stale_receiver_or_native_auth(harness):
    """Verify pre dispatch failure can close without stale receiver or native auth.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    backend = harness["backend"]
    backend.receiver_expected_password = "rotated-sftp-password"
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        queued, dispatcher = execute_operation(db, inspected, source, reviewed)
        dispatcher.run()
        failed = read_operation(db, inspected["operation_id"])
        assert failed["state"] == "needs_recovery"
        assert failed["checkpoint"] == "queued"
        assert workflow.operation_status(db, "admin", inspected["operation_id"])["can_close_without_credentials"] is True
        assert backend.validations == []
        assert backend.config_writes == []
        assert backend.backup_starts == []
        assert backend.prepared_directories == set()
        assert queued["state"] == "queued"
        locks = list(failed["reservation_keys"])
        assert locks
        assert all(db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is not None for key in locks)

    # Neither stale receiver credentials nor native authentication are needed
    # to close a task whose durable checkpoints prove that dispatch never began.
    backend.reject_native_login = True
    def stale_secret(_db, _reference):
        """Support stale secret.

        Args:
            _db: Unused database session accepted by the controlled failure stub.
            _reference: Unused secret or native reference for the controlled failure stub.
        """
        raise workflow.BackupOperationError("The selected Vault key changed after review.")
    harness["monkeypatch"].setattr(workflow, "_secret", stale_secret)
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source], "close_reviewed": True,
        }, CapturedDispatcher())
        assert result["state"] == "reconciled"
        assert result["checkpoint"] == "closed_without_replay"
        assert result["can_close_without_credentials"] is False
        assert result["reconciliation"] == []
        assert all(db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is None for key in locks)
    assert backend.validations == []
    assert backend.config_writes == []
    assert backend.backup_starts == []
    assert backend.prepared_directories == set()


def test_configuration_only_reconciliation_does_not_require_receiver_auth(harness):
    """Verify configuration only reconciliation does not require receiver auth.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    with SessionLocal() as db:
        row, current = workflow._state(db, "admin", inspected["operation_id"])
        group = current["plan"][0]
        group["checkpoint"] = "configuration_submitted"
        group["configuration_reference"] = {"native_task_id": "configuration-task-1"}
        group.pop("backup_reference", None)
        current["checkpoint"] = "configuration_submitted"
        workflow._save(db, row, current)

    # Config task readback is still required, but no backup artifact lookup is
    # possible or needed without a backup reference.
    harness["backend"].receiver_expected_password = "rotated-sftp-password"
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source], "close_reviewed": True,
        }, CapturedDispatcher())
        assert result["state"] == "reconciled"
        assert result["reconciliation"][0]["native_configuration"]["state"] == "succeeded"
        assert "native_backup" not in result["reconciliation"][0]
        for key in state["reservation_keys"]:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is None


def test_receiver_drift_keeps_native_success_unverified(harness):
    """Verify receiver drift keeps native success unverified.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "succeeded"
    backend.receiver_expected_password = "rotated-sftp-password"
    harness["monkeypatch"].setattr(
        workflow,
        "receiver_revision",
        lambda receiver: {
            **{key: receiver[key] for key in (
                "host", "port", "username", "directory", "host_key",
                "rsa_host_key", "ecdsa_fingerprint", "interfaces", "volume",
            )},
            "revision": "revision-2",
        },
    )
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, CapturedDispatcher())
        assert result["state"] == "needs_recovery"
        assert result["reconciliation"][0]["native_backup"]["state"] == "succeeded"
        assert result["reconciliation"][0]["verified"] is False
        assert "receiver changed" in result["reconciliation"][0]["warning"]
        assert "unverified" in result["recovery_warning"]
        for key in state["reservation_keys"]:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is not None


def test_unready_receiver_returns_native_report_and_allows_terminal_close(harness):
    """Verify unready receiver returns native report and allows terminal close.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "succeeded"
    backend.receiver_expected_password = "rotated-sftp-password"

    def unavailable_receiver(_db):
        """Support unavailable receiver.

        Args:
            _db: Unused database session accepted by the controlled failure stub.
        """
        raise workflow.ReceiverError("receiver is not ready")

    harness["monkeypatch"].setattr(workflow, "require_receiver", unavailable_receiver)
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source], "close_reviewed": True,
        }, CapturedDispatcher())
        assert result["state"] == "reconciled"
        assert result["reconciliation"][0]["native_backup"]["state"] == "succeeded"
        assert result["reconciliation"][0]["verified"] is False
        assert "receiver is not ready" in result["recovery_warning"]
        for key in state["reservation_keys"]:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is None


def test_changed_sftp_secret_returns_unverified_native_report(harness):
    """Verify changed sftp secret returns unverified native report.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
    """
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "succeeded"

    def changed_secret(_db, _reference):
        """Support changed secret.

        Args:
            _db: Unused database session accepted by the controlled failure stub.
            _reference: Unused secret or native reference for the controlled failure stub.
        """
        raise workflow.BackupOperationError("The reviewed backup secret changed; review again.")

    harness["monkeypatch"].setattr(workflow, "_secret", changed_secret)
    with SessionLocal() as db:
        result = settled_reconcile(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, CapturedDispatcher())
        assert result["state"] == "needs_recovery"
        assert result["reconciliation"][0]["native_backup"]["state"] == "succeeded"
        assert result["reconciliation"][0]["verified"] is False
        assert "secret changed" in result["reconciliation"][0]["warning"]
        for key in state["reservation_keys"]:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is not None


@pytest.mark.parametrize("revocation", ["stop-job", "disable-actor"])
def test_stop_or_actor_revocation_after_preflight_prevents_next_native_write(harness, revocation):
    """Verify stop or actor revocation after preflight prevents next native write.

    Args:
        harness: Fake native, receiver, clock, and administrator fixtures for workflow execution.
        revocation: Authority or task-state change injected after native preflight.
    """
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        queued, dispatcher = execute_operation(db, inspected, source, reviewed)

    def revoke_after_preflight() -> None:
        with SessionLocal() as db:
            if revocation == "stop-job":
                job = db.get(Job, queued["job_id"])
                assert job is not None
                job.status = "failed"
            else:
                user = db.scalar(__import__("sqlalchemy").select(User).where(User.username == "admin"))
                assert user is not None
                user.enabled = False
            db.commit()

    harness["backend"].after_validate = revoke_after_preflight
    dispatcher.run()

    state = read_operation(SessionLocal(), inspected["operation_id"])
    assert state["state"] == "needs_recovery"
    assert harness["backend"].config_writes == []
    assert harness["backend"].backup_starts == []
    expected = "task was stopped" if revocation == "stop-job" else "enabled administrator"
    assert expected in state["error"]
