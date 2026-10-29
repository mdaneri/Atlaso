"""Durable workflow contracts for reviewed native VCF backup plans."""

from __future__ import annotations

import json
from typing import Any

import pytest
from itsdangerous import SignatureExpired

from atlaso.app.database import SessionLocal
from atlaso.app.models import Job, JobStep, Setting, User
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


class FakeBackend:
    def __init__(self, *, kind: str = "sddc", fleet_size: int = 0) -> None:
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
        self.after_validate: Any = None
        self.inventory_drift = False
        self.artifact_components: set[str] | None = None
        self.files: dict[str, tuple[int, int]] = {}
        self.baseline_files: dict[str, tuple[int, int]] = {}
        self.native_state = "succeeded"
        self.status_references: list[Any] = []
        self.component_ids = (
            ["component-a", "component-b"] if fleet_size == 2 else ["sddc-manager"]
        )
        self.group_id = "lcm-1" if kind == "fleet" else "sddc-manager"

    def inventory(self) -> dict[str, Any]:
        current = dict(self.initial)
        if self.inventory_drift:
            current["host"] = "changed-after-review.example.test"
        components = [
            {
                "id": native_id,
                "group_id": self.group_id,
                "name": f"Component {native_id}",
                "product": "SDDC_MANAGER" if self.kind == "fleet" else "sddc_manager",
                "version": "9.1.1.0",
                "supported": True,
                "current": current,
                "warnings": [],
            }
            for native_id in self.component_ids
        ]
        identity = "fleet:lcm-manager.example.test" if self.kind == "fleet" else "sddc:manager-1"
        return {
            "identity": identity,
            "version": "9.1.1.0",
            "components": components,
            "groups": [{
                "id": self.group_id,
                "product": self.kind if self.kind == "fleet" else "sddc_manager",
                "component_ids": list(self.component_ids),
                "current": current,
                "native_identity": {"sddc_manager_id": "manager-1"},
                "reservation_keys": ["sddc-manager-id:manager-1"],
                "side_effects": [],
            }],
            "coverage_gaps": [],
        }


class FakeNative:
    backend: FakeBackend

    def __init__(self, source: dict[str, Any], credentials: Any) -> None:
        self.source = source
        self.credentials = credentials
        self.backend = FakeNative.backend
        self.logged_in = False

    def __enter__(self):
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def login(self) -> None:
        self.logged_in = True

    def discover(self) -> dict[str, Any]:
        return self.backend.inventory()

    def current(self, group: str) -> dict[str, Any]:
        return dict(self.backend.current_by_group.get(group, self.backend.initial))

    def proposed(self, group: str, policy: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
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
        self.backend.validations.append((group, dict(proposed)))
        if self.backend.after_validate is not None:
            self.backend.after_validate()
        return dict(self.backend.validation_result)

    def configure(self, group: str, proposed: dict[str, Any], *_secrets: str) -> dict[str, Any]:
        self.backend.config_writes.append((group, dict(proposed)))
        self.backend.current_by_group[group] = dict(proposed)
        return {"native_task_id": "configuration-task-1"} if self.backend.kind == "fleet" else {}

    def configuration_status(self, _group: str, _reference: dict[str, Any]) -> dict[str, str]:
        return {"state": "succeeded"}

    def start_backup(self, group: str, component_ids: list[str]) -> dict[str, Any]:
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
        return {"state": self.backend.native_state, "artifacts": artifacts}


class FakeReceiverSession:
    backend: FakeBackend

    def __init__(self, _receiver: dict[str, Any], _password: str) -> None:
        self.backend = FakeReceiverSession.backend

    def __enter__(self):
        self.backend.files = dict(self.backend.baseline_files)
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def prepare(self, _directory: str) -> None:
        return None

    def manifest(self, _directory: str) -> dict[str, tuple[int, int]]:
        return dict(self.backend.files)


class CapturedDispatcher:
    def __init__(self) -> None:
        self.call: tuple[Any, tuple[Any, ...], dict[str, Any]] | None = None

    def add_task(self, func: Any, *args: Any, **kwargs: Any) -> None:
        self.call = (func, args, kwargs)

    def run(self) -> None:
        assert self.call is not None
        func, args, kwargs = self.call
        func(*args, **kwargs)


@pytest.fixture()
def harness(client, monkeypatch) -> dict[str, Any]:
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
            return None

    monkeypatch.setattr(workflow, "time", FastClock)
    monkeypatch.setattr(workflow, "BACKUP_SECONDS", 1.0)
    with SessionLocal() as db:
        assert db.scalar(__import__("sqlalchemy").select(User).where(User.username == "admin")) is not None
    return {"client": client, "backend": backend, "monkeypatch": monkeypatch}


def source_values(kind: str = "sddc") -> dict[str, Any]:
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
    return (
        {"vault_id": 1, "entry_id": 1, "label": "SFTP password", "revision": sftp_revision},
        {"vault_id": 1, "entry_id": 2, "label": "Backup passphrase", "revision": pass_revision},
    )


def inspect_operation(db, *, kind: str = "sddc") -> tuple[dict[str, Any], dict[str, Any]]:
    result = workflow.dispatch(db, "admin", "inspect", source_values(kind), CapturedDispatcher())
    source_id = result["source_id"]
    inspected_source = {**source_values(kind), "source_id": source_id}
    return result, inspected_source


def review_operation(db, inspected: dict[str, Any], inspected_source: dict[str, Any], selected: list[str] | None = None) -> dict[str, Any]:
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
    row = db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == workflow.PREFIX + operation_id))
    assert row is not None
    return json.loads(row.value)


def test_inspect_review_execute_is_actor_bound_single_use_and_secret_free(harness):
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


def test_review_token_expiry_is_rejected_before_reservation_or_dispatch(harness):
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)

        class Expired:
            @staticmethod
            def loads(*_args: Any, **_kwargs: Any) -> Any:
                raise SignatureExpired("expired")

        harness["monkeypatch"].setattr(workflow, "_serializer", lambda: Expired())
        with pytest.raises(workflow.BackupOperationError, match="expired or is invalid"):
            execute_operation(db, inspected, source, reviewed)
        assert harness["backend"].config_writes == []
        assert db.scalar(__import__("sqlalchemy").select(Job)) is None


@pytest.mark.parametrize("change", ["policy", "selected", "sftp_revision", "pass_revision", "receiver"])
def test_review_revision_changes_are_rejected(harness, change):
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


def test_native_validation_failure_blocks_every_write(harness):
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


def test_preexisting_files_are_not_treated_as_fresh_backup_evidence(harness):
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
    with SessionLocal() as db:
        inspected, source = inspect_operation(db)
        reviewed = review_operation(db, inspected, source)
        changed = {**source, "address": "different.example.test"}
        with pytest.raises(workflow.BackupOperationError, match="address or confirmed fingerprint changed"):
            execute_operation(db, inspected, changed, reviewed)
        assert harness["backend"].config_writes == []


def test_revoked_actor_cannot_start_native_writes_from_queued_task(harness):
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


def test_fleet_review_rejects_partial_native_backup_group(harness):
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


def test_fleet_native_success_without_one_component_artifact_is_not_full_success(harness):
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
    """Run one task to its durable backup-submitted checkpoint without completion."""
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


def test_reconcile_adopts_exact_backup_reference_and_fresh_files_without_replaying(harness):
    inspected, source, state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    assert backend.files
    config_count = len(backend.config_writes)
    backup_count = len(backend.backup_starts)
    expected_reference = state["plan"][0]["backup_reference"]["reference"]
    backend.native_state = "succeeded"
    harness["monkeypatch"].setattr(FakeReceiverSession, "__enter__", lambda self: self)

    with SessionLocal() as db:
        result = workflow.dispatch(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, CapturedDispatcher())

    recovered = read_operation(SessionLocal(), inspected["operation_id"])
    assert backend.status_references[-1] == expected_reference
    assert recovered["state"] == "succeeded"
    assert recovered["plan"][0]["checkpoint"] == "verified"
    assert recovered["plan"][0]["verified_components"]["sddc-manager"]
    assert result["reconciliation"][0]["verified"] is True
    assert len(backend.config_writes) == config_count
    assert len(backend.backup_starts) == backup_count


def test_running_native_backup_cannot_close_recovery(harness):
    inspected, source, _state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "running"
    with pytest.raises(workflow.BackupOperationError, match="native task is still running"):
        with SessionLocal() as db:
            workflow.dispatch(db, "admin", "reconcile", {
                "operation_id": inspected["operation_id"], "sources": [source],
                "close_reviewed": True,
            }, CapturedDispatcher())
    recovered = read_operation(SessionLocal(), inspected["operation_id"])
    assert recovered["state"] == "needs_recovery"
    assert recovered["checkpoint"] == "backup_submitted"


def test_reconciliation_cannot_adopt_success_after_policy_drift(harness):
    inspected, source, _state = _leave_backup_submitted_for_recovery(harness)
    backend = harness["backend"]
    backend.native_state = "succeeded"
    backend.current_by_group[backend.group_id] = dict(backend.initial)
    harness["monkeypatch"].setattr(FakeReceiverSession, "__enter__", lambda self: self)
    with SessionLocal() as db:
        result = workflow.dispatch(db, "admin", "reconcile", {
            "operation_id": inspected["operation_id"], "sources": [source],
        }, CapturedDispatcher())
        assert result["state"] == "needs_recovery"
        assert result["reconciliation"][0]["verified"] is False
        assert "no longer matches" in result["reconciliation"][0]["warning"]
        assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == workflow.LOCK_PREFIX + "global")) is not None


def test_final_readback_detects_policy_changed_after_initial_backup(harness):
    original_status = FakeNative.backup_status

    def drift_after_completion(native, group, reference):
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
    with SessionLocal() as db:
        with pytest.raises(workflow.BackupOperationError, match="no recorded outcome"):
            workflow.dispatch(db, "admin", "reconcile", {
                "operation_id": inspected["operation_id"], "sources": [source], "close_reviewed": True,
            }, CapturedDispatcher())
    with SessionLocal() as db:
        assert read_operation(db, inspected["operation_id"])["state"] == "needs_recovery"
        for key in state["reservation_keys"]:
            assert db.scalar(__import__("sqlalchemy").select(Setting).where(Setting.key == key)) is not None
    assert counts == (len(harness["backend"].config_writes), len(harness["backend"].backup_starts))


@pytest.mark.parametrize("revocation", ["stop-job", "disable-actor"])
def test_stop_or_actor_revocation_after_preflight_prevents_next_native_write(harness, revocation):
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
