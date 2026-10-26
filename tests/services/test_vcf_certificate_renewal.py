"""Pure database tests for Atlaso-managed VCF certificate renewal policy."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from itsdangerous import SignatureExpired
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atlaso.app.database import Base
from atlaso.app.models import Job, Schedule, Setting, User
from atlaso.app.services import automation
from atlaso.app.services import vcf_certificate_renewal as renewal
from atlaso.app.services.vcf_certificate_remote import RemoteError

ADMIN = "admin"
POLICY_ID = "a" * 32
OPERATION_ID = "b" * 32
CONNECTION_ID = "c" * 32
FINGERPRINT = "d" * 64


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        session.add_all(
            [
                User(username=ADMIN, role="admin"),
                User(username="second-admin", role="admin"),
                User(username="service-operator", role="service-admin"),
            ]
        )
        session.commit()
        yield session
    engine.dispose()


def _policy(*, enabled: bool = True, operation_id: str | None = None) -> dict:
    return {
        "id": POLICY_ID,
        "actor": ADMIN,
        "connection_id": CONNECTION_ID,
        "certificate_id": "vcenter-machine-ssl",
        "host": "vcenter.example.test",
        "health_reference": {"mode": "vault", "vault_id": 1, "entry_id": 1},
        "confirmed_target_tls_fingerprint": FINGERPRINT,
        "profile_id": 1,
        "threshold_days": 30,
        "enabled": enabled,
        "schedule_id": 1,
        "cron_expression": "0 2 * * *",
        "timezone_name": "UTC",
        "observation": None,
        "operation_id": operation_id,
        "last_check_at": None,
    }


def _store_policy(db: Session, *, enabled: bool = True, operation_id: str | None = None) -> dict:
    policy = _policy(enabled=enabled, operation_id=operation_id)
    renewal._put(db, "policy", POLICY_ID, policy)
    db.commit()
    return policy


def _observation(days_remaining: float) -> dict:
    return {
        "connection_id": CONNECTION_ID,
        "certificate_id": "vcenter-machine-ssl",
        "host": "vcenter.example.test",
        "issuer": "Test CA",
        "native_auto_renewal": "Disabled",
        "eligible": True,
        "reason": "test observation",
        "expiry": "2030-01-01T00:00:00+00:00",
        "days_remaining": days_remaining,
        "fingerprint": FINGERPRINT,
    }


def test_disabled_policy_check_does_not_discover_or_open_remote_clients(db, monkeypatch):
    _store_policy(db, enabled=False)
    selected = Mock(side_effect=AssertionError("disabled policy must not inspect VCF"))
    client_factory = Mock(side_effect=AssertionError("disabled policy must not authenticate"))
    monkeypatch.setattr(renewal, "_selected", selected)
    monkeypatch.setattr(renewal, "OperationsClient", client_factory)

    result = renewal.check_policy(db, POLICY_ID)

    assert result == {"state": "disabled", "policy_id": POLICY_ID}
    selected.assert_not_called()
    client_factory.assert_not_called()
    assert db.scalars(select(Setting).where(Setting.key.startswith(renewal.PREFIX + "operation:"))).all() == []


@pytest.mark.parametrize(
    "days_remaining,expected",
    [(30, "proposal"), (31, "not_due")],
)
def test_check_policy_uses_expiry_threshold_and_suppresses_duplicate_proposals(
    db, monkeypatch, days_remaining, expected
):
    _store_policy(db)
    selected = Mock(return_value=_observation(days_remaining))
    client_factory = Mock(side_effect=AssertionError("discovery must not open a write workflow"))
    issue_certificate = Mock(side_effect=AssertionError("discovery must not issue certificates"))
    monkeypatch.setattr(renewal, "_selected", selected)
    monkeypatch.setattr(renewal, "OperationsClient", client_factory)
    monkeypatch.setattr(renewal.ca, "issue_certificate", issue_certificate)
    monkeypatch.setattr(renewal, "acquire_network_objects_write_lock", Mock())

    first = renewal.check_policy(db, POLICY_ID)
    second = renewal.check_policy(db, POLICY_ID)

    assert first["state"] == expected
    assert second["state"] == expected
    operations = db.scalars(
        select(Setting).where(Setting.key.startswith(renewal.PREFIX + "operation:"))
    ).all()
    assert len(operations) == (1 if expected == "proposal" else 0)
    client_factory.assert_not_called()
    issue_certificate.assert_not_called()


def test_default_enrollment_is_disabled_and_uses_real_timezone_schedule_validation(
    db, monkeypatch
):
    candidate = _observation(90)
    monkeypatch.setattr(renewal, "_inventory", Mock(return_value=[candidate]))
    monkeypatch.setattr(
        renewal,
        "_reference",
        Mock(return_value={"mode": "vault", "vault_id": 1, "entry_id": 1, "revision": "r1"}),
    )
    monkeypatch.setattr(renewal.native, "_ready_ca", Mock())
    monkeypatch.setattr(renewal, "acquire_network_objects_write_lock", Mock())
    client_factory = Mock(side_effect=AssertionError("saving a policy must not authenticate"))
    monkeypatch.setattr(renewal, "OperationsClient", client_factory)

    result = renewal.dispatch(
        db,
        ADMIN,
        "save_policy",
        {
            "connection_id": CONNECTION_ID,
            "certificate_id": "vcenter-machine-ssl",
            "profile_id": 1,
            "confirmed_target_tls_fingerprint": FINGERPRINT,
            "health_credential_vault_id": 1,
            "health_credential_entry_id": 1,
            "timezone_name": "America/Los_Angeles",
        },
    )

    _, policy = renewal._row(db, "policy", result["policy_id"])
    schedule = db.get(Schedule, result["schedule_id"])
    assert policy["threshold_days"] == 30
    assert policy["enabled"] is False
    assert policy["timezone_name"] == "America/Los_Angeles"
    assert schedule is not None and not schedule.enabled
    assert schedule.next_run_at is None
    assert json.loads(schedule.task_config_json) == {"policy_id": policy["id"]}
    client_factory.assert_not_called()


@pytest.mark.parametrize("proposal", [False, True])
def test_disable_existing_enrollment_is_local_and_retains_bindings(db, monkeypatch, proposal):
    """Outages and unavailable issuance prerequisites cannot prevent stopping checks.

    Args:
        db: Isolated policy database.
        monkeypatch: Fixture prohibiting remote or CA/credential access.
        proposal: Whether a discovery-only proposal must also be cancelled.
    """
    policy = _store_policy(db, operation_id=OPERATION_ID if proposal else None)
    schedule = Schedule(id=policy["schedule_id"], name="Renewal", task_type="vcf_certificate_renewal_check", task_config_json=json.dumps({"policy_id": POLICY_ID}), created_by=ADMIN, enabled=True, next_run_at=datetime(2030, 1, 1, tzinfo=timezone.utc))
    db.add(schedule)
    if proposal:
        renewal._put(db, "operation", OPERATION_ID, {"id": OPERATION_ID, "state": "proposal", "checkpoint": "discovered", "write_revision": 0})
    db.commit()
    for name in ("_inventory", "_reference", "_credentials", "OperationsClient"):
        monkeypatch.setattr(renewal, name, Mock(side_effect=AssertionError("disable must remain local")))
    monkeypatch.setattr(renewal.native, "_ready_ca", Mock(side_effect=AssertionError("CA/profile is unavailable")))
    result = renewal.dispatch(db, ADMIN, "save_policy", {"policy_id": POLICY_ID, "enabled": False, "connection_id": "changed", "profile_id": 999})
    current = renewal._row(db, "policy", POLICY_ID)[1]
    assert current == dict(policy, enabled=False)
    assert result["schedule_id"] == schedule.id
    assert not schedule.enabled and schedule.next_run_at is None
    assert renewal.check_policy(db, POLICY_ID)["state"] == "disabled"
    if proposal:
        assert renewal._row(db, "operation", OPERATION_ID)[1]["state"] == "cancelled"


@pytest.mark.parametrize("active_state", ["preparing", "prepared", "installing", "verifying", "needs_recovery"])
def test_disable_refuses_admitted_operations_without_changing_reservations(db, monkeypatch, active_state):
    """An operator must reconcile retained native work before editing enrollment.

    Args:
        db: Isolated policy database.
        monkeypatch: Fixture forbidding remote discovery.
        active_state: Admitted operation state that must remain protected.
    """
    policy = _store_policy(db, operation_id=OPERATION_ID)
    renewal._put(db, "operation", OPERATION_ID, {"id": OPERATION_ID, "state": active_state, "write_revision": 1})
    db.add(Setting(key="vcf_cert_lock:retained", value=OPERATION_ID))
    db.commit()
    monkeypatch.setattr(renewal, "_inventory", Mock(side_effect=AssertionError("disable must remain local")))
    with pytest.raises(renewal.RenewalError, match="active renewal"):
        renewal.dispatch(db, ADMIN, "save_policy", {"policy_id": POLICY_ID, "enabled": False})
    assert renewal._row(db, "policy", POLICY_ID)[1] == policy
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:retained")).value == OPERATION_ID


@pytest.mark.parametrize("binding", ["missing", "foreign", "malformed"])
def test_disable_never_mutates_an_unbound_schedule(db, binding):
    """A retained or reused schedule identity does not grant authority over it.

    Args:
        db: Isolated policy database.
        binding: Missing, foreign or malformed retained schedule binding.
    """
    policy = _store_policy(db)
    if binding != "missing":
        db.add(Schedule(id=policy["schedule_id"], name="Unbound", task_type="vcf_certificate_renewal_check", task_config_json="broken" if binding == "malformed" else json.dumps({"policy_id": "f" * 32}), created_by=ADMIN, enabled=True))
        db.commit()
    result = renewal.dispatch(db, ADMIN, "save_policy", {"policy_id": POLICY_ID, "enabled": False})
    assert result["schedule_id"] is None
    assert not renewal._row(db, "policy", POLICY_ID)[1]["enabled"]
    if binding != "missing":
        assert db.get(Schedule, policy["schedule_id"]).enabled


def test_automation_schedule_validator_accepts_iana_zone_and_rejects_unknown_zone():
    config = json.dumps({"policy_id": POLICY_ID})
    common = {
        "task_type": "vcf_certificate_renewal_check",
        "task_config_json": config,
        "schedule_kind": "cron",
        "cron_expression": "0 2 * * *",
        "run_once_at": None,
    }

    assert automation.validate_schedule_values(
        **common, timezone_name="America/Los_Angeles"
    ) == []
    errors = automation.validate_schedule_values(
        **common, timezone_name="Not/A_Real_Timezone"
    )
    assert any("IANA timezone" in error for error in errors)


def test_worker_check_job_ignores_malicious_execute_action_and_never_writes(
    db, monkeypatch
):
    policy = _policy(operation_id=OPERATION_ID)
    renewal._put(db, "policy", POLICY_ID, policy)
    operation = {
        "id": OPERATION_ID,
        "policy_id": POLICY_ID,
        "actor": ADMIN,
        "state": "prepared",
        "checkpoint": "csr_received",
        "write_revision": 1,
        "current_fingerprint": FINGERPRINT,
        "verification": {},
    }
    renewal._put(db, "operation", OPERATION_ID, operation)
    job = Job(
        id="job_check_malicious",
        type=renewal.CHECK_JOB_TYPE,
        status="pending",
        created_by=ADMIN,
        task_config_json=json.dumps(
            {"policy_id": POLICY_ID, "operation_id": OPERATION_ID, "action": "execute"}
        ),
        result="{}",
    )
    db.add(job)
    db.commit()
    monkeypatch.setattr(renewal, "_selected", Mock(return_value=_observation(10)))
    monkeypatch.setattr(renewal, "acquire_network_objects_write_lock", Mock())
    client_factory = Mock(side_effect=AssertionError("check jobs must not open Operations write sessions"))
    issue_certificate = Mock(side_effect=AssertionError("check jobs must not issue CA certificates"))
    monkeypatch.setattr(renewal, "OperationsClient", client_factory)
    monkeypatch.setattr(renewal.ca, "issue_certificate", issue_certificate)
    monkeypatch.setattr(renewal, "_prepare", Mock(side_effect=AssertionError("prepare dispatched")))
    monkeypatch.setattr(renewal, "_execute", Mock(side_effect=AssertionError("replace dispatched")))
    monkeypatch.setattr(renewal, "SessionLocal", sessionmaker(bind=db.get_bind(), expire_on_commit=False))

    renewal.run(job.id)

    db.refresh(job)
    _, current = renewal._row(db, "operation", OPERATION_ID)
    assert job.status == "succeeded"
    assert current["state"] == "prepared"
    assert current["checkpoint"] == "csr_received"
    client_factory.assert_not_called()
    issue_certificate.assert_not_called()
    renewal._prepare.assert_not_called()
    renewal._execute.assert_not_called()


def test_dispatch_rechecks_admin_authorization_before_any_remote_probe(db, monkeypatch):
    probe = Mock(side_effect=AssertionError("unauthorized probe reached remote endpoint"))
    monkeypatch.setattr(
        renewal, "PinnedHTTPS", Mock(return_value=Mock(probe=probe))
    )

    with pytest.raises(renewal.RenewalError, match="Administrator access"):
        renewal.dispatch(
            db,
            "service-operator",
            "probe",
            {"address": "vc.example.test", "confirmed_tls_fingerprint": FINGERPRINT},
        )

    probe.assert_not_called()


def test_dispatch_sanitizes_credential_and_remote_error_details(db, monkeypatch):
    monkeypatch.setattr(
        renewal,
        "_inventory",
        Mock(side_effect=RemoteError("password=secret-value token=opaque-value")),
    )

    with pytest.raises(renewal.RenewalError) as raised:
        renewal.dispatch(db, ADMIN, "inventory", {"connection_id": CONNECTION_ID})

    message = str(raised.value)
    assert "secret-value" not in message
    assert "opaque-value" not in message
    assert "password=" not in message


def test_only_one_check_task_is_admitted_per_policy(db, monkeypatch):
    _store_policy(db)
    monkeypatch.setattr(renewal, "acquire_network_objects_write_lock", Mock())

    first = renewal.dispatch(db, ADMIN, "check", {"policy_id": POLICY_ID})
    with pytest.raises(renewal.RenewalError, match="already has an active"):
        renewal.dispatch(db, ADMIN, "check", {"policy_id": POLICY_ID})

    jobs = db.scalars(
        select(Job).where(Job.type == renewal.CHECK_JOB_TYPE, Job.status == "pending")
    ).all()
    assert len(jobs) == 1
    assert jobs[0].id == first["job_id"]


def _prepared_review_state(db: Session) -> dict:
    policy = _policy(operation_id=OPERATION_ID)
    operation = {
        "id": OPERATION_ID,
        "policy_id": POLICY_ID,
        "actor": ADMIN,
        "state": "prepared",
        "checkpoint": "csr_received",
        "write_revision": 1,
        "current_fingerprint": FINGERPRINT,
        "policy_snapshot": renewal._policy_digest(policy),
        "ca_snapshot": {"profile": {"name": "vcenter-test"}},
        "replacement_certificate": {"fingerprint_sha256": "e" * 64},
        "csr_pem": "public csr",
        "leaf_pem": "public leaf",
        "root_pem": "public chain",
        "verification": {},
    }
    renewal._put(db, "policy", POLICY_ID, policy)
    renewal._put(db, "operation", OPERATION_ID, operation)
    db.commit()
    return operation


def test_replacement_review_is_actor_bound_single_use_and_rejects_stale_state(
    db, monkeypatch
):
    _prepared_review_state(db)
    monkeypatch.setattr(renewal, "_material", Mock(return_value=("public leaf", "public chain")))
    monkeypatch.setattr(renewal, "acquire_network_objects_write_lock", Mock())
    reviewer = renewal.dispatch(db, ADMIN, "review", {"operation_id": OPERATION_ID})
    token = reviewer["review_token"]

    with pytest.raises(renewal.RenewalError, match="belongs to another administrator"):
        renewal.dispatch(
            db,
            "second-admin",
            "execute",
            {"operation_id": OPERATION_ID, "review_token": token},
        )

    admitted = renewal.dispatch(
        db,
        ADMIN,
        "execute",
        {"operation_id": OPERATION_ID, "review_token": token},
    )
    assert admitted["job_id"].startswith("job_renewal_")
    with pytest.raises(renewal.RenewalError, match="stale or already used"):
        renewal.dispatch(
            db,
            ADMIN,
            "execute",
            {"operation_id": OPERATION_ID, "review_token": token},
        )

    _, operation = renewal._row(db, "operation", OPERATION_ID)
    assert operation["state"] == "installing"
    assert operation["checkpoint"] == "queued_replacement"


def test_replacement_review_rejects_changed_material(db, monkeypatch):
    _prepared_review_state(db)
    monkeypatch.setattr(renewal, "_material", Mock(return_value=("public leaf", "public chain")))
    monkeypatch.setattr(renewal, "acquire_network_objects_write_lock", Mock())
    token = renewal.dispatch(db, ADMIN, "review", {"operation_id": OPERATION_ID})["review_token"]
    _, operation = renewal._row(db, "operation", OPERATION_ID)
    operation["replacement_certificate"] = {"fingerprint_sha256": "f" * 64}
    renewal._put(db, "operation", OPERATION_ID, operation)
    db.commit()

    with pytest.raises(renewal.RenewalError, match="stale or already used"):
        renewal.dispatch(
            db,
            ADMIN,
            "execute",
            {"operation_id": OPERATION_ID, "review_token": token},
        )


def test_replacement_review_rejects_expired_token(db, monkeypatch):
    _prepared_review_state(db)
    monkeypatch.setattr(renewal, "_material", Mock(return_value=("public leaf", "public chain")))
    monkeypatch.setattr(renewal, "acquire_network_objects_write_lock", Mock())

    class ExpiredSerializer:
        def dumps(self, value: dict) -> str:
            del value
            return "expired-review-token"

        def loads(self, value: str, *, max_age: int) -> dict:
            del value, max_age
            raise SignatureExpired("expired")

    monkeypatch.setattr(renewal, "_serializer", ExpiredSerializer)
    token = renewal.dispatch(db, ADMIN, "review", {"operation_id": OPERATION_ID})["review_token"]

    with pytest.raises(renewal.RenewalError, match="Review expired or is invalid"):
        renewal.dispatch(
            db,
            ADMIN,
            "execute",
            {"operation_id": OPERATION_ID, "review_token": token},
        )
