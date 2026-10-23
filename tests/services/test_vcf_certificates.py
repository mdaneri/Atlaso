"""Durable-state checks for VCF appliance certificate operations."""

import json
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.models import Base, Job, Setting, User
from atlaso.app.services import vcf_certificates as service


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        session.add(User(username="admin", role="admin", enabled=True))
        session.commit()
        yield session
    engine.dispose()


def _record(db, checkpoint="queued_preparation"):
    op = "a" * 32
    state = {
        "operation_id": op,
        "actor": "admin",
        "checkpoint": checkpoint,
        "state": "preparing"
        if checkpoint == "queued_preparation"
        else "needs_recovery",
        "reservation_keys": ["vcf_cert_lock:identity"],
        "verification": {},
        "progress_percent": 10,
        "job_id": "job_certificate",
        "product": "vcenter",
    }
    db.add_all(
        [
            Setting(key=service.PREFIX + op, value=json.dumps(state)),
            Setting(key=state["reservation_keys"][0], value=op),
            Job(
                id="job_certificate",
                type=service.JOB_TYPE,
                created_by="admin",
                status="running",
                result="{}",
                task_config_json=json.dumps({"operation_id": op}),
            ),
        ]
    )
    db.commit()
    return op, state


def test_operation_state_is_actor_bound(db):
    op, _ = _record(db)
    with pytest.raises(
        service.CertificateOperationError, match="another administrator"
    ):
        service.operation_status(db, "other-admin", op)
    assert service.operation_status(db, "admin", op)["operation_id"] == op


def test_restart_marks_recovery_and_preserves_reservation(db):
    op, _ = _record(db)
    assert service.recover_interrupted_jobs(db) == 1
    state = json.loads(
        db.scalar(select(Setting).where(Setting.key == service.PREFIX + op)).value
    )
    job = db.get(Job, "job_certificate")
    assert state["state"] == "needs_recovery"
    assert state["checkpoint"] == "queued_preparation"
    assert (
        db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:identity")).value
        == op
    )
    assert job.status == "failed"


def test_manual_credentials_are_request_local_only():
    values = {"username": "admin", "password": "do-not-persist"}
    reference = {"mode": "manual"}
    manual = service._manual(values, reference)
    assert manual == values
    assert "do-not-persist" not in json.dumps(
        {"operation": "prepared", "credential_reference": reference}
    )
    assert service._manual(values, {"mode": "vault", "entry_id": 7}) is None


def test_names_reject_duplicate_or_unexpected_sans():
    expected = {"dns_names": ["vc.test"], "ip_addresses": ["192.0.2.10"]}
    with pytest.raises(service.CertificateOperationError):
        service._names(
            {
                "common_name": "vc.test",
                "dns_names": ["vc.test", "vc.test"],
                "ip_addresses": [],
            },
            expected,
        )
    with pytest.raises(service.CertificateOperationError):
        service._names(
            {"common_name": "vc.test", "dns_names": ["other.test"], "ip_addresses": []},
            expected,
        )


def test_queued_prepare_reconcile_releases_only_not_dispatched_reservation(
    db, monkeypatch
):
    op, state = _record(db)
    row = db.scalar(select(Setting).where(Setting.key == service.PREFIX + op))
    from atlaso.app.services.vcf_certificate_remote import Credentials

    result = service._reconcile(db, row, state, Credentials("admin", "unused"))
    assert result["checkpoint"] == "reconciled_not_dispatched"
    assert (
        db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:identity"))
        is None
    )


def test_uncertain_checkpoint_retains_reservation_and_refuses_retry(db):
    op, state = _record(db, "installation_dispatched")
    row = db.scalar(select(Setting).where(Setting.key == service.PREFIX + op))
    from atlaso.app.services.vcf_certificate_remote import Credentials

    with pytest.raises(
        service.CertificateOperationError, match="reservation is retained"
    ):
        service._reconcile(db, row, state, Credentials("admin", "unused"))
    assert (
        db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:identity")).value
        == op
    )
    assert "csr_pem" not in state


def _dispatch_mocks(monkeypatch):
    inspection = {
        "identity": "vc.test",
        "product_info": {"product": "vcenter", "version": "8.0"},
        "names": {
            "common_name": "vc.test",
            "dns_names": ["vc.test"],
            "ip_addresses": [],
        },
        "current_certificate": {"fingerprint_sha256": "old"},
        "baseline_health": {"status": "green"},
    }
    monkeypatch.setattr(service, "_confirmed", lambda *_: None)
    monkeypatch.setattr(service, "_inspect", lambda *_: dict(inspection))
    monkeypatch.setattr(
        service,
        "_ca_snapshot",
        lambda *_: {"root": {"fingerprint": "root"}, "profile": {"id": 1}},
    )
    monkeypatch.setattr(service, "_locks", lambda *_: ["vcf_cert_lock:identity"])
    monkeypatch.setattr(
        service,
        "_credentials",
        lambda *_: service.Credentials("admin", "request-secret"),
    )
    return inspection


def _prepare_values(**overrides):
    values = {
        "product": "vcenter",
        "address": "vc.test",
        "port": 443,
        "confirmed_tls_fingerprint": "a" * 64,
        "confirmed": True,
        "username": "admin",
        "password": "request-secret",
        "acknowledged": True,
        "recovery_ready": True,
        "recovery_reference": "snapshot after install",
        "profile_id": 1,
        "common_name": "vc.test",
        "dns_names": ["vc.test"],
        "ip_addresses": [],
    }
    values.update(overrides)
    return values


class _Tasks:
    def __init__(self):
        self.calls = []

    def add_task(self, func, *args, **kwargs):
        self.calls.append((func, args, kwargs))


def test_prepare_dispatch_persists_checkpoint_without_password(db, monkeypatch):
    _dispatch_mocks(monkeypatch)
    tasks = _Tasks()
    result = service.dispatch(db, "admin", "prepare", _prepare_values(), tasks)
    row = db.scalar(
        select(Setting).where(Setting.key == service.PREFIX + result["operation_id"])
    )
    serialized = row.value
    assert result["checkpoint"] == "queued_preparation"
    assert "request-secret" not in serialized
    assert "password" not in serialized
    assert len(tasks.calls) == 1
    assert (
        db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:identity"))
        is not None
    )


def test_prepare_requires_ack_before_inspection_or_dispatch(db, monkeypatch):
    inspect = Mock(side_effect=AssertionError("inspection must not happen"))
    monkeypatch.setattr(service, "_inspect", inspect)
    monkeypatch.setattr(service, "_confirmed", lambda *_: None)
    monkeypatch.setattr(
        service, "_credentials", lambda *_: service.Credentials("admin", "secret")
    )
    tasks = _Tasks()
    with pytest.raises(service.CertificateOperationError, match="Acknowledge"):
        service.dispatch(
            db, "admin", "prepare", _prepare_values(acknowledged=False), tasks
        )
    inspect.assert_not_called()
    assert tasks.calls == []
    assert (
        list(db.scalars(select(Setting).where(Setting.key.like(service.PREFIX + "%"))))
        == []
    )


def test_concurrent_prepare_reserves_target_once(db, monkeypatch):
    _dispatch_mocks(monkeypatch)
    tasks = _Tasks()
    service.dispatch(db, "admin", "prepare", _prepare_values(), tasks)
    with pytest.raises(
        service.CertificateOperationError, match="Another operation reserves"
    ):
        service.dispatch(db, "admin", "prepare", _prepare_values(), tasks)
    assert len(tasks.calls) == 1
    assert (
        len(
            list(
                db.scalars(
                    select(Setting).where(Setting.key.like(service.PREFIX + "%"))
                )
            )
        )
        == 1
    )


def test_review_token_actor_bound_single_use_and_expiry(db, monkeypatch):
    _dispatch_mocks(monkeypatch)
    monkeypatch.setattr(service, "_revalidate", lambda *_: None)
    tasks = _Tasks()
    prepared = service.dispatch(db, "admin", "prepare", _prepare_values(), tasks)
    row = db.scalar(
        select(Setting).where(Setting.key == service.PREFIX + prepared["operation_id"])
    )
    state = json.loads(row.value)
    state.update(
        state="prepared",
        checkpoint="certificate_prepared",
        replacement_certificate={"fingerprint_sha256": "new"},
        issuer="Atlaso",
        trust_changes=["root"],
        replacement_ready=True,
    )
    row.value = json.dumps(state)
    db.commit()
    request = _prepare_values(operation_id=prepared["operation_id"])
    reviewed = service.dispatch(db, "admin", "review", request, tasks)
    execute = dict(
        request,
        operation_id=prepared["operation_id"],
        token=reviewed["token"],
        acknowledged=True,
    )
    db.add(User(username="other-admin", role="admin", enabled=True))
    db.commit()
    with pytest.raises(
        service.CertificateOperationError, match="another administrator"
    ):
        service.dispatch(db, "other-admin", "execute", execute, tasks)
    done = service.dispatch(db, "admin", "execute", execute, tasks)
    assert done["checkpoint"] == "queued_installation"
    assert len(tasks.calls) == 2
    with pytest.raises(service.CertificateOperationError, match="Prepare successfully"):
        service.dispatch(db, "admin", "execute", execute, tasks)
    assert len(tasks.calls) == 2


def test_reviewed_profile_or_names_change_rejected(db, monkeypatch):
    _dispatch_mocks(monkeypatch)
    monkeypatch.setattr(service, "_revalidate", lambda *_: None)
    tasks = _Tasks()
    prepared = service.dispatch(db, "admin", "prepare", _prepare_values(), tasks)
    row = db.scalar(
        select(Setting).where(Setting.key == service.PREFIX + prepared["operation_id"])
    )
    state = json.loads(row.value)
    state.update(
        state="prepared",
        checkpoint="certificate_prepared",
        replacement_certificate={"fingerprint_sha256": "new"},
        issuer="Atlaso",
        trust_changes=["root"],
    )
    row.value = json.dumps(state)
    db.commit()
    request = _prepare_values(
        operation_id=prepared["operation_id"], common_name="changed.test"
    )
    with pytest.raises(service.CertificateOperationError, match="SANs"):
        service.dispatch(db, "admin", "review", request, tasks)


def test_review_expired_token_refused(db, monkeypatch):
    from itsdangerous import SignatureExpired

    _dispatch_mocks(monkeypatch)
    monkeypatch.setattr(service, "_revalidate", lambda *_: None)
    tasks = _Tasks()
    prepared = service.dispatch(db, "admin", "prepare", _prepare_values(), tasks)
    row = db.scalar(
        select(Setting).where(Setting.key == service.PREFIX + prepared["operation_id"])
    )
    state = json.loads(row.value)
    state.update(
        state="prepared",
        checkpoint="certificate_prepared",
        replacement_certificate={"fingerprint_sha256": "new"},
        issuer="Atlaso",
        trust_changes=["root"],
    )
    row.value = json.dumps(state)
    db.commit()
    request = _prepare_values(operation_id=prepared["operation_id"])
    reviewed = service.dispatch(db, "admin", "review", request, tasks)
    monkeypatch.setattr(
        service,
        "_serializer",
        lambda: Mock(loads=Mock(side_effect=SignatureExpired("expired"))),
    )
    with pytest.raises(service.CertificateOperationError, match="expired"):
        service.dispatch(
            db,
            "admin",
            "execute",
            dict(
                request,
                operation_id=prepared["operation_id"],
                token=reviewed["token"],
                acknowledged=True,
            ),
            tasks,
        )
    assert len(tasks.calls) == 1
