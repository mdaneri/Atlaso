"""Durable-state checks for VCF appliance certificate operations."""

import json
from unittest.mock import MagicMock, Mock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.models import Base, Job, Setting, User
from atlaso.app.services import vcf_certificates as service
from atlaso.app.services.vcf_certificate_remote import RemoteError


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
        lambda *_: {
            "root": {"fingerprint_sha256": "a" * 64},
            "profile": {"id": 1, "name": "vCenter Profile", "key_size": 2048},
        },
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


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("legacy", [False, True])
def test_srm_health_baseline_preserves_accepted_native_variants(wrapped, legacy):
    rows = [
        {
            "service_name" if legacy else "id": "service",
            "startup_type": "automatic",
            "service_status" if legacy else "is_running": "running" if legacy else True,
            "url": "excluded",
        }
    ]
    health = {"list": rows} if wrapped else rows
    assert service.healthy_services("srm", health)
    baseline = {"list": service._srm_service_rows(health)}
    assert baseline == {
        "list": [
            {
                "id": "service",
                "name": "service",
                "startup_type": "automatic",
                "is_running": True,
            }
        ]
    }
    assert service.healthy_services("srm", health, baseline)


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


def _worker_state(db, action="prepare"):
    op, _ = _record(
        db, "queued_preparation" if action == "prepare" else "queued_installation"
    )
    row = db.scalar(select(Setting).where(Setting.key == service.PREFIX + op))
    state = json.loads(row.value)
    state.update(
        state="preparing" if action == "prepare" else "installing",
        product="vcenter",
        address="vc.test",
        port=443,
        confirmed_tls_fingerprint="a" * 64,
        credential_reference={"mode": "manual", "username": "admin"},
        identity="vc.test",
        product_info={"product": "vcenter", "version": "8.0"},
        names={"common_name": "vc.test", "dns_names": ["vc.test"], "ip_addresses": []},
        profile_id=1,
        ca_snapshot={
            "root": {"fingerprint_sha256": "a" * 64},
            "profile": {"id": 1, "name": "vCenter"},
        },
        current_certificate={"fingerprint_sha256": "old"},
        baseline_health={},
        replacement_certificate={"fingerprint_sha256": "new"},
        issuer="Atlaso",
        issuer_fingerprint_sha256="a" * 64,
        profile={"id": 1, "name": "vCenter"},
        trust_changes=["root"],
        recovery_reference="recovery point",
    )
    row.value = json.dumps(state)
    job = db.get(Job, state["job_id"])
    job.task_config_json = json.dumps({"operation_id": op, "action": action})
    job.status = "pending"
    db.commit()
    return op, row, state, job


def test_review_exposes_exact_issuer_fingerprint_and_profile(db, monkeypatch):
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
        issuer_fingerprint_sha256="b" * 64,
        profile={"id": 1, "name": "vCenter Profile"},
        trust_changes=["root"],
    )
    row.value = json.dumps(state)
    db.commit()
    review = service.dispatch(
        db,
        "admin",
        "review",
        _prepare_values(operation_id=prepared["operation_id"]),
        tasks,
    )["review"]
    assert review["issuer_fingerprint_sha256"] == "a" * 64
    assert review["profile"] == "vCenter Profile"


def test_worker_csr_uncertain_failure_keeps_checkpoint_and_reservation(db, monkeypatch):

    op, _, state, job = _worker_state(db)
    monkeypatch.setattr(service, "SessionLocal", lambda: db)
    monkeypatch.setattr(service, "_actor", lambda *_: None)
    monkeypatch.setattr(
        service,
        "_credentials",
        lambda *_: service.Credentials("admin", "worker-secret"),
    )
    monkeypatch.setattr(
        service,
        "_inspect",
        lambda *_: {
            key: state[key]
            for key in ("identity", "product_info", "names", "current_certificate")
        },
    )
    monkeypatch.setattr(service, "_ca_snapshot", lambda *_: state["ca_snapshot"])
    monkeypatch.setattr(service, "_ready_ca", lambda *_: (object(), []))
    monkeypatch.setattr(service, "_csr_spec", lambda *_: {"common_name": "vc.test"})

    class Native:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def login(self, *_):
            return "session"

        def generate_csr(self, _):
            db.expire_all()
            persisted = json.loads(
                db.get(
                    Setting,
                    db.scalar(
                        select(Setting.id).where(Setting.key == service.PREFIX + op)
                    ),
                ).value
            )
            assert persisted["checkpoint"] == "csr_dispatch_pending"
            raise RemoteError("connection lost")

    monkeypatch.setattr(service, "NativeAdapter", lambda *_: Native())
    service.run_job(job.id, {"username": "admin", "password": "worker-secret"})
    db.expire_all()
    current = json.loads(
        db.scalar(select(Setting).where(Setting.key == service.PREFIX + op)).value
    )
    assert current["checkpoint"] == "csr_dispatch_pending"
    assert current["state"] == "needs_recovery"
    assert "csr_pem" not in current
    assert (
        db.scalar(
            select(Setting).where(Setting.key == state["reservation_keys"][0])
        ).value
        == op
    )
    assert "worker-secret" not in job.task_config_json + job.result + job.error


def test_revoked_admin_cannot_dispatch_csr(db, monkeypatch):

    op, _, state, job = _worker_state(db)
    monkeypatch.setattr(service, "SessionLocal", lambda: db)
    monkeypatch.setattr(
        service, "_credentials", lambda *_: service.Credentials("admin", "secret")
    )
    monkeypatch.setattr(
        service,
        "_inspect",
        lambda *_: {
            key: state[key]
            for key in ("identity", "product_info", "names", "current_certificate")
        },
    )
    monkeypatch.setattr(service, "_ca_snapshot", lambda *_: state["ca_snapshot"])
    monkeypatch.setattr(service, "_ready_ca", lambda *_: (object(), []))
    monkeypatch.setattr(service, "_csr_spec", lambda *_: {})
    db.get(User, 1).enabled = False
    db.commit()
    native = Mock()
    monkeypatch.setattr(service, "NativeAdapter", lambda *_: native)
    service.run_job(job.id, {"username": "admin", "password": "secret"})
    native.generate_csr.assert_not_called()
    assert (
        db.scalar(
            select(Setting).where(Setting.key == state["reservation_keys"][0])
        ).value
        == op
    )


def test_install_uncertain_response_verifies_without_repeating_write(db, monkeypatch):

    op, _, state, job = _worker_state(db, "install")
    monkeypatch.setattr(service, "SessionLocal", lambda: db)
    monkeypatch.setattr(service, "_actor", lambda *_: None)
    monkeypatch.setattr(
        service,
        "_credentials",
        lambda *_: service.Credentials("admin", "install-secret"),
    )
    monkeypatch.setattr(service, "_revalidate", lambda *_: None)
    monkeypatch.setattr(service, "_material", lambda *_: ("LEAF PEM", "ROOT PEM"))
    monkeypatch.setattr(service, "_verify", lambda *args: True)

    class Native:
        def __init__(self):
            self.install_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def login(self, *_):
            return "session"

        def import_and_verify_root(self, *_):
            return True

        def install_csr(self, *_):
            self.install_calls += 1
            db.expire_all()
            row = db.scalar(select(Setting).where(Setting.key == service.PREFIX + op))
            assert (
                json.loads(row.value)["checkpoint"] == "installation_dispatch_pending"
            )
            raise RemoteError("lost install response")

    native = Native()
    monkeypatch.setattr(service, "NativeAdapter", lambda *_: native)
    monkeypatch.setattr(service.time, "sleep", lambda *_: None)
    service.run_job(job.id, {"username": "admin", "password": "install-secret"})
    db.expire_all()
    state_now = json.loads(
        db.scalar(select(Setting).where(Setting.key == service.PREFIX + op)).value
    )
    assert native.install_calls == 1
    assert state_now["state"] == "succeeded"
    assert state_now["checkpoint"] == "verified"
    assert (
        db.scalar(select(Setting).where(Setting.key == state["reservation_keys"][0]))
        is None
    )
    assert "install-secret" not in job.task_config_json + job.result + (job.error or "")


def _sddc_worker(db, monkeypatch, action="prepare"):
    op, row, state, job = _worker_state(db, action)
    state["product"] = "sddc"
    state["product_info"] = {
        "product": "sddc",
        "role": "SddcManager",
        "version": "9.1.1",
        "identity": "sddc.test",
        "domain_id": "d1",
        "resource_id": "r1",
    }
    row.value = json.dumps(state)
    db.commit()
    monkeypatch.setattr(service, "SessionLocal", lambda: db)
    monkeypatch.setattr(
        service,
        "_credentials",
        lambda *_: service.Credentials("admin", "private-password"),
    )
    monkeypatch.setattr(
        service,
        "_inspect",
        lambda *_: {
            key: state[key]
            for key in ("identity", "product_info", "names", "current_certificate")
        },
    )
    monkeypatch.setattr(service, "_ca_snapshot", lambda *_: state["ca_snapshot"])
    monkeypatch.setattr(service, "_ready_ca", lambda *_: (object(), []))
    monkeypatch.setattr(service, "_csr_spec", lambda *_: {})
    monkeypatch.setattr(service, "_material", lambda *_: ("LEAF", "ROOT"))
    native = MagicMock(spec=service.SddcAdapter)
    native.__enter__.return_value = native
    native.start_csr.return_value = "native-csr-1"
    native.wait_csr.return_value = "PUBLIC CSR"
    native.start_validation.return_value = "validation-1"
    native.wait_validation.return_value = True
    monkeypatch.setattr(service, "_native", lambda *_: native)

    def issue(db, row, state):
        state.update(
            certificate_id=5,
            replacement_certificate={"fingerprint_sha256": "new"},
            state="preparing",
            checkpoint="certificate_issued",
        )
        service._save(db, row, state)

    monkeypatch.setattr(service, "_issue", issue)
    return op, row, state, job, native


def test_sddc_worker_records_task_ids_before_polling_and_requires_validation(
    db, monkeypatch
):
    op, row, state, job, native = _sddc_worker(db, monkeypatch)

    def started(_):
        assert json.loads(row.value)["checkpoint"] == "csr_dispatch_pending"
        return "native-csr-1"

    native.start_csr.side_effect = started

    def csr(task_id, _):
        persisted = json.loads(row.value)
        assert persisted["native_csr_task_id"] == task_id
        assert persisted["checkpoint"] == "csr_task_submitted"
        return "PUBLIC CSR"

    native.wait_csr.side_effect = csr

    def validated(validation_id, _):
        persisted = json.loads(row.value)
        assert persisted["native_validation_id"] == validation_id
        assert persisted["certificate_id"] == 5
        assert persisted["checkpoint"] == "validation_task_submitted"

    native.wait_validation.side_effect = validated
    service.run_job(job.id, {"username": "admin", "password": "private-password"})
    db.expire_all()
    persisted = json.loads(row.value)
    assert persisted["state"] == "prepared"
    assert persisted["checkpoint"] == "certificate_prepared"
    native.start_csr.assert_called_once()
    native.start_install.assert_not_called()
    assert "private-password" not in row.value + job.task_config_json + job.result
    assert (
        db.scalar(select(Setting).where(Setting.key == state["reservation_keys"][0]))
        is not None
    )


def test_sddc_interrupted_csr_reconciliation_reads_original_task_without_resubmission(
    db, monkeypatch
):
    op, row, state, job, native = _sddc_worker(db, monkeypatch)
    native.wait_csr.side_effect = RemoteError("request interrupted")
    service.run_job(job.id, {"username": "admin", "password": "private-password"})
    db.expire_all()
    state = json.loads(row.value)
    assert state["state"] == "needs_recovery"
    assert state["checkpoint"] == "csr_task_submitted"
    native.wait_csr.side_effect = None
    row, state = service._state(db, op, "admin")
    result = service._reconcile(
        db, row, state, service.Credentials("admin", "private-password")
    )
    assert result["state"] == "prepared"
    native.start_csr.assert_called_once()
    native.start_install.assert_not_called()


def test_sddc_uncertain_install_is_verified_without_repeating_native_write(
    db, monkeypatch
):
    op, row, state, job, native = _sddc_worker(db, monkeypatch, "install")
    monkeypatch.setattr(service, "_revalidate", lambda *_: None)
    monkeypatch.setattr(service, "_verify", lambda *_: True)
    native.start_install.side_effect = RemoteError("restart dropped response")
    service.run_job(job.id, {"username": "admin", "password": "private-password"})
    db.expire_all()
    assert json.loads(row.value)["state"] == "succeeded"
    native.start_install.assert_called_once_with("LEAF", ["ROOT"])
    native.install_csr.assert_not_called()
