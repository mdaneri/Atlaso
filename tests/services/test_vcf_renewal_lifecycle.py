"""Approval, signing, uncertainty and verification boundaries for renewal."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    Base,
    CaCertificate,
    CaProfile,
    CaSettings,
    Job,
    Setting,
    User,
)
from atlaso.app.services import ca
from atlaso.app.services import vcf_certificate_renewal as service
from atlaso.app.services.vcf_certificate_remote import Credentials, RemoteError


@pytest.fixture
def setup(monkeypatch):
    """Create an isolated DB, synthetic CA and a target-owned CSR in memory.

    Args:
        monkeypatch: Test-only environment and transport replacement fixture.
    """
    monkeypatch.setenv("ATLASO_SECRET_KEY", "synthetic-renewal-test-secret")
    service.get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        db.add(User(username="admin", enabled=True, role="admin"))
        settings = CaSettings(enabled=True, root_common_name="Synthetic Test CA", organization="Test", key_algorithm="RSA", key_size=2048, digest_algorithm="sha256", root_valid_days=3650)
        profile = CaProfile(name="vCenter", enabled=True, certificate_type="server", key_algorithm="RSA", key_size=2048,
                            validity_days=365, san_required=True, key_usage="digitalSignature,keyEncipherment", extended_key_usage="serverAuth")
        db.add_all([settings, profile])
        db.flush()
        ca.ensure_root_ca_material(settings)
        db.commit()
        identifier, connection = "a" * 32, "b" * 32
        policy = {"id": identifier, "actor": "admin", "connection_id": connection, "certificate_id": "vc-cert-1", "host": "vcenter.lab.test",
                  "profile_id": profile.id, "enabled": True, "confirmed_target_tls_fingerprint": "1" * 64,
                  "health_reference": {}, "threshold_days": 30}
        service._put(db, "connection", connection, {"id": connection})
        service._put(db, "policy", identifier, policy)
        db.commit()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, policy["host"])]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(policy["host"])]), False)
               .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
        client = MagicMock()
        client.generate_csr.return_value = "csr-request"
        client.workflow.return_value = {"state": "COMPLETED"}
        client.csrs.side_effect = [[], [{"csr": csr, "certificateId": "vc-cert-1"}]]
        context = MagicMock()
        context.__enter__.return_value = client
        monkeypatch.setattr(service, "_client", Mock(return_value=context))
        monkeypatch.setattr(service, "_credentials", Mock(return_value=Credentials("test", "synthetic")))
        monkeypatch.setattr(service, "_selected", Mock(return_value={"fingerprint": "1" * 64, "host": policy["host"], "eligible": True, "days_remaining": 5}))
        monkeypatch.setattr(service.native, "_locks", Mock(return_value=["vcf_cert_lock:test-target"]))
        monkeypatch.setattr(service.native, "_inspect", Mock(return_value={"identity": policy["host"],
                            "names": {"common_name": policy["host"], "dns_names": [policy["host"]], "ip_addresses": []},
                            "baseline_health": {"health": "green"}, "product_info": {"version": "9.1.1"}}))
        yield db, policy, client
    engine.dispose()
    service.get_settings.cache_clear()


def propose(db, policy):
    """Create a due proposal through the real discovery state transition.

    Args:
        db: Isolated database session.
        policy: Enrolled fixture policy.
    """
    service.check_policy(db, policy["id"])
    _, current = service._row(db, "policy", policy["id"])
    return service._row(db, "operation", current["operation_id"])[1]


def prepare(db, policy):
    """Admit preparation through the real explicit-approval entrypoint.

    Args:
        db: Isolated database session.
        policy: Enrolled fixture policy.
    """
    result = service.dispatch(db, "admin", "prepare", {"policy_id": policy["id"], "acknowledge_preparation": True, "acknowledge_recovery": True})
    _, current = service._row(db, "policy", policy["id"])
    operation = service._row(db, "operation", result["operation_id"])[1]
    return current, operation


def test_approved_csr_is_signed_once_without_a_target_private_key(setup):
    """Real CA issuance retains target key custody and validates the resulting leaf.

    Args:
        setup: Isolated cryptographic and transport fixtures.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    stored = service._row(db, "operation", operation["id"])[1]
    certificate = db.get(CaCertificate, stored["certificate_id"])
    assert stored["state"] == "prepared"
    assert certificate.status == "issued" and not certificate.private_key_encrypted
    assert stored["replacement_certificate"]["dns_names"] == [policy["host"]]
    client.generate_csr.assert_called_once()
    client.replace.assert_not_called()
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None


def test_csr_dispatch_is_durable_before_remote_write_and_lost_response_is_retained(setup):
    """An ambiguous generation response leaves a checkpoint that cannot repeat CSR generation.

    Args:
        setup: Isolated database and transport fixtures.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)

    def lost_response(*args):
        """Assert the pre-write checkpoint before simulating a lost response.

        Args:
            *args: Admitted native request arguments.
        """
        assert service._row(db, "operation", operation["id"])[1]["checkpoint"] == "csr_dispatch_pending"
        raise RemoteError("synthetic response loss")

    client.generate_csr.side_effect = lost_response
    with pytest.raises(RemoteError):
        service._prepare(db, policy, operation)
    with pytest.raises(service.RenewalError, match="uncertain"):
        service._reconcile(db, policy, operation)
    assert client.generate_csr.call_count == 1
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None


def test_prepare_rejects_existing_native_csr_without_generation(setup):
    """Existing native key material cannot be overwritten by preparation.

    Args:
        setup: Isolated database and transport fixtures.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    client.csrs.side_effect = None
    client.csrs.return_value = [{"csr": "retained"}]
    with pytest.raises(service.RenewalError, match="already exists"):
        service._prepare(db, policy, operation)
    client.generate_csr.assert_not_called()
    assert db.scalar(select(CaCertificate)) is None


def test_unconfirmed_changed_target_leaf_never_receives_credentials(setup, monkeypatch):
    """Discovery cannot silently promote an observed replacement leaf to trusted identity.

    Args:
        setup: Isolated database fixtures.
        monkeypatch: Test transport replacement fixture.
    """
    db, policy, _ = setup
    operation = propose(db, policy)
    policy, operation = prepare(db, policy)
    operation["current_fingerprint"] = "2" * 64
    monkeypatch.setattr(service, "_selected", Mock(return_value={"fingerprint": "2" * 64}))
    with pytest.raises(service.RenewalError, match="independent reconfirmation"):
        service._prepare(db, policy, operation)
    service._credentials.assert_not_called()


def test_approval_is_single_use_and_cannot_install_before_review(setup):
    """One exact leaf review admits at most one queued installation.

    Args:
        setup: Isolated cryptographic and transport fixtures.
    """
    db, policy, _ = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    db.get(Job, operation["job_id"]).status = "succeeded"
    db.commit()
    review = service.dispatch(db, "admin", "review", {"operation_id": operation["id"]})
    result = service.dispatch(db, "admin", "execute", {"operation_id": operation["id"], "review_token": review["review_token"]})
    assert db.get(Job, result["job_id"]).type == service.JOB_TYPE
    with pytest.raises(service.RenewalError, match="stale|already used"):
        service.dispatch(db, "admin", "execute", {"operation_id": operation["id"], "review_token": review["review_token"]})


def test_verify_requires_health_and_preserves_reservation_on_failure(setup, monkeypatch):
    """Strict TLS alone cannot declare renewal successful.

    Args:
        setup: Isolated cryptographic and transport fixtures.
        monkeypatch: Native health replacement fixture.
    """
    db, policy, _ = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    monkeypatch.setattr(service.native, "_verify", Mock(return_value=False))
    with pytest.raises(service.RenewalError, match="not verified"):
        service._verify(db, policy, operation)
    assert operation["state"] != "succeeded"
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None
    target = service._credentials.call_args.args[2]
    assert target.strict_tls and target.ca_pem == operation["root_pem"]


def test_verified_replacement_releases_reservation_and_advances_trusted_pin(setup, monkeypatch):
    """Only the exact independently verified issued leaf becomes the next trusted baseline.

    Args:
        setup: Isolated cryptographic and transport fixtures.
        monkeypatch: Native verification replacement fixture.
    """
    db, policy, _ = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    monkeypatch.setattr(service.native, "_verify", Mock(return_value=True))
    service._verify(db, policy, operation)
    assert service._row(db, "operation", operation["id"])[1]["state"] == "succeeded"
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is None
    assert service._row(db, "policy", policy["id"])[1]["confirmed_target_tls_fingerprint"] == operation["replacement_certificate"]["fingerprint_sha256"]


def test_restart_preserves_uncertain_checkpoint_and_reservation(setup):
    """Worker restarts must not auto-retry possible native writes.

    Args:
        setup: Isolated database and transport fixtures.
    """
    db, policy, _ = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    job = db.get(Job, operation["job_id"])
    job.status = "running"
    service._checkpoint(db, operation, checkpoint="csr_dispatch_pending")
    assert service.recover_interrupted_jobs(db) == 1
    current = service._row(db, "operation", operation["id"])[1]
    assert current["checkpoint"] == "csr_dispatch_pending" and current["state"] == "needs_recovery"
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None


def test_reconcile_undispatched_preparation_releases_for_explicit_retry(setup):
    """A durable pre-dispatch failure can return to a proposal without remote writes.

    Args:
        setup: Isolated database and transport fixtures.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._checkpoint(db, operation, state="needs_recovery")
    service._reconcile(db, policy, operation)
    assert service._row(db, "operation", operation["id"])[1]["state"] == "proposal"
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is None
    client.generate_csr.assert_not_called()
    client.replace.assert_not_called()


def test_reconcile_undispatched_replacement_requires_fresh_review(setup):
    """A pre-dispatch replacement failure retains material without reinstalling it.

    Args:
        setup: Isolated database and transport fixtures.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    job = db.get(Job, operation["job_id"])
    job.status = "succeeded"
    db.commit()
    review = service.dispatch(db, "admin", "review", {"operation_id": operation["id"]})
    service.dispatch(db, "admin", "execute", {"operation_id": operation["id"], "review_token": review["review_token"]})
    _, operation = service._row(db, "operation", operation["id"])
    service._checkpoint(db, operation, state="needs_recovery")
    job = db.get(Job, operation["job_id"])
    job.status = "failed"
    db.commit()
    service._reconcile(db, policy, operation)
    assert service._row(db, "operation", operation["id"])[1]["state"] == "prepared"
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None
    client.replace.assert_not_called()
    with pytest.raises(service.RenewalError, match="stale or already used"):
        service.dispatch(db, "admin", "execute", {"operation_id": operation["id"], "review_token": review["review_token"]})


def test_due_time_uses_real_leaf_expiry_instead_of_fleet_day_rounding(monkeypatch):
    """Expiry decisions are based on the served certificate's actual UTC expiry.

    Args:
        monkeypatch: TLS-probe replacement fixture.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcenter.lab.test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(4)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10)).sign(key, hashes.SHA256()))
    probe = {"sha256": cert.fingerprint(hashes.SHA256()).hex(), "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode()}
    monkeypatch.setattr(service, "PinnedHTTPS", Mock(return_value=Mock(probe=Mock(return_value=probe))))
    value = service._inventory_record("a" * 32, {"certificateResourceKey": "vc-cert", "applianceFqdn": "vcenter.lab.test", "appliance": "VCENTER", "category": "TLS_CERT", "daysToExpire": 365, "certificateMetadata": {"certificatePurpose": "MACHINE_SSL_CERT"}})
    assert 9 < value["days_remaining"] <= 10


def test_policy_observations_do_not_invalidate_prepared_review(setup):
    """Scheduled observation changes cannot invalidate unchanged enrollment policy.

    Args:
        setup: Isolated database fixtures.
    """
    _, policy, _ = setup
    changed = dict(policy, last_check_at="later", observation={"days_remaining": 1}, last_job_id="job_check")
    assert service._policy_digest(policy) == service._policy_digest(changed)
    assert service._policy_digest(policy) != service._policy_digest(dict(policy, profile_id=999))


def test_async_replacement_uses_exact_chain_and_checkpoints_before_dispatch(setup, monkeypatch):
    """VCF receives one approved public chain only after the write checkpoint is durable.

    Args:
        setup: Isolated CA and transport fixtures.
        monkeypatch: Read-only native verification replacement.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    monkeypatch.setattr(service.native, "_verify", Mock(return_value=True))

    def replace(certificate_id, chain):
        """Observe the actual submitted certificate chain and durable pre-write state.

        Args:
            certificate_id: Native fleet certificate identity.
            chain: Exact issued public chain.
        """
        assert certificate_id == policy["certificate_id"]
        assert chain == operation["leaf_pem"].rstrip() + "\n" + operation["root_pem"].strip() + "\n"
        assert service._row(db, "operation", operation["id"])[1]["checkpoint"] == "replacement_dispatch_pending"
        return "replacement-request"

    client.replace.side_effect = replace
    service._execute(db, policy, operation)
    client.replace.assert_called_once()
    assert operation["replacement_request_id"] == "replacement-request"
    assert operation["state"] == "succeeded"


def test_lost_replacement_workflow_identity_is_not_declared_success_from_tls(setup, monkeypatch):
    """A healthy served leaf cannot substitute for VCF coordinator completion evidence.

    Args:
        setup: Isolated CA and transport fixtures.
        monkeypatch: Native verification replacement.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    service._checkpoint(db, operation, checkpoint="replacement_dispatch_pending", state="needs_recovery")
    verifier = Mock(return_value=True)
    monkeypatch.setattr(service.native, "_verify", verifier)
    with pytest.raises(service.RenewalError, match="workflow identity is unknown"):
        service._reconcile(db, policy, operation)
    client.replace.assert_not_called()
    verifier.assert_not_called()
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None


def test_renewal_schedules_and_runtime_state_are_not_exported(setup):
    """Archive export cannot transfer enrollment bindings or remote operation authority.

    Args:
        setup: Isolated database fixture.
    """
    from atlaso.app.models import Schedule
    from atlaso.app.services.settings_archive import (
        _schedules_to_archive,
        _settings_rows,
    )

    db, policy, _ = setup
    db.add(Schedule(name="Renewal", task_type="vcf_certificate_renewal_check", task_config_json=json.dumps({"policy_id": policy["id"]}), created_by="admin", enabled=True))
    db.commit()
    assert not _schedules_to_archive(db)
    assert not any(row["key"].startswith(service.PREFIX) for row in _settings_rows(db))
