"""Approval, signing, uncertainty and verification boundaries for renewal."""

import json
from contextlib import nullcontext
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


def connection_confirmation(db, policy):
    """Store a synthetic Operations binding and return explicit reconfirmation input.

    Args:
        db: Isolated database session.
        policy: Enrolled target whose connection identity must remain stable.
    """
    old = {"id": policy["connection_id"], "name": "Operations", "address": "operations.lab.test", "port": 443,
           "confirmed_tls_fingerprint": "2" * 64, "reference": {"mode": "vault", "vault_id": 1, "entry_id": 2, "revision": "old"}, "actor": "admin"}
    service._put(db, "connection", old["id"], old)
    db.commit()
    values = {"connection_id": old["id"], "confirm_connection_update": True, "name": "Operations", "address": old["address"], "port": 443,
              "confirmed_tls_fingerprint": "3" * 64, "credential_vault_id": 1, "credential_entry_id": 2}
    return old, values


@pytest.mark.parametrize("recovery", [False, True])
def test_connection_reconfirmation_retains_native_work_and_invalidates_old_approval(setup, monkeypatch, recovery):
    """Rotated Operations access repairs the same binding without retrying native writes.

    Args:
        setup: Real synthetic issuance and durable operation fixtures.
        monkeypatch: Fixture providing newly selected Vault metadata and native health.
        recovery: Whether a retained replacement request needs reconciliation.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    db.get(Job, operation["job_id"]).status = "succeeded"
    db.commit()
    old_token = service.dispatch(db, "admin", "review", {"operation_id": operation["id"]})["review_token"]
    if recovery:
        service._checkpoint(db, operation, state="needs_recovery", checkpoint="replacement_submitted", replacement_request_id="retained-replacement")
    before = service._row(db, "operation", operation["id"])[1]
    _, values = connection_confirmation(db, policy)
    reference = {"mode": "vault", "vault_id": 1, "entry_id": 2, "revision": "rotated"}
    monkeypatch.setattr(service, "_reference", Mock(return_value=reference))
    service._client.reset_mock()
    result = service.dispatch(db, "admin", "save_connection", values)
    assert result["connection_id"] == policy["connection_id"]
    updated = service._row(db, "connection", policy["connection_id"])[1]
    assert updated["reference"] == reference and updated["confirmed_tls_fingerprint"] == "3" * 64
    assert service._client.call_args.args[1] == updated
    retained = service._row(db, "operation", operation["id"])[1]
    assert retained["state"] == before["state"] and retained["checkpoint"] == before["checkpoint"]
    assert retained["csr_request_id"] == before["csr_request_id"]
    assert retained.get("replacement_request_id") == before.get("replacement_request_id")
    assert retained["certificate_id"] == before["certificate_id"]
    assert retained["approval_revision"] == before.get("approval_revision", 0) + 1
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None
    assert service._row(db, "policy", policy["id"])[1]["connection_id"] == updated["id"]
    if recovery:
        client.reset_mock()
        monkeypatch.setattr(service.native, "_verify", Mock(return_value=True))
        service._reconcile(db, policy, retained)
        client.workflow.assert_called_once_with("retained-replacement")
        client.generate_csr.assert_not_called()
        client.replace.assert_not_called()
    else:
        with pytest.raises(service.RenewalError, match="stale or already used"):
            service.dispatch(db, "admin", "execute", {"operation_id": operation["id"], "review_token": old_token})
        assert service.dispatch(db, "admin", "review", {"operation_id": operation["id"]})["review_token"] != old_token


@pytest.mark.parametrize("invalid", ["acknowledgement", "host", "port"])
def test_connection_reconfirmation_cannot_retarget_or_omit_confirmation(setup, monkeypatch, invalid):
    """Connection repair cannot send a saved credential to another endpoint.

    Args:
        setup: Isolated database and transport fixtures.
        monkeypatch: Fixture forbidding credential resolution before admission.
        invalid: Required confirmation or immutable endpoint field to violate.
    """
    db, policy, _ = setup
    old, values = connection_confirmation(db, policy)
    values[{"acknowledgement": "confirm_connection_update", "host": "address", "port": "port"}[invalid]] = {"acknowledgement": False, "host": "other.lab.test", "port": 8443}[invalid]
    reference = Mock(side_effect=AssertionError("must not resolve a rejected destination"))
    monkeypatch.setattr(service, "_reference", reference)
    service._client.reset_mock()
    with pytest.raises(service.RenewalError, match="confirm|host and port"):
        service.dispatch(db, "admin", "save_connection", values)
    reference.assert_not_called()
    service._client.assert_not_called()
    assert service._row(db, "connection", old["id"])[1] == old


@pytest.mark.parametrize("status", ["pending", "running"])
def test_connection_reconfirmation_waits_for_live_certificate_tasks(setup, monkeypatch, status):
    """Connection confirmation must not invalidate a live worker's transport.

    Args:
        setup: Isolated operation and transport fixtures.
        monkeypatch: Fixture forbidding credential resolution during a write task.
        status: Live worker task status to guard.
    """
    db, policy, _ = setup
    old, values = connection_confirmation(db, policy)
    db.add(Job(id="job_live_write", type=service.JOB_TYPE, status=status, created_by="admin", task_config_json=json.dumps({"policy_id": policy["id"]})))
    db.commit()
    monkeypatch.setattr(service, "_reference", Mock(side_effect=AssertionError("write task must finish first")))
    service._client.reset_mock()
    with pytest.raises(service.RenewalError, match="active certificate write task"):
        service.dispatch(db, "admin", "save_connection", values)
    service._client.assert_not_called()
    assert service._row(db, "connection", old["id"])[1] == old


def test_connection_reconfirmation_authentication_failure_keeps_old_binding(setup, monkeypatch):
    """An unsuccessful fresh authentication cannot replace stored identity evidence.

    Args:
        setup: Isolated connection database and Operations transport fixtures.
        monkeypatch: Fixture supplying rotated public Vault metadata.
    """
    db, policy, _ = setup
    old, values = connection_confirmation(db, policy)
    monkeypatch.setattr(service, "_reference", Mock(return_value={"revision": "new"}))
    service._client.side_effect = RemoteError("synthetic authentication failure")
    with pytest.raises(service.RenewalError, match="prerequisites"):
        service.dispatch(db, "admin", "save_connection", values)
    assert service._row(db, "connection", old["id"])[1] == old


@pytest.mark.parametrize("drift", ["connection", "credential", "task"])
def test_connection_reconfirmation_rejects_concurrent_changes_atomically(setup, monkeypatch, drift):
    """Confirmation cannot overwrite newer access or stale an active operation.

    Args:
        setup: Isolated issuance and Operations transport fixtures.
        monkeypatch: Fixture simulating a change during fresh authentication.
        drift: State changed between preflight and the final writer gate.
    """
    db, policy, _ = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    db.get(Job, operation["job_id"]).status = "succeeded"
    db.commit()
    before = service._row(db, "operation", operation["id"])[1]
    old, values = connection_confirmation(db, policy)
    reference = {"revision": "new"}
    monkeypatch.setattr(service, "_reference", Mock(side_effect=[reference, {"revision": "newer"}]) if drift == "credential" else Mock(return_value=reference))
    context = MagicMock()

    def authenticated():
        """Commit synthetic competing work after the initial admission check."""
        if drift == "connection":
            service._put(db, "connection", old["id"], dict(old, name="Concurrent confirmation"))
        elif drift == "task":
            db.add(Job(id="job_concurrent_write", type=service.JOB_TYPE, status="pending", created_by="admin", task_config_json=json.dumps({"policy_id": policy["id"]})))
        db.commit()

    context.__enter__.side_effect = authenticated
    monkeypatch.setattr(service, "_client", Mock(return_value=context))
    with pytest.raises(service.RenewalError, match="changed during|active certificate write task"):
        service.dispatch(db, "admin", "save_connection", values)
    retained = service._row(db, "operation", operation["id"])[1]
    assert retained == before
    assert service._row(db, "connection", old["id"])[1] == (dict(old, name="Concurrent confirmation") if drift == "connection" else old)
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None


def health_access_fixture(monkeypatch, policy):
    """Provide a current public Vault reference and read-only native adapter.

    Args:
        monkeypatch: Test-only native transport replacement.
        policy: Immutable enrolled target identity.
    """
    reference = {"mode": "vault", "vault_id": 1, "entry_id": 2, "revision": "rotated-health"}
    monkeypatch.setattr(service, "_reference", Mock(return_value=reference))
    remote = MagicMock()
    remote.product_info.return_value = {"product": "VMware vCenter Server", "version": "9.1.1"}
    remote.vcenter_permissions.return_value = True
    remote.vcenter_registrations.return_value = [{"node_id": "node", "service_id": "service", "endpoints": "https://" + policy["host"] + "/sdk"}]
    remote.vcenter_ha.return_value = {"config_state": "NOT_CONFIGURED"}
    remote.health.return_value = {"health": "red"}
    context = MagicMock()
    context.__enter__.return_value = remote
    monkeypatch.setattr(service.native, "_native", Mock(return_value=context))
    return reference, remote


@pytest.mark.parametrize("phase", ["none", "prepared", "csr_submitted", "replacement_submitted"])
def test_health_reconfirmation_repairs_only_access_and_preserves_native_work(setup, monkeypatch, phase):
    """A rotated health credential can be repaired before or after native installation.

    Args:
        setup: Isolated real issuance and durable native request fixtures.
        monkeypatch: Fixture providing authenticated native reads without a live target.
        phase: Native checkpoint at the time the password rotates.
    """
    db, policy, client = setup
    operation = None
    old_token = None
    if phase != "none":
        propose(db, policy)
        policy, operation = prepare(db, policy)
        if phase == "csr_submitted":
            service._checkpoint(db, operation, state="needs_recovery", checkpoint=phase, csr_request_id="retained-csr")
        else:
            service._prepare(db, policy, operation)
            old_token = service.dispatch(db, "admin", "review", {"operation_id": operation["id"]})["review_token"]
            if phase == "replacement_submitted":
                service._checkpoint(db, operation, state="needs_recovery", checkpoint=phase, replacement_request_id="retained-replacement")
        db.get(Job, operation["job_id"]).status = "succeeded" if phase == "prepared" else "failed"
        db.commit()
    before = service._row(db, "operation", operation["id"])[1] if operation else None
    reference, remote = health_access_fixture(monkeypatch, policy)
    monkeypatch.setattr(service.native, "_ready_ca", Mock(side_effect=AssertionError("health repair must not require an enabled CA")))
    client.reset_mock()
    pin = operation["replacement_certificate"]["fingerprint_sha256"] if phase == "replacement_submitted" else policy["confirmed_target_tls_fingerprint"]
    result = service.dispatch(db, "admin", "save_policy", {"policy_id": policy["id"], "confirm_health_update": True,
        "health_credential_vault_id": 1, "health_credential_entry_id": 2, "confirmed_target_tls_fingerprint": pin,
        "address": "unrelated.example.test", "port": 8443})
    current = service._row(db, "policy", policy["id"])[1]
    assert result["policy_id"] == policy["id"] and current["health_reference"] == reference
    assert current["host"] == policy["host"] and current["profile_id"] == policy["profile_id"]
    assert current["confirmed_target_tls_fingerprint"] == policy["confirmed_target_tls_fingerprint"]
    target = service.native._native.call_args.args[0]
    assert target.host == policy["host"] and target.port == 443 and target.fingerprint == pin.lower()
    assert target.strict_tls is (phase == "replacement_submitted")
    if target.strict_tls:
        assert target.ca_pem == operation["root_pem"]
    remote.login.assert_called_once()
    remote.health.assert_called_once()  # Red health can be observed, never declared successful here.
    client.generate_csr.assert_not_called()
    client.replace.assert_not_called()
    if operation:
        retained = service._row(db, "operation", operation["id"])[1]
        for key in ("state", "checkpoint", "csr_request_id", "replacement_request_id", "certificate_id", "csr_pem", "leaf_pem", "reservation_keys"):
            assert retained.get(key) == before.get(key)
        assert retained["policy_snapshot"] == service._policy_digest(current)
        assert retained["approval_revision"] == before.get("approval_revision", 0) + 1
        assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None
        if phase == "prepared":
            with pytest.raises(service.RenewalError, match="stale or already used"):
                service.dispatch(db, "admin", "execute", {"operation_id": retained["id"], "review_token": old_token})
        if phase == "replacement_submitted":
            monkeypatch.setattr(service.native, "_verify", Mock(return_value=True))
            service._reconcile(db, current, retained)
            assert service._row(db, "operation", retained["id"])[1]["state"] == "succeeded"
            client.workflow.assert_called_once_with("retained-replacement")
            assert service._credentials.call_args.args[1] == reference
            assert service._credentials.call_args.args[2].strict_tls
            client.generate_csr.assert_not_called()
            client.replace.assert_not_called()


@pytest.mark.parametrize("invalid", ["fingerprint", "login", "identity", "topology", "permissions", "version", "live_task"])
def test_health_reconfirmation_refuses_unverified_access_without_changing_checkpoints(setup, monkeypatch, invalid):
    """Failed read-only confirmation cannot change a retained credential or operation.

    Args:
        setup: Isolated issued-certificate and reservation fixtures.
        monkeypatch: Fixture supplying failed native identity or authentication evidence.
        invalid: Specific precondition to reject.
    """
    db, policy, _ = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    job = db.get(Job, operation["job_id"])
    job.status = "running" if invalid == "live_task" else "succeeded"
    db.commit()
    before = service._row(db, "operation", operation["id"])[1]
    _, remote = health_access_fixture(monkeypatch, policy)
    pin = policy["confirmed_target_tls_fingerprint"]
    if invalid == "fingerprint":
        pin = "e" * 64
    elif invalid == "login":
        remote.login.side_effect = RemoteError("synthetic login failure")
    elif invalid == "identity":
        remote.vcenter_registrations.return_value[0]["endpoints"] = "https://other.lab.test/sdk"
    elif invalid == "topology":
        remote.vcenter_ha.return_value = {}
    elif invalid == "permissions":
        remote.vcenter_permissions.return_value = False
    elif invalid == "version":
        remote.product_info.return_value = {"version": "7.0.0"}
    with pytest.raises(service.RenewalError):
        service.dispatch(db, "admin", "save_policy", {"policy_id": policy["id"], "confirm_health_update": True,
            "health_credential_vault_id": 1, "health_credential_entry_id": 2, "confirmed_target_tls_fingerprint": pin})
    assert service._row(db, "operation", operation["id"])[1] == before
    assert service._row(db, "policy", policy["id"])[1]["health_reference"] == policy["health_reference"]
    if invalid in {"fingerprint", "live_task"}:
        remote.login.assert_not_called()



@pytest.mark.parametrize("drift", ["policy", "operation", "credential", "task"])
def test_health_reconfirmation_rejects_concurrent_changes(setup, monkeypatch, drift):
    """Fresh authentication cannot overwrite a changed policy or active worker.

    Args:
        setup: Isolated durable operation and issued material.
        monkeypatch: Fixture changing state during remote authentication.
        drift: Competing state change to preserve.
    """
    db, policy, _ = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    db.get(Job, operation["job_id"]).status = "succeeded"
    db.commit()
    before = service._row(db, "operation", operation["id"])[1]
    reference, remote = health_access_fixture(monkeypatch, policy)
    if drift == "credential":
        monkeypatch.setattr(service, "_reference", Mock(side_effect=[reference, {"revision": "newer"}]))

    def authenticated(credentials):
        """Simulate a competing durable update while native login is in flight."""
        del credentials
        if drift == "policy":
            service._put(db, "policy", policy["id"], dict(policy, threshold_days=15))
        elif drift == "operation":
            service._checkpoint(db, operation, checkpoint="concurrent_checkpoint")
        elif drift == "task":
            db.add(Job(id="job_competing_health", type=service.JOB_TYPE, status="running", created_by="admin", task_config_json=json.dumps({"policy_id": policy["id"]})))
        db.commit()

    remote.login.side_effect = authenticated
    with pytest.raises(service.RenewalError, match="changed during|active certificate write task"):
        service.dispatch(db, "admin", "save_policy", {"policy_id": policy["id"], "confirm_health_update": True,
            "health_credential_vault_id": 1, "health_credential_entry_id": 2,
            "confirmed_target_tls_fingerprint": policy["confirmed_target_tls_fingerprint"]})
    retained = service._row(db, "operation", operation["id"])[1]
    assert retained == (dict(before, checkpoint="concurrent_checkpoint", write_revision=before["write_revision"] + 1) if drift == "operation" else before)
    assert service._row(db, "policy", policy["id"])[1]["health_reference"] == policy["health_reference"]


def test_health_fingerprint_probe_is_bound_to_saved_target(setup, monkeypatch):
    """An unauthenticated probe ignores supplied addresses and never opens credentials.

    Args:
        setup: Saved enrollment fixture.
        monkeypatch: Fixture replacing the public TLS probe.
    """
    db, policy, _ = setup
    transport = Mock()
    transport.probe.return_value = {"sha256": "2" * 64, "issuer": "Synthetic", "subject": "Synthetic"}
    factory = Mock(return_value=transport)
    monkeypatch.setattr(service, "PinnedHTTPS", factory)
    monkeypatch.setattr(service, "_reference", Mock(side_effect=AssertionError("probe must not resolve credentials")))
    service.dispatch(db, "admin", "probe", {"policy_id": policy["id"], "address": "other.test", "port": 8443})
    target = factory.call_args.args[0]
    assert target.host == policy["host"] and target.port == 443


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


def test_restart_after_issuance_restores_same_prepared_certificate_without_writes(setup, monkeypatch):
    """A committed issuance survives a crash before the worker task status commits.

    Args:
        setup: Isolated cryptographic and transport fixtures.
        monkeypatch: Fixture preventing a second signing operation.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    db.get(Job, operation["job_id"]).status = "running"
    service._prepare(db, policy, operation)
    certificate_id, leaf = operation["certificate_id"], operation["leaf_pem"]
    assert service.recover_interrupted_jobs(db) == 1
    _, retained = service._row(db, "operation", operation["id"])
    assert retained["state"] == "needs_recovery" and retained["checkpoint"] == "certificate_prepared"
    monkeypatch.setattr(service.ca, "issue_certificate", Mock(side_effect=AssertionError("must not reissue")))
    client.reset_mock()
    service._reconcile(db, policy, retained)
    assert retained["state"] == "prepared" and retained["certificate_id"] == certificate_id
    assert retained["leaf_pem"] == leaf
    assert len(list(db.scalars(select(CaCertificate)))) == 1
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None
    review = service.dispatch(db, "admin", "review", {"operation_id": retained["id"]})
    assert review["summary"]["leaf_pem"] == leaf and review["review_token"]
    client.generate_csr.assert_not_called()
    client.replace.assert_not_called()


def test_restart_after_verified_commit_preserves_success_and_released_reservation(setup, monkeypatch):
    """Task finalization cannot undo an already committed verified replacement.

    Args:
        setup: Isolated cryptographic and database fixtures.
        monkeypatch: Fixture supplying successful native verification.
    """
    db, policy, _ = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    db.get(Job, operation["job_id"]).status = "running"
    service._prepare(db, policy, operation)
    monkeypatch.setattr(service.native, "_verify", Mock(return_value=True))
    service._verify(db, policy, operation)
    assert service.recover_interrupted_jobs(db) == 1
    assert service._row(db, "operation", operation["id"])[1]["state"] == "succeeded"
    assert db.get(Job, operation["job_id"]).status == "succeeded"
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is None


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


@pytest.mark.parametrize("stage", ["review", "approval", "worker"])
@pytest.mark.parametrize("change", ["revoked", "disabled", "missing", "changed"])
def test_invalidated_issued_material_never_reaches_replacement(setup, monkeypatch, stage, change):
    """Revalidate real issued material at each approval and dispatch boundary.

    Args:
        setup: Isolated real CA issuance and synthetic VCF transport fixtures.
        monkeypatch: Fixture binding the persistent runner to this test session.
        stage: Point at which the administrator invalidates the issued record.
        change: Certificate-accounting change that must invalidate admission.
    """
    db, policy, client = setup
    propose(db, policy)
    policy, operation = prepare(db, policy)
    service._prepare(db, policy, operation)
    db.get(Job, operation["job_id"]).status = "succeeded"
    db.commit()
    token = None
    if stage != "review":
        token = service.dispatch(db, "admin", "review", {"operation_id": operation["id"]})["review_token"]
    if stage == "worker":
        admitted = service.dispatch(db, "admin", "execute", {"operation_id": operation["id"], "review_token": token})
    certificate = db.get(CaCertificate, operation["certificate_id"])
    if change == "revoked":
        certificate.status = "revoked"
    elif change == "disabled":
        certificate.enabled = False
    elif change == "missing":
        db.delete(certificate)
    else:
        certificate.certificate_pem = operation["root_pem"]
    db.commit()
    if stage == "worker":
        monkeypatch.setattr(service, "SessionLocal", lambda: nullcontext(db))
        service.run(admitted["job_id"])
        assert db.get(Job, admitted["job_id"]).status == "failed"
        retained = service._row(db, "operation", operation["id"])[1]
        assert retained["state"] == "needs_recovery"
        assert retained["checkpoint"] == "queued_replacement"
    else:
        action = "review" if stage == "review" else "execute"
        with pytest.raises(service.RenewalError, match="prerequisites"):
            service.dispatch(db, "admin", action, {"operation_id": operation["id"], "review_token": token})
        assert service._row(db, "operation", operation["id"])[1]["state"] == "prepared"
    client.replace.assert_not_called()
    assert client.generate_csr.call_count == 1
    assert db.scalar(select(Setting).where(Setting.key == "vcf_cert_lock:test-target")) is not None


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
