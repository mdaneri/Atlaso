"""Approval-gated renewal with read-only schedules and durable native checkpoints.

VCF Operations owns CSR/replacement execution. The existing vCenter adapter is
used only for independently authenticated discovery and post-install health.
Only public material and Vault references are persisted; uncertain remote writes
retain their reservations and can only be reconciled, never blindly repeated.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography import x509
from itsdangerous import BadData, URLSafeTimedSerializer
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    AuditEvent,
    CaCertificate,
    CaProfile,
    Job,
    Schedule,
    Setting,
    utcnow,
)
from atlaso.app.services import ca
from atlaso.app.services import vcf_certificates as native
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.vcf_certificate_material import (
    CertificateMaterialError,
    certificate_metadata,
    validate_issued_certificate,
    validate_product_csr,
)
from atlaso.app.services.vcf_certificate_remote import PinnedHTTPS, RemoteError, Target
from atlaso.app.services.vcf_operations import OperationsClient

PREFIX = "vcf_renewal:"
JOB_TYPE = "vcf-certificate-renewal"
CHECK_JOB_TYPE = "vcf-certificate-renewal-check"
REVIEW_SECONDS = 600
REMOTE_WAIT_SECONDS = 900
TERMINAL = {"succeeded", "cancelled"}


class RenewalError(ValueError):
    """Sanitized refusal safe for the management browser and task history."""


def _json(value: Any) -> str:
    """Serialize public state deterministically.

    Args:
        value: Public JSON-compatible state.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    """Bind review and remote identity to immutable public state.

    Args:
        value: Public JSON-compatible snapshot.
    """
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _row(db: Session, kind: str, identifier: str) -> tuple[Setting, dict[str, Any]]:
    """Read one bounded resource without allowing arbitrary Setting access.

    Args:
        db: Active database session.
        kind: Internal resource namespace.
        identifier: Resource UUID in hexadecimal form.
    """
    if not re.fullmatch(r"[a-f0-9]{32}", str(identifier)):
        raise RenewalError("Renewal resource not found.")
    row = db.scalar(select(Setting).where(Setting.key == PREFIX + kind + ":" + identifier))
    if row is None:
        raise RenewalError("Renewal resource not found.")
    db.refresh(row)
    try:
        value = json.loads(row.value)
        if not isinstance(value, dict):
            raise ValueError
    except (ValueError, TypeError):
        raise RenewalError("Renewal state needs administrator recovery.") from None
    return row, value


def _put(db: Session, kind: str, identifier: str, value: dict[str, Any]) -> Setting:
    """Write admitted public resource state in the caller's transaction.

    Args:
        db: Active database writer transaction.
        kind: Internal resource namespace.
        identifier: Resource UUID.
        value: Public state or credential references only.
    """
    key = PREFIX + kind + ":" + identifier
    row = db.scalar(select(Setting).where(Setting.key == key))
    if row is None:
        row = Setting(key=key, value=_json(value))
        db.add(row)
    else:
        row.value, row.updated_at = _json(value), utcnow()
    return row


def _all(db: Session, kind: str) -> list[dict[str, Any]]:
    """Load the bounded internal collection.

    Args:
        db: Active database session.
        kind: Resource namespace.
    """
    rows = list(db.scalars(select(Setting).where(Setting.key.startswith(PREFIX + kind + ":")).limit(1001)))
    if len(rows) > 1000:
        raise RenewalError("Renewal inventory exceeds the supported bound.")
    try:
        values = [json.loads(row.value) for row in rows]
        if any(not isinstance(value, dict) for value in values):
            raise ValueError
    except (ValueError, TypeError):
        raise RenewalError("Renewal state needs administrator recovery.") from None
    return values


def _actor(db: Session, actor: str) -> None:
    """Recheck current administrator authority for browser and scheduled work.

    Args:
        db: Active database session.
        actor: Persisted or current administrator identity.
    """
    try:
        native._actor(db, actor)
    except native.CertificateOperationError:
        raise RenewalError("Administrator access is required for certificate renewal.") from None


def _target(values: dict[str, Any]) -> Target:
    """Validate one explicitly selected endpoint and TLS pin.

    Args:
        values: Public endpoint and fingerprint fields.
    """
    host = str(values.get("address", "")).strip().lower().rstrip(".").strip("[]")
    if not host or len(host) > 253 or not re.fullmatch(r"[a-z0-9.:-]+", host):
        raise RenewalError("Enter a hostname or IP address without a URL.")
    return Target(host, int(values.get("port", 443)), str(values.get("confirmed_tls_fingerprint") or "0" * 64))


def _reference(db: Session, values: dict[str, Any], target: Target) -> dict[str, Any]:
    """Require a saved Vault credential whose HTTPS URI names the exact endpoint.

    Args:
        db: Active database session.
        values: Vault and entry identifiers.
        target: Independently confirmed credential destination.
    """
    from atlaso.app.models import VaultEntry

    reference = native._reference(db, values)
    if reference.get("mode") != "vault":
        raise RenewalError("Scheduled renewal requires a saved Vault credential.")
    entry = db.get(VaultEntry, reference["entry_id"])
    if entry is None:
        raise RenewalError("Choose an existing Vault credential.")
    try:
        endpoints = [urlsplit(item) for item in json.loads(entry.uris_json)]
        matched = any(
            item.scheme == "https" and not item.username and not item.password
            and (item.hostname or "").lower().rstrip(".") == target.host
            and (item.port or 443) == target.port for item in endpoints
        )
    except (TypeError, ValueError):
        matched = False
    if not matched:
        raise RenewalError("The saved credential must have an HTTPS URI for this exact endpoint.")
    return reference


def _credentials(db: Session, reference: dict[str, Any], target: Target) -> Any:
    """Resolve a still-bound Vault reference after proving the current TLS pin.

    Args:
        db: Active database session.
        reference: Saved credential reference without secret values.
        target: Confirmed credential destination.
    """
    if PinnedHTTPS(target).probe()["sha256"] != target.fingerprint:
        raise RenewalError("Endpoint TLS identity changed; confirm it again before authentication.")
    values = {"credential_vault_id": reference["vault_id"], "credential_entry_id": reference["entry_id"]}
    if _reference(db, values, target) != reference:
        raise RenewalError("The saved credential changed; inspect the connection again.")
    return native._credentials(db, values, reference)


@contextmanager
def _client(db: Session, connection: dict[str, Any]) -> Iterator[OperationsClient]:
    """Open a pinned short-lived VCF Operations session.

    Args:
        db: Active database session.
        connection: Saved endpoint and Vault references.
    """
    target = _target(connection)
    credentials = _credentials(db, connection["reference"], target)
    with OperationsClient(target) as client:
        client.login(credentials)
        version = client.version()
        if not isinstance(version, dict) or tuple(version.get(k) for k in ("major", "minor", "minorMinor", "patch")) != (9, 1, 1, 0):
            raise RenewalError("Only the VCF Operations 9.1.1 contract is implemented; live validation is pending.")
        yield client


def _inventory_record(connection_id: str, record: dict[str, Any]) -> dict[str, Any]:
    """Project public fleet fields and independently observe the target's TLS leaf.

    Args:
        connection_id: Saved Operations integration identity.
        record: Allowlisted fleet certificate response.
    """
    host = str(record.get("applianceFqdn", "")).lower().rstrip(".")
    identifier = str(record.get("certificateResourceKey", ""))
    metadata = record.get("certificateMetadata") or {}
    eligible = (
        record.get("appliance") == "VCENTER" and record.get("category") == "TLS_CERT"
        and isinstance(metadata, dict) and metadata.get("certificatePurpose") == "MACHINE_SSL_CERT"
        and bool(re.fullmatch(r"[a-z0-9.:-]{1,253}", host))
        and bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", identifier))
    )
    value = {"connection_id": connection_id, "certificate_id": identifier, "host": host,
             "issuer": str(record.get("issuedBy", ""))[:500], "native_auto_renewal": str(record.get("displayAutoRenewState", "Not recorded"))[:80],
             "eligible": eligible, "reason": "Experimental; native topology and health checked before preparation." if eligible else "Only explicitly identified vCenter Machine SSL leaves are eligible.",
             "expiry": "", "days_remaining": None, "fingerprint": ""}
    if eligible:
        observed = PinnedHTTPS(Target(host, 443, "0" * 64)).probe()
        leaf = x509.load_pem_x509_certificate(observed["certificate_pem"].encode())
        value.update(fingerprint=observed["sha256"], expiry=leaf.not_valid_after_utc.isoformat(),
                     days_remaining=(leaf.not_valid_after_utc - datetime.now(timezone.utc)).total_seconds() / 86400)
    return value


def _inventory(db: Session, connection_id: str, *, certificate_id: str | None = None) -> list[dict[str, Any]]:
    """Read fleet metadata and limit TLS probes to the selected target when given.

    Args:
        db: Active database session.
        connection_id: Saved integration identity.
        certificate_id: Optional exact identity selected before target TLS probing.
    """
    _, connection = _row(db, "connection", connection_id)
    with _client(db, connection) as client:
        records = client.inventory()
    identifiers = [str(item.get("certificateResourceKey", "")) for item in records]
    if len(identifiers) != len(set(identifiers)):
        raise RenewalError("VCF returned ambiguous certificate identities.")
    if certificate_id is not None:
        records = [record for record in records if record.get("certificateResourceKey") == certificate_id]
    result = []
    for record in records:
        try:
            result.append(_inventory_record(connection_id, record))
        except (RemoteError, ValueError):
            result.append({"connection_id": connection_id, "certificate_id": str(record.get("certificateResourceKey", "")),
                           "host": "", "eligible": False, "reason": "Target TLS identity is unavailable; correct connectivity before enrollment."})
    return result


def _selected(db: Session, policy: dict[str, Any]) -> dict[str, Any]:
    """Require the same unique eligible fleet target on each state transition.

    Args:
        db: Active database session.
        policy: Persisted exact target binding.
    """
    records = _inventory(db, policy["connection_id"], certificate_id=policy["certificate_id"])
    if len(records) != 1 or not records[0].get("eligible") or records[0]["host"] != policy["host"]:
        raise RenewalError("The enrolled target is missing, ambiguous or no longer eligible.")
    return records[0]


def _active(db: Session, policy: dict[str, Any]) -> dict[str, Any] | None:
    """Return a retained proposal/operation, including uncertain failed writes.

    Args:
        db: Active database session.
        policy: Persisted policy state.
    """
    if not policy.get("operation_id"):
        return None
    _, operation = _row(db, "operation", policy["operation_id"])
    return operation if operation["state"] not in TERMINAL else None


def _policy_digest(policy: dict[str, Any]) -> str:
    """Exclude read-only observations from the approval-bound policy identity.

    Args:
        policy: Persisted enrollment and observational state.
    """
    return _digest({k: v for k, v in policy.items() if k not in {"last_check_at", "last_job_id", "operation_id", "observation"}})


def check_policy(db: Session, policy_id: str) -> dict[str, Any]:
    """Perform only observation and proposal creation, safe for the scheduler.

    Args:
        db: Active database session.
        policy_id: Explicitly enrolled policy identity.
    """
    _, policy = _row(db, "policy", policy_id)
    _actor(db, policy["actor"])
    if not policy["enabled"]:
        return {"state": "disabled", "policy_id": policy_id}
    observed = _selected(db, policy)
    acquire_network_objects_write_lock(db)
    _, current = _row(db, "policy", policy_id)
    if _policy_digest(current) != _policy_digest(policy):
        raise RenewalError("Renewal policy changed during discovery; check again.")
    if not current["enabled"]:
        db.rollback()
        return {"state": "disabled", "policy_id": policy_id}
    current.update(last_check_at=utcnow().isoformat(), observation=observed)
    operation = _active(db, current)
    if operation is None and observed["days_remaining"] <= current["threshold_days"]:
        identifier = uuid4().hex
        operation = {"id": identifier, "policy_id": policy_id, "actor": current["actor"],
                     "state": "proposal", "checkpoint": "discovered", "write_revision": 0,
                     "current_fingerprint": observed["fingerprint"], "created_at": utcnow().isoformat(), "verification": {}}
        _put(db, "operation", identifier, operation)
        current["operation_id"] = identifier
        db.add(AuditEvent(actor=current["actor"], action="vcf_renewal_proposal", resource_type="vcf_certificate_renewal", resource_id=identifier, detail="Expiry threshold reached; no native writes performed."))
    _put(db, "policy", policy_id, current)
    db.commit()
    return {"state": operation["state"] if operation else "not_due", "policy_id": policy_id}


def _enqueue(db: Session, actor: str, action: str, policy: dict[str, Any], operation: dict[str, Any] | None = None) -> Job:
    """Queue one admitted worker action while serializing competing requests.

    Args:
        db: Active database writer transaction.
        actor: Current administrator identity.
        action: Internal admitted action, never derived from a schedule.
        policy: Exact persisted target policy.
        operation: Optional retained operation.
    """
    policy_id = policy["id"]
    for item in db.scalars(select(Job).where(Job.type.in_([JOB_TYPE, CHECK_JOB_TYPE]), Job.status.in_(["pending", "running"]))):
        if json.loads(item.task_config_json).get("policy_id") == policy_id:
            raise RenewalError("This target already has an active renewal task.")
    job = Job(id="job_renewal_" + uuid4().hex[:20], type=CHECK_JOB_TYPE if action == "check" else JOB_TYPE,
              created_by=actor, status="pending", result="{}", task_config_json=_json({"policy_id": policy_id, "operation_id": operation["id"] if operation else None, "action": action}))
    db.add(job)
    policy["last_job_id"] = job.id
    _put(db, "policy", policy_id, policy)
    if operation:
        operation["job_id"] = job.id
        _put(db, "operation", operation["id"], operation)
    db.commit()
    return job


def _checkpoint(db: Session, operation: dict[str, Any], *, commit: bool = True, **updates: Any) -> None:
    """Compare-and-swap a durable checkpoint before any remote write dispatch.

    Args:
        db: Active database session.
        operation: Locally observed state carrying its committed revision.
        commit: Commit now or join the caller's atomic completion transaction.
        **updates: New public checkpoint fields.
    """
    acquire_network_objects_write_lock(db)
    row, current = _row(db, "operation", operation["id"])
    if current["write_revision"] != operation["write_revision"]:
        raise RenewalError("Renewal state changed; reconcile before another operation.")
    operation.update(updates)
    operation["write_revision"] += 1
    row.value = _json(operation)
    if commit:
        db.commit()


def _review_digest(operation: dict[str, Any]) -> str:
    """Bind approval to exact material and policy, not changing task metadata.

    Args:
        operation: Durable operation public snapshot.
    """
    return _digest({k: operation.get(k) for k in ("id", "actor", "approval_revision", "policy_snapshot", "ca_snapshot", "current_fingerprint", "replacement_certificate", "csr_pem", "leaf_pem", "root_pem")})


def _serializer() -> URLSafeTimedSerializer:
    """Create a short-lived, purpose-bound certificate review signer."""
    return URLSafeTimedSerializer(get_settings().secret_key, salt="vcf-managed-renewal-v1")


def _wait(client: OperationsClient, request_id: str) -> None:
    """Poll an already dispatched workflow within one fixed readiness deadline.

    Args:
        client: Authenticated Operations client.
        request_id: Previously persisted native workflow identity.
    """
    deadline = time.monotonic() + REMOTE_WAIT_SECONDS
    while time.monotonic() < deadline:
        result = client.workflow(request_id)
        status = result.get("state")
        if status == "COMPLETED":
            return
        if status == "FAILED":
            raise RenewalError("VCF workflow failed; inspect native task state before retrying.")
        if status not in {"CREATED", "IN_PROGRESS", "INPROGRESS", "RUNNING"}:
            raise RenewalError("VCF returned an unknown workflow state; reconciliation is required.")
        time.sleep(2)
    raise RenewalError("VCF workflow has not completed within the readiness limit; reconcile status.")


def _health_target(policy: dict[str, Any], fingerprint: str) -> Target:
    """Bind read-only native checks to the enrolled vCenter identity.

    Args:
        policy: Persisted exact target policy.
        fingerprint: Confirmed old or exact replacement leaf fingerprint.
    """
    return Target(policy["host"], 443, fingerprint)


def _prepare(db: Session, policy: dict[str, Any], operation: dict[str, Any]) -> None:
    """Prepare exactly one target-owned CSR after explicit operator admission.

    Args:
        db: Active database session.
        policy: Unchanged enrolled policy.
        operation: Admitted preparation operation.
    """
    observed = _selected(db, policy)
    if observed["fingerprint"] != operation["current_fingerprint"]:
        raise RenewalError("Target certificate changed after discovery; create a fresh proposal.")
    if observed["fingerprint"] != policy["confirmed_target_tls_fingerprint"]:
        raise RenewalError("Target TLS identity differs from enrollment; independent reconfirmation is required before credentials can be released.")
    target = _health_target(policy, operation["current_fingerprint"])
    credentials = _credentials(db, policy["health_reference"], target)
    discovered = native._inspect(db, "vcenter", target, credentials)
    operation.update(discovered, address=policy["host"], port=443, product="vcenter", profile_id=policy["profile_id"], confirmed_tls_fingerprint=target.fingerprint)
    if discovered["identity"].lower().rstrip(".") != policy["host"]:
        raise RenewalError("Native vCenter identity differs from the enrolled fleet target.")
    operation["ca_snapshot"] = native._ca_snapshot(db, "vcenter", policy["profile_id"])
    _, connection = _row(db, "connection", policy["connection_id"])
    with _client(db, connection) as client:
        if client.csrs(policy["certificate_id"]):
            raise RenewalError("A native CSR already exists; reconcile it before generating another.")
        profile = operation["ca_snapshot"]["profile"]
        names = operation["names"]
        spec = {"commonName": names["common_name"], "keyAlgorithm": "RSA", "keySize": "KEY_" + str(profile["key_size"]),
                "organization": "Atlaso", "orgUnit": "VCF", "subjectAltNames": {"dns": names["dns_names"], "ip": names["ip_addresses"]}}
        _checkpoint(db, operation, checkpoint="csr_dispatch_pending", state="preparing")
        request_id = client.generate_csr(policy["certificate_id"], spec)
        _checkpoint(db, operation, checkpoint="csr_submitted", csr_request_id=request_id)
        _wait(client, request_id)
        records = client.csrs(policy["certificate_id"])
    if len(records) != 1 or not isinstance(records[0].get("csr"), str):
        raise RenewalError("Generated CSR identity is ambiguous; reconcile the native request.")
    _checkpoint(db, operation, checkpoint="csr_received", csr_pem=records[0]["csr"])
    _issue(db, policy, operation)


def _issue(db: Session, policy: dict[str, Any], operation: dict[str, Any]) -> None:
    """Validate and account for one captured CSR through the shared CA writer.

    Args:
        db: Active database session.
        policy: Unchanged selected CA profile.
        operation: Durable captured public CSR and identity.
    """
    names = operation["names"]
    csr = validate_product_csr(operation["csr_pem"].encode(), "vcenter", set(names["dns_names"]), set(names["ip_addresses"]))
    common_names = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != names["common_name"]:
        raise RenewalError("CSR common name differs from the reviewed target identity.")
    acquire_network_objects_write_lock(db)
    if native._ca_snapshot(db, "vcenter", policy["profile_id"]) != operation["ca_snapshot"]:
        raise RenewalError("CA or profile changed; reconcile the captured CSR.")
    settings, profiles = native._ready_ca(db, "vcenter", policy["profile_id"])
    certificate = CaCertificate(common_name=names["common_name"], profile_id=policy["profile_id"], subject_alt_names="\n".join(names["dns_names"]),
                                ip_addresses="\n".join(names["ip_addresses"]), csr_text=operation["csr_pem"], status="csr-staged", enabled=True,
                                description="VCF managed renewal " + operation["id"])
    db.add(certificate)
    db.flush()
    if not ca.issue_certificate(settings, profiles, certificate):
        raise RenewalError("The shared CA could not issue the captured CSR.")
    root = settings.root_certificate_pem
    leaf = certificate.certificate_pem
    issued = validate_issued_certificate(operation["csr_pem"].encode(), leaf.encode(), "vcenter", set(names["dns_names"]), set(names["ip_addresses"]), x509.load_pem_x509_certificate(root.encode()))
    metadata = json.loads(_json(certificate_metadata(issued).__dict__))
    db.add(AuditEvent(actor=operation["actor"], action="vcf_renewal_certificate_issued", resource_type="ca_certificate", resource_id=str(certificate.id), detail="operation=" + operation["id"]))
    _checkpoint(db, operation, checkpoint="certificate_prepared", state="prepared", certificate_id=certificate.id,
                leaf_pem=leaf, root_pem=root, replacement_certificate=metadata)


def _material(db: Session, operation: dict[str, Any]) -> tuple[str, str]:
    """Revalidate the retained public certificate against current CA accounting.

    Args:
        db: Active session admitted to the shared CA writer boundary.
        operation: Exact CSR, issued-certificate identity and reviewed public PEM.
    """
    acquire_network_objects_write_lock(db)
    db.expire_all()
    leaf, root = native._material(db, operation)
    if leaf != operation["leaf_pem"] or root.strip() != operation["root_pem"].strip():
        raise RenewalError("Retained certificate material changed; native recovery is required.")
    return leaf, root


def _execute(db: Session, policy: dict[str, Any], operation: dict[str, Any]) -> None:
    """Dispatch the approved exact chain once and independently verify installation.

    Args:
        db: Active database session.
        policy: Unchanged enrolled policy.
        operation: Single-use approved operation.
    """
    observed = _selected(db, policy)
    if observed["fingerprint"] != operation["current_fingerprint"]:
        raise RenewalError("Target certificate changed after review; reconcile the existing operation.")
    if native._ca_snapshot(db, "vcenter", policy["profile_id"]) != operation["ca_snapshot"]:
        raise RenewalError("CA or profile changed after review; reconcile the existing operation.")
    credentials = _credentials(db, policy["health_reference"], _health_target(policy, observed["fingerprint"]))
    fresh = native._inspect(db, "vcenter", _health_target(policy, observed["fingerprint"]), credentials)
    if fresh["names"] != operation["names"] or fresh["identity"] != operation["identity"]:
        raise RenewalError("Native identity or SANs changed after preparation.")
    _, connection = _row(db, "connection", policy["connection_id"])
    with _client(db, connection) as client:
        leaf, root = _material(db, operation)
        _checkpoint(db, operation, checkpoint="replacement_dispatch_pending", state="installing")
        request_id = client.replace(policy["certificate_id"], leaf.rstrip() + "\n" + root.strip() + "\n")
        _checkpoint(db, operation, checkpoint="replacement_submitted", replacement_request_id=request_id)
        _wait(client, request_id)
    _verify(db, policy, operation)


def _verify(db: Session, policy: dict[str, Any], operation: dict[str, Any]) -> None:
    """Require exact fresh strict TLS and authenticated native health before success.

    Args:
        db: Active database session.
        policy: Enrolled target and Vault references.
        operation: Exact issued leaf and checkpoint.
    """
    _checkpoint(db, operation, checkpoint="verifying", state="verifying")
    expected = operation["replacement_certificate"]["fingerprint_sha256"]
    target = Target(policy["host"], 443, expected, strict_tls=True, ca_pem=operation["root_pem"])
    credentials = _credentials(db, policy["health_reference"], target)
    if not native._verify(operation, credentials, operation["root_pem"]):
        raise RenewalError("The exact replacement certificate and native health are not verified; reconcile status.")
    _checkpoint(db, operation, commit=False, state="succeeded", checkpoint="verified")
    _, current_policy = _row(db, "policy", policy["id"])
    current_policy["confirmed_target_tls_fingerprint"] = expected
    _put(db, "policy", policy["id"], current_policy)
    db.execute(delete(Setting).where(Setting.key.in_(operation.get("reservation_keys", [])), Setting.value == operation["id"]))
    db.add(AuditEvent(actor=operation["actor"], action="vcf_renewal_replacement_verified", resource_type="vcf_certificate_renewal", resource_id=operation["id"], detail="Exact served leaf, strict TLS and authenticated native health verified."))
    db.commit()


def _reconcile(db: Session, policy: dict[str, Any], operation: dict[str, Any]) -> None:
    """Observe existing native work without generating another CSR or replacement.

    Args:
        db: Active database session.
        policy: Exact enrolled target policy.
        operation: Retained possibly uncertain operation.
    """
    if operation["checkpoint"] == "queued_preparation":
        # Dispatch is possible only after the separately committed CSR intent.
        # This checkpoint proves no certificate-management write was sent.
        _checkpoint(db, operation, commit=False, state="proposal", checkpoint="discovered")
        db.execute(delete(Setting).where(Setting.key.in_(operation.get("reservation_keys", [])), Setting.value == operation["id"]))
        db.commit()
    elif operation["checkpoint"] == "queued_replacement":
        # The issued material remains reserved; a new actor-bound review is
        # required before any later replacement dispatch.
        _checkpoint(db, operation, state="prepared", checkpoint="certificate_prepared")
    elif operation["checkpoint"] == "certificate_prepared" and operation.get("certificate_id"):
        # Issuance and its public material were committed atomically before the
        # worker stopped. Validate that retained material, never sign it again.
        _material(db, operation)
        _checkpoint(db, operation, state="prepared")
    elif operation.get("replacement_request_id"):
        _, connection = _row(db, "connection", policy["connection_id"])
        with _client(db, connection) as client:
            _wait(client, operation["replacement_request_id"])
        _verify(db, policy, operation)
    elif operation["checkpoint"] in {"replacement_dispatch_pending", "verifying"}:
        # Exact TLS cannot prove that VCF's coordinating workflow is terminal.
        # Preserve its reservation until a native recovery procedure can prove
        # the request identity; never substitute another replacement dispatch.
        raise RenewalError("The VCF replacement workflow identity is unknown; native recovery is required. No replacement was retried.")
    elif operation.get("csr_request_id") and not operation.get("certificate_id"):
        _, connection = _row(db, "connection", policy["connection_id"])
        with _client(db, connection) as client:
            _wait(client, operation["csr_request_id"])
            records = client.csrs(policy["certificate_id"])
        if len(records) != 1 or not isinstance(records[0].get("csr"), str):
            raise RenewalError("The retained CSR cannot be identified; native recovery is required.")
        _checkpoint(db, operation, checkpoint="csr_received", csr_pem=records[0]["csr"])
        _issue(db, policy, operation)
    else:
        raise RenewalError("Native request identity is uncertain; follow the documented recovery procedure. No write was retried.")


def run(job_id: str) -> None:
    """Run a claimed persistent task, separating discovery from admitted writes.

    Args:
        job_id: Existing task claimed by the persistent worker.
    """
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None or job.status not in {"running", "pending"}:
            return
        config = json.loads(job.task_config_json)
        operation = None
        try:
            _, policy = _row(db, "policy", config["policy_id"])
            _actor(db, policy["actor"])
            if job.type == CHECK_JOB_TYPE:
                result = check_policy(db, policy["id"])
            else:
                _, operation = _row(db, "operation", config["operation_id"])
                _actor(db, operation["actor"])
                if operation.get("job_id") != job_id or operation.get("policy_snapshot") != _policy_digest(policy):
                    raise RenewalError("Operation or policy changed after admission; reconcile status.")
                if job.cancel_requested_at:
                    raise RenewalError("Task cancellation requires reconciliation; no further native writes were dispatched.")
                action = config.get("action")
                if action == "prepare" and operation["checkpoint"] == "queued_preparation":
                    _prepare(db, policy, operation)
                elif action == "execute" and operation["checkpoint"] == "queued_replacement":
                    _execute(db, policy, operation)
                elif action == "reconcile":
                    _reconcile(db, policy, operation)
                else:
                    raise RenewalError("This task cannot dispatch the requested operation from its checkpoint.")
                result = {"operation_id": operation["id"], "state": operation["state"], "checkpoint": operation["checkpoint"]}
            job.status, job.result, job.progress_percent = "succeeded", _json(result), 100
        except (RenewalError, native.CertificateOperationError, CertificateMaterialError, RemoteError, ValueError, KeyError, TypeError, OSError):
            db.rollback()
            if operation:
                _, operation = _row(db, "operation", operation["id"])
                _checkpoint(db, operation, state="needs_recovery", error="Renewal could not be verified. Reconcile native state; no uncertain write will be repeated.")
            job = db.get(Job, job_id)
            if job is None:
                return
            job.status, job.error = "failed", "Renewal could not be verified. Check prerequisites and reconcile status."
        job.finished_at = utcnow()
        db.add(AuditEvent(actor=job.created_by, action="vcf_renewal_task_finished", resource_type="job", resource_id=job.id, detail="status=" + job.status))
        db.commit()


def state(db: Session, actor: str) -> dict[str, Any]:
    """Return public administration state without resolving credentials.

    Args:
        db: Active database session.
        actor: Current administrator identity.
    """
    _actor(db, actor)
    connections = [{k: value.get(k) for k in ("id", "name", "address", "port")} for value in _all(db, "connection")]
    policies = []
    inventory = []
    for policy in _all(db, "policy"):
        value = {k: policy.get(k) for k in ("id", "connection_id", "certificate_id", "host", "profile_id", "enabled", "threshold_days", "cron_expression", "timezone_name", "operation_id", "last_check_at")}
        schedule = db.get(Schedule, policy["schedule_id"]) if policy.get("schedule_id") else None
        if schedule and (schedule.task_type != "vcf_certificate_renewal_check" or json.loads(schedule.task_config_json).get("policy_id") != policy["id"]):
            schedule = None
        value["next_check_at"] = schedule.next_run_at.isoformat() if schedule and schedule.next_run_at else None
        value["proposal_state"] = "not_due"
        operation = _row(db, "operation", policy["operation_id"])[1] if policy.get("operation_id") else None
        value["job_id"] = policy.get("last_job_id")
        if operation:
            value.update(proposal_state=operation["state"], job_id=operation.get("job_id") or value["job_id"])
        policies.append(value)
        if policy.get("observation"):
            inventory.append(policy["observation"])
    profiles = [{"id": p.id, "name": p.name} for p in db.scalars(select(CaProfile).where(CaProfile.enabled.is_(True)))]
    return {"connections": connections, "policies": policies, "profiles": profiles, "inventory": inventory, "experimental": True}


def dispatch(db: Session, actor: str, action: str, values: dict[str, Any]) -> dict[str, Any]:
    """Admit one administrator browser action without accepting worker actions from schedules.

    Args:
        db: Active database session.
        actor: Current administrator identity.
        action: Explicit allowlisted browser action.
        values: Bounded parsed browser values.
    """
    try:
        _actor(db, actor)
        return _dispatch(db, actor, action, values)
    except RenewalError:
        db.rollback()
        raise
    except (native.CertificateOperationError, CertificateMaterialError, RemoteError, ValueError, TypeError, KeyError, OverflowError) as exc:
        db.rollback()
        raise RenewalError("Renewal prerequisites could not be verified. Check credentials, TLS identity and native capability.") from exc


def _idle_connection_policies(db: Session, identifier: str) -> list[dict[str, Any]]:
    """Reject connection changes while any bound certificate write task is live.

    Args:
        db: Administrator session before confirmation or its final writer transaction.
        identifier: Retained Operations connection identity.
    """
    policies = [p for p in _all(db, "policy") if p["connection_id"] == identifier]
    policy_ids = {p["id"] for p in policies}
    for job in db.scalars(select(Job).where(Job.type == JOB_TYPE, Job.status.in_(["pending", "running"]))):
        if json.loads(job.task_config_json).get("policy_id") in policy_ids:
            raise RenewalError("Wait for the active certificate write task to finish before reconfirming this connection.")
    return policies


def _save_connection(db: Session, actor: str, values: dict[str, Any]) -> dict[str, Any]:
    """Authenticate an explicitly confirmed new or retained Operations endpoint.

    Args:
        db: Administrator database session.
        actor: Administrator confirming this endpoint and saved Vault reference.
        values: Public endpoint, exact fingerprint, Vault reference and optional existing identity.
    """
    target = _target(values)
    existing = _row(db, "connection", str(values["connection_id"]))[1] if values.get("connection_id") else None
    if existing:
        if values.get("confirm_connection_update") is not True:
            raise RenewalError("Explicitly confirm reconnection and the current endpoint fingerprint.")
        if target.host != existing["address"] or target.port != existing["port"]:
            raise RenewalError("Reconfirmation must retain the saved Operations host and port.")
        _idle_connection_policies(db, str(existing["id"]))
    reference = _reference(db, values, target)
    identifier = str(existing["id"]) if existing else uuid4().hex
    connection = {"id": identifier, "name": str(values.get("name", "VCF Operations"))[:120], "address": target.host, "port": target.port,
                  "confirmed_tls_fingerprint": target.fingerprint, "reference": reference, "actor": actor}
    # Resolve and authenticate only after the exact fresh fingerprint and saved
    # Vault destination are checked. The request-local token is released here.
    with _client(db, connection):
        pass
    acquire_network_objects_write_lock(db)
    db.expire_all()
    if existing:
        if _digest(_row(db, "connection", identifier)[1]) != _digest(existing):
            raise RenewalError("The saved connection changed during confirmation; inspect it again.")
        policies = _idle_connection_policies(db, identifier)
        for policy in policies:
            operation = _active(db, policy)
            if operation and operation.get("certificate_id"):
                # Keep request identities, native checkpoints and reservations.
                # An old approval cannot outlive a connection reconfirmation.
                _checkpoint(db, operation, commit=False, approval_revision=operation.get("approval_revision", 0) + 1)
    if _reference(db, values, target) != reference:
        raise RenewalError("The Vault credential changed during confirmation; select it again.")
    _put(db, "connection", identifier, connection)
    db.add(AuditEvent(actor=actor, action="vcf_renewal_connection_reconfirmed" if existing else "vcf_renewal_connection_created",
                      resource_type="vcf_operations_connection", resource_id=identifier, detail="Exact endpoint fingerprint and saved Vault authentication confirmed."))
    db.commit()
    return {"connection_id": identifier, "message": "Existing Operations connection reconfirmed; review prepared replacements again." if existing else "Operations connection saved."}


def _dispatch(db: Session, actor: str, action: str, values: dict[str, Any]) -> dict[str, Any]:
    """Implement browser actions behind shared authorization and error sanitation.

    Args:
        db: Active database session.
        actor: Current administrator identity.
        action: Explicit browser action.
        values: Bounded parsed browser values.
    """
    if action == "probe":
        observed = PinnedHTTPS(_target(values)).probe()
        return {"fingerprint": observed["sha256"], "issuer": observed["issuer"], "subject": observed["subject"]}
    if action == "save_connection":
        return _save_connection(db, actor, values)
    if action == "inventory":
        return {"inventory": _inventory(db, str(values["connection_id"]))}
    if action == "save_policy":
        return _save_policy(db, actor, values)
    if action == "check":
        acquire_network_objects_write_lock(db)
        _, policy = _row(db, "policy", str(values["policy_id"]))
        if not policy["enabled"]:
            raise RenewalError("Enable enrollment before checking this renewal policy.")
        return {"job_id": _enqueue(db, actor, "check", policy).id}
    if action in {"prepare", "review", "execute", "reconcile"}:
        acquire_network_objects_write_lock(db)
        if action == "prepare":
            _, policy = _row(db, "policy", str(values["policy_id"]))
            operation = _active(db, policy)
            if not policy["enabled"] or operation is None or operation["state"] != "proposal":
                raise RenewalError("An enabled due proposal is required before preparation.")
            if values.get("acknowledge_preparation") is not True or values.get("acknowledge_recovery") is not True:
                raise RenewalError("Acknowledge native CSR preparation and the recovery prerequisites.")
            target = _health_target(policy, operation["current_fingerprint"])
            keys = native._locks("vcenter", target, policy["host"])
            if any(db.scalar(select(Setting).where(Setting.key == key)) for key in keys):
                raise RenewalError("This vCenter already has a reserved certificate operation.")
            for key in keys:
                db.add(Setting(key=key, value=operation["id"]))
            operation.update(actor=actor, policy_snapshot=_policy_digest(policy), checkpoint="queued_preparation", state="preparing", reservation_keys=keys)
            return {"operation_id": operation["id"], "job_id": _enqueue(db, actor, "prepare", policy, operation).id}
        _, operation = _row(db, "operation", str(values["operation_id"]))
        _, policy = _row(db, "policy", operation["policy_id"])
        if operation["actor"] != actor:
            raise RenewalError("This renewal operation belongs to another administrator.")
        if action == "review":
            if operation["state"] != "prepared":
                raise RenewalError("Prepare a certificate before reviewing replacement.")
            _material(db, operation)
            token = _serializer().dumps({"actor": actor, "operation_id": operation["id"], "digest": _review_digest(operation)})
            return {"operation_id": operation["id"], "review_token": token, "summary": {
                "host": policy["host"], "current_fingerprint": operation["current_fingerprint"], "replacement_certificate": operation["replacement_certificate"],
                "leaf_pem": operation["leaf_pem"], "chain_pem": operation["root_pem"], "impact": "VCF coordinates Machine SSL replacement. Expect interrupted management sessions; retain the supported vCenter recovery procedure."}}
        if action == "execute":
            try:
                review = _serializer().loads(str(values.get("review_token", "")), max_age=REVIEW_SECONDS)
            except BadData:
                raise RenewalError("Review expired or is invalid; review the exact certificate again.") from None
            if operation["state"] != "prepared" or review != {"actor": actor, "operation_id": operation["id"], "digest": _review_digest(operation)}:
                raise RenewalError("This review is stale or already used.")
            if operation["policy_snapshot"] != _policy_digest(policy) or not policy["enabled"]:
                raise RenewalError("Enrollment changed after preparation; reconcile the retained operation.")
            _material(db, operation)
            operation.update(state="installing", checkpoint="queued_replacement", approval_revision=operation.get("approval_revision", 0) + 1)
        elif action == "reconcile":
            if operation["state"] != "needs_recovery":
                raise RenewalError("Only an uncertain operation requires reconciliation.")
        return {"operation_id": operation["id"], "job_id": _enqueue(db, actor, action, policy, operation).id}
    raise RenewalError("Unknown renewal action.")


def _disable_policy(db: Session, actor: str, policy_id: str) -> dict[str, Any]:
    """Stop discovery using local bindings while preserving admitted native work.

    Args:
        db: Administrator session before writer admission.
        actor: Current administrator for the audit event.
        policy_id: Existing enrollment identity whose bindings must be retained.
    """
    acquire_network_objects_write_lock(db)
    _, policy = _row(db, "policy", policy_id)
    active = _active(db, policy)
    if active and active["state"] != "proposal":
        raise RenewalError("Reconcile or finish the active renewal before disabling this policy.")
    if active:
        active.update(state="cancelled", checkpoint="enrollment_disabled", write_revision=active["write_revision"] + 1)
        _put(db, "operation", active["id"], active)
    schedule = db.get(Schedule, policy["schedule_id"]) if policy.get("schedule_id") else None
    try:
        bound = schedule is not None and schedule.task_type == "vcf_certificate_renewal_check" and json.loads(schedule.task_config_json).get("policy_id") == policy_id
    except (ValueError, TypeError, AttributeError):
        bound = False
    if bound and schedule is not None:
        schedule.enabled, schedule.next_run_at = False, None
    policy["enabled"] = False
    _put(db, "policy", policy_id, policy)
    db.add(AuditEvent(actor=actor, action="vcf_renewal_policy", resource_type="vcf_certificate_renewal", resource_id=policy_id, detail="Discovery-only enrollment disabled locally; saved bindings retained."))
    db.commit()
    return {"policy_id": policy_id, "schedule_id": schedule.id if bound and schedule else None,
            "message": "Enrollment disabled. Saved target, credentials, profile and timing bindings were retained."}


def _save_policy(db: Session, actor: str, values: dict[str, Any]) -> dict[str, Any]:
    """Create or edit one opt-in policy and its discovery-only persistent schedule.

    Args:
        db: Active database session.
        actor: Current administrator identity.
        values: Exact inventory target, profile, credential references and timing.
    """
    from atlaso.app.services.automation import (
        next_schedule_run,
        validate_schedule_values,
    )

    enabled = values.get("enabled", False)
    if not isinstance(enabled, bool):
        raise RenewalError("Enrollment enabled state must be a boolean.")
    if values.get("policy_id") and values.get("enabled") is False:
        return _disable_policy(db, actor, str(values["policy_id"]))
    connection_id = str(values["connection_id"])
    certificate_id = str(values["certificate_id"])
    candidates = [r for r in _inventory(db, connection_id, certificate_id=certificate_id) if r["certificate_id"] == certificate_id and r.get("eligible")]
    if len(candidates) != 1:
        raise RenewalError("Select one eligible vCenter Machine SSL certificate.")
    observed = candidates[0]
    threshold = int(values.get("threshold_days", 30))
    if isinstance(values.get("threshold_days"), bool) or not 1 <= threshold <= 365:
        raise RenewalError("Expiry threshold must be between 1 and 365 days.")
    profile_id = int(values["profile_id"])
    native._ready_ca(db, "vcenter", profile_id)
    pin = str(values.get("confirmed_target_tls_fingerprint", ""))
    if pin.replace(":", "").lower() != observed["fingerprint"]:
        raise RenewalError("Independently confirm the displayed target TLS fingerprint before enrollment.")
    target = Target(observed["host"], 443, pin)
    health_reference = _reference(db, {"credential_vault_id": values.get("health_credential_vault_id"), "credential_entry_id": values.get("health_credential_entry_id")}, target)
    identifier = str(values.get("policy_id") or uuid4().hex)
    cron = str(values.get("cron_expression", "0 2 * * *"))
    timezone_name = str(values.get("timezone_name", "UTC"))
    errors = validate_schedule_values(task_type="vcf_certificate_renewal_check", task_config_json=_json({"policy_id": identifier}),
                                     schedule_kind="cron", cron_expression=cron, run_once_at=None, timezone_name=timezone_name)
    if errors:
        raise RenewalError(" ".join(errors))
    acquire_network_objects_write_lock(db)
    old = None
    if values.get("policy_id"):
        _, old = _row(db, "policy", identifier)
        active = _active(db, old)
        if active:
            if active["state"] != "proposal":
                raise RenewalError("Reconcile or finish the active renewal before editing this policy.")
            active.update(state="cancelled", checkpoint="policy_changed", write_revision=active["write_revision"] + 1)
            _put(db, "operation", active["id"], active)
    for existing in _all(db, "policy"):
        if existing["id"] != identifier and (existing["host"] == observed["host"] or (existing["connection_id"] == connection_id and existing["certificate_id"] == certificate_id)):
            raise RenewalError("This vCenter already has a renewal policy.")
    schedule = db.get(Schedule, old["schedule_id"]) if old else None
    if schedule and (schedule.task_type != "vcf_certificate_renewal_check" or json.loads(schedule.task_config_json).get("policy_id") != identifier):
        schedule = None
    if schedule is None:
        schedule = Schedule(name="VCF renewal " + observed["host"], task_type="vcf_certificate_renewal_check", created_by=actor)
        db.add(schedule)
    schedule.task_config_json = _json({"policy_id": identifier})
    schedule.schedule_kind, schedule.cron_expression, schedule.timezone_name, schedule.enabled = "cron", cron, timezone_name, enabled
    schedule.next_run_at = next_schedule_run(schedule, after=utcnow()) if enabled else None
    db.flush()
    policy = {"id": identifier, "actor": actor, "connection_id": connection_id, "certificate_id": certificate_id, "host": observed["host"],
              "health_reference": health_reference, "confirmed_target_tls_fingerprint": target.fingerprint,
              "profile_id": profile_id, "threshold_days": threshold, "enabled": enabled, "schedule_id": schedule.id,
              "cron_expression": cron, "timezone_name": timezone_name, "observation": observed, "operation_id": None, "last_check_at": None}
    _put(db, "policy", identifier, policy)
    db.add(AuditEvent(actor=actor, action="vcf_renewal_policy", resource_type="vcf_certificate_renewal", resource_id=identifier, detail="Discovery-only enrollment " + ("enabled" if enabled else "disabled")))
    db.commit()
    return {"policy_id": identifier, "schedule_id": schedule.id}


def recover_interrupted_jobs(db: Session) -> int:
    """Recover stopped worker jobs; never call while their worker can still run.

    Args:
        db: Worker startup session after the preceding worker has stopped.
    """
    jobs = list(db.scalars(select(Job).where(Job.type == JOB_TYPE, Job.status == "running")))
    for job in jobs:
        config = json.loads(job.task_config_json)
        try:
            _, operation = _row(db, "operation", config["operation_id"])
            if operation["state"] == "succeeded" and operation["checkpoint"] == "verified":
                # Completion and reservation release already committed; only
                # the task's final status write was interrupted.
                job.status, job.error, job.progress_percent = "succeeded", "", 100
                job.result = _json({"operation_id": operation["id"], "state": "succeeded", "checkpoint": "verified"})
                job.finished_at = utcnow()
                continue
            _checkpoint(db, operation, state="needs_recovery", error="Interrupted renewal; reconcile native state before another write.")
        except (RenewalError, ValueError, KeyError):
            db.rollback()
        job.status, job.error, job.finished_at = "failed", "Interrupted renewal requires native-state reconciliation.", utcnow()
    db.commit()
    return len(jobs)
