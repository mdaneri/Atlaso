"""Coordinate administrator recovery transport and public-trust persistence.

Operational plaintext never enters the control plane. The privileged helper
returns only an encrypted archive or public trust and leaves imported keys offline.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.kmip.recovery import MAX_ARCHIVE_BYTES, RecoveryError, validate_trust
from atlaso.app.models import (
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
)
from atlaso.app.services.appliance_apply_admission import (
    ApplianceApplyAdmissionBusy,
    lock_appliance_apply_snapshot_tables,
)
from atlaso.app.services.vsphere_key_providers import parse_public_certificate


def public_trust(db: Session) -> dict[str, Any]:
    """Capture exact provider IDs and public certificate bytes from desired state.

    Args:
        db: Desired-state database session holding writer admission.
    """
    return {
        "providers": [{field: getattr(row, field) for field in ("id", "name", "description", "enabled")}
                      for row in db.scalars(select(VsphereKeyProvider).order_by(VsphereKeyProvider.id))],
        "vcenters": [{field: getattr(row, field) for field in ("id", "provider_id", "name", "hostname", "description", "enabled")}
                     for row in db.scalars(select(VsphereTrustedVcenter).order_by(VsphereTrustedVcenter.id))],
        "certificates": [{field: getattr(row, field) for field in ("id", "trusted_vcenter_id", "certificate_pem", "fingerprint_sha256")}
                         for row in db.scalars(select(VsphereTrustedVcenterCertificate).order_by(VsphereTrustedVcenterCertificate.id))],
    }


def _request(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Call the fixed helper with request-bound stdin and sanitized failure text.

    Args:
        action: Fixed supported privileged helper action.
        payload: Request-bound helper input serialized through standard input.
    """
    result = SystemAdapter()._helper_result(
        "kms", action, input_text=json.dumps(payload), timeout_seconds=180,
        dry_run_message="Recovery requires a live appliance.", dry_run_returncode=2,
    )
    if result.dry_run or result.returncode != 0:
        raise RecoveryError("KMIP recovery requires a live appliance and complete offline validation; inspect pending recovery before retrying.")
    try:
        response = json.loads(result.stdout)
        if not isinstance(response, dict):
            raise ValueError
        return response
    except ValueError as exc:
        raise RecoveryError("KMIP recovery returned invalid evidence; preserve state before retrying.") from exc


def _admit(db: Session) -> None:
    """Hold complete desired-state writer admission through export/import commit.

    Args:
        db: Desired-state database session holding writer admission.
    """
    try:
        lock_appliance_apply_snapshot_tables(db)
        db.expire_all()
    except ApplianceApplyAdmissionBusy as exc:
        raise RecoveryError("Recovery writer admission is busy; retry after the active appliance change completes.") from exc


def export_archive(db: Session, passphrase: str) -> bytes:
    """Export a quiesced, passphrase-encrypted authenticated recovery bundle.

    Args:
        db: Desired-state database session holding writer admission.
        passphrase: Request-bound recovery passphrase, never retained or logged.
    """
    _admit(db)
    result = _request("recovery-export", {"passphrase": passphrase, "trust": public_trust(db)})
    try:
        archive = base64.b64decode(result["archive"], validate=True)
        if len(archive) > MAX_ARCHIVE_BYTES:
            raise ValueError
        return archive
    except (KeyError, ValueError, TypeError) as exc:
        raise RecoveryError("KMIP recovery archive response is invalid.") from exc


def import_archive(db: Session, archive: bytes, passphrase: str) -> None:
    """Publish only to empty targets and atomically persist disabled public trust.

    A failed database commit leaves the helper's durable pending journal and
    offline keys intact. Uploading the same archive retries that commit.

    Args:
        db: Desired-state database session holding writer admission.
        archive: Bounded encrypted recovery bundle supplied by the caller.
        passphrase: Request-bound recovery passphrase, never retained or logged.
    """
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise RecoveryError("KMIP recovery archive exceeds the supported limit.")
    _admit(db)
    existing = public_trust(db)
    if any(existing.values()):
        raise RecoveryError("KMIP recovery requires an empty provider/trust target; preserve existing providers.")
    result = _request("recovery-import", {"passphrase": passphrase, "archive": base64.b64encode(archive).decode("ascii")})
    trust = result.get("trust")
    validate_trust(trust)
    assert isinstance(trust, dict)
    try:
        for row in trust["providers"]:
            db.add(VsphereKeyProvider(**{**row, "enabled": False, "applied_at": None}))
        db.flush()
        for row in trust["vcenters"]:
            db.add(VsphereTrustedVcenter(**{**row, "enabled": False}))
        db.flush()
        for row in trust["certificates"]:
            parsed = parse_public_certificate(row["certificate_pem"], require_current=False)
            parsed.pop("certificate_pem")
            parsed.pop("fingerprint_sha256")
            db.add(VsphereTrustedVcenterCertificate(**row, **parsed, source="uploaded_public"))
        db.flush()
    except Exception:
        db.rollback()
        raise
