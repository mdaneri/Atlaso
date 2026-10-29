"""Reviewed native VCF backup configuration with secret-free durable checkpoints.

Native products own recurring schedules. Atlaso configures one reviewed plan,
starts initial backups once, and verifies their artifacts on its SFTP receiver.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from pathlib import PurePosixPath
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from itsdangerous import BadData, URLSafeTimedSerializer
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal
from atlaso.app.models import Job, JobStep, Setting, User, VaultEntry, utcnow
from atlaso.app.secrets import decrypt_secret
from atlaso.app.security import user_roles
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.vaults import vault_entry_uris
from atlaso.app.services.vcf_backup_native import NativeBackup
from atlaso.app.services.vcf_backup_receiver import (
    ReceiverError,
    ReceiverSession,
    receiver_revision,
    require_receiver,
)
from atlaso.app.services.vcf_certificate_remote import (
    Credentials,
    PinnedHTTPS,
    RemoteError,
    Target,
)

PREFIX = "vcf_backup_op:"
LOCK_PREFIX = "vcf_backup_lock:"
JOB_TYPE = "vcf-backup-configuration"
REVIEW_SECONDS = 600
CONFIGURATION_SECONDS = 3600
BACKUP_SECONDS = 3600
MAX_SOURCES = 12
MAX_COMPONENTS = 300
MAX_STATE_BYTES = 1024 * 1024


class BackupOperationError(ValueError):
    """Public refusal that never includes native error payloads or secrets."""


class Dispatcher(Protocol):
    def add_task(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """Schedule one admitted task with request-local manual credentials.

        Args:
            func: Admitted synchronous worker.
            *args: Request-local worker inputs.
            **kwargs: Request-local worker inputs.
        """
        ...


def _json(value: Any) -> str:
    """Serialize only the public operation representation.

    Args:
        value: Public operation metadata.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    """Bind public metadata or encrypted-at-rest Vault revisions.

    Args:
        value: Public metadata or existing ciphertext; never plaintext passwords.
    """
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _actor(db: Session, actor: str) -> None:
    """Recheck administrator authority before reads, admission, and native writes.

    Args:
        db: Current workflow database session.
        actor: Administrator that owns this operation.
    """
    user = db.scalar(select(User).where(User.username == actor).execution_options(populate_existing=True))
    if user is None or not user.enabled or "admin" not in user_roles(user):
        raise BackupOperationError("An enabled administrator account is required.")


def _serializer() -> URLSafeTimedSerializer:
    """Bind short-lived reviews to this appliance's application key."""
    return URLSafeTimedSerializer(get_settings().secret_key, salt="vcf-backup-review-v1")


def _endpoint(address: Any, port: Any, fingerprint: Any = "0" * 64) -> Target:
    """Validate a literal appliance endpoint without userinfo or URL paths.

    Args:
        address: Hostname or IP; never an authenticated URI.
        port: HTTPS service port.
        fingerprint: Explicitly confirmed SHA-256 leaf fingerprint.
    """
    host = str(address or "").strip().lower().rstrip(".").strip("[]")
    try:
        if not host or len(host) > 253 or not re.fullmatch(r"[a-z0-9.:-]+", host):
            raise ValueError
        return Target(host, int(port or 443), str(fingerprint or "0" * 64))
    except (TypeError, ValueError):
        raise BackupOperationError("Enter a valid server address, HTTPS port, and SHA-256 fingerprint.") from None


def _source(values: dict[str, Any], *, confirmed: bool) -> dict[str, Any]:
    """Normalize a source while keeping manual credentials out of durable state.

    Args:
        values: Browser connection inputs.
        confirmed: Whether credentials may be resolved for this action.
    """
    kind = str(values.get("source_kind", values.get("kind", "")))
    if kind == "operations":
        kind = "fleet"
    if kind not in {"fleet", "sddc", "vcenter", "nsx"}:
        raise BackupOperationError("Select VCF Operations, SDDC Manager, vCenter, or NSX.")
    target = _endpoint(values.get("address"), values.get("port"), values.get("confirmed_tls_fingerprint"))
    if confirmed and (values.get("confirmed") is not True or target.fingerprint == "0" * 64):
        raise BackupOperationError("Confirm the server TLS fingerprint before using credentials.")
    result: dict[str, Any] = {"kind": kind, "address": target.host, "port": target.port, "fingerprint": target.fingerprint}
    if kind == "fleet" and any(values.get(key) for key in ("fleet_address", "fleet_port", "fleet_confirmed_tls_fingerprint")):
        raise BackupOperationError("VCF Operations discovers its registered backup service. Remove the separate Fleet connection override.")
    return result


def _reference(db: Session, values: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    """Bind saved credentials to an exact HTTP URI or retain only a manual username.

    Args:
        db: Session holding encrypted Vault entries.
        values: Request-local browser credentials or saved entry selection.
        source: Confirmed source endpoint.
    """
    vault, entry_id = values.get("credential_vault_id"), values.get("credential_entry_id")
    if vault in (None, "") and entry_id in (None, ""):
        username, password = values.get("username"), values.get("password")
        if (
            not isinstance(username, str) or not isinstance(password, str) or not username.strip() or not password
            or len(username) > 180 or len(password.encode()) > 4096
            or any(ord(char) < 32 for char in username + password)
        ):
            raise BackupOperationError("Enter request-local API administrator credentials.")
        return {"mode": "manual", "username": username.strip()}
    try:
        entry = db.get(VaultEntry, int(str(entry_id)), populate_existing=True)
        if entry is None or entry.vault_id != int(str(vault)) or not entry.username:
            raise ValueError
        uri = str(values.get("credential_uri", ""))
        parsed = urlsplit(uri)
        if (
            uri not in vault_entry_uris(entry) or parsed.scheme not in {"http", "https"}
            or parsed.username or parsed.password or not parsed.hostname
            or parsed.hostname.lower().rstrip(".") != source["address"]
            or (parsed.port or (443 if parsed.scheme == "https" else 80)) != source["port"]
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise BackupOperationError("Select a saved HTTP/HTTPS credential for this exact server.") from None
    return {"mode": "vault", "vault_id": entry.vault_id, "entry_id": entry.id, "username": entry.username,
            "uri": uri, "revision": _digest([entry.encrypted_value, str(entry.updated_at)])}


def _credentials(db: Session, values: dict[str, Any], source: dict[str, Any]) -> Credentials:
    """Resolve only a still-current credential selection after TLS confirmation.

    Args:
        db: Current database session.
        values: Request-local credential input.
        source: Recorded confirmed source and its public credential reference.
    """
    reference = _reference(db, values, source)
    if reference != source["credential_reference"]:
        raise BackupOperationError("The credential selection changed; inspect again.")
    if reference["mode"] == "manual":
        return Credentials(reference["username"], str(values["password"]))
    entry = db.get(VaultEntry, reference["entry_id"])
    if entry is None:
        raise BackupOperationError("The selected Vault credential is unavailable.")
    return Credentials(reference["username"], decrypt_secret(entry.encrypted_value))


def _secret_reference(db: Session, value: Any) -> dict[str, Any]:
    """Bind a backup secret by encrypted Vault revision, never by a password hash.

    Args:
        db: Database containing concealed Vault values.
        value: Browser-selected Vault and entry identifiers.
    """
    try:
        if not isinstance(value, dict):
            raise ValueError
        entry = db.get(VaultEntry, int(value.get("entry_id", 0)), populate_existing=True)
        if entry is None or entry.vault_id != int(value.get("vault_id", 0)) or not entry.encrypted_value:
            raise ValueError
    except (ValueError, TypeError):
        raise BackupOperationError("Select encrypted Vault keys for the SFTP password and backup passphrase.") from None
    return {"vault_id": entry.vault_id, "entry_id": entry.id, "label": entry.key,
            "revision": _digest([entry.encrypted_value, str(entry.updated_at)])}


def secret_options(db: Session) -> list[dict[str, Any]]:
    """List concealed-key identifiers and labels without resolving any value.

    Args:
        db: Current management session.
    """
    return [{"vault_id": row.vault_id, "entry_id": row.id, "label": row.key}
            for row in db.scalars(select(VaultEntry).where(VaultEntry.encrypted_value != "").order_by(VaultEntry.vault_id, VaultEntry.key))]


def _secret(db: Session, reference: dict[str, Any]) -> str:
    """Resolve the exact reviewed encrypted Vault revision inside an admitted task.

    Args:
        db: Current operation session.
        reference: Reviewed concealed-key reference.
    """
    if _secret_reference(db, reference) != reference:
        raise BackupOperationError("A reviewed backup secret changed; review again.")
    entry = db.get(VaultEntry, reference["entry_id"])
    if entry is None:
        raise BackupOperationError("A reviewed backup secret is unavailable.")
    return decrypt_secret(entry.encrypted_value)


def _policy(values: Any) -> dict[str, Any]:
    """Validate editable native schedule and product-specific retention settings.

    Args:
        values: Browser policy values, never native API request bodies.
    """
    if not isinstance(values, dict):
        raise BackupOperationError("Review a backup policy first.")
    result: dict[str, Any] = {"full_time": str(values.get("full_time", "02:00")),
              "retention_mode": str(values.get("retention_mode", "count")),
              "state_change": values.get("state_change", True)}
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", result["full_time"]):
        raise BackupOperationError("Enter a daily full-backup time as HH:MM.")
    if result["retention_mode"] not in {"count", "days"} or not isinstance(result["state_change"], bool):
        raise BackupOperationError("Choose a supported retention mode and state-change setting.")
    for key, default, minimum, maximum in (
        ("retention_value", 14, 1, 365), ("nsx_interval_minutes", 60, 5, 1440),
        ("sddc_most_recent", 10, 1, 600), ("sddc_hourly_days", 2, 0, 14),
        ("sddc_daily_days", 15, 0, 30),
    ):
        try:
            number = int(values.get(key, default))
            if isinstance(values.get(key), bool) or not minimum <= number <= maximum:
                raise ValueError
            result[key] = number
        except (ValueError, TypeError):
            raise BackupOperationError(f"Enter a supported value for {key.replace('_', ' ')}.") from None
    return result


def _state(db: Session, actor: str, operation_id: str) -> tuple[Setting, dict[str, Any]]:
    """Load only an operation owned by this administrator.

    Args:
        db: Session holding operation checkpoints.
        actor: Submitting administrator username.
        operation_id: Opaque identifier from inspection.
    """
    if not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise BackupOperationError("Inspect the backup sources first.")
    row = db.scalar(select(Setting).where(Setting.key == PREFIX + operation_id).execution_options(populate_existing=True))
    if row is None:
        raise BackupOperationError("The backup operation is unavailable.")
    state = json.loads(row.value)
    if state.get("actor") != actor:
        raise BackupOperationError("This operation belongs to another administrator.")
    return row, state


def _revision(state: dict[str, Any]) -> str:
    """Bind immutable discovery and review inputs without hashing plaintext secrets.

    Args:
        state: Public durable operation checkpoint.
    """
    return _digest({key: state.get(key) for key in ("sources", "receiver", "plan", "policy", "selected_ids", "sftp_secret", "encryption_secret")})


def _save(db: Session, row: Setting, state: dict[str, Any]) -> None:
    """Publish a bounded public checkpoint before any external mutation.

    Args:
        db: Database writer holding workflow admission.
        row: Original operation record.
        state: Public state without plaintext credentials or native response bodies.
    """
    text = _json(state)
    if len(text.encode()) > MAX_STATE_BYTES:
        raise BackupOperationError("The selected fleet exceeds the supported operation size.")
    if sa_inspect(row).persistent:
        previous = row.value
        with db.no_autoflush:
            changed = db.execute(update(Setting).where(Setting.id == row.id, Setting.value == previous)
                                 .values(value=text, updated_at=utcnow()).execution_options(synchronize_session=False))
        if not isinstance(changed, CursorResult) or changed.rowcount != 1:
            db.rollback()
            raise BackupOperationError("This operation changed concurrently. Reload its current status.")
        db.expire(row)
    else:
        row.value, row.updated_at = text, utcnow()
        db.add(row)
    db.commit()


def _inventory(value: dict[str, Any], source_id: str) -> dict[str, Any]:
    """Bind adapter capability inventory to stable operation-local component IDs.

    Args:
        value: Adapter's allowlisted public inventory.
        source_id: Immutable connection identifier.
    """
    components, groups = value.get("components"), value.get("groups")
    if not isinstance(components, list) or not isinstance(groups, list) or len(components) > MAX_COMPONENTS:
        raise BackupOperationError("Native inventory is incomplete or too large.")
    ids: set[str] = set()
    rows = []
    group_ids = [str(group.get("id", "")) for group in groups if isinstance(group, dict)]
    if len(group_ids) != len(groups) or len(set(group_ids)) != len(groups) or any(not key for key in group_ids):
        raise BackupOperationError("Native inventory contains missing or duplicate scheduler identities.")
    for component in components:
        native_id = str(component["id"])
        if not native_id or native_id in ids:
            raise BackupOperationError("Native inventory contains missing or duplicate component identities.")
        ids.add(native_id)
        if component.get("supported") is True and str(component.get("group_id", "")) not in group_ids:
            raise BackupOperationError("A supported component has no native scheduler identity.")
        rows.append({**component, "native_id": native_id, "source_id": source_id,
                     "id": "c_" + _digest([source_id, native_id])[:40],
                     "native_group_id": str(component.get("group_id", ""))})
    if not value.get("identity") or not re.fullmatch(r"9\.1(?:\.\d+){0,3}", str(value.get("version", ""))):
        raise BackupOperationError("A verified VCF 9.1 source identity and version are required.")
    return {"identity": str(value["identity"]), "version": str(value["version"]),
            "components": rows, "groups": groups, "coverage_gaps": value.get("coverage_gaps", []),
            "service": value.get("service")}


def operation_status(db: Session, actor: str, operation_id: str) -> dict[str, Any]:
    """Return public inventory, checkpoints, coverage gaps, and verified task progress.

    Args:
        db: Current operation session.
        actor: Owner of the operation.
        operation_id: Opaque discovery identifier.
    """
    _actor(db, actor)
    _, state = _state(db, actor, operation_id)
    result: dict[str, Any] = {key: state[key] for key in ("operation_id", "state", "checkpoint", "job_id", "progress_percent", "error", "coverage_gaps") if key in state}
    result["can_close_without_credentials"] = can_close_without_credentials(state)
    result.update(receiver=state["receiver"], revision=_revision(state),
                  sources=[{key: source[key] for key in ("source_id", "kind", "address", "port", "fingerprint", "fleet_address", "fleet_port", "fleet_fingerprint") if key in source} for source in state["sources"]],
                  components=[component for source in state["sources"] for component in source["inventory"]["components"]])
    result["groups"] = [{key: group[key] for key in ("id", "component_ids", "checkpoint", "artifacts", "native_artifacts") if key in group}
                        for group in state.get("plan", [])]
    for public, source in zip(result["sources"], state["sources"], strict=True):
        reference = source["credential_reference"]
        public["credential_reference"] = {key: reference[key] for key in ("mode", "username", "vault_id", "entry_id", "uri") if key in reference}
        if source["inventory"].get("service"):
            public["service"] = source["inventory"]["service"]
    if state.get("reconciliation"):
        result["reconciliation"] = state["reconciliation"]
    return result


def can_close_without_credentials(state: dict[str, Any]) -> bool:
    """Report whether durable checkpoints prove native dispatch never began."""
    plan = state.get("plan", [])
    return bool(plan) and state.get("checkpoint") in {"reviewed", "queued"} and all(
        group.get("checkpoint") == "reviewed"
        and group.get("configuration_reference") is None
        and group.get("backup_reference") is None
        for group in plan
    )


def _source_inputs(db: Session, state: dict[str, Any], values: dict[str, Any]) -> dict[str, tuple[dict[str, Any], Credentials]]:
    """Re-resolve each selected source without serializing manual credentials.

    Args:
        db: Session holding current Vault references.
        state: Recorded operation and sources.
        values: Request-local credentials supplied for all recorded sources.
    """
    supplied = values.get("sources")
    if not isinstance(supplied, list) or len(supplied) != len(state["sources"]):
        raise BackupOperationError("Supply the exact inspected source connections.")
    mapped: dict[str, tuple[dict[str, Any], Credentials]] = {}
    for source in state["sources"]:
        matches = [item for item in supplied if isinstance(item, dict) and item.get("source_id") == source["source_id"]]
        if len(matches) != 1:
            raise BackupOperationError("A source credential is missing or duplicated.")
        item = matches[0]
        normalized = _source(item, confirmed=True)
        if any(normalized.get(key) != source.get(key) for key in normalized):
            raise BackupOperationError("A source address or confirmed fingerprint changed.")
        mapped[source["source_id"]] = (source, _credentials(db, item, source))
    return mapped


def _native_tasks_terminal(plan: list[dict[str, Any]], reports: list[dict[str, Any]]) -> bool:
    """Require every recorded native task reference to have a terminal readback."""
    for group, report in zip(plan, reports, strict=True):
        for reference_key, status_key in (
            ("configuration_reference", "native_configuration"),
            ("backup_reference", "native_backup"),
        ):
            if group.get(reference_key) is None:
                continue
            status = report.get(status_key)
            if not isinstance(status, dict) or status.get("state") not in {"succeeded", "failed"}:
                return False
    return True


def _current_inventory(native: NativeBackup, source: dict[str, Any]) -> None:
    """Reject native capability/configuration drift from the inspected source.

    Args:
        native: Authenticated pinned native adapter.
        source: Reviewed public inventory snapshot.
    """
    latest = _inventory(native.discover(), source["source_id"])
    if latest != source["inventory"]:
        raise BackupOperationError("Native inventory or backup settings changed. Inspect that source again before reviewing.")


def _review(db: Session, actor: str, row: Setting, state: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    """Produce the exact native configuration changes without performing native writes.

    Args:
        db: Current operation session.
        actor: Submitting administrator.
        row: Original operation record.
        state: Public discovery snapshot.
        values: Policy, key references, and request-local API credentials.
    """
    if state["state"] not in {"draft", "reviewed", "reconciled"}:
        raise BackupOperationError("Reconcile the current task before reviewing another plan.")
    revision = _revision(state)
    if values.get("revision") != revision:
        raise BackupOperationError("Discovery changed; inspect its current revision again.")
    receiver = receiver_revision(require_receiver(db))
    if receiver != state["receiver"]:
        raise BackupOperationError("The applied SFTP receiver changed. Start a fresh inspection.")
    policy = _policy(values.get("policy"))
    sftp_secret = _secret_reference(db, values.get("sftp_secret"))
    encryption_secret = _secret_reference(db, values.get("encryption_secret"))
    selected = values.get("selected_ids")
    if not isinstance(selected, list) or not selected or len(selected) != len(set(selected)):
        raise BackupOperationError("Select the exact native backup components once each.")
    all_components = [component for source in state["sources"] for component in source["inventory"]["components"]]
    known = {component["id"]: component for component in all_components}
    if any(not isinstance(key, str) or key not in known or known[key].get("supported") is not True for key in selected):
        raise BackupOperationError("Select only inspected components with native backup support.")
    inputs = _source_inputs(db, state, values)
    selected_kinds = {
        source["kind"] for source in state["sources"]
        if any(item["source_id"] == source["source_id"] and item["id"] in selected for item in all_components)
    }
    if {"sddc", "nsx"} <= selected_kinds:
        raise BackupOperationError("SDDC Manager also changes its co-managed NSX backup policy. Configure SDDC Manager first, then inspect and review NSX in a fresh operation.")
    plan: list[dict[str, Any]] = []
    seen_assets: set[str] = set()
    gaps: list[Any] = [gap for source in state["sources"] for gap in source["inventory"]["coverage_gaps"]]
    gaps.extend({"component": item["name"], "product": item.get("product"), "reason": item.get("coverage_gap") or "Not selected for native backup."}
                for item in all_components if item["id"] not in selected)
    for source, credentials in inputs.values():
        with NativeBackup(source, credentials) as native:
            native.login()
            _current_inventory(native, source)
            for group in source["inventory"]["groups"]:
                members = [item for item in all_components if item["source_id"] == source["source_id"] and item["native_group_id"] == str(group["id"]) and item["id"] in selected]
                if not members:
                    continue
                eligible = set(group["component_ids"])
                if source["kind"] == "fleet" and {item["native_id"] for item in members} != eligible:
                    raise BackupOperationError("Fleet LCM schedules cover the complete lifecycle-manager group; select every eligible component in that group.")
                service_identity = (source["inventory"].get("service") or {}).get("fingerprint", source["fingerprint"])
                asset = _digest([source["kind"], service_identity, str(group["id"])])
                reservation_assets = [asset, *[_digest(["native", key]) for key in group.get("reservation_keys", [])]]
                if any(key in seen_assets for key in reservation_assets):
                    raise BackupOperationError("The same native scheduler was selected through multiple connections.")
                seen_assets.update(reservation_assets)
                group_receiver = {**receiver, "directory": "/backups/vcf/" + asset[:24]}
                proposed = native.proposed(str(group["id"]), policy, group_receiver)
                plan.append({"id": "g_" + asset[:32], "source_id": source["source_id"], "native_group_id": str(group["id"]),
                             "kind": source["kind"], "component_ids": [item["id"] for item in members],
                             "native_component_ids": [item["native_id"] for item in members],
                             "current": native.current(str(group["id"])), "proposed": proposed,
                             "receiver_directory": group_receiver["directory"], "asset": asset,
                             "reservation_assets": reservation_assets, "side_effects": group.get("side_effects", []),
                             "service": source["inventory"].get("service"),
                             "checkpoint": "reviewed"})
    if not plan:
        raise BackupOperationError("No supported native backup group is selected.")
    acquire_network_objects_write_lock(db)
    db.refresh(row)
    current_state = json.loads(row.value)
    if _revision(current_state) != revision or current_state["state"] not in {"draft", "reviewed", "reconciled"}:
        raise BackupOperationError("This operation changed during review; review its current state.")
    state.update(policy=policy, selected_ids=sorted(selected), plan=plan, coverage_gaps=gaps,
                 sftp_secret=sftp_secret, encryption_secret=encryption_secret,
                 state="reviewed", checkpoint="reviewed", review_nonce=secrets.token_hex(24))
    token = _serializer().dumps({"actor": actor, "operation_id": state["operation_id"],
                                 "revision": _revision(state), "nonce": state["review_nonce"]})
    _save(db, row, state)
    return {"operation_id": state["operation_id"], "revision": _revision(state), "review_token": token, "expires_in": REVIEW_SECONDS,
            "review": {"receiver": receiver, "policy": policy,
                       "components": [{"names": [known[key]["name"] for key in group["component_ids"]], **group} for group in plan],
                       "coverage_gaps": gaps, "secret_labels": {"sftp": sftp_secret["label"], "encryption": encryption_secret["label"]},
                       "warnings": list(dict.fromkeys([warning for item in all_components if item["id"] in selected for warning in item.get("warnings", [])])) +
                                   ["Existing secret values cannot be read back; selected destinations will use the reviewed Vault keys.",
                                    "Native products own schedule execution. Operations schedules use UTC; direct products use their configured appliance time zones.",
                                    "NSX native backups do not enforce a retention limit; arrange and verify external retention."]}}


def _release(db: Session, state: dict[str, Any]) -> None:
    """Release only reservations whose owner is still this exact operation.

    Args:
        db: Current admitted writer.
        state: Operation owning the reservations.
    """
    for key in state.get("reservation_keys", []):
        row = db.scalar(select(Setting).where(Setting.key == key))
        if row is not None and row.value == state["operation_id"]:
            db.delete(row)


def dispatch(db: Session, actor: str, action: str, values: dict[str, Any], background: Dispatcher) -> dict[str, Any]:
    """Admit browser discovery, exact review, one-shot execution, or reconciliation.

    Args:
        db: Request database session.
        actor: Enabled administrator username.
        action: Browser workflow action.
        values: Validated bounded JSON request, possibly with ephemeral credentials.
        background: Request-owned task dispatcher.
    """
    try:
        return _dispatch(db, actor, action, values, background)
    except (ReceiverError, RemoteError) as exc:
        raise BackupOperationError(str(exc)) from None
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, BackupOperationError):
            raise
        raise BackupOperationError("Native backup inputs or capability data are incomplete. Inspect again.") from None


def _dispatch(db: Session, actor: str, action: str, values: dict[str, Any], background: Dispatcher) -> dict[str, Any]:
    """Perform an admitted action with no implicit native write retries.

    Args:
        db: Request database session.
        actor: Submitting administrator.
        action: Requested workflow action.
        values: Request-local workflow data.
        background: One-shot task dispatcher.
    """
    _actor(db, actor)
    if action == "reconcile":
        row, state = _state(db, actor, str(values.get("operation_id", "")))
        return _reconcile(db, actor, row, state, values)
    receiver = receiver_revision(require_receiver(db))
    if action == "probe":
        source = _source(values, confirmed=False)
        targets = []
        for key, address, port in [("server", source["address"], source["port"])]:
            public = PinnedHTTPS(Target(address, port, "0" * 64)).probe()
            targets.append({"key": key, "address": address, "port": port,
                            **{field: public[field] for field in ("sha256", "subject", "issuer")}})
        return {"targets": targets}
    if action == "inspect":
        source = _source(values, confirmed=True)
        source["credential_reference"] = _reference(db, values, source)
        credentials = _credentials(db, values, source)
        operation_id = str(values.get("operation_id") or "")
        if operation_id:
            row, state = _state(db, actor, operation_id)
            if state["state"] not in {"draft", "reviewed", "reconciled"}:
                raise BackupOperationError("Reconcile the existing task before changing its sources.")
            prior_revision = _revision(state)
        else:
            operation_id = uuid4().hex
            state = {"operation_id": operation_id, "actor": actor, "state": "draft", "sources": [], "receiver": receiver,
                     "checkpoint": "inspected", "progress_percent": 0, "coverage_gaps": []}
            row = Setting(key=PREFIX + operation_id, value="")
            prior_revision = ""
        matching = [item for item in state["sources"] if item["kind"] == source["kind"] and item["address"] == source["address"] and item["port"] == source["port"]]
        source_id = matching[0]["source_id"] if matching else uuid4().hex
        with NativeBackup(source, credentials) as native:
            native.login()
            inventory = _inventory(native.discover(), source_id)
        source.update(source_id=source_id, inventory=inventory)
        candidates = [item for item in state["sources"] if item["source_id"] != source_id] + [source]
        if len(candidates) > MAX_SOURCES or sum(len(item["inventory"]["components"]) for item in candidates) > MAX_COMPONENTS:
            raise BackupOperationError("The selected fleet exceeds the supported source/component limit.")
        acquire_network_objects_write_lock(db)
        if prior_revision:
            db.refresh(row)
            latest = json.loads(row.value)
            if _revision(latest) != prior_revision or latest["state"] not in {"draft", "reviewed", "reconciled"}:
                raise BackupOperationError("The operation changed during discovery; inspect its current state.")
        state.update(sources=candidates, state="draft", receiver=receiver, coverage_gaps=[gap for item in candidates for gap in item["inventory"]["coverage_gaps"]])
        state.pop("review_nonce", None)
        for field in ("plan", "selected_ids", "policy", "sftp_secret", "encryption_secret"):
            state.pop(field, None)
        db.add(row)
        _save(db, row, state)
        record_audit(db, actor=actor, action="inspect_vcf_backup", resource_type=JOB_TYPE, resource_id=operation_id)
        return {**operation_status(db, actor, operation_id), "source_id": source_id}
    row, state = _state(db, actor, str(values.get("operation_id", "")))
    if receiver != state["receiver"]:
        raise BackupOperationError("The applied backup receiver changed; reconcile and inspect again.")
    if action == "review":
        return _review(db, actor, row, state, values)
    if action != "execute" or state["state"] != "reviewed":
        raise BackupOperationError("Review the exact current changes before configuring backups.")
    if any(values.get(key) is not True for key in ("acknowledged", "replacements_confirmed", "recovery_ready")):
        raise BackupOperationError("Approve replacements and confirm separate passphrase recovery custody first.")
    inputs = _source_inputs(db, state, values)
    if (_policy(values.get("policy")) != state["policy"] or sorted(values.get("selected_ids", [])) != state["selected_ids"]
        or _secret_reference(db, values.get("sftp_secret")) != state["sftp_secret"]
        or _secret_reference(db, values.get("encryption_secret")) != state["encryption_secret"]):
        raise BackupOperationError("The reviewed policy, selection, or secret references changed.")
    try:
        token = _serializer().loads(str(values.get("review_token", "")), max_age=REVIEW_SECONDS)
    except BadData:
        raise BackupOperationError("The review expired or is invalid. Review again.") from None
    acquire_network_objects_write_lock(db)
    db.refresh(row)
    state = json.loads(row.value)
    if state["state"] != "reviewed" or not state.get("review_nonce") or token != {
        "actor": actor, "operation_id": state["operation_id"], "revision": _revision(state), "nonce": state["review_nonce"],
    }:
        raise BackupOperationError("The review was consumed or this operation changed.")
    reservation_keys = sorted({LOCK_PREFIX + "global", *{LOCK_PREFIX + asset for group in state["plan"] for asset in group.get("reservation_assets", [group["asset"]])}})
    for key in reservation_keys:
        existing = db.scalar(select(Setting).where(Setting.key == key))
        if existing is not None:
            raise BackupOperationError("Another operation reserves this native scheduler; reconcile it first.")
        db.add(Setting(key=key, value=state["operation_id"]))
    job = Job(id="job_" + uuid4().hex[:12], type=JOB_TYPE, created_by=actor, status="pending",
              task_config_json=_json({"operation_id": state["operation_id"]}), result="{}")
    db.add(job)
    for position, component_id in enumerate(state["selected_ids"]):
        component = next(item for source in state["sources"] for item in source["inventory"]["components"] if item["id"] == component_id)
        db.add(JobStep(id=uuid4().hex, job_id=job.id, component_key=component_id,
                       label=str(component["name"])[:160], position=position, status="pending"))
    state.update(state="queued", checkpoint="queued", job_id=job.id, reservation_keys=reservation_keys)
    state.pop("review_nonce", None)
    try:
        _save(db, row, state)
    except IntegrityError:
        db.rollback()
        raise BackupOperationError("Another operation reserved this scheduler during admission.") from None
    # Passwords are retained only by this request's one background invocation.
    manual = {source_id: {"username": credential.username, "password": credential.password}
              for source_id, (source, credential) in inputs.items() if source["credential_reference"]["mode"] == "manual"}
    background.add_task(run_job, job.id, manual)
    return operation_status(db, actor, state["operation_id"])


def _worker_inputs(db: Session, state: dict[str, Any], manual: dict[str, Any]) -> dict[str, Credentials]:
    """Resolve saved credentials anew; require request-local values for manual sources.

    Args:
        db: Current operation session.
        state: Durable source references.
        manual: Request-local credentials passed directly to the admitted worker.
    """
    result = {}
    for source in state["sources"]:
        reference = source["credential_reference"]
        values = manual.get(source["source_id"], {}) if reference["mode"] == "manual" else {
            "credential_vault_id": reference["vault_id"], "credential_entry_id": reference["entry_id"], "credential_uri": reference["uri"],
        }
        result[source["source_id"]] = _credentials(db, values, source)
    return result


def _checkpoint(db: Session, row: Setting, state: dict[str, Any], group: dict[str, Any], checkpoint: str) -> None:
    """Commit each dispatch boundary before sending a native mutation.

    Args:
        db: Current operation writer.
        row: Original operation row.
        state: Secret-free operation state.
        group: Reviewed native scheduler group.
        checkpoint: Last independently known dispatch phase.
    """
    if checkpoint.endswith("dispatch_pending"):
        _actor(db, state["actor"])
        job = db.get(Job, state["job_id"], populate_existing=True)
        if job is None or job.status != "running":
            raise BackupOperationError("This task was stopped. Reconcile native work before retrying.")
        if receiver_revision(require_receiver(db)) != state["receiver"]:
            raise BackupOperationError("The receiver changed before native dispatch.")
        for field in ("sftp_secret", "encryption_secret"):
            if _secret_reference(db, state[field]) != state[field]:
                raise BackupOperationError("A reviewed backup secret changed before native dispatch.")
        for source in state["sources"]:
            reference = source["credential_reference"]
            if reference["mode"] == "vault":
                values = {"credential_vault_id": reference["vault_id"], "credential_entry_id": reference["entry_id"], "credential_uri": reference["uri"]}
                if _reference(db, values, source) != reference:
                    raise BackupOperationError("A reviewed source credential changed before native dispatch.")
    group["checkpoint"] = checkpoint
    state["checkpoint"] = checkpoint
    _save(db, row, state)


def _matches(current: dict[str, Any], proposed: dict[str, Any]) -> bool:
    """Compare native readback only for public configurable policy fields.

    Args:
        current: Native's allowlisted current configuration.
        proposed: Reviewed public configuration, excluding write-only secrets.
    """
    ignored = {"password_configured", "encryption_configured", "password_changed", "encryption_changed",
               "secret_configured", "sftp_secret_configured", "host_key"}
    return all(current.get(key) == value for key, value in proposed.items() if key not in ignored)


def _verified_artifacts(group: dict[str, Any], native_state: dict[str, Any],
                        files: dict[str, tuple[int, int]]) -> dict[str, list[dict[str, Any]]]:
    """Require new receiver files for every selected component's successful native backup.

    Args:
        group: Reviewed scheduler and durable pre-dispatch file metadata.
        native_state: Status for the exact recorded initial backup reference.
        files: Current bounded metadata from the reviewed receiver directory.
    """
    if native_state.get("state") != "succeeded":
        return {}
    before = group.get("artifact_baseline", {})
    fresh = {path: detail for path, detail in files.items()
             if detail[0] > 0 and list(detail) != list(before.get(path, (0, 0)))}
    if not fresh:
        return {}
    root = PurePosixPath(group["receiver_directory"])
    records = native_state.get("artifacts", [])
    verified: dict[str, list[dict[str, Any]]] = {}
    for component in group["native_component_ids"]:
        matching: set[str] = set()
        for record in records:
            if not isinstance(record, dict) or record.get("component_id") != component:
                continue
            path = record.get("path")
            if not isinstance(path, str) or not path or "://" in path or "\\" in path or any(ord(char) < 32 for char in path):
                continue
            candidate = PurePosixPath(path)
            if ".." in candidate.parts:
                continue
            candidate = candidate if candidate.is_absolute() else root / candidate
            if candidate != root and root not in candidate.parents:
                continue
            matching.update(name for name in fresh if PurePosixPath(name) == candidate or candidate in PurePosixPath(name).parents)
        # These direct APIs return a task result without an artifact path. Their
        # one-component scheduler has a separate reviewed receiver directory.
        if not records and group["kind"] in {"sddc", "nsx", "vcenter"} and len(group["native_component_ids"]) == 1:
            matching.update(fresh)
        if not matching:
            return {}
        verified[component] = [{"path": path, "bytes": fresh[path][0], "mtime": fresh[path][1]} for path in sorted(matching)]
    return verified


def _validate_shared_encryption_passphrase(value: str) -> None:
    """Enforce the stricter passphrase policy shared by every native product."""
    if (
        not isinstance(value, str)
        or not 12 <= len(value) <= 20
        or any(not 33 <= ord(char) <= 126 for char in value)
        or not any(char.isupper() for char in value)
        or not any(char.islower() for char in value)
        or sum(char.isdigit() for char in value) < 2
        or not any(not char.isalnum() for char in value)
    ):
        raise BackupOperationError(
            "The backup passphrase must have 12–20 visible ASCII characters, uppercase and lowercase letters, at least two digits, and a symbol."
        )


def _fail_unfinished_steps(job: Job, message: str) -> None:
    """Finish pending work after a job fails without overwriting completed steps."""
    for step in job.steps:
        if step.status in {"pending", "running"}:
            step.status = "failed"
            step.error = message
            step.finished_at = utcnow()


def run_job(job_id: str, manual: dict[str, Any] | None = None) -> None:
    """Configure reviewed native schedulers and verify initial backup artifacts once.

    Args:
        job_id: Admitted durable task.
        manual: Ephemeral remote API credentials, never serialized to jobs or settings.
    """
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None or job.type != JOB_TYPE or job.status != "pending":
            return
        operation_id = json.loads(job.task_config_json)["operation_id"]
        row, state = _state(db, job.created_by, operation_id)
        if state["job_id"] != job_id or state["state"] != "queued":
            return
        job.status, job.started_at = "running", utcnow()
        state["state"] = "running"
        _save(db, row, state)
        try:
            _actor(db, state["actor"])
            receiver = require_receiver(db)
            if receiver_revision(receiver) != state["receiver"]:
                raise BackupOperationError("The receiver changed after review.")
            credentials = _worker_inputs(db, state, manual or {})
            sftp_password, passphrase = _secret(db, state["sftp_secret"]), _secret(db, state["encryption_secret"])
            _validate_shared_encryption_passphrase(passphrase)
            # Native validation checks whether each destination already exists
            # on the receiver, so prepare every reviewed path before preflight.
            with ReceiverSession(receiver, sftp_password) as receiver_preflight:
                for group in state["plan"]:
                    receiver_preflight.prepare(group["receiver_directory"])
            # Recheck the entire plan before the first native write.
            for source in state["sources"]:
                with NativeBackup(source, credentials[source["source_id"]]) as native:
                    native.login()
                    _current_inventory(native, source)
                    for group in state["plan"]:
                        if group["source_id"] == source["source_id"]:
                            validation = native.validate(group["native_group_id"], group["proposed"], sftp_password, passphrase)
                            if validation.get("supported", True) and validation.get("valid") is not True:
                                raise BackupOperationError("Native destination validation did not succeed. Resolve it before configuring backups.")
            with ReceiverSession(receiver, sftp_password) as storage:
                for position, group in enumerate(state["plan"]):
                    source = next(item for item in state["sources"] if item["source_id"] == group["source_id"])
                    if receiver_revision(require_receiver(db)) != state["receiver"]:
                        raise BackupOperationError("The receiver changed during execution. Reconcile before retrying.")
                    storage.prepare(group["receiver_directory"])
                    before = storage.manifest(group["receiver_directory"])
                    group["artifact_baseline"] = before
                    steps = list(db.scalars(select(JobStep).where(JobStep.job_id == job_id, JobStep.component_key.in_(group["component_ids"]))))
                    for step in steps:
                        step.status, step.started_at = "running", utcnow()
                    with NativeBackup(source, credentials[source["source_id"]]) as native:
                        native.login()
                        native.discover()
                        if native.current(group["native_group_id"]) != group["current"]:
                            raise BackupOperationError("Native backup settings changed after preflight. Reconcile before a new review.")
                        _checkpoint(db, row, state, group, "configuration_dispatch_pending")
                        group["configuration_reference"] = native.configure(group["native_group_id"], group["proposed"], sftp_password, passphrase)
                        _checkpoint(db, row, state, group, "configuration_submitted")
                        config_deadline = time.monotonic() + CONFIGURATION_SECONDS
                        while time.monotonic() < config_deadline:
                            configuration = native.configuration_status(group["native_group_id"], group["configuration_reference"])
                            if configuration["state"] == "succeeded":
                                break
                            if configuration["state"] == "failed":
                                raise BackupOperationError("Native configuration failed. Reconcile before retrying.")
                            time.sleep(5)
                        else:
                            raise BackupOperationError("Native configuration remains uncertain after one hour. Reconcile before retrying.")
                        if not _matches(native.current(group["native_group_id"]), group["proposed"]):
                            raise BackupOperationError("Native configuration readback differs from the reviewed changes.")
                        _checkpoint(db, row, state, group, "backup_dispatch_pending")
                        group["backup_reference"] = native.start_backup(group["native_group_id"], group["native_component_ids"])
                        _checkpoint(db, row, state, group, "backup_submitted")
                        deadline = time.monotonic() + BACKUP_SECONDS
                        while time.monotonic() < deadline:
                            _actor(db, state["actor"])
                            native_state = native.backup_status(group["native_group_id"], group["backup_reference"].get("reference", group["backup_reference"]))
                            if native_state["state"] == "failed":
                                raise BackupOperationError("The native initial backup failed. Reconcile this task without repeating it.")
                            if native_state["state"] == "succeeded":
                                files = storage.manifest(group["receiver_directory"])
                                native_artifacts = native_state.get("artifacts", [])
                                verified = _verified_artifacts(group, native_state, files)
                                if verified:
                                    group["verified_components"] = verified
                                    group["artifacts"] = list({item["path"]: item for artifacts in verified.values() for item in artifacts}.values())
                                    group["native_artifacts"] = native_artifacts
                                    break
                            time.sleep(5)
                        else:
                            raise BackupOperationError("Initial backup verification did not finish within one hour. Reconcile before retrying.")
                    group["checkpoint"] = "verified"
                    for step in steps:
                        step.status, step.finished_at, step.progress_percent = "succeeded", utcnow(), 100
                        native_id = group["native_component_ids"][group["component_ids"].index(step.component_key)]
                        step.result = _json({"native_backup_reference": group["backup_reference"], "artifacts": group["verified_components"][native_id], "verified": True})
                    job.progress_percent = int((position + 1) * 100 / len(state["plan"]))
                    state["progress_percent"] = job.progress_percent
                    _save(db, row, state)
            # A later product configuration must not silently invalidate an
            # earlier verified scheduler (including native cross-product effects).
            for group in state["plan"]:
                source = next(item for item in state["sources"] if item["source_id"] == group["source_id"])
                with NativeBackup(source, credentials[source["source_id"]]) as native:
                    native.login()
                    native.discover()
                    if not _matches(native.current(group["native_group_id"]), group["proposed"]):
                        raise BackupOperationError("A configured native policy changed before final verification. Reconcile the operation.")
            state.update(state="succeeded", checkpoint="verified", error="", progress_percent=100)
            job.status, job.progress_percent = "succeeded", 100
            _release(db, state)
        except Exception as exc:  # noqa: BLE001 - retain uncertain native dispatches without automatic retries.
            db.rollback()
            row, state = _state(db, job.created_by, operation_id)
            message = str(exc) if isinstance(exc, (BackupOperationError, ReceiverError, RemoteError)) else "Backup operation interrupted. Reconcile before retrying; native writes may have occurred."
            state.update(state="needs_recovery", error=message)
            job = db.get(Job, job_id)
            if job is not None:
                job.status, job.error = "failed", message
                _fail_unfinished_steps(job, message)
        finally:
            if job is not None:
                job.finished_at = utcnow()
                job.result = _json({"operation_id": operation_id, "state": state["state"],
                                    "coverage_gaps": state["coverage_gaps"], "checkpoint": state["checkpoint"]})
            _save(db, row, state)
            record_audit(db, actor=state["actor"], action="configure_vcf_backup", resource_type=JOB_TYPE,
                         resource_id=job_id, success=state["state"] == "succeeded",
                         detail=_json({"operation_id": operation_id, "checkpoint": state["checkpoint"]}), post_commit_best_effort=True)
            db.commit()


def _reconcile(db: Session, actor: str, row: Setting, state: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    """Read current native state; never replay an uncertain configuration or backup.

    Args:
        db: Current operation session.
        actor: Owner of the operation.
        row: Durable operation record.
        state: Last independently recorded checkpoints.
        values: Re-entered manual credentials or saved references.
    """
    job = db.get(Job, state.get("job_id", ""))
    if job is not None and job.status in {"pending", "running"}:
        return operation_status(db, actor, state["operation_id"])
    original = row.value
    close_reviewed = values.get("close_reviewed") is True and state["state"] != "succeeded"
    plan = state.get("plan", [])
    if close_reviewed and can_close_without_credentials(state):
        # A persisted reviewed checkpoint proves that no native mutation was
        # attempted. Let an authorized actor release reservations even when the
        # reviewed SFTP secret or native credentials can no longer authenticate.
        acquire_network_objects_write_lock(db)
        db.refresh(row)
        latest = json.loads(row.value)
        if row.value != original or latest.get("job_id") != state.get("job_id") or latest["state"] not in {"needs_recovery", "succeeded", "reconciled"}:
            raise BackupOperationError("This operation changed during reconciliation.")
        state["state"], state["checkpoint"] = "reconciled", "closed_without_replay"
        state["reconciliation"] = []
        _release(db, state)
        _save(db, row, state)
        return {**operation_status(db, actor, state["operation_id"]), "reconciliation": [],
                "recovery_warning": "Reconciliation is read-only. Unknown native writes are never repeated; inspect a fresh plan before another configuration attempt."}
    if close_reviewed and any(group.get("checkpoint") in {"configuration_dispatch_pending", "backup_dispatch_pending"}
                              for group in plan):
        raise BackupOperationError("A native dispatch has no recorded outcome. Its reservation must remain held until the native product provides verifiable task reconciliation.")
    inputs = _source_inputs(db, state, values)
    reports: list[dict[str, Any]] = []
    for group in state.get("plan", []):
        source, credential = inputs[group["source_id"]]
        with NativeBackup(source, credential) as native:
            native.login()
            native.discover()
            report = {"group_id": group["id"], "checkpoint": group["checkpoint"], "current": native.current(group["native_group_id"])}
            reference = group.get("backup_reference")
            if reference:
                report["native_backup"] = native.backup_status(group["native_group_id"], reference.get("reference", reference))
            configuration_reference = group.get("configuration_reference")
            if configuration_reference is not None:
                report["native_configuration"] = native.configuration_status(group["native_group_id"], configuration_reference)
            reports.append(report)
    # A matching native completion and independently fresh SFTP metadata can
    # finish an interrupted task, but never dispatch another native operation.
    receiver: dict[str, Any] | None = None
    receiver_warning: str | None = None
    try:
        receiver = require_receiver(db)
        if receiver_revision(receiver) != state["receiver"]:
            receiver = None
            receiver_warning = "The applied receiver changed since review; native status was read, but receiver artifacts are unverified."
    except (ReceiverError, BackupOperationError) as exc:
        receiver_warning = f"The applied receiver is unavailable; native status was read, but receiver artifacts are unverified: {exc}"
    successful_backups = [report for report in reports if report.get("native_backup", {}).get("state") == "succeeded"]
    if successful_backups and receiver is not None:
        try:
            password = _secret(db, state["sftp_secret"])
            with ReceiverSession(receiver, password) as storage:
                for group, report in zip(plan, reports, strict=True):
                    if report.get("native_backup", {}).get("state") == "succeeded":
                        verified = _verified_artifacts(group, report["native_backup"], storage.manifest(group["receiver_directory"]))
                        if verified and _matches(report["current"], group["proposed"]):
                            group["verified_components"] = verified
                            group["checkpoint"] = "verified"
                            group["artifacts"] = list({item["path"]: item for artifacts in verified.values() for item in artifacts}.values())
                            group["native_artifacts"] = report["native_backup"].get("artifacts", [])
                            report["verified"] = True
                            report["artifacts"] = group["artifacts"]
                        else:
                            report["verified"] = False
                            report["warning"] = (
                                "Initial artifacts exist, but the native policy no longer matches the reviewed configuration."
                                if verified else "Native backup succeeded, but fresh receiver artifacts could not be verified."
                            )
        except (ReceiverError, BackupOperationError) as exc:
            receiver_warning = f"Native status was read, but receiver artifacts could not be verified: {exc}"
    if receiver_warning:
        for report in successful_backups:
            report["verified"] = False
            report["warning"] = receiver_warning
    acquire_network_objects_write_lock(db)
    db.refresh(row)
    latest = json.loads(row.value)
    if row.value != original or latest.get("job_id") != state.get("job_id") or latest["state"] not in {"needs_recovery", "succeeded", "reconciled"}:
        raise BackupOperationError("This operation changed during reconciliation.")
    state["reconciliation"] = reports
    if reports and all(report.get("verified") for report in reports):
        state.update(state="succeeded", checkpoint="verified", progress_percent=100, error="")
        if job is not None:
            job.status, job.progress_percent, job.finished_at, job.error = "succeeded", 100, utcnow(), ""
            job.result = _json({"operation_id": state["operation_id"], "state": "succeeded", "checkpoint": "verified",
                                "coverage_gaps": state["coverage_gaps"]})
            for step in job.steps:
                group = next(item for item in state["plan"] if step.component_key in item["component_ids"])
                native_id = group["native_component_ids"][group["component_ids"].index(step.component_key)]
                step.status, step.finished_at, step.progress_percent, step.error = "succeeded", utcnow(), 100, ""
                step.result = _json({"artifacts": group["verified_components"][native_id], "verified": True})
        _release(db, state)
    # Explicit closure releases reservations but never calls a native write or
    # claims that an uncertain dispatch succeeded. A new plan needs fresh inspect.
    if values.get("close_reviewed") is True and state["state"] != "succeeded":
        if not _native_tasks_terminal(plan, reports):
            raise BackupOperationError("A native task is still running or its outcome is unknown; wait for a verified terminal state before closing recovery.")
        state["state"], state["checkpoint"] = "reconciled", "closed_without_replay"
        _release(db, state)
    _save(db, row, state)
    return {**operation_status(db, actor, state["operation_id"]), "reconciliation": reports,
            "recovery_warning": receiver_warning or "Reconciliation is read-only. Unknown native writes are never repeated; inspect a fresh plan before another configuration attempt."}


def recover_interrupted_jobs(db: Session) -> int:
    """Mark interrupted tasks for read-only recovery without releasing reservations.

    Args:
        db: Startup database session.
    """
    count = 0
    for job in db.scalars(select(Job).where(Job.type == JOB_TYPE, Job.status.in_(["pending", "running"]))):
        operation_id = json.loads(job.task_config_json).get("operation_id", "")
        row = db.scalar(select(Setting).where(Setting.key == PREFIX + operation_id))
        if row is None:
            continue
        state = json.loads(row.value)
        state.update(state="needs_recovery", error="Atlaso restarted. Reconcile recorded native work before retrying.")
        row.value = _json(state)
        job.status, job.error, job.finished_at = "failed", state["error"], utcnow()
        _fail_unfinished_steps(job, state["error"])
        count += 1
    db.commit()
    return count
