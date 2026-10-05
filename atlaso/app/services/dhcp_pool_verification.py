"""Queue bounded, report-only observations of applied DHCP pools."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.models import (
    AuditEvent,
    DhcpReservation,
    DhcpScope,
    Job,
    JobStatus,
    Schedule,
    Setting,
    utcnow,
)
from atlaso.app.services import task_cancellation
from atlaso.app.services.dnsmasq import (
    DHCP_POOL_METADATA_PREFIX,
    DNSMASQ_AUTHORITATIVE_CONFIG_PREFIX,
    dhcp_pool_metadata,
)
from atlaso.app.services.network_objects import acquire_network_objects_write_lock

JOB_TYPE = "dhcp-pool-verify"
MAX_ADDRESSES = 1024
MAX_RUN_SECONDS = 600
MIN_INTERVAL_SECONDS = 900
BASELINES_KEY = "appliance_apply.baselines.v1"
REPORT_PREFIX = "dhcp.pool_verification."


def forget_scope(db: Session, scope_id: int) -> None:
    """Remove deleted scope evidence in the caller's scope-deletion transaction.

    Args:
        db: Caller-owned scope-deletion transaction.
        scope_id: Scope being removed.
    """
    acquire_network_objects_write_lock(db)
    stored = db.scalar(select(Setting).where(Setting.key == REPORT_PREFIX + str(scope_id)))
    if stored is not None:
        db.delete(stored)
    for schedule in db.scalars(select(Schedule).where(Schedule.task_type == "dhcp_pool_verify")):
        config = object_json(schedule.task_config_json)
        if config.get("scope_id") == scope_id:
            schedule.enabled = False
            schedule.next_run_at = None
            config.pop("scope_id")
            schedule.task_config_json = json.dumps(config, sort_keys=True)
            schedule.updated_at = utcnow()


def require_report_owner(db: Session, scope_id: int, job_id: str) -> None:
    """Reject a worker whose scope report was deleted or replaced.

    Args:
        db: Current publication transaction.
        scope_id: Original scope ID.
        job_id: Original admitted verifier job.
    """
    stored = db.scalar(select(Setting).where(Setting.key == REPORT_PREFIX + str(scope_id)))
    if object_json(stored.value if stored else None).get("job_id") != job_id:
        raise ValueError("Pool verification ownership changed; old result was not published.")


def object_json(raw: str | None) -> dict[str, Any]:
    """Read bounded internal JSON without adopting malformed state.

    Args:
        raw: Persisted JSON object.
    """
    try:
        value = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def applied_preview(db: Session) -> str:
    """Read the last applied dnsmasq configuration, including every pool identity.

    Args:
        db: Read transaction.
    """
    row = db.scalar(select(Setting).where(Setting.key == BASELINES_KEY).execution_options(populate_existing=True))
    baseline = object_json(row.value if row else None).get("dnsmasq", {})
    preview = str(baseline.get("config_preview", "")) if isinstance(baseline, dict) else ""
    return preview


def applied_pool(db: Session, scope_id: int) -> tuple[dict[str, Any], str]:
    """Bind one current pool to its last successfully applied configuration.

    Args:
        db: Read transaction.
        scope_id: Existing managed pool ID.
    """
    scope = db.get(DhcpScope, scope_id, populate_existing=True)
    if scope is None or not scope.enabled or scope.address_family != "ipv4":
        raise ValueError("Choose an enabled IPv4 pool; IPv6 pools are not swept.")
    preview = applied_preview(db)
    current = dhcp_pool_metadata(scope, list(db.scalars(select(DhcpReservation))))
    for line in preview.splitlines():
        if not line.startswith(DHCP_POOL_METADATA_PREFIX):
            continue
        saved = object_json(line[len(DHCP_POOL_METADATA_PREFIX):])
        if saved.get("scope_id") == scope_id:
            if saved != current:
                raise ValueError("Pool or reservations changed; submit DNS/DHCP through Appliance Apply before verification.")
            main_lines = [item for item in preview.splitlines() if not item.startswith(DNSMASQ_AUTHORITATIVE_CONFIG_PREFIX)]
            installed = "\n".join(main_lines).rstrip() + "\n"
            return saved, hashlib.sha256(installed.encode()).hexdigest()
    raise ValueError("No applied pool identity recorded; submit DNS/DHCP through Appliance Apply before verification.")


def enqueue(
    db: Session, *, scope_id: int, actor: str, schedule_id: int | None = None,
    trigger: str = "manual", planned_for: datetime | None = None,
) -> Job:
    """Admit one verifier globally and rate-limit each pool; caller commits.

    Args:
        db: Caller-owned transaction.
        scope_id: Managed IPv4 pool.
        actor: Authorized caller or scheduler identity.
        schedule_id: Optional existing schedule owner.
        trigger: Manual or scheduled submission origin.
        planned_for: Scheduled run time when present.
    """
    if type(scope_id) is not int or scope_id < 1:
        raise ValueError("Choose a positive managed pool ID.")
    acquire_network_objects_write_lock(db)
    pool, digest = applied_pool(db, scope_id)
    active = db.scalar(select(Job.id).where(Job.type == JOB_TYPE, Job.status.in_(task_cancellation.ACTIVE)).limit(1))
    if active:
        raise ValueError(f"Pool verification already active in task {active}.")
    recent = list(db.scalars(select(Job).where(
        Job.type == JOB_TYPE, Job.status != JobStatus.SKIPPED.value, Job.created_at >= utcnow() - timedelta(seconds=MIN_INTERVAL_SECONDS)
    )))
    if any(object_json(job.task_config_json).get("scope_id") == scope_id for job in recent):
        raise ValueError("Wait 15 minutes between verification runs of the same pool.")
    job = Job(
        id=f"job_{uuid4().hex[:12]}", type=JOB_TYPE, status=JobStatus.PENDING.value,
        created_by=actor, schedule_id=schedule_id, trigger=trigger, planned_for=planned_for,
        progress_percent=0,
        task_config_json=json.dumps({"scope_id": scope_id, "config_hash": digest, "pool": pool}),
        result=json.dumps({"state": "queued", "scope_id": scope_id, "observations": []}),
    )
    db.add(job)
    db.flush()
    stored = db.scalar(select(Setting).where(Setting.key == REPORT_PREFIX + str(scope_id)))
    report = object_json(stored.value if stored else None)
    if report.get("config_hash") != digest:
        report = {"observations": []}
    report.update(config_hash=digest, job_id=job.id, state="pending", reason="Report-only verification queued.")
    if stored is None:
        db.add(Setting(key=REPORT_PREFIX + str(scope_id), value=json.dumps(report)))
    else:
        stored.value = json.dumps(report)
    db.add(AuditEvent(actor=actor, action="verify_dhcp_pool", resource_type="job", resource_id=job.id,
                      detail=f"scope_id={scope_id}; interface={pool['interface_name']}; report_only=true"))
    return job


def _lease_identity(leases: list[dict[str, Any]], address: str, now: datetime) -> tuple[list[str], list[str]]:
    """Discard expired leases and preserve available client identifiers.

    Args:
        leases: Bounded helper snapshot.
        address: Candidate address.
        now: Observation timestamp.
    """
    active = [row for row in leases if row.get("ip_address") == address and (
        int(row.get("expires_epoch", 0)) == 0 or int(row.get("expires_epoch", 0)) > now.timestamp()
    )]
    macs = sorted({str(row.get("mac_address", "")).lower() for row in active} - {"", "*"})
    clients = sorted({str(row.get("client_id", "")) for row in active} - {"", "*"})
    return macs, clients


def classify(
    observation: dict[str, Any], pool: dict[str, Any], before: list[dict[str, Any]],
    after: list[dict[str, Any]], observed_at: str, *, lease_attribution_unknown: bool = False,
) -> dict[str, Any]:
    """Separate fresh occupancy evidence from availability and identity claims.

    Args:
        observation: Fresh bounded interface observation.
        pool: Applied pool identity.
        before: Lease snapshot immediately before probes.
        after: Lease snapshot immediately after probes.
        observed_at: Helper UTC observation timestamp.
        lease_attribution_unknown: Unscoped lease could belong to another overlapping link.
    """
    address = str(observation["ip_address"])
    now = datetime.fromisoformat(observed_at).astimezone(timezone.utc)
    expected, clients = _lease_identity(after, address, now)
    previous_expected, previous_clients = _lease_identity(before, address, now)
    reserved = sorted({str(row["mac_address"]).lower() for row in pool.get("reservations", [])
                       if row["ip_address"] == address})
    observed = sorted(set(observation.get("mac_addresses", [])))
    state = "unknown"
    reason = "Observation incomplete; availability and identity are unknown."
    if lease_attribution_unknown:
        reason = "Lease file has no interface attribution for overlapping pools; identity is unknown."
    elif (expected, clients) != (previous_expected, previous_clients):
        reason = "Lease changed during observation; retry before classifying identity."
    elif observation.get("status") == "no_response":
        state, reason = "no_response", "No response observed; this does not prove availability or resolve an earlier finding."
    elif observation.get("status") == "response":
        identities = set(expected + reserved)
        if len(observed) > 1:
            state, reason = "confirmed_conflict", "Multiple MAC addresses replied for this IP on the selected link; proxy ARP remains possible."
        elif not observed:
            reason = "Response did not include a usable hardware identity."
        elif not identities:
            state, reason = "unexpected_occupancy", "Fresh ARP response without a matching active lease or reservation; static or proxy use may be legitimate."
        elif not set(observed).issubset(identities):
            state, reason = "occupant_lease_mismatch", "Observed MAC differs from the current lease/reservation; investigate static use, client identity, or proxy ARP."
        elif expected and reserved and set(expected) != set(reserved):
            state, reason = "occupant_lease_mismatch", "Active lease and declared reservation identities disagree."
        else:
            state, reason = "legitimate_use", "Observed MAC matches the active lease or declared reservation; ARP is evidence of this link only."
    return {
        "ip_address": address, "status": state, "reason": reason,
        "observed_mac_addresses": observed, "expected_mac_addresses": sorted(set(expected + reserved)),
        "expected_client_ids": clients, "first_seen": observed_at, "last_seen": observed_at,
        "verified_at": observed_at, "unresolved": state in FINDINGS,
        "previous_status": None, "resolved_at": None,
    }


FINDINGS = {"unexpected_occupancy", "occupant_lease_mismatch", "confirmed_conflict"}


def retain_history(current: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any]:
    """Resolve a finding only with positive matching identity evidence.

    Args:
        current: New address classification.
        previous: Last report for the same applied pool and address.
    """
    if not previous:
        return current
    current["first_seen"] = previous.get("first_seen", current["first_seen"])
    if not previous.get("unresolved") and current["status"] not in FINDINGS:
        current["previous_status"] = previous.get("previous_status")
        current["resolved_at"] = previous.get("resolved_at")
    if previous.get("unresolved"):
        current["previous_status"] = previous.get("previous_status") or previous["status"]
        if current["status"] == "legitimate_use":
            current["resolved_at"] = current["verified_at"]
        else:
            current["unresolved"] = True
            if current["status"] not in FINDINGS:
                current["last_seen"] = previous["last_seen"]
    return current


def status(db: Session, scope_id: int) -> dict[str, Any]:
    """Project current progress and invalidate edited/deleted/applied identities.

    Args:
        db: Read transaction.
        scope_id: Existing pool ID.
    """
    scope = db.get(DhcpScope, scope_id)
    if scope is None:
        raise ValueError("Pool no longer exists.")
    row = db.scalar(select(Setting).where(Setting.key == REPORT_PREFIX + str(scope_id)))
    report = object_json(row.value if row else None)
    result: dict[str, Any] = {
        "scope_id": scope_id, "name": scope.name, "interface_name": scope.interface_name,
        "state": "not_recorded", "reason": "No verification recorded.", "job_id": None,
        "progress_percent": 0, "config_hash": None, "verified_at": None,
        "dnsmasq_version": None, "observations": [], "unresolved_count": 0,
    }
    try:
        _pool, digest = applied_pool(db, scope_id)
    except ValueError as exc:
        result.update(state="unknown", reason=str(exc))
        return result
    latest = db.get(Job, report["job_id"]) if report.get("job_id") else None
    if report.get("config_hash") == digest:
        result.update(report)
    if latest and object_json(latest.task_config_json).get("config_hash") == digest:
        result.update(job_id=latest.id, progress_percent=latest.progress_percent)
        if latest.status in task_cancellation.ACTIVE:
            result.update(state=latest.status, reason="Report-only verification in progress; previous evidence is retained.")
        elif latest.status in {JobStatus.FAILED.value, JobStatus.CANCELLED.value}:
            result.update(state="unknown" if latest.status == JobStatus.FAILED.value else "cancelled",
                          reason="Latest verification did not complete; retained evidence may be stale. See Tasks.")
    result["unresolved_count"] = sum(bool(item.get("unresolved")) for item in result["observations"])
    return result


def run(job_id: str) -> None:
    """Observe chunks without holding database locks or changing DHCP service.

    Args:
        job_id: Claimed durable worker task.
    """
    from atlaso.app.database import SessionLocal

    deadline = time.monotonic() + MAX_RUN_SECONDS
    offset = 0
    observations: list[dict[str, Any]] = []
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None:
            return
        config = object_json(job.task_config_json)
        scope_id = int(config["scope_id"])
        digest = str(config["config_hash"])
        require_report_owner(db, scope_id, job_id)
        previous = status(db, scope_id)
    state, reason = "complete", "Bounded verification completed; nonresponse is not proof of availability."
    version: str | None = None
    link_identity: str | None = None
    expected_total: int | None = None
    verified_at: str | None = None
    while time.monotonic() < deadline:
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if job is None or job.status not in task_cancellation.ACTIVE:
                return
            require_report_owner(db, scope_id, job_id)
            if job.cancel_requested_at is not None:
                state, reason = "cancelled", "Stopped at a bounded observation checkpoint; partial report retained."
                break
            pool, current_digest = applied_pool(db, scope_id)
            if current_digest != digest:
                raise ValueError("Applied configuration changed during verification; old result was not published.")
            # dnsmasq's lease file cannot attribute duplicate IPv4 ranges to links.
            from ipaddress import ip_address

            overlapping = [
                object_json(line[len(DHCP_POOL_METADATA_PREFIX):])
                for line in applied_preview(db).splitlines() if line.startswith(DHCP_POOL_METADATA_PREFIX)
            ]
        reply = SystemAdapter().verify_dhcp_pool(scope_id, offset, digest)
        data = object_json(reply.stdout)
        if reply.returncode or data.get("status") != "complete" or data.get("config_hash") != digest or data.get("scope") != pool:
            state, reason = "partial" if observations else "unknown", str(data.get("reason") or "Pool observation unavailable; no availability conclusion can be made.")
            break
        total = data.get("total")
        observed_link = data.get("link_identity_hash")
        if not isinstance(observed_link, str) or len(observed_link) != 64 or (link_identity is not None and link_identity != observed_link):
            state, reason = "partial" if observations else "unknown", "Pool link identity changed or is unavailable; verification is incomplete."
            break
        link_identity = observed_link
        chunk = data.get("observations", [])
        if type(total) is not int or not 0 < total <= MAX_ADDRESSES or not isinstance(chunk, list) or not 0 < len(chunk) <= 16:
            raise ValueError("Invalid bounded observation response.")
        next_offset = data.get("next_offset")
        if data.get("offset") != offset or offset + len(chunk) > total or (expected_total is not None and total != expected_total):
            raise ValueError("Pool observation identity or size changed.")
        if (next_offset is None and offset + len(chunk) != total) or (next_offset is not None and (
            type(next_offset) is not int or next_offset != offset + len(chunk) or next_offset >= total
        )):
            raise ValueError("Invalid pool observation cursor.")
        seen_addresses = {item["ip_address"] for item in observations}
        reserved_addresses = {item["ip_address"] for item in pool["reservations"]}
        for item in chunk:
            candidate = str(item["ip_address"])
            address_value = int(ip_address(candidate))
            in_range = any(int(ip_address(start)) <= address_value <= int(ip_address(end)) for start, end in pool["ranges"])
            if candidate in seen_addresses or candidate == pool["site_address"] or not (in_range or candidate in reserved_addresses):
                raise ValueError("Observation is duplicate or outside the applied pool.")
            seen_addresses.add(candidate)
        expected_total = total
        verified_at = str(data["observed_at"])
        version = str(data.get("dnsmasq_version") or "Unknown")[:200]
        old_rows = {row["ip_address"]: row for row in previous.get("observations", [])}
        for row in chunk:
            address = int(ip_address(row["ip_address"]))
            ambiguous = any(other["interface_name"] != pool["interface_name"] and (any(
                int(ip_address(start)) <= address <= int(ip_address(end)) for start, end in other["ranges"]
            ) or any(int(ip_address(item["ip_address"])) == address for item in other["reservations"])) for other in overlapping)
            current = classify(row, pool, data["leases_before"], data["leases_after"], verified_at,
                               lease_attribution_unknown=ambiguous)
            observations.append(retain_history(current, old_rows.get(current["ip_address"])))
        with SessionLocal() as db:
            acquire_network_objects_write_lock(db)
            job = db.get(Job, job_id)
            if job is None:
                return
            require_report_owner(db, scope_id, job_id)
            _current_pool, current_digest = applied_pool(db, scope_id)
            if current_digest != digest:
                raise ValueError("Applied pool changed; partial result was not published.")
            job.progress_percent = min(99, int(len(observations) / total * 100))
            job.result = json.dumps({"state": "running", "scope_id": scope_id, "checked": len(observations), "total": total})
            partial_rows = observations + [dict(row, status="unknown", reason="Not yet checked in this run; retained evidence may be stale.")
                for row in previous.get("observations", []) if row["ip_address"] not in {item["ip_address"] for item in observations}]
            partial = {"state": "running", "reason": "Bounded verification in progress; unchecked evidence remains unknown.",
                       "config_hash": digest, "job_id": job_id, "verified_at": verified_at,
                       "dnsmasq_version": version, "observations": partial_rows}
            stored = db.scalar(select(Setting).where(Setting.key == REPORT_PREFIX + str(scope_id)))
            if stored is None:
                db.add(Setting(key=REPORT_PREFIX + str(scope_id), value=json.dumps(partial)))
            else:
                stored.value = json.dumps(partial)
            db.commit()
        if next_offset is None:
            break
        offset = next_offset
    else:
        state, reason = "partial", "Verification time limit reached; partial report retained."
    with SessionLocal() as db:
        acquire_network_objects_write_lock(db)
        job = db.get(Job, job_id, populate_existing=True)
        if job is None:
            return
        require_report_owner(db, scope_id, job_id)
        _pool, current_digest = applied_pool(db, scope_id)
        if current_digest != digest:
            raise ValueError("Applied configuration changed; old result was not published.")
        if job.cancel_requested_at is not None:
            state, reason = "cancelled", "Cancellation acknowledged; partial report retained."
        if state != "complete":
            seen = {item["ip_address"] for item in observations}
            observations.extend(dict(row, status="unknown", reason="Not checked in the completed portion; retained finding is unresolved.")
                                for row in previous.get("observations", []) if row["ip_address"] not in seen)
        report = {
            "state": state, "reason": reason, "config_hash": digest, "job_id": job_id,
            "verified_at": verified_at, "dnsmasq_version": version, "observations": observations,
        }
        stored = db.scalar(select(Setting).where(Setting.key == REPORT_PREFIX + str(scope_id)))
        if stored is None:
            stored = Setting(key=REPORT_PREFIX + str(scope_id), value=json.dumps(report))
            db.add(stored)
        else:
            stored.value = json.dumps(report)
        job.result = json.dumps(report)
        if state == "cancelled":
            task_cancellation.finish_stop(db, job, detail="No active probe remains; helper chunk completed and socket closed.")
        else:
            job.status = JobStatus.SUCCEEDED.value
            job.finished_at = utcnow()
            job.progress_percent = 100
        db.commit()
