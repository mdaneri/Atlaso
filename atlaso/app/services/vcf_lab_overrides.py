"""Version-gated VCF property reviews, bounded SSH execution, and durable tasks."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import paramiko  # type: ignore[import-untyped]  # Paramiko has no bundled typing stubs.
from itsdangerous import BadData, URLSafeTimedSerializer
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal
from atlaso.app.models import Job, JobStatus, Setting, User, VaultEntry, utcnow
from atlaso.app.secrets import decrypt_secret
from atlaso.app.security import user_roles
from atlaso.app.services import vcf_lab_remote
from atlaso.app.services.remote_ssh import (
    probe_remote_ssh_host,
    remote_entry_target,
    ssh_fingerprint,
)
from atlaso.app.services.vaults import vault_entry_uris
from atlaso.app.services.vcf_depot_target import VcfDepotApiClient
from atlaso.app.services.vcf_sddc_deployment import tls_sha256_fingerprint

JOB_TYPE = "vcf-lab-overrides"
CATALOG = (
    {
        "id": "esa",
        "label": "Allow non-HCL vSAN ESA devices",
        "key": vcf_lab_remote.KEYS["esa"],
        "value": "true",
    },
    {
        "id": "nic",
        "label": "Disable 10GbE physical NIC validation",
        "key": vcf_lab_remote.KEYS["nic"],
        "value": "false",
    },
)
WARNING = (
    "Lab / PoC / non-production only. Property management does not certify hardware or "
    "prove a VCF validation was bypassed. VCF 9.1.1 and later provide native ESA handling; "
    "this explicit legacy property edit does not replace that workflow."
)


def supported_catalog(role: str, version: str) -> tuple[dict[str, str], ...]:
    """Select the explicit property-management contract for supported targets."""
    if role not in {"VcfInstaller", "SddcManager"}:
        raise LabOverrideError(
            "Only VCF Installer and SDDC Manager targets are eligible."
        )
    if not re.fullmatch(r"9\.[01]\.\d+(?:\.\d+)*(?:[-+]\d+)?", version):
        raise LabOverrideError(
            "Only detected VCF 9.0.x and 9.1.x releases are eligible."
        )
    return CATALOG


class LabOverrideError(ValueError):
    """A safe operator-facing refusal, containing no remote output."""


@dataclass(frozen=True)
class Target:
    """Credential-free target identity bound into a signed review."""

    host: str
    api_port: int
    ssh_port: int
    api_entry_id: int
    api_uri_index: int
    ssh_entry_id: int
    ssh_uri_index: int

    def fields(self) -> dict[str, Any]:
        """Return stable review input fields."""
        return dict(self.__dict__)


def target_from_values(db: Session, values: dict[str, Any]) -> Target:
    """Resolve matching API/SSH endpoints from existing encrypted Vault entries."""
    try:
        api_id, ssh_id = int(values["api_entry_id"]), int(values["ssh_entry_id"])
        api_index, ssh_index = (
            int(values["api_uri_index"]),
            int(values["ssh_uri_index"]),
        )
        api_entry, ssh_entry = db.get(VaultEntry, api_id), db.get(VaultEntry, ssh_id)
        if api_entry is None or ssh_entry is None:
            raise ValueError
        uris = vault_entry_uris(api_entry)
        if not 1 <= api_index <= len(uris) or not api_entry.username:
            raise ValueError
        api_uri = urlsplit(uris[api_index - 1])
        if (
            api_uri.scheme not in {"http", "https"}
            or not api_uri.hostname
            or api_uri.username
            or api_uri.password
        ):
            raise ValueError
        host, ssh_port, _ = remote_entry_target(ssh_entry, ssh_index)
        if host.lower().rstrip(".") != api_uri.hostname.lower().rstrip("."):
            raise LabOverrideError(
                "API and SSH credentials must identify the same hostname or IP."
            )
        # The API always uses TLS. An HTTP URI contributes its hostname only.
        api_port = (api_uri.port or 443) if api_uri.scheme == "https" else 443
        return Target(
            host.lower().rstrip("."),
            api_port,
            ssh_port,
            api_id,
            api_index,
            ssh_id,
            ssh_index,
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, LabOverrideError):
            raise
        raise LabOverrideError(
            "Choose valid API and SSH Vault credentials for the target."
        ) from None


def _entry(db: Session, identifier: int) -> VaultEntry:
    """Require a current credential record at every use."""
    entry = db.get(VaultEntry, identifier)
    if entry is None or not entry.username:
        raise LabOverrideError("A selected credential is no longer available.")
    return entry


def probe(target: Target) -> dict[str, str]:
    """Return unauthenticated TLS and SSH fingerprints for explicit confirmation."""
    try:
        ssh = probe_remote_ssh_host(target.host, target.ssh_port)
    except Exception as exc:
        raise LabOverrideError("Could not probe the target SSH host key.") from exc
    try:
        tls = tls_sha256_fingerprint(target.host, target.api_port)
    except Exception:  # noqa: BLE001 - pinned SSH recovery remains available when TLS is down.
        tls = ""
    return {"target": target.host, "tls_fingerprint": tls, "ssh_fingerprint": ssh}


def appliance_info(db: Session, target: Target, fingerprint: str) -> dict[str, str]:
    """Authenticate only after certificate pinning and gate exact version families."""
    if not fingerprint:
        raise LabOverrideError("Confirm the TLS fingerprint before authentication.")
    entry = _entry(db, target.api_entry_id)
    try:
        with VcfDepotApiClient(
            target.host,
            entry.username,
            decrypt_secret(entry.encrypted_value),
            port=target.api_port,
            expected_fingerprint=fingerprint,
        ) as api:
            info = api.appliance_info()
        supported_catalog(info["role"], info["version"])
        return info
    except LabOverrideError:
        raise
    except Exception as exc:
        raise LabOverrideError(
            "Could not verify VCF role/version using the confirmed API endpoint."
        ) from exc


def remote(
    db: Session, target: Target, fingerprint: str, request: dict[str, Any]
) -> dict[str, Any]:
    """Execute the fixed editor over pinned SSH with bounded input/output/time."""
    if not fingerprint:
        raise LabOverrideError("Confirm the SSH host key before authentication.")
    entry = _entry(db, target.ssh_entry_id)
    transport: paramiko.Transport | None = None
    try:
        sock = socket.create_connection((target.host, target.ssh_port), timeout=10)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=10)
        if ssh_fingerprint(transport.get_remote_server_key()) != fingerprint:
            raise LabOverrideError("SSH host key changed after confirmation.")
        transport.auth_password(entry.username, decrypt_secret(entry.encrypted_value))
        source = base64.b64encode(Path(vcf_lab_remote.__file__).read_bytes()).decode(
            "ascii"
        )
        program = f"import base64;exec(compile(base64.b64decode('{source}'),'<atlaso-vcf-lab>','exec'))"
        command = (
            ("" if entry.username == "root" else "sudo -n -- ")
            + "python3 -c "
            + shlex.quote(program)
        )
        channel = transport.open_session(timeout=10)
        channel.settimeout(10)
        channel.exec_command(command)
        channel.sendall(json.dumps(request).encode() + b"\n")
        channel.shutdown_write()
        output = bytearray()
        total = 0
        deadline = time.monotonic() + 330
        while time.monotonic() < deadline:
            if channel.recv_ready():
                data = channel.recv(8192)
                total += len(data)
                output.extend(data)
            if channel.recv_stderr_ready():
                total += len(channel.recv_stderr(8192))
            if total > 16384:
                raise LabOverrideError(
                    "Remote output exceeded its safe bound; inspect target state."
                )
            if (
                channel.exit_status_ready()
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                if channel.recv_exit_status() != 0:
                    raise LabOverrideError(
                        "Remote editor could not run. Check SSH privileges and Python 3 availability."
                    )
                payload = json.loads(output)
                if not isinstance(payload, dict):
                    raise ValueError
                return payload
            time.sleep(0.05)
        raise LabOverrideError(
            "Remote operation timed out; changes may have occurred. Inspect before recovery."
        )
    except LabOverrideError:
        raise
    except Exception as exc:
        raise LabOverrideError(
            "SSH operation failed; inspect target state before retrying."
        ) from exc
    finally:
        if transport is not None:
            transport.close()


def inspect_target(db: Session, target: Target, tls: str, ssh: str) -> dict[str, Any]:
    """Return only bounded boolean state and verified appliance identity."""
    info = appliance_info(db, target, tls)
    return {**inspect_properties(db, target, ssh), **info}


def inspect_properties(db: Session, target: Target, ssh: str) -> dict[str, Any]:
    """Inspect pinned SSH state independently of domainmanager API readiness."""
    state = remote(db, target, ssh, {"action": "inspect"})
    if state.get("ok") is not True:
        raise LabOverrideError(
            "Could not inspect the fixed property file. Check privileges, file integrity and service availability."
        )
    observed = state.get("values")
    if (
        not isinstance(observed, dict)
        or set(observed) != set(vcf_lab_remote.KEYS)
        or any(value not in {None, "true", "false"} for value in observed.values())
    ):
        raise LabOverrideError("Remote property state is ambiguous.")
    revision = state.get("revision")
    if not isinstance(revision, str) or not re.fullmatch("[0-9a-f]{64}", revision):
        raise LabOverrideError("Remote configuration revision is unavailable.")
    return {
        "target": target.host,
        "values": observed,
        "revision": revision,
        "service_active": state.get("service_active") is True,
        "warning": WARNING,
    }


def _signer() -> URLSafeTimedSerializer:
    """Bind review tokens to the appliance secret and this workflow only."""
    return URLSafeTimedSerializer(get_settings().secret_key, salt="vcf-lab-review-v1")


def review(
    db: Session, actor: str, target: Target, values: dict[str, Any]
) -> dict[str, Any]:
    """Capture a signed ten-minute plan, including previous/default values."""
    if values.get("confirmed") is not True:
        raise LabOverrideError(
            "Confirm both fingerprints out of band before inspecting the target."
        )
    tls, ssh = (
        str(values.get("tls_fingerprint", "")),
        str(values.get("ssh_fingerprint", "")),
    )
    source_id = values.get("source_job_id")
    if source_id:
        source = db.get(Job, str(source_id))
        if source is None or source.type != JOB_TYPE:
            raise LabOverrideError("The selected managed operation does not exist.")
        previous = json.loads(source.task_config_json)
        evidence = json.loads(source.result or "{}")
        if previous.get("source_job_id") or source.status in {"pending", "running"}:
            raise LabOverrideError(
                "Select a completed property-change operation to revert."
            )
        if (
            evidence.get("changed") is not True
            or evidence.get("property_verified") is not True
        ):
            raise LabOverrideError(
                "This task has no verified managed change to revert. Inspect uncertain outcomes on the target before recovery."
            )
        if (
            previous.get("target") != target.fields()
            or previous.get("ssh_fingerprint") != ssh
        ):
            raise LabOverrideError(
                "The target identity differs from the original operation."
            )
        supported_catalog(previous["role"], previous["version"])
        state = {
            **inspect_properties(db, target, ssh),
            "role": previous["role"],
            "version": previous["version"],
            "identity_source": "original verified operation; recovery uses pinned SSH",
        }
        tls = previous["tls_fingerprint"]
        if any(
            state["values"][key] != value for key, value in previous["desired"].items()
        ):
            raise LabOverrideError(
                "Managed properties changed since the operation; revert would overwrite another edit."
            )
        desired = previous["previous"]
    else:
        state = inspect_target(db, target, tls, ssh)
        allowed = {
            item["id"]: item["value"]
            for item in supported_catalog(state["role"], state["version"])
        }
        selected = values.get("selections")
        if (
            not isinstance(selected, list)
            or not selected
            or any(not isinstance(key, str) or key not in allowed for key in selected)
            or len(set(selected)) != len(selected)
        ):
            raise LabOverrideError("Select one or both lab overrides.")
        desired = {key: allowed[key] for key in selected}
        if not state["service_active"]:
            raise LabOverrideError(
                "domainmanager is not active. Restore service health before applying overrides."
            )
    plan = {
        "actor": actor,
        "target": target.fields(),
        "tls_fingerprint": tls,
        "ssh_fingerprint": ssh,
        "role": state["role"],
        "version": state["version"],
        "revision": state["revision"],
        "desired": desired,
        "previous": {key: state["values"][key] for key in desired},
        "source_job_id": str(source_id) if source_id else None,
        "nonce": str(uuid4()),
    }
    return {
        **state,
        "token": _signer().dumps(plan),
        "changes": [
            {
                "id": key,
                "key": vcf_lab_remote.KEYS[key],
                "previous": plan["previous"][key],
                "value": value,
            }
            for key, value in desired.items()
        ],
        "restart_required": plan["previous"] != desired,
    }


def enqueue(db: Session, actor: str, token: str) -> Job:
    """Atomically consume a review and reserve the SSH identity across workers."""
    try:
        plan = _signer().loads(token, max_age=600)
    except BadData:
        raise LabOverrideError(
            "Review expired or changed; inspect and review again."
        ) from None
    if plan.get("actor") != actor:
        raise LabOverrideError("This review belongs to another operator.")
    target = target_from_values(db, plan["target"])
    if target.fields() != plan["target"]:
        raise LabOverrideError("Vault endpoint changed; review again.")
    job_id = str(uuid4())
    lock_key = (
        "vcf_lab_lock:" + hashlib.sha256(plan["ssh_fingerprint"].encode()).hexdigest()
    )
    used_key = "vcf_lab_used:" + plan["nonce"]
    job = Job(
        id=job_id,
        type=JOB_TYPE,
        status=JobStatus.PENDING.value,
        created_by=actor,
        task_config_json=json.dumps(plan),
        result=json.dumps(
            {
                "target": target.host,
                "previous": plan["previous"],
                "desired": plan["desired"],
            }
        ),
    )
    db.add_all(
        [Setting(key=lock_key, value=job_id), Setting(key=used_key, value=job_id), job]
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise LabOverrideError(
            "Another operation is active, or this review was already submitted. Check Tasks."
        ) from None
    return job


def run_job(job_id: str) -> None:
    """Execute and retain truthful partial outcomes plus a safe revert baseline."""
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None or job.status != JobStatus.PENDING.value:
            return
        plan = json.loads(job.task_config_json)
        lock_key = (
            "vcf_lab_lock:"
            + hashlib.sha256(plan["ssh_fingerprint"].encode()).hexdigest()
        )
        claimed = db.execute(
            update(Job)
            .where(Job.id == job_id, Job.status == JobStatus.PENDING.value)
            .values(
                status=JobStatus.RUNNING.value, started_at=utcnow(), progress_percent=10
            )
            .returning(Job.id)
        ).scalar_one_or_none()
        if claimed is None:
            db.rollback()
            return
        db.commit()
        result: dict[str, Any] = {
            "target": plan["target"]["host"],
            "previous": plan["previous"],
            "desired": plan["desired"],
            "property_verified": False,
            "service_active": False,
            "api_ready": False,
        }
        try:
            actor = db.scalar(select(User).where(User.username == job.created_by))
            if actor is None or not actor.enabled or "admin" not in user_roles(actor):
                raise LabOverrideError(
                    "The submitting administrator is no longer authorized."
                )
            target = target_from_values(db, plan["target"])
            if target.fields() != plan["target"]:
                raise LabOverrideError("Vault endpoint changed after review.")
            if plan["source_job_id"]:
                # API availability must not be a recovery prerequisite.
                state = {
                    **inspect_properties(db, target, plan["ssh_fingerprint"]),
                    "role": plan["role"],
                    "version": plan["version"],
                }
            else:
                state = inspect_target(
                    db, target, plan["tls_fingerprint"], plan["ssh_fingerprint"]
                )
            if any(state[key] != plan[key] for key in ("role", "version", "revision")):
                raise LabOverrideError(
                    "Target version or configuration changed after review."
                )
            job.progress_percent = 30
            db.commit()
            outcome = remote(
                db,
                target,
                plan["ssh_fingerprint"],
                {
                    "action": "write",
                    "revision": plan["revision"],
                    "desired": plan["desired"],
                },
            )
            observed = outcome.get("values", {})
            result.update(
                changed=outcome.get("changed") is True,
                service_active=outcome.get("service_active") is True,
                property_verified=isinstance(observed, dict)
                and all(
                    observed.get(key) == value for key, value in plan["desired"].items()
                ),
            )
            job.result = json.dumps(result)
            db.commit()
            if (
                outcome.get("ok") is not True
                or not result["property_verified"]
                or not result["service_active"]
            ):
                raise LabOverrideError(
                    "Property application or domainmanager recovery failed. Inspect the target and review a revert; changes may have occurred."
                )
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                try:
                    info = appliance_info(db, target, plan["tls_fingerprint"])
                    if (
                        info["role"] == plan["role"]
                        and info["version"] == plan["version"]
                    ):
                        result["api_ready"] = True
                        break
                except LabOverrideError:
                    pass
                time.sleep(3)
            if not result["api_ready"]:
                raise LabOverrideError(
                    "Properties verified, but the VCF API did not recover before the deadline. Review target health or revert."
                )
            job.status = JobStatus.SUCCEEDED.value
        except Exception as exc:  # noqa: BLE001 - retain a sanitized terminal outcome for every worker failure.
            job.status = JobStatus.FAILED.value
            job.error = (
                str(exc)
                if isinstance(exc, LabOverrideError)
                else "Operation interrupted; inspect the target before retrying or reverting."
            )
        finally:
            job.result, job.finished_at, job.progress_percent = (
                json.dumps(result),
                utcnow(),
                100,
            )
            db.execute(
                delete(Setting).where(Setting.key == lock_key, Setting.value == job_id)
            )
            db.commit()
            record_audit(
                db,
                actor=job.created_by,
                action="revert_vcf_lab_overrides"
                if plan["source_job_id"]
                else "apply_vcf_lab_overrides",
                resource_type=JOB_TYPE,
                resource_id=job.id,
                success=job.status == JobStatus.SUCCEEDED.value,
                detail=json.dumps(
                    {
                        "target": target.host
                        if "target" in locals()
                        else plan["target"]["host"],
                        "version": plan["version"],
                        **result,
                    }
                ),
            )


def history(db: Session) -> list[dict[str, str]]:
    """List bounded operation history without credentials or configuration."""
    jobs = db.scalars(
        select(Job)
        .where(Job.type == JOB_TYPE)
        .order_by(Job.created_at.desc())
        .limit(50)
    )
    return [
        {
            "id": job.id,
            "target": json.loads(job.task_config_json)["target"]["host"],
            "status": job.status,
            "created_at": job.created_at.isoformat(),
        }
        for job in jobs
    ]


def recover_interrupted_jobs(db: Session) -> int:
    """Close interrupted tasks without guessing whether a dispatched write ran."""
    jobs = list(
        db.scalars(
            select(Job).where(
                Job.type == JOB_TYPE, Job.status.in_(["pending", "running"])
            )
        )
    )
    for job in jobs:
        # A pending task never dispatched SSH. A running task retains its target
        # reservation because its remote process may still hold the Linux lock.
        if job.status == "pending":
            db.execute(
                delete(Setting).where(
                    Setting.key.like("vcf_lab_lock:%"), Setting.value == job.id
                )
            )
        job.status, job.finished_at, job.progress_percent = "failed", utcnow(), 100
        job.error = "Interrupted by Atlaso restart. Inspect remote state before recovery; a dispatched target reservation remains held for maintainer reconciliation."
    db.commit()
    return len(jobs)
