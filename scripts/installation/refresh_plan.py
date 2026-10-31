"""Validate a bounded, immutable offline ISO refresh plan and phase history."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from pathlib import PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Any

PHASES = (
    "drift",
    "compare",
    "capture",
    "admit",
    "build",
    "readback",
    "install",
    "verify",
    "cleanup",
    "protected",
)

# Capacity and time bounds are part of the workflow contract, not plan inputs.
MIN_FREE_GIB = MappingProxyType(
    {
        "drift": 0,
        "compare": 0,
        "capture": 120,
        "admit": 2,
        "build": 12,
        "readback": 4,
        "install": 74,
        "verify": 2,
        "cleanup": 2,
        "protected": 0,
    }
)
TIMEOUT_SECONDS = MappingProxyType(
    {
        "drift": 900,
        "compare": 900,
        "capture": 21600,
        "admit": 1800,
        "build": 3600,
        "readback": 1800,
        "install": 3600,
        "verify": 1200,
        "cleanup": 1200,
        "protected": 300,
    }
)

_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_NATIVE_DISTRIBUTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_PLAN_KEYS = {
    "schema",
    "operation_id",
    "task_id",
    "installer_commit",
    "software",
    "source_iso",
    "rpms",
    "powercli",
    "output_root",
    "pull_request_number",
    "native_distribution",
    "protected_files",
    "capture_receipt",
}
_RESULT_STATUSES = {"succeeded", "failed", "refused", "interrupted", "pending"}
_DRIFT_DISPOSITIONS = {"reuse", "requires_capture", "requires_review"}


def _require_mapping(value: object, name: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{name} schema is invalid")
    return dict(value)


def _path(value: object, name: str) -> PurePosixPath | PureWindowsPath:
    """Accept only canonical absolute local paths; plans never accept URI/UNC paths."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} path is invalid")
    if value.startswith(("//", "\\\\")) or "://" in value:
        raise ValueError(f"{name} path must be a local absolute path")

    windows = PureWindowsPath(value)
    if windows.drive:
        if not windows.is_absolute() or value != str(windows) or any(part == ".." for part in windows.parts):
            raise ValueError(f"{name} Windows path is not canonical and absolute")
        return windows

    posix = PurePosixPath(value)
    if "\\" in value or not posix.is_absolute() or value != str(posix) or any(part == ".." for part in posix.parts):
        raise ValueError(f"{name} POSIX path is not canonical and absolute")
    return posix


def _same_path_kind(first: PurePosixPath | PureWindowsPath, second: PurePosixPath | PureWindowsPath) -> bool:
    return type(first) is type(second)


def _within(path: PurePosixPath | PureWindowsPath, root: PurePosixPath | PureWindowsPath) -> bool:
    return _same_path_kind(path, root) and path.is_relative_to(root)


def _overlaps(first: PurePosixPath | PureWindowsPath, second: PurePosixPath | PureWindowsPath) -> bool:
    return _within(first, second) or _within(second, first)


def validate_plan(
    value: object,
    *,
    configured_root: str | None = None,
    worktree: str | None = None,
) -> dict[str, Any]:
    """Validate the exact plan schema and path boundaries without filesystem access.

    The caller must provide the independently resolved worktree and configured root
    before authorizing any phase. A null capture receipt describes a fresh RPM and
    PowerCLI capture that the driver must create in its separate retained input root
    and receipt before first use.
    """
    plan = _require_mapping(value, "refresh plan", _PLAN_KEYS)
    if type(plan["schema"]) is not int or plan["schema"] != 1:
        raise ValueError("refresh plan schema version is unsupported")
    if not isinstance(plan["operation_id"], str) or not _HEX32.fullmatch(plan["operation_id"]):
        raise ValueError("refresh operation identity is invalid")
    if not isinstance(plan["task_id"], str):
        raise ValueError("refresh task identity is invalid")
    try:
        parsed_task_id = uuid.UUID(plan["task_id"])
    except (ValueError, AttributeError) as exc:
        raise ValueError("refresh task identity is invalid") from exc
    if str(parsed_task_id) != plan["task_id"]:
        raise ValueError("refresh task identity is not canonical")
    if not isinstance(plan["installer_commit"], str) or not _HEX40.fullmatch(plan["installer_commit"]):
        raise ValueError("installer source identity is invalid")
    if type(plan["pull_request_number"]) is not int or not 0 < plan["pull_request_number"] <= 2**31 - 1:
        raise ValueError("owning pull request number is invalid")
    native_distribution = plan["native_distribution"]
    if native_distribution is not None and (
        not isinstance(native_distribution, str) or not _NATIVE_DISTRIBUTION.fullmatch(native_distribution)
    ):
        raise ValueError("native distribution selector is invalid")

    software = _require_mapping(plan["software"], "software", {"path", "version", "source_commit"})
    software_path = _path(software["path"], "software")
    if not isinstance(software["version"], str) or not _VERSION.fullmatch(software["version"]):
        raise ValueError("software version is invalid")
    if not isinstance(software["source_commit"], str) or not _HEX40.fullmatch(software["source_commit"]):
        raise ValueError("software source identity is invalid")

    source_iso = _path(plan["source_iso"], "source ISO")
    rpms = _path(plan["rpms"], "RPM input")
    powercli = _path(plan["powercli"], "PowerCLI input")
    output_root = _path(plan["output_root"], "output root")

    receipt_value = plan["capture_receipt"]
    capture_receipt = None
    receipt_path = None
    if receipt_value is not None:
        capture_receipt = _require_mapping(receipt_value, "capture receipt", {"path", "sha256"})
        receipt_path = _path(capture_receipt["path"], "capture receipt")
        if not isinstance(capture_receipt["sha256"], str) or not _HEX64.fullmatch(capture_receipt["sha256"]):
            raise ValueError("capture receipt digest is invalid")

    protected = plan["protected_files"]
    if not isinstance(protected, list) or len(protected) > 64:
        raise ValueError("protected-file inventory is invalid")
    protected_paths: list[PurePosixPath | PureWindowsPath] = []
    for item in protected:
        record = _require_mapping(item, "protected-file record", {"path", "sha256"})
        path = _path(record["path"], "protected file")
        if not isinstance(record["sha256"], str) or not _HEX64.fullmatch(record["sha256"]):
            raise ValueError("protected-file digest is invalid")
        protected_paths.append(path)

    sources = [software_path, source_iso, rpms, powercli]
    if any(type(path) is not type(output_root) for path in sources):
        raise ValueError("plan paths must use one local path syntax")
    if len(set(sources)) != len(sources):
        raise ValueError("source input paths are duplicated")
    for index, first in enumerate(sources):
        if any(_overlaps(first, second) for second in sources[index + 1 :]):
            raise ValueError("source input paths overlap")
    for path in sources:
        if _overlaps(output_root, path):
            raise ValueError("output root overlaps an input path")
    for path in protected_paths:
        if type(path) is not type(output_root) or _overlaps(output_root, path):
            raise ValueError("output root overlaps a protected file")
    all_protected = protected_paths + ([receipt_path] if receipt_path is not None else [])
    if len(set(all_protected)) != len(all_protected):
        raise ValueError("protected and receipt paths are duplicated")
    if any(type(path) is not type(output_root) for path in all_protected):
        raise ValueError("plan paths must use one local path syntax")
    if receipt_path is not None and _overlaps(output_root, receipt_path):
        raise ValueError("capture receipt must be outside the output root")

    if (configured_root is None) != (worktree is None):
        raise ValueError("configured root and worktree must be supplied together")
    if configured_root is not None and worktree is not None:
        configured = _path(configured_root, "configured worktree root")
        task_worktree = _path(worktree, "task worktree")
        if not _within(task_worktree, configured) or task_worktree == configured:
            raise ValueError("task worktree is not beneath the configured root")
        if not _within(output_root, task_worktree) or output_root == task_worktree:
            raise ValueError("output root is not a strict worktree descendant")
        if receipt_path is not None and _overlaps(receipt_path, task_worktree):
            raise ValueError("capture receipt must be outside the task worktree")
        if plan["capture_receipt"] is None and (
            not _within(rpms, configured)
            or not _within(powercli, configured)
            or rpms == configured
            or powercli == configured
            or _within(rpms, task_worktree)
            or _within(powercli, task_worktree)
            or _overlaps(rpms, powercli)
        ):
            raise ValueError("fresh capture inputs must be separate strict configured-root descendants outside the task worktree")

    return {
        "schema": 1,
        "operation_id": plan["operation_id"],
        "task_id": plan["task_id"],
        "installer_commit": plan["installer_commit"],
        "software": software,
        "source_iso": plan["source_iso"],
        "rpms": plan["rpms"],
        "powercli": plan["powercli"],
        "output_root": plan["output_root"],
        "pull_request_number": plan["pull_request_number"],
        "native_distribution": native_distribution,
        "protected_files": [dict(item) for item in protected],
        "capture_receipt": capture_receipt,
    }


def canonical_plan_sha256(value: object, **path_context: str) -> str:
    """Hash the canonical validated plan representation."""
    plan = validate_plan(value, **path_context)
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _phase_record(
    phase: str,
    record: object,
    *,
    plan: Mapping[str, Any] | None,
) -> tuple[str, str | None]:
    if phase not in PHASES or not isinstance(record, Mapping):
        return "refused", "phase record is malformed"
    status = record.get("status")
    if not isinstance(status, str) or status not in _RESULT_STATUSES:
        return "refused", "phase status is unknown"
    if plan is not None and _binding_error(record, plan):
        return "refused", _binding_error(record, plan)
    if record.get("whole_job_quiescent") is not True:
        return "refused", "phase whole-job quiescence is unproven"
    return status, None


def _binding_error(record: Mapping[str, Any], plan: Mapping[str, Any]) -> str | None:
    if record.get("operation_id") != plan.get("operation_id"):
        return "phase operation identity differs"
    if record.get("task_id") != plan.get("task_id"):
        return "phase task identity differs"
    if record.get("installer_commit") != plan.get("installer_commit"):
        return "phase source identity differs"
    return None


def _history_error(
    results: Mapping[str, object],
    started: Mapping[str, object],
    *,
    plan: Mapping[str, Any] | None,
    target: str,
) -> tuple[str, str] | None:
    """Require one bound, quiescent result for every prior original intent."""
    if any(phase not in PHASES for phase in (*results, *started)):
        return "refused", "phase history contains an unknown phase"
    for phase, intent in started.items():
        if not isinstance(intent, Mapping):
            return "refused", f"{phase} original start intent is malformed"
        intent_id = intent.get("intent_id")
        if not isinstance(intent_id, str) or not intent_id:
            return "refused", f"{phase} original start identity is missing"
        if _binding_error(intent, plan if plan is not None else intent):
            return "refused", f"{phase} original start identity differs"
        if phase not in results:
            return "pending", f"{phase} original consumer has no terminal result"
    for phase, record in results.items():
        if phase not in started:
            return "refused", f"{phase} result lacks its original start intent"
        if not isinstance(record, Mapping) or record.get("start_intent_id") != started[phase].get("intent_id"):
            return "refused", f"{phase} result does not match its original start intent"
        if _binding_error(record, plan if plan is not None else started[phase]):
            return "refused", f"{phase} result source identity differs from its original start intent"
        status, reason = _phase_record(phase, record, plan=plan)
        if reason:
            return "refused", reason
        if status == "pending":
            return "pending", f"{phase} result is pending"
        if status in {"failed", "refused", "interrupted"}:
            if phase == "install" and target == "verify" and status in {"failed", "interrupted"}:
                continue
            return "refused", f"{phase} is terminal with status {status}; later phases are blocked"
    return None


def authorize_phase(
    phase: str,
    results: Mapping[str, object],
    started: Mapping[str, object],
    *,
    plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return whether a phase may start, honoring dependencies and no-replay rules."""
    if phase not in PHASES:
        return {"status": "refused", "reason": "phase is unknown"}
    if phase in started or phase in results:
        return {"status": "refused", "reason": "phase already has an original start intent"}

    history_error = _history_error(results, started, plan=plan, target=phase)
    if history_error is not None:
        status, reason = history_error
        return {"status": status, "reason": reason}

    def result_status(name: str) -> tuple[str, str | None]:
        if name not in results:
            return "pending", f"{name} result is pending"
        status, reason = _phase_record(name, results[name], plan=plan)
        if reason:
            return status, reason
        return status, None

    drift_status, reason = result_status("drift")
    if phase != "drift" and (drift_status != "succeeded" or reason):
        return {"status": "pending" if drift_status == "pending" else "refused", "reason": reason or "drift must succeed first"}
    drift = results.get("drift") if drift_status == "succeeded" else None
    disposition = drift.get("disposition") if isinstance(drift, Mapping) else None
    if phase == "drift":
        return _authorization(phase)
    if disposition not in _DRIFT_DISPOSITIONS:
        return {"status": "refused", "reason": "drift disposition is unknown"}
    if phase == "compare":
        if disposition != "requires_review":
            return {"status": "refused", "reason": "native comparison is only needed for review-required drift"}
        return _authorization(phase)
    if disposition == "requires_review":
        return {"status": "refused", "reason": "runtime behavior requires explicit review in a new source operation"}
    if phase == "capture":
        if disposition != "requires_capture":
            return {"status": "refused", "reason": "capture is only authorized by a requires_capture drift result"}
        return _authorization(phase)

    if phase in PHASES[2:]:
        if disposition == "requires_capture":
            capture_status, capture_reason = result_status("capture")
            if capture_status != "succeeded" or capture_reason:
                return {"status": "pending" if capture_status == "pending" else "refused", "reason": capture_reason or "capture must succeed first"}
        elif "capture" in results or "capture" in started:
            return {"status": "refused", "reason": "capture exists for a reuse plan"}

    dependencies = {
        "admit": (),
        "build": ("admit",),
        "readback": ("build",),
        "install": ("readback",),
        "verify": ("readback", "install"),
        "cleanup": ("verify",),
        "protected": ("cleanup",),
    }
    for dependency in dependencies.get(phase, ()):
        status, dependency_reason = result_status(dependency)
        if dependency == "install" and phase == "verify":
            if dependency not in started:
                return {"status": "refused", "reason": "installation has no original start intent"}
            if status not in {"succeeded", "failed", "interrupted"} or dependency_reason:
                return {"status": "pending" if status == "pending" else "refused", "reason": dependency_reason or "installation result must be terminal"}
            if not isinstance(results[dependency], Mapping) or results[dependency].get("whole_job_quiescent") is not True:
                return {"status": "refused", "reason": "installation whole-job quiescence is unproven"}
            continue
        if status != "succeeded" or dependency_reason:
            return {"status": "pending" if status == "pending" else "refused", "reason": dependency_reason or f"{dependency} must succeed first"}
    return _authorization(phase)


def _authorization(phase: str) -> dict[str, Any]:
    return {
        "status": "authorized",
        "phase": phase,
        "minimum_free_gib": MIN_FREE_GIB[phase],
        "timeout_seconds": TIMEOUT_SECONDS[phase],
    }


def next_phase(
    results: Mapping[str, object],
    started: Mapping[str, object],
    *,
    plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Find the next authorized phase, stopping at pending, refused, or terminal work."""
    for phase in PHASES:
        if phase == "compare" and phase not in started and phase not in results:
            continue
        if phase == "capture":
            drift = results.get("drift")
            if isinstance(drift, Mapping) and drift.get("disposition") == "reuse":
                continue
        if phase in results:
            status, reason = _phase_record(phase, results[phase], plan=plan)
            if reason:
                return {"status": "refused", "phase": phase, "reason": reason}
            if phase not in started:
                return {"status": "refused", "phase": phase, "reason": "phase result lacks its original start intent"}
            if status == "succeeded":
                continue
            if phase == "install" and status in {"failed", "interrupted"}:
                install_result = results[phase]
                if isinstance(install_result, Mapping) and install_result.get("whole_job_quiescent") is True:
                    continue
                return {"status": "refused", "phase": phase, "reason": "installation whole-job quiescence is unproven"}
            if status != "pending":
                return {"status": "refused", "phase": phase, "reason": f"{phase} is terminal with status {status}"}
            if phase in started:
                return {"status": "pending", "phase": phase, "reason": "original phase is still pending; never replay it"}
        authorization = authorize_phase(phase, results, started, plan=plan)
        authorization.setdefault("phase", phase)
        return authorization
    return {"status": "succeeded", "reason": "all required phases are complete"}
