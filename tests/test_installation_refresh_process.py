"""Windows refresh admission tests for CPython's virtualenv redirector."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts.completed_task_files import FileRefusal
from scripts.installation import refresh

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native refresh process admission requires Windows")


def _admission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, failure: str | None = None) -> tuple[Path, dict]:
    """Prepare one synthetic suspended launcher and its direct venv worker.

    Args:
        tmp_path: Receipted pytest fixture directory for original records.
        monkeypatch: Replaces kernel observations with deterministic process identities.
        failure: Optional process property to invalidate at the native boundary.
    """
    child_path = tmp_path / "drift-child.json"
    plan = {"task_id": "01a19320-0e85-76f0-a1ba-e68ff3ac6d71"}
    checksum = "a" * 64
    intent = {"intent_id": "f" * 32, "plan_sha256": checksum,
              "deadline_utc": "2026-11-06T23:00:00+00:00"}
    refresh.publish(tmp_path / "drift-intent.json", intent)
    interpreter = {
        "kind": "venv",
        "launcher": {"path": r"C:\fixture\venv\Scripts\python.exe", "native_identity": "launcher-id", "sha256": "1" * 64},
        "worker": {"path": r"C:\fixture\Python314\python.exe", "native_identity": "worker-id", "sha256": "2" * 64},
    }
    child = {
        "schema": 2, "phase": "drift", "task_id": plan["task_id"], "plan_sha256": checksum,
        "intent_id": intent["intent_id"], "deadline_utc": intent["deadline_utc"],
        "pid": 4200, "start_filetime_utc": 100, "job_name": r"Local\Atlaso-Refresh-test",
        "interpreter": interpreter,
    }
    if failure == "deadline-offset":
        child["deadline_utc"] = "2026-11-06T15:00:00-08:00"
    elif failure == "deadline-changed":
        child["deadline_utc"] = "2026-11-06T23:00:01+00:00"
    elif failure == "deadline-naive":
        child["deadline_utc"] = "2026-11-06T23:00:00"
    elif failure == "deadline-malformed":
        child["deadline_utc"] = "not-a-deadline"
    refresh.publish(child_path, child)

    def process_identity(process_id: int, job_name: str | None = None) -> dict:
        """Return one synthetic kernel process observation.

        Args:
            process_id: Launcher or worker PID selected by admission.
            job_name: Exact original job whose membership is required.
        """
        if job_name != child["job_name"]:
            raise refresh.RefreshRefusal("outside job")
        if process_id == child["pid"]:
            return {"pid": process_id, "parent_pid": 7, "start_filetime_utc": 101 if failure == "birth" else 100,
                    "path": r"C:\fixture\rogue.exe" if failure == "root-executable" else interpreter["launcher"]["path"]}
        return {"pid": process_id, "parent_pid": 99 if failure == "parent" else child["pid"],
                "start_filetime_utc": 99 if failure == "worker-birth" else 200,
                "path": interpreter["worker"]["path"]}

    def executable_identity(path: str) -> dict:
        """Return the fixture's original executable identity.

        Args:
            path: Launcher or worker image path selected for comparison.
        """
        if path == interpreter["launcher"]["path"]:
            return interpreter["launcher"]
        return interpreter["worker"]

    current_interpreter = interpreter
    if failure == "worker-executable":
        current_interpreter = {**interpreter, "worker": {**interpreter["worker"], "sha256": "3" * 64}}
    elif failure == "worker-file-identity":
        current_interpreter = {
            **interpreter,
            "worker": {**interpreter["worker"], "native_identity": "replacement-worker-id"},
        }

    monkeypatch.setattr(refresh.os, "name", "nt")
    monkeypatch.setattr(refresh, "_windows_process_identity", process_identity)
    monkeypatch.setattr(refresh, "_executable_identity", executable_identity)
    monkeypatch.setattr(refresh, "interpreter_identity", lambda: current_interpreter)
    if failure == "job":
        monkeypatch.setattr(refresh, "_windows_process_identity", lambda process_id, job_name=None: process_identity(process_id, "wrong-job"))
    return child_path, plan


def test_venv_worker_is_admitted_as_direct_child_without_rewriting_launcher_receipt(tmp_path, monkeypatch):
    """Keep launcher PID/birth immutable and publish a distinct first-use worker receipt.

    Args:
        tmp_path: Receipted pytest fixture directory for original records.
        monkeypatch: Supplies synthetic native process identities.
    """
    child_path, plan = _admission(tmp_path, monkeypatch)
    original = child_path.read_bytes()

    refresh.assert_native_child(child_path, plan, "a" * 64, "drift", tmp_path)

    assert child_path.read_bytes() == original
    worker = refresh.read(tmp_path / "drift-worker-original.json")
    assert worker["pid"] == os.getpid()
    assert worker["parent_pid"] == 4200
    assert worker["start_filetime_utc"] == 200
    assert worker["executable"]["sha256"] == "2" * 64
    assert worker["child_receipt_sha256"] == refresh.digest(child_path)
    with pytest.raises(FileRefusal, match="new name|publication"):
        refresh.assert_native_child(child_path, plan, "a" * 64, "drift", tmp_path)


def test_powershell_local_offset_for_same_deadline_instant_is_admitted(tmp_path, monkeypatch):
    """Accept the same deadline instant after PowerShell serializes its local offset.

    Args:
        tmp_path: Receipted pytest fixture directory for original records.
        monkeypatch: Supplies synthetic native process identities.
    """
    child_path, plan = _admission(tmp_path, monkeypatch, failure="deadline-offset")

    refresh.assert_native_child(child_path, plan, "a" * 64, "drift", tmp_path)

    assert refresh.read(tmp_path / "drift-worker-original.json")["start_filetime_utc"] == 200


@pytest.mark.parametrize("failure", [
    "birth", "root-executable", "worker-executable", "worker-file-identity", "worker-birth", "parent", "job",
    "deadline-changed", "deadline-naive", "deadline-malformed",
])
def test_venv_worker_rejects_wrong_process_provenance_and_preserves_original(tmp_path, monkeypatch, failure):
    """Refuse a child when any original process ownership edge is different.

    Args:
        tmp_path: Receipted pytest fixture directory for original records.
        monkeypatch: Supplies one deliberately unsafe native process observation.
        failure: Exact process property changed by the fixture.
    """
    child_path, plan = _admission(tmp_path, monkeypatch, failure=failure)
    original = child_path.read_bytes()

    with pytest.raises(refresh.RefreshRefusal):
        refresh.assert_native_child(child_path, plan, "a" * 64, "drift", tmp_path)

    assert child_path.read_bytes() == original
    assert not (tmp_path / "drift-worker-original.json").exists()
