"""Failure and provenance integration checks for offline ISO refresh orchestration."""

from __future__ import annotations

import io
import json
import os
import tarfile

import pytest

from scripts.installation import refresh
from scripts.installation.manifest import digest


@pytest.fixture
def operation(tmp_path, monkeypatch):
    """Create a synthetic originally receipted operation for admission tests.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
        monkeypatch: Pytest fixture replacing dependencies without external operations.
    """
    root, state = tmp_path / "output", tmp_path / "evidence"
    root.mkdir()
    state.mkdir()
    plan = {"schema": 1, "operation_id": "a" * 32, "task_id": "01a19320-0e85-76f0-a1ba-e68ff3ac6d71",
            "installer_commit": "b" * 40, "output_root": str(root), "protected_files": [], "capture_receipt": None}
    monkeypatch.setattr(refresh, "source_input_sha256", lambda: "c" * 64)
    refresh.publish(state / "output-original.json", {"plan_sha256": "d" * 64, "path": str(root),
                    "task_id": plan["task_id"], "protected_files": [],
                    "root_identity": list(refresh.WindowsFiles().snapshot(root)["."]["identity"])})
    return plan, state, "d" * 64


@pytest.mark.skipif(os.name != "nt", reason="Original output identity uses Windows handles")
def test_phase_intent_is_original_and_cannot_be_replayed(operation):
    """Refuse replay while preserving the original phase intent.

    Args:
        operation: Synthetic plan, original output receipt and immutable plan digest fixture.
    """
    plan, state, checksum = operation
    intent = refresh.preflight(plan, state, checksum, "drift")
    assert intent["intent_id"]
    assert intent["deadline_utc"] > intent["started_utc"]
    before = (state / "drift-intent.json").read_bytes()
    with pytest.raises(ValueError, match="no proven terminal"):
        refresh.preflight(plan, state, checksum, "drift")
    assert (state / "drift-intent.json").read_bytes() == before
    assert not (state / "drift-result.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Original output identity uses Windows handles")
def test_capacity_refusal_creates_no_original_consumer_or_resource(operation, monkeypatch):
    """Refuse insufficient capacity before publishing a consumer intent.

    Args:
        operation: Synthetic plan, original output receipt and immutable plan digest fixture.
        monkeypatch: Pytest fixture replacing dependencies without external operations.
    """
    plan, state, checksum = operation
    monkeypatch.setattr(refresh, "authorize_phase", lambda *args, **kwargs: {
        "status": "authorized", "minimum_free_gib": 120, "timeout_seconds": 300})
    monkeypatch.setattr(refresh.shutil, "disk_usage", lambda path: type("Usage", (), {"free": 10})())
    with pytest.raises(ValueError, match="capacity_refusal"):
        refresh.preflight(plan, state, checksum, "drift")
    assert list(state.iterdir()) == [state / "output-original.json"]


def test_report_edit_invalidates_success_before_reuse(tmp_path):
    """Refuse altered reports even when an earlier result claimed success.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
    """
    report = tmp_path / "drift-report.json"
    refresh.publish(report, {"disposition": "reuse"})
    refresh.publish(tmp_path / "drift-intent.json", {"plan_sha256": "a" * 64})
    refresh.publish(tmp_path / "drift-result.json", {"plan_sha256": "a" * 64, "status": "succeeded",
                    "whole_job_quiescent": True, "report_sha256": digest(report)})
    report.write_text('{"disposition":"requires_capture"}')
    with pytest.raises(ValueError, match="report changed"):
        refresh.history(tmp_path, "a" * 64)


def test_protected_file_same_byte_replacement_is_not_original_identity(tmp_path):
    """Reject same-byte protected-file replacement by filesystem identity.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
    """
    protected = tmp_path / "protected.txt"
    protected.write_bytes(b"protected bytes")
    plan = {"protected_files": [{"path": str(protected), "sha256": digest(protected)}]}
    refresh.publish(tmp_path / "output-original.json", {"protected_files": refresh.protected_files(plan)})
    assert refresh.verify_protected_files(plan, tmp_path)
    replacement = tmp_path / "replacement.txt"
    replacement.write_bytes(protected.read_bytes())
    os.replace(replacement, protected)
    with pytest.raises(ValueError, match="identity changed"):
        refresh.verify_protected_files(plan, tmp_path)


def test_source_invalidation_refuses_capture_reuse(tmp_path, monkeypatch):
    """Refuse captured inputs whose source compatibility digest changed.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
        monkeypatch: Pytest fixture replacing dependencies without external operations.
    """
    original = tmp_path / "original.json"
    refresh.publish(original, {"source_commit": "a" * 40, "task_id": "original-owner"})
    receipt = {"schema": 1, "kind": "installation-refresh-capture", "source_commit": "a" * 40,
               "task_id": "original-owner", "repository": "mdaneri/Atlaso", "source_input_sha256": "b" * 64,
               "rpms": str(tmp_path / "rpms"), "powercli": str(tmp_path / "modules"), "inventory": {},
               "original_root_receipt": {"path": str(original), "sha256": digest(original)}}
    refresh.publish(tmp_path / "capture-inputs.json", receipt)
    monkeypatch.setattr(refresh, "source_input_sha256", lambda: "c" * 64)
    plan = {"capture_receipt": None, "rpms": receipt["rpms"], "powercli": receipt["powercli"]}
    with pytest.raises(ValueError, match="source compatibility"):
        refresh.check_capture(plan, tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="Capture root provenance uses native Windows identity")
def test_complete_original_capture_reuse_requires_unchanged_bytes_and_creator_completion(tmp_path, monkeypatch):
    """Admit complete original capture proof and refuse changed input bytes.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
        monkeypatch: Pytest fixture replacing dependencies without external operations.
    """
    capture = tmp_path / "retained-inputs"
    capture.mkdir()
    for name in ("rpms", "powercli"):
        (capture / name).mkdir()
        (capture / name / "fixture.bin").write_bytes(b"original captured public input")
    identity = refresh.WindowsFiles().snapshot(capture)["."]["identity"]
    native_identity = f"{identity[0]:08X}:{identity[1]:08X}{identity[2]:08X}"
    original = tmp_path / "capture-root-original.json"
    refresh.publish(original, {"path": str(capture), "native_identity": native_identity,
                    "task_id": "original-owner", "source_commit": "b" * 40, "plan_sha256": "c" * 64})
    plan = {"capture_receipt": None, "rpms": str(capture / "rpms"), "powercli": str(capture / "powercli")}
    receipt = tmp_path / "capture-inputs.json"
    refresh.publish(receipt, {"schema": 1, "kind": "installation-refresh-capture", "repository": "mdaneri/Atlaso",
                    "task_id": "original-owner", "source_commit": "b" * 40, "source_input_sha256": "a" * 64,
                    "rpms": plan["rpms"], "powercli": plan["powercli"], "inventory": refresh.input_inventory(plan),
                    "original_root_receipt": {"path": str(original), "sha256": digest(original)}})
    plan["capture_receipt"] = {"path": str(receipt), "sha256": digest(receipt)}
    report = tmp_path / "capture-report.json"
    refresh.publish(report, {"capture_receipt": plan["capture_receipt"]})
    refresh.publish(tmp_path / "capture-result.json", {"status": "succeeded", "whole_job_quiescent": True,
                    "plan_sha256": "c" * 64, "task_id": "original-owner", "installer_commit": "b" * 40,
                    "report_sha256": digest(report)})
    monkeypatch.setattr(refresh, "source_input_sha256", lambda: "a" * 64)
    refresh.check_capture(plan, tmp_path)
    (capture / "powercli/fixture.bin").write_bytes(b"changed captured input")
    with pytest.raises(ValueError, match="complete bytes"):
        refresh.check_capture(plan, tmp_path)


@pytest.mark.parametrize("name,kind", [
    ("../escape", tarfile.REGTYPE), ("Modules/link", tarfile.SYMTYPE),
    ("Modules/file:stream", tarfile.REGTYPE), ("Modules/NUL.txt", tarfile.REGTYPE),
    ("Modules/trailing.", tarfile.REGTYPE),
])
def test_capture_archive_path_admission_rejects_platform_independent_unsafe_entries(name, kind):
    """Exercise native extraction's path/type guard without requiring Windows handles.

    Args:
        name: Traversal, link, alternate stream or reserved Windows archive path.
        kind: Tar entry type for the unsafe candidate.
    """
    member = tarfile.TarInfo(name)
    member.type = kind
    with pytest.raises(ValueError, match="unsafe entry"):
        refresh._capture_member_path(member, "Modules")


@pytest.mark.skipif(os.name != "nt", reason="Archive extraction retains native Windows directory handles")
@pytest.mark.parametrize("name,kind", [
    ("../escape", tarfile.REGTYPE), ("Modules/link", tarfile.SYMTYPE),
    ("Modules/file:stream", tarfile.REGTYPE), ("Modules/NUL.txt", tarfile.REGTYPE),
    ("Modules/trailing.", tarfile.REGTYPE),
])
def test_complete_capture_extraction_preserves_unsafe_input_without_writing_outside(tmp_path, name, kind):
    """Preserve unsafe capture archives and refuse writes outside the native extraction root.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
        name: Unsafe archive path that must never escape or alias the extraction root.
        kind: Tar member type used to exercise the extraction admission boundary.
    """
    archive = tmp_path / "capture.tar"
    with tarfile.open(archive, "w:") as stream:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = "../../escape"
        stream.addfile(member)
    before = archive.read_bytes()
    with pytest.raises(ValueError, match="unsafe entry"):
        refresh._unpack(archive, tmp_path / "output", "Modules")
    assert archive.read_bytes() == before
    assert not (tmp_path / "escape").exists()


@pytest.mark.skipif(os.name != "nt", reason="Archive extraction retains native Windows directory handles")
def test_complete_capture_extraction_never_substitutes_existing_file(tmp_path):
    """Extract a complete fixture once and refuse destination replacement.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
    """
    archive = tmp_path / "capture.tar"
    with tarfile.open(archive, "w:") as stream:
        member = tarfile.TarInfo("Modules/Test/module.psm1")
        member.size = 4
        stream.addfile(member, io.BytesIO(b"test"))
    output = tmp_path / "modules"
    refresh._unpack(archive, output, "Modules")
    assert (output / "Test/module.psm1").read_bytes() == b"test"
    with pytest.raises(ValueError, match="already exists"):
        refresh._unpack(archive, output, "Modules")


def test_direct_worker_replay_is_not_native_admission(tmp_path):
    """Refuse direct worker calls without their original native process admission.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
    """
    record = tmp_path / "install-child.json"
    refresh.publish(record, {"pid": os.getpid() + 1, "task_id": "actual", "phase": "install", "plan_sha256": "a" * 64})
    with pytest.raises(ValueError, match="original native child|native Windows job"):
        refresh.assert_native_child(record, {"task_id": "actual"}, "a" * 64, "install", tmp_path)


def test_immutable_publication_refuses_overwrite_and_duplicate_json_keys(tmp_path):
    """Preserve original evidence and refuse ambiguous duplicate JSON keys.

    Args:
        tmp_path: Pytest-owned temporary directory for isolated synthetic fixtures.
    """
    path = tmp_path / "intent.json"
    refresh.publish(path, {"original": True})
    with pytest.raises(Exception, match="new name|publication"):
        refresh.publish(path, {"original": False})
    assert json.loads(path.read_bytes()) == {"original": True}
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"phase":"build","phase":"install"}')
    with pytest.raises(ValueError, match="duplicate keys"):
        refresh.read(duplicate)
