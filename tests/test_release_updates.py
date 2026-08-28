"""Test release updates behavior."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atlaso.app.services.release_updates import (
    ReleaseManifestError,
    inventory_version_tuple,
    validate_inventory_release_manifest,
    validate_release_manifest,
    verify_signed_json,
)

ROOT = Path(__file__).resolve().parents[1]
KEY_ID = "test-release-key"


def load_script(module_name: str, filename: str):
    """Load one repository script as a test module.

    Args:
        module_name: Unique module name for the import.
        filename: Script filename under the repository scripts directory.

    Returns:
        The loaded script module.
    """
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "scripts" / filename)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


published_channel_check = load_script(
    "check_published_release_channel_script",
    "check_published_release_channel.py",
)


def canonical(payload: dict) -> bytes:
    """Return canonical.

    Args:
        payload: Validated request or task payload consumed by the operation.
    """
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def release_payload() -> dict:
    """Return release payload."""
    return {
        "schema_version": 2,
        "kind": "atlaso-release",
        "updater_protocol": 2,
        "database_schema_version": 1,
        "version": "0.9.0",
        "git_commit": "a" * 40,
        "built_at": "2026-07-23T12:00:00Z",
        "signing_key_id": KEY_ID,
        "supported_python_abis": ["cp314"],
        "bundle": {
            "url": "https://github.com/mdaneri/Atlaso/releases/download/v0.9.0/bundle.tar.gz",
            "size": 123,
            "sha256": "b" * 64,
        },
        "content_hashes": {"packages/atlaso.whl": "c" * 64},
    }


def inventory_payload() -> dict:
    """Return inventory payload."""
    return {
        "schema_version": 1,
        "kind": "atlaso-inventory-linux-release",
        "version": "2026.05.1+8",
        "git_commit": "a" * 40,
        "built_at": "2026-07-31T12:00:00Z",
        "signing_key_id": KEY_ID,
        "architecture": "x86_64",
        "package": {
            "name": "atlaso-inventory-linux-2026.05.1+8.zip",
            "url": "https://github.com/mdaneri/Atlaso/releases/download/inventory-linux-v2026.05.1%2B8/atlaso-inventory-linux-2026.05.1%2B8.zip",
            "size": 123,
            "sha256": "d" * 64,
        },
    }


def signed(payload: dict, private_key: Ed25519PrivateKey) -> tuple[bytes, bytes]:
    """Return signed.

    Args:
        payload: Validated request or task payload consumed by the operation.
        private_key: Private key supplied to the test scenario.
    """
    raw = canonical(payload)
    signature = canonical(
        {
            "schema_version": 1,
            "key_id": KEY_ID,
            "signature": base64.b64encode(private_key.sign(raw)).decode(),
        }
    )
    return raw, signature


@pytest.fixture
def trust(tmp_path):
    """Return trust.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / f"{KEY_ID}.pem").write_bytes(public_key)
    return private_key, trust_dir


def test_signed_release_verification_fails_closed(trust):
    """Verify that signed release verification fails closed.

    Args:
        trust: Trust supplied to the test scenario.
    """
    private_key, trust_dir = trust
    raw, signature = signed(release_payload(), private_key)

    assert verify_signed_json(raw, signature, trust_dir=trust_dir, document_kind="release")["version"] == "0.9.0"

    with pytest.raises(ReleaseManifestError, match="invalid"):
        verify_signed_json(raw + b" ", signature, trust_dir=trust_dir, document_kind="release")
    with pytest.raises(ReleaseManifestError, match="not trusted"):
        verify_signed_json(raw, signature, trust_dir=trust_dir / "missing", document_kind="release")
    with pytest.raises(ReleaseManifestError, match="valid JSON"):
        verify_signed_json(raw, b"not-json", trust_dir=trust_dir, document_kind="release")
    (trust_dir / f"{KEY_ID}.pem").write_text("not a key", encoding="utf-8")
    with pytest.raises(ReleaseManifestError, match="malformed"):
        verify_signed_json(raw, signature, trust_dir=trust_dir, document_kind="release")


def test_channel_pointer_must_match_named_key(trust):
    """Verify that channel pointer must match named key.

    Args:
        trust: Trust supplied to the test scenario.
    """
    private_key, trust_dir = trust
    channel = {
        "schema_version": 2,
        "kind": "atlaso-channel",
        "channel": "preview",
        "version": "0.9.0",
        "git_commit": "a" * 40,
        "release_manifest_url": "https://example.test/releases/v0.9.0/release-manifest.json",
        "issued_at": "2026-07-23T12:00:00Z",
        "signing_key_id": KEY_ID,
    }
    raw, signature = signed(channel, private_key)
    assert verify_signed_json(raw, signature, trust_dir=trust_dir, document_kind="channel")["channel"] == "preview"
    channel["signing_key_id"] = "another-key"
    mismatched_raw = canonical(channel)
    mismatched_signature = canonical(
        {
            "schema_version": 1,
            "key_id": KEY_ID,
            "signature": base64.b64encode(private_key.sign(mismatched_raw)).decode(),
        }
    )
    with pytest.raises(ReleaseManifestError, match="key IDs do not match"):
        verify_signed_json(mismatched_raw, mismatched_signature, trust_dir=trust_dir, document_kind="channel")


def test_signed_inventory_release_verification_detects_tampering(trust):
    """Verify that signed inventory release verification detects tampering.

    Args:
        trust: Trust supplied to the test scenario.
    """
    private_key, trust_dir = trust
    raw, signature = signed(inventory_payload(), private_key)
    assert verify_signed_json(
        raw,
        signature,
        trust_dir=trust_dir,
        document_kind="inventory",
    )["version"] == "2026.05.1+8"
    with pytest.raises(ReleaseManifestError, match="signature is invalid"):
        verify_signed_json(
            raw.replace(b'"size": 123', b'"size": 124'),
            signature,
            trust_dir=trust_dir,
            document_kind="inventory",
        )


def test_worker_publishes_candidate_identity_and_waits_for_release_finalizer(monkeypatch, tmp_path):
    """Verify candidate worker startup is published before interrupted-job recovery.

    Args:
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for isolated startup evidence.
    """
    import atlaso.app.worker as worker

    release_root = tmp_path / "releases" / "0.9.156"
    release_root.mkdir(parents=True)
    marker = tmp_path / "worker-startup.json"
    finalizer = tmp_path / "finalizer.json"
    finalizer.write_text(
        json.dumps(
            {
                "status": "restart_pending",
                "job_id": "job_release_restart",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "ATLASO_CURRENT_RELEASE_PATH", release_root)
    monkeypatch.setattr(worker, "WORKER_STARTUP_STATUS_PATH", marker)
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    monkeypatch.setattr(worker, "__version__", "0.9.156+gtest")
    monkeypatch.setattr(worker, "_worker_process_identity", lambda: ("current-boot", "4242"))

    worker._write_worker_startup_status()

    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["boot_id"] == "current-boot"
    assert payload["pid"] == os.getpid()
    assert payload["start_ticks"] == "4242"
    assert payload["version"] == "0.9.156"
    assert payload["current_release"] == str(release_root.resolve())
    assert payload["release_job_id"] == "job_release_restart"
    finalizer.write_text(
        json.dumps({"status": "activation_committed", "job_id": "job_release_committed"}),
        encoding="utf-8",
    )
    worker._write_worker_startup_status()
    assert json.loads(marker.read_text(encoding="utf-8"))["release_job_id"] == "job_release_committed"
    states = [
        {"status": "restart_pending"},
        {"status": "restart_pending"},
        {"status": "succeeded"},
    ]
    monkeypatch.setattr(worker, "_release_finalizer", lambda: states.pop(0))
    monkeypatch.setattr(worker, "_release_transaction_owner_alive", lambda _owner: True)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)

    assert worker._wait_for_release_restart_finalizer(timeout_seconds=1) is True

    assert states == []


def test_worker_rejects_stale_provisional_finalizer_without_runtime_gate(monkeypatch, tmp_path):
    """Verify stale durable transaction evidence cannot admit ordinary job recovery.

    Args:
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for the absent runtime gate.
    """
    import atlaso.app.worker as worker

    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_RESTART_GATE_PATH", tmp_path / "missing-gate")
    monkeypatch.setattr(
        worker,
        "_release_finalizer",
        lambda: {
            "status": "restart_pending",
            "transaction_recovery": {
                "owner": {"boot_id": "previous-boot", "pid": 99, "start_ticks": "1"}
            },
        },
    )
    monkeypatch.setattr(worker, "_release_transaction_owner_alive", lambda _owner: False)

    assert worker._wait_for_release_restart_finalizer(timeout_seconds=90) is False


def test_worker_activation_requires_exact_systemd_and_release_identity(monkeypatch, tmp_path):
    """Verify helper rejects stale or mismatched worker startup markers.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for isolated startup evidence.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    expected_release = tmp_path / "releases" / "0.9.156"
    expected_release.mkdir(parents=True)
    marker = tmp_path / "worker-startup.json"
    marker.write_text(
        json.dumps(
            {
                "boot_id": "current-boot",
                "pid": 202,
                "start_ticks": "200",
                "version": "0.9.156",
                "current_release": str(expected_release),
                "release_job_id": "job_release_restart",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ATLASO_WORKER_STARTUP_STATUS_PATH", marker)
    monkeypatch.setattr(helper, "_service_main_pid", lambda _unit: 202)
    monkeypatch.setattr(
        helper,
        "_running_worker_process_identity",
        lambda _pid: {"boot_id": "current-boot", "pid": 202, "start_ticks": "200"},
    )

    result = helper._wait_for_worker_activation(
        expected_version="0.9.156",
        expected_release=expected_release,
        expected_job_id="job_release_restart",
        previous_pid=101,
        timeout_seconds=1,
    )

    assert result["success"] is True, result
    assert result["worker_pid"] == 202
    marker.write_text(
        json.dumps(
            {
                "boot_id": "current-boot",
                "pid": 202,
                "start_ticks": "200",
                "version": "0.9.156",
                "current_release": str(tmp_path / "missing-release"),
                "release_job_id": "job_release_restart",
            }
        ),
        encoding="utf-8",
    )
    monotonic = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(helper.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)

    result = helper._wait_for_worker_activation(
        expected_version="0.9.156",
        expected_release=expected_release,
        expected_job_id="job_release_restart",
        previous_pid=101,
        timeout_seconds=1,
    )

    assert result["success"] is False


@pytest.mark.parametrize(
    ("marker_boot_id", "marker_start_ticks"),
    [("prior-boot", "200"), ("current-boot", "prior-start")],
)
def test_worker_activation_rejects_stale_marker_with_reused_pid(
    monkeypatch,
    tmp_path,
    marker_boot_id,
    marker_start_ticks,
):
    """Verify reboot recovery rejects startup evidence from an older boot or process.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for isolated startup evidence.
        marker_boot_id: Boot identity persisted in the simulated stale marker.
        marker_start_ticks: Process-start identity persisted in the simulated stale marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    expected_release = tmp_path / "releases" / "0.9.160"
    expected_release.mkdir(parents=True)
    marker = tmp_path / "worker-startup.json"
    marker.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "boot_id": marker_boot_id,
                "pid": 202,
                "start_ticks": marker_start_ticks,
                "version": "0.9.160",
                "current_release": str(expected_release),
                "release_job_id": "job-committed-reboot",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ATLASO_WORKER_STARTUP_STATUS_PATH", marker)
    monkeypatch.setattr(helper, "_service_main_pid", lambda _unit: 202)
    monkeypatch.setattr(
        helper,
        "_running_worker_process_identity",
        lambda _pid: {"boot_id": "current-boot", "pid": 202, "start_ticks": "200"},
    )
    monotonic = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(helper.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)

    result = helper._wait_for_worker_activation(
        expected_version="0.9.160",
        expected_release=expected_release,
        expected_job_id="job-committed-reboot",
        previous_pid=0,
        timeout_seconds=1,
    )

    assert result["success"] is False
    assert result["worker_pid"] == 202
    assert result["worker_boot_id"] == marker_boot_id
    assert result["worker_start_ticks"] == marker_start_ticks


def test_worker_restart_gate_timeout_fails_closed(monkeypatch, tmp_path):
    """Verify an uncleared release gate prevents a visible finalizer from being trusted.

    Args:
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for the runtime gate.
    """
    import atlaso.app.worker as worker

    gate = tmp_path / "restart-gate"
    gate.write_text("job_release_restart\n", encoding="utf-8")
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_RESTART_GATE_PATH", gate)
    monkeypatch.setattr(worker, "_release_finalizer", lambda: {"status": "succeeded"})
    monotonic = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)

    assert worker._wait_for_release_restart_finalizer(timeout_seconds=1) is False


def test_worker_restart_gate_wait_extends_while_transaction_owner_is_live(monkeypatch, tmp_path):
    """Verify a live rollback helper cannot be outrun by the candidate worker timeout.

    Args:
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for the runtime gate.
    """
    import atlaso.app.worker as worker

    gate = tmp_path / "restart-gate"
    gate.write_text("job-live-rollback\n", encoding="utf-8")
    finalizers = iter(
        (
            {
                "status": "failed",
                "job_id": "job-live-rollback",
                "rolled_back": False,
                "transaction_recovery": {"owner": {"pid": 99}},
            },
            {"status": "failed", "job_id": "job-live-rollback", "rolled_back": True},
        )
    )
    monotonic = iter((0.0, 2.0, 2.5))
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_RESTART_GATE_PATH", gate)
    monkeypatch.setattr(worker, "_release_finalizer", lambda: next(finalizers))
    monkeypatch.setattr(worker, "_release_transaction_owner_alive", lambda _owner: True)
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)

    assert worker._wait_for_release_restart_finalizer(timeout_seconds=1) is True


def test_worker_ignores_matching_stale_gate_after_definitive_finalizer(monkeypatch, tmp_path):
    """Verify a helper crash after the definitive write cannot deadlock worker startup.

    Args:
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for the orphaned runtime gate.
    """
    import atlaso.app.worker as worker

    gate = tmp_path / "restart-gate"
    gate.write_text("job-definitive\n", encoding="utf-8")
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_RESTART_GATE_PATH", gate)
    monkeypatch.setattr(
        worker,
        "_release_finalizer",
        lambda: {
            "status": "succeeded",
            "job_id": "job-definitive",
            "rolled_back": False,
        },
    )

    assert worker._wait_for_release_restart_finalizer(timeout_seconds=90) is True


def test_worker_exits_when_release_restart_gate_does_not_open(monkeypatch):
    """Verify systemd retries worker startup instead of running work behind a closed release gate.

    Args:
        monkeypatch: Pytest fixture used to replace worker startup dependencies.
    """
    import atlaso.app.worker as worker

    monkeypatch.setattr(worker.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(worker, "init_db", lambda: None)
    monkeypatch.setattr(worker, "_write_worker_startup_status", lambda: None)
    monkeypatch.setattr(worker, "_wait_for_release_restart_finalizer", lambda: False)
    monkeypatch.setattr(
        worker,
        "recover_interrupted_worker_jobs",
        lambda *_args, **_kwargs: pytest.fail("closed-gate startup must not reconcile jobs"),
    )

    assert worker.main() == 1


def test_candidate_worker_exits_after_reconciling_healthy_rollback(monkeypatch):
    """Verify systemd replaces candidate code only after rollback bookkeeping completes.

    Args:
        monkeypatch: Pytest fixture used to replace worker startup dependencies.
    """
    from contextlib import nullcontext

    import atlaso.app.worker as worker

    events: list[str] = []
    monkeypatch.setattr(worker.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(worker, "init_db", lambda: None)
    monkeypatch.setattr(worker, "_write_worker_startup_status", lambda: None)
    monkeypatch.setattr(worker, "_wait_for_release_restart_finalizer", lambda: True)
    monkeypatch.setattr(worker, "SessionLocal", lambda: nullcontext(object()))
    monkeypatch.setattr(
        worker,
        "recover_interrupted_worker_jobs",
        lambda *_args, **_kwargs: events.append("bookkeeping") or 1,
    )
    monkeypatch.setattr(
        worker,
        "_release_finalizer",
        lambda: {
            "status": "failed",
            "rolled_back": True,
            "previous_version": "0.9.155",
        },
    )
    monkeypatch.setattr(worker, "__version__", "0.9.159")
    monkeypatch.setattr(
        worker,
        "_complete_recovered_rollback_job",
        lambda: events.append("completion") or True,
    )
    monkeypatch.setattr(
        worker,
        "ensure_vcf_depot_running_operation_index",
        lambda: pytest.fail("candidate worker must exit before entering its ordinary work loop"),
    )

    assert worker.main() == 1
    assert events == ["bookkeeping", "completion"]


def test_candidate_recovery_one_shot_completes_bookkeeping(monkeypatch):
    """Verify privileged reboot recovery can invoke candidate bookkeeping once.

    Args:
        monkeypatch: Pytest fixture used to replace worker recovery dependencies.
    """
    from contextlib import nullcontext

    import atlaso.app.worker as worker

    events: list[str] = []
    monkeypatch.setattr(
        worker,
        "init_db",
        lambda: pytest.fail("candidate rollback bookkeeping must not initialize the restored schema"),
    )
    monkeypatch.setattr(worker, "SessionLocal", lambda: nullcontext(object()))
    monkeypatch.setattr(
        worker,
        "recover_interrupted_worker_jobs",
        lambda *_args, **_kwargs: events.append("bookkeeping") or 1,
    )
    monkeypatch.setattr(
        worker,
        "_complete_recovered_rollback_job",
        lambda: events.append("completion") or True,
    )

    assert worker.recover_release_rollback_handoff() == 0
    assert events == ["bookkeeping", "completion"]


@pytest.mark.parametrize(
    ("status", "allow_worker"),
    [("transaction_pending", False), ("restart_pending", True), ("activation_committed", True)],
)
def test_release_prestart_recovery_defers_to_live_transaction_owner(
    monkeypatch,
    tmp_path,
    status,
    allow_worker,
):
    """Verify pre-start recovery neither rolls back nor outruns the live helper.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for provisional evidence.
        status: Transaction phase under test.
        allow_worker: Whether the phase permits the intentional worker handoff.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    finalizer = tmp_path / "finalizer.json"
    finalizer.write_text(
        json.dumps(
            {
                "status": status,
                "job_id": "job-live-owner",
                "transaction_recovery": {"owner": {"pid": 101}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    monkeypatch.setattr(
        helper,
        "_validated_release_recovery_context",
        lambda _payload: pytest.fail("live transaction owner must not be rolled back"),
    )

    result = helper._recover_interrupted_release_transaction()

    assert result["status"] == "transaction_active"
    assert result["allow_worker"] is allow_worker
    assert result["success"] is allow_worker


@pytest.mark.parametrize(
    ("finalizer", "allow_worker", "gate_cleared"),
    [
        ({"status": "succeeded", "job_id": "job-definitive"}, True, True),
        (
            {
                "status": "failed",
                "job_id": "job-definitive",
                "rolled_back": True,
            },
            True,
            True,
        ),
        (
            {
                "status": "failed",
                "job_id": "job-definitive",
                "rolled_back": False,
            },
            False,
            False,
        ),
    ],
)
def test_release_prestart_recovery_handles_gate_after_definitive_write(
    monkeypatch,
    tmp_path,
    finalizer,
    allow_worker,
    gate_cleared,
):
    """Verify only a complete matching transaction can clear an orphaned gate.

    Args:
        monkeypatch: Pytest fixture used to replace helper paths.
        tmp_path: Temporary directory provided for finalizer and gate evidence.
        finalizer: Definitive transaction evidence under test.
        allow_worker: Whether pre-start recovery should admit the worker.
        gate_cleared: Whether the matching runtime gate should be removed.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    finalizer_path = tmp_path / "finalizer.json"
    finalizer_path.write_text(json.dumps(finalizer), encoding="utf-8")
    gate = tmp_path / "restart-gate"
    gate.write_text("job-definitive\n", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer_path)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_RESTART_GATE_PATH", gate)

    result = helper._recover_interrupted_release_transaction()

    assert result["allow_worker"] is allow_worker
    assert result["success"] is allow_worker
    assert gate.exists() is (not gate_cleared)


@pytest.mark.parametrize("bookkeeping_success", [True, False])
@pytest.mark.parametrize("finalizer_write_success", [True, False])
@pytest.mark.parametrize("status_write_success", [True, False])
def test_release_prestart_recovery_rolls_back_stale_transaction(
    monkeypatch,
    tmp_path,
    bookkeeping_success,
    finalizer_write_success,
    status_write_success,
):
    """Verify a reboot-stale provisional transaction restores the previous release.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for recovery state.
        bookkeeping_success: Whether candidate-version task recovery completes.
        finalizer_write_success: Whether definitive rollback evidence can be persisted.
        status_write_success: Whether reboot rollback status can be persisted.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    releases = tmp_path / "releases"
    previous = releases / "0.9.158"
    candidate = releases / "0.9.159"
    previous.mkdir(parents=True)
    candidate.mkdir()
    current = tmp_path / "current"
    current.symlink_to(candidate, target_is_directory=True)
    backup_root = tmp_path / "backups" / "transaction"
    backup_root.mkdir(parents=True)
    database_backup = backup_root / "atlaso.db"
    database_backup.write_text("previous database", encoding="utf-8")
    database = tmp_path / "atlaso.db"
    database.write_text("candidate database", encoding="utf-8")
    finalizer = tmp_path / "finalizer.json"
    finalizer.write_text(
        json.dumps(
            {
                "status": "restart_pending",
                "job_id": "job-stale-owner",
                "release": "0.9.159",
                "candidate_version": "0.9.159",
                "previous_version": "0.9.158",
                "transaction_recovery": {
                    "schema_version": 1,
                    "owner": {"boot_id": "previous-boot", "pid": 101, "start_ticks": "1"},
                },
                "commands": [],
            }
        ),
        encoding="utf-8",
    )
    gate = tmp_path / "restart-gate"
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_RESTART_GATE_PATH", gate)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: False)

    def restore_link(target, link):
        """Replace the test release link without relying on Windows rename semantics.

        Args:
            target: Release directory that should become active.
            link: Compatibility link to replace.
        """
        link.unlink(missing_ok=True)
        link.symlink_to(target, target_is_directory=True)

    monkeypatch.setattr(helper, "_atomic_symlink", restore_link)
    monkeypatch.setattr(
        helper,
        "_validated_release_recovery_context",
        lambda _payload: {
            "previous": previous,
            "candidate": candidate,
            "backup_root": backup_root,
            "database_backup": database_backup,
            "file_backups": [],
        },
    )
    monkeypatch.setattr(
        helper,
        "_service_command",
        lambda action, *units: {
            "command": ["systemctl", action, *units],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        },
    )
    maintenance_states: list[bool] = []

    def maintenance(enabled):
        """Record whether reboot recovery closes or opens the front door.

        Args:
            enabled: Whether maintenance must remain enabled.
        """
        maintenance_states.append(enabled)
        return {
            "command": ["maintenance", str(enabled)],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_set_release_maintenance", maintenance)
    monkeypatch.setattr(
        helper,
        "_wait_for_atlaso_health",
        lambda: {"command": ["health"], "returncode": 0, "success": True, "stdout": "", "stderr": ""},
    )
    monkeypatch.setattr(helper, "_refresh_release_data_disk_identity", lambda **_kwargs: [])
    monkeypatch.setattr(helper, "_restore_release_owned_files", lambda _backups: None)
    monkeypatch.setattr(helper, "_restore_sqlite_backup", lambda source: database.write_bytes(source.read_bytes()))
    monkeypatch.setattr(
        helper,
        "_sync_release_activation",
        lambda: {
            "command": ["sync"],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        },
    )
    monkeypatch.setattr(
        helper,
        "_release_activation_verification",
        lambda *_args, **_kwargs: (
            {"success": True, "candidate_version": "0.9.158", "failure_layer": ""},
            [{"command": ["front-door"], "returncode": 0, "success": True, "stdout": "", "stderr": ""}],
        ),
    )
    def write_status(_payload):
        """Persist status or inject the post-finalizer status failure.

        Args:
            _payload: Reboot rollback status selected for publication.
        """
        if not status_write_success:
            raise OSError("injected reboot status failure")

    monkeypatch.setattr(helper, "_write_update_info", write_status)
    if not finalizer_write_success:
        def fail_finalizer(_payload):
            """Inject failure before definitive reboot rollback evidence is durable.

            Args:
                _payload: Definitive rollback evidence rejected by the test.
            """
            raise OSError("injected reboot finalizer failure")

        monkeypatch.setattr(helper, "_write_release_finalizer", fail_finalizer)
    candidate_recovery: list[Path] = []

    def recover_candidate(release):
        """Record candidate recovery while its release directory remains present.

        Args:
            release: Candidate release selected for one-shot recovery.
        """
        assert release.is_dir()
        assert current.resolve() == previous.resolve()
        assert maintenance_states[-1] is True
        pending = json.loads(finalizer.read_text(encoding="utf-8"))
        assert pending["status"] == "rollback_pending"
        assert pending["rolled_back"] is False
        assert pending["bookkeeping_pending"] is True
        candidate_recovery.append(release)
        return {
            "command": ["candidate-recovery"],
            "returncode": 0 if bookkeeping_success else 1,
            "success": bookkeeping_success,
            "stdout": "",
            "stderr": "" if bookkeeping_success else "bookkeeping failed",
        }

    monkeypatch.setattr(helper, "_run_candidate_release_recovery", recover_candidate)

    result = helper._recover_interrupted_release_transaction()

    persisted = json.loads(finalizer.read_text(encoding="utf-8"))
    if not finalizer_write_success:
        assert result["success"] is False
        assert result["allow_worker"] is False
        assert result["rolled_back"] is False
        assert persisted["status"] == "restart_pending"
        assert maintenance_states[-1] is True
        assert not candidate_recovery
        assert candidate.exists()
        assert gate.exists()
        return
    if not status_write_success:
        assert result["success"] is False
        assert result["allow_worker"] is False
        assert result["rolled_back"] is False
        assert persisted["status"] == "rollback_pending"
        assert persisted["rolled_back"] is False
        assert maintenance_states[-1] is True
        assert not candidate_recovery
        assert candidate.exists()
        assert gate.exists()
        return
    assert result["success"] is bookkeeping_success, result
    assert result["allow_worker"] is bookkeeping_success
    assert result["rolled_back"] is bookkeeping_success
    assert persisted["status"] == ("failed" if bookkeeping_success else "rollback_pending")
    assert persisted["rolled_back"] is bookkeeping_success
    assert current.resolve() == previous.resolve()
    assert database.read_text(encoding="utf-8") == "previous database"
    assert candidate_recovery == [candidate]
    assert candidate.exists() is (not bookkeeping_success)
    assert gate.exists() is (not bookkeeping_success)


def test_release_startup_guard_holds_maintenance_before_control_plane(monkeypatch, tmp_path):
    """Verify provisional reboot evidence closes nginx before services can start.

    Args:
        monkeypatch: Pytest fixture used to replace helper paths and nginx validation.
        tmp_path: Temporary directory provided for startup-guard evidence.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    finalizer = tmp_path / "finalizer.json"
    finalizer.write_text(
        json.dumps(
            {
                "status": "restart_pending",
                "job_id": "job-startup-guard",
                "transaction_recovery": {
                    "owner": {"boot_id": "previous", "pid": 10, "start_ticks": "1"}
                },
            }
        ),
        encoding="utf-8",
    )
    maintenance = tmp_path / "run/atlaso-update-maintenance"
    management_site = tmp_path / "management.conf"
    management_site.write_text(
        "server {\n  listen 80 default_server;\n}\n"
        "server {\n  listen 443 ssl default_server;\n}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_site)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "valid", ""),
    )

    result = helper._guard_interrupted_release_startup()

    assert result["success"] is True
    assert maintenance.is_file()
    assert management_site.read_text(encoding="utf-8").count(
        f"if (-f {maintenance}) {{ return 503; }}"
    ) == 2


def test_release_prestart_runs_candidate_bookkeeping_as_atlaso(monkeypatch, tmp_path):
    """Verify reboot recovery retains candidate code for one bounded worker handoff.

    Args:
        monkeypatch: Pytest fixture used to replace helper command execution.
        tmp_path: Temporary directory provided for candidate and environment paths.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    candidate = tmp_path / "releases/0.9.159"
    python = candidate / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    environment = tmp_path / "atlaso.env"
    environment.write_text("ATLASO_DATABASE_URL=sqlite:////var/lib/atlaso/atlaso.db\n", encoding="utf-8")
    captured: list[tuple[list[str], float | None]] = []
    monkeypatch.setattr(helper, "ATLASO_ENV_PATH", environment)
    monkeypatch.setattr(helper, "ATLASO_STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda command: "/usr/bin/systemd-run" if command == "systemd-run" else None,
    )

    def run(command, *, timeout=None, env=None):
        """Capture the candidate recovery command without exposing environment contents.

        Args:
            command: Command and arguments selected by reboot recovery.
            timeout: Maximum command duration.
            env: Optional process environment, which must remain unused here.
        """
        assert env is None
        captured.append((command, timeout))
        return subprocess.CompletedProcess(command, 0, "bookkeeping complete", "")

    monkeypatch.setattr(helper, "_run", run)

    result = helper._run_candidate_release_recovery(candidate)

    assert result["success"] is True
    command, timeout = captured[0]
    assert timeout == 1800
    assert command[:6] == [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--service-type=exec",
    ]
    assert "--uid=atlaso" in command
    assert "--gid=atlaso" in command
    assert f"--property=EnvironmentFile={environment}" in command
    assert "--setenv=ATLASO_RELEASE_RECOVERY_ONLY=1" in command
    assert command[-3:] == [str(python), "-m", "atlaso.app.worker"]


def test_release_recovery_manifest_accepts_the_migrated_esx_allowlist(monkeypatch, tmp_path):
    """Verify reboot recovery validates the ESX claim backup added after migration.

    Args:
        monkeypatch: Pytest fixture used to replace helper paths.
        tmp_path: Temporary directory provided for bounded recovery state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    releases = tmp_path / "releases"
    previous = releases / "0.9.158"
    candidate = releases / "0.9.159"
    previous.mkdir(parents=True)
    candidate.mkdir()
    backups = tmp_path / "backups"
    backup_root = backups / "transaction"
    backup_root.mkdir(parents=True)
    database_backup = backup_root / "atlaso.db"
    database_backup.write_bytes(b"database")
    allowlist = tmp_path / "host/etc/atlaso/esx-storage-disks.conf"
    allowlist.parent.mkdir(parents=True)
    allowlist.write_text("claim\n", encoding="utf-8")
    allowlist_backup = backup_root.joinpath(*allowlist.parts[1:])
    allowlist_backup.parent.mkdir(parents=True)
    allowlist_backup.write_bytes(allowlist.read_bytes())
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", releases)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", backups)
    monkeypatch.setattr(helper, "ESX_STORAGE_DISK_ALLOWLIST_PATH", allowlist)

    context = helper._validated_release_recovery_context(
        {
            "transaction_recovery": {
                "schema_version": 1,
                "previous_release": str(previous),
                "candidate_release": str(candidate),
                "backup_root": str(backup_root),
                "database_backup": str(database_backup),
                "database_backed_up": True,
                "file_backups": [
                    {
                        "backup": str(allowlist_backup),
                        "destination": str(allowlist),
                    }
                ],
            }
        }
    )

    assert context["file_backups"] == [(allowlist_backup.resolve(), allowlist)]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"version": "2026.05.1"}, "X.Y.Z\\+revision"),
        ({"architecture": "aarch64"}, "x86_64"),
        ({"package": {"size": 0}}, "size"),
        ({"package": {"size": 2 * 1024 * 1024 * 1024 + 1}}, "size"),
        ({"package": {"sha256": "nope"}}, "SHA256"),
        ({"package": {"url": "http://github.com/example.zip"}}, "HTTPS URL"),
        ({"package": {"url": "https://example.test/example.zip"}}, "dedicated Atlaso release tag"),
        (
            {
                "package": {
                    "url": "https://github.com/mdaneri/Atlaso/releases/download/inventory-linux-v2026.05.1%2B9/atlaso-inventory-linux-2026.05.1%2B8.zip"
                }
            },
            "dedicated Atlaso release tag",
        ),
    ],
)
def test_inventory_release_manifest_fails_closed(mutation, message):
    """Verify that inventory release manifest fails closed.

    Args:
        mutation: Mutation supplied to the test scenario.
        message: Human-readable message associated with the operation.
    """
    payload = inventory_payload()
    for key, value in mutation.items():
        if key == "package":
            payload["package"].update(value)
        else:
            payload[key] = value
    with pytest.raises(ReleaseManifestError, match=message):
        validate_inventory_release_manifest(payload)


def test_inventory_version_order_includes_revision():
    """Verify that inventory version order includes revision."""
    assert inventory_version_tuple("2026.05.1+8") > inventory_version_tuple("2026.05.1+7")
    assert inventory_version_tuple("2026.06.0+1") > inventory_version_tuple("2026.05.99+99")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("updater_protocol", 0, "updater_protocol"),
        ("database_schema_version", 0, "database_schema_version"),
        ("version", "0.9", "semantic versioning"),
        ("built_at", "not-a-time", "ISO 8601"),
    ],
)
def test_release_manifest_requires_complete_v2_interface(field, value, message):
    """Verify that release manifest requires complete v2 interface.

    Args:
        field: Field supplied to the test scenario.
        value: Candidate value consumed by test release manifest requires complete v2 interface.
        message: Human-readable message associated with the operation.
    """
    payload = release_payload()
    payload[field] = value
    with pytest.raises(ReleaseManifestError, match=message):
        validate_release_manifest(payload)


def test_release_manifest_rejects_non_appliance_python_abi():
    """Verify that release manifest rejects non appliance python abi."""
    payload = release_payload()
    payload["supported_python_abis"] = ["cp313"]
    with pytest.raises(ReleaseManifestError, match="supported_python_abis"):
        validate_release_manifest(payload)


def test_release_manifest_validates_optional_summary_and_release_notes():
    """Keep optional v2 publication metadata backward compatible and credential free."""
    legacy = release_payload()
    assert validate_release_manifest(legacy) is legacy

    enriched = release_payload()
    enriched["summary"] = "Improve durable update visibility"
    enriched["release_notes_url"] = "https://github.com/mdaneri/Atlaso/releases/tag/v0.9.0"
    assert validate_release_manifest(enriched) is enriched

    for value, message in (
        ({"summary": "first\nsecond"}, "summary"),
        ({"summary": "x" * 241}, "summary"),
        ({"release_notes_url": "http://example.test/release"}, "HTTPS URL"),
        ({"release_notes_url": "https://user:secret@example.test/release"}, "HTTPS URL"),
        ({"release_notes_url": "https://example.test/" + "a" * 2049}, "at most 2048"),
    ):
        payload = release_payload()
        payload.update(value)
        with pytest.raises(ReleaseManifestError, match=message):
            validate_release_manifest(payload)


def test_release_bundle_publishes_commit_subject_summary_and_release_link():
    """Keep manifest generation deterministic and tied to the immutable release tag."""
    source = (ROOT / "scripts/build_release_bundle.py").read_text(encoding="utf-8")
    assert 'git_value(["show", "-s", "--format=%s", commit])' in source
    assert '"summary": release_summary' in source
    assert '"release_notes_url": f"https://github.com/mdaneri/Atlaso/releases/tag/v{version}"' in source


def test_release_workflows_use_successful_main_sha_and_promote_without_rebuilding():
    """Verify that release workflows use successful main sha and promote without rebuilding."""
    publication = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    prerelease = (ROOT / ".github/workflows/virtualization-prerelease.yml").read_text(
        encoding="utf-8"
    )
    virtualization = (ROOT / ".github/workflows/virtualization-stable.yml").read_text(
        encoding="utf-8"
    )
    windows_candidate = (
        ROOT / ".github/workflows/virtualization-windows-candidate.yml"
    ).read_text(encoding="utf-8")
    index_builder = (
        ROOT / "scripts/build_virtualization_artifact_index.py"
    ).read_text(encoding="utf-8")
    inventory = (ROOT / ".github/workflows/inventory-linux-release.yml").read_text(
        encoding="utf-8"
    )
    inventory_publisher = (
        ROOT / "scripts/publish_inventory_linux_release.py"
    ).read_text(encoding="utf-8")
    promotion = (ROOT / ".github/workflows/promote-release.yml").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "github.event.workflow_run.head_branch == 'main'" in publication
    assert "github.event.workflow_run.event == 'push'" in publication
    assert (
        publication.count(
            "github.event.workflow_run.head_repository.full_name == github.repository"
        )
        == 1
    )
    assert "github.event_name == 'workflow_dispatch'" in publication
    assert "vars.AUTOMATIC_SOFTWARE_RELEASE_ENABLED == 'true'" in publication
    assert "-f head_sha=\"$RELEASE_SHA\"" in publication
    assert "-f status=success" in publication
    assert "has no successful main push CI run" in publication
    assert "legacy bridge" not in publication
    assert 'cat > "$SITE_ROOT/index.html"' in publication
    assert "Everything your virtualization lab needs." in publication
    assert "Infrastructure • Storage • Identity • Networking • Lifecycle" in publication
    assert "The HTML page is informational." in publication
    assert "python scripts/check_published_release_channel.py" in publication
    assert "--expected-channel development" in publication
    publication_check = publication.split(
        "- name: Verify the published development channel",
        1,
    )[1]
    assert "/updates/channels/development/manifest.json" in publication_check
    assert '--expected-version "$VERSION"' in publication_check
    assert '--expected-commit "$RELEASE_SHA"' in publication_check
    assert "<script" not in publication
    assert publication.count("ref: ${{ needs.prepare.outputs.release_sha }}") == 2
    assert "actions/upload-artifact@v7" in publication
    assert publication.count("actions/download-artifact@v8") == 1
    for runner_label in ("atlaso-vmware", "atlaso-proxmox", "atlaso-kvm", "atlaso-hyperv"):
        assert runner_label not in publication
    for job in (
        "vmware_ova_build",
        "vmware_ova_smoke",
        "proxmox_ova_smoke",
        "kvm_ova_smoke",
        "hyperv_package",
        "hyperv_smoke",
        "virtualization_release",
    ):
        assert f"  {job}:" not in publication
    ci_packer = ci.split("  deployment-packer:", 1)[1].split("  python-tests:", 1)[0]
    assert "Test-AtlasoVirtualizationArtifacts.ps1" in ci_packer
    assert "Test-AtlasoHyperVSecureString.ps1" not in ci_packer
    assert "build_virtualization_artifact_index.py" not in publication
    assert "--require-virtualization-assets" not in publication
    assert "runs-on: [self-hosted, Linux, X64" in virtualization
    assert "proxmox_smoke" in virtualization
    assert "kvm_smoke" in virtualization
    assert "permissions: {}" not in virtualization
    assert "RELEASE_SIGNING_PRIVATE_KEY" not in virtualization.split("  proxmox_smoke:", 1)[1].split(
        "  kvm_smoke:", 1
    )[0]
    assert "RELEASE_SIGNING_PRIVATE_KEY" not in virtualization.split("  kvm_smoke:", 1)[1].split(
        "  publish:", 1
    )[0]
    assert "gh release edit \"$STABLE_TAG\" --draft=false" in virtualization
    assert "run-name: Promote ${{ inputs.prerelease_tag }}" in virtualization
    assert "group: atlaso-virtualization-stable" in virtualization
    assert "group: virtualization-stable-${{ inputs.prerelease_tag }}" not in virtualization
    assert 'test "$(jq -r .isPrerelease <<<"$STATE")" = false' in virtualization
    assert "cmp --silent" in virtualization
    assert "gh-pages" not in virtualization
    assert "environment: appliance-release" in prerelease
    assert "run-name: Finalize ${{ inputs.prerelease_tag }}" in prerelease
    assert "--classification prerelease" in prerelease
    assert "gh release edit \"$RELEASE_TAG\" --draft=false --prerelease --verify-tag" in prerelease
    assert "already_published=true" in prerelease
    assert "steps.identity.outputs.already_published != 'true'" in prerelease
    assert (
        'gh release view "$RELEASE_TAG" --repo "${{ github.repository }}"'
        in prerelease
    )
    assert (
        'gh release view "$PRERELEASE_TAG" --repo "${{ github.repository }}"'
        in virtualization
    )
    assert "verify_vmware_release_assets(" in index_builder
    assert "ref: ${{ inputs.release_sha }}" not in prerelease
    assert "ref: refs/heads/main" in prerelease
    assert "gh-pages" not in prerelease
    windows_job = windows_candidate.split("  produce:\n", 1)[1].split(
        "  stage_draft:\n", 1
    )[0]
    assert "runs-on: [self-hosted, Windows, X64" in windows_job
    assert "contents: read" in windows_job
    assert "contents: write" not in windows_job
    assert "RELEASE_SIGNING_PRIVATE_KEY" not in windows_job
    assert "-CandidateOnly" in windows_job
    assert "ref: ${{ inputs.release_sha }}" not in windows_candidate
    assert "ref: ${{ needs.admit.outputs.release_sha }}" in windows_job
    assert windows_candidate.count("ref: refs/heads/main") == 2
    assert 'git checkout --detach "$RELEASE_SHA"' in windows_candidate
    assert "comm -23" in windows_candidate
    assert "ATLASO_ONEPASSWORD_ENVIRONMENT_ID" in windows_job
    assert "ATLASO_ONEPASSWORD_ACCOUNT" in windows_job
    assert "ATLASO_ONEPASSWORD_PYTHON" in windows_job
    assert "uses: ./.github/workflows/virtualization-prerelease.yml" in windows_candidate
    stage_draft = windows_candidate.split("  stage_draft:\n", 1)[1].split(
        "  finalize:\n", 1
    )[0]
    assert "contents: write" in stage_draft
    assert "persist-credentials: true" in stage_draft
    assert "already_published: ${{ steps.target.outputs.already_published }}" in windows_candidate
    assert "gh api graphql" in windows_candidate
    assert "if test \"$STATE\" != null" in windows_candidate
    assert "2>/dev/null" not in windows_candidate.split("  produce:\n", 1)[0]
    assert 'test "$WINDOWS_RUNNER_LABEL" = "$EXPECTED_WINDOWS_LABEL"' in windows_candidate
    assert windows_candidate.count("if: needs.admit.outputs.already_published != 'true'") == 2
    assert "needs.admit.outputs.already_published == 'true'" in windows_candidate
    assert "needs.stage_draft.result == 'success'" in windows_candidate
    assert "ref: ${{ steps.identity.outputs.release_sha }}" not in virtualization
    assert "ref: ${{ needs.admit.outputs.release_sha }}" not in virtualization
    assert virtualization.count("ref: refs/heads/main") == 4
    assert 'test "$PROXMOX_RUNNER_LABEL" = "atlaso-proxmox-$LABEL_SUFFIX"' in virtualization
    assert 'test "$KVM_RUNNER_LABEL" = "atlaso-kvm-$LABEL_SUFFIX"' in virtualization
    assert "python-version: '3.14'" in publication
    assert "python-version: '3.14'" in promotion
    assert ci.count("python-version: '3.14'") == 3
    assert "cp312" not in publication
    assert "cp313" not in publication
    assert "actions/upload-artifact@v4" not in publication
    assert "actions/download-artifact@v4" not in publication
    assert '--commit "$RELEASE_SHA"' in publication
    assert "--expected-version \"$VERSION\"" in publication
    assert '--site-root "$SITE_ROOT/updates"' in publication
    assert 'test "$VERSION" = "0.9.18"' in publication
    assert "gh release download" in promotion
    assert "build_release_bundle.py" not in promotion
    assert "--expected-version \"$RELEASE_VERSION\"" in promotion
    assert "python scripts/check_published_release_channel.py" in promotion
    assert '--expected-channel "$RELEASE_CHANNEL"' in promotion
    promotion_check = promotion.split(
        "- name: Verify the published signed channel",
        1,
    )[1]
    assert '--expected-version "$RELEASE_VERSION"' in promotion_check
    assert '--expected-commit "$RELEASE_COMMIT"' in promotion_check
    assert "workflow_dispatch:" in inventory
    assert "workflow_run:" not in inventory
    assert "schedule:" not in inventory
    assert "environment: appliance-release" in inventory
    assert '-f head_sha="$RELEASE_SHA"' in inventory
    assert "-f branch=main" in inventory
    assert "-f event=push" in inventory
    assert "-f status=success" in inventory
    assert "has no successful main push CI run" in inventory
    assert "--latest=false" in inventory_publisher
    assert '"--draft"' not in inventory_publisher
    assert '"--prerelease"' not in inventory_publisher
    assert "inventory-linux-v" not in publication
    assert "--inventory-package" not in publication
    assert "development" not in inventory
    assert "preview" not in inventory
    assert "staging" not in inventory


def test_published_channel_check_verifies_pointer_release_and_compatibility(
    trust,
    monkeypatch,
):
    """Verify the live guard reaches signed release and ABI validation.

    Args:
        trust: Trust supplied to the test scenario.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    private_key, trust_dir = trust
    channel_url = "https://updates.example.test/channels/stable/manifest.json"
    release_url = "https://github.com/example/releases/download/v0.9.0/release-manifest.json"
    release = release_payload()
    channel = {
        "schema_version": 2,
        "kind": "atlaso-channel",
        "channel": "stable",
        "version": release["version"],
        "git_commit": release["git_commit"],
        "release_manifest_url": release_url,
        "issued_at": "2026-08-13T12:00:00Z",
        "signing_key_id": KEY_ID,
    }
    raw_channel, channel_signature = signed(channel, private_key)
    raw_release, release_signature = signed(release, private_key)
    documents = {
        channel_url: raw_channel,
        f"{channel_url}.sig": channel_signature,
        release_url: raw_release,
        f"{release_url}.sig": release_signature,
    }
    monkeypatch.setattr(
        published_channel_check,
        "fetch_document",
        lambda url, **_kwargs: documents[url],
    )

    result = published_channel_check.verify_channel(
        channel_url,
        expected_channel="stable",
        expected_version="0.9.0",
        expected_commit="a" * 40,
        expected_python_abi="cp314",
        trusted_key=trust_dir / f"{KEY_ID}.pem",
        timeout_seconds=30,
        deadline=published_channel_check.time.monotonic() + 65.0,
    )

    assert result["channel"]["version"] == "0.9.0"
    assert result["release"]["git_commit"] == "a" * 40

    with pytest.raises(ValueError, match="does not support cp313"):
        published_channel_check.verify_channel(
            channel_url,
            expected_channel="stable",
            expected_version="0.9.0",
            expected_commit="a" * 40,
            expected_python_abi="cp313",
            trusted_key=trust_dir / f"{KEY_ID}.pem",
            timeout_seconds=30,
            deadline=published_channel_check.time.monotonic() + 65.0,
        )

    with pytest.raises(ValueError, match="expected v0.9.1"):
        published_channel_check.verify_channel(
            channel_url,
            expected_channel="stable",
            expected_version="0.9.1",
            expected_commit="b" * 40,
            expected_python_abi="cp314",
            trusted_key=trust_dir / f"{KEY_ID}.pem",
            timeout_seconds=30,
            deadline=published_channel_check.time.monotonic() + 65.0,
        )


@pytest.mark.parametrize(
    ("deadline", "expected_timeout"),
    [(10.0, 10.0), (60.0, 30.0)],
)
def test_published_channel_check_cancels_fetch_worker_at_deadline(
    monkeypatch,
    deadline: float,
    expected_timeout: float,
):
    """Verify fetches cannot extend the request or publication deadline.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        deadline: Absolute publication deadline supplied to the fetch.
        expected_timeout: Tighter request or publication timeout expected in the parent.
    """
    command: list[str] = []
    worker_timeout = 0.0

    def run(args, *, capture_output, check, timeout):
        """Simulate a fetch worker that reaches its parent-enforced timeout.

        Args:
            args: Worker command arguments supplied to the subprocess runner.
            capture_output: Whether the subprocess runner captures standard streams.
            check: Whether the subprocess runner raises for a nonzero exit code.
            timeout: Parent-enforced timeout for the worker process.
        """
        nonlocal command, worker_timeout
        command = args
        worker_timeout = timeout
        raise subprocess.TimeoutExpired(args, timeout)

    monkeypatch.setattr(published_channel_check.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(published_channel_check.subprocess, "run", run)

    with pytest.raises(TimeoutError, match="publication window"):
        published_channel_check.fetch_document(
            "https://updates.example.test/manifest.json",
            timeout_seconds=30.0,
            deadline=deadline,
        )

    assert command[2] == published_channel_check.FETCH_WORKER_FLAG
    assert command[3] == "https://updates.example.test/manifest.json"
    assert command[4] == str(expected_timeout)
    assert worker_timeout == expected_timeout


def test_published_channel_check_imports_atlaso_from_a_clean_checkout(tmp_path: Path):
    """Verify direct workflow execution imports Atlaso without an installation.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts" / "check_published_release_channel.py"),
            "--help",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Verify a published Atlaso channel" in result.stdout


def test_published_channel_check_caps_requests_and_sleeps_to_publication_window(
    trust,
    monkeypatch,
):
    """Verify slow requests cannot exceed the bounded publication window.

    Args:
        trust: Trust supplied to the test scenario.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    _private_key, trust_dir = trust
    clock = 0.0
    request_timeouts: list[float] = []

    def monotonic() -> float:
        return clock

    def verify_channel(*_args, timeout_seconds: float, deadline: float, **_kwargs):
        """Simulate one verification attempt consuming its request budget.

        Args:
            *_args: Positional verifier arguments unused by the simulation.
            timeout_seconds: Configured per-request timeout.
            deadline: Absolute publication deadline for the verification attempt.
            **_kwargs: Keyword verifier arguments unused by the simulation.
        """
        nonlocal clock
        effective_timeout = min(timeout_seconds, deadline - clock)
        request_timeouts.append(effective_timeout)
        clock += effective_timeout
        raise TimeoutError("publication request timed out")

    def sleep(seconds: float) -> None:
        """Advance the simulated clock instead of sleeping.

        Args:
            seconds: Simulated sleep interval in seconds.
        """
        nonlocal clock
        clock += seconds

    monkeypatch.setattr(published_channel_check.time, "monotonic", monotonic)
    monkeypatch.setattr(published_channel_check.time, "sleep", sleep)
    monkeypatch.setattr(published_channel_check, "verify_channel", verify_channel)

    with pytest.raises(SystemExit, match="failed verification after 2 attempt"):
        published_channel_check.main(
            [
                "--channel-url",
                "https://updates.example.test/channels/stable/manifest.json",
                "--expected-channel",
                "stable",
                "--expected-version",
                "0.9.0",
                "--expected-commit",
                "a" * 40,
                "--trusted-key",
                str(trust_dir / f"{KEY_ID}.pem"),
                "--publication-window-seconds",
                "65",
                "--retry-delay-seconds",
                "10",
                "--timeout-seconds",
                "30",
            ]
        )

    assert request_timeouts == [30.0, 25.0]
    assert clock == 65.0


def test_published_channel_check_fails_when_default_pointer_is_absent(
    trust,
    monkeypatch,
):
    """Verify the live guard reports a missing default channel.

    Args:
        trust: Trust supplied to the test scenario.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    _private_key, trust_dir = trust
    monkeypatch.setattr(
        published_channel_check,
        "fetch_document",
        lambda url, **_kwargs: (_ for _ in ()).throw(
            HTTPError(url, 404, "Not Found", {}, None)
        ),
    )

    with pytest.raises(SystemExit, match="failed verification.*404"):
        published_channel_check.main(
            [
                "--channel-url",
                "https://updates.example.test/channels/stable/manifest.json",
                "--expected-channel",
                "stable",
                "--expected-version",
                "0.9.0",
                "--expected-commit",
                "a" * 40,
                "--trusted-key",
                str(trust_dir / f"{KEY_ID}.pem"),
                "--attempts",
                "1",
            ]
        )


def test_pages_writers_share_multi_entry_publication_queue():
    """Verify every Pages writer preserves multiple pending publications."""
    workflow_root = ROOT / ".github" / "workflows"
    writers: set[Path] = set()
    queue_users: set[Path] = set()

    for path in workflow_root.glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if "HEAD:gh-pages" in text:
            writers.add(path)
            assert 'test -s "$SITE_ROOT/updates/channels/stable/manifest.json"' in text, path
            assert 'test -s "$SITE_ROOT/updates/channels/stable/manifest.json.sig"' in text, path
        if "group: atlaso-github-pages" not in text:
            continue
        queue_users.add(path)
        for declaration in text.split("group: atlaso-github-pages")[1:]:
            settings = "\n".join(declaration.splitlines()[:3])
            assert "queue: max" in settings, path
            assert "cancel-in-progress: false" in settings, path

    assert writers
    assert queue_users == writers

    inventory = (workflow_root / "inventory-linux-release.yml").read_text(
        encoding="utf-8"
    )
    build_job, publish_job = inventory.split("  build:\n", 1)[1].split(
        "  publish:\n", 1
    )
    assert "atlaso-github-pages" not in build_job
    assert "actions/upload-artifact@v7" in build_job
    assert "group: atlaso-github-pages" in publish_job
    assert "actions/download-artifact@v8" in publish_job
    assert "HEAD:gh-pages" in publish_job


def test_idempotent_publisher_refuses_existing_tag_for_another_commit(monkeypatch, tmp_path):
    """Verify that idempotent publisher refuses existing tag for another commit.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    spec = importlib.util.spec_from_file_location("publish_release", ROOT / "scripts/publish_release.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "release-manifest.json").write_text("{}", encoding="utf-8")
    requested = "a" * 40
    existing = "b" * 40

    def fake_run(command, *, check=True):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            check: Whether a nonzero command status raises an exception.


        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        import subprocess

        if command[:3] == ["git", "ls-remote", "--tags"]:
            return subprocess.CompletedProcess(command, 0, f"{existing}\trefs/tags/v0.9.0\n", "")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(module, "run", fake_run)
    monkeypatch.setattr(module, "version", lambda: "0.9.0")
    monkeypatch.setattr(
        "sys.argv",
        ["publish_release.py", "--commit", requested, "--assets", str(assets)],
    )
    with pytest.raises(SystemExit, match="already identifies"):
        module.main()


def test_idempotent_publisher_creates_annotated_tag_without_global_git_identity(
    monkeypatch,
    tmp_path,
):
    """Verify that idempotent publisher creates annotated tag without global git identity.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    spec = importlib.util.spec_from_file_location("publish_release", ROOT / "scripts/publish_release.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "release-manifest.json").write_text("{}", encoding="utf-8")
    requested = "a" * 40
    commands: list[list[str]] = []

    def fake_run(command, *, check=True):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            check: Whether a nonzero command status raises an exception.
        """
        import subprocess

        commands.append(command)
        if command[:3] == ["git", "ls-remote", "--tags"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["gh", "release", "view"]:
            return subprocess.CompletedProcess(command, 1, "", "release not found")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(module, "run", fake_run)
    monkeypatch.setattr(module, "version", lambda: "0.9.0")
    monkeypatch.setattr(
        "sys.argv",
        ["publish_release.py", "--commit", requested, "--assets", str(assets)],
    )

    assert module.main() == 0
    tag_command = next(command for command in commands if "tag" in command)
    assert tag_command[:6] == [
        "git",
        "-c",
        "user.name=github-actions[bot]",
        "-c",
        "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "tag",
    ]
    assert ["git", "push", "origin", "refs/tags/v0.9.0"] in commands


def test_deterministic_release_archive_normalizes_metadata(tmp_path):
    """Verify that deterministic release archive normalizes metadata.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    spec = importlib.util.spec_from_file_location("build_release_bundle", ROOT / "scripts/build_release_bundle.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source"
    source.mkdir()
    (source / "z.txt").write_text("same\n", encoding="utf-8")
    (source / "a").mkdir()
    (source / "a/data.txt").write_text("content\n", encoding="utf-8")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    module.deterministic_tar_gz(source, first)
    os.utime(source / "z.txt", (2_000_000_000, 2_000_000_000))
    module.deterministic_tar_gz(source, second)
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()


def test_release_bundle_carries_transactional_data_disk_safety_assets():
    """Verify that signed release bundles carry every runtime disk-safety asset."""
    spec = importlib.util.spec_from_file_location("build_release_bundle", ROOT / "scripts/build_release_bundle.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    destinations = {destination.as_posix() for _source, destination in module.RELEASE_OWNED_ASSETS}
    assert {
        "bin/atlaso-mount-data-disks",
        "bin/atlaso-select-guest-agent",
        "bin/atlaso-initialize-machine-identity.py",
        "data-disks/hyperv.conf",
        "data-disks/virtualization.conf",
        "data-disks/vmware.conf",
        "systemd/atlaso-bootstrap-https.service",
        "systemd/atlaso-data-disks.service",
        "systemd/atlaso-data-disks-legacy.service",
        "systemd/atlaso-guest-agent-select.service",
        "systemd/atlaso.service.d/atlaso-data-disks.conf",
        "systemd/nginx.service.d/atlaso-data-disks.conf",
        "udev/99-atlaso-disk-identity.rules",
    } <= destinations


def test_signed_updates_install_and_rollback_every_first_boot_asset(tmp_path):
    """Bind bundled first-boot assets to their live updater-owned destinations.

    Args:
        tmp_path: Temporary release root used to verify source mappings.
    """

    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    owned = helper._release_first_boot_owned_files(tmp_path)

    assert owned == [
        (
            tmp_path / "bin/atlaso-select-guest-agent",
            helper.ATLASO_GUEST_AGENT_SELECTOR_PATH,
            0o755,
        ),
        (
            tmp_path / "bin/atlaso-initialize-machine-identity.py",
            helper.ATLASO_MACHINE_IDENTITY_INITIALIZER_PATH,
            0o755,
        ),
        (
            tmp_path / "systemd/atlaso-guest-agent-select.service",
            helper.ATLASO_GUEST_AGENT_SELECT_UNIT_PATH,
            0o644,
        ),
    ]


def test_legacy_release_uses_data_disk_unit_without_new_selector_dependency(tmp_path):
    """An older appliance can install the disk boundary without unavailable selector assets.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """

    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    owned = helper._release_data_disk_owned_files(tmp_path, "vmware")
    unit_sources = [source for source, destination, _mode in owned if destination == helper.ATLASO_DATA_DISK_UNIT_PATH]
    assert unit_sources == [tmp_path / "systemd/atlaso-data-disks-legacy.service"]


def test_image_bootstrap_release_skips_previous_updater_compatibility_gate(monkeypatch, tmp_path):
    """Keep fresh-image startup independent of candidate-only release assets.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    releases = tmp_path / "opt/atlaso/releases"
    release_root = releases / "bootstrap-0.9.131"
    release_root.mkdir(parents=True)
    (release_root / "bundle-metadata.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": "0.9.131",
                "bootstrap": True,
                "supported_python_abis": ["cp314"],
            }
        ),
        encoding="utf-8",
    )
    current = tmp_path / "opt/atlaso/current"
    current.symlink_to(release_root, target_is_directory=True)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", releases)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    marker = tmp_path / "etc/atlaso/data-disk-safety-bootstrap.json"
    monkeypatch.setattr(helper, "ATLASO_DATA_DISK_BOOTSTRAP_MARKER_PATH", marker)
    monkeypatch.setattr(
        helper,
        "_release_data_disk_platform",
        lambda: (_ for _ in ()).throw(
            AssertionError("fresh image must not enter candidate compatibility bootstrap")
        ),
    )
    assert helper._bootstrap_release_data_disk_safety(release_root) == []
    assert json.loads(marker.read_text(encoding="utf-8")) == {"schema_version": 1, "status": "complete"}
    if os.name == "posix":
        assert marker.stat().st_mode & 0o777 == 0o600
    assert helper._bootstrap_release_data_disk_safety(release_root) == []


def test_previous_updater_service_bootstraps_every_new_data_disk_safety_asset(monkeypatch, tmp_path):
    """Prove the previous installer can enter the new root bootstrap through atlaso.service.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    release_root = tmp_path / "opt/atlaso/releases/candidate"
    release_root.mkdir(parents=True)
    current = tmp_path / "opt/atlaso/current"
    current.parent.mkdir(parents=True, exist_ok=True)
    current.symlink_to(release_root, target_is_directory=True)
    sources = {
        "bin/atlaso-mount-data-disks": b"mount-script",
        "systemd/atlaso-data-disks.service": b"disk-unit",
        "systemd/atlaso.service.d/atlaso-data-disks.conf": b"atlaso-dropin",
        "systemd/atlaso-bootstrap-https.service": b"bootstrap-unit",
        "systemd/nginx.service.d/atlaso-data-disks.conf": b"nginx-dropin",
        "udev/99-atlaso-disk-identity.rules": b"udev-rule",
        "data-disks/virtualization.conf": b"disk-policy",
    }
    destinations = {
        "ATLASO_MOUNT_DATA_DISKS_PATH": tmp_path / "host/bin/atlaso-mount-data-disks",
        "ATLASO_DATA_DISK_UNIT_PATH": tmp_path / "host/systemd/atlaso-data-disks.service",
        "ATLASO_SERVICE_DATA_DISK_DROPIN_PATH": tmp_path / "host/systemd/atlaso.service.d/atlaso-data-disks.conf",
        "ATLASO_BOOTSTRAP_HTTPS_UNIT_PATH": tmp_path / "host/systemd/atlaso-bootstrap-https.service",
        "ATLASO_NGINX_DATA_DISK_DROPIN_PATH": tmp_path / "host/systemd/nginx.service.d/atlaso-data-disks.conf",
        "ATLASO_DISK_IDENTITY_UDEV_PATH": tmp_path / "host/udev/99-atlaso-disk-identity.rules",
        "ATLASO_DATA_DISK_POLICY_PATH": tmp_path / "host/etc/atlaso/data-disks.conf",
    }
    for relative_path, content in sources.items():
        source = release_root / relative_path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(content)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", release_root.parent)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    marker = tmp_path / "host/etc/atlaso/data-disk-safety-bootstrap.json"
    monkeypatch.setattr(helper, "ATLASO_DATA_DISK_BOOTSTRAP_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "_release_data_disk_platform", lambda: "virtualization")
    for name, destination in destinations.items():
        monkeypatch.setattr(helper, name, destination)
    commands: list[list[str]] = []
    events: list[str] = []

    def command_payload(command, **_kwargs):
        """Return a successful bootstrap command result.

        Args:
            command: Command and arguments issued by the bootstrap.
            **_kwargs: Optional command execution arguments.
        """
        commands.append(command)
        if command == [destinations["ATLASO_MOUNT_DATA_DISKS_PATH"].as_posix()]:
            events.append("preflight")
        return {"command": command, "returncode": 0, "success": True, "stdout": "", "stderr": ""}

    monkeypatch.setattr(helper, "_command_payload", command_payload)
    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        helper,
        "_migrate_release_esx_storage_claims",
        lambda _backup_root, _backups: events.append("migration"),
    )

    helper._bootstrap_release_data_disk_safety(release_root)

    for (relative_path, content), destination in zip(sources.items(), destinations.values(), strict=True):
        assert destination.read_bytes() == content, relative_path
        expected_mode = 0o755 if relative_path == "bin/atlaso-mount-data-disks" else 0o644
        if os.name == "posix":
            assert destination.stat().st_mode & 0o777 == expected_mode, relative_path
    assert ["/usr/bin/udevadm", "control", "--reload-rules"] in commands
    assert [destinations["ATLASO_MOUNT_DATA_DISKS_PATH"].as_posix()] in commands
    assert ["/usr/bin/systemctl", "daemon-reload"] in commands
    assert events == ["migration", "preflight"]
    assert not any((tmp_path / "backups").iterdir())
    assert json.loads(marker.read_text(encoding="utf-8")) == {"schema_version": 1, "status": "complete"}
    assert helper._bootstrap_release_data_disk_safety(release_root) == []
    unit_path = ROOT / "image/common/systemd/atlaso.service"
    assert (
        "ExecStartPre=+/opt/atlaso/bin/atlaso-helper appliance-update "
        "bootstrap-data-disk-safety --real /opt/atlaso/current"
    ) in unit_path.read_text(encoding="utf-8")


def test_previous_updater_bootstrap_restores_assets_claims_and_database(monkeypatch, tmp_path):
    """Restore every compatibility mutation when the first candidate preflight fails.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import sqlite3

    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    release_root = tmp_path / "opt/atlaso/releases/candidate"
    release_root.mkdir(parents=True)
    current = tmp_path / "opt/atlaso/current"
    current.parent.mkdir(parents=True, exist_ok=True)
    current.symlink_to(release_root, target_is_directory=True)
    source = release_root / "safety-asset"
    source.write_bytes(b"candidate-asset")
    destination = tmp_path / "host/safety-asset"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"previous-asset")
    new_source = release_root / "new-safety-asset"
    new_source.write_bytes(b"candidate-new-asset")
    new_destination = tmp_path / "host/new-safety-asset"
    allowlist = tmp_path / "host/esx-storage-disks.conf"
    allowlist.write_text("previous-claim\n", encoding="utf-8")
    database = tmp_path / "host/atlaso.db"
    connection = sqlite3.connect(database)
    try:
        connection.execute("create table bootstrap_state (value text)")
        connection.execute("insert into bootstrap_state values ('previous')")
        connection.commit()
    finally:
        connection.close()

    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", release_root.parent)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    marker = tmp_path / "host/data-disk-safety-bootstrap.json"
    monkeypatch.setattr(helper, "ATLASO_DATA_DISK_BOOTSTRAP_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)
    monkeypatch.setattr(helper, "_release_data_disk_platform", lambda: "virtualization")
    monkeypatch.setattr(
        helper,
        "_release_data_disk_owned_files",
        lambda _release_root, _platform: [
            (source, destination, 0o644),
            (new_source, new_destination, 0o644),
        ],
    )
    events: list[str] = []

    def migrate_claims(backup_root, backups):
        """Simulate the real claim and database migration inside the transaction.

        Args:
            backup_root: Bootstrap transaction backup directory.
            backups: Asset backups extended with the allowlist backup.
        """
        events.append("migration")
        backup = backup_root / "esx-storage-disks.conf"
        backup.write_bytes(allowlist.read_bytes())
        backups.append((backup, allowlist))
        allowlist.write_text("candidate-claim\n", encoding="utf-8")
        connection = sqlite3.connect(database)
        try:
            connection.execute("update bootstrap_state set value = 'candidate'")
            connection.commit()
        finally:
            connection.close()

    def refresh_identity(*, validate):
        """Fail candidate validation and accept the restored identity refresh.

        Args:
            validate: Whether this invocation is the candidate preflight.
        """
        events.append("preflight" if validate else "rollback-refresh")
        return [
            {
                "command": ["disk-preflight" if validate else "udev-refresh"],
                "returncode": 1 if validate else 0,
                "success": not validate,
                "stdout": "",
                "stderr": "unsafe disk" if validate else "",
            }
        ]

    monkeypatch.setattr(helper, "_migrate_release_esx_storage_claims", migrate_claims)
    monkeypatch.setattr(helper, "_refresh_release_data_disk_identity", refresh_identity)
    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        helper,
        "_command_payload",
        lambda command, **_kwargs: {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        },
    )

    with pytest.raises(ValueError, match="prior safety state restored"):
        helper._bootstrap_release_data_disk_safety(release_root)

    assert destination.read_bytes() == b"previous-asset"
    assert not new_destination.exists()
    assert not marker.exists()
    assert not destination.with_suffix(".bootstrap").exists()
    assert not new_destination.with_suffix(".bootstrap").exists()
    assert allowlist.read_text(encoding="utf-8") == "previous-claim\n"
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("select value from bootstrap_state").fetchone()[0] == "previous"
    finally:
        connection.close()
    assert events == ["migration", "preflight", "rollback-refresh"]
    assert not any((tmp_path / "backups").iterdir())


@pytest.mark.parametrize(
    ("vendor", "product", "expected"),
    [
        ("Microsoft Corporation", "Virtual Machine", "hyperv"),
        ("VMware, Inc.", "VMware Virtual Platform", "vmware"),
    ],
)
def test_release_data_disk_platform_preserves_legacy_topology(
    monkeypatch,
    tmp_path,
    vendor,
    product,
    expected,
):
    """Select the matching signed legacy policy when no first-boot marker exists.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        vendor: DMI system vendor supplied to the test scenario.
        product: DMI product name supplied to the test scenario.
        expected: Expected legacy policy name.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    vendor_path = tmp_path / "sys_vendor"
    product_path = tmp_path / "product_name"
    vendor_path.write_text(vendor, encoding="utf-8")
    product_path.write_text(product, encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_GUEST_AGENT_MARKER_PATH", tmp_path / "missing-marker")
    monkeypatch.setattr(helper, "ATLASO_DMI_SYS_VENDOR_PATH", vendor_path)
    monkeypatch.setattr(helper, "ATLASO_DMI_PRODUCT_NAME_PATH", product_path)
    monkeypatch.setattr(helper, "ATLASO_DATA_DISK_POLICY_PATH", tmp_path / "missing-policy")
    monkeypatch.setattr(helper, "ATLASO_VMWARE_OVF_UNIT_PATH", tmp_path / "missing-vmware-unit")
    monkeypatch.setattr(helper, "ATLASO_HYPERV_GENERATOR_PATH", tmp_path / "missing-generator")

    assert helper._release_data_disk_platform() == expected


@pytest.mark.parametrize("platform", ["vmware", "qemu", "hyperv", "baremetal"])
def test_release_data_disk_platform_uses_portable_artifact_marker(monkeypatch, tmp_path, platform):
    """Use the shared four-disk policy for every verified portable artifact.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        platform: Verified provider recorded by first boot.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    marker = tmp_path / "guest-agent.applied"
    marker.write_text(f"platform={platform}\n", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_GUEST_AGENT_MARKER_PATH", marker)

    assert helper._release_data_disk_platform() == "virtualization"


def test_release_data_disk_platform_rejects_conflicting_legacy_evidence(monkeypatch, tmp_path):
    """Fail closed instead of replacing an installed policy under contradictory evidence.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    vendor_path = tmp_path / "sys_vendor"
    product_path = tmp_path / "product_name"
    vmware_unit = tmp_path / "atlaso-vmware-ovf-customize.service"
    vendor_path.write_text("Microsoft Corporation", encoding="utf-8")
    product_path.write_text("Virtual Machine", encoding="utf-8")
    vmware_unit.write_text("[Unit]\n", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_GUEST_AGENT_MARKER_PATH", tmp_path / "missing-marker")
    monkeypatch.setattr(helper, "ATLASO_DMI_SYS_VENDOR_PATH", vendor_path)
    monkeypatch.setattr(helper, "ATLASO_DMI_PRODUCT_NAME_PATH", product_path)
    monkeypatch.setattr(helper, "ATLASO_DATA_DISK_POLICY_PATH", tmp_path / "missing-policy")
    monkeypatch.setattr(helper, "ATLASO_VMWARE_OVF_UNIT_PATH", vmware_unit)
    monkeypatch.setattr(helper, "ATLASO_HYPERV_GENERATOR_PATH", tmp_path / "missing-generator")

    with pytest.raises(ValueError, match="hyperv, vmware"):
        helper._release_data_disk_platform()


def test_release_data_disk_refresh_settles_before_preflight(monkeypatch):
    """Verify that upgrade-created stable identities settle before validation.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    captured: list[list[str]] = []

    def command_payload(command):
        """Return a successful command result while retaining order.

        Args:
            command: Command and arguments supplied by the helper.
        """
        captured.append(command)
        return {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper, "_command_payload", command_payload)

    results = helper._refresh_release_data_disk_identity(validate=True)

    assert all(result["success"] for result in results)
    assert captured == [
        ["/usr/bin/udevadm", "control", "--reload-rules"],
        ["/usr/bin/udevadm", "trigger", "--subsystem-match=block", "--action=add"],
        ["/usr/bin/udevadm", "settle"],
        ["/opt/atlaso/bin/atlaso-mount-data-disks"],
    ]


def test_release_migrates_boot_safe_configured_mounted_disk_claim(monkeypatch, tmp_path):
    """Verify that an older applied mounted-ext4 volume is claimed before preflight.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import sqlite3

    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    database = tmp_path / "atlaso.db"
    baseline_summary = [
        "service disabled",
        "2 storage volumes",
        "0 enabled NFS datastores",
        "IPv4 and IPv6 are equivalent listener families",
    ]
    baseline_preview = json.dumps(
        {
            "enabled": False,
            "volumes": [
                {
                    "source_type": "mounted_ext4",
                    "stable_device_id": "/dev/disk/by-id/scsi-older-alias",
                    "filesystem_uuid": "3f832583-beec-4be7-969c-92519ea77273",
                    "mount_path": "/mnt/operator-existing-ext4",
                },
                {
                    "source_type": "blank_disk",
                    "stable_device_id": "/dev/disk/by-id/scsi-formatted-older-alias",
                    "filesystem_uuid": "aa0a2164-220e-4dbb-acb8-f4215f3e1b1f",
                    "mount_path": "/mnt/atlaso-esx-storage/formatted",
                },
            ],
        },
        indent=2,
        sort_keys=True,
    )
    baseline_snapshot = {
        "unit_id": "esx_storage",
        "summary": baseline_summary,
        "config_path": "/var/lib/atlaso/apply/esx-storage/atlaso-esx-storage.json",
        "config_preview": baseline_preview,
        "snapshot_marker": None,
    }
    baseline_hash = hashlib.sha256(
        json.dumps(baseline_snapshot, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    baselines = {
        "esx_storage": {
            "snapshot_hash": baseline_hash,
            "config_path": baseline_snapshot["config_path"],
            "config_preview": baseline_preview,
            "summary": baseline_summary,
            "applied_at": "2026-08-13T00:00:00+00:00",
        }
    }
    with sqlite3.connect(database) as connection:
        connection.execute(
            "create table esx_storage_volumes (source_type text, stable_device_id text, "
            "filesystem_uuid text, mount_path text, applied integer)"
        )
        connection.execute(
            "insert into esx_storage_volumes values (?, ?, ?, ?, 1)",
            (
                "mounted_ext4",
                "/dev/disk/by-id/scsi-older-alias",
                "3f832583-beec-4be7-969c-92519ea77273",
                "/mnt/operator-existing-ext4",
            ),
        )
        connection.execute(
            "insert into esx_storage_volumes values (?, ?, ?, ?, 1)",
            (
                "blank_disk",
                "/dev/disk/by-id/scsi-formatted-older-alias",
                "aa0a2164-220e-4dbb-acb8-f4215f3e1b1f",
                "/mnt/atlaso-esx-storage/formatted",
            ),
        )
        connection.execute(
            "create table settings (id integer primary key, key text unique, value text, updated_at text)"
        )
        connection.execute(
            "insert into settings (key, value, updated_at) values (?, ?, ?)",
            ("appliance_apply.baselines.v1", json.dumps(baselines), "2026-08-13T00:00:00+00:00"),
        )
    allowlist = tmp_path / "etc/atlaso/esx-storage-disks.conf"
    allowlist.parent.mkdir(parents=True)
    allowlist.write_text(
        "3f832583-beec-4be7-969c-92519ea77273\t/dev/disk/by-id/scsi-older-alias\t"
        "/mnt/operator-existing-ext4\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)
    monkeypatch.setattr(helper, "ESX_STORAGE_DISK_ALLOWLIST_PATH", allowlist)
    monkeypatch.setattr(
        helper,
        "_esx_storage_inventory",
        lambda: [
            {
                "candidate_type": "mounted_ext4",
                "type": "disk",
                "stable_device_id": "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_3_0",
                "filesystem_type": "ext4",
                "filesystem_uuid": "3f832583-beec-4be7-969c-92519ea77273",
                "mount_paths": ["/mnt/operator-existing-ext4"],
                "writable_mount_paths": ["/mnt/operator-existing-ext4"],
                "partitions": [],
                "holders": [],
                "os_related": False,
                "read_only": False,
                "persistent_uuid_mount": True,
            },
            {
                "candidate_type": "mounted_ext4",
                "type": "disk",
                "stable_device_id": "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_4_0",
                "filesystem_type": "ext4",
                "filesystem_uuid": "aa0a2164-220e-4dbb-acb8-f4215f3e1b1f",
                "mount_paths": ["/mnt/atlaso-esx-storage/formatted"],
                "writable_mount_paths": ["/mnt/atlaso-esx-storage/formatted"],
                "partitions": [],
                "holders": [],
                "os_related": False,
                "read_only": False,
                "persistent_uuid_mount": True,
            },
        ],
    )
    monkeypatch.setattr(
        helper,
        "_esx_storage_resolved_by_id_device",
        lambda value: (
            Path("/dev/sdd")
            if value
            in {
                "/dev/disk/by-id/scsi-older-alias",
                "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_3_0",
            }
            else Path("/dev/sde")
            if value
            in {
                "/dev/disk/by-id/scsi-formatted-older-alias",
                "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_4_0",
            }
            else (_ for _ in ()).throw(ValueError(value))
        ),
    )
    backups: list[tuple[Path | None, Path]] = []
    checkpointed_backups: list[list[tuple[Path | None, Path]]] = []

    def checkpoint_before_claim_mutation(current_backups):
        """Verify the allowlist backup is durable before either claim store changes.

        Args:
            current_backups: Recovery manifest extended with the allowlist backup.
        """
        checkpointed_backups.append(list(current_backups))
        assert "scsi-older-alias" in allowlist.read_text(encoding="utf-8")
        with sqlite3.connect(database) as connection:
            identities = connection.execute(
                "select stable_device_id from esx_storage_volumes order by stable_device_id"
            ).fetchall()
        assert ("/dev/disk/by-id/scsi-older-alias",) in identities

    helper._migrate_release_esx_storage_claims(
        tmp_path / "backups",
        backups,
        before_mutation=checkpoint_before_claim_mutation,
    )

    assert allowlist.read_text(encoding="utf-8") == (
        "3f832583-beec-4be7-969c-92519ea77273\t"
        "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_3_0\t"
        "/mnt/operator-existing-ext4\tmounted_ext4\n"
        "aa0a2164-220e-4dbb-acb8-f4215f3e1b1f\t"
        "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_4_0\t"
        "/mnt/atlaso-esx-storage/formatted\tblank_disk\n"
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "select source_type, stable_device_id from esx_storage_volumes order by source_type"
        ).fetchall() == [
            ("blank_disk", "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_4_0"),
            ("mounted_ext4", "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_3_0"),
        ]
        stored_baselines = json.loads(
            connection.execute(
                "select value from settings where key = ?", ("appliance_apply.baselines.v1",)
            ).fetchone()[0]
        )
    migrated_baseline = stored_baselines["esx_storage"]
    migrated_preview = json.loads(migrated_baseline["config_preview"])
    assert migrated_preview["enabled"] is False
    assert [volume["stable_device_id"] for volume in migrated_preview["volumes"]] == [
        "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_3_0",
        "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_4_0",
    ]
    migrated_snapshot = {
        **baseline_snapshot,
        "config_preview": migrated_baseline["config_preview"],
    }
    assert migrated_baseline["snapshot_hash"] == hashlib.sha256(
        json.dumps(migrated_snapshot, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert len(backups) == 1
    backup_path, backup_destination = backups[0]
    assert backup_path is not None
    assert backup_destination == allowlist
    assert backup_path.read_text(encoding="utf-8").startswith("3f832583-beec-4be7-969c-92519ea77273\t")
    assert checkpointed_backups == [backups]


def test_abi_wheelhouse_lock_covers_exact_checked_in_versions(monkeypatch, tmp_path):
    """Verify that abi wheelhouse lock covers exact checked in versions.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    spec = importlib.util.spec_from_file_location(
        "write_wheelhouse_lock",
        ROOT / "scripts/write_wheelhouse_lock.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "example_pkg-1.2.3-py3-none-any.whl").write_bytes(b"wheel-one")
    (wheelhouse / "second-4.5.6-py3-none-any.whl").write_bytes(b"wheel-two")
    source_lock = tmp_path / "source.lock"
    source_lock.write_text("example-pkg==1.2.3\nsecond==4.5.6\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "write_wheelhouse_lock.py",
            "--wheelhouse",
            str(wheelhouse),
            "--source-lock",
            str(source_lock),
        ],
    )
    assert module.main() == 0
    runtime_lock = (wheelhouse / "requirements-wheelhouse.lock").read_text(encoding="utf-8")
    assert "example-pkg==1.2.3 --hash=sha256:" in runtime_lock
    assert "second==4.5.6 --hash=sha256:" in runtime_lock


def test_helper_offline_install_uses_only_locked_wheelhouse(monkeypatch, tmp_path):
    """Verify that helper offline install uses only locked wheelhouse.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    release = tmp_path / "release"
    (release / "wheelhouse/cp314").mkdir(parents=True)
    (release / "wheelhouse/cp314/dependency.whl").write_bytes(b"wheel")
    (release / "packages").mkdir()
    (release / "packages/atlaso-0.9.0-py3-none-any.whl").write_bytes(b"wheel")
    (release / "wheelhouse/cp314/requirements-wheelhouse.lock").write_text(
        "dependency==1.0 --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    captured: list[tuple[list[str], dict[str, str]]] = []

    def fake_command(command, *, success_codes=None, env=None):
        """Return fake command.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        captured.append((command, env or {}))
        if command[1:3] == ["-m", "venv"]:
            (Path(command[-1]) / "bin").mkdir(parents=True)
            (Path(command[-1]) / "bin/python").write_text("", encoding="utf-8")
        return {"command": command, "returncode": 0, "success": True, "stdout": "", "stderr": ""}

    monkeypatch.setattr(helper, "_command_payload", fake_command)
    commands = helper._install_release_venv(release, "cp314")
    assert all(command["success"] for command in commands)
    dependency_command, env = next(
        item for item in captured if "--require-hashes" in item[0]
    )
    assert "--no-index" in dependency_command
    assert "--find-links" in dependency_command
    assert env["PIP_CONFIG_FILE"] == "/dev/null"
    assert env["PIP_NO_INDEX"] == "1"


def test_photon_candidate_abi_uses_python_nevra_and_transaction_is_test_only(monkeypatch):
    """Verify that photon candidate abi uses python nevra and transaction is test only.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/tdnf")
    monkeypatch.setattr(
        helper,
        "_command_payload",
        lambda command, **_kwargs: {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": "VMware Photon Linux 5.0\npython3-3.14.5-2.ph5.x86_64\n",
            "stderr": "",
        },
    )
    command, abi = helper._candidate_photon_python_abi()
    assert command["success"] is True
    assert abi == "cp314"
    helper_text = (ROOT / "scripts/appliance/atlaso-helper").read_text(encoding="utf-8")
    assert '[tdnf, "-y", "update", "--testonly"]' in helper_text
    assert "--assumeno" not in helper_text


def test_helper_rejects_unsafe_release_archive(tmp_path):
    """Verify that helper rejects unsafe release archive.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    archive_path = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("../outside")
        payload = b"bad"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    with pytest.raises(ValueError, match="unsafe member"):
        helper._safe_extract_release(archive_path, tmp_path / "extract")


def test_sqlite_backup_restores_database_identity(monkeypatch, tmp_path):
    """Verify that sqlite backup restores database identity.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import sqlite3

    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    database = tmp_path / "atlaso.db"
    backup = tmp_path / "backup.db"
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("create table identity(value text)")
        connection.execute("insert into identity values ('before')")
        connection.commit()
    finally:
        connection.close()
    helper._sqlite_backup(backup)
    connection = sqlite3.connect(database)
    try:
        connection.execute("update identity set value='after'")
        connection.commit()
    finally:
        connection.close()
    helper._restore_sqlite_backup(backup)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("select value from identity").fetchone()[0] == "before"
    finally:
        connection.close()


def test_sqlite_restore_rejects_missing_transaction_backup(monkeypatch, tmp_path):
    """Verify a disappeared transaction backup cannot be counted as restored.

    Args:
        monkeypatch: Pytest fixture used to replace the database destination.
        tmp_path: Temporary directory provided for missing backup evidence.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", tmp_path / "atlaso.db")

    with pytest.raises(FileNotFoundError, match="database backup is unavailable"):
        helper._restore_sqlite_backup(tmp_path / "missing-backup.db")


def test_release_asset_restore_attempts_every_backup_after_failure(monkeypatch, tmp_path):
    """Verify one asset restore failure does not prevent later independent restores.

    Args:
        monkeypatch: Pytest fixture used to inject one file-specific restore failure.
        tmp_path: Temporary directory provided for isolated asset backups.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    first_backup = tmp_path / "first.backup"
    second_backup = tmp_path / "second.backup"
    first_backup.write_text("first-before", encoding="utf-8")
    second_backup.write_text("second-before", encoding="utf-8")
    first_destination = tmp_path / "first.asset"
    second_destination = tmp_path / "second.asset"
    first_destination.write_text("first-candidate", encoding="utf-8")
    second_destination.write_text("second-candidate", encoding="utf-8")
    original_copy = helper.shutil.copy2

    def copy2(source, destination):
        """Fail only the first asset restore.

        Args:
            source: Backup source selected for restoration.
            destination: Installed asset destination selected for restoration.
        """
        if Path(destination) == first_destination:
            raise OSError("injected first asset failure")
        return original_copy(source, destination)

    monkeypatch.setattr(helper.shutil, "copy2", copy2)

    results = helper._restore_release_owned_files(
        [(first_backup, first_destination), (second_backup, second_destination)]
    )

    assert [item["success"] for item in results] == [False, True]
    assert first_destination.read_text(encoding="utf-8") == "first-candidate"
    assert second_destination.read_text(encoding="utf-8") == "second-before"


def test_release_transaction_backup_sync_flushes_files_before_directory_entries(monkeypatch, tmp_path):
    """Verify rollback backup bytes and directory entries precede checkpoint publication.

    Args:
        monkeypatch: Pytest fixture used to capture durability operations.
        tmp_path: Temporary directory provided for the bounded backup tree.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    backup_root = tmp_path / "backups" / "transaction"
    database_backup = backup_root / "atlaso.db"
    asset_backup = backup_root / "etc/systemd/system/atlaso.service"
    asset_backup.parent.mkdir(parents=True)
    database_backup.write_bytes(b"database backup")
    asset_backup.write_bytes(b"service backup")
    events: list[tuple[str, Path]] = []
    monkeypatch.setattr(helper, "_fsync_file", lambda path: events.append(("file", path)))
    monkeypatch.setattr(helper, "_fsync_directory", lambda path: events.append(("directory", path)))

    helper._sync_release_transaction_backups(
        backup_root,
        database_backup,
        [(asset_backup, Path("/etc/systemd/system/atlaso.service"))],
    )

    first_directory = next(index for index, event in enumerate(events) if event[0] == "directory")
    assert {path for kind, path in events[:first_directory] if kind == "file"} == {
        database_backup.resolve(),
        asset_backup.resolve(),
    }
    flushed_directories = [path for kind, path in events if kind == "directory"]
    assert asset_backup.parent.resolve() in flushed_directories
    assert backup_root.resolve() in flushed_directories
    assert flushed_directories[-1] == backup_root.resolve().parent


@pytest.mark.parametrize("legacy_marker", [{"service_health": True}, {"no_change": True}])
def test_startup_reconciles_legacy_success_finalizer_from_durable_state(
    monkeypatch,
    tmp_path,
    legacy_marker,
):
    """Verify legacy success is accepted only from matching durable release state.

    Args:
        monkeypatch: Pytest fixture used to replace release paths and version state.
        tmp_path: Temporary directory provided for release artifacts.
        legacy_marker: Historical success marker emitted by the legacy updater.
    """
    from atlaso.app.services import appliance_update

    release = release_payload()
    release_root = tmp_path / "releases/0.9.0"
    (release_root / ".venv").mkdir(parents=True)
    (release_root / ".release-manifest.json").write_text(json.dumps(release), encoding="utf-8")
    current = tmp_path / "current"
    current.symlink_to(release_root, target_is_directory=True)
    compatibility_venv = tmp_path / ".venv"
    compatibility_venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    receipt_sha256 = hashlib.sha256(
        json.dumps(release, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    finalizer = {
        "job_id": "job_legacy_release_finalizer",
        "status": "succeeded",
        "release": "0.9.0",
        "git_commit": release["git_commit"],
        "bundle_sha256": release["bundle"]["sha256"],
        "release_manifest_sha256": receipt_sha256,
        "rolled_back": False,
        **legacy_marker,
    }
    monkeypatch.setattr(appliance_update, "ATLASO_CURRENT_RELEASE_PATH", current)
    monkeypatch.setattr(appliance_update, "ATLASO_COMPATIBILITY_VENV_PATH", compatibility_venv)
    monkeypatch.setattr(appliance_update, "__version__", "0.9.0")

    reconciled, consistent = appliance_update.reconcile_release_success_finalizer(finalizer)

    assert consistent is True
    assert reconciled["status"] == "succeeded"
    assert reconciled["startup_reconciliation"] == {
        "success": True,
        "legacy_finalizer": True,
        "candidate_version": "0.9.0",
        "current_release": str(release_root.resolve()),
        "compatibility_venv": str((release_root / ".venv").resolve()),
        "receipt_version": "0.9.0",
        "running_version": "0.9.0",
    }


def test_startup_rejects_unmarked_success_without_current_activation_evidence(monkeypatch, tmp_path):
    """Verify missing current evidence is not accepted without a legacy marker.

    Args:
        monkeypatch: Pytest fixture used to replace release paths and version state.
        tmp_path: Temporary directory provided for release artifacts.
    """
    from atlaso.app.services import appliance_update

    release = release_payload()
    release_root = tmp_path / "releases/0.9.0"
    (release_root / ".venv").mkdir(parents=True)
    (release_root / ".release-manifest.json").write_text(json.dumps(release), encoding="utf-8")
    current = tmp_path / "current"
    current.symlink_to(release_root, target_is_directory=True)
    compatibility_venv = tmp_path / ".venv"
    compatibility_venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    receipt_sha256 = hashlib.sha256(
        json.dumps(release, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    finalizer = {
        "job_id": "job_unmarked_release_finalizer",
        "status": "succeeded",
        "release": "0.9.0",
        "git_commit": release["git_commit"],
        "bundle_sha256": release["bundle"]["sha256"],
        "release_manifest_sha256": receipt_sha256,
        "rolled_back": False,
    }
    monkeypatch.setattr(appliance_update, "ATLASO_CURRENT_RELEASE_PATH", current)
    monkeypatch.setattr(appliance_update, "ATLASO_COMPATIBILITY_VENV_PATH", compatibility_venv)
    monkeypatch.setattr(appliance_update, "__version__", "0.9.0")

    reconciled, consistent = appliance_update.reconcile_release_success_finalizer(finalizer)

    assert consistent is False
    assert reconciled["status"] == "failed"
    assert "definitive activation evidence is missing" in reconciled["error"]
    assert "candidate worker restart evidence is missing" in reconciled["error"]


@pytest.mark.parametrize("legacy_finalizer", [False, True])
def test_worker_restart_uses_matching_root_release_finalizer(
    client,
    monkeypatch,
    tmp_path,
    legacy_finalizer,
):
    """Verify that worker restart uses matching root release finalizer.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        legacy_finalizer: Whether to exercise the predecessor helper's success format.
    """
    from sqlalchemy import select

    from atlaso.app import worker
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep
    from atlaso.app.services import appliance_update
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    finalizer = tmp_path / "finalizer-status.json"
    release = release_payload()
    release_root = tmp_path / "releases/0.9.0"
    (release_root / ".venv").mkdir(parents=True)
    (release_root / ".release-manifest.json").write_text(json.dumps(release), encoding="utf-8")
    current = tmp_path / "current"
    current.symlink_to(release_root, target_is_directory=True)
    compatibility_venv = tmp_path / ".venv"
    compatibility_venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    receipt_sha256 = hashlib.sha256(
        json.dumps(release, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    finalizer_payload = {
        "job_id": "job_release_finalizer",
        "status": "succeeded",
        "release": "0.9.0",
        "git_commit": "a" * 40,
        "verified_key_id": "atlaso-release-2026-01",
        "bundle_sha256": "b" * 64,
        "release_manifest_sha256": receipt_sha256,
        "rolled_back": False,
    }
    if legacy_finalizer:
        finalizer_payload["service_health"] = True
    else:
        finalizer_payload.update(
            {
                "worker_restart": {
                    "success": True,
                    "worker_version": "0.9.0",
                    "worker_release": str(release_root),
                    "release_job_id": "job_release_finalizer",
                },
                "active_release_verification": {
                    "success": True,
                    "candidate_version": "0.9.0",
                    "receipt_version": "0.9.0",
                    "internal_version": "0.9.0",
                    "host_facing_version": "0.9.0",
                },
            }
        )
    finalizer.write_text(json.dumps(finalizer_payload), encoding="utf-8")
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    monkeypatch.setattr(appliance_update, "ATLASO_CURRENT_RELEASE_PATH", current)
    monkeypatch.setattr(appliance_update, "ATLASO_COMPATIBILITY_VENV_PATH", compatibility_venv)
    monkeypatch.setattr(appliance_update, "__version__", "0.9.0")
    with SessionLocal() as db:
        job = Job(
            id="job_release_finalizer",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "selected_streams": ["powershell_modules", "photon_os", "atlaso_release"],
                    "schema_version": 2,
                    "execution_order": ["atlaso_release", "powershell_modules", "photon_os"],
                    "status_legacy_execution_order": True,
                    "status_transaction_id": "1" * 32,
                    "mode": "run",
                }
            ),
            result='{"selected_streams":["powershell_modules","photon_os","atlaso_release"]}',
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["powershell_modules", "photon_os", "atlaso_release"],
        )
        steps[0].status = "running"
        db.commit()
        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, "job_release_finalizer")
        assert recovered.status == "pending"
        assert recovered.error is None
        recovered_steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
        assert [(step.component_key, step.status) for step in recovered_steps] == [
            ("atlaso_release", "succeeded"),
            ("powershell_modules", "pending"),
            ("photon_os", "pending"),
        ]
        result = json.loads(recovered.result)
        assert result["worker_recovery"] == "release_handoff"
        assert result["release_transaction"]["verified_key_id"] == "atlaso-release-2026-01"
        assert bool(result["release_transaction"].get("startup_reconciliation")) is legacy_finalizer

        recovered.status = "running"
        recovered_steps[1].status = "succeeded"
        recovered_steps[1].progress_percent = 100
        recovered_steps[1].result = json.dumps(
            {
                "unit_id": "powershell_modules",
                "status": "succeeded",
                "success": True,
                "commands": [],
            }
        )
        db.commit()
        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, "job_release_finalizer")
        assert recovered.status == "pending"
        assert recovered.progress_percent == 60
        assert [(step.component_key, step.status) for step in recovered_steps] == [
            ("atlaso_release", "succeeded"),
            ("powershell_modules", "succeeded"),
            ("photon_os", "pending"),
        ]

    import atlaso.app.ui as ui

    calls: list[str] = []

    def execute_remaining(**kwargs):
        """Return successful results for untouched post-release streams.

        Args:
            **kwargs: Appliance Update execution fields supplied by the worker.
        """
        stream = str(kwargs["selected_stream_ids"][0])
        calls.append(stream)
        return {
            "unit_id": stream,
            "label": stream,
            "mode": "run",
            "selected_streams": [stream],
            "selected_labels": [stream],
            "status": "succeeded",
            "success": True,
            "dry_run": False,
            "restart_after_commit": False,
            "commands": [],
            "config_path": "",
            "config_preview": "",
        }

    class RestartAdapter:
        """Record the required post-Photon service restart."""

        def restart_appliance_after_update(self, config_path):
            """Return a successful restart scheduling result.

            Args:
                config_path: Staged Appliance Update manifest path.
            """
            return AdapterResult(
                command=["restart-service", str(config_path)],
                dry_run=False,
            )

    monkeypatch.setattr(ui, "execute_appliance_update_job", execute_remaining)
    monkeypatch.setattr(ui, "SystemAdapter", RestartAdapter)
    monkeypatch.setattr(worker, "_publish_appliance_update_status", lambda *_args, **_kwargs: True)

    assert worker.run_worker_once() == "job_release_finalizer"
    assert calls == ["photon_os"]
    with SessionLocal() as db:
        completed = db.get(Job, "job_release_finalizer")
        assert completed.status == "succeeded"


def test_worker_restart_resumes_untouched_children_after_healthy_release_rollback(
    client,
    monkeypatch,
    tmp_path,
):
    """Verify healthy rollback resumes independent children without rerunning release.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace completion side effects.
        tmp_path: Temporary directory provided for finalizer evidence.
    """
    from sqlalchemy import select

    from atlaso.app import ui, worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    finalizer = tmp_path / "rollback-finalizer.json"
    finalizer.write_text(
        json.dumps(
            {
                "job_id": "job_release_rollback_handoff",
                "status": "failed",
                "release": "0.9.0",
                "previous_version": "0.9.163",
                "rolled_back": True,
                "rollback_health": True,
                "failure_layer": "management_front_door",
                "commands": [],
                "error": "candidate readiness failed",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    with SessionLocal() as db:
        job = Job(
            id="job_release_rollback_handoff",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "selected_streams": ["atlaso_release", "powershell_modules", "photon_os"],
                    "schema_version": 2,
                    "execution_order": ["atlaso_release", "powershell_modules", "photon_os"],
                    "status_legacy_execution_order": True,
                    "status_transaction_id": "2" * 32,
                    "settings": {},
                    "mode": "run",
                }
            ),
            result='{"status":"running","success":false}',
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["atlaso_release", "powershell_modules", "photon_os"],
        )
        steps[0].status = "running"
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        assert recovered.status == "pending"
        recovered_steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
        assert [(step.component_key, step.status) for step in recovered_steps] == [
            ("atlaso_release", "failed"),
            ("powershell_modules", "pending"),
            ("photon_os", "pending"),
        ]

    run_appliance_update = worker._run_appliance_update
    monkeypatch.setattr(worker, "_rollback_requires_worker_restart", lambda: True)
    monkeypatch.setattr(
        worker,
        "_run_appliance_update",
        lambda _job_id: pytest.fail("the rejected candidate must not resume pending update children"),
    )
    assert worker._complete_recovered_rollback_job() is True
    with SessionLocal() as db:
        assert db.get(Job, "job_release_rollback_handoff").status == "pending"
    monkeypatch.setattr(worker, "_rollback_requires_worker_restart", lambda: False)
    monkeypatch.setattr(worker, "_run_appliance_update", run_appliance_update)

    calls: list[str] = []

    def execute_remaining(**kwargs):
        """Return a successful result for the independent PowerShell child.

        Args:
            **kwargs: Appliance Update execution fields supplied by the worker.
        """
        stream = str(kwargs["selected_stream_ids"][0])
        calls.append(stream)
        return {
            "unit_id": stream,
            "label": stream,
            "mode": "run",
            "selected_streams": [stream],
            "selected_labels": [stream],
            "status": "succeeded",
            "success": True,
            "dry_run": False,
            "restart_after_commit": False,
            "commands": [],
            "config_path": "",
            "config_preview": "",
        }

    monkeypatch.setattr(ui, "execute_appliance_update_job", execute_remaining)
    monkeypatch.setattr(worker, "_publish_appliance_update_status", lambda *_args, **_kwargs: True)

    assert worker.run_worker_once() == "job_release_rollback_handoff"
    assert calls == ["powershell_modules"]
    with SessionLocal() as db:
        completed = db.get(Job, "job_release_rollback_handoff")
        completed_steps = db.execute(
            select(JobStep).where(JobStep.job_id == completed.id).order_by(JobStep.position)
        ).scalars().all()
        assert completed.status == "failed"
        assert [(step.component_key, step.status) for step in completed_steps] == [
            ("atlaso_release", "failed"),
            ("powershell_modules", "succeeded"),
            ("photon_os", "skipped"),
        ]
        assert "earlier selected update stream failed" in (completed_steps[-1].error or "")


def test_candidate_bookkeeping_fails_parent_before_definitive_legacy_rollback(
    client,
    monkeypatch,
    tmp_path,
):
    """Verify candidate bookkeeping precedes definitive legacy rollback evidence.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace completion side effects.
        tmp_path: Temporary directory provided for finalizer evidence.
    """
    from sqlalchemy import select

    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    finalizer = tmp_path / "legacy-rollback-finalizer.json"
    finalizer.write_text(
        json.dumps(
            {
                "job_id": "job_legacy_rollback_handoff",
                "status": "rollback_pending",
                "release": "0.9.163",
                "previous_version": "0.9.162",
                "rolled_back": False,
                "rollback_health": True,
                "bookkeeping_pending": True,
                "failure_layer": "management_front_door",
                "commands": [],
                "error": "candidate readiness failed",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    monkeypatch.setenv("ATLASO_RELEASE_RECOVERY_ONLY", "1")
    with SessionLocal() as db:
        job = Job(
            id="job_legacy_rollback_handoff",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "selected_streams": ["atlaso_release", "powershell_modules", "photon_os"],
                    "settings": {},
                    "mode": "run",
                }
            ),
            result='{"status":"running","success":false}',
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["atlaso_release", "powershell_modules", "photon_os"],
        )
        steps[0].status = "running"
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        recovered_steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
        assert recovered.status == "failed"
        assert [(step.component_key, step.status) for step in recovered_steps] == [
            ("atlaso_release", "failed"),
            ("powershell_modules", "skipped"),
            ("photon_os", "skipped"),
        ]
        assert "cannot preserve terminal release results" in (
            recovered_steps[1].error or ""
        )
        transaction = json.loads(recovered.result)["release_transaction"]
        assert transaction["status"] == "rollback_pending"
        assert transaction["bookkeeping_pending"] is True


@pytest.mark.parametrize("finalizer_status", ["succeeded", "failed"])
def test_worker_restart_runs_normal_release_completion_bookkeeping(
    client,
    monkeypatch,
    tmp_path,
    finalizer_status,
):
    """Verify recovered terminal releases retain helper output, logs, and audit.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace completion side effects.
        tmp_path: Temporary directory provided for finalizer evidence.
        finalizer_status: Definitive success or rollback result to recover.
    """
    from atlaso.app import ui, worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    job_id = f"job_release_bookkeeping_{finalizer_status}"
    command = {
        "command": ["release-activation-check", "complete"],
        "returncode": 0 if finalizer_status == "succeeded" else 1,
        "success": finalizer_status == "succeeded",
        "stdout": "candidate ready" if finalizer_status == "succeeded" else "",
        "stderr": "" if finalizer_status == "succeeded" else "candidate rolled back",
    }
    finalizer = tmp_path / f"{finalizer_status}-finalizer.json"
    finalizer.write_text(
        json.dumps(
            {
                "job_id": job_id,
                "status": finalizer_status,
                "release": "0.9.0",
                "rolled_back": finalizer_status == "failed",
                "commands": [command],
                "error": "candidate rolled back" if finalizer_status == "failed" else "",
                "worker_restart": {"success": True} if finalizer_status == "succeeded" else {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    monkeypatch.setattr(worker, "reconcile_release_success_finalizer", lambda payload: (payload, True))
    submissions: list[tuple[str, dict]] = []
    failures: list[tuple[str, dict]] = []
    audits: list[dict] = []
    monkeypatch.setattr(
        ui,
        "log_appliance_update_submission",
        lambda recovered_job_id, result: submissions.append((recovered_job_id, result)),
    )
    monkeypatch.setattr(
        ui,
        "log_appliance_update_failures",
        lambda recovered_job_id, result: failures.append((recovered_job_id, result)),
    )
    monkeypatch.setattr(ui, "record_audit", lambda _db, **kwargs: audits.append(kwargs))

    with SessionLocal() as db:
        job = Job(
            id=job_id,
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "selected_streams": ["atlaso_release"],
                    "settings": {},
                    "mode": "run",
                }
            ),
            result='{"status":"running","success":false}',
        )
        db.add(job)
        db.flush()
        step = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["atlaso_release"],
        )[0]
        step.status = "running"
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job_id)
        recovered_step = recovered.steps[0]
        assert recovered.status == finalizer_status
        assert json.loads(recovered_step.result)["commands"] == [command]
        assert json.loads(recovered.result)["commands"] == [command]

    assert len(submissions) == 1
    assert len(failures) == (1 if finalizer_status == "failed" else 0)
    assert len(audits) == 1
    assert audits[0]["action"] == "run_appliance_update"
    assert audits[0]["detail"] == "release-activation-check complete"
    assert audits[0]["success"] is (finalizer_status == "succeeded")


def test_worker_restart_rejects_success_finalizer_for_another_running_version(client, monkeypatch, tmp_path):
    """Verify startup rejects success evidence that disagrees with the running release.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for release artifacts.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services import appliance_update

    release = release_payload()
    release_root = tmp_path / "releases/0.9.0"
    (release_root / ".venv").mkdir(parents=True)
    (release_root / ".release-manifest.json").write_text(json.dumps(release), encoding="utf-8")
    current = tmp_path / "current"
    current.symlink_to(release_root, target_is_directory=True)
    compatibility_venv = tmp_path / ".venv"
    compatibility_venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    receipt_sha256 = hashlib.sha256(
        json.dumps(release, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    finalizer = tmp_path / "finalizer-status.json"
    finalizer.write_text(
        json.dumps(
            {
                "job_id": "job_inconsistent_release_finalizer",
                "status": "succeeded",
                "release": "0.9.0",
                "candidate_version": "0.9.0",
                "git_commit": release["git_commit"],
                "bundle_sha256": release["bundle"]["sha256"],
                "release_manifest_sha256": receipt_sha256,
                "rolled_back": False,
                "active_release_verification": {
                    "success": True,
                    "candidate_version": "0.9.0",
                    "receipt_version": "0.9.0",
                    "internal_version": "0.9.0",
                    "host_facing_version": "0.9.0",
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    monkeypatch.setattr(appliance_update, "ATLASO_CURRENT_RELEASE_PATH", current)
    monkeypatch.setattr(appliance_update, "ATLASO_COMPATIBILITY_VENV_PATH", compatibility_venv)
    monkeypatch.setattr(appliance_update, "__version__", "0.8.9")

    with SessionLocal() as db:
        db.add(
            Job(
                id="job_inconsistent_release_finalizer",
                type="appliance-update",
                status="running",
                created_by="admin",
                result='{"selected_streams":["atlaso_release"]}',
            )
        )
        db.commit()
        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, "job_inconsistent_release_finalizer")
        assert recovered.status == "failed"
        assert "running Atlaso version" in (recovered.error or "")
        result = json.loads(recovered.result)
        assert result["release_transaction"]["failure_layer"] == "startup_reconciliation"
        assert result["release_transaction"]["startup_consistent"] is False


@pytest.mark.parametrize(
    ("receipt_failure", "expected_error"),
    [
        ("bundle_shape", "receipt bundle"),
        ("utf8", "receipt is missing or invalid"),
    ],
)
def test_worker_restart_reconciles_completed_success_against_durable_release(
    client,
    monkeypatch,
    tmp_path,
    receipt_failure,
    expected_error,
):
    """Verify startup revises a completed success when the durable release disagrees.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for release artifacts.
        receipt_failure: Signed receipt corruption scenario to exercise.
        expected_error: Expected sanitized reconciliation error fragment.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services import appliance_update

    release = release_payload()
    malformed_release = {**release, "bundle": "corrupted"}
    release_root = tmp_path / "releases/0.9.0"
    (release_root / ".venv").mkdir(parents=True)
    receipt_path = release_root / ".release-manifest.json"
    if receipt_failure == "utf8":
        receipt_path.write_bytes(b"\xff\xfe\xfd")
    else:
        receipt_path.write_text(json.dumps(malformed_release), encoding="utf-8")
    current = tmp_path / "current"
    current.symlink_to(release_root, target_is_directory=True)
    compatibility_venv = tmp_path / ".venv"
    compatibility_venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    receipt_sha256 = hashlib.sha256(
        json.dumps(release, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    finalizer = tmp_path / "finalizer-status.json"
    finalizer.write_text(
        json.dumps(
            {
                "job_id": "job_completed_inconsistent_release",
                "status": "succeeded",
                "release": "0.9.0",
                "candidate_version": "0.9.0",
                "git_commit": release["git_commit"],
                "bundle_sha256": release["bundle"]["sha256"],
                "release_manifest_sha256": receipt_sha256,
                "rolled_back": False,
                "active_release_verification": {
                    "success": True,
                    "candidate_version": "0.9.0",
                    "receipt_version": "0.9.0",
                    "internal_version": "0.9.0",
                    "host_facing_version": "0.9.0",
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    monkeypatch.setattr(appliance_update, "ATLASO_CURRENT_RELEASE_PATH", current)
    monkeypatch.setattr(appliance_update, "ATLASO_COMPATIBILITY_VENV_PATH", compatibility_venv)
    monkeypatch.setattr(appliance_update, "__version__", "0.9.0")

    with SessionLocal() as db:
        db.add(
            Job(
                id="job_completed_inconsistent_release",
                type="appliance-update",
                status="succeeded",
                created_by="admin",
                progress_percent=100,
                result='{"status":"succeeded","success":true}',
            )
        )
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, "job_completed_inconsistent_release")
        assert recovered.status == "failed"
        assert expected_error in (recovered.error or "")
        result = json.loads(recovered.result)
        assert result["status"] == "failed"
        assert result["success"] is False
        assert result["release_transaction"]["failure_layer"] == "startup_reconciliation"
        first_finished_at = recovered.finished_at

        assert worker.recover_interrupted_worker_jobs(db) == 0
        assert db.get(Job, "job_completed_inconsistent_release").finished_at == first_finished_at


def test_worker_restart_fails_update_parent_after_children_commit(client, monkeypatch, tmp_path):
    """Verify that worker restart fails update parent after children commit.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    monkeypatch.setattr(
        worker,
        "APPLIANCE_UPDATE_FINALIZER_PATH",
        str(tmp_path / "missing-finalizer-status.json"),
    )
    with SessionLocal() as db:
        job = Job(
            id="job_update_children_committed",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {"selected_streams": ["powershell_modules", "photon_os"], "mode": "check"}
            ),
            result='{"status":"pending","success":false}',
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["powershell_modules", "photon_os"],
        )
        for step in steps:
            step.status = "succeeded"
            step.progress_percent = 100
            step.result = '{"status":"succeeded","success":true}'
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        assert recovered.status == "failed"
        assert recovered.progress_percent == 100
        assert "worker restarted" in (recovered.error or "")
        result = json.loads(recovered.result or "{}")
        assert result["status"] == "failed"
        assert result["success"] is False
        assert result["worker_recovery"] == "interrupted"
        assert [step.status for step in recovered.steps] == ["succeeded", "succeeded"]


def test_worker_restart_records_interrupted_check_as_latest_failed_attempt(
    client,
    monkeypatch,
    tmp_path,
):
    """Keep an older confirmation while blocking installs after interrupted checks.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for finalizer state.
    """
    from datetime import datetime, timezone

    from atlaso.app import ui, worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_update import (
        APPLIANCE_UPDATE_AVAILABILITY_KEY,
        empty_update_availability,
        ensure_appliance_update_job_steps,
        manual_install_gate,
        record_update_availability_attempt,
        update_availability_to_json,
        update_stream_configuration_fingerprints,
    )

    monkeypatch.setattr(
        worker,
        "APPLIANCE_UPDATE_FINALIZER_PATH",
        str(tmp_path / "missing-finalizer-status.json"),
    )
    with SessionLocal() as db:
        settings = ui.appliance_update_settings(db)
        fingerprint = update_stream_configuration_fingerprints(settings)["photon_os"]
        availability = record_update_availability_attempt(
            empty_update_availability(),
            stream="photon_os",
            job_id="job-earlier-check",
            checked_at=datetime.now(timezone.utc),
            fingerprint=fingerprint,
            result={
                "state": "available",
                "current": "1.0",
                "target": "2.0",
                "change_count": 1,
                "changes": [{"name": "photon", "action": "upgrade"}],
            },
        )
        ui.set_setting_value(
            db,
            APPLIANCE_UPDATE_AVAILABILITY_KEY,
            update_availability_to_json(availability),
        )
        job = Job(
            id="job-interrupted-check",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "selected_streams": ["photon_os"],
                    "settings": settings,
                    "mode": "check",
                }
            ),
            result='{"status":"running","success":false}',
        )
        db.add(job)
        db.flush()
        step = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["photon_os"],
        )[0]
        step.status = "running"
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        assert recovered.status == "failed"
        assert json.loads(recovered.result)["worker_recovery"] == "interrupted"

        summary = ui.appliance_update_availability_summary(db)
        photon = next(row for row in summary["streams"] if row["id"] == "photon_os")
        assert photon["last_attempt"]["success"] is False
        assert photon["last_attempt"]["state"] == "failed"
        assert photon["confirmed"]["update_available"] is True
        allowed, reason = manual_install_gate(summary, ["photon_os"])
        assert allowed is False
        assert "interrupted check" in reason


def test_worker_restart_preserves_completed_child_check_availability(
    client,
    monkeypatch,
    tmp_path,
):
    """Retain a completed child result while failing the interrupted child.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace worker dependencies.
        tmp_path: Temporary directory provided for finalizer state.
    """
    from atlaso.app import ui, worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    monkeypatch.setattr(
        worker,
        "APPLIANCE_UPDATE_FINALIZER_PATH",
        str(tmp_path / "missing-finalizer-status.json"),
    )
    with SessionLocal() as db:
        settings = ui.appliance_update_settings(db)
        job = Job(
            id="job-partially-completed-check",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "selected_streams": ["powershell_modules", "photon_os"],
                    "settings": settings,
                    "mode": "check",
                }
            ),
            result='{"status":"running","success":false}',
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["powershell_modules", "photon_os"],
        )
        powershell = next(
            step for step in steps if step.component_key == "powershell_modules"
        )
        powershell.status = "succeeded"
        powershell.progress_percent = 100
        powershell.result = json.dumps(
            {
                "unit_id": "powershell_modules",
                "status": "succeeded",
                "success": True,
                "commands": [],
                "availability": {
                    "state": "up_to_date",
                    "current": "2.0.0",
                    "target": "2.0.0",
                    "change_count": 0,
                    "changes": [],
                },
            }
        )
        photon = next(step for step in steps if step.component_key == "photon_os")
        photon.status = "running"
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        assert recovered.status == "failed"

        summary = ui.appliance_update_availability_summary(db)
        rows = {row["id"]: row for row in summary["streams"]}
        assert rows["powershell_modules"]["last_attempt"]["success"] is True
        assert rows["powershell_modules"]["confirmed"]["state"] == "up_to_date"
        assert rows["photon_os"]["last_attempt"]["success"] is False
        assert rows["photon_os"]["last_attempt"]["state"] == "failed"


def test_worker_restart_removes_interrupted_network_boot_upload(client, monkeypatch):
    """Verify that worker restart removes interrupted network boot upload.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    cleaned = []
    monkeypatch.setattr(worker, "cleanup_network_boot_upload", cleaned.append)
    with SessionLocal() as db:
        job = Job(
            id="job_" + ("e" * 32),
            type="pxe-media-sync",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {"environment": "inventory", "source": "upload"}
            ),
        )
        db.add(job)
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        assert cleaned == [job.id]
        assert db.get(Job, job.id).status == "failed"


def test_worker_restart_keeps_release_finalizer_scoped_to_its_child(client, monkeypatch, tmp_path):
    """Verify that worker restart keeps release finalizer scoped to its child.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select

    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    finalizer = tmp_path / "finalizer-status.json"
    finalizer.write_text(
        json.dumps(
            {
                "job_id": "job_release_partial_finalizer",
                "status": "succeeded",
                "release": "0.9.0",
                "git_commit": "a" * 40,
                "verified_key_id": "atlaso-release-2026-01",
                "bundle_sha256": "b" * 64,
                "rolled_back": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    monkeypatch.setattr(worker, "reconcile_release_success_finalizer", lambda payload: (payload, True))
    with SessionLocal() as db:
        job = Job(
            id="job_release_partial_finalizer",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {"selected_streams": ["atlaso_release", "photon_os"], "mode": "run"}
            ),
            result='{"selected_streams":["atlaso_release","photon_os"]}',
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["atlaso_release", "photon_os"],
        )
        release_step = next(step for step in steps if step.component_key == "atlaso_release")
        release_step.status = "running"
        next(step for step in steps if step.component_key == "photon_os").status = "running"
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
        assert recovered.status == "failed"
        assert [(step.component_key, step.status) for step in steps] == [
            ("atlaso_release", "succeeded"),
            ("photon_os", "failed"),
        ]
        assert "worker restarted" in (steps[-1].error or "")


def test_no_change_release_failure_finalizer_retains_readiness_commands(monkeypatch, tmp_path):
    """Verify already-active release failures preserve their diagnostic checks.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for release state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    release = release_payload()
    bundle_bytes = b"signed release bundle"
    release["bundle"] = {
        "url": "https://example.test/atlaso-release.tar.gz",
        "size": len(bundle_bytes),
        "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
    }
    channel = {
        "channel": "stable",
        "release_manifest_url": "https://example.test/release.json",
    }
    releases = tmp_path / "releases"
    release_root = releases / str(release["version"])
    release_root.mkdir(parents=True)
    (release_root / ".venv").mkdir()
    (release_root / ".release-manifest.json").write_text(
        json.dumps(release),
        encoding="utf-8",
    )
    current = tmp_path / "current"
    current.symlink_to(release_root, target_is_directory=True)
    compatibility_venv = tmp_path / ".venv"
    compatibility_venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    finalizer = tmp_path / "finalizer.json"
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", releases)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_VENV_LINK", compatibility_venv)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer)
    monkeypatch.setattr(
        helper,
        "_download_signed_release_from_sources",
        lambda *_args: (channel, release, channel["release_manifest_url"], None),
    )
    monkeypatch.setattr(helper, "_fetch_http_bytes", lambda *_args: bundle_bytes)
    monkeypatch.setattr(helper, "_safe_extract_release", lambda *_args: None)
    monkeypatch.setattr(helper, "_validate_release_content", lambda *_args: None)
    monkeypatch.setattr(helper, "_current_python_abi", lambda: "cp314")
    monkeypatch.setattr(
        helper,
        "_install_release_venv",
        lambda *_args: [
            {
                "command": ["offline-install"],
                "returncode": 0,
                "success": True,
                "stdout": "",
                "stderr": "",
            }
        ],
    )
    monkeypatch.setattr(
        helper,
        "_sync_release_activation",
        lambda: {
            "command": ["release-activation-check", "durable_activation"],
            "returncode": 0,
            "success": True,
            "stdout": "durable",
            "stderr": "",
            "layer": "durable_activation",
        },
    )
    failed_command = {
        "command": ["release-activation-check", "management_front_door"],
        "returncode": 1,
        "success": False,
        "stdout": "",
        "stderr": "front door version mismatch",
        "layer": "management_front_door",
    }
    monkeypatch.setattr(
        helper,
        "_release_activation_verification",
        lambda *_args, **_kwargs: (
            {
                "success": False,
                "candidate_version": str(release["version"]),
                "failure_layer": "management_front_door",
            },
            [failed_command],
        ),
    )

    with pytest.raises(ValueError, match="management_front_door"):
        helper._apply_atlaso_release({"job_id": "job-no-change"})

    persisted = json.loads(finalizer.read_text(encoding="utf-8"))
    assert persisted["status"] == "failed"
    assert persisted["no_change"] is True
    assert failed_command in persisted["commands"]


@pytest.mark.parametrize(
    ("failure_stage", "expected_layer", "expected_rolled_back"),
    [
        ("systemd_assets", "data_disk_identity", True),
        ("symlink_switch", "systemd_reload", True),
        ("candidate_startup", "candidate_startup", True),
        ("nginx_configuration", "nginx_configuration", True),
        ("worker_restart", "worker_restart", True),
        ("worker_activation", "worker_restart", True),
        ("transaction_backup_sync", "transaction_checkpoint", True),
        ("rollback_symlink_sync", "candidate_startup", True),
        ("rollback_database_missing", "candidate_startup", False),
        ("rollback_link_restore", "candidate_startup", False),
        ("rollback_activation", "candidate_startup", False),
        ("rollback_front_activation", "candidate_startup", True),
        ("rollback_host_finalizer_persistence", "candidate_startup", True),
        ("rollback_worker_state", "candidate_startup", False),
        ("rollback_worker_status_query", "candidate_startup", False),
        ("rollback_finalizer_persistence", "candidate_startup", False),
        ("rollback_gate", "candidate_startup", False),
    ],
)
def test_failed_candidate_restores_previous_release_and_database(
    monkeypatch,
    tmp_path,
    failure_stage,
    expected_layer,
    expected_rolled_back,
):
    """Verify that failed candidate restores previous release and database.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        failure_stage: Failure stage supplied to the test scenario.
        expected_layer: Sanitized transaction layer expected in final evidence.
        expected_rolled_back: Whether the scenario must prove a complete rollback.
    """
    import sqlite3

    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    home = tmp_path / "opt/atlaso"
    releases = home / "releases"
    previous = releases / "0.8.9"
    previous.mkdir(parents=True)
    (previous / ".venv").mkdir()
    current = home / "current"
    current.symlink_to(previous, target_is_directory=True)
    venv = home / ".venv"
    venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    database = tmp_path / "atlaso.db"

    def set_identity(value: str) -> None:
        """Update identity.

        Args:
            value: Candidate value consumed by set identity.
        """
        connection = sqlite3.connect(database)
        try:
            connection.execute("create table if not exists identity(value text)")
            connection.execute("delete from identity")
            connection.execute("insert into identity values (?)", (value,))
            connection.commit()
        finally:
            connection.close()

    def get_identity() -> str:
        """Return identity."""
        connection = sqlite3.connect(database)
        try:
            return connection.execute("select value from identity").fetchone()[0]
        finally:
            connection.close()

    set_identity("before")
    metadata = canonical(
        {
            "schema_version": 1,
            "version": "0.9.0",
            "git_commit": "a" * 40,
            "built_at": "2026-07-23T12:00:00Z",
            "supported_python_abis": ["cp314"],
        }
    )
    bundle_buffer = io.BytesIO()
    with tarfile.open(fileobj=bundle_buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("bundle-metadata.json")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))
    bundle_bytes = bundle_buffer.getvalue()
    release = release_payload()
    release["supported_python_abis"] = ["cp314"]
    release["bundle"] = {
        "url": "https://example.test/bundle.tar.gz",
        "size": len(bundle_bytes),
        "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
    }
    release["content_hashes"] = {
        "bundle-metadata.json": hashlib.sha256(metadata).hexdigest(),
    }
    channel = {
        "channel": "development",
        "release_manifest_url": "https://example.test/release-manifest.json",
    }
    monkeypatch.setattr(helper, "ATLASO_HOME", home)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", releases)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_VENV_LINK", venv)
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", tmp_path / "finalizer.json")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_RESTART_GATE_PATH", tmp_path / "restart-gate")
    restore_sqlite_backup = helper._restore_sqlite_backup

    def restore_database_backup(source):
        """Remove the rollback snapshot only in the missing-backup scenario.

        Args:
            source: SQLite transaction backup selected for restoration.
        """
        if failure_stage in {"rollback_database_missing", "rollback_worker_status_query"}:
            source.unlink(missing_ok=True)
        return restore_sqlite_backup(source)

    monkeypatch.setattr(helper, "_restore_sqlite_backup", restore_database_backup)
    original_restart_gate = helper._set_release_restart_gate
    handoff_events: list[str] = []

    def restart_gate(enabled: bool, job_id: str = "") -> None:
        """Inject a rollback gate creation failure.

        Args:
            enabled: Whether worker recovery must remain gated.
            job_id: Appliance Update job associated with the gate.

        Raises:
            OSError: When the rollback gate failure scenario is active.
        """
        if failure_stage == "rollback_gate" and enabled:
            raise OSError("injected rollback gate creation failure")
        if enabled:
            handoff_events.append("gate")
        original_restart_gate(enabled, job_id)

    monkeypatch.setattr(helper, "_set_release_restart_gate", restart_gate)
    credential_path = tmp_path / "atlaso-update-credentials.json"
    credential_path.write_text('{"sources": {}}', encoding="utf-8")

    def replace_symlink(target: Path, link: Path) -> None:
        """Handle replace symlink.

        Args:
            target: Target resource or location affected by the operation.
            link: Filesystem path associated with link.


        Raises:
            OSError: If the operating-system operation fails.
        """
        if target.name == "0.9.0":
            set_identity("after")
        if failure_stage == "rollback_link_restore" and target == previous:
            raise OSError("injected rollback symlink restore failure")
        link.unlink(missing_ok=True)
        link.symlink_to(target, target_is_directory=True)
        if failure_stage == "rollback_symlink_sync" and target == previous:
            raise OSError("injected rollback symlink directory sync failure")

    monkeypatch.setattr(helper, "_atomic_symlink", replace_symlink)
    monkeypatch.setattr(
        helper,
        "_download_signed_release_from_sources",
        lambda *_args: (channel, release, channel["release_manifest_url"], None),
    )
    monkeypatch.setattr(helper, "_fetch_http_bytes", lambda *_args: bundle_bytes)

    def install_venv(root: Path, _abi: str):
        """Return install venv.

        Args:
            root: Repository or filesystem root searched by the operation.
            _abi: Abi supplied to the test scenario.
        """
        (root / ".venv").mkdir()
        return [{"command": ["offline-install"], "returncode": 0, "success": True, "stdout": "", "stderr": ""}]

    monkeypatch.setattr(helper, "_install_release_venv", install_venv)
    def install_owned_files(*_args, before_install=None):
        """Invoke the durable checkpoint before simulating installed assets.

        Args:
            *_args: Release and backup roots accepted by the helper.
            before_install: Durable pre-mutation checkpoint callback.
        """
        if before_install is not None:
            before_install([])
        return []

    monkeypatch.setattr(helper, "_install_release_owned_files", install_owned_files)
    esx_allowlist = tmp_path / "host/etc/atlaso/esx-storage-disks.conf"
    esx_allowlist.parent.mkdir(parents=True)
    esx_allowlist.write_text("previous-claim\n", encoding="utf-8")
    monkeypatch.setattr(helper, "ESX_STORAGE_DISK_ALLOWLIST_PATH", esx_allowlist)

    def migrate_claims(backup_root, backups, *, before_mutation=None):
        """Simulate an ESX alias migration that extends the rollback manifest.

        Args:
            backup_root: Transaction backup root used for the allowlist copy.
            backups: Installed-asset manifest extended by the migration.
            before_mutation: Durable checkpoint callback invoked before the simulated rewrite.
        """
        backup = backup_root.joinpath(*esx_allowlist.parts[1:])
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(esx_allowlist.read_bytes())
        backups.append((backup, esx_allowlist))
        if before_mutation is not None:
            before_mutation(backups)
        esx_allowlist.write_text("candidate-claim\n", encoding="utf-8")

    monkeypatch.setattr(helper, "_migrate_release_esx_storage_claims", migrate_claims)
    identity_refreshes = 0

    def refresh_identity(**_kwargs):
        """Inject one failure after candidate systemd assets are installed.

        Args:
            **_kwargs: Data-disk refresh options accepted by the helper.
        """
        nonlocal identity_refreshes
        identity_refreshes += 1
        success = failure_stage != "systemd_assets" or identity_refreshes > 1
        return [
            {
                "command": ["data-disk-preflight"],
                "returncode": 0 if success else 1,
                "success": success,
                "stdout": "",
                "stderr": "" if success else "injected post-asset failure",
            }
        ]

    monkeypatch.setattr(helper, "_refresh_release_data_disk_identity", refresh_identity)
    original_command_payload = helper._command_payload

    def command_payload(command, **kwargs):
        """Return a successful disk preflight and preserve other command behavior.

        Args:
            command: Command and arguments supplied by the helper.
            **kwargs: Optional command execution arguments.
        """
        if command == ["/opt/atlaso/bin/atlaso-mount-data-disks"]:
            return {
                "command": command,
                "returncode": 0,
                "success": True,
                "stdout": "",
                "stderr": "",
            }
        return original_command_payload(command, **kwargs)

    monkeypatch.setattr(helper, "_command_payload", command_payload)
    daemon_reloads = 0
    candidate_starts = 0
    rollback_worker_starts = 0
    rollback_worker_fail_closed_stops = 0
    rollback_worker_state_queries = 0
    worker_stopped_fail_closed = False

    def service_command(action, *units):
        """Return service command.

        Args:
            action: Action supplied to the test scenario.
            *units: Additional positional arguments accepted by the callable.
        """
        nonlocal daemon_reloads, candidate_starts, rollback_worker_starts
        nonlocal rollback_worker_fail_closed_stops, rollback_worker_state_queries, worker_stopped_fail_closed
        success = True
        if action == "daemon-reload":
            daemon_reloads += 1
            success = failure_stage != "symlink_switch" or daemon_reloads > 1
        if action == "start" and units == ("atlaso.service",):
            candidate_starts += 1
            success = (
                failure_stage
                not in {
                    "candidate_startup",
                        "rollback_symlink_sync",
                        "rollback_database_missing",
                        "rollback_link_restore",
                        "rollback_activation",
                        "rollback_front_activation",
                        "rollback_host_finalizer_persistence",
                        "rollback_worker_state",
                        "rollback_worker_status_query",
                        "rollback_finalizer_persistence",
                        "rollback_gate",
                }
                or candidate_starts > 1
            )
        if action == "restart" and units == ("atlaso-worker.service",):
            success = failure_stage != "worker_restart"
        if action == "stop" and "atlaso-worker.service" in units:
            if expected_rolled_back and failure_stage != "rollback_gate":
                pytest.fail("healthy rollback must preserve the running worker through its definitive write")
            rollback_worker_fail_closed_stops += 1
            worker_stopped_fail_closed = True
        if action == "start" and "atlaso-worker.service" in units:
            rollback_worker_starts += 1
            pytest.fail("rollback must preserve the existing worker instead of starting a restored unit")
        if action == "is-active" and units == ("atlaso-worker.service",):
            success = not worker_stopped_fail_closed and failure_stage != "rollback_worker_state"
        if action == "show" and units == (
            "--property=ActiveState",
            "--value",
            "atlaso-worker.service",
        ):
            rollback_worker_state_queries += 1
            success = not (
                failure_stage == "rollback_worker_status_query" and rollback_worker_state_queries == 1
            )
            return {
                "command": ["systemctl", action, *units],
                "returncode": 0 if success else 1,
                "success": success,
                "stdout": "inactive" if success else "",
                "stderr": "" if success else "injected systemd query failure",
            }
        return {
            "command": ["systemctl", action, *units],
            "returncode": 0 if success else 1,
            "success": success,
            "stdout": "",
            "stderr": "" if success else "injected service failure",
        }

    monkeypatch.setattr(helper, "_service_command", service_command)
    monkeypatch.setattr(helper, "_service_main_pid", lambda _unit: 100)

    def worker_activation(**_kwargs):
        """Inject candidate worker-identity activation failure.

        Args:
            **_kwargs: Expected candidate worker identity fields.
        """
        success = failure_stage != "worker_activation"
        return {
            "command": ["release-activation-check", "worker_restart"],
            "returncode": 0 if success else 1,
            "success": success,
            "stdout": "",
            "stderr": "" if success else "injected worker identity failure",
            "layer": "worker_restart",
        }

    monkeypatch.setattr(helper, "_wait_for_worker_activation", worker_activation)
    maintenance_disables = 0
    maintenance_states: list[bool] = []
    rollback_sequence: list[str] = []

    def maintenance(enabled, *, cleanup_preflight_failure=False):
        """Inject one failure while removing candidate maintenance mode.

        Args:
            enabled: Whether nginx maintenance mode should remain active.
            cleanup_preflight_failure: Whether initial admission may restore the live front door on failure.
        """
        nonlocal maintenance_disables
        maintenance_states.append(enabled)
        success = True
        if not enabled:
            rollback_sequence.append("maintenance_cleanup")
            maintenance_disables += 1
            success = failure_stage != "maintenance_cleanup" or maintenance_disables > 1
        return {
            "command": ["maintenance", str(enabled)],
            "returncode": 0 if success else 1,
            "success": success,
            "stdout": "",
            "stderr": "" if success else "injected maintenance cleanup failure",
        }

    monkeypatch.setattr(helper, "_set_release_maintenance", maintenance)

    def health():
        """Return health."""
        return {
            "command": ["health"],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_wait_for_atlaso_health", health)
    monkeypatch.setattr(
        helper,
        "_sync_release_activation",
        lambda: {
            "command": ["release-activation-check", "durable_activation"],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
            "layer": "durable_activation",
        },
    )

    def activation(root, release_definition, **_kwargs):
        """Inject candidate final-readiness failures while keeping rollback healthy.

        Args:
            root: Release root being verified.
            release_definition: Expected release identity used by verification.
            **_kwargs: Additional activation-verification options.
        """
        is_candidate = root.name == "0.9.0"
        layer = (
            failure_stage
            if is_candidate and failure_stage in {"nginx_configuration", "management_front_door"}
            else "management_front_door"
            if not is_candidate and failure_stage == "rollback_activation"
            else "management_front_door"
            if (
                not is_candidate
                and failure_stage == "rollback_front_activation"
                and _kwargs.get("include_front_door", True)
            )
            else ""
        )
        success = not layer
        evidence = {
            "success": success,
            "candidate_version": str(release_definition["version"]),
            "failure_layer": layer,
        }
        commands = [
            {
                "command": ["release-activation-check", layer or "complete"],
                "returncode": 0 if success else 1,
                "success": success,
                "stdout": "",
                "stderr": "" if success else "injected final readiness failure",
                "layer": layer or "complete",
            }
        ]
        return evidence, commands

    monkeypatch.setattr(helper, "_release_activation_verification", activation)
    monkeypatch.setattr(helper, "_write_update_info", lambda _payload: None)
    write_finalizer = helper._write_release_finalizer
    sync_backups = helper._sync_release_transaction_backups
    finalizer_statuses: list[str] = []
    checkpoint_backup_counts: list[int] = []
    backup_sync_counts: list[int] = []

    def sync_transaction_backups(backup_root, database_backup, backups):
        """Capture each durable backup flush before its checkpoint is published.

        Args:
            backup_root: Transaction backup root supplied by the helper.
            database_backup: SQLite rollback snapshot supplied by the helper.
            backups: Installed-asset backups currently included in recovery.
        """
        if failure_stage == "transaction_backup_sync":
            raise OSError("injected rollback backup sync failure")
        sync_backups(backup_root, database_backup, backups)
        backup_sync_counts.append(len(backups))

    monkeypatch.setattr(helper, "_sync_release_transaction_backups", sync_transaction_backups)

    def finalizer(payload):
        """Inject a success-finalizer persistence failure inside the rollback boundary.

        Args:
            payload: Definitive or provisional transaction evidence to persist.
        """
        finalizer_statuses.append(str(payload.get("status") or ""))
        if payload.get("status") == "transaction_pending":
            recovery = payload.get("transaction_recovery") or {}
            backup_count = len(recovery.get("file_backups") or [])
            assert backup_sync_counts[-1] == backup_count
            checkpoint_backup_counts.append(backup_count)
        if payload.get("status") == "restart_pending":
            handoff_events.append("restart_pending")
        if payload.get("status") == "failed" and failure_stage != "rollback_gate":
            assert (tmp_path / "restart-gate").exists()
            rollback_sequence.append("definitive_finalizer")
        if failure_stage == "rollback_finalizer_persistence" and payload.get("status") == "failed":
            raise OSError("injected definitive rollback finalizer failure")
        if (
            failure_stage == "rollback_host_finalizer_persistence"
            and payload.get("status") == "failed"
            and payload.get("host_facing_ready") is True
        ):
            raise OSError("injected host-facing rollback finalizer failure")
        if failure_stage == "finalizer_persistence" and payload.get("status") == "succeeded":
            raise OSError("injected finalizer directory sync failure")
        write_finalizer(payload)

    monkeypatch.setattr(helper, "_write_release_finalizer", finalizer)

    outcome = "rolled back" if expected_rolled_back else "rollback was incomplete"
    with pytest.raises(ValueError, match=outcome):
        helper._apply_atlaso_release({}, {}, credential_path)

    link_restored = failure_stage != "rollback_link_restore"
    expected_release = previous if link_restored else releases / "0.9.0"
    assert current.resolve() == expected_release.resolve()
    assert get_identity() == (
        "after"
        if failure_stage in {"rollback_database_missing", "rollback_worker_status_query"}
        else "before"
    )
    assert (releases / "0.9.0").exists()
    finalizer = json.loads((tmp_path / "finalizer.json").read_text(encoding="utf-8"))
    if failure_stage == "rollback_finalizer_persistence":
        assert finalizer["status"] == "transaction_pending"
        assert finalizer["rolled_back"] is False
        assert maintenance_states[-1] is True
    else:
        assert finalizer["rolled_back"] is expected_rolled_back
        assert finalizer["rollback_health"] is expected_rolled_back
        assert finalizer["failure_layer"] == expected_layer
    assert finalizer["commands"]
    assert not credential_path.exists()
    assert rollback_worker_starts == 0
    if expected_rolled_back:
        assert rollback_sequence.index("definitive_finalizer") < rollback_sequence.index(
            "maintenance_cleanup"
        )
    expected_stop_attempts = (
        0
        if expected_rolled_back
        else 2
        if failure_stage == "rollback_worker_status_query"
        else 1
    )
    assert rollback_worker_fail_closed_stops == expected_stop_attempts
    assert rollback_worker_state_queries == expected_stop_attempts
    if failure_stage == "transaction_backup_sync":
        assert "transaction_pending" not in finalizer_statuses
        assert not checkpoint_backup_counts
        assert not backup_sync_counts
    else:
        assert "transaction_pending" in finalizer_statuses
    assert esx_allowlist.read_text(encoding="utf-8") == "previous-claim\n"
    if failure_stage == "transaction_backup_sync":
        assert not checkpoint_backup_counts
    elif failure_stage == "systemd_assets":
        assert checkpoint_backup_counts == [0]
    else:
        assert checkpoint_backup_counts[:2] == [0, 1]
    assert backup_sync_counts[: len(checkpoint_backup_counts)] == checkpoint_backup_counts
    if failure_stage in {"worker_restart", "worker_activation", "finalizer_persistence"}:
        assert "restart_pending" in finalizer_statuses
        assert handoff_events.index("restart_pending") < handoff_events.index("gate")
        assert not (tmp_path / "restart-gate").exists()
    if failure_stage == "rollback_symlink_sync":
        assert "rollback_release_link" in finalizer["rollback_failures"]
    if failure_stage == "rollback_database_missing":
        assert "rollback_database_restore" in finalizer["rollback_failures"]
        assert maintenance_states[-1] is True
    if not expected_rolled_back and failure_stage != "rollback_finalizer_persistence":
        assert finalizer["status"] == "rollback_pending"
        assert finalizer["transaction_recovery"]["owner"]
    if failure_stage == "rollback_link_restore":
        assert "rollback_release_link" in finalizer["rollback_failures"]
        assert "rollback_active_release_link" in finalizer["rollback_failures"]
        assert False not in maintenance_states
        assert maintenance_states[-1] is True
    if failure_stage == "rollback_activation":
        assert "rollback_activation_verification" in finalizer["rollback_failures"]
        assert False not in maintenance_states
        assert maintenance_states[-1] is True
    if failure_stage in {"rollback_front_activation", "rollback_host_finalizer_persistence"}:
        assert finalizer["status"] == "failed"
        assert finalizer["rolled_back"] is True
        assert finalizer["host_facing_ready"] is False
        assert maintenance_states[-1] is True
    if failure_stage in {"rollback_link_restore", "rollback_activation", "rollback_worker_state"}:
        assert (tmp_path / "restart-gate").exists()
    if failure_stage == "rollback_worker_state":
        assert "rollback_worker_state" in finalizer["rollback_failures"]
    if failure_stage == "rollback_gate":
        assert "rollback_worker_restart_gate_hold" in finalizer["rollback_failures"]
        assert not (tmp_path / "restart-gate").exists()


def test_release_activation_verification_requires_exact_candidate_through_nginx(monkeypatch, tmp_path):
    """Verify success evidence agrees across links, receipt, services, and both OpenAPI paths.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for release artifacts.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    release = release_payload()
    release_root = tmp_path / "releases/0.9.0"
    (release_root / ".venv").mkdir(parents=True)
    (release_root / ".release-manifest.json").write_text(json.dumps(release), encoding="utf-8")
    current = tmp_path / "current"
    current.symlink_to(release_root, target_is_directory=True)
    venv = tmp_path / ".venv"
    venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_VENV_LINK", venv)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", tmp_path / "maintenance")
    status_marker = tmp_path / "update-status-marker"
    status_marker.write_text("job_0123456789ab\n", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_STATUS_MARKER_PATH", status_marker)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "configuration is valid", ""),
    )
    monkeypatch.setattr(
        helper,
        "_service_command",
        lambda action, *units: {
            "command": ["systemctl", action, *units],
            "returncode": 0,
            "success": True,
            "stdout": "active",
            "stderr": "",
        },
    )
    monkeypatch.setattr(
        helper,
        "_console_management_readiness_checks",
        lambda: (
            True,
            (
                ("Atlaso application loopback", "http://127.0.0.1:8000/openapi.json", False, "200"),
                ("nginx HTTPS readiness", "https://127.0.0.1/openapi.json", True, "200"),
            ),
        ),
    )

    observed_urls = {}

    def version_check(*, layer, expected_version, url, **_kwargs):
        """Return exact candidate-version readiness for either endpoint.

        Args:
            layer: Stable readiness layer represented by the probe.
            expected_version: Candidate version expected from the endpoint.
            url: Endpoint used for the readiness probe.
            **_kwargs: Additional endpoint probe options.
        """
        observed_urls[layer] = url
        return helper._release_check(
            layer,
            True,
            f"{layer} reported Atlaso {expected_version}.",
            expected_version=expected_version,
            observed_version=expected_version,
        )

    monkeypatch.setattr(helper, "_wait_for_openapi_version", version_check)

    evidence, checks = helper._release_activation_verification(release_root, release)

    assert evidence == {
        "success": True,
        "candidate_version": "0.9.0",
        "current_release": str(release_root.resolve()),
        "compatibility_venv": str((release_root / ".venv").resolve()),
        "receipt_version": "0.9.0",
        "receipt_manifest_sha256": hashlib.sha256(
            json.dumps(release, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "maintenance_removed": True,
        "nginx_ready": True,
        "services_active": True,
        "internal_version": "0.9.0",
        "host_facing_version": "0.9.0",
        "failure_layer": "",
    }
    assert all(check["success"] for check in checks)
    assert observed_urls == {
        "internal_openapi": "http://127.0.0.1:8000/openapi.json",
        "management_front_door": (
            "https://127.0.0.1"
            f"{helper.ATLASO_UPDATE_READINESS_PATH}"
        ),
    }

    status_marker.unlink()
    observed_urls.clear()
    evidence, checks = helper._release_activation_verification(release_root, release)
    assert evidence["success"] is True
    assert all(check["success"] for check in checks)
    assert observed_urls["management_front_door"] == "https://127.0.0.1/openapi.json"


@pytest.mark.parametrize("failure_stage", ["", "maintenance_cleanup", "management_front_door", "finalizer_persistence"])
def test_committed_activation_finishes_forward_without_database_rollback(monkeypatch, tmp_path, failure_stage):
    """Verify the durable commit precedes exposure and every later failure preserves the candidate.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for candidate and gate evidence.
        failure_stage: Forward-completion failure injected after rollback is prohibited.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    candidate = tmp_path / "releases/0.9.0"
    candidate.mkdir(parents=True)
    receipt = release_payload()
    (candidate / ".release-manifest.json").write_text(json.dumps(receipt), encoding="utf-8")
    gate = tmp_path / "restart-gate"
    gate.write_text("job-forward", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_RESTART_GATE_PATH", gate)
    monkeypatch.setattr(helper, "_active_release_root", lambda: candidate)
    monkeypatch.setattr(helper, "_validated_release_recovery_context", lambda _parsed: {"candidate": candidate})
    events: list[str] = ["activation_committed"]

    def maintenance(enabled):
        """Record front-door state and inject cleanup failure.

        Args:
            enabled: Whether the transaction maintenance response is required.
        """
        events.append(f"maintenance:{enabled}")
        success = enabled or failure_stage != "maintenance_cleanup"
        return helper._release_check(
            "maintenance_hold" if enabled else "maintenance_cleanup",
            success,
            "maintenance transition",
        )

    monkeypatch.setattr(helper, "_set_release_maintenance", maintenance)
    monkeypatch.setattr(
        helper,
        "_sync_release_activation",
        lambda: helper._release_check("durable_activation", True, "durable"),
    )

    def activation(_root, _release, **kwargs):
        """Return internal success and optionally fail the exposed front-door proof.

        Args:
            _root: Candidate release root supplied by the helper.
            _release: Candidate receipt supplied by the helper.
            **kwargs: Verification phase controls.
        """
        front_door = kwargs.get("include_front_door", True)
        success = not (front_door and failure_stage == "management_front_door")
        layer = "management_front_door" if not success else "complete"
        events.append(f"verify:{'front' if front_door else 'internal'}")
        return (
            {"success": success, "failure_layer": "" if success else layer},
            [helper._release_check(layer, success, layer)],
        )

    monkeypatch.setattr(helper, "_release_activation_verification", activation)
    finalizers: list[str] = []

    def finalizer(payload):
        """Record finalizer state and inject definitive persistence failure.

        Args:
            payload: Forward activation evidence to persist.
        """
        status = str(payload.get("status") or "")
        events.append(f"finalizer:{status}")
        finalizers.append(status)
        if failure_stage == "finalizer_persistence" and status == "succeeded":
            raise OSError("injected definitive finalizer failure")

    monkeypatch.setattr(helper, "_write_release_finalizer", finalizer)
    monkeypatch.setattr(helper, "_write_update_info", lambda _payload: None)
    gate_states: list[bool] = []
    monkeypatch.setattr(
        helper,
        "_set_release_restart_gate",
        lambda enabled, _job_id="": gate_states.append(enabled),
    )
    parsed = {
        "job_id": "job-forward",
        "status": "activation_committed",
        "candidate_version": "0.9.0",
        "commands": [],
        "transaction_recovery": {"schema_version": 1},
    }
    finalizer_path = tmp_path / "finalizer.json"
    finalizer_path.write_text(json.dumps(parsed), encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer_path)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: False)

    result = helper._complete_committed_release_activation(parsed)

    assert candidate.exists()
    assert events.index("activation_committed") < events.index("maintenance:False")
    if failure_stage:
        assert result["status"] == "activation_committed"
        assert result["rolled_back"] is False
        assert finalizers[-1] == "activation_committed"
        assert not gate_states
    else:
        assert result["status"] == "succeeded"
        assert finalizers == ["succeeded"]
        assert gate_states == [False]


def test_committed_prestart_recreates_gate_and_defers_worker_proof(monkeypatch, tmp_path):
    """Verify reboot pre-start recreates the volatile gate without requiring its own worker.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for committed evidence.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    finalizer = tmp_path / "finalizer.json"
    parsed = {
        "job_id": "job-committed-reboot",
        "status": "activation_committed",
        "transaction_recovery": {"owner": {"boot_id": "old"}},
        "commands": [],
    }
    finalizer.write_text(json.dumps(parsed), encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: False)
    monkeypatch.setattr(helper, "_validated_release_recovery_context", lambda _parsed: {"candidate": tmp_path})
    gate_calls: list[tuple[bool, str]] = []
    monkeypatch.setattr(
        helper,
        "_set_release_restart_gate",
        lambda enabled, job_id="": gate_calls.append((enabled, job_id)),
    )
    monkeypatch.setattr(
        helper,
        "_set_release_maintenance",
        lambda _enabled: helper._release_check("maintenance_hold", True, "held"),
    )
    monkeypatch.setattr(
        helper,
        "_schedule_committed_release_completion",
        lambda _job_id: {
            **helper._release_check("committed_activation_handoff", True, "scheduled"),
            "owner": {"boot_id": "new", "pid": 202, "start_ticks": "22"},
        },
    )
    persisted: list[dict] = []
    monkeypatch.setattr(helper, "_write_release_finalizer", lambda payload: persisted.append(payload))
    monkeypatch.setattr(helper, "_write_update_info", lambda _payload: None)
    monkeypatch.setattr(
        helper,
        "_complete_committed_release_activation",
        lambda _parsed: pytest.fail("ExecStartPre must not require atlaso-worker.service"),
    )

    result = helper._recover_interrupted_release_transaction()

    assert result["status"] == "activation_committed"
    assert result["allow_worker"] is True
    assert gate_calls == [(True, "job-committed-reboot")]
    assert persisted[-1]["transaction_recovery"]["owner"] == {
        "boot_id": "new",
        "pid": 202,
        "start_ticks": "22",
    }


def test_committed_handoff_waits_for_new_worker_before_front_door(monkeypatch, tmp_path):
    """Verify the root handoff proves the post-ExecStart worker before definitive completion.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for candidate evidence.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    candidate = tmp_path / "releases/0.9.160"
    candidate.mkdir(parents=True)
    parsed = {
        "job_id": "job-committed-worker",
        "status": "activation_committed",
        "candidate_version": "0.9.160",
        "transaction_recovery": {"schema_version": 1},
        "commands": [],
    }
    finalizer = tmp_path / "finalizer.json"
    finalizer.write_text(json.dumps(parsed), encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer)
    monkeypatch.setattr(helper, "_validated_release_recovery_context", lambda _parsed: {"candidate": candidate})
    observed: dict[str, object] = {}

    def worker_activation(**kwargs):
        """Record the post-ExecStart candidate identity proof.

        Args:
            **kwargs: Worker activation expectations supplied by the helper.
        """
        observed.update(kwargs)
        return helper._release_check("worker_restart", True, "worker ready")

    monkeypatch.setattr(helper, "_wait_for_worker_activation", worker_activation)
    monkeypatch.setattr(
        helper,
        "_complete_committed_release_activation",
        lambda payload: {**payload, "status": "succeeded", "success": True, "allow_worker": True},
    )

    result = helper._finish_committed_release_after_worker_start()

    assert result["status"] == "succeeded"
    assert observed["expected_version"] == "0.9.160"
    assert observed["expected_release"] == candidate
    assert observed["expected_job_id"] == "job-committed-worker"
    assert observed["previous_pid"] == 0


def test_committed_forward_scheduler_binds_stable_unit_owner(monkeypatch):
    """Verify reboot forward completion reports one stable live helper identity.

    Args:
        monkeypatch: Pytest fixture used to replace systemd process discovery.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    commands: list[list[str]] = []

    def command_payload(command):
        """Record the transient-unit command and return successful scheduling evidence.

        Args:
            command: Root-owned systemd-run command selected by the helper.
        """
        commands.append(command)
        return helper._release_check("committed_activation_handoff", True, "scheduled")

    monkeypatch.setattr(helper, "_command_payload", command_payload)
    monkeypatch.setattr(helper, "_service_main_pid", lambda _unit: 303)
    monkeypatch.setattr(
        helper,
        "_running_worker_process_identity",
        lambda _pid: {"boot_id": "current", "pid": 303, "start_ticks": "33"},
    )

    first = helper._schedule_committed_release_completion("job-stable-forward")
    second = helper._schedule_committed_release_completion("job-stable-forward")

    first_unit = commands[0][commands[0].index("--unit") + 1]
    second_unit = commands[1][commands[1].index("--unit") + 1]
    assert first_unit == second_unit
    assert first["unit"] == f"{first_unit}.service"
    assert first["owner"] == {"boot_id": "current", "pid": 303, "start_ticks": "33"}
    assert second["owner"] == first["owner"]


def test_release_maintenance_cleanup_validates_and_reloads_nginx(monkeypatch, tmp_path):
    """Verify leaving maintenance mode proves the final nginx configuration and reload.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for the maintenance marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    maintenance = tmp_path / "maintenance"
    maintenance.write_text("", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "configuration is valid", ""),
    )
    calls = []

    def service_command(action, *units):
        """Record the nginx reload performed after maintenance removal.

        Args:
            action: Systemd action requested by maintenance cleanup.
            *units: Systemd units targeted by the action.
        """
        assert maintenance.is_file()
        calls.append((action, units))
        return {
            "command": ["systemctl", action, *units],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_service_command", service_command)

    result = helper._set_release_maintenance(False)

    assert result["success"] is True
    assert not maintenance.exists()
    assert calls == [("reload", ("nginx.service",))]


def test_release_maintenance_enable_guards_every_management_server_before_reload(
    monkeypatch,
    tmp_path,
):
    """Verify stale mixed management blocks are all closed before nginx reload.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for the management site and marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    maintenance = tmp_path / "run/atlaso-update-maintenance"
    management_site = tmp_path / "management.conf"
    condition = f"  if (-f {maintenance}) {{ return 503; }}"
    management_site.write_text(
        "\n".join(
            [
                "server {",
                "  listen 80 default_server;",
                "  location / { return 308 https://$host$request_uri; }",
                "}",
                "server {",
                condition,
                "  listen 443 ssl default_server;",
                "  location / { proxy_pass http://127.0.0.1:8000; }",
                "}",
                "server {",
                "  listen 192.0.2.10:443 ssl bind;",
                "  location / { proxy_pass http://127.0.0.1:8000; }",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_site)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "valid", ""),
    )
    calls: list[tuple[str, tuple[str, ...]]] = []

    def service_command(action, *units):
        """Assert every block is guarded before nginx is reloaded.

        Args:
            action: Systemd action requested by maintenance activation.
            *units: Systemd units targeted by the action.
        """
        text = management_site.read_text(encoding="utf-8")
        assert text.count(f"if (-f {maintenance}) {{ return 503; }}") == 3
        assert maintenance.is_file()
        calls.append((action, units))
        return {
            "command": ["systemctl", action, *units],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_service_command", service_command)
    monkeypatch.setattr(
        helper,
        "_verify_release_maintenance_response",
        lambda text: {
            "command": ["maintenance", "enable", "probe"],
            "returncode": 0,
            "success": condition in text,
            "stdout": "verified",
            "stderr": "",
            "layer": "maintenance_probe",
            "listener_count": 2,
            "stable_samples": 3,
        },
    )

    result = helper._set_release_maintenance(True, cleanup_preflight_failure=True)

    assert result["success"] is True
    assert result["maintenance_probe"]["stable_samples"] == 3
    assert calls == [("reload", ("nginx.service",))]


def test_release_maintenance_enable_rejects_missing_management_site(monkeypatch, tmp_path):
    """Verify a missing applied site aborts before nginx reload or Atlaso shutdown.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for the missing site and marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    maintenance = tmp_path / "run/atlaso-update-maintenance"
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", tmp_path / "missing.conf")
    monkeypatch.setattr(
        helper,
        "_service_command",
        lambda *_args, **_kwargs: pytest.fail("nginx reload must not run without the management site"),
    )

    result = helper._set_release_maintenance(True, cleanup_preflight_failure=True)

    assert result["success"] is False
    assert result["failure_layer"] == "management_site"
    assert "services remain running" in result["stderr"]
    assert not maintenance.exists()
    assert result["preflight_cleanup"]["success"] is True
    assert result["preflight_cleanup"]["marker_removed"] is True


def test_release_maintenance_enable_requires_live_503_proof(monkeypatch, tmp_path):
    """Verify marker visibility failure aborts before the release can stop Atlaso.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for the management site and marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    maintenance = tmp_path / "run/atlaso-update-maintenance"
    management_site = tmp_path / "management.conf"
    previous = "server {\n  listen 80 default_server;\n  location / { proxy_pass http://127.0.0.1:8000; }\n}\n"
    management_site.write_text(previous, encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_site)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "valid", ""),
    )
    monkeypatch.setattr(
        helper,
        "_service_command",
        lambda action, *units: {
            "command": ["systemctl", action, *units],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        },
    )
    monkeypatch.setattr(
        helper,
        "_verify_release_maintenance_response",
        lambda _text: helper._release_maintenance_failure(
            "maintenance_probe",
            "The applied listener returned 200; Atlaso services remain running.",
        ),
    )

    result = helper._set_release_maintenance(True, cleanup_preflight_failure=True)

    assert result["success"] is False
    assert result["failure_layer"] == "maintenance_probe"
    assert not maintenance.exists()
    assert management_site.read_text(encoding="utf-8") == previous
    assert result["preflight_cleanup"]["success"] is True
    assert result["preflight_cleanup"]["marker_removed"] is True


def test_release_maintenance_recovery_failure_retains_marker(monkeypatch, tmp_path):
    """Verify recovery cannot remove an existing fail-closed maintenance hold.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for the management site and marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    maintenance = tmp_path / "run/atlaso-update-maintenance"
    management_site = tmp_path / "management.conf"
    previous = "server {\n  listen 80 default_server;\n  location / { proxy_pass http://127.0.0.1:8000; }\n}\n"
    management_site.write_text(previous, encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_site)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "valid", ""),
    )
    monkeypatch.setattr(
        helper,
        "_service_command",
        lambda action, *units: {
            "command": ["systemctl", action, *units],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        },
    )
    monkeypatch.setattr(
        helper,
        "_verify_release_maintenance_response",
        lambda _text: helper._release_maintenance_failure(
            "maintenance_probe",
            "The recovery listener did not prove maintenance.",
        ),
    )

    result = helper._set_release_maintenance(True)

    assert result["success"] is False
    assert result["failure_layer"] == "maintenance_probe"
    assert maintenance.is_file()
    assert f"if (-f {maintenance}) {{ return 503; }}" in management_site.read_text(encoding="utf-8")
    assert "preflight_cleanup" not in result


def test_release_maintenance_enable_reload_failure_skips_live_probe(monkeypatch, tmp_path):
    """Verify a failed nginx reload cannot advance to marker-visibility proof.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for the management site and marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    maintenance = tmp_path / "run/atlaso-update-maintenance"
    management_site = tmp_path / "management.conf"
    previous = "server {\n  listen 80 default_server;\n  location / { proxy_pass http://127.0.0.1:8000; }\n}\n"
    management_site.write_text(previous, encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_site)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "valid", ""),
    )
    monkeypatch.setattr(
        helper,
        "_service_command",
        lambda action, *units: {
            "command": ["systemctl", action, *units],
            "returncode": 1,
            "success": False,
            "stdout": "",
            "stderr": "injected nginx reload failure",
        },
    )
    monkeypatch.setattr(
        helper,
        "_verify_release_maintenance_response",
        lambda _text: pytest.fail("maintenance proof must not run after reload failure"),
    )

    result = helper._set_release_maintenance(True, cleanup_preflight_failure=True)

    assert result["success"] is False
    assert result["failure_layer"] == "nginx_reload"
    assert not maintenance.exists()
    assert management_site.read_text(encoding="utf-8") == previous
    assert result["preflight_cleanup"]["success"] is False
    assert result["preflight_cleanup"]["marker_removed"] is True
    assert result["preflight_cleanup"]["nginx_reloaded"] is False


def test_release_maintenance_probe_requires_every_default_listener(monkeypatch):
    """Verify both HTTP and HTTPS defaults return stable 503 responses.

    Args:
        monkeypatch: Pytest fixture used to replace curl discovery and responses.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/curl" if command == "curl" else None)
    observed: list[tuple[str, bool]] = []

    def status(_curl, url, *, insecure=False):
        """Record each listener proof and inject one unguarded HTTPS response.

        Args:
            _curl: Resolved curl path.
            url: Management URL selected for proof.
            insecure: Whether the HTTPS probe bypasses local CA trust.
        """
        observed.append((url, insecure))
        return "200" if url.startswith("https://") else "503"

    monkeypatch.setattr(helper, "_console_management_http_status", status)
    site = "\n".join(
        [
            "server {",
            "  listen 8080 default_server;",
            "}",
            "server {",
            "  listen 8443 ssl default_server;",
            "}",
            "",
        ]
    )

    result = helper._verify_release_maintenance_response(
        site,
        samples=1,
        attempts=1,
        retry_interval=0,
    )

    assert result["success"] is False
    assert result["failure_layer"] == "maintenance_probe"
    assert observed == [
        ("http://127.0.0.1:8080/openapi.json", False),
        ("https://127.0.0.1:8443/openapi.json", True),
    ]


def test_release_maintenance_probe_allows_bounded_nginx_convergence(monkeypatch):
    """Verify a transient old response must converge before three stable samples.

    Args:
        monkeypatch: Pytest fixture used to replace curl discovery and responses.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/curl" if command == "curl" else None)
    statuses = iter(["200", "503", "503", "503"])
    sleeps: list[float] = []
    monkeypatch.setattr(
        helper,
        "_console_management_http_status",
        lambda *_args, **_kwargs: next(statuses),
    )
    monkeypatch.setattr(helper.time, "sleep", sleeps.append)

    result = helper._verify_release_maintenance_response(
        "server {\n  listen 80 default_server;\n}\n",
        attempts=4,
        retry_interval=0.2,
    )

    assert result["success"] is True
    assert result["stable_samples"] == 3
    assert result["attempts"] == 4
    assert sleeps == [0.2, 0.2, 0.2]


def test_release_maintenance_cleanup_failure_keeps_nginx_in_maintenance(monkeypatch, tmp_path):
    """Verify final nginx validation failure preserves the fail-closed response.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for the maintenance marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    maintenance = tmp_path / "maintenance"
    maintenance.write_text("", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 1, "", "invalid configuration"),
    )

    result = helper._set_release_maintenance(False)

    assert result["success"] is False
    assert maintenance.is_file()


def test_release_maintenance_reload_failure_keeps_nginx_in_maintenance(monkeypatch, tmp_path):
    """Verify nginx reload failure cannot expose the unverified candidate front door.

    Args:
        monkeypatch: Pytest fixture used to replace helper dependencies.
        tmp_path: Temporary directory provided for the maintenance marker.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    maintenance = tmp_path / "maintenance"
    maintenance.write_text("", encoding="utf-8")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", maintenance)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "configuration is valid", ""),
    )
    monkeypatch.setattr(
        helper,
        "_service_command",
        lambda action, *units: {
            "command": ["systemctl", action, *units],
            "returncode": 1,
            "success": False,
            "stdout": "",
            "stderr": "injected nginx reload failure",
        },
    )

    result = helper._set_release_maintenance(False)

    assert result["success"] is False
    assert maintenance.is_file()


@pytest.mark.parametrize("failure_stage", ["download", "signature", "extraction", "installation"])
def test_pre_switch_release_failures_leave_previous_release_and_database_untouched(
    monkeypatch,
    tmp_path,
    failure_stage,
):
    """Verify that pre switch release failures leave previous release and database untouched.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        failure_stage: Failure stage supplied to the test scenario.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    home = tmp_path / "opt/atlaso"
    previous = home / "releases/bootstrap-0.9.0"
    previous.mkdir(parents=True)
    (previous / ".venv").mkdir()
    current = home / "current"
    current.symlink_to(previous, target_is_directory=True)
    database = tmp_path / "atlaso.db"
    database.write_bytes(b"database-before")
    monkeypatch.setattr(helper, "ATLASO_HOME", home)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", home / "releases")
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_VENV_LINK", home / ".venv")
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)

    metadata = canonical(
        {
            "schema_version": 1,
            "version": "0.9.0",
            "git_commit": "a" * 40,
            "built_at": "2026-07-23T12:00:00Z",
            "supported_python_abis": ["cp314"],
        }
    )
    bundle_buffer = io.BytesIO()
    with tarfile.open(fileobj=bundle_buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("bundle-metadata.json")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))
    bundle_bytes = bundle_buffer.getvalue()
    release = release_payload()
    release["supported_python_abis"] = ["cp314"]
    release["bundle"] = {
        "url": "https://example.test/bundle.tar.gz",
        "size": len(bundle_bytes),
        "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
    }
    release["content_hashes"] = {
        "bundle-metadata.json": hashlib.sha256(metadata).hexdigest(),
    }
    channel = {
        "channel": "development",
        "release_manifest_url": "https://example.test/release-manifest.json",
    }
    if failure_stage == "signature":
        monkeypatch.setattr(
            helper,
            "_download_signed_release_from_sources",
            lambda *_args: (_ for _ in ()).throw(ValueError("injected invalid signature")),
        )
    else:
        monkeypatch.setattr(
            helper,
            "_download_signed_release_from_sources",
            lambda *_args: (channel, release, channel["release_manifest_url"], None),
        )
    if failure_stage == "download":
        monkeypatch.setattr(
            helper,
            "_fetch_http_bytes",
            lambda *_args: (_ for _ in ()).throw(OSError("injected download failure")),
        )
    else:
        monkeypatch.setattr(helper, "_fetch_http_bytes", lambda *_args: bundle_bytes)
    if failure_stage == "extraction":
        monkeypatch.setattr(
            helper,
            "_safe_extract_release",
            lambda *_args: (_ for _ in ()).throw(ValueError("injected extraction failure")),
        )
    if failure_stage == "installation":
        monkeypatch.setattr(
            helper,
            "_install_release_venv",
            lambda *_args: [
                {
                    "command": ["offline-install"],
                    "returncode": 1,
                    "success": False,
                    "stdout": "",
                    "stderr": "injected installation failure",
                }
            ],
        )

    with pytest.raises((OSError, ValueError)):
        helper._apply_atlaso_release({}, {})
    assert current.resolve() == previous.resolve()
    assert database.read_bytes() == b"database-before"
    assert not (home / "releases/0.9.0").exists()


def test_failed_revalidation_does_not_delete_an_existing_release(monkeypatch, tmp_path):
    """Verify that failed revalidation does not delete an existing release.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    home = tmp_path / "opt/atlaso"
    releases = home / "releases"
    previous = releases / "bootstrap-0.9.0"
    existing = releases / "0.9.0"
    previous.mkdir(parents=True)
    existing.mkdir(parents=True)
    marker = existing / "known-good"
    marker.write_text("preserve", encoding="utf-8")
    current = home / "current"
    current.symlink_to(previous, target_is_directory=True)
    release = release_payload()
    bundle = b"signed-bundle"
    release["bundle"] = {
        "url": "https://example.test/bundle.tar.gz",
        "size": len(bundle),
        "sha256": hashlib.sha256(bundle).hexdigest(),
    }
    monkeypatch.setattr(helper, "ATLASO_HOME", home)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", releases)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(
        helper,
        "_download_signed_release_from_sources",
        lambda *_args: (
            {"channel": "development"},
            release,
            "https://example.test/release-manifest.json",
            None,
        ),
    )
    monkeypatch.setattr(helper, "_fetch_http_bytes", lambda *_args: bundle)
    monkeypatch.setattr(
        helper,
        "_safe_extract_release",
        lambda *_args: (_ for _ in ()).throw(ValueError("injected extraction failure")),
    )

    with pytest.raises(ValueError, match="injected extraction failure"):
        helper._apply_atlaso_release({}, {})

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert current.resolve() == previous.resolve()


def test_authenticated_release_redirect_rejects_another_origin():
    """Verify that authenticated release redirect rejects another origin."""
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    source = "https://updates.example.test/channels/stable/manifest.json"
    request = helper.Request(source, headers={"Authorization": "Basic protected"})
    handler = helper._UpdateRedirectHandler(authenticated_origin=helper._url_origin(source))

    with pytest.raises(ValueError, match="another origin"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://redirect.example.test/manifest.json",
        )


def test_authenticated_release_redirect_preserves_same_origin_authorization():
    """Verify that authenticated release redirect preserves same origin authorization."""
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    source = "https://updates.example.test/channels/stable/manifest.json"
    request = helper.Request(source, headers={"Authorization": "Basic protected"})
    handler = helper._UpdateRedirectHandler(authenticated_origin=helper._url_origin(source))

    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://updates.example.test/releases/v0.9.0/manifest.json",
    )

    assert redirected.full_url == "https://updates.example.test/releases/v0.9.0/manifest.json"
    assert redirected.get_header("Authorization") == "Basic protected"


def test_release_redirect_rejects_https_downgrade_without_credentials():
    """Verify that release redirect rejects https downgrade without credentials."""
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    source = "https://updates.example.test/channels/stable/manifest.json"
    handler = helper._UpdateRedirectHandler(authenticated_origin=None)

    with pytest.raises(ValueError, match="less secure scheme"):
        handler.redirect_request(
            helper.Request(source),
            None,
            302,
            "Found",
            {},
            "http://updates.example.test/manifest.json",
        )
