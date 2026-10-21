"""Synthetic recovery tests never access an appliance or operator key store."""

from __future__ import annotations

import copy
import json
import os
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from atlaso.app.kmip.recovery import (
    RecoveryError,
    build_candidate,
    capture,
    decrypt,
    encrypt,
)
from atlaso.app.kmip.store import WrappedKeyStore

PASSPHRASE = "synthetic-recovery-test-only"


def snapshot_fixture(tmp_path: Path):
    """Build an active synthetic key and its exact protected snapshot.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
    """
    source = tmp_path / "source"
    provider = str(uuid4())
    store = WrappedKeyStore(source / "store.db", source / "kek.json", secrets_key="synthetic-source")
    key = store.create_key(provider, name="synthetic")
    store.activate_key(provider, key.key_id)
    metadata, plaintext = store.get_key(provider, key.key_id)
    snapshot = capture(store, {"providers": [{"id": provider, "name": "synthetic", "description": "", "enabled": True}],
                               "vcenters": [], "certificates": []})
    store.close()
    return snapshot, metadata, plaintext


def test_authenticated_roundtrip_preserves_exact_wrapped_identity_and_kek(tmp_path):
    """A different appliance secret can recover the pre-export active key.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
    """
    snapshot, metadata, plaintext = snapshot_fixture(tmp_path)
    archive = encrypt(snapshot, PASSPHRASE)
    assert plaintext not in archive
    assert metadata.key_id.encode() not in archive
    candidate = tmp_path / "candidate"
    candidate.mkdir(mode=0o700)
    build_candidate(decrypt(archive, PASSPHRASE), candidate, secrets_key="synthetic-target")
    restored = WrappedKeyStore(candidate / "store.db", candidate / "kek.json", secrets_key="synthetic-target")
    assert restored.get_key(metadata.provider_id, metadata.key_id) == (metadata, plaintext)
    assert capture(restored, snapshot["trust"])["keys"] == snapshot["keys"]
    assert capture(restored, snapshot["trust"])["kek"] == snapshot["kek"]
    restored.close()
    reopened = WrappedKeyStore(candidate / "store.db", candidate / "kek.json", secrets_key="synthetic-target")
    assert reopened.get_key(metadata.provider_id, metadata.key_id) == (metadata, plaintext)
    reopened.close()


@pytest.mark.parametrize("damage", ["wrong-passphrase", "truncate", "corrupt", "version"])
def test_archive_rejects_damage_before_candidate_creation(tmp_path, damage):
    """Authentication and framing failures cannot reach store publication.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        damage: Malformed archive or snapshot variant exercised by the test.
    """
    snapshot, _, _ = snapshot_fixture(tmp_path)
    archive = encrypt(snapshot, PASSPHRASE)
    passphrase = PASSPHRASE
    if damage == "wrong-passphrase":
        passphrase = "wrong-synthetic-passphrase"
    elif damage == "truncate":
        archive = archive[:-20]
    elif damage == "corrupt":
        archive = archive[:-1] + bytes([archive[-1] ^ 1])
    else:
        archive = b"!" + archive[1:]
    with pytest.raises(RecoveryError):
        decrypt(archive, passphrase)
    assert not (tmp_path / "candidate").exists()


@pytest.mark.parametrize("damage", ["schema", "duplicate-key", "duplicate-provider", "incomplete", "missing-provider", "kek"])
def test_authenticated_but_invalid_snapshot_is_rejected(tmp_path, damage):
    """A valid passphrase never permits malformed or incomplete logical state.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        damage: Malformed archive or snapshot variant exercised by the test.
    """
    snapshot, _, _ = snapshot_fixture(tmp_path)
    snapshot = copy.deepcopy(snapshot)
    if damage == "schema":
        snapshot["schema"] = 2
    elif damage == "duplicate-key":
        snapshot["keys"].append(snapshot["keys"][0])
    elif damage == "duplicate-provider":
        snapshot["trust"]["providers"].append(snapshot["trust"]["providers"][0])
    elif damage == "incomplete":
        del snapshot["keys"][0]["ciphertext"]
    elif damage == "missing-provider":
        snapshot["trust"]["providers"] = []
    else:
        snapshot["kek"] = "aW52YWxpZA=="
    candidate = tmp_path / "candidate"
    candidate.mkdir(mode=0o700)
    with pytest.raises(RecoveryError):
        decoded = decrypt(encrypt(snapshot, PASSPHRASE), PASSPHRASE)
        build_candidate(decoded, candidate, secrets_key="synthetic-target")


def test_nonempty_candidate_remains_unchanged(tmp_path):
    """Candidate construction must never adopt an existing store.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
    """
    snapshot, _, _ = snapshot_fixture(tmp_path)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    sentinel = candidate / "preserved"
    sentinel.write_bytes(b"unchanged")
    with pytest.raises(RecoveryError):
        build_candidate(snapshot, candidate, secrets_key="synthetic-target")
    assert sentinel.read_bytes() == b"unchanged"


def test_sqlite_handles_close_before_recovery_files_are_moved(tmp_path):
    """Checkpoint and close permit Windows candidate validation and retry.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
    """
    snapshot, _, _ = snapshot_fixture(tmp_path)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    build_candidate(snapshot, candidate, secrets_key="synthetic-target")
    candidate.rename(tmp_path / "moved")
    assert json.loads((tmp_path / "moved/public-trust.json").read_bytes()) == snapshot["trust"]
    with sqlite3.connect(tmp_path / "moved/store.db") as db:
        assert db.execute("SELECT count(*) FROM wrapped_keys").fetchone()[0] == 1


def test_recovery_apply_keeps_expired_public_history_without_requiring_its_trust(tmp_path, monkeypatch):
    """Retained historical certificates must not make a reviewed Apply impossible.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    from atlaso.app.kmip import recovery_runtime as runtime
    from atlaso.app.services.vsphere_key_providers import parse_public_certificate
    from tests.routers.api_v1.test_certificate_trust import _public_client_certificate

    provider, vcenter = str(uuid4()), str(uuid4())
    certificates = []
    for expired in (False, True):
        pem, _private = _public_client_certificate(expired=expired)
        parsed = parse_public_certificate(pem, require_current=False)
        certificates.append({"certificate_pem": pem, "fingerprint_sha256": parsed["fingerprint_sha256"], "trusted_vcenter_id": vcenter})
    state = tmp_path / "state"
    state.mkdir()
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    config = tmp_path / "server.json"
    config.write_text(json.dumps({"enabled": True, "providers": [{"id": provider, "client_fingerprints": [certificates[0]["fingerprint_sha256"]]}]}))
    journal = {"identity": [state.stat().st_dev, state.stat().st_ino], "trust": {
        "providers": [{"id": provider, "enabled": True}],
        "vcenters": [{"id": vcenter, "provider_id": provider, "enabled": True}],
        "certificates": certificates,
    }}
    (anchor / "pending.json").write_text(json.dumps(journal))
    monkeypatch.setattr(runtime, "STATE", state)
    monkeypatch.setattr(runtime, "ANCHOR", anchor)
    # This test exercises trust rendering, with native directory custody checked in Linux.
    handle_file = tmp_path / "handle"
    handle_file.write_bytes(b"")
    monkeypatch.setattr(runtime, "_secure_anchor", lambda _path: os.open(handle_file, os.O_RDONLY))
    monkeypatch.setattr(runtime.os, "fsync", lambda _fd: None)
    runtime.authorize(config)
    runtime.assert_startup_allowed(config)
    assert json.loads((anchor / "pending.json").read_bytes()) == journal


@pytest.mark.parametrize("operation", ["export", "import"])
def test_recovery_admission_contention_never_reaches_helper(monkeypatch, operation):
    """Concurrent desired-state writers prevent any operational side effect.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
        operation: Recovery operation exercised by the test.
    """
    from atlaso.app.services import kmip_recovery as service
    from atlaso.app.services.appliance_apply_admission import (
        ApplianceApplyAdmissionBusy,
    )

    def busy(_db):
        """Busy.

        Args:
            _db: Db supplied to this operation.
        """
        raise ApplianceApplyAdmissionBusy("synthetic contention")

    monkeypatch.setattr(service, "lock_appliance_apply_snapshot_tables", busy)
    monkeypatch.setattr(service, "_request", lambda *_args: pytest.fail("unadmitted helper mutation"))
    with pytest.raises(RecoveryError, match="admission is busy"):
        if operation == "export":
            service.export_archive(None, PASSPHRASE)
        else:
            service.import_archive(None, b"synthetic", PASSPHRASE)


@pytest.mark.skipif(os.name != "posix", reason="Native recovery directory-fd contract")
@pytest.mark.parametrize("failure", ["duplicate-key", "journal-before-publish", "journal-after-publish"])
def test_failed_preparation_cleans_only_unjournaled_candidate(tmp_path, monkeypatch, failure):
    """Repeated rejected imports cannot accumulate partial key-bearing stores.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        monkeypatch: Pytest fixture replacing external dependencies.
        failure: Injected preparation failure exercised by this regression.
    """
    from atlaso.app.kmip import recovery_runtime as runtime

    snapshot, _, _ = snapshot_fixture(tmp_path)
    if failure == "duplicate-key":
        snapshot["keys"].append(snapshot["keys"][0])
    archive = encrypt(snapshot, PASSPHRASE)
    anchor = tmp_path / "anchor"
    anchor.mkdir(mode=0o700)
    state = tmp_path / "state"
    state.mkdir()
    sentinel = anchor / "previous-preserved"
    sentinel.mkdir()
    (sentinel / "preserved").write_bytes(b"unchanged")
    monkeypatch.setattr(runtime, "ANCHOR", anchor)
    monkeypatch.setattr(runtime, "STATE", state)
    # Production root ownership is exercised separately on the Photon appliance.
    monkeypatch.setattr(runtime, "_secure_anchor", lambda path: os.open(path, os.O_RDONLY | runtime.O_DIRECTORY))
    original_journal = runtime._journal

    def fail_journal(path, document):
        """Fail journal.

        Args:
            path: Filesystem entry whose ownership and contents are checked.
            document: Complete checkpoint document to publish durably.
        """
        if failure == "journal-after-publish":
            original_journal(path, document)
        raise OSError("synthetic journal failure")

    if failure != "duplicate-key":
        monkeypatch.setattr(runtime, "_journal", fail_journal)
    for _ in range(3 if failure != "journal-after-publish" else 1):
        with pytest.raises((RecoveryError, OSError)):
            runtime.import_archive(archive, PASSPHRASE, "synthetic-target", uid=os.getuid(), gid=os.getgid())
        assert not list(state.iterdir())
        assert (sentinel / "preserved").read_bytes() == b"unchanged"
        candidates = list(anchor.glob("candidate-*"))
        if failure == "journal-after-publish":
            assert len(candidates) == 1
            assert json.loads((anchor / "pending.json").read_bytes())["candidate"] == candidates[0].name
        else:
            assert not candidates
            assert not (anchor / "pending.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="Native recovery directory-fd contract")
def test_unjournaled_cleanup_refuses_replaced_candidate(tmp_path):
    """An identity mismatch must preserve the replacement and original stores.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
    """
    from atlaso.app.kmip import recovery_runtime as runtime

    anchor_fd = os.open(tmp_path, os.O_RDONLY | runtime.O_DIRECTORY)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    candidate_fd = os.open(candidate, os.O_RDONLY | runtime.O_DIRECTORY)
    try:
        candidate.rename(tmp_path / "original")
        candidate.mkdir()
        (candidate / "preserved").write_bytes(b"unchanged")
        with pytest.raises(RecoveryError, match="identity changed"):
            runtime._discard_unjournaled_candidate("candidate", candidate_fd, anchor_fd)
        assert (candidate / "preserved").read_bytes() == b"unchanged"
        assert (tmp_path / "original").is_dir()
    finally:
        os.close(candidate_fd)
        os.close(anchor_fd)


@pytest.mark.parametrize("failure", ["service-before", "service-after", "pending-after"])
def test_completion_failure_retains_pending_gate_and_resumes(tmp_path, monkeypatch, failure):
    """Checkpoint retirement failures preserve startup protection and retry.

    Args:
        tmp_path: Isolated filesystem directory supplied by pytest.
        monkeypatch: Pytest fixture replacing native descriptor operations on Windows.
        failure: Completion rename boundary at which to inject an error.
    """
    from atlaso.app.kmip import recovery_runtime as runtime

    anchor = tmp_path / "anchor"
    state = tmp_path / "state"
    anchor.mkdir()
    state.mkdir()
    config = tmp_path / "server.json"
    config.write_text(json.dumps({"enabled": True, "providers": []}), encoding="utf-8")
    journal = {"archive": "synthetic", "identity": [state.stat().st_dev, state.stat().st_ino],
               "trust": {"providers": [], "vcenters": [], "certificates": []}}
    (anchor / "pending.json").write_text(json.dumps(journal), encoding="utf-8")
    (anchor / "service.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(runtime, "ANCHOR", anchor)
    monkeypatch.setattr(runtime, "STATE", state)
    handle = tmp_path / "handle"
    handle.write_bytes(b"")
    monkeypatch.setattr(runtime, "_secure_anchor", lambda _path: os.open(handle, os.O_RDONLY))
    monkeypatch.setattr(runtime.os, "fsync", lambda _fd: None)
    runtime.authorize(config)
    fail_once = True

    def rename(source, destination, source_fd, destination_fd):
        """Simulate a native rename and one failure before or after publication.

        Args:
            source: Entry being moved within the protected anchor.
            destination: Unoccupied destination entry.
            source_fd: Pinned source parent, unused by this portable simulation.
            destination_fd: Pinned destination parent, unused by this portable simulation.
        """
        nonlocal fail_once
        if source in {"service.json", "pending.json"} or source.startswith("completed-"):
            assert (anchor / "pending.json").exists() or source.startswith("completed-")
        if source == "pending.json":
            assert not (anchor / "service.json").exists()
        inject = fail_once and source == ("pending.json" if failure == "pending-after" else "service.json")
        if inject and failure == "service-before":
            fail_once = False
            raise OSError("synthetic checkpoint rename failure")
        assert not (anchor / destination).exists()
        (anchor / source).rename(anchor / destination)
        if inject:
            fail_once = False
            raise OSError("synthetic post-rename flush failure")

    monkeypatch.setattr(runtime, "_rename_absent", rename)
    with pytest.raises(OSError):
        runtime.authorize(config, complete=True)
    assert runtime.pending()
    # Apply rollback changes the runtime bytes; the retained journal must deny it.
    original = config.read_bytes()
    config.write_bytes(b"{}")
    with pytest.raises(RecoveryError):
        runtime.assert_startup_allowed(config)
    config.write_bytes(original)
    runtime.authorize(config, complete=True)
    assert not runtime.pending()
    assert not (anchor / "service.json").exists()
    assert json.loads((anchor / "completed-synthetic.json").read_bytes()) == journal
    states = {"atlaso-kmip.service": [False, False], "atlaso-kms.service": [False, False]}
    assert runtime.service_checkpoint({"binding": "different", "operation": "export", "states": states}) == {"states": states}
