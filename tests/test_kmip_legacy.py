"""Prove legacy admission never writes or discards retained PyKMIP data."""

import sqlite3
import subprocess

import pytest

from atlaso.app.kmip.legacy import LegacyStoreError, assert_legacy_empty


def test_empty_missing_and_retained_legacy_stores(tmp_path):
    """Empty-store proof is read-only; any application row blocks replacement."""
    state, config = tmp_path / "kms", tmp_path / "pykmip.conf"
    assert_legacy_empty(state, config)
    state.mkdir()
    database = state / "pykmip.db"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE managed_objects(id INTEGER PRIMARY KEY, value BLOB)")
    original = database.read_bytes()
    assert_legacy_empty(state, config)
    assert database.read_bytes() == original
    with sqlite3.connect(database) as db:
        db.execute("INSERT INTO managed_objects VALUES (1, X'01')")
    original = database.read_bytes()
    with pytest.raises(LegacyStoreError, match="preserved"):
        assert_legacy_empty(state, config)
    assert database.read_bytes() == original


@pytest.mark.parametrize("kind", ["corrupt", "unknown", "journal", "configured-missing"])
def test_unavailable_legacy_evidence_fails_closed(tmp_path, kind):
    """Missing configured data, corruption, and retained journals are preserved."""
    state, config = tmp_path / "kms", tmp_path / "pykmip.conf"
    state.mkdir()
    path = state / {"corrupt": "pykmip.db", "unknown": "retained", "journal": "pykmip.db-wal", "configured-missing": "missing.db"}[kind]
    if kind == "configured-missing":
        config.write_text("[server]\ndatabase_path=" + str(path) + "\n")
    else:
        path.write_bytes(b"synthetic-retained-evidence")
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    with pytest.raises(LegacyStoreError):
        assert_legacy_empty(state, config)
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before


@pytest.mark.parametrize("posture", ["active", "unavailable", "late-write", "inactive"])
def test_release_admission_requires_stopped_writer_and_final_empty_proof(tmp_path, monkeypatch, posture):
    """A candidate import must reject both an active old writer and its late commit."""
    from atlaso.app.kmip import legacy

    state, config = tmp_path / "kms", tmp_path / "missing.conf"
    state.mkdir()
    database = state / "pykmip.db"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE objects(id INTEGER PRIMARY KEY)")

    def probe(*_args, **_kwargs):
        if posture == "late-write":
            with sqlite3.connect(database) as db:
                db.execute("INSERT INTO objects VALUES (1)")
        return subprocess.CompletedProcess([], 1 if posture == "unavailable" else 0,
                                           "LoadState=loaded\nActiveState=" + ("active" if posture == "active" else "inactive"), "")

    monkeypatch.setattr(legacy.subprocess, "run", probe)
    if posture == "inactive":
        legacy.assert_release_admission(state, config)
    else:
        with pytest.raises(LegacyStoreError):
            legacy.assert_release_admission(state, config)
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT count(*) FROM objects").fetchone()[0] == (1 if posture == "late-write" else 0)
