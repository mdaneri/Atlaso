"""Verify full retained history and source-bound redaction across pages."""

import gzip
from pathlib import Path

import pytest

from atlaso.app.services import log_viewer


def test_file_history_reads_every_line_beyond_old_tail(tmp_path):
    """Walk bounded pages without losing the first or final retained entries.

    Args:
        tmp_path: Test-owned log directory.
    """
    path = tmp_path / "history.log"
    expected = [f"entry {index}" for index in range(1501)]
    path.write_text("\n".join(expected) + "\n", encoding="utf-8")
    cursor = ""
    actual = []
    while True:
        page = log_viewer.file_page(path, source="test", cursor=cursor)
        actual.extend(page["text"].splitlines())
        assert len(page["text"].splitlines()) <= 500
        cursor = page["next_cursor"]
        if not page["has_more"]:
            break
    assert actual == expected
    path.write_text(path.read_text(encoding="utf-8") + "later entry\n", encoding="utf-8")
    assert log_viewer.file_page(path, source="test", cursor=cursor)["text"] == "later entry"


def test_history_cursor_preserves_private_key_redaction(tmp_path):
    """A page boundary cannot turn the interior of a key into visible text.

    Args:
        tmp_path: Test-owned log directory.
    """
    path = tmp_path / "history.log"
    path.write_text("safe\n-----BEGIN PRIVATE KEY-----\nconcealed material\n-----END PRIVATE KEY-----\nlast\n", encoding="utf-8")
    first = log_viewer.file_page(path, source="test", limit=2)
    second = log_viewer.file_page(path, source="test", cursor=first["next_cursor"])
    assert "concealed" not in second["text"]
    assert second["text"].endswith("last")
    with pytest.raises(ValueError, match="another source"):
        log_viewer.file_page(path, source="other", cursor=first["next_cursor"])
    with pytest.raises(ValueError):
        log_viewer.file_page(path, source="test", cursor=first["next_cursor"] + "changed")


def test_history_rotation_is_reported(tmp_path):
    """A replaced file never silently continues an old offset.

    Args:
        tmp_path: Test-owned log directory.
    """
    path = tmp_path / "history.log"
    path.write_text("before\n", encoding="utf-8")
    first = log_viewer.file_page(path, source="test")
    path.rename(tmp_path / "old.log")
    path.write_text("after\n", encoding="utf-8")
    page = log_viewer.file_page(path, source="test", cursor=first["next_cursor"])
    assert page["reset"]
    assert page["text"] == "after"


def test_nonregular_log_is_rejected(tmp_path):
    """No caller can turn a fixed-file viewer into a directory reader.

    Args:
        tmp_path: Test-owned directory.
    """
    with pytest.raises((ValueError, OSError)):
        log_viewer.file_page(Path(tmp_path), source="test")


def test_numbered_and_compressed_rotations_are_complete(tmp_path):
    """Keep archived entries in chronological order across file boundaries.

    Args:
        tmp_path: Test-owned retained history directory.
    """
    path = tmp_path / "history.log"
    with gzip.open(tmp_path / "history.log.2.gz", "wb") as archive:
        archive.write(b"oldest\n")
    (tmp_path / "history.log.1").write_bytes(b"older\n")
    path.write_bytes(b"current\n")
    cursor, entries = "", []
    while True:
        page = log_viewer.file_page(path, source="test", cursor=cursor)
        entries.extend(page["text"].splitlines())
        cursor = page["next_cursor"]
        if not page["has_more"]:
            break
    assert entries == ["oldest", "older", "current"]


def test_partial_line_waits_for_completion(tmp_path):
    """A writer's incomplete line cannot bypass line-based redaction.

    Args:
        tmp_path: Test-owned live history directory.
    """
    path = tmp_path / "history.log"
    path.write_bytes(b"safe\n-----BEGIN PRIVATE")
    first = log_viewer.file_page(path, source="test")
    assert first["text"] == "safe"
    assert not first["has_more"]
    with path.open("ab") as handle:
        handle.write(b" KEY-----\nsecret material\n-----END PRIVATE KEY-----\n")
    page = log_viewer.file_page(path, source="test", cursor=first["next_cursor"])
    assert "secret material" not in page["text"]
    assert page["text"].count("[redacted private key]") == 3


def test_copytruncate_regrowth_resets_position(tmp_path):
    """A reused inode cannot silently hide a replacement file's first lines.

    Args:
        tmp_path: Test-owned current log directory.
    """
    path = tmp_path / "history.log"
    path.write_bytes(b"old\n")
    first = log_viewer.file_page(path, source="test")
    path.write_bytes(b"replacement is longer\n")
    page = log_viewer.file_page(path, source="test", cursor=first["next_cursor"])
    assert page["reset"]
    assert page["text"] == "replacement is longer"


def test_privileged_file_reader_preserves_boundaries(tmp_path):
    """The fixed privileged source has the same rotation and partial-line contract.

    Args:
        tmp_path: Test-owned fixed log path.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    path = tmp_path / "access.log"
    (tmp_path / "access.log.1").write_bytes(b"archived\n")
    path.write_bytes(b"current\npartial")
    first = helper._read_fixed_log_history(path, {})
    assert first["lines"] == ["archived"]
    current = helper._read_fixed_log_history(path, first["file_position"])
    assert current["lines"] == ["current"]
    assert not current["has_more"]
    with path.open("ab") as handle:
        handle.write(b" completed\n")
    assert helper._read_fixed_log_history(path, current["file_position"])["lines"] == ["partial completed"]
    path.write_bytes(b"replacement entry\n")
    reset = helper._read_fixed_log_history(path, current["file_position"])
    assert reset["reset"]
    assert reset["lines"] == ["replacement entry"]


def test_audit_history_pages_and_observes_new_events(client):
    """Read beyond the former total cap, then observe appended audit events.

    Args:
        client: Authenticated appliance test transport.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent
    from tests.routers.ui.helpers import login

    login(client)
    with SessionLocal() as db:
        db.add_all([AuditEvent(actor="history-test", action="history", resource_type="test", success=True,
                               detail=f"entry {index}") for index in range(1100)])
        db.commit()
    cursor, rows = "", []
    while True:
        response = client.get("/ui/management/audit-log", params={"cursor": cursor},
                              headers={"X-Atlaso-Task-Log": "1"})
        assert response.status_code == 200
        page = response.json()
        assert len(page["rows"]) <= 500
        rows.extend(row for row in page["rows"] if row["actor"] == "history-test")
        cursor = page["next_cursor"]
        if not page["has_more"]:
            break
    assert [row["detail"] for row in rows] == [f"entry {index}" for index in range(1100)]
    with SessionLocal() as db:
        db.add(AuditEvent(actor="history-test", action="later", resource_type="test", success=True))
        db.commit()
    response = client.get("/ui/management/audit-log", params={"cursor": cursor}, headers={"X-Atlaso-Task-Log": "1"})
    assert [row["action"] for row in response.json()["rows"]] == ["later"]
    wrong_source = client.get("/ui/management/logs/data", params={"source": "app", "cursor": cursor})
    assert wrong_source.status_code == 400


def test_journal_history_is_bounded_and_uses_fixed_units(monkeypatch, capsys):
    """Keep opaque positions while preventing arbitrary journal selectors.

    Args:
        monkeypatch: Substitute only the journal subprocess transport.
        capsys: Capture the helper's structured response.
    """
    import io
    import json
    from unittest.mock import MagicMock

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    entries = [{"MESSAGE": f"event {index}", "__CURSOR": f"cursor-{index}", "__REALTIME_TIMESTAMP": "1000000"}
               for index in range(501)]
    process = MagicMock()
    process.__enter__.return_value = process
    process.stdout = io.BytesIO("\n".join(json.dumps(entry) for entry in entries).encode())
    process.wait.return_value = 0
    process.poll.return_value = 0
    launch = MagicMock(return_value=process)
    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    assert helper._read_log_history(["nginx", '{"journal_cursor":"prior"}']) == 0
    page = json.loads(capsys.readouterr().out)
    assert len(page["lines"]) == 500
    assert page["has_more"]
    assert page["journal_cursor"] == "cursor-499"
    command = launch.call_args.args[0]
    assert command[command.index("--unit") + 1] == "nginx.service"
    assert "--lines=+501" in command
    assert "--after-cursor=prior" in command
    assert helper._read_log_history(["../../secret", "{}"]) == 2
    assert launch.call_count == 1
