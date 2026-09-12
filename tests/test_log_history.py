"""Verify full retained history and source-bound redaction across pages."""

import gzip
import json
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


def test_journal_large_batch_advances_complete_entries(monkeypatch, capsys):
    """A batch exceeding the byte budget still returns a usable continuation.

    Args:
        monkeypatch: Replace the fixed journal transport with retained entries.
        capsys: Read the helper response.
    """
    import io
    import json
    from unittest.mock import MagicMock

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    entries = [{"MESSAGE": f"event {index} " + "x" * 10000, "__CURSOR": f"c-{index}",
                "__REALTIME_TIMESTAMP": "1000000"} for index in range(501)]
    process = MagicMock()
    process.__enter__.return_value = process
    process.wait.return_value = 0
    process.poll.return_value = 0
    monkeypatch.setattr(helper.subprocess, "Popen", lambda *args, **kwargs: process)
    offset, actual = 0, []
    while offset < len(entries):
        process.stdout = io.BytesIO("\n".join(json.dumps(entry) for entry in entries[offset:]).encode())
        assert helper._read_log_history(["nginx", json.dumps({"journal_cursor": f"c-{offset - 1}"})]) == 0
        page = json.loads(capsys.readouterr().out)
        assert page["lines"]
        actual.extend(page["lines"])
        offset = int(page["journal_cursor"].removeprefix("c-")) + 1
        assert page["has_more"] == (offset < len(entries))
    assert len(actual) == 501
    assert all(f"event {index} " in line for index, line in enumerate(actual))


def test_task_progress_does_not_reset_later_history(client, monkeypatch):
    """Mutable summary fields cannot invalidate an older output page.

    Args:
        client: Initialized application database.
        monkeypatch: Use small pages to exercise pagination boundaries.
    """
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.ui import _task_log_lines

    monkeypatch.setattr(log_viewer, "PAGE_BYTES", 100)
    with SessionLocal() as db:
        job = Job(id="progress-history", type="managed-script", status="running", created_by="admin",
                  result=json.dumps({"state": "starting", "log_lines": [f"entry {i}" for i in range(100)]}))
        db.add(job)
        db.commit()
        first = log_viewer.text_page("\n".join(_task_log_lines(job, db, include_metadata=False)), source="task:test")
        before = log_viewer.text_page("\n".join(_task_log_lines(job, db, include_metadata=False)), source="task:test", cursor=first["next_cursor"])
        job.progress_percent = 75
        job.status = "succeeded"
        job.result = json.dumps({"state": "completed", "log_lines": [f"entry {i}" for i in range(101)]})
        db.commit()
        after = log_viewer.text_page("\n".join(_task_log_lines(job, db, include_metadata=False)), source="task:test", cursor=first["next_cursor"])
        assert not after["reset"]
        assert after["text"] == before["text"]


@pytest.mark.parametrize("privileged", [False, True])
def test_oversized_file_entry_advances_without_exposing_fragments(tmp_path, privileged):
    """An oversized physical line cannot hide newer entries or leak discarded pieces.

    Args:
        tmp_path: Test-owned log source.
        privileged: Exercise the fixed privileged reader as well as the web reader.
    """
    from tests.test_appliance_helper import load_helper_module

    path = tmp_path / "oversized.log"
    path.write_bytes(b"first\n" + b"private-fragment" * 200000 + b"\nlast\n")
    cursor, actual, pages = ({} if privileged else ""), [], 0
    helper = load_helper_module() if privileged else None
    while True:
        if privileged:
            page = helper._read_fixed_log_history(path, cursor)
            actual.extend(page["lines"])
            cursor = page["file_position"]
        else:
            page = log_viewer.file_page(path, source="oversized", cursor=cursor)
            actual.extend(page["text"].splitlines())
            cursor = page["next_cursor"]
        pages += 1
        assert pages < 10
        if not page["has_more"]:
            break
    assert actual[0] == "first"
    assert actual[-1] == "last"
    assert sum("Oversized log entry omitted" in line for line in actual) == 1
    assert "private-fragment" not in "\n".join(actual)


def test_failed_task_error_survives_paginated_projection(client):
    """A terminal error remains readable even without result or audit output.

    Args:
        client: Initialized application database.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.ui import _task_log_lines

    with SessionLocal() as db:
        job = Job(id="error-history", type="managed-script", status="failed", created_by="admin",
                  error="Owned script exited with code 7.")
        db.add(job)
        db.commit()
        lines = _task_log_lines(job, db, include_metadata=False)
        assert lines == ["Error: Owned script exited with code 7."]


def test_audit_live_tail_avoids_replaying_old_groups(client):
    """The initial live request reads only the newest group; history remains explicit.

    Args:
        client: Authenticated application transport.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent
    from tests.routers.ui.helpers import login

    login(client)
    with SessionLocal() as db:
        entries = [AuditEvent(actor="tail-test", action=f"entry-{i}", resource_type="test", success=True) for i in range(1501)]
        db.add_all(entries)
        db.commit()
        first_id, last_id = entries[0].id, entries[-1].id
    headers = {"X-Atlaso-Task-Log": "1"}
    tail = client.get("/ui/management/audit-log", params={"tail": "1"}, headers=headers).json()
    assert len(tail["rows"]) == 500
    assert tail["rows"][0]["id"] == last_id - 499
    assert tail["rows"][-1]["id"] == last_id
    assert not tail["has_more"]
    previous = client.get("/ui/management/audit-log", params={"cursor": tail["previous_cursor"]}, headers=headers).json()
    assert len(previous["rows"]) == 500
    assert previous["rows"][-1]["id"] == tail["rows"][0]["id"] - 1
    beginning = client.get("/ui/management/audit-log", headers=headers).json()
    assert beginning["rows"][0]["id"] <= first_id
    assert beginning["has_more"]


def test_task_pages_bound_utf8_bytes_and_tail(monkeypatch):
    """Multilingual output remains character-safe within the transport byte budget.

    Args:
        monkeypatch: Reduce the budget to exercise multiple pages cheaply.
    """
    monkeypatch.setattr(log_viewer, "PAGE_BYTES", 100)
    text = ("漢字🙂\n" * 100)
    cursor, actual = "", ""
    while True:
        page = log_viewer.text_page(text, source="utf8", cursor=cursor)
        assert len(page["text"].encode("utf-8")) <= 100
        actual += page["text"]
        cursor = page["next_cursor"]
        if not page["has_more"]:
            break
    assert actual == text
    tail = log_viewer.text_page(text, source="utf8", tail=True)
    assert len(tail["text"].encode("utf-8")) <= 100
    assert text.endswith(tail["text"])
    assert not tail["has_more"]


@pytest.mark.parametrize("privileged", [False, True])
def test_file_tail_is_bounded_and_preserves_rotated_key_state(tmp_path, privileged):
    """Jumping to the newest group preserves redaction state from earlier rotations.

    Args:
        tmp_path: Fixed retained source directory.
        privileged: Exercise the standalone helper contract too.
    """
    from tests.test_appliance_helper import load_helper_module

    path = tmp_path / "history.log"
    (tmp_path / "history.log.1").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
    path.write_text("".join(f"hidden-fragment-{i}\n" for i in range(1500)) + "-----END PRIVATE KEY-----\nvisible\n", encoding="utf-8")
    if privileged:
        helper = load_helper_module()
        page = helper._read_fixed_log_history(path, {"tail": True})
        assert page["initial_private_key"]
        lines, _ = log_viewer.redact_lines(page["lines"], private_key=page["initial_private_key"])
    else:
        page = log_viewer.file_page(path, source="tail", tail=True)
        assert log_viewer.decode_cursor(page["cursor"], "tail")["private_key"]
        lines = page["text"].splitlines()
    assert len(lines) == 500
    assert lines[-1] == "visible"
    assert "hidden-fragment" not in "\n".join(lines)
    assert not page["has_more"]


def test_journal_oversized_record_advances_metadata_after_message(monkeypatch, capsys):
    """A large journal message cannot hide its cursor or any following entries.

    Args:
        monkeypatch: Replace the owned subprocess transport.
        capsys: Read the helper's structured response.
    """
    import io
    import json
    from unittest.mock import MagicMock

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    entry = {"MESSAGE": "private-fragment" * 200000, "__CURSOR": "large-cursor", "__REALTIME_TIMESTAMP": "1000000"}
    later = {"MESSAGE": "later", "__CURSOR": "later-cursor", "__REALTIME_TIMESTAMP": "1000001"}
    process = MagicMock()
    process.__enter__.return_value = process
    process.wait.return_value = process.poll.return_value = 0
    process.stdout = io.BytesIO((json.dumps(entry) + "\n" + json.dumps(later) + "\n").encode())
    monkeypatch.setattr(helper.subprocess, "Popen", lambda *args, **kwargs: process)
    assert helper._read_log_history(["nginx", "{}"]) == 0
    page = json.loads(capsys.readouterr().out)
    assert page["journal_cursor"] == "large-cursor"
    assert page["has_more"]
    assert "Oversized journal entry omitted" in page["lines"][0]
    assert "private-fragment" not in str(page)
    process.stdout = io.BytesIO((json.dumps(later) + "\n").encode())
    assert helper._read_log_history(["nginx", json.dumps({"journal_cursor": page["journal_cursor"]})]) == 0
    assert json.loads(capsys.readouterr().out)["lines"][0].endswith(" later")


def test_journal_tail_recovers_prior_key_state(monkeypatch, capsys):
    """The latest journal group has a stable start and redaction predecessor.

    Args:
        monkeypatch: Substitute the owned journal transport.
        capsys: Read the helper page.
    """
    import io
    import json
    from unittest.mock import MagicMock

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    commands = []
    def launch(command, **_kwargs):
        commands.append(command)
        message, cursor = ("-----BEGIN PRIVATE KEY-----", "prior") if any(arg.startswith("--grep=") for arg in command) else ("hidden", "latest")
        process = MagicMock()
        process.__enter__.return_value = process
        process.wait.return_value = process.poll.return_value = 0
        process.stdout = io.BytesIO((json.dumps({"MESSAGE": message, "__CURSOR": cursor,
                                               "__REALTIME_TIMESTAMP": "1000000"}) + "\n").encode())
        return process
    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    assert helper._read_log_history(["nginx", '{"tail":true}']) == 0
    page = json.loads(capsys.readouterr().out)
    assert page["initial_private_key"]
    assert page["current_position"] == {"journal_start_cursor": "latest"}
    assert "--lines=500" in commands[0]
    assert "--cursor=latest" in commands[1]


def test_tail_of_unfinished_oversized_key_keeps_future_fragments_redacted(tmp_path):
    """A tail positioned inside a huge unfinished line retains its complete key state.

    Args:
        tmp_path: Fixed log source owned by the test.
    """
    path = tmp_path / "unfinished.log"
    path.write_bytes(b"prefix" * 200000 + b"-----BEGIN PRIVATE KEY-----" + b"hidden" * 200000)
    first = log_viewer.file_page(path, source="unfinished", tail=True)
    assert log_viewer.decode_cursor(first["next_cursor"], "unfinished")["private_key"]
    with path.open("ab") as handle:
        handle.write(b"\nprivate-fragment\n-----END PRIVATE KEY-----\nvisible\n")
    later = log_viewer.file_page(path, source="unfinished", cursor=first["next_cursor"])
    assert "private-fragment" not in later["text"]
    assert later["text"].endswith("visible")


@pytest.mark.parametrize("privileged", [False, True])
def test_copytruncate_same_banner_resets_cursor(tmp_path, privileged):
    """A regrown file with an unchanged banner must not conceal replacement history.

    Args:
        tmp_path: Owned retained log directory.
        privileged: Exercise both independent file readers.
    """
    from tests.test_appliance_helper import load_helper_module

    path = tmp_path / "replacement.log"
    banner = b"banner" * 900 + b"\n"
    path.write_bytes(banner + b"old entry\n" * 600)
    helper = load_helper_module() if privileged else None
    first = helper._read_fixed_log_history(path, {}) if privileged else log_viewer.file_page(path, source="replacement")
    position = first["file_position"] if privileged else first["next_cursor"]
    path.write_bytes(banner + b"replacement entry\n" * 900)
    page = helper._read_fixed_log_history(path, position) if privileged else log_viewer.file_page(path, source="replacement", cursor=position)
    assert page["reset"]
    text = "\n".join(page["lines"]) if privileged else page["text"]
    assert text.startswith(banner.decode().rstrip())
    assert "replacement entry" in text


def test_expanded_journal_message_pages_without_loss_and_tail_skips_history(monkeypatch, capsys):
    """One multiline record stays bounded, resumes exactly, and opens at its latest rows.

    Args:
        monkeypatch: Substitute only the journal process reader.
        capsys: Capture structured helper pages.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    messages = [f"row-{index}" for index in range(1501)]
    entry = {"MESSAGE": "\n".join(messages), "__CURSOR": "multiline", "__REALTIME_TIMESTAMP": "1000000"}
    def entries(command, **_kwargs):
        return ([], False) if any(arg.startswith("--grep=") for arg in command) else ([entry], False)
    monkeypatch.setattr(helper, "_journal_history_entries", entries)
    position, actual = {}, []
    for _ in range(5):
        assert helper._read_log_history(["nginx", json.dumps(position)]) == 0
        page = json.loads(capsys.readouterr().out)
        assert len(page["lines"]) <= 500
        assert len("\n".join(page["lines"]).encode("utf-8")) <= 1024 * 1024
        actual.extend(line.split(" ", 1)[1] for line in page["lines"])
        position = page["journal_position"]
        if not page["has_more"]:
            break
    assert actual == messages
    assert helper._read_log_history(["nginx", '{"tail":true}']) == 0
    tail = json.loads(capsys.readouterr().out)
    assert [line.split(" ", 1)[1] for line in tail["lines"]] == messages[-500:]
    assert not tail["has_more"]
    assert tail["current_position"]["journal_text_offset"] > 0
    assert helper._read_log_history(["nginx", json.dumps(tail["previous_position"])]) == 0
    previous = json.loads(capsys.readouterr().out)
    assert [line.split(" ", 1)[1] for line in previous["lines"]] == messages[-1000:-500]
    assert previous["journal_position"]["journal_text_offset"] == tail["current_position"]["journal_text_offset"]
    # The final short predecessor must remain bounded on refresh too.
    for _ in range(2):
        assert helper._read_log_history(["nginx", json.dumps(previous["previous_position"])]) == 0
        previous = json.loads(capsys.readouterr().out)
    assert len(previous["lines"]) == 1
    assert helper._read_log_history(["nginx", json.dumps(previous["current_position"])]) == 0
    assert json.loads(capsys.readouterr().out)["lines"] == previous["lines"]
    assert helper._read_log_history(["nginx", json.dumps(tail["current_position"])]) == 0
    assert json.loads(capsys.readouterr().out)["lines"] == tail["lines"]


def test_expanded_journal_page_includes_timestamp_byte_budget(monkeypatch, capsys):
    """Timestamp expansion is included in the byte budget and preserves continuation.

    Args:
        monkeypatch: Substitute immutable journal entries.
        capsys: Capture helper output.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    message = ("x" * 2074 + "\n") * 500
    entry = {"MESSAGE": message, "__CURSOR": "byte-bound", "__REALTIME_TIMESTAMP": "1000000"}
    monkeypatch.setattr(helper, "_journal_history_entries", lambda *args, **kwargs: ([entry], False))
    assert helper._read_log_history(["nginx", "{}"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["has_more"]
    assert len("\n".join(first["lines"]).encode()) <= 1024 * 1024
    assert helper._read_log_history(["nginx", json.dumps(first["journal_position"])]) == 0
    second = json.loads(capsys.readouterr().out)
    assert len(first["lines"]) + len(second["lines"]) == 500
    assert not second["has_more"]


@pytest.mark.parametrize("privileged", [False, True])
@pytest.mark.parametrize("padding", [65530, 1048580])
def test_discarded_file_fragments_preserve_key_state(tmp_path, privileged, padding):
    """Markers crossing discarded chunk and page boundaries still protect later lines.

    Args:
        tmp_path: Owned fixed log path.
        privileged: Exercise the privileged reader and its redaction handoff.
        padding: Locate a split marker at a chunk or page boundary.
    """
    from tests.test_appliance_helper import load_helper_module

    path = tmp_path / "discarded-key.log"
    path.write_bytes(b"x" * padding + b"-----BEGIN PRIVATE KEY-----" + b"y" * 70000 +
                     b"\nprivate-fragment\n-----END PRIVATE KEY-----\nvisible\n")
    helper = load_helper_module() if privileged else None
    cursor, actual, private_key = ({} if privileged else ""), [], False
    for _ in range(8):
        if privileged:
            page = helper._read_fixed_log_history(path, cursor)
            lines, private_key = log_viewer.redact_lines(page["lines"], private_key=private_key)
            cursor = page["file_position"]
        else:
            page = log_viewer.file_page(path, source="discarded-key", cursor=cursor)
            lines = page["text"].splitlines()
            cursor = page["next_cursor"]
        actual.extend(lines)
        if not page["has_more"]:
            break
    assert actual[-1] == "visible"
    assert "private-fragment" not in "\n".join(actual)
    assert "[redacted private key]" in actual


@pytest.mark.parametrize("privileged", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
def test_previous_file_page_opens_group_before_tail(tmp_path, privileged, compressed):
    """Backward paging starts beside the live tail, including compressed rotations.

    Args:
        tmp_path: Owned retained log directory.
        privileged: Exercise both independent file readers.
        compressed: Store the history in an archived gzip file.
    """
    from tests.test_appliance_helper import load_helper_module

    path = tmp_path / "backward.log"
    text = "".join(f"line-{index}\n" for index in range(1501))
    if compressed:
        with gzip.open(tmp_path / "backward.log.1.gz", "wb") as handle:
            handle.write(text.encode())
    else:
        path.write_text(text, encoding="utf-8")
    helper = load_helper_module() if privileged else None
    page = helper._read_fixed_log_history(path, {"tail": True}) if privileged else log_viewer.file_page(path, source="backward", tail=True)
    for expected_start, expected_end in [(501, 1000), (1, 500), (0, 0)]:
        if privileged:
            page = helper._read_fixed_log_history(path, page["previous_position"])
            lines = page["lines"]
        else:
            page = log_viewer.file_page(path, source="backward", cursor=page["previous_cursor"])
            lines = page["text"].splitlines()
        assert lines == [f"line-{index}" for index in range(expected_start, expected_end + 1)]
    assert not page.get("previous_position" if privileged else "previous_cursor")


def test_previous_text_page_is_adjacent_and_refresh_stable(monkeypatch):
    """A task can inspect the group before its tail without replaying older output.

    Args:
        monkeypatch: Use a small byte budget for multiple pages.
    """
    monkeypatch.setattr(log_viewer, "PAGE_BYTES", 100)
    text = "".join(f"row-{index}\n" for index in range(100))
    tail = log_viewer.text_page(text, source="back-text", tail=True)
    older = log_viewer.text_page(text, source="back-text", cursor=tail["previous_cursor"])
    assert log_viewer.decode_cursor(older["next_cursor"], "back-text")["offset"] == log_viewer.decode_cursor(tail["cursor"], "back-text")["offset"]
    assert older["text"] not in tail["text"]
    assert log_viewer.text_page(text, source="back-text", cursor=older["cursor"])["text"] == older["text"]


@pytest.mark.parametrize("limit", [100, 200, 500])
def test_selected_page_size_preserves_complete_file_history(tmp_path, limit):
    """Choosing a smaller live tail changes page size without discarding history.

    Args:
        tmp_path: Owned file source.
        limit: Established operator page-size choice.
    """
    from tests.test_appliance_helper import load_helper_module

    path = tmp_path / "selected-size.log"
    path.write_text("".join(f"row-{i}\n" for i in range(1501)), encoding="utf-8")
    tail = log_viewer.file_page(path, source="size", tail=True, limit=limit)
    assert len(tail["text"].splitlines()) == limit
    assert tail["text"].splitlines()[0] == f"row-{1501-limit}"
    helper = load_helper_module()
    raw = helper._read_fixed_log_history(path, {"tail": True, "limit": limit})
    assert raw["lines"] == tail["text"].splitlines()
    cursor, lines = "", []
    while True:
        page = log_viewer.file_page(path, source="size", cursor=cursor, limit=limit)
        lines.extend(page["text"].splitlines())
        assert len(page["text"].splitlines()) <= limit
        if not page["has_more"]:
            break
        cursor = page["next_cursor"]
    assert lines == [f"row-{i}" for i in range(1501)]


def test_logs_controls_preserve_availability_and_selected_page_limit(client, monkeypatch):
    """The rendered controls distinguish unavailable sources and pass page-size choices.

    Args:
        client: Initialized application transport.
        monkeypatch: Supply fixed availability and capture the reader contract.
    """
    import re

    from atlaso.app import ui
    from tests.routers.ui.helpers import login

    login(client)
    monkeypatch.setattr(ui, "log_sources_context", lambda **_kwargs: [
        {"id": "app", "label": "Atlaso App", "available": False, "path": "/missing", "size_bytes": 0, "lines": []},
        {"id": "nginx", "label": "Nginx", "available": True, "path": "journal", "size_bytes": 0, "lines": []},
    ])
    response = client.get("/ui/management/logs")
    assert response.status_code == 200
    missing = re.search(r'<button[^>]*data-log-source-tab="app"[^>]*>', response.text).group()
    available = re.search(r'<button[^>]*data-log-source-tab="nginx"[^>]*>', response.text).group()
    assert 'disabled aria-disabled="true"' in missing
    assert 'aria-disabled="false"' in available
    assert 'data-log-lines aria-label="Log lines per page"' in response.text
    selected = []
    def page(source, **kwargs):
        selected.append((source, kwargs["limit"]))
        return {"text": "", "available": True, "has_more": False}
    monkeypatch.setattr(log_viewer, "source_page", page)
    response = client.get("/ui/management/logs/data", params={"source": "nginx", "lines": 200, "tail": "true"})
    assert response.status_code == 200
    assert selected == [("nginx", 200)]


@pytest.mark.parametrize("limit", [100, 200, 500])
def test_journal_selected_tail_size(monkeypatch, capsys, limit):
    """Journal expansion respects the selected line count as well as its byte budget.

    Args:
        monkeypatch: Provide a bounded immutable journal message.
        capsys: Capture the helper response.
        limit: Operator-selected page size.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    entry = {"MESSAGE": "\n".join(f"row-{i}" for i in range(1501)), "__CURSOR": "selected", "__REALTIME_TIMESTAMP": "1000000"}
    def entries(command, **_kwargs):
        return ([], False) if any(arg.startswith("--grep=") for arg in command) else ([entry], False)
    monkeypatch.setattr(helper, "_journal_history_entries", entries)
    assert helper._read_log_history(["nginx", json.dumps({"tail": True, "limit": limit})]) == 0
    page = json.loads(capsys.readouterr().out)
    assert len(page["lines"]) == limit
    assert page["lines"][0].endswith(f" row-{1501-limit}")
    assert not page["has_more"]


@pytest.mark.parametrize("privileged", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("complete", [False, True])
def test_previous_page_advances_across_oversized_tail(tmp_path, privileged, compressed, complete):
    """Every bounded predecessor advances until entries before an oversized tail appear.

    Args:
        tmp_path: Owned retained source directory.
        privileged: Exercise both independent file readers.
        compressed: Exercise bounded gzip seeking too.
        complete: Whether the oversized physical entry has its final newline.
    """
    from tests.test_appliance_helper import load_helper_module

    path = tmp_path / "large-tail.log"
    contents = b"older retained entry\n" + b"x" * (3 * 1024 * 1024) + (b"\n" if complete else b"")
    if compressed:
        with gzip.open(tmp_path / "large-tail.log.1.gz", "wb") as handle:
            handle.write(contents)
    else:
        path.write_bytes(contents)
    helper = load_helper_module() if privileged else None
    page = helper._read_fixed_log_history(path, {"tail": True}) if privileged else log_viewer.file_page(path, source="large-tail", tail=True)
    seen = set()
    for _ in range(6):
        text = "\n".join(page["lines"]) if privileged else page["text"]
        if "older retained entry" in text:
            break
        assert "Oversized log entry omitted" in text
        position = page["previous_position"] if privileged else log_viewer.decode_cursor(page["previous_cursor"], "large-tail")
        assert position["offset"] not in seen
        seen.add(position["offset"])
        page = helper._read_fixed_log_history(path, position) if privileged else log_viewer.file_page(path, source="large-tail", cursor=page["previous_cursor"])
    else:
        pytest.fail("Backward paging did not reach the earlier retained entry")


@pytest.mark.parametrize("category", ["dhcp", "tftp"])
def test_sparse_dnsmasq_tail_classifies_before_limit_and_preserves_redaction(monkeypatch, capsys, category):
    """Other protocols cannot hide retained entries or reset their private-key state.

    Args:
        monkeypatch: Supply one fixed journal stream and the privileged adapter response.
        capsys: Capture bounded helper pages.
        category: Sparse protocol whose newest entries precede many DNS records.
    """
    import io
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    pairs = [("dnsmasq", "-----BEGIN PRIVATE KEY-----"),
             (f"dnsmasq-{category}", "private-fragment"),
             ("dnsmasq", "-----END PRIVATE KEY-----"),
             (f"dnsmasq-{category}", "retained protocol entry")]
    pairs.extend(("dnsmasq", f"newer DNS entry {index}") for index in range(700))
    records = [{"__CURSOR": str(index), "__REALTIME_TIMESTAMP": str(1000000 + index),
                "SYSLOG_IDENTIFIER": identifier, "MESSAGE": message} for index, (identifier, message) in enumerate(pairs)]
    commands = []
    def launch(command, **_kwargs):
        commands.append(command)
        rows = list(records)
        reverse = "--reverse" in command
        for argument in command:
            if argument.startswith("--cursor="):
                index = int(argument.split("=", 1)[1])
                rows = rows[:index + 1] if reverse else rows[index:]
        if any(argument.startswith("--grep=") for argument in command):
            rows = [entry for entry in rows if "PRIVATE KEY-----" in entry["MESSAGE"]]
        if reverse:
            rows.reverse()
        process = MagicMock()
        process.__enter__.return_value = process
        process.wait.return_value = process.poll.return_value = 0
        process.stdout = io.BytesIO("".join(json.dumps(entry) + "\n" for entry in rows).encode())
        process.stderr = io.BytesIO()
        return process
    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    for position in ({"tail": True, "limit": 100}, {"limit": 100}):
        assert helper._read_log_history([f"dnsmasq-{category}", json.dumps(position)]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert len(payload["lines"]) == 2
        assert payload["line_private_keys"] == [True, False]
        assert not payload["has_more"]
        monkeypatch.setattr(log_viewer.SystemAdapter, "read_log_history", lambda *_args, payload=payload: SimpleNamespace(returncode=0, stdout=json.dumps(payload)))
        page = log_viewer.source_page(f"dnsmasq-{category}", tail=True, limit=100)
        assert "private-fragment" not in page["text"]
        assert "retained protocol entry" in page["text"]
        assert "newer DNS" not in page["text"]
    assert "--lines=all" in commands[0]
    assert commands[0][commands[0].index("--unit") + 1] == "dnsmasq.service"
