"""Independent regression coverage for producer capture and accepted page boundaries."""

import logging
import sqlite3

import pytest

from atlaso.app.services import producer_log_history as history


def test_first_accepted_page_reports_partial_retention_expiry(tmp_path, monkeypatch):
    """Refuse an accepted beginning page when retention removes only its first rows.

    Args:
        tmp_path: Owned private test directory.
        monkeypatch: Scoped retention configuration.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "app", ["one", "two", "three"])
    accepted = history.viewer_page(path, "app")
    monkeypatch.setattr(history, "RETAINED_BYTES", 11)
    history.append(path, "app", ["four"])
    assert history.read_page(path, "app").lines == ("three", "four")
    with pytest.raises(ValueError, match="expired"):
        history.viewer_page(path, "app", cursor=accepted["cursor"])


def test_accepted_empty_page_stays_empty_when_later_history_expires(tmp_path, monkeypatch):
    """Keep an empty accepted page stable because it never contained expired rows.

    Args:
        tmp_path: Owned private test directory.
        monkeypatch: Scoped retention configuration.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    accepted = history.viewer_page(path, "app")
    monkeypatch.setattr(history, "RETAINED_BYTES", 6)
    history.append(path, "app", ["one", "two", "three"])
    assert history.viewer_page(path, "app", cursor=accepted["cursor"])["text"] == ""
    assert history.viewer_page(path, "app")["text"] == "three"


@pytest.mark.parametrize("message", ["ordinary diagnostic\n" * 501, "x" * 65537], ids=["many-lines", "long-line"])
def test_large_app_record_does_not_permanently_poison_capture(tmp_path, message):
    """Accept valid logging output without making every later App event fail.

    Args:
        tmp_path: Owned private test directory.
        message: Valid Python log output beyond one transport batch.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    formatter = logging.Formatter("%(message)s")
    record = logging.LogRecord("atlaso", logging.INFO, __file__, 1, message, (), None)
    history.capture_record(path, "web", record, formatter)
    following = logging.LogRecord("atlaso", logging.INFO, __file__, 1, "later event", (), None)
    history.capture_record(path, "worker", following, formatter)
    assert history.read_tail(path, "app", limit=1).lines == ("later event",)


def test_prepared_publication_failure_is_atomic_and_recoverable(tmp_path):
    """Recover the first batch exactly once when the publication receipt fails last.

    Args:
        tmp_path: Owned private test directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    formatter = logging.Formatter("%(message)s")
    with sqlite3.connect(path) as db:
        db.execute("CREATE TRIGGER reject_publish BEFORE INSERT ON receipt "
                   "BEGIN SELECT RAISE(ABORT,'publication receipt'); END")
    first = logging.LogRecord("atlaso", logging.INFO, __file__, 1, "first\nsecond", (), None)
    with pytest.raises(sqlite3.IntegrityError, match="publication receipt"):
        history.capture_record(path, "web", first, formatter)
    assert history.read_page(path, "app").lines == ()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT prepared IS NOT NULL FROM capture_pending").fetchone() == (1,)
        db.execute("DROP TRIGGER reject_publish")
    later = logging.LogRecord("atlaso", logging.INFO, __file__, 1, "third", (), None)
    history.capture_record(path, "worker", later, formatter)
    assert history.read_page(path, "app").lines == ("first", "second", "third")
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM capture_pending").fetchone() == (0,)
        assert db.execute("SELECT writer,revision FROM receipt ORDER BY writer").fetchall() == [
            ("web", 1), ("worker", 1),
        ]


def test_oversized_markers_preserve_redaction_across_records(tmp_path):
    """Scan oversized opening and closing lines before replacing their display text.

    Args:
        tmp_path: Owned private test directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    formatter = logging.Formatter("%(message)s")
    for message in (
        "x" * 65537 + "-----BEGIN RSA PRIVATE KEY-----",
        "synthetic key body",
        "x" * 65537 + "-----END RSA PRIVATE KEY-----",
        "ordinary event after closing marker",
    ):
        record = logging.LogRecord("atlaso", logging.INFO, __file__, 1, message, (), None)
        history.capture_record(path, "web", record, formatter)
    lines = history.read_page(path, "app").lines
    assert len(lines) == 4
    assert lines[0].startswith("[Oversized log entry omitted:")
    assert lines[1] == "[redacted private key]"
    assert lines[2].startswith("[Oversized log entry omitted:")
    assert lines[3] == "ordinary event after closing marker"


def test_large_prepared_record_recovers_its_final_open_marker(tmp_path):
    """Recover a marker beyond one normal batch before accepting the next body.

    Args:
        tmp_path: Owned private test directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    formatter = logging.Formatter("%(message)s")
    message = "ordinary event\n" * 500 + "-----BEGIN RSA PRIVATE KEY-----"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TRIGGER reject_large_publish BEFORE INSERT ON receipt "
                   "BEGIN SELECT RAISE(ABORT,'large publication'); END")
    record = logging.LogRecord("atlaso", logging.INFO, __file__, 1, message, (), None)
    with pytest.raises(sqlite3.IntegrityError, match="large publication"):
        history.capture_record(path, "web", record, formatter)
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER reject_large_publish")
    later = logging.LogRecord("atlaso", logging.INFO, __file__, 1,
                              "synthetic key body\n-----END RSA PRIVATE KEY-----\nvisible again", (), None)
    history.capture_record(path, "web", later, formatter)
    assert history.read_tail(path, "app", limit=4).lines == (
        "[redacted private key]", "[redacted private key]", "[redacted private key]", "visible again",
    )
    assert history.read_page(path, "app").through == 504
