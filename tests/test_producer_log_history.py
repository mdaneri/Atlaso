"""Exercise the producer-owned operational history transaction contract."""

import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from atlaso.app.services import producer_log_history as history


def test_pages_stay_fixed_during_concurrent_appends(tmp_path):
    """Keep accepted history boundaries stable while producers commit new lines.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "app", [f"event {index}" for index in range(30)])
    first = history.read_page(path, "app", limit=7)

    def produce():
        """Commit independent records through the actual store writer."""
        for index in range(200):
            history.append(path, "app", [f"new event {index}"])

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(produce)
        rows, position = [], 0
        while True:
            page = history.read_page(path, "app", after=position, through=first.through,
                                     generation=first.generation, limit=7)
            rows.extend(page.lines)
            position = page.after
            assert history.read_page(path, "app", through=first.through, limit=7) == first
            if not page.more:
                break
        future.result()
    assert rows == [f"event {index}" for index in range(30)]
    assert len(history.read_page(path, "app", after=first.through).lines) == 200


def test_failed_redaction_commit_rolls_back_rows_and_context(tmp_path):
    """Retain an open key when a footer transaction fails before commit.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "kms", ["-----BEGIN RSA PRIVATE KEY-----"])
    with sqlite3.connect(path) as db:
        db.execute("CREATE TRIGGER reject_update BEFORE UPDATE ON producer BEGIN SELECT RAISE(ABORT,'injected'); END")
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        history.append(path, "kms", ["-----END RSA PRIVATE KEY-----"])
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER reject_update")
    history.append(path, "kms", ["synthetic private body"])
    history.append(path, "app", ["ordinary app record", "activation.code=synthetic-secret"])
    assert history.read_page(path, "kms").lines == ("[redacted private key]",) * 2
    assert history.read_page(path, "app").lines[0] == "ordinary app record"
    assert "synthetic-secret" not in history.read_page(path, "app").lines[-1]


def test_retention_and_replacement_expire_positions(tmp_path, monkeypatch):
    """Reject stale positions instead of spinning on deleted history.

    Args:
        tmp_path: Private test-owned storage directory.
        monkeypatch: Scoped retained-byte budget override.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "app", ["old1", "old2", "old3"])
    before = history.read_page(path, "app", limit=1)
    monkeypatch.setattr(history, "RETAINED_BYTES", 10)
    history.append(path, "app", ["new1", "new2", "new3"])
    assert history.read_page(path, "app").lines == ("new2", "new3")
    with pytest.raises(ValueError, match="expired"):
        history.read_page(path, "app", after=before.after)
    with pytest.raises(ValueError, match="expired"):
        history.read_page(path, "app", through=before.through)
    with pytest.raises(ValueError, match="replaced"):
        history.read_page(path, "app", generation="different-store")


@pytest.mark.parametrize("line", ["first\nsecond", "first\rsecond", "first\u2028second", "first\x85second"])
def test_invalid_batch_never_creates_store(tmp_path, line):
    """Validate producer framing before any storage mutation.

    Args:
        tmp_path: Private test-owned storage directory.
        line: A value containing a physical line separator requiring producer framing.
    """
    path = tmp_path / "missing.sqlite"
    with pytest.raises(ValueError, match="physical lines"):
        history.append(path, "app", [line])
    assert not path.exists()


def test_pages_bound_encoded_bytes_and_reject_future_positions(tmp_path):
    """Preserve complete Unicode records within the response budget.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    value = "\u03bb" * 16000
    for _ in range(4):
        history.append(path, "nginx-access", [value] * 20)
    position, found = 0, []
    while True:
        page = history.read_page(path, "nginx-access", after=position)
        assert sum(len(line.encode("utf-8")) + 1 for line in page.lines) <= history.BATCH_BYTES
        found.extend(page.lines)
        position = page.after
        if not page.more:
            break
    assert found == [value] * 80
    with pytest.raises(ValueError, match="unavailable"):
        history.read_page(path, "nginx-access", after=81)


def test_signed_viewer_tail_previous_and_live_positions(tmp_path):
    """Traverse backward and forward while retaining accepted display boundaries.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "app", [f"event {index}" for index in range(23)])
    tail = history.viewer_page(path, "app", tail=True, limit=7)
    assert tail["text"].splitlines() == [f"event {index}" for index in range(16, 23)]
    previous = history.viewer_page(path, "app", cursor=tail["previous_cursor"], limit=7)
    assert previous["text"].splitlines() == [f"event {index}" for index in range(9, 16)]
    history.append(path, "app", ["new live entry"])
    assert history.viewer_page(path, "app", cursor=tail["cursor"], limit=7)["text"] == tail["text"]
    assert history.viewer_page(path, "app", cursor=previous["cursor"], limit=7)["text"] == previous["text"]
    assert history.viewer_page(path, "app", cursor=tail["next_cursor"], limit=7)["text"] == "new live entry"
    beginning = history.viewer_page(path, "app", limit=7)
    assert not beginning["previous_cursor"]
    assert beginning["text"].splitlines()[0] == "event 0"
    with pytest.raises(ValueError, match="another source"):
        history.viewer_page(path, "kms", cursor=tail["cursor"])
    with pytest.raises(ValueError, match="Invalid log history"):
        history.viewer_page(path, "app", cursor=tail["cursor"] + "tampered")


def test_signed_viewer_rejects_replaced_store_and_legacy_positions(tmp_path):
    """Keep source and storage-generation binding separate from row positions.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    from atlaso.app.services.log_viewer import encode_cursor

    first, replacement = tmp_path / "first.sqlite", tmp_path / "replacement.sqlite"
    history.initialize(first)
    history.initialize(replacement)
    cursor = history.viewer_page(first, "app")["cursor"]
    with pytest.raises(ValueError, match="replaced"):
        history.viewer_page(replacement, "app", cursor=cursor)
    with pytest.raises(ValueError, match="another storage generation"):
        history.viewer_page(first, "app", cursor=encode_cursor("app", offset=0))


def test_retry_after_lost_acknowledgment_does_not_replay_redaction(tmp_path):
    """Recognize the same committed batch without publishing or parsing it again.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "app", ["-----BEGIN RSA PRIVATE KEY-----"], writer="web", revision=1)
    assert history.append(path, "app", ["-----END RSA PRIVATE KEY-----"], writer="web", revision=2) == 2
    history.append(path, "app", ["-----BEGIN RSA PRIVATE KEY-----"], writer="worker", revision=1)
    # Web's successful acknowledgment was lost; its old footer must not close worker's key.
    assert history.append(path, "app", ["-----END RSA PRIVATE KEY-----"], writer="web", revision=2) == 2
    history.append(path, "app", ["synthetic body"], writer="worker", revision=2)
    assert history.read_page(path, "app").lines == ("[redacted private key]",) * 4
    with pytest.raises(ValueError, match="conflicts"):
        history.append(path, "app", ["changed retry"], writer="web", revision=2)
    with pytest.raises(ValueError, match="conflicts"):
        history.append(path, "app", ["stale retry"], writer="web", revision=1)


def test_receipt_failure_rolls_back_event_and_parser(tmp_path):
    """Keep a failed batch retryable even if receipt persistence fails last.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TRIGGER reject_receipt BEFORE INSERT ON receipt BEGIN SELECT RAISE(ABORT,'receipt'); END")
    with pytest.raises(sqlite3.IntegrityError, match="receipt"):
        history.append(path, "kms", ["-----BEGIN RSA PRIVATE KEY-----"], writer="service", revision=1)
    assert not history.read_page(path, "kms").lines
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER reject_receipt")
    assert history.append(path, "kms", ["-----BEGIN RSA PRIVATE KEY-----"], writer="service", revision=1) == 1
    history.append(path, "kms", ["synthetic body"], writer="service", revision=2)
    assert history.read_page(path, "kms").lines == ("[redacted private key]",) * 2


def test_interleaved_producer_footer_cannot_release_another_key(tmp_path):
    """Keep independent process checkpoints while conservatively masking the source.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "app", ["-----BEGIN RSA PRIVATE KEY-----"], writer="web", revision=1)
    history.append(path, "app", ["-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"],
                   writer="worker", revision=1)
    history.append(path, "app", ["synthetic web key body"], writer="web", revision=2)
    history.append(path, "app", ["worker ordinary record"], writer="worker", revision=2)
    history.append(path, "app", ["-----END RSA PRIVATE KEY-----"], writer="web", revision=3)
    history.append(path, "app", ["visible again"], writer="worker", revision=3)
    assert history.read_page(path, "app").lines == ("[redacted private key]",) * 6 + ("visible again",)


def test_producer_checkpoint_failure_preserves_open_key_and_receipt(tmp_path):
    """Roll back source ordering and acknowledgment if the writer checkpoint fails.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "app", ["-----BEGIN RSA PRIVATE KEY-----"], writer="web", revision=1)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON checkpoint "
                   "BEGIN SELECT RAISE(ABORT,'checkpoint'); END")
    with pytest.raises(sqlite3.IntegrityError, match="checkpoint"):
        history.append(path, "app", ["-----END RSA PRIVATE KEY-----"], writer="web", revision=2)
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER reject_checkpoint")
    history.append(path, "app", ["synthetic body after rollback"], writer="web", revision=2)
    assert history.read_page(path, "app").lines == ("[redacted private key]",) * 2


def test_append_and_small_pages_do_not_scan_retained_rows(tmp_path, monkeypatch):
    """Bound SQLite work for one new event independently of retained history.

    Args:
        tmp_path: Private test-owned storage directory.
        monkeypatch: Scoped connection instrumentation for SQLite VM instructions.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    for _ in range(16):
        history.append(path, "app", ["retained event"] * 500)
    connect = history._connect
    steps = []

    def count_work():
        """Count each group of one hundred virtual machine instructions."""
        steps.append(1)
        return 0

    def instrumented_connect(database, source):
        """Instrument real database operations without changing their query plans.

        Args:
            database: Trusted test-owned store path.
            source: Fixed operational source identifier.
        """
        connection = connect(database, source)
        connection.set_progress_handler(count_work, 100)
        return connection

    monkeypatch.setattr(history, "_connect", instrumented_connect)
    history.append(path, "app", ["new event"])
    assert history.read_tail(path, "app", limit=3).lines[-1] == "new event"
    assert len(history.read_page(path, "app", limit=3).lines) == 3
    # A retained-row scan uses tens of thousands of instructions at this size.
    # Leave headroom for SQLite-version differences in bounded index operations.
    assert len(steps) < 100


def test_app_handler_captures_before_file_and_keeps_process_identity(tmp_path):
    """Exercise the real App handler with concurrent fixed process writer slots.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    import os

    from atlaso.app.operational_logging import _HistoryFileHandler

    path = tmp_path / "history.sqlite"
    history.initialize(path)
    pid = os.getpid()
    handlers = [_HistoryFileHandler(tmp_path / f"{writer}.log", path, writer) for writer in ("web", "worker")]
    for handler in handlers:
        handler.setFormatter(logging.Formatter("%(message)s"))

    def produce(handler):
        """Emit records through the normal logging Handler entry point.

        Args:
            handler: Test-owned real rotating producer handler.
        """
        for index in range(20):
            handler.handle(logging.LogRecord("atlaso", logging.INFO, __file__, 1, f"event {index}", (), None))

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(produce, handlers))
        assert os.getpid() == pid
        assert len(history.read_page(path, "app").lines) == 40
        assert all(len((tmp_path / f"{writer}.log").read_text().splitlines()) == 20 for writer in ("web", "worker"))
    finally:
        for handler in handlers:
            handler.close()


def test_app_capture_failure_recovers_sanitized_input_across_restart(tmp_path):
    """Recover an interrupted sanitized batch before accepting a later key body.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    from atlaso.app.operational_logging import _HistoryFileHandler

    path = tmp_path / "history.sqlite"
    log = tmp_path / "app.log"
    history.initialize(path)
    handler = _HistoryFileHandler(log, path, "web")
    handler.setFormatter(logging.Formatter("%(message)s"))
    with sqlite3.connect(path) as db:
        db.execute("CREATE TRIGGER reject_capture BEFORE INSERT ON record BEGIN SELECT RAISE(ABORT,'capture'); END")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="capture"):
            handler.handle(logging.LogRecord("atlaso", logging.INFO, __file__, 1, "-----BEGIN RSA PRIVATE KEY-----", (), None))
    finally:
        handler.close()
    with sqlite3.connect(path) as db:
        staged = db.execute("SELECT prepared FROM capture_pending").fetchone()[0]
        assert "-----BEGIN RSA PRIVATE KEY-----" not in staged
        assert "[redacted private key]" in staged
        db.execute("DROP TRIGGER reject_capture")
    with pytest.raises(ValueError, match="conflicts with its prepared capture"):
        history.append(path, "app", ["changed interrupted input"], writer="web", revision=1)
    restarted = _HistoryFileHandler(log, path, "web")
    try:
        restarted.handle(logging.LogRecord("atlaso", logging.INFO, __file__, 1, "synthetic secret body", (), None))
        assert history.read_page(path, "app").lines == ("[redacted private key]",) * 2
        with sqlite3.connect(path) as db:
            assert db.execute("SELECT COUNT(*) FROM capture_pending").fetchone()[0] == 0
    finally:
        restarted.close()


def test_unprepared_capture_cannot_be_skipped_after_restart(tmp_path):
    """Reject later input when a formatter failed before producing recoverable rows.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    record = logging.LogRecord("atlaso", logging.INFO, __file__, 1, "synthetic body", (), None)
    with pytest.raises(ValueError):
        history.capture_record(path, "web", record, logging.Formatter("%(missing_field)s"))
    with pytest.raises(ValueError, match="interrupted-record recovery"):
        history.capture_record(path, "worker", record, logging.Formatter("%(message)s"))
    assert not history.read_page(path, "app").lines


def test_app_viewer_switches_only_after_verified_cutover(tmp_path, monkeypatch):
    """Keep legacy output until activation, then page stable producer boundaries.

    Args:
        tmp_path: Private test-owned storage directory.
        monkeypatch: Scoped settings selecting test-owned log and producer paths.
    """
    from atlaso.app.config import get_settings
    from atlaso.app.services import log_viewer

    path = tmp_path / "history.sqlite"
    legacy = tmp_path / "app.log"
    legacy.write_text("legacy retained entry\n", encoding="utf-8")
    history.initialize(path)
    settings = get_settings().model_copy(update={"app_log_path": legacy, "app_log_history_path": path})
    monkeypatch.setattr(log_viewer, "get_settings", lambda: settings)
    history.import_legacy(path, "app", [])
    history.append(path, "app", ["legacy retained entry", "captured new entry"])
    assert log_viewer.source_page("app")["text"] == "legacy retained entry"
    boundary = history.read_page(path, "app")
    history.activate_source(path, "app", generation=boundary.generation, through=boundary.through)
    accepted = log_viewer.source_page("app")
    assert accepted["text"].splitlines() == ["legacy retained entry", "captured new entry"]
    history.append(path, "app", ["live entry"])
    assert log_viewer.source_page("app", cursor=accepted["cursor"])["text"] == accepted["text"]
    assert log_viewer.source_page("app", cursor=accepted["next_cursor"])["text"] == "live entry"


def test_cutover_rejects_changed_or_interrupted_boundary(tmp_path):
    """Require the same validated generation and complete source boundary.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    boundary = history.read_page(path, "app")
    with pytest.raises(ValueError, match="boundary changed"):
        history.activate_source(path, "app", generation="replaced", through=0)
    history.append(path, "app", ["advanced"])
    with pytest.raises(ValueError, match="boundary changed"):
        history.activate_source(path, "app", generation=boundary.generation, through=0)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO capture_pending VALUES ('app','web',1,NULL)")
    with pytest.raises(ValueError, match="unfinished capture"):
        history.activate_source(path, "app", generation=boundary.generation, through=1)
    assert not history.source_active(path, "app")


def test_verified_legacy_import_preserves_rotated_order_and_redaction(tmp_path):
    """Import plain/gzip snapshots in one transaction without publishing early.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    import gzip
    import hashlib

    path = tmp_path / "history.sqlite"
    history.initialize(path)
    old, current = tmp_path / "app.log.1.gz", tmp_path / "app.log"
    old.write_bytes(gzip.compress(b"older\n-----BEGIN RSA PRIVATE KEY-----\n"))
    current.write_bytes(b"synthetic body\n-----END RSA PRIVATE KEY-----\nnewer\n")
    snapshots = [(p, hashlib.sha256(p.read_bytes()).hexdigest()) for p in (old, current)]
    history.import_legacy(path, "app", snapshots)
    page = history.read_page(path, "app")
    assert page.lines == ("older",) + ("[redacted private key]",) * 3 + ("newer",)
    assert not history.source_active(path, "app")
    history.activate_source(path, "app", generation=page.generation, through=page.through)
    assert history.source_active(path, "app")
    with pytest.raises(ValueError, match="unused source"):
        history.import_legacy(path, "app", snapshots)


def test_legacy_digest_failure_rolls_back_entire_import(tmp_path):
    """Reject changed snapshots without retaining earlier imported rows or readiness.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    import hashlib

    path = tmp_path / "history.sqlite"
    history.initialize(path)
    old, changed = tmp_path / "old.log", tmp_path / "changed.log"
    old.write_bytes(b"older retained entry\n")
    changed.write_bytes(b"modified after preservation\n")
    with pytest.raises(ValueError, match="digest changed"):
        history.import_legacy(path, "app", [(old, hashlib.sha256(old.read_bytes()).hexdigest()), (changed, "0" * 64)])
    page = history.read_page(path, "app")
    assert not page.lines
    with pytest.raises(ValueError, match="verified legacy import"):
        history.activate_source(path, "app", generation=page.generation, through=0)


def test_short_records_are_not_expired_by_an_unrelated_row_limit(tmp_path):
    """Keep the full byte retention window even when it contains many short lines.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    for _ in range(20):
        history.append(path, "app", ["x"] * 500)
    first = history.read_page(path, "app", limit=1)
    assert first.start == 0
    assert first.through == 10000
    assert first.lines == ("x",)


def test_redaction_expansion_does_not_shorten_raw_byte_retention(tmp_path, monkeypatch):
    """Expire by producer bytes rather than the longer fixed redaction labels.

    Args:
        tmp_path: Private test-owned storage directory.
        monkeypatch: Scoped small byte budget for deterministic expiry.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.append(path, "app", ["-----BEGIN RSA PRIVATE KEY-----"])
    monkeypatch.setattr(history, "RETAINED_BYTES", 6)
    history.append(path, "app", ["x"] * 4)
    assert history.read_page(path, "app").lines == ("[redacted private key]",) * 3


@pytest.mark.parametrize("compressed", [False, True])
def test_legacy_oversized_lines_preserve_redaction_and_byte_charge(tmp_path, compressed):
    """Stream omitted entries without losing split markers or original byte retention.

    Args:
        tmp_path: Private test-owned storage directory.
        compressed: Whether the preserved snapshot uses gzip encoding.
    """
    import gzip
    import hashlib
    import sqlite3

    path = tmp_path / "history.sqlite"
    history.initialize(path)
    # Split BEGIN across the importer's 64 KiB read boundary.
    content = (b"x" * 65530 + b"-----BEGIN RSA PRIVATE KEY-----" + b"y" * 70000
               + b"\nsynthetic body\n-----END RSA PRIVATE KEY-----\nafter\n")
    snapshot = tmp_path / ("app.log.gz" if compressed else "app.log")
    snapshot.write_bytes(gzip.compress(content) if compressed else content)
    history.import_legacy(path, "app", [(snapshot, hashlib.sha256(snapshot.read_bytes()).hexdigest())])
    page = history.read_page(path, "app")
    assert page.lines == (
        "[Oversized log entry omitted: exceeds 64 KiB; continuing with the next complete entry.]",
        "[redacted private key]", "[redacted private key]", "after")
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT byte_end FROM producer").fetchone()[0] == len(content)



def test_escaped_tail_budget_keeps_predecessor_positions(tmp_path):
    """Trimming a tail retains newest rows and reaches every older row once.

    Args:
        tmp_path: Private test-owned storage directory.
    """
    import json

    path = tmp_path / "history.sqlite"
    history.initialize(path)
    lines = [f"row {index}:" + "\0" * 50000 for index in range(5)]
    history.append(path, "app", lines)
    page = history.viewer_page(path, "app", tail=True)
    actual = page["text"].splitlines()
    assert actual == lines[-3:]
    assert len(json.dumps(page).encode()) <= history.BATCH_BYTES
    while page["previous_cursor"]:
        page = history.viewer_page(path, "app", cursor=page["previous_cursor"])
        assert len(json.dumps(page).encode()) <= history.BATCH_BYTES
        actual = page["text"].splitlines() + actual
    assert actual == lines
