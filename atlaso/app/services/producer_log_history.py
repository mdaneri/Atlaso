"""Store producer-owned log records and redaction state in one durable transaction.

This internal store accepts newly emitted records, never mutable file snapshots.
Callers must supply a private, trusted storage directory, not a request pathname.
Service producer wiring and legacy-file cutover are separate from this contract.
"""

import codecs
import gzip
import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from atlaso.app.services.log_sanitization import _safe_lines, redact_operational_text

SOURCES = frozenset({"app", "kms", "nginx-access", "nginx-error"})
WRITERS = {"app": frozenset({"web", "worker"}), "kms": frozenset({"service"}),
           "nginx-access": frozenset({"service"}), "nginx-error": frozenset({"service"})}
BATCH_BYTES = 1024 * 1024
RETAINED_BYTES = 8 * BATCH_BYTES


@dataclass(frozen=True)
class ProducerPage:
    """Describe an immutable source boundary and its bounded sanitized rows."""

    generation: str
    through: int
    start: int
    after: int
    lines: tuple[str, ...]
    more: bool
    oldest: int


def initialize(path: Path) -> None:
    """Initialize the store inside an already prepared private directory.

    Args:
        path: Internal database path within the producer's trusted private root.
    """
    lock_path = path.with_suffix(".capture-lock.sqlite")
    if not path.parent.is_dir() or path.is_symlink() or lock_path.is_symlink():
        raise ValueError("Producer history requires a prepared private directory.")
    with closing(sqlite3.connect(path, timeout=5)) as db, db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 8):
            raise ValueError("Unsupported producer history schema.")
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS identity(
                slot INTEGER PRIMARY KEY CHECK(slot=1), generation TEXT NOT NULL, receipt_key BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS producer(
                source TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
                byte_end INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoint(
                source TEXT NOT NULL, writer TEXT NOT NULL, private INTEGER NOT NULL,
                parser TEXT NOT NULL, PRIMARY KEY(source,writer));
            CREATE TABLE IF NOT EXISTS record(
                source TEXT NOT NULL, sequence INTEGER NOT NULL, byte_end INTEGER NOT NULL,
                text TEXT NOT NULL, PRIMARY KEY(source,sequence));
            CREATE INDEX IF NOT EXISTS record_bytes ON record(source,byte_end);
            CREATE TABLE IF NOT EXISTS receipt(
                source TEXT NOT NULL, writer TEXT NOT NULL, revision INTEGER NOT NULL,
                fingerprint BLOB NOT NULL, sequence INTEGER NOT NULL, PRIMARY KEY(source,writer));
            CREATE TABLE IF NOT EXISTS capture_pending(
                source TEXT PRIMARY KEY, writer TEXT NOT NULL, revision INTEGER NOT NULL, prepared TEXT);
            CREATE TABLE IF NOT EXISTS cutover(source TEXT PRIMARY KEY, boundary INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS legacy_import(source TEXT PRIMARY KEY, manifest TEXT NOT NULL);
        """)
        db.execute("INSERT OR IGNORE INTO identity VALUES (1,?,?)", (uuid4().hex, secrets.token_bytes(32)))
        db.execute("PRAGMA user_version=8")
    with closing(sqlite3.connect(lock_path, timeout=5)) as lock, lock:
        lock.execute("CREATE TABLE IF NOT EXISTS guard(slot INTEGER PRIMARY KEY)")


def capture_record(path: Path, writer: str, record: logging.LogRecord, formatter: logging.Formatter,
                   *, source: str = "app") -> None:
    """Capture one in-process fixed-source record without changing the service process.

    A separate SQLite write lock serializes fixed-source capture. The durable pending
    marker precedes formatting and remains after any unacknowledged failure. A
    restart refuses further capture until that interrupted input is recovered;
    it must never accept a later private-key body after losing its opening marker.

    Args:
        path: Trusted initialized producer database path.
        writer: Fixed producer slot for the selected source.
        record: Newly emitted Python logging record.
        formatter: Existing operational formatter including exception rendering.
        source: Fixed App or external operational source identifier.
    """
    if writer not in WRITERS.get(source, frozenset()):
        raise ValueError("Invalid producer slot.")
    lock_path = path.with_suffix(".capture-lock.sqlite")
    if lock_path.is_symlink():
        raise ValueError("Invalid producer capture lock.")
    with closing(sqlite3.connect(lock_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)) as lock, lock:
        lock.execute("BEGIN IMMEDIATE")
        _finish_prepared_capture(path, source)
        with closing(_connect(path, source)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM capture_pending WHERE source=?", (source,)).fetchone():
                raise ValueError("Producer history capture requires interrupted-record recovery.")
            row = db.execute("SELECT revision FROM receipt WHERE source=? AND writer=?", (source, writer)).fetchone()
            revision = int(row[0]) + 1 if row else 1
            db.execute("INSERT INTO capture_pending VALUES (?,?,?,NULL)", (source, writer, revision))
        lines = formatter.format(record).splitlines() or [""]
        append(path, source, lines, writer=writer, revision=revision, prepare_only=True)
        _finish_prepared_capture(path, source)


def _finish_prepared_capture(path: Path, source: str) -> None:
    """Publish an interrupted sanitized batch while the caller holds the capture lock.

    Args:
        path: Trusted initialized producer database path.
        source: Fixed operational source identifier.
    """
    with closing(_connect(path, source)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT writer,revision,prepared FROM capture_pending WHERE source=?", (source,)).fetchone()
        if row is None:
            return
        if row[2] is None:
            raise ValueError("Producer history capture requires interrupted-record recovery.")
        prepared = json.loads(row[2])
        current = db.execute("SELECT sequence,byte_end FROM producer WHERE source=?", (source,)).fetchone()
        sequence, byte_end = (int(current[0]), int(current[1])) if current else (0, 0)
        if [sequence, byte_end] != prepared["base"]:
            raise ValueError("Prepared capture does not match its source boundary.")
        for text, charge in zip(prepared["lines"], prepared["charges"], strict=True):
            sequence += 1
            byte_end += charge
            db.execute("INSERT INTO record VALUES (?,?,?,?)", (source, sequence, byte_end, text))
        db.execute("UPDATE producer SET sequence=?,byte_end=? WHERE source=?", (sequence, byte_end, source))
        db.execute("UPDATE checkpoint SET private=?,parser=? WHERE source=? AND writer=?",
                   (prepared["private"], json.dumps(prepared["parser"]), source, row[0]))
        db.execute("INSERT INTO receipt VALUES (?,?,?,?,?) ON CONFLICT(source,writer) DO UPDATE SET "
                   "revision=excluded.revision,fingerprint=excluded.fingerprint,sequence=excluded.sequence",
                   (source, row[0], row[1], bytes.fromhex(prepared["fingerprint"]), sequence))
        if source == "app":
            db.execute("DELETE FROM record WHERE source=? AND byte_end<=?", (source, byte_end - RETAINED_BYTES))
        db.execute("DELETE FROM capture_pending WHERE source=?", (source,))


def _connect(path: Path, source: str) -> sqlite3.Connection:
    """Open an initialized fixed-source store without creating a missing database.

    Args:
        path: Trusted producer database path.
        source: Fixed operational source identifier.
    """
    if source not in SOURCES or path.is_symlink():
        raise ValueError("Invalid producer history source.")
    return sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)


def activate_source(path: Path, source: str, *, generation: str, through: int) -> None:
    """Publish a verified import/capture boundary after the caller quiesces producers.

    This internal cutover operation is not exposed to browser requests. The
    lifecycle caller must first preserve and validate all retained legacy input.
    Compare-and-set prevents publishing if capture advanced after validation.

    Args:
        path: Trusted prepared producer store.
        source: Fixed operational source identifier.
        generation: Verified store generation selected by the lifecycle caller.
        through: Exact source sequence after legacy import and validation.
    """
    with closing(_connect(path, source)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        observed = db.execute("SELECT generation FROM identity").fetchone()[0]
        row = db.execute("SELECT sequence FROM producer WHERE source=?", (source,)).fetchone()
        if generation != observed or type(through) is not int or through != (int(row[0]) if row else 0):
            raise ValueError("Producer cutover boundary changed after validation.")
        if db.execute("SELECT 1 FROM capture_pending WHERE source=?", (source,)).fetchone():
            raise ValueError("Producer cutover has unfinished capture.")
        if not db.execute("SELECT 1 FROM legacy_import WHERE source=?", (source,)).fetchone():
            raise ValueError("Producer cutover requires verified legacy import.")
        db.execute("INSERT INTO cutover VALUES (?,?) ON CONFLICT(source) DO NOTHING", (source, through))


class _DigestInput:
    """Hash exactly the preserved bytes consumed by the legacy decoder."""

    def __init__(self, stream: BinaryIO) -> None:
        """Bind a caller-owned snapshot descriptor.

        Args:
            stream: Already opened preserved legacy file.
        """
        self.stream = stream
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        """Read and authenticate one bounded compressed or plain input chunk.

        Args:
            size: Bounded byte count requested by the importer or gzip decoder.
        """
        if size < 0:
            raise ValueError("Legacy import requires bounded reads.")
        data = self.stream.read(size)
        self.digest.update(data)
        return data

    def seek(self, offset: int) -> int:
        """Reject rewinding an authenticated single-pass stream.

        Args:
            offset: Unsupported requested stream position.
        """
        raise OSError("Preserved legacy input is a forward-only authenticated stream.")


def import_legacy(path: Path, source: str, snapshots: list[tuple[Path, str]]) -> None:
    """Import preserved oldest-first snapshots atomically before enabling capture.

    The lifecycle caller owns quiescence, inventory completeness and snapshot
    preservation. Expected digests must come from that inventory. A mismatch,
    decode failure rolls back the entire source import. Oversized physical lines
    retain their byte charge and redaction state but display an omission notice.

    Args:
        path: Prepared private producer database with no prior source events.
        source: Fixed operational source identifier.
        snapshots: Preserved plain/gzip paths and expected SHA256 digests, oldest first.
    """
    with closing(_connect(path, source)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if any(db.execute(f"SELECT 1 FROM {table} WHERE source=?", (source,)).fetchone()
               for table in ("producer", "capture_pending", "cutover", "legacy_import")):
            raise ValueError("Legacy import requires an unused source.")
        sequence, byte_end, private = 0, 0, False
        parser: dict[str, str] = {}
        for snapshot, expected in snapshots:
            if snapshot.is_symlink() or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
                raise ValueError("Invalid preserved legacy snapshot.")
            with snapshot.open("rb") as raw:
                checked = _DigestInput(raw)
                decoded = gzip.GzipFile(fileobj=checked, mode="rb") if snapshot.suffix == ".gz" else checked
                pending = b""
                charge = 0
                oversized = False
                try:
                    while True:
                        block = decoded.read(65536)
                        fragments = block.split(b"\n")
                        for index, fragment in enumerate(fragments):
                            complete = index < len(fragments) - 1
                            charge += len(fragment) + int(complete)
                            if oversized:
                                _, private = _safe_lines([fragment.decode("utf-8", errors="replace")], private, parser)
                            else:
                                pending += fragment
                                if len(pending) > 65536:
                                    oversized = True
                                    _, private = _safe_lines([pending.decode("utf-8", errors="replace")], private, parser)
                                    pending = b""
                            if complete or (not block and charge):
                                if oversized:
                                    safe = ["[Oversized log entry omitted: exceeds 64 KiB; continuing with the next complete entry.]"]
                                else:
                                    safe, private = _safe_lines([pending.decode("utf-8", errors="replace").removesuffix("\r")], private, parser)
                                for row_index, value in enumerate(safe):
                                    text = redact_operational_text(value)
                                    sequence += 1
                                    byte_end += max(1, charge) if row_index == 0 else 0
                                    db.execute("INSERT INTO record VALUES (?,?,?,?)", (source, sequence, byte_end, text))
                                pending, charge, oversized = b"", 0, False
                        if not block:
                            break
                    if not hmac.compare_digest(checked.digest.hexdigest(), expected):
                        raise ValueError("Preserved legacy snapshot digest changed.")
                finally:
                    if isinstance(decoded, gzip.GzipFile):
                        decoded.close()
        db.execute("INSERT INTO producer VALUES (?,?,?)", (source, sequence, byte_end))
        for writer in WRITERS[source]:
            db.execute("INSERT INTO checkpoint VALUES (?,?,?,?)", (source, writer, int(private), json.dumps(parser)))
        db.execute("INSERT INTO legacy_import VALUES (?,?)", (source, json.dumps([digest for _, digest in snapshots])))


def source_active(path: Path, source: str) -> bool:
    """Return whether lifecycle validation explicitly published this source.

    Args:
        path: Trusted prepared producer store.
        source: Fixed operational source identifier.
    """
    with closing(_connect(path, source)) as db:
        return db.execute("SELECT 1 FROM cutover WHERE source=?", (source,)).fetchone() is not None


def append(path: Path, source: str, lines: list[str], *, writer: str | None = None,
           revision: int | None = None, prepare_only: bool = False) -> int:
    """Commit newly emitted complete lines with their redaction checkpoint.

    Args:
        path: Trusted initialized producer database path.
        source: Fixed operational source identifier.
        lines: New complete physical lines; cumulative snapshots are not accepted.
        writer: Optional fixed producer slot for retry-safe ordered batches.
        revision: Monotonic producer batch number, required with writer; retries reuse it.
        prepare_only: Stage sanitized producer input under an existing capture marker for crash recovery.
    """
    if not isinstance(lines, list) or not lines or (not prepare_only and len(lines) > 500) or any(
        not isinstance(line, str) or (bool(line) and line.splitlines() != [line])
        or (not prepare_only and len(line.encode("utf-8")) > 65536)
        for line in lines
    ):
        raise ValueError("Producer records must be bounded complete physical lines.")
    if not prepare_only and sum(len(line.encode("utf-8")) + 1 for line in lines) > BATCH_BYTES:
        raise ValueError("Producer batch exceeds its byte budget.")
    if (writer is None) != (revision is None) or (writer is not None and (
        writer not in WRITERS.get(source, frozenset()) or type(revision) is not int or revision < 1
    )):
        raise ValueError("Invalid producer receipt identity.")
    with closing(_connect(path, source)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        pending = db.execute("SELECT writer,revision,prepared FROM capture_pending WHERE source=?", (source,)).fetchone()
        if pending and (writer, revision) != tuple(pending[:2]):
            raise ValueError("Producer capture requires interrupted-record recovery.")
        if prepare_only and pending is None:
            raise ValueError("Prepared capture requires a matching input marker.")
        fingerprint = b""
        if writer is not None:
            key = bytes(db.execute("SELECT receipt_key FROM identity").fetchone()[0])
            fingerprint = hmac.new(key, json.dumps(lines, ensure_ascii=False).encode("utf-8"), hashlib.sha256).digest()
            if pending and pending[2] is not None and not hmac.compare_digest(
                bytes.fromhex(json.loads(pending[2])["fingerprint"]), fingerprint
            ):
                raise ValueError("Producer input conflicts with its prepared capture.")
            receipt = db.execute("SELECT revision,fingerprint,sequence FROM receipt WHERE source=? AND writer=?",
                                 (source, writer)).fetchone()
            previous = int(receipt[0]) if receipt else 0
            if revision == previous and receipt and hmac.compare_digest(bytes(receipt[1]), fingerprint):
                return int(receipt[2])
            if revision != previous + 1:
                raise ValueError("Producer revision conflicts with its committed receipt.")
        db.execute("INSERT OR IGNORE INTO producer VALUES (?,0,0)", (source,))
        row = db.execute("SELECT sequence,byte_end FROM producer WHERE source=?", (source,)).fetchone()
        sequence, byte_end = int(row[0]), int(row[1])
        slot = writer or ""
        db.execute("INSERT OR IGNORE INTO checkpoint VALUES (?,?,0,'{}')", (source, slot))
        state = db.execute("SELECT private,parser FROM checkpoint WHERE source=? AND writer=?",
                           (source, slot)).fetchone()
        parser: dict[str, str] = json.loads(state[1])
        safe, private = _safe_lines(lines, bool(state[0]), parser)
        # A different process's footer cannot close this producer's private key.
        # Keep the combined source conservative while any other producer is inside
        # a key or has an incomplete marker, without merging their parser streams.
        concealed = False
        for other_private, other_parser in db.execute(
            "SELECT private,parser FROM checkpoint WHERE source=? AND writer<>?", (source, slot)
        ):
            other = json.loads(other_parser)
            carry = json.loads(other["carry"]) if other.get("carry") else ["S", ""]
            concealed = concealed or bool(other_private) or other.get("hold") == "1" or carry[0] != "S" or bool(carry[1])
        texts = ["[redacted private key]" if concealed else redact_operational_text(line) for line in safe]
        charges = [len(line.encode("utf-8")) + 1 for line in lines]
        # A formatted LogRecord can contain a traceback or a multiline diagnostic
        # longer than a transport page. Capture the whole new event atomically;
        # page limits are reader limits. Match the existing file viewer's explicit
        # oversized-line marker, after scanning the original for redaction state.
        texts = ["[Oversized log entry omitted: exceeds 64 KiB; continuing with the next complete entry.]"
                 if charge > 65537 else text for text, charge in zip(texts, charges, strict=True)]
        if prepare_only:
            prepared = {"base": [sequence, byte_end], "lines": texts, "private": int(private),
                        "parser": parser, "fingerprint": fingerprint.hex(), "charges": charges}
            db.execute("UPDATE capture_pending SET prepared=? WHERE source=?", (json.dumps(prepared), source))
            return sequence + len(texts)
        for text, charge in zip(texts, charges, strict=True):
            sequence += 1
            byte_end += charge
            db.execute("INSERT INTO record VALUES (?,?,?,?)", (source, sequence, byte_end, text))
        db.execute("UPDATE producer SET sequence=?,byte_end=? WHERE source=?", (sequence, byte_end, source))
        db.execute("UPDATE checkpoint SET private=?,parser=? WHERE source=? AND writer=?",
                   (int(private), json.dumps(parser), source, slot))
        # Charge original producer bytes: redaction expansion must not shorten the
        # existing file retention window. Indexed expiry does not scan kept rows.
        if source == "app":
            db.execute("DELETE FROM record WHERE source=? AND byte_end<=?", (source, byte_end - RETAINED_BYTES))
        if writer is not None:
            db.execute("INSERT INTO receipt VALUES (?,?,?,?,?) ON CONFLICT(source,writer) DO UPDATE SET "
                       "revision=excluded.revision,fingerprint=excluded.fingerprint,sequence=excluded.sequence",
                       (source, writer, revision, fingerprint, sequence))
        if pending:
            db.execute("DELETE FROM capture_pending WHERE source=?", (source,))
        return sequence


def append_stream(path: Path, source: str, chunks: Iterable[bytes], *, writer: str, revision: int) -> int:
    """Commit one authenticated physical record using bounded input chunks.

    The caller owns the sealed input and complete record boundary. Raw bytes are
    fingerprinted even when their visible row is an omission notice. Checkpoint
    changes remain local until the entire input and receipt have been checked.

    Args:
        path: Trusted initialized producer database path.
        source: Fixed operational source identifier.
        chunks: One complete physical record in nonempty chunks of at most 64 KiB.
        writer: Fixed producer slot for retry-safe ordered records.
        revision: Monotonic batch number, reused unchanged after a lost acknowledgment.
    """
    if writer not in WRITERS.get(source, frozenset()) or type(revision) is not int or revision < 1:
        raise ValueError("Invalid producer receipt identity.")
    with closing(_connect(path, source)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM capture_pending WHERE source=?", (source,)).fetchone():
            raise ValueError("Producer capture requires interrupted-record recovery.")
        key = bytes(db.execute("SELECT receipt_key FROM identity").fetchone()[0])
        digest = hmac.new(key, b"physical-record\0", hashlib.sha256)
        state = db.execute("SELECT private,parser FROM checkpoint WHERE source=? AND writer=?",
                           (source, writer)).fetchone()
        private, parser = (bool(state[0]), json.loads(state[1])) if state else (False, {})
        pending = b""
        charge, terminated, oversized = 0, False, False
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        for chunk in chunks:
            if not isinstance(chunk, bytes) or not 0 < len(chunk) <= 65536 or terminated:
                raise ValueError("Streamed producer records require bounded physical input.")
            if b"\n" in chunk:
                if not chunk.endswith(b"\n") or b"\n" in chunk[:-1]:
                    raise ValueError("Streamed producer input contains multiple physical records.")
                terminated = True
            digest.update(chunk)
            charge += len(chunk)
            fragment = chunk[:-1] if terminated else chunk
            if oversized:
                _, private = _safe_lines([decoder.decode(fragment)], private, parser)
            elif len(pending) + len(fragment) > 65536:
                oversized = True
                _, private = _safe_lines([decoder.decode(pending + fragment)], private, parser)
                pending = b""
            else:
                pending += fragment
        if not charge:
            raise ValueError("Streamed producer record is empty.")
        if oversized:
            _, private = _safe_lines([decoder.decode(b"", final=True)], private, parser)
            text = "[Oversized log entry omitted: exceeds 64 KiB; continuing with the next complete entry.]"
        else:
            safe, private = _safe_lines([pending.decode("utf-8", errors="replace").removesuffix("\r")], private, parser)
            # Other Unicode line separators are accepted by the shared sanitizer;
            # keep this physical record represented by exactly one durable row.
            text = " ".join(redact_operational_text(value) for value in safe)
        fingerprint = digest.digest()
        receipt = db.execute("SELECT revision,fingerprint,sequence FROM receipt WHERE source=? AND writer=?",
                             (source, writer)).fetchone()
        previous = int(receipt[0]) if receipt else 0
        if revision == previous and receipt and hmac.compare_digest(bytes(receipt[1]), fingerprint):
            return int(receipt[2])
        if revision != previous + 1:
            raise ValueError("Producer revision conflicts with its committed receipt.")
        for other_private, other_parser in db.execute(
            "SELECT private,parser FROM checkpoint WHERE source=? AND writer<>?", (source, writer)
        ):
            other = json.loads(other_parser)
            carry = json.loads(other["carry"]) if other.get("carry") else ["S", ""]
            if not oversized and (other_private or other.get("hold") == "1" or carry[0] != "S" or carry[1]):
                text = "[redacted private key]"
        db.execute("INSERT OR IGNORE INTO producer VALUES (?,0,0)", (source,))
        row = db.execute("SELECT sequence,byte_end FROM producer WHERE source=?", (source,)).fetchone()
        sequence, byte_end = int(row[0]) + 1, int(row[1]) + charge
        db.execute("INSERT INTO record VALUES (?,?,?,?)", (source, sequence, byte_end, text))
        db.execute("UPDATE producer SET sequence=?,byte_end=? WHERE source=?", (sequence, byte_end, source))
        db.execute("INSERT INTO checkpoint VALUES (?,?,?,?) ON CONFLICT(source,writer) DO UPDATE SET "
                   "private=excluded.private,parser=excluded.parser", (source, writer, int(private), json.dumps(parser)))
        if source == "app":
            db.execute("DELETE FROM record WHERE source=? AND byte_end<=?", (source, byte_end - RETAINED_BYTES))
        db.execute("INSERT INTO receipt VALUES (?,?,?,?,?) ON CONFLICT(source,writer) DO UPDATE SET "
                   "revision=excluded.revision,fingerprint=excluded.fingerprint,sequence=excluded.sequence",
                   (source, writer, revision, fingerprint, sequence))
        return sequence


def read_page(path: Path, source: str, *, after: int = 0, through: int | None = None,
              generation: str | None = None, limit: int = 500) -> ProducerPage:
    """Read within a stable source boundary while independent producers append.

    Args:
        path: Trusted initialized producer database path.
        source: Fixed operational source identifier.
        after: Exclusive sequence of the last accepted row, or zero for retained start.
        through: Pinned inclusive boundary, or None to select the current live boundary.
        generation: Expected database identity from an earlier page, if present.
        limit: Maximum physical rows to return, between one and five hundred.
    """
    if not 1 <= limit <= 500 or after < 0 or (through is not None and through < after):
        raise ValueError("Invalid producer history position.")
    with closing(_connect(path, source)) as db, db:
        db.execute("BEGIN")
        observed = str(db.execute("SELECT generation FROM identity").fetchone()[0])
        if generation is not None and generation != observed:
            raise ValueError("Producer history was replaced; reopen retained history.")
        row = db.execute("SELECT sequence FROM producer WHERE source=?", (source,)).fetchone()
        newest = int(row[0]) if row else 0
        boundary = newest if through is None else through
        if boundary > newest or after > newest:
            raise ValueError("Producer history boundary is unavailable.")
        first = db.execute("SELECT MIN(sequence) FROM record WHERE source=?", (source,)).fetchone()[0]
        if through and first is not None and through < int(first):
            raise ValueError("Producer history boundary expired through retention.")
        if (after or (through is not None and through > 0)) and first is not None and after < int(first) - 1:
            raise ValueError("Producer history position expired through retention.")
        output: list[str] = []
        used, position = 0, after
        for sequence, text in db.execute(
            "SELECT sequence,text FROM record WHERE source=? AND sequence>? AND sequence<=? ORDER BY sequence LIMIT ?",
            (source, after, boundary, limit),
        ):
            size = len(str(text).encode("utf-8")) + 1
            if used + size > BATCH_BYTES:
                break
            output.append(str(text))
            used += size
            position = int(sequence)
        start = max(after, int(first) - 1) if output and first is not None else after
        return ProducerPage(observed, boundary, start, position, tuple(output), position < newest, int(first or 0))


def read_tail(path: Path, source: str, *, before: int | None = None,
              generation: str | None = None, limit: int = 500) -> ProducerPage:
    """Select the newest bounded group at a fixed predecessor boundary.

    Args:
        path: Trusted initialized producer database path.
        source: Fixed operational source identifier.
        before: Inclusive final sequence, or None for the current retained tail.
        generation: Expected database identity from an earlier page, if present.
        limit: Maximum physical rows to return, between one and five hundred.
    """
    if not 1 <= limit <= 500 or (before is not None and before < 0):
        raise ValueError("Invalid producer history position.")
    with closing(_connect(path, source)) as db, db:
        db.execute("BEGIN")
        observed = str(db.execute("SELECT generation FROM identity").fetchone()[0])
        if generation is not None and generation != observed:
            raise ValueError("Producer history was replaced; reopen retained history.")
        # SQLite's endpoint optimization applies to one MIN/MAX aggregate per
        # statement; selecting both together walks the entire retained source.
        first = db.execute("SELECT MIN(sequence) FROM record WHERE source=?", (source,)).fetchone()[0]
        last = db.execute("SELECT MAX(sequence) FROM record WHERE source=?", (source,)).fetchone()[0]
        boundary = int(last or 0) if before is None else before
        if boundary > int(last or 0) or (boundary and first is not None and boundary < int(first)):
            raise ValueError("Producer history boundary expired through retention.")
        rows: list[tuple[int, str]] = []
        used = 0
        for sequence, text in db.execute(
            "SELECT sequence,text FROM record WHERE source=? AND sequence<=? ORDER BY sequence DESC LIMIT ?",
            (source, boundary, limit),
        ):
            size = len(str(text).encode("utf-8")) + 1
            if used + size > BATCH_BYTES:
                break
            rows.append((int(sequence), str(text)))
            used += size
        rows.reverse()
        start = rows[0][0] - 1 if rows else boundary
        end = rows[-1][0] if rows else boundary
        return ProducerPage(observed, boundary, start, end, tuple(text for _, text in rows),
                            end < int(last or 0), int(first or 0))


def viewer_page(path: Path, source: str, *, cursor: str = "", tail: bool = False,
                limit: int = 500) -> dict[str, object]:
    """Adapt committed producer records to the existing signed viewer contract.

    Args:
        path: Server-selected private store path, never taken from the cursor.
        source: Authorized fixed operational source selected by the endpoint.
        cursor: Existing appliance-signed producer position for this source.
        tail: Whether to open the newest retained group directly.
        limit: Requested physical row limit.
    """
    # Local import keeps logging initialization independent of viewer initialization.
    from atlaso.app.services.log_viewer import decode_cursor

    position = decode_cursor(cursor, source)
    if position and position.get("kind") != "producer":
        raise ValueError("Log history position belongs to another storage generation.")
    generation = position.get("generation")
    if generation is not None and not isinstance(generation, str):
        raise ValueError("Invalid producer history identity.")
    for key in ("after", "through", "before"):
        if key in position and (type(position[key]) is not int or position[key] < 0):
            raise ValueError("Invalid producer history position.")
    if tail or "before" in position:
        page = read_tail(path, source, before=None if tail else position["before"],
                         generation=generation, limit=limit)
    else:
        page = read_page(path, source, after=position.get("after", 0), through=position.get("through"),
                         generation=generation, limit=limit)
    return bounded_viewer_page(page, source, backward=tail or "before" in position)


def bounded_viewer_page(page: ProducerPage, source: str, *, backward: bool = False) -> dict[str, object]:
    """Fit sanitized rows and signed positions inside the complete JSON wire budget.

    Args:
        page: Validated immutable row range returned by a local or privileged store.
        source: Authorized operational source bound into every cursor.
        backward: Keep the newest rows when selecting a tail or predecessor page.
    """
    from atlaso.app.services.log_viewer import PAGE_BYTES, encode_cursor

    def render(count: int) -> dict[str, object]:
        """Build one candidate response with positions matching only included rows.

        Args:
            count: Number of rows retained from the requested directional boundary.
        """
        lines = page.lines[-count:] if backward and count else page.lines[:count]
        start = page.after - count if backward else page.start
        after = page.after if backward else page.start + count
        common = {"kind": "producer", "generation": page.generation}
        return {"source": source, "available": True, "text": "\n".join(lines),
                "cursor": encode_cursor(source, **common, after=start, through=after),
                "next_cursor": encode_cursor(source, **common, after=after),
                "previous_cursor": encode_cursor(source, **common, before=start)
                if start >= page.oldest and page.oldest else "",
                "has_more": page.more or (not backward and count < len(page.lines)),
                "reset": False, "notice": ""}

    low, high = 0, len(page.lines)
    while low < high:
        middle = (low + high + 1) // 2
        # ASCII escaping is at least as large as the UTF-8 JSON emitted by the API.
        if len(json.dumps(render(middle), ensure_ascii=True).encode("utf-8")) <= PAGE_BYTES:
            low = middle
        else:
            high = middle - 1
    if page.lines and low == 0:
        raise ValueError("Producer record exceeds the viewer response budget.")
    return render(low)
