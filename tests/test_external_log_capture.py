"""Verify external producer capture without changing appliance services."""

import hashlib
import io
import json
import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from atlaso.app.services import (
    external_log_reader,
    nginx_log_capture,
    nginx_log_sealing,
    producer_log_history,
)
from atlaso.app.services.kmip_log_capture import CapturingStreamHandler


def test_nginx_seal_waits_for_closed_descriptors_and_includes_final_write(tmp_path):
    """Reopen alone cannot publish an old file that a worker still writes.

    Args:
        tmp_path: Test-owned source and generation directories.
    """
    logs, retained = tmp_path / "logs", tmp_path / "generation"
    logs.mkdir()
    retained.mkdir(mode=0o700)
    for name in nginx_log_sealing.LOG_NAMES:
        (logs / name).write_bytes(b"first\n")
    observed = []

    def reopen():
        """Simulate master reopen while a worker retains its old file."""
        for name in nginx_log_sealing.LOG_NAMES:
            (logs / name).write_bytes(b"new generation\n")
        assert json.loads((retained / "manifest.json").read_text())["state"] == "prepared"

    def closed(identities):
        """Simulate a final worker write before all inherited descriptors close.

        Args:
            identities: Both retained device/inode identities.
        """
        observed.append(identities)
        if len(observed) == 1:
            with (retained / "access.log").open("ab") as stream:
                stream.write(b"last worker write\n")
            return False
        return True

    manifest = nginx_log_sealing.seal_generation(logs, retained, reopen=reopen, writers_closed=closed)
    assert len(observed) == 2
    assert manifest["state"] == "sealed"
    assert manifest["files"]["access.log"]["sha256"] == hashlib.sha256(b"first\nlast worker write\n").hexdigest()
    assert (logs / "access.log").read_bytes() == b"new generation\n"


def test_nginx_failed_reopen_preserves_generation_and_retry(tmp_path):
    """A failed signal retains complete recovery state and does not delete data.

    Args:
        tmp_path: Test-owned source and retained generation directories.
    """
    logs, retained = tmp_path / "logs", tmp_path / "generation"
    logs.mkdir()
    retained.mkdir(mode=0o700)
    for name in nginx_log_sealing.LOG_NAMES:
        (logs / name).write_bytes(b"retained\n")

    def failed():
        """Inject an unavailable reopen operation."""
        raise OSError("synthetic unavailable master")

    with pytest.raises(OSError, match="synthetic"):
        nginx_log_sealing.seal_generation(logs, retained, reopen=failed, writers_closed=lambda _: True)
    assert json.loads((retained / "manifest.json").read_text())["state"] == "prepared"
    assert (retained / "access.log").read_bytes() == b"retained\n"
    result = nginx_log_sealing.seal_generation(logs, retained, reopen=lambda: None, writers_closed=lambda _: True)
    assert result["state"] == "sealed"
    (retained / "access.log").write_bytes(b"rewritten\n")
    with pytest.raises(ValueError, match="contents changed"):
        nginx_log_sealing.seal_generation(logs, retained, reopen=lambda: None, writers_closed=lambda _: True)


def test_nginx_never_seals_with_live_old_descriptor(tmp_path):
    """A persistent old worker descriptor leaves the source unsealed.

    Args:
        tmp_path: Test-owned source and generation directories.
    """
    logs, retained = tmp_path / "logs", tmp_path / "generation"
    logs.mkdir()
    retained.mkdir(mode=0o700)
    for name in nginx_log_sealing.LOG_NAMES:
        (logs / name).write_bytes(b"retained\n")
    with pytest.raises(TimeoutError, match="not closed"):
        nginx_log_sealing.seal_generation(logs, retained, reopen=lambda: None,
                                         writers_closed=lambda _: False, timeout=0.001)
    assert json.loads((retained / "manifest.json").read_text())["state"] == "prepared"


def test_kms_capture_commits_before_mirror_and_survives_new_handler(tmp_path):
    """A new KMS handler continues durable redaction through an interrupted key.

    Args:
        tmp_path: Test-owned prepared producer database directory.
    """
    path = tmp_path / "kms.sqlite"
    producer_log_history.initialize(path)
    producer_log_history.import_legacy(path, "kms", [])
    mirror = io.StringIO()
    handler = CapturingStreamHandler(path, mirror)
    handler.emit(logging.LogRecord("kms", logging.INFO, "", 0, "-----BEGIN PRIVATE KEY-----", (), None))
    handler = CapturingStreamHandler(path, mirror)
    handler.emit(logging.LogRecord("kms", logging.INFO, "", 0, "synthetic-hidden-body", (), None))
    page = producer_log_history.read_page(path, "kms")
    assert len(page.lines) == 2
    assert "synthetic-hidden-body" not in "\n".join(page.lines)
    assert producer_log_history.read_page(path, "app").lines == ()


def test_kms_capture_failure_does_not_acknowledge_or_mirror(tmp_path, monkeypatch):
    """Failed durable capture cannot silently pass a record to the raw mirror.

    Args:
        tmp_path: Test-owned store pathname.
        monkeypatch: Capture failure injection.
    """
    def fail(*args, **kwargs):
        """Reject the synthetic capture transaction.

        Args:
            *args: Capture positional arguments.
            **kwargs: Capture named arguments.
        """
        raise OSError("synthetic disk full")

    monkeypatch.setattr(producer_log_history, "capture_record", fail)
    mirror = io.StringIO()
    handler = CapturingStreamHandler(tmp_path / "kms.sqlite", mirror)
    with pytest.raises(OSError, match="disk full"):
        handler.emit(logging.LogRecord("kms", logging.INFO, "", 0, "new record", (), None))
    assert mirror.getvalue() == ""


def test_fixed_producer_reader_activation_and_stable_page(tmp_path, monkeypatch):
    """Readers stay inactive until verified cutover, then refresh exact boundaries.

    Args:
        tmp_path: Test-owned fixed producer store.
        monkeypatch: Bind the server-selected source path to the owned fixture.
    """
    path = tmp_path / "nginx.sqlite"
    monkeypatch.setitem(external_log_reader.STORE_PATHS, "nginx-access", path)
    request = {"transport": "producer", "limit": 2}
    assert external_log_reader.producer_page("nginx-access", request) == {"active": False}
    producer_log_history.initialize(path)
    producer_log_history.import_legacy(path, "nginx-access", [])
    producer_log_history.append(path, "nginx-access", ["one", "two"], writer="service", revision=1)
    assert external_log_reader.producer_page("nginx-access", request) == {"active": False}
    boundary = producer_log_history.read_page(path, "nginx-access")
    producer_log_history.activate_source(path, "nginx-access", generation=boundary.generation, through=boundary.through)
    first = external_log_reader.producer_page("nginx-access", request)
    producer_log_history.append(path, "nginx-access", ["three"], writer="service", revision=2)
    repeat = external_log_reader.producer_page("nginx-access", {
        **request, "after": first["start"], "through": first["after"], "generation": first["generation"]})
    assert repeat["lines"] == first["lines"] == ("one", "two")


@pytest.mark.parametrize("position", [
    {"transport": "producer", "path": "/etc/passwd"},
    {"transport": "producer", "after": True},
    {"transport": "producer", "limit": 501},
    {"transport": "producer", "generation": "../elsewhere"},
    {"transport": "producer", "before": 1, "after": 0},
])
def test_fixed_producer_reader_rejects_unbounded_or_arbitrary_fields(position):
    """Only source-bound numeric positions cross the privilege boundary.

    Args:
        position: Invalid synthetic request position.
    """
    with pytest.raises(ValueError):
        external_log_reader.producer_page("nginx-access", position)


def test_helper_producer_transport_is_fixed_and_bounded(monkeypatch, capsys):
    """The privileged reader launches only the fixed module and bounded request.

    Args:
        monkeypatch: Replace process execution with a captured synthetic response.
        capsys: Capture sanitized helper response text.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    calls = []

    def run(command, **kwargs):
        """Record the exact allowlisted helper subprocess.

        Args:
            command: Fixed Python module plus bounded source/position.
            **kwargs: Fixed timeout options.
        """
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, '{"active": false}', "")

    monkeypatch.setattr(helper, "_run", run)
    assert helper._read_log_history(["nginx-access", '{"transport":"producer"}']) == 0
    assert json.loads(capsys.readouterr().out) == {"active": False}
    assert calls[0][0] == [str(helper.ATLASO_VENV_PYTHON_PATH), "-I", "-m",
                          "atlaso.app.services.external_log_reader", "nginx-access", '{"transport":"producer"}']
    assert calls[0][1] == {"timeout": 15}
    assert helper._read_log_history(["/etc/passwd", '{"transport":"producer"}']) == 2


def test_sealed_generation_capture_retries_lost_acknowledgment(tmp_path, monkeypatch):
    """A committed batch whose offset write failed is replayed without duplicates.

    Args:
        tmp_path: Test-owned sealed generation and producer store.
        monkeypatch: Inject one post-commit checkpoint publication failure.
    """
    logs, retained = tmp_path / "logs", tmp_path / "generation"
    logs.mkdir()
    retained.mkdir(mode=0o700)
    (logs / "access.log").write_bytes(b"first\nsecond\n")
    (logs / "error.log").write_bytes(b"-----BEGIN PRIVATE KEY-----\nsynthetic-private-body\n")
    nginx_log_sealing.seal_generation(logs, retained, reopen=lambda: None, writers_closed=lambda _: True)
    path = tmp_path / "history.sqlite"
    producer_log_history.initialize(path)
    for source in ("nginx-access", "nginx-error"):
        producer_log_history.import_legacy(path, source, [])
    original = nginx_log_capture._checkpoint
    calls = []

    def interrupted(directory, state):
        """Lose the offset publication after the first committed batch.

        Args:
            directory: Sealed generation checkpoint directory.
            state: Pending or acknowledged offset state.
        """
        calls.append(True)
        if len(calls) == 3:
            raise OSError("synthetic lost offset acknowledgment")
        original(directory, state)

    monkeypatch.setattr(nginx_log_capture, "_checkpoint", interrupted)
    with pytest.raises(OSError, match="lost offset"):
        nginx_log_capture.capture_generation(path, retained)
    assert producer_log_history.read_page(path, "nginx-access").lines == ("first", "second")
    monkeypatch.setattr(nginx_log_capture, "_checkpoint", original)
    nginx_log_capture.capture_generation(path, retained)
    nginx_log_capture.capture_generation(path, retained)
    assert producer_log_history.read_page(path, "nginx-access").lines == ("first", "second")
    assert "synthetic-private-body" not in "\n".join(producer_log_history.read_page(path, "nginx-error").lines)
    assert (retained / "access.log").read_bytes() == b"first\nsecond\n"


def test_sealed_capture_is_bounded_across_many_short_lines(tmp_path):
    """A large generation is appended in bounded batches without dropping records.

    Args:
        tmp_path: Test-owned sealed generation and producer store.
    """
    logs, retained = tmp_path / "logs", tmp_path / "generation"
    logs.mkdir()
    retained.mkdir(mode=0o700)
    for name in nginx_log_sealing.LOG_NAMES:
        (logs / name).write_bytes(b"short line\n" * 1001)
    nginx_log_sealing.seal_generation(logs, retained, reopen=lambda: None, writers_closed=lambda _: True)
    path = tmp_path / "history.sqlite"
    producer_log_history.initialize(path)
    for source in ("nginx-access", "nginx-error"):
        producer_log_history.import_legacy(path, source, [])
    nginx_log_capture.capture_generation(path, retained)
    assert producer_log_history.read_page(path, "nginx-access").through == 1001
    assert producer_log_history.read_page(path, "nginx-error").through == 1001


def test_nginx_descriptor_proof_rejects_old_handles_and_membership_changes(tmp_path, monkeypatch):
    """A stable full process inventory and absence of old inodes are both required.

    Args:
        tmp_path: Test-owned model of fixed procfs and cgroup paths.
        monkeypatch: Bind only the module's kernel paths to the owned fixture.
    """
    cgroup = tmp_path / "sys/fs/cgroup/system.slice/nginx.service"
    cgroup.mkdir(parents=True)
    fd_root = tmp_path / "proc/123/fd"
    fd_root.mkdir(parents=True)
    descriptor = fd_root / "4"
    descriptor.write_bytes(b"active log")
    identity = descriptor.stat().st_dev, descriptor.stat().st_ino
    monkeypatch.setattr(nginx_log_sealing, "Path", lambda value: tmp_path / value.lstrip("/"))
    monkeypatch.setattr(nginx_log_sealing, "_processes", lambda _: {123: "start-ticks"})
    assert not nginx_log_sealing.nginx_writers_closed({identity})
    assert nginx_log_sealing.nginx_writers_closed({(0, 0)})
    observations = iter(({123: "start-ticks"}, {123: "different-start-ticks"}))
    monkeypatch.setattr(nginx_log_sealing, "_processes", lambda _: next(observations))
    assert not nginx_log_sealing.nginx_writers_closed({(0, 0)})
    monkeypatch.setattr(nginx_log_sealing, "_processes", lambda _: {})
    assert not nginx_log_sealing.nginx_writers_closed({(0, 0)})


def test_nginx_descriptor_permission_failure_never_proves_closure(monkeypatch, tmp_path):
    """An unreadable service inventory fails closed instead of sealing input.

    Args:
        monkeypatch: Inject unavailable process identity evidence.
        tmp_path: Test-owned cgroup directory.
    """
    def unavailable(_):
        """Reject the inaccessible synthetic process inventory.

        Args:
            _: Fixed cgroup path passed by the production proof.
        """
        raise PermissionError("synthetic procfs permission denied")

    monkeypatch.setattr(nginx_log_sealing, "Path", lambda _: tmp_path)
    monkeypatch.setattr(nginx_log_sealing, "_processes", unavailable)
    with pytest.raises(PermissionError):
        nginx_log_sealing.nginx_writers_closed({(0, 0)})


def test_fixed_producer_tail_wire_budget_keeps_newest_rows(tmp_path, monkeypatch):
    """Escaped control text remains bounded without dropping the newest tail edge.

    Args:
        tmp_path: Test-owned fixed producer store.
        monkeypatch: Bind the fixed external source to its owned fixture.
    """
    path = tmp_path / "nginx.sqlite"
    producer_log_history.initialize(path)
    producer_log_history.import_legacy(path, "nginx-access", [])
    producer_log_history.append(path, "nginx-access", [f"{index}" + "\0" * 50000 for index in range(5)],
                                writer="service", revision=1)
    boundary = producer_log_history.read_page(path, "nginx-access")
    producer_log_history.activate_source(path, "nginx-access", generation=boundary.generation, through=boundary.through)
    monkeypatch.setitem(external_log_reader.STORE_PATHS, "nginx-access", path)
    result = external_log_reader.producer_page("nginx-access", {"transport": "producer", "tail": True})
    assert len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= external_log_reader.MAX_RESPONSE_BYTES
    assert result["after"] == 5
    assert result["start"] > 0
    assert result["lines"][-1].startswith("4")


def test_selected_external_store_loss_does_not_fall_back_to_incomplete_raw_files(tmp_path, monkeypatch):
    """Installed capture failure cannot masquerade as a never-migrated source.

    Args:
        tmp_path: Test-owned selected store and activation marker.
        monkeypatch: Bind fixed source paths to owned fixtures.
    """
    marker = tmp_path / "nginx-state.json"
    marker.write_text('{"phase":"active"}', encoding="utf-8")
    monkeypatch.setitem(external_log_reader.STORE_PATHS, "nginx-access", tmp_path / "missing.sqlite")
    monkeypatch.setitem(external_log_reader.ACTIVATION_PATHS, "nginx-access", marker)
    with pytest.raises(ValueError, match="unavailable"):
        external_log_reader.producer_page("nginx-access", {"transport": "producer"})


def test_nginx_closing_client_sockets_do_not_prevent_log_descriptor_proof(tmp_path, monkeypatch):
    """Normal traffic descriptor churn must not stall the sealed log frontier.

    Args:
        tmp_path: Test-owned fixed cgroup and procfs model.
        monkeypatch: Inject a client socket disappearing during descriptor scanning.
    """
    cgroup = tmp_path / "sys/fs/cgroup/system.slice/nginx.service"
    cgroup.mkdir(parents=True)
    descriptors = tmp_path / "proc/123/fd"
    descriptors.mkdir(parents=True)
    original_iterdir = Path.iterdir

    def vanished():
        """Model a client socket that closed after directory enumeration."""
        raise FileNotFoundError("synthetic completed request")

    def iterdir(path):
        """Enumerate one vanished client socket in the owned procfs fixture.

        Args:
            path: Directory requested by the descriptor proof.
        """
        return iter([SimpleNamespace(stat=vanished)]) if path == descriptors else original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    monkeypatch.setattr(nginx_log_sealing, "Path", lambda value: tmp_path / value.lstrip("/"))
    monkeypatch.setattr(nginx_log_sealing, "_processes", lambda _: {123: "stable-worker"})
    assert nginx_log_sealing.nginx_writers_closed({(0, 0)})


def test_nginx_seal_recovers_interrupted_initial_manifest_write(tmp_path):
    """A crash before the first rename retries only its owned partial manifest.

    Args:
        tmp_path: Test-owned current logs and private generation directory.
    """
    logs, retained = tmp_path / "logs", tmp_path / "generation"
    logs.mkdir()
    retained.mkdir(mode=0o700)
    for name in nginx_log_sealing.LOG_NAMES:
        (logs / name).write_bytes(b"still current\n")
    (retained / "manifest.pending").write_bytes(b'{"schema":')
    result = nginx_log_sealing.seal_generation(logs, retained, reopen=lambda: None, writers_closed=lambda _: True)
    assert result["state"] == "sealed"
    assert (retained / "access.log").read_bytes() == b"still current\n"


@pytest.mark.parametrize("terminated", [False, True])
def test_oversized_nginx_capture_streams_markers_and_recovers_lost_ack(tmp_path, monkeypatch, terminated):
    """Oversized input preserves raw history, parser continuity and retry receipts.

    Args:
        tmp_path: Owned sealed generation and producer store.
        monkeypatch: Inject a lost oversized-record acknowledgment and observe chunks.
        terminated: Whether the final oversized record has its physical newline.
    """
    logs, retained = tmp_path / "logs", tmp_path / "generation"
    logs.mkdir()
    retained.mkdir(mode=0o700)
    # Split BEGIN and END over streaming chunk boundaries; the footer in the
    # second oversized record must release the following ordinary record.
    first = b"x" * (65536 - 8) + b"-----BEGIN PRIVATE KEY-----" + b"s" * 150000 + b"\n"
    closing = b"s" * (65536 - 6) + b"-----END PRIVATE KEY-----" + b"x" * 150000 + b"\n"
    raw = b"before\n" + first + b"hidden-body\n" + closing + b"visible-after\n" + b"z" * 180000
    raw += b"\n" if terminated else b""
    (logs / "access.log").write_bytes(raw)
    (logs / "error.log").write_bytes(b"error ordinary\n")
    nginx_log_sealing.seal_generation(logs, retained, reopen=lambda: None, writers_closed=lambda _: True)
    path = tmp_path / "history.sqlite"
    producer_log_history.initialize(path)
    for source in ("nginx-access", "nginx-error"):
        producer_log_history.import_legacy(path, source, [])
    original = nginx_log_capture._checkpoint
    failed = False

    def interrupted(directory, state):
        """Lose only the first oversized record's committed offset publication.

        Args:
            directory: Owned sealed generation directory.
            state: Collector's pending or acknowledged offsets.
        """
        nonlocal failed
        entry = state["files"]["access.log"]
        if not failed and entry["pending"] is None and entry["offset"] == len(b"before\n") + len(first):
            failed = True
            raise OSError("synthetic oversized acknowledgment lost")
        original(directory, state)

    original_chunks = nginx_log_capture._record_chunks
    sizes = []

    def chunks(stream, end):
        """Observe the actual store transport's maximum allocation.

        Args:
            stream: Authenticated sealed input.
            end: Fixed exclusive physical-record boundary.
        """
        for chunk in original_chunks(stream, end):
            sizes.append(len(chunk))
            yield chunk

    monkeypatch.setattr(nginx_log_capture, "_record_chunks", chunks)
    monkeypatch.setattr(nginx_log_capture, "_checkpoint", interrupted)
    with pytest.raises(OSError, match="acknowledgment lost"):
        nginx_log_capture.capture_generation(path, retained)
    nginx_log_capture.capture_generation(path, retained)
    nginx_log_capture.capture_generation(path, retained)
    page = producer_log_history.read_page(path, "nginx-access")
    assert len(page.lines) == 6
    assert page.lines[0] == "before"
    assert all("Oversized log entry omitted" in page.lines[index] for index in (1, 3, 5))
    assert page.lines[2] == "[redacted private key]"
    assert page.lines[4] == "visible-after"
    assert max(sizes) == 65536
    assert (retained / "access.log").read_bytes() == raw
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT byte_end FROM producer WHERE source='nginx-access'").fetchone()[0] == len(raw)


def test_streamed_receipt_rejects_changed_retry_and_rolls_back_bad_boundaries(tmp_path):
    """Stream receipts bind all raw bytes and malformed input cannot commit state.

    Args:
        tmp_path: Owned producer store.
    """
    path = tmp_path / "history.sqlite"
    producer_log_history.initialize(path)
    producer_log_history.import_legacy(path, "nginx-access", [])
    chunks = [b"x" * 65536, b"first\n"]
    assert producer_log_history.append_stream(path, "nginx-access", iter(chunks), writer="service", revision=1) == 1
    with pytest.raises(ValueError, match="receipt"):
        producer_log_history.append_stream(path, "nginx-access", [chunks[0], b"other\n"], writer="service", revision=1)
    for invalid in ([b"-----BEGIN PRIVATE KEY-----\n", b"second"], [b"one\ntwo\n"], [b"x" * 65537]):
        with pytest.raises(ValueError, match="physical"):
            producer_log_history.append_stream(path, "nginx-access", invalid, writer="service", revision=2)
    producer_log_history.append(path, "nginx-access", ["visible"], writer="service", revision=2)
    assert producer_log_history.read_page(path, "nginx-access").lines[-1] == "visible"


def test_external_commands_do_not_load_application_database_in_clean_readonly_cwd(tmp_path):
    """Standalone history commands need only their explicitly selected stores.

    Args:
        tmp_path: Owned unrelated working directory and producer storage.
    """
    working = tmp_path / "readonly-working"
    working.mkdir()
    store = tmp_path / "history.sqlite"
    producer_log_history.initialize(store)
    producer_log_history.import_legacy(store, "nginx-access", [])
    producer_log_history.append(store, "nginx-access", ["standalone row"])
    boundary = producer_log_history.read_page(store, "nginx-access")
    producer_log_history.activate_source(store, "nginx-access", generation=boundary.generation, through=1)
    # An audit-enforced read-only working directory is portable to Windows,
    # where chmod does not deny mkdir. The child receives no Atlaso settings.
    script = '''
import importlib
import os
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
working = Path.cwd()
def readonly(event, arguments):
    if event in {"os.mkdir", "os.remove", "os.rmdir", "os.rename"}:
        if Path(arguments[0]).resolve().is_relative_to(working):
            raise PermissionError("standalone working directory is read-only")
    if event == "open" and isinstance(arguments[0], (str, bytes, os.PathLike)):
        if Path(os.fsdecode(arguments[0])).resolve().is_relative_to(working):
            mode, flags = arguments[1], arguments[2]
            if (mode and any(value in mode for value in "wax+")) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
                raise PermissionError("standalone working directory is read-only")
sys.addaudithook(readonly)
collector = importlib.import_module("atlaso.app.services.external_history_lifecycle")
reader = importlib.import_module("atlaso.app.services.external_log_reader")
reader.STORE_PATHS["nginx-access"] = Path(sys.argv[2])
assert reader.main(["nginx-access", '{"transport":"producer"}']) == 0
for forbidden in ("atlaso.app.config", "atlaso.app.models", "atlaso.app.database", "sqlalchemy"):
    assert forbidden not in sys.modules, forbidden
assert not list(working.iterdir())
'''
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script,
                             str(Path(__file__).resolve().parents[1]), str(store)],
                            cwd=working, env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["lines"] == ["standalone row"]
    assert not list(working.iterdir())
