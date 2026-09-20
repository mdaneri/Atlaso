"""Review App migration recovery and the privileged external viewer boundary."""

import json
import sqlite3

import pytest

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.services import app_history_cutover as cutover
from atlaso.app.services import external_log_reader, log_viewer
from atlaso.app.services import producer_log_history as history


class _Controller:
    """Model already-published configuration without starting real services."""

    def __init__(self, selected):
        """Bind the existing store.

        Args:
            selected: Previously published store path.
        """
        self.selected = selected
        self.running = cutover.UNITS
        self.actions = []

    def active_units(self):
        """Return currently running producers."""
        return self.running

    def stop(self):
        """Stop both simulated producers."""
        self.actions.append("stop")
        self.running = ()

    def assert_stopped(self):
        """Prove both simulated producers are stopped."""
        assert not self.running

    def configured_store(self):
        """Return the already-published selection."""
        return self.selected

    def publish(self, path):
        """Reject unexpected replacement of existing selection.

        Args:
            path: Candidate store that must not replace published history.
        """
        pytest.fail(f"Unexpected replacement selection: {path.name}")

    def resume(self, units):
        """Record service restart without touching infrastructure.

        Args:
            units: Previously running producer names.
        """
        self.actions.append("resume")
        self.running = units


def test_invalid_previously_published_capture_stays_stopped(tmp_path):
    """An unfinished published store cannot fall through pre-publication rollback.

    Args:
        tmp_path: Owned private test directory.
    """
    runtime, preserved, logs = (tmp_path / name for name in ("runtime", "preserved", "logs"))
    for directory in (runtime, preserved, logs):
        directory.mkdir()
    store = runtime / "app.sqlite"
    history.initialize(store)
    history.import_legacy(store, "app", [])
    boundary = history.read_page(store, "app")
    history.activate_source(store, "app", generation=boundary.generation, through=boundary.through)
    with sqlite3.connect(store) as db:
        db.execute("INSERT INTO capture_pending VALUES ('app','web',1,NULL)")
    controller = _Controller(store)
    with pytest.raises(ValueError, match="unfinished capture"):
        cutover.run_cutover(logs / "app.log", runtime, preserved, controller)
    assert "resume" not in controller.actions
    assert not controller.running
    assert controller.selected == store


def test_external_wire_limit_reserves_the_process_output_newline(tmp_path, monkeypatch):
    """A maximal valid producer response must survive the helper's printed framing.

    Args:
        tmp_path: Owned private test directory.
        monkeypatch: Scoped fixed-store and helper transport replacements.
    """
    path = tmp_path / "nginx.sqlite"
    source = "nginx-access"
    history.initialize(path)
    history.import_legacy(path, source, [])
    generation = history.read_page(path, source).generation
    lines = ["x" * 65536] * 15 + [""]
    payload = {"active": True, "generation": generation, "through": 16, "start": 0,
               "after": 16, "lines": lines, "more": False, "oldest": 1}
    overhead = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    lines[-1] = "z" * (external_log_reader.MAX_RESPONSE_BYTES - overhead)
    history.append(path, source, lines)
    history.activate_source(path, source, generation=generation, through=16)
    monkeypatch.setitem(external_log_reader.STORE_PATHS, source, path)

    def read(self, selected, position):
        """Mirror exact reader/helper JSON output, including the print terminator.

        Args:
            selected: Application-selected fixed source.
            position: Application-authenticated cursor position.
        """
        response = external_log_reader.producer_page(selected, {**position, "transport": "producer"})
        return AdapterResult([], False, stdout=json.dumps(response, ensure_ascii=False) + "\n")

    monkeypatch.setattr(SystemAdapter, "read_producer_log", read)
    first = log_viewer.source_page(source)
    actual = first["text"].splitlines()
    if first["has_more"]:
        second = log_viewer.source_page(source, cursor=first["next_cursor"])
        actual.extend(second["text"].splitlines())
        assert not second["has_more"]
    assert actual == lines
