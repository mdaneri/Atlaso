"""Verify metadata-only availability for selected producer history."""

import json
import sqlite3

import pytest

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.services import external_log_reader, log_viewer
from atlaso.app.services import producer_log_history as history


def test_unavailable_selected_app_does_not_fall_back_to_legacy(tmp_path, monkeypatch):
    """A missing selected database cannot report its unrelated raw mirror as healthy.

    Args:
        tmp_path: Owned private metadata fixture directory.
        monkeypatch: Scoped settings and fixed-helper replacement.
    """
    legacy = tmp_path / "app.log"
    legacy.write_text("legacy mirror\n", encoding="utf-8")
    settings = get_settings().model_copy(update={"app_log_path": legacy,
                                                 "app_log_history_path": tmp_path / "missing.sqlite"})
    monkeypatch.setattr(log_viewer, "get_settings", lambda: settings)
    monkeypatch.setattr(SystemAdapter, "read_log_history",
                        lambda *args: AdapterResult([], False, stdout='{"sources":[]}'))
    monkeypatch.setattr(SystemAdapter, "read_producer_log",
                        lambda *args: AdapterResult([], False, stdout='{"active":true}'))
    monkeypatch.setattr(log_viewer, "_file_available", lambda path: pytest.fail("Selected sources must not probe mirrors"))
    availability = {row["id"]: row["available"] for row in log_viewer.source_availability()["sources"]}
    assert availability["app"] is False


@pytest.mark.parametrize("source", ["kms", "nginx-access", "nginx-error"])
@pytest.mark.parametrize("state,expected", [("active", True), ("missing-selected", False), ("inactive", True)])
def test_external_availability_follows_activation_without_reading_rows(tmp_path, monkeypatch, source, state, expected):
    """Prefer active metadata, fail closed on missing selection, and retain legacy fallback.

    Args:
        tmp_path: Owned private metadata fixture directory.
        monkeypatch: Scoped fixed store, helper and page-reader replacements.
        source: Fixed external source under test.
        state: Source activation state to simulate.
        expected: Resulting source availability.
    """
    store = tmp_path / "history.sqlite"
    activation = tmp_path / "selected.env"
    monkeypatch.setitem(external_log_reader.STORE_PATHS, source, store)
    monkeypatch.setitem(external_log_reader.ACTIVATION_PATHS, source, activation)
    if state == "active":
        history.initialize(store)
        history.import_legacy(store, source, [])
        boundary = history.read_page(store, source)
        history.activate_source(store, source, generation=boundary.generation, through=0)
    if state != "inactive":
        activation.write_text("selected", encoding="utf-8")
    monkeypatch.setattr(external_log_reader, "read_page", lambda *args, **kwargs: pytest.fail("Metadata read source rows"))
    monkeypatch.setattr(external_log_reader, "read_tail", lambda *args, **kwargs: pytest.fail("Metadata read source tail"))
    monkeypatch.setattr(log_viewer, "_file_available", lambda path: state == "inactive")
    legacy = {"sources": [{"id": source, "available": state != "active"}]}
    monkeypatch.setattr(SystemAdapter, "read_log_history",
                        lambda *args: AdapterResult([], False, stdout=json.dumps(legacy)))

    def metadata(self, selected, position):
        """Use the actual privileged metadata reader without launching a process.

        Args:
            selected: Application-selected fixed source.
            position: Metadata-only request.
        """
        assert position == {"metadata": True}
        if selected != source:
            return AdapterResult([], False, stdout='{"active":false}')
        try:
            response = external_log_reader.producer_page(selected, {**position, "transport": "producer"})
        except (OSError, ValueError, sqlite3.Error):
            return AdapterResult([], False, returncode=1)
        assert set(response) == {"active"}
        return AdapterResult([], False, stdout=json.dumps(response))

    monkeypatch.setattr(SystemAdapter, "read_producer_log", metadata)
    availability = {row["id"]: row["available"] for row in log_viewer.source_availability()["sources"]}
    assert availability[source] is expected


@pytest.mark.parametrize("position", [
    {"metadata": 1}, {"metadata": "true"}, {"metadata": True, "after": 0},
])
def test_external_metadata_rejects_non_metadata_inputs(position):
    """A metadata probe cannot accidentally request a row cursor or alternate path.

    Args:
        position: Invalid metadata request contents.
    """
    with pytest.raises(ValueError, match="metadata"):
        external_log_reader.producer_page("kms", {"transport": "producer", **position})
