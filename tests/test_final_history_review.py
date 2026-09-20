"""Verify final selected-source routing and bounded response contracts."""

import json
import sqlite3

import pytest

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.services import (
    external_history_lifecycle,
    external_log_reader,
    log_viewer,
)
from atlaso.app.services import producer_log_history as history


def test_app_availability_uses_selected_history_without_legacy_mirror(tmp_path, monkeypatch):
    """Retained producer rows keep the App tab available without its raw mirror.

    Args:
        tmp_path: Owned private storage root.
        monkeypatch: Scoped App settings and metadata transport.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    history.import_legacy(path, "app", [])
    history.append(path, "app", ["retained producer event"])
    boundary = history.read_page(path, "app")
    history.activate_source(path, "app", generation=boundary.generation, through=boundary.through)
    settings = get_settings().model_copy(update={"app_log_path": tmp_path / "missing.log",
                                                 "app_log_history_path": path})
    monkeypatch.setattr(log_viewer, "get_settings", lambda: settings)
    monkeypatch.setattr(SystemAdapter, "read_log_history",
                        lambda *args: AdapterResult([], False, stdout='{"sources":[]}'))
    assert log_viewer.source_page("app")["text"] == "retained producer event"
    availability = {row["id"]: row["available"] for row in log_viewer.source_availability()["sources"]}
    assert availability["app"] is True


def test_app_producer_page_bounds_json_escaping_and_keeps_all_rows(tmp_path):
    """Bound the actual App viewer response, including escaped control characters.

    Args:
        tmp_path: Owned private storage root.
    """
    path = tmp_path / "history.sqlite"
    history.initialize(path)
    lines = [f"row {index}:" + "\0" * 50000 for index in range(5)]
    history.append(path, "app", lines)
    actual = []
    cursor = ""
    for _ in range(5):
        page = history.viewer_page(path, "app", cursor=cursor)
        assert len(json.dumps(page, ensure_ascii=False).encode("utf-8")) <= log_viewer.PAGE_BYTES
        actual.extend(page["text"].splitlines())
        if not page["has_more"]:
            break
        cursor = page["next_cursor"]
    else:
        raise AssertionError("App producer page did not advance within the bounded test calls")
    assert actual == lines


def test_external_page_budget_includes_application_signed_cursors(tmp_path, monkeypatch):
    """Reserve bytes for signed application metadata beyond the helper payload.

    Args:
        tmp_path: Owned private storage root.
        monkeypatch: Scoped fixed-store and helper transport replacements.
    """
    source = "nginx-access"
    path = tmp_path / "nginx.sqlite"
    history.initialize(path)
    history.import_legacy(path, source, [])
    generation = history.read_page(path, source).generation
    lines = ["x" * 65536] * 15 + [""]
    raw = {"active": True, "generation": generation, "through": 16, "start": 0,
           "after": 16, "lines": lines, "more": False, "oldest": 1}
    lines[-1] = "z" * (external_log_reader.MAX_RESPONSE_BYTES - 50
                       - len(json.dumps(raw, ensure_ascii=False).encode("utf-8")))
    history.append(path, source, lines)
    history.activate_source(path, source, generation=generation, through=16)
    monkeypatch.setitem(external_log_reader.STORE_PATHS, source, path)

    def read(self, selected, position):
        """Return the real reader response through the simulated helper boundary.

        Args:
            selected: Authorized fixed source.
            position: Verified cursor contents.
        """
        response = external_log_reader.producer_page(selected, {**position, "transport": "producer"})
        return AdapterResult([], False, stdout=json.dumps(response, ensure_ascii=False) + "\n")

    monkeypatch.setattr(SystemAdapter, "read_producer_log", read)
    page = log_viewer.source_page(source)
    assert len(json.dumps(page, ensure_ascii=False).encode("utf-8")) <= log_viewer.PAGE_BYTES


def test_existing_kms_capture_rejects_interrupted_formatter_state(tmp_path, monkeypatch):
    """Do not report successful KMS cutover while all future capture is blocked.

    Args:
        tmp_path: Owned private storage root.
        monkeypatch: Scoped lifecycle paths and service-state inspection.
    """
    path = tmp_path / "history.sqlite"
    environment = tmp_path / "history.env"
    history.initialize(path)
    history.import_legacy(path, "kms", [])
    boundary = history.read_page(path, "kms")
    history.activate_source(path, "kms", generation=boundary.generation, through=0)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO capture_pending VALUES ('kms','service',1,NULL)")
    environment.write_text(f"ATLASO_KMS_LOG_HISTORY_PATH={path}\n", encoding="utf-8")
    (tmp_path / "kms-state.json").write_text(
        '{"schema":1,"phase":"complete","previous_active":true}', encoding="utf-8")
    monkeypatch.setattr(external_history_lifecycle, "ROOT", tmp_path)
    monkeypatch.setattr(external_history_lifecycle, "KMS_STORE", path)
    monkeypatch.setattr(external_history_lifecycle, "KMS_ENVIRONMENT", environment)

    def systemctl(*arguments):
        """Return an active KMS service with its required environment hook.

        Args:
            *arguments: Lifecycle-owned service inspection arguments.
        """
        if "--property=EnvironmentFiles" in arguments:
            return f"{environment} (ignore_errors=yes)"
        assert arguments[0] == "show"
        return "LoadState=loaded\nActiveState=active\n"

    monkeypatch.setattr(external_history_lifecycle, "_systemctl", systemctl)
    with pytest.raises(ValueError):
        external_history_lifecycle.prepare_kms(resume=True)
