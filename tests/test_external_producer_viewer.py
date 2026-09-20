"""Exercise application signing around fixed privileged producer pages."""

import json

import pytest

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.services import external_log_reader, log_viewer, producer_log_history


@pytest.mark.parametrize("source", ["kms", "nginx-access", "nginx-error"])
def test_external_source_signs_stable_pages_and_live_continuation(tmp_path, monkeypatch, source):
    """Keep fixed accepted pages while privileged producers append new rows.

    Args:
        tmp_path: Private test-owned storage directory.
        monkeypatch: Scoped fixed-helper transport replacement.
        source: Authorized external source under test.
    """
    path = tmp_path / "history.sqlite"
    producer_log_history.initialize(path)
    producer_log_history.import_legacy(path, source, [])
    producer_log_history.append(path, source, ["one", "two", "three"])
    page = producer_log_history.read_page(path, source)
    producer_log_history.activate_source(path, source, generation=page.generation, through=page.through)
    monkeypatch.setitem(external_log_reader.STORE_PATHS, source, path)

    def read(self, selected, position):
        """Use the real fixed reader behind the simulated helper process boundary.

        Args:
            selected: Fixed requested source.
            position: Verified source position sent by the application.
        """
        response = external_log_reader.producer_page(selected, {**position, "transport": "producer"})
        return AdapterResult([], False, stdout=json.dumps(response))

    monkeypatch.setattr(SystemAdapter, "read_producer_log", read)
    accepted = log_viewer.source_page(source, limit=2)
    assert accepted["text"] == "one\ntwo"
    producer_log_history.append(path, source, ["four"])
    assert log_viewer.source_page(source, cursor=accepted["cursor"], limit=2)["text"] == "one\ntwo"
    assert log_viewer.source_page(source, cursor=accepted["next_cursor"], limit=2)["text"] == "three\nfour"
    tail = log_viewer.source_page(source, tail=True, limit=2)
    assert tail["text"] == "three\nfour"
    assert log_viewer.source_page(source, cursor=tail["previous_cursor"], limit=2)["text"] == "one\ntwo"
    with pytest.raises(ValueError, match="another source"):
        log_viewer.source_page("app", cursor=accepted["cursor"])


def test_external_producer_does_not_fall_back_after_missing_active_store(monkeypatch):
    """Reject a replaced producer store without interpreting its cursor as file offsets.

    Args:
        monkeypatch: Scoped helper response replacement.
    """
    monkeypatch.setattr(SystemAdapter, "read_producer_log", lambda *args: AdapterResult([], False, stdout='{"active":false}'))
    cursor = log_viewer.encode_cursor("kms", kind="producer", generation="a" * 32, after=0, through=1)
    with pytest.raises(ValueError, match="replaced"):
        log_viewer.source_page("kms", cursor=cursor)


@pytest.mark.parametrize("source", ["app", "kms", "nginx-access", "nginx-error"])
@pytest.mark.parametrize("initial", [[], ["already visible"]])
def test_pinned_tail_signals_new_records_without_replacing_page(tmp_path, monkeypatch, source, initial):
    """Polling a pinned page signals its live continuation even when initially empty.

    Args:
        tmp_path: Private test-owned storage directory.
        monkeypatch: Scoped fixed-helper transport replacement.
        source: Authorized producer source under test.
        initial: Rows present before the browser accepts the tail.
    """
    path = tmp_path / "history.sqlite"
    producer_log_history.initialize(path)
    producer_log_history.import_legacy(path, source, [])
    if initial:
        producer_log_history.append(path, source, initial)
    boundary = producer_log_history.read_page(path, source)
    producer_log_history.activate_source(path, source, generation=boundary.generation, through=boundary.through)
    monkeypatch.setitem(external_log_reader.STORE_PATHS, source, path)

    def read(self, selected, position):
        """Read actual captured rows through the helper transport contract.

        Args:
            selected: Fixed requested source.
            position: Verified source position sent by the application.
        """
        response = external_log_reader.producer_page(selected, {**position, "transport": "producer"})
        return AdapterResult([], False, stdout=json.dumps(response))

    monkeypatch.setattr(SystemAdapter, "read_producer_log", read)

    def page(**options):
        """Select the local App or privileged external viewer path.

        Args:
            **options: Existing signed cursor and tail selection arguments.
        """
        if source == "app":
            return producer_log_history.viewer_page(path, source, **options)
        return log_viewer.source_page(source, **options)

    accepted = page(tail=True)
    assert accepted["has_more"] is False
    producer_log_history.append(path, source, ["new live entry"])
    refreshed = page(cursor=accepted["cursor"])
    assert refreshed["text"] == accepted["text"]
    assert refreshed["cursor"] == accepted["cursor"]
    assert refreshed["has_more"] is True
    continuation = page(cursor=refreshed["next_cursor"])
    assert continuation["text"] == "new live entry"
    assert continuation["has_more"] is False
