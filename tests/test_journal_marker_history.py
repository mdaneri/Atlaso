"""Verify finite journal marker state across records and preparation windows."""

import io
import json
from collections import OrderedDict
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from atlaso.app.services import log_viewer
from tests.test_appliance_helper import load_helper_module


@pytest.fixture
def journal_transport(monkeypatch, capsys):
    """Provide command-capped journal records through the actual helper and adapter.

    Args:
        monkeypatch: Replace only process transport and reset task-local test caches.
        capsys: Capture each helper response before source cursor encoding.
    """
    helper = load_helper_module()
    records, requests = [], []
    monkeypatch.setattr(log_viewer, "_JOURNAL_PREPARATION", OrderedDict())

    def launch(command, **_options):
        """Honor cursor inclusivity, direction, and journal count semantics.

        Args:
            command: Fixed journal invocation from the production helper.
            **_options: Process options unused by the in-memory transport.
        """
        rows = list(records)
        reverse = "--reverse" in command
        for argument in command:
            if argument.startswith(("--cursor=", "--after-cursor=")):
                boundary = int(argument.split("=", 1)[1])
                inclusive = argument.startswith("--cursor=")
                rows = [row for row in rows if (int(row["__CURSOR"]) <= boundary if reverse and inclusive else
                        int(row["__CURSOR"]) < boundary if reverse else
                        int(row["__CURSOR"]) >= boundary if inclusive else int(row["__CURSOR"]) > boundary)]
        if reverse:
            rows.reverse()
        count = int(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--lines=")))
        rows = rows[:count]
        process = MagicMock()
        process.__enter__.return_value = process
        process.wait.return_value = process.poll.return_value = 0
        process.stdout = io.BytesIO("".join(json.dumps(row) + "\n" for row in rows).encode())
        process.stderr = io.BytesIO()
        return process

    def adapter(_self, source, position):
        """Pass real bounded helper output to the browser-facing source reader.

        Args:
            _self: Adapter instance.
            source: Allowlisted journal source.
            position: Signed or cached preparation position.
        """
        requests.append(dict(position))
        assert helper._read_log_history([source, json.dumps(position)]) == 0
        payload = capsys.readouterr().out
        assert len(payload.encode()) <= 1024 * 1024
        return SimpleNamespace(returncode=0, stdout=payload)

    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    monkeypatch.setattr(log_viewer.SystemAdapter, "read_log_history", adapter)
    return records, requests


def _records(messages):
    """Build immutable records with headers excluded from the classified view.

    Args:
        messages: Ordered producer fragments.
    """
    return [{"MESSAGE": message, "__CURSOR": str(index), "__REALTIME_TIMESTAMP": "1000000",
             "SYSLOG_IDENTIFIER": "dnsmasq-dhcp" if message in {"private-body", "visible"} else "dnsmasq"}
            for index, message in enumerate(messages)]


@pytest.mark.parametrize("source", ["nginx", "dnsmasq-dhcp"])
@pytest.mark.parametrize("tail", [False, True])
@pytest.mark.parametrize("limit", [1, 500])
def test_split_header_and_footer_survive_journal_navigation(journal_transport, source, tail, limit):
    """Split markers protect bodies in forward, backward, and filtered views.

    Args:
        journal_transport: Real reader with an immutable fake journal process.
        source: Classified or unclassified source.
        tail: Walk from the tail using Previous instead of forward pages.
        limit: Selected page size, including boundaries between every record.
    """
    records, _ = journal_transport
    records.extend(_records(["-----BEG", "IN " + "R" * 70000 + " PRIVATE KE", "Y-----", "private-body", "-----E", "ND PRIVATE KEY-----", "visible"]))
    cursor, texts = "", []
    for _ in range(30):
        page = log_viewer.source_page(source, cursor=cursor, tail=tail and not cursor, limit=limit)
        if page.get("pending"):
            continue
        texts.append(page["text"])
        assert "private-body" not in page["text"]
        state = log_viewer.decode_cursor(page["next_cursor"], source)
        assert len(state.get("journal_pem_state", "")) <= 16
        if tail:
            if not page["previous_cursor"]:
                break
            cursor = page["previous_cursor"]
        else:
            if not page["has_more"]:
                break
            cursor = page["next_cursor"]
    else:
        raise AssertionError("Journal navigation did not finish")
    assert "visible" in "\n".join(texts)
    assert "[redacted private key]" in "\n".join(texts)


@pytest.mark.parametrize("source", ["nginx", "dnsmasq-dhcp"])
def test_tail_preparation_resumes_without_retaining_log_contents(journal_transport, source):
    """A context scan larger than one raw window advances on the next request.

    Args:
        journal_transport: Real reader with enough immutable records for two scan windows.
        source: Classified or unclassified context preparation.
    """
    records, requests = journal_transport
    records.extend(_records(["-----BEG", "IN PRIVATE KEY-----"] + ["private-body"] * 50000 + ["-----END PRIVATE KEY-----", "visible"]))
    first = log_viewer.source_page(source, tail=True)
    assert first["pending"] and first["text"] == ""
    assert len(log_viewer._JOURNAL_PREPARATION) == 1
    assert "private-body" not in json.dumps(list(log_viewer._JOURNAL_PREPARATION.values()))
    second = log_viewer.source_page(source, tail=True)
    assert not second.get("pending")
    assert "private-body" not in second["text"]
    assert "visible" in second["text"]
    assert requests[1]["journal_context"]["cursor"] != ""
    assert not log_viewer._JOURNAL_PREPARATION


@pytest.mark.parametrize("tail", [False, True])
@pytest.mark.parametrize("oversized_first", [False, True])
def test_oversized_record_retains_split_marker_edges(journal_transport, tail, oversized_first):
    """Omission retains partial headers on either side of a record boundary.

    Args:
        journal_transport: Real bounded helper transport.
        tail: Recover marker context from a tail page.
        oversized_first: Put the large body before the partial start rather than within its label.
    """
    records, _ = journal_transport
    fragments = (["x" * 1100000 + "-----BEG", "IN PRIVATE KEY-----"] if oversized_first else
                 ["-----BEG", "IN " + "R" * 1100000 + " PRIVATE KEY-----"])
    records.extend(_records(fragments + ["private-body", "-----END PRIVATE KEY-----", "visible"]))
    cursor, texts = "", []
    for _ in range(20):
        page = log_viewer.source_page("nginx", cursor=cursor, tail=tail and not cursor, limit=1)
        if page.get("pending"):
            continue
        assert "private-body" not in page["text"]
        texts.append(page["text"])
        next_cursor = page["previous_cursor"] if tail else page["next_cursor"] if page["has_more"] else ""
        if not next_cursor:
            break
        cursor = next_cursor
    else:
        raise AssertionError("Oversized journal history did not finish")
    assert "visible" in "\n".join(texts)


@pytest.mark.parametrize("tail", [False, True])
def test_oversized_closing_fragment_restores_visible_output(journal_transport, tail):
    """An omitted closing fragment ends redaction even with a long split label.

    Args:
        journal_transport: Actual bounded helper transport.
        tail: Traverse from the live tail instead of the beginning.
    """
    records, _ = journal_transport
    records.extend(_records(["-----BEGIN PRIVATE KEY-----", "private-body", "-----E", "ND " + "R" * 1100000 + " PRIVATE KEY-----", "visible"]))
    cursor, texts = "", []
    for _ in range(20):
        page = log_viewer.source_page("nginx", cursor=cursor, tail=tail and not cursor, limit=1)
        if page.get("pending"):
            continue
        assert "private-body" not in page["text"]
        texts.append(page["text"])
        next_cursor = page["previous_cursor"] if tail else page["next_cursor"] if page["has_more"] else ""
        if not next_cursor:
            break
        cursor = next_cursor
    assert "visible" in "\n".join(texts)


def test_live_journal_append_uses_saved_partial_marker(journal_transport):
    """A later request completes a header using the previously signed parser state.

    Args:
        journal_transport: Mutable fixture retaining immutable existing records.
    """
    records, _ = journal_transport
    records.extend(_records(["-----BEG"]))
    first = log_viewer.source_page("nginx")
    records.extend(_records(["-----BEG", "IN PRIVATE KEY-----", "private-body", "-----END PRIVATE KEY-----", "visible"])[1:])
    page = log_viewer.source_page("nginx", cursor=first["next_cursor"])
    assert "private-body" not in page["text"]
    assert "visible" in page["text"]


def test_expired_preparation_cursor_preserves_known_private_context(monkeypatch):
    """Restarting a vacuummed scan cannot forget a previously observed opening key.

    Args:
        monkeypatch: Expire the saved progress cursor while retaining the target record.
    """
    helper = load_helper_module()
    calls = []

    def entries(command, **options):
        """Restart at retained history after the specific saved-cursor failure.

        Args:
            command: Bounded context scan invocation.
            **options: Shared deadline and raw scan budget.
        """
        calls.append((command, options["deadline"]))
        if any(arg == "--after-cursor=retired" for arg in command):
            raise helper._JournalCursorExpired("expired")
        return [{"__CURSOR": "body", "MESSAGE": "private-body"}, {"__CURSOR": "target", "MESSAGE": "later-body"}], False

    monkeypatch.setattr(helper, "_journal_history_entries", entries)
    recovered, checkpoint = helper._journal_marker_context("journalctl", "nginx.service", "target", 0,
        deadline=helper.time.monotonic() + 10, checkpoint={"cursor": "retired", "private": True, "pem_state": "S"})
    assert recovered == (True, b"S") and checkpoint is None
    assert len(calls) == 2 and calls[0][1] == calls[1][1]


def test_concurrent_preparation_does_not_overwrite_newer_checkpoint(monkeypatch):
    """A slower viewer cannot replace context progress another viewer published.

    Args:
        monkeypatch: Supply two controlled concurrent helper completions.
    """
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock

    monkeypatch.setattr(log_viewer, "_JOURNAL_PREPARATION", OrderedDict())
    started, release, lock = Event(), Event(), Lock()
    calls = 0

    def adapter(_self, source, position):
        """Delay the first result until the competing viewer stores its checkpoint.

        Args:
            _self: Adapter instance.
            source: Shared journal source.
            position: Initial tail request loaded before either completion.
        """
        nonlocal calls
        with lock:
            calls += 1
            current = calls
        if current == 1:
            started.set()
            assert release.wait(10)
        payload = {"pending": True, "preparation_position": {"journal_start_cursor": f"target-{current}"}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload))

    monkeypatch.setattr(log_viewer.SystemAdapter, "read_log_history", adapter)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(log_viewer.source_page, "nginx", tail=True)
        try:
            assert started.wait(10)
            second = pool.submit(log_viewer.source_page, "nginx", tail=True)
            assert second.result(timeout=10)["pending"]
        finally:
            release.set()
        assert first.result(timeout=10)["pending"]
    checkpoint, _ = next(iter(log_viewer._JOURNAL_PREPARATION.values()))
    assert checkpoint["journal_start_cursor"] == "target-2"
