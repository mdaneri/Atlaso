"""Filter oversized native journal data before the bounded SSH readback."""

import contextlib
import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as fixture  # noqa: E402 - Native evidence consumer.

BOOT = "a" * 32
MARKER = "NTPsec initial clock acquisition failed (TimeoutExpired); Apply must roll back."


@pytest.fixture
def journal(monkeypatch):
    """Execute the actual guest filter with only journalctl and SSH replaced.

    Args:
        monkeypatch: Installs local journal and protected transport stand-ins.
    """
    rows = [{"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": str(101 + i), "MESSAGE": "ordinary startup",
             "UNRELATED_METADATA": "private-journal-canary" * 60} for i in range(100)]
    rows[50]["MESSAGE"] = MARKER
    state = SimpleNamespace(rows=rows, returncode=0, output=b"", calls=0,
                            before={"boot": BOOT, "monotonic": 100, "cursor": "original-cursor"})

    def query(args, **kwargs):
        """Supply complete native JSON records without starting journalctl.

        Args:
            args: Exact bounded post-cursor query arguments.
            **kwargs: Existing subprocess output and timeout controls.
        """
        if state.before["cursor"] is None:
            assert "_BOOT_ID=" + BOOT in args and not any(arg.startswith("--after-cursor=") for arg in args)
        else:
            assert args[-1] == "--after-cursor=original-cursor"
        assert args[args.index("-n") + 1] == "257" and kwargs["timeout"] == 8
        data = b"\n".join(json.dumps(row).encode() for row in state.rows)
        return SimpleNamespace(returncode=state.returncode, stdout=data)

    def read(_session, program, _password):
        """Run the actual reviewed guest program and enforce the original wire cap.

        Args:
            _session: Unused pinned-session stand-in.
            program: Source encoded by the real guest-command boundary.
            _password: Synthetic credential deliberately unused by this stand-in.
        """
        state.calls += 1
        stream = io.StringIO()
        try:
            with contextlib.redirect_stdout(stream):
                exec(program, {})
        except (AssertionError, ValueError, TypeError):
            raise fixture.Refusal("bootstrap_guest_readback_failed") from None
        state.output = stream.getvalue().encode()
        assert len(state.output) <= 65536
        return state.output

    monkeypatch.setattr(subprocess, "run", query)
    monkeypatch.setattr(fixture, "guest_python_command", lambda program: program)
    monkeypatch.setattr(fixture, "sudo_read", read)
    return state


def test_large_native_journal_produces_only_fixed_post_checkpoint_failure(journal):
    """The observed oversized metadata no longer crosses SSH or weakens proof.

    Args:
        journal: Actual guest filter with oversized synthetic native metadata.
    """
    result = fixture.acquisition_failure(None, "synthetic", journal.before)
    assert result["initializer_failed"] and result["reason"] == "TimeoutExpired"
    assert result["journal_records"] == 100 and result["journal_bytes_filtered_in_guest"] > 65536
    assert len(journal.output) < 1024 and b"private-journal-canary" not in journal.output


@pytest.mark.parametrize("mutation", ["old-time", "wrong-boot", "prefix", "duplicate", "missing", "truncated", "oversized", "command-failed"])
def test_no_stale_approximate_duplicate_or_partial_failure_can_pass(journal, mutation):
    """Exactly one complete native marker after the original checkpoint remains mandatory.

    Args:
        journal: Synthetic original native journal source.
        mutation: Evidence invalidation or resource limit to exercise.
    """
    marker = journal.rows[50]
    if mutation == "old-time":
        marker["__MONOTONIC_TIMESTAMP"] = "100"
    elif mutation == "wrong-boot":
        marker["_BOOT_ID"] = "b" * 32
    elif mutation == "prefix":
        marker["MESSAGE"] = "untrusted prefix " + MARKER
    elif mutation == "duplicate":
        journal.rows[51]["MESSAGE"] = MARKER
    elif mutation == "missing":
        marker["MESSAGE"] = "no initializer failure"
    elif mutation == "truncated":
        journal.rows.extend(dict(journal.rows[0]) for _ in range(157))
    elif mutation == "oversized":
        journal.rows[0]["UNRELATED_METADATA"] = "x" * (2 * 1024**2)
    else:
        journal.returncode = 1
    with pytest.raises(fixture.Refusal):
        fixture.acquisition_failure(None, "synthetic", journal.before)


@pytest.mark.parametrize("cursor", [None, "", "bad\nvalue", "bad\x00value", "x" * 2049])
def test_missing_or_unsafe_original_cursor_stops_before_guest_read(journal, cursor):
    """An original cursor is required; no broader journal fallback is admitted.

    Args:
        journal: Pinned transport stand-in recording guest reads.
        cursor: Invalid original checkpoint cursor.
    """
    journal.before["cursor"] = cursor
    with pytest.raises(fixture.Refusal, match="negative_checkpoint_missing"):
        fixture.acquisition_failure(None, "synthetic", journal.before)
    assert journal.calls == 0


@pytest.mark.parametrize("cursor", [None, "original-cursor"])
def test_cold_observations_filter_oversized_metadata_in_guest(journal, cursor):
    """Both an empty original journal and a recorded cursor keep raw metadata off SSH.

    Args:
        journal: Actual guest program and bounded SSH boundary.
        cursor: Empty-journal fallback or original post-cursor selector.
    """
    journal.before["cursor"] = cursor
    journal.rows[50]["MESSAGE"] = "CLOCK: time set +1.553679 s"
    result = fixture.acquisition_observation(None, "synthetic", journal.before)
    assert result["native_events"] == [{"kind": "step", "seconds": 1.553679}]
    assert result["real_clock_step_observed"] and result["journal_bytes_filtered_in_guest"] > 65536
    assert len(journal.output) < 1024 and b"private-journal-canary" not in journal.output


@pytest.mark.parametrize("mutation", ["old-time", "wrong-boot", "prefix", "out-of-range", "too-many", "truncated", "oversized", "command-failed"])
def test_cold_observations_reject_unsafe_or_incomplete_evidence(journal, mutation):
    """Only bounded exact fresh native events become observations.

    Args:
        journal: Actual cold observation filter with synthetic journal records.
        mutation: Stale, malformed or excessive evidence to exercise.
    """
    marker = journal.rows[50]
    marker["MESSAGE"] = "CLOCK: time set +1.553679 s"
    if mutation == "old-time":
        marker["__MONOTONIC_TIMESTAMP"] = "100"
    elif mutation == "wrong-boot":
        marker["_BOOT_ID"] = "b" * 32
    elif mutation == "prefix":
        marker["MESSAGE"] = "prefix " + marker["MESSAGE"]
    elif mutation == "out-of-range":
        marker["MESSAGE"] = "CLOCK: time set +86401.0 s"
    elif mutation == "too-many":
        for row in journal.rows[51:55]:
            row["MESSAGE"] = marker["MESSAGE"]
    elif mutation == "truncated":
        journal.rows.extend(dict(journal.rows[0]) for _ in range(157))
    elif mutation == "oversized":
        marker["UNRELATED_METADATA"] = "x" * (2 * 1024**2)
    else:
        journal.returncode = 1
    if mutation in {"old-time", "wrong-boot", "prefix"}:
        result = fixture.acquisition_observation(None, "synthetic", journal.before)
        assert result["native_events"] == [] and not result["real_clock_step_observed"]
    else:
        with pytest.raises(fixture.Refusal):
            fixture.acquisition_observation(None, "synthetic", journal.before)
