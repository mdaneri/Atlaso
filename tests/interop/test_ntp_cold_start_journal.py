"""Require fresh native acquisition failure before claiming negative acceptance."""

import contextlib
import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as fixture  # noqa: E402 - Local interop entrypoint.

BOOT = "a" * 32
FAILURE = "NTPsec initial clock acquisition failed (TimeoutExpired); Apply must roll back."


@pytest.fixture
def guest_journal(monkeypatch):
    """Execute the actual guest filter with a controlled native journal source.

    Args:
        monkeypatch: Replaces only the guest process and pinned SSH boundary.
    """
    state = SimpleNamespace(rows=[], output=b"")
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout=b"\n".join(json.dumps(row).encode() for row in state.rows)))
    monkeypatch.setattr(fixture, "guest_python_command", lambda program: program)

    def read(_session, program, _password):
        """Return only the real filter's bounded aggregate.

        Args:
            _session: Original session stand-in.
            program: Reviewed guest filter source.
            _password: Unused synthetic protected credential.
        """
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            exec(program, {})
        state.output = stream.getvalue().encode()
        assert len(state.output) <= 65536
        return state.output

    monkeypatch.setattr(fixture, "sudo_read", read)
    return state


def test_acquisition_failure_accepts_only_one_new_original_boot_event(guest_journal):
    """The failure proof excludes old journal lines and all arbitrary native text.

    Args:
        guest_journal: Actual guest filtering against synthetic native records.
    """
    rows = [
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "10", "MESSAGE": FAILURE},
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "21", "MESSAGE": FAILURE},
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "22", "MESSAGE": "private arbitrary native text"},
    ]
    guest_journal.rows = rows
    result = fixture.acquisition_failure(object(), "private-password", {"boot": BOOT, "monotonic": 20, "cursor": "original"})
    assert result == {"initializer_failed": True, "reason": "TimeoutExpired", "after_original_checkpoint": True,
                      "journal_records": 3,
                      "journal_bytes_filtered_in_guest": len(b"\n".join(json.dumps(row).encode() for row in rows))}
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("events", [[], [0], [2], [1, 1]], ids=["missing", "old", "other-boot", "multiple"])
def test_acquisition_failure_refuses_missing_old_or_ambiguous_events(guest_journal, events):
    """A failed master task alone cannot establish that NTP caused its failure.

    Args:
        guest_journal: Actual guest filtering against selected native records.
        events: Indices selecting missing, old, foreign-boot, or duplicate rows.
    """
    choices = [
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "10", "MESSAGE": FAILURE},
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "21", "MESSAGE": FAILURE},
        {"_BOOT_ID": "b" * 32, "__MONOTONIC_TIMESTAMP": "21", "MESSAGE": FAILURE},
    ]
    guest_journal.rows = [choices[i] for i in events]
    with pytest.raises(fixture.Refusal, match="negative_acquisition_failure_unproven"):
        fixture.acquisition_failure(object(), "private-password", {"boot": BOOT, "monotonic": 20, "cursor": "original"})


def test_acquisition_observes_real_step_and_slew_without_treating_them_as_health(guest_journal):
    """Only source-defined fixed native messages become bounded observations.

    Args:
        guest_journal: Actual guest filtering against native acquisition records.
    """
    messages = ["CLOCK: time set +2.745000 s", "CLOCK: time slew -0.002100 s", "private native data"]
    rows = [{"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "21", "MESSAGE": value} for value in messages]
    guest_journal.rows = rows
    result = fixture.acquisition_observation(object(), "private-password", {"boot": BOOT, "monotonic": 20})
    assert result == {"native_events": [{"kind": "step", "seconds": 2.745}, {"kind": "slew", "seconds": -0.0021}],
                      "real_clock_step_observed": True, "journal_records": 3,
                      "journal_bytes_filtered_in_guest": len(b"\n".join(json.dumps(row).encode() for row in rows))}
    assert "healthy" not in result and "private" not in json.dumps(result)
