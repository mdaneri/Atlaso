"""Require fresh native acquisition failure before claiming negative acceptance."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as fixture  # noqa: E402 - Local interop entrypoint.

BOOT = "a" * 32
FAILURE = "NTPsec initial clock acquisition failed (TimeoutExpired); Apply must roll back."


def test_acquisition_failure_accepts_only_one_new_original_boot_event(monkeypatch):
    """The failure proof excludes old journal lines and all arbitrary native text."""
    rows = [
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "10", "MESSAGE": FAILURE},
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "21", "MESSAGE": FAILURE},
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "22", "MESSAGE": "private arbitrary native text"},
    ]
    monkeypatch.setattr(fixture, "sudo_read", lambda *_: b"\n".join(json.dumps(row).encode() for row in rows))
    result = fixture.acquisition_failure(object(), "private-password", {"boot": BOOT, "monotonic": 20})
    assert result == {"initializer_failed": True, "reason": "TimeoutExpired", "after_original_checkpoint": True}
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("events", [[], [0], [2], [1, 1]], ids=["missing", "old", "other-boot", "multiple"])
def test_acquisition_failure_refuses_missing_old_or_ambiguous_events(monkeypatch, events):
    """A failed master task alone cannot establish that NTP caused its failure."""
    choices = [
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "10", "MESSAGE": FAILURE},
        {"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "21", "MESSAGE": FAILURE},
        {"_BOOT_ID": "b" * 32, "__MONOTONIC_TIMESTAMP": "21", "MESSAGE": FAILURE},
    ]
    monkeypatch.setattr(fixture, "sudo_read", lambda *_: b"\n".join(json.dumps(choices[i]).encode() for i in events))
    with pytest.raises(fixture.Refusal, match="negative_acquisition_failure_unproven"):
        fixture.acquisition_failure(object(), "private-password", {"boot": BOOT, "monotonic": 20})


def test_acquisition_observes_real_step_and_slew_without_treating_them_as_health(monkeypatch):
    """Only source-defined fixed native messages become bounded observations."""
    messages = ["CLOCK: time set +2.745000 s", "CLOCK: time slew -0.002100 s", "private native data"]
    rows = [{"_BOOT_ID": BOOT, "__MONOTONIC_TIMESTAMP": "21", "MESSAGE": value} for value in messages]
    monkeypatch.setattr(fixture, "sudo_read", lambda *_: b"\n".join(json.dumps(row).encode() for row in rows))
    result = fixture.acquisition_observation(object(), "private-password", {"boot": BOOT, "monotonic": 20})
    assert result == {"native_events": [{"kind": "step", "seconds": 2.745}, {"kind": "slew", "seconds": -0.0021}],
                      "real_clock_step_observed": True}
    assert "healthy" not in result and "private" not in json.dumps(result)
