"""Exercise the private capture exchange using only memory and synthetic clocks."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import struct
import subprocess
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from scripts.interop.certificate_dual_stack_capture_frames import (
    HEADER_BYTES,
    CaptureBinding,
    CaptureChildFrames,
    CaptureControllerFrames,
    CaptureFrameRefusal,
    ClockSample,
    FrameKind,
    parse_header,
)
from scripts.interop.certificate_dual_stack_guest import MAX_PUBLIC_BYTES, public_bytes
from scripts.interop.certificate_dual_stack_restore import capture_restoration_baseline
from tests.test_certificate_dual_stack_restore import _MAC, _PATHS, _Transport
from tests.test_certificate_dual_stack_restore import dns_form as dns_form

_BINDING = CaptureBinding(b"r" * 16, b"n" * 16, b"c" * 32, b"l" * 32, b"p" * 32, b"b" * 32, 2_000, 100, 20_000)
_RECEIPT = b"j" * 32


def clock(offset: int = 0) -> ClockSample:
    """Build a progressing same-boot synthetic sample.

    Args:
        offset: Elapsed counter ticks.
    """
    return ClockSample(_BINDING.boot_sha256, 1_000 + offset, 100, 10_000 + offset * 10)


def frame(kind: FrameKind, data: bytes) -> bytes:
    """Construct a fixture independently of the encoder.

    Args:
        kind: Wire message type.
        data: Exact frame body.
    """
    return struct.pack("!4sBBI", b"ARCP", 1, kind, len(data)) + data


def started() -> tuple[CaptureControllerFrames, CaptureChildFrames]:
    """Prepare the two memory endpoints after a synthetic GO."""
    controller = CaptureControllerFrames(_BINDING)
    child = CaptureChildFrames(_BINDING)
    child.accept_go(controller.go(clock()), clock(1))
    return controller, child


@pytest.fixture
def baseline(dns_form: str) -> bytes:
    """Return real stage1 canonical bytes from synthetic normal UI responses.

    Args:
        dns_form: Rendered current normal DNS settings form.
    """
    return public_bytes(capture_restoration_baseline(_Transport(dns_form).client, "eth1", _MAC, lambda _: None))


def host_frame_expression(method: str, fields: tuple[bytes | int, ...]) -> str:
    """Build a PowerShell call using only fixture bytes and exact integer literals.

    Args:
        method: The fixed host encoder method selected by the test.
        fields: Synthetic fixed-width fields in wire order.
    """
    arguments = [
        f"[Convert]::FromHexString('{field.hex()}')" if isinstance(field, bytes) else f"[long]({field})"
        for field in fields
    ]
    return f"[Atlaso.RestorationControlFrames]::{method}({', '.join(arguments)})"


def run_host_frames(executable: str, script: str) -> list[str]:
    """Run the in-memory Windows encoder fixture and return its lines.

    Args:
        executable: Resolved PowerShell executable.
        script: Test-only calls built from fixed synthetic fields.
    """
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference = 'Stop'; "
         "Import-Module ./scripts/windows/vmware/Atlaso.RestorationControlFrames.psm1; " + script],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


@pytest.mark.parametrize("high", [False, True], ids=["asymmetric", "signed-maximum"])
def test_windows_control_frames_match_python_oracle(high: bool, baseline: bytes) -> None:
    """Compare every host byte with the normative controller's real GO and ACK.

    Args:
        high: Use the maximum signed counter and maximum UTC deadline.
        baseline: Exact stage1 DATA from the synthetic normal UI fixture.
    """
    pwsh = shutil.which("pwsh") if os.name == "nt" else None
    if pwsh is None:
        pytest.skip("Windows PowerShell 7 is required for the host encoder")

    deadline = (1 << 63) - 1 if high else 0x0102030405060708
    utc_ms = 253_402_300_799_999 if high else 0x010203040506
    original = tuple(bytes(range(start, start + width)) for start, width in (
        (1, 16), (25, 16), (42, 32), (76, 32), (111, 32), (147, 32),
    ))
    binding = CaptureBinding(*original, deadline, 1_000_003, utc_ms)
    sample = ClockSample(binding.boot_sha256, deadline - 1_000_004, binding.frequency, utc_ms - 1_002)
    receipt = bytes(range(185, 217))
    controller = CaptureControllerFrames(binding)
    expected_go = controller.go(sample)
    controller.accept_checkpoint(frame(FrameKind.CHECKPOINT, baseline), sample)
    expected_ack = controller.acknowledge(receipt, sample)
    go = host_frame_expression("EncodeGo", (
        *original, deadline, binding.frequency, utc_ms, sample.counter, sample.utc_ms,
    ))
    ack_fields = (*original[:3], hashlib.sha256(baseline).digest(), receipt)
    ack = host_frame_expression("EncodeAck", ack_fields)
    changed_ack = host_frame_expression("EncodeAck", (*ack_fields[:3], receipt, ack_fields[3]))
    observed = run_host_frames(pwsh, f"[Convert]::ToHexString({go}); [Convert]::ToHexString({ack}); "
                                    f"[Convert]::ToHexString({changed_ack})")
    assert len(observed) == 3
    assert [bytes.fromhex(value) for value in observed[:2]] == [expected_go, expected_ack]
    assert bytes.fromhex(observed[2]) != expected_ack


def test_windows_control_encoder_refuses_invalid_fields() -> None:
    """Keep width and numeric refusal in the host encoder itself."""
    pwsh = shutil.which("pwsh") if os.name == "nt" else None
    if pwsh is None:
        pytest.skip("Windows PowerShell 7 is required for the host encoder")
    binding = (b"r" * 16, b"n" * 16, b"i" * 32, b"l" * 32, b"p" * 32, b"b" * 32)
    calls = (
        host_frame_expression("EncodeGo", (*binding, 2000, 0, 2000, 1000, 1000)),
        host_frame_expression("EncodeGo", (*binding, 2000, 1000, 253_402_300_800_000, 1000, 1000)),
        host_frame_expression("EncodeGo", (*binding, 2000, 1000, 2000, -1, 1000)),
        host_frame_expression("EncodeAck", (*binding[:3], b"d" * 32, b"j" * 33)),
    )
    script = "; ".join(
        f"try {{ $null = {call}; throw 'Encoder accepted invalid input' }} catch {{ "
        "if ($_.Exception.GetBaseException() -isnot [ArgumentException]) { throw }; 'refused' }"
        for call in calls
    )
    assert run_host_frames(pwsh, script) == ["refused"] * len(calls)


def test_exchange_wraps_the_original_stage1_callback_and_final_return(dns_form: str) -> None:
    """Keep durable acknowledgement separate from the normal final-read return.

    Args:
        dns_form: Rendered current normal DNS settings form.
    """
    controller, child = started()
    ui = _Transport(dns_form)
    checkpointed: list[bytes] = []

    def checkpoint(value: dict[str, Any]) -> None:
        """Simulate a publisher acknowledging only the frozen canonical data.

        Args:
            value: Original callback's independent DATA copy.
        """
        assert ui.requests == [("GET", path) for path in _PATHS * 2]
        checkpointed.append(controller.accept_checkpoint(child.checkpoint(public_bytes(value), clock(2)), clock(3)))
        assert child.accept_ack(controller.acknowledge(_RECEIPT, clock(4)), clock(5)) == _RECEIPT

    data = public_bytes(capture_restoration_baseline(ui.client, "eth1", _MAC, checkpoint))
    assert ui.requests == [("GET", path) for path in _PATHS * 3]
    assert checkpointed == [data]
    controller.accept_complete(child.complete(data, clock(6)), clock(7))
    assert controller.accept_eof(b"", clock(8)) == data
    with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
        controller.accept_eof(b"", clock(9))


@pytest.mark.parametrize(("kind", "length"), [
    (FrameKind.GO, 199), (FrameKind.GO, 201), (FrameKind.ACK, 127), (FrameKind.ACK, 129),
    (FrameKind.CHECKPOINT, 1), (FrameKind.COMPLETE, MAX_PUBLIC_BYTES + 1),
])
def test_reject_length_before_body_allocation(kind: FrameKind, length: int) -> None:
    """Refuse frame declarations outside the closed bounds.

    Args:
        kind: Candidate message type.
        length: Declared out-of-range payload size.
    """
    with pytest.raises(CaptureFrameRefusal, match="capture_length_invalid"):
        parse_header(struct.pack("!4sBBI", b"ARCP", 1, kind, length), kind)


@pytest.mark.parametrize("header", [
    b"", b"ARCP", b"WRNG\x01\x02\x00\x00\x00\x02",
    b"ARCP\x02\x02\x00\x00\x00\x02", b"ARCP\x01\xff\x00\x00\x00\x02",
    b"ARCP\x01\x04\x00\x00\x00\x02",
])
def test_reject_unknown_partial_or_wrong_direction_header(header: bytes) -> None:
    """Accept only the complete header for the expected frame kind.

    Args:
        header: Candidate invalid header bytes.
    """
    with pytest.raises(CaptureFrameRefusal, match="capture_header_invalid"):
        parse_header(header, FrameKind.CHECKPOINT)
    assert parse_header(frame(FrameKind.CHECKPOINT, b"{}")[:HEADER_BYTES], FrameKind.CHECKPOINT) == 2


@pytest.mark.parametrize("mode", ["partial", "trailing", "duplicate", "direction"])
def test_wrong_frame_consumes_original_controller(mode: str, baseline: bytes) -> None:
    """Prevent a retry after malformed or mismatched input.

    Args:
        mode: Frame corruption case.
        baseline: Canonical stage1 DATA bytes.
    """
    controller, child = started()
    valid = child.checkpoint(baseline, clock(2))
    wrong = {
        "partial": valid[:-1], "trailing": valid + b"!", "duplicate": valid + valid,
        "direction": frame(FrameKind.COMPLETE, baseline),
    }[mode]
    with pytest.raises(CaptureFrameRefusal):
        controller.accept_checkpoint(wrong, clock(3))
    with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
        controller.accept_checkpoint(valid, clock(4))


@pytest.mark.parametrize("offset", [0, 16, 32, 64, 96, 128, 160, 168, 176])
def test_go_rejects_each_mismatched_original_binding(offset: int) -> None:
    """Bind every launch field to independently supplied child data.

    Args:
        offset: Byte offset of an original GO field.
    """
    good = CaptureControllerFrames(_BINDING).go(clock())
    altered = bytearray(good)
    altered[HEADER_BYTES + offset] ^= 1
    child = CaptureChildFrames(_BINDING)
    with pytest.raises(CaptureFrameRefusal, match="capture_go_invalid"):
        child.accept_go(bytes(altered), clock(1))
    with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
        child.accept_go(good, clock(2))


@pytest.mark.parametrize("offset", [0, 16, 32, 64])
def test_ack_rejects_wrong_run_nonce_intent_or_baseline(offset: int, baseline: bytes) -> None:
    """Prevent ACK from releasing a different checkpoint or attempt.

    Args:
        offset: Byte offset of an ACK field.
        baseline: Canonical stage1 DATA bytes.
    """
    controller, child = started()
    controller.accept_checkpoint(child.checkpoint(baseline, clock(2)), clock(3))
    ack = controller.acknowledge(_RECEIPT, clock(4))
    altered = bytearray(ack)
    altered[HEADER_BYTES + offset] ^= 1
    with pytest.raises(CaptureFrameRefusal, match="capture_ack_invalid"):
        child.accept_ack(bytes(altered), clock(5))
    with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
        child.accept_ack(ack, clock(6))


@pytest.mark.parametrize("mode", ["whitespace", "duplicate", "ascii", "flag", "digest", "private", "nested", "dirty"])
def test_reject_noncanonical_or_out_of_scope_baselines(mode: str, baseline: bytes) -> None:
    """Refuse malformed bytes and unexpected stage1 content on both sides.

    Args:
        mode: DATA corruption case.
        baseline: Canonical stage1 DATA bytes.
    """
    data = json.loads(baseline)
    data["test_only"] = 1
    changed = {
        "whitespace": b" " + baseline, "duplicate": b'{"test_only":true,' + baseline[1:],
        "ascii": baseline + b"\xff", "flag": public_bytes(data),
    }
    data["test_only"] = True
    data["projection_sha256"]["review"] = "0" * 64
    changed["digest"] = public_bytes(data)
    for key, field, value, case in (
        ("dns_settings", "csrf_token", "private", "private"),
        ("original_row", "name", {"private": "unexpected"}, "nested"),
        ("review", "active_task", {"id": 1}, "dirty"),
    ):
        modified = json.loads(baseline)
        modified[key][field] = value
        modified["projection_sha256"][key] = hashlib.sha256(public_bytes(modified[key])).hexdigest()
        changed[case] = public_bytes(modified)
    controller, child = started()
    with pytest.raises(CaptureFrameRefusal, match="capture_baseline_invalid"):
        child.checkpoint(changed[mode], clock(2))
    with pytest.raises(CaptureFrameRefusal, match="capture_baseline_invalid"):
        controller.accept_checkpoint(frame(FrameKind.CHECKPOINT, changed[mode]), clock(3))


@pytest.mark.parametrize("mode", ["different_complete", "trailing_after_complete", "premature_eof", "early_complete"])
def test_checkpoint_and_ack_alone_cannot_yield_provisional_data(mode: str, baseline: bytes) -> None:
    """Require an exact completed exchange before returning bytes.

    Args:
        mode: Missing or invalid completion phase.
        baseline: Canonical stage1 DATA bytes.
    """
    controller, child = started()
    controller.accept_checkpoint(child.checkpoint(baseline, clock(2)), clock(3))
    if mode == "early_complete":
        with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
            controller.accept_complete(frame(FrameKind.COMPLETE, baseline), clock(4))
        return
    child.accept_ack(controller.acknowledge(_RECEIPT, clock(4)), clock(5))
    if mode == "premature_eof":
        with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
            controller.accept_eof(b"", clock(6))
    elif mode == "different_complete":
        other = json.loads(baseline)
        other["dns_settings"]["cache_size"] += 1
        other["projection_sha256"]["dns_settings"] = hashlib.sha256(public_bytes(other["dns_settings"])).hexdigest()
        changed = public_bytes(other)
        with pytest.raises(CaptureFrameRefusal, match="capture_complete_differs"):
            child.complete(changed, clock(6))
        with pytest.raises(CaptureFrameRefusal, match="capture_complete_differs"):
            controller.accept_complete(frame(FrameKind.COMPLETE, changed), clock(7))
    else:
        controller.accept_complete(child.complete(baseline, clock(6)), clock(7))
        with pytest.raises(CaptureFrameRefusal, match="capture_eof_invalid"):
            controller.accept_eof(b"trailing", clock(8))
        with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
            controller.accept_eof(b"", clock(9))


@pytest.mark.parametrize(("sample", "diagnostic"), [
    (replace(clock(), counter=2_000), "capture_deadline_invalid"),
    (replace(clock(), utc_ms=20_000), "capture_deadline_invalid"),
    (replace(clock(), boot_sha256=b"x" * 32), "capture_clock_invalid"),
    (replace(clock(), frequency=101), "capture_clock_invalid"),
    (replace(clock(), counter=True), "capture_clock_invalid"),
    (replace(clock(), counter=-1), "capture_clock_invalid"),
    (replace(clock(), counter=999), "capture_clock_regressed"),
    (replace(clock(), utc_ms=9_999), "capture_clock_regressed"),
])
def test_absolute_clock_rechecks_consume_phase(sample: ClockSample, diagnostic: str, baseline: bytes) -> None:
    """Refuse cutoff, clock changes and regression without a budget reset.

    Args:
        sample: Unacceptable clock reading.
        diagnostic: Expected fixed diagnostic.
        baseline: Canonical stage1 DATA bytes.
    """
    controller, child = started()
    checkpoint = child.checkpoint(baseline, clock(2))
    with pytest.raises(CaptureFrameRefusal, match=diagnostic):
        controller.accept_checkpoint(checkpoint, sample)
    with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
        controller.accept_checkpoint(checkpoint, clock(3))


def test_child_accounts_for_elapsed_time_before_go_and_ack(baseline: bytes) -> None:
    """Use the original cap across launch delay and checkpoint publication.

    Args:
        baseline: Canonical stage1 DATA bytes.
    """
    controller = CaptureControllerFrames(_BINDING)
    go = controller.go(clock(100))
    assert _BINDING.remaining_ns(clock(101)) == 8_990_000_000
    assert _BINDING.remaining_ns(replace(clock(101), utc_ms=19_999)) == 1_000_000
    with pytest.raises(CaptureFrameRefusal, match="capture_go_invalid"):
        CaptureChildFrames(_BINDING).accept_go(go, clock(99))
    with pytest.raises(CaptureFrameRefusal, match="capture_deadline_invalid"):
        CaptureChildFrames(_BINDING).accept_go(go, clock(1_000))
    child = CaptureChildFrames(_BINDING)
    child.accept_go(go, clock(101))
    controller.accept_checkpoint(child.checkpoint(baseline, clock(102)), clock(103))
    with pytest.raises(CaptureFrameRefusal, match="capture_deadline_invalid"):
        controller.acknowledge(_RECEIPT, clock(1_000))
    with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
        controller.acknowledge(_RECEIPT, clock(104))


def test_foreign_thread_and_copied_exchange_cannot_advance() -> None:
    """Keep phase state on its original endpoint and owner thread."""
    controller = CaptureControllerFrames(_BINDING)
    errors: list[str] = []

    def foreign_thread() -> None:
        """Record the original endpoint's refusal on another thread."""
        try:
            controller.go(clock())
        except CaptureFrameRefusal as error:
            errors.append(str(error))

    worker = threading.Thread(target=foreign_thread)
    worker.start()
    worker.join()
    assert errors == ["capture_owner_invalid"]
    with pytest.raises(CaptureFrameRefusal, match="capture_owner_invalid"):
        copy.copy(controller).go(clock())
    controller.go(clock())
    with pytest.raises(CaptureFrameRefusal, match="capture_phase_invalid"):
        controller.go(clock())
