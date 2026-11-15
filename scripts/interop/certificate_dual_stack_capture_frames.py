"""Source-only framing for a single read-only restoration capture exchange."""

from __future__ import annotations

import hashlib
import struct
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum

from scripts.interop.certificate_dual_stack_guest import (
    MAX_PUBLIC_BYTES,
    json_loads_unique,
    public_bytes,
)
from scripts.interop.certificate_dual_stack_restore import _REQUIRED_DNS, _ROW_KEYS
from scripts.interop.certificate_dual_stack_ui import FIELDS, assert_public_review

_MAGIC = b"ARCP"
_VERSION = 1
_HEADER = struct.Struct("!4sBBI")
HEADER_BYTES = _HEADER.size
_GO = struct.Struct("!16s16s32s32s32s32sQQQQQ")
_ACK = struct.Struct("!16s16s32s32s32s")
_MAX_COUNTER = (1 << 63) - 1
_MAX_UTC_MS = 253_402_300_799_999
_MAX_SECONDS = 420
_PROJECTIONS = {"review", "original_row", "browser_fields", "dns_settings"}
_FLAGS = {"test_only": True, "consistency_only": True, "native_acceptance": False, "formal_acceptance": False}
_CLEAN_REVIEW = public_bytes({
    "units": [], "pending_count": 0, "execution_count": 0, "requested_units": [],
    "plan_error": "", "initial_apply_required": False, "active_task": None,
})


class CaptureFrameRefusal(ValueError):
    """A fixed diagnostic that excludes frame data and clock or identity values."""


class FrameKind(IntEnum):
    """The four private capture frame kinds in wire order."""

    GO = 1
    CHECKPOINT = 2
    ACK = 3
    COMPLETE = 4


def _fixed_bytes(value: object, length: int) -> bool:
    """Require immutable bytes of an exact wire width.

    Args:
        value: Candidate binary value.
        length: Required byte count.
    """
    return type(value) is bytes and len(value) == length


def _unsigned(value: int, maximum: int) -> bool:
    """Check an integer range without accepting bool or coercions.

    Args:
        value: Candidate numeric field.
        maximum: Inclusive upper bound.
    """
    return type(value) is int and 0 <= value <= maximum


@dataclass(frozen=True, slots=True)
class ClockSample:
    """An externally supplied same-boot counter and UTC sample."""

    boot_sha256: bytes
    counter: int
    frequency: int
    utc_ms: int


@dataclass(frozen=True, slots=True)
class CaptureBinding:
    """Exact original attempt fields independently available to both endpoints."""

    run_id: bytes
    receiver_nonce: bytes
    capture_intent_sha256: bytes
    launch_intent_sha256: bytes
    process_receipt_sha256: bytes
    boot_sha256: bytes
    deadline_counter: int
    frequency: int
    deadline_utc_ms: int

    def __post_init__(self) -> None:
        if (not all(_fixed_bytes(value, 16) for value in (self.run_id, self.receiver_nonce))
                or not all(_fixed_bytes(value, 32) for value in (
                    self.capture_intent_sha256, self.launch_intent_sha256, self.process_receipt_sha256, self.boot_sha256,
                ))
                or not _unsigned(self.deadline_counter, _MAX_COUNTER)
                or not _unsigned(self.frequency, _MAX_COUNTER) or self.frequency == 0
                or not _unsigned(self.deadline_utc_ms, _MAX_UTC_MS)):
            raise CaptureFrameRefusal("capture_binding_invalid")

    def remaining_ns(self, sample: ClockSample) -> int:
        """Return the smaller remaining original budget, rounded down.

        Args:
            sample: Current externally supplied raw-counter and UTC observation.
        """
        if (type(sample) is not ClockSample or not _fixed_bytes(sample.boot_sha256, 32)
                or sample.boot_sha256 != self.boot_sha256 or not _unsigned(sample.frequency, _MAX_COUNTER)
                or sample.frequency != self.frequency or not _unsigned(sample.counter, _MAX_COUNTER)
                or not _unsigned(sample.utc_ms, _MAX_UTC_MS)):
            raise CaptureFrameRefusal("capture_clock_invalid")
        ticks = self.deadline_counter - sample.counter
        utc_ms = self.deadline_utc_ms - sample.utc_ms
        if ticks <= 0 or utc_ms <= 0 or ticks > self.frequency * _MAX_SECONDS or utc_ms > _MAX_SECONDS * 1000:
            raise CaptureFrameRefusal("capture_deadline_invalid")
        remaining = min(ticks * 1_000_000_000 // self.frequency, utc_ms * 1_000_000)
        if remaining == 0:
            raise CaptureFrameRefusal("capture_deadline_invalid")
        return remaining


def parse_header(raw: bytes, expected: FrameKind) -> int:
    """Check an exact header before a future adapter allocates its body.

    Args:
        raw: Exactly the fixed header bytes.
        expected: The frame kind allowed in the current direction and phase.
    """
    if not _fixed_bytes(raw, HEADER_BYTES) or type(expected) is not FrameKind:
        raise CaptureFrameRefusal("capture_header_invalid")
    magic, version, kind, length = _HEADER.unpack(raw)
    if magic != _MAGIC or version != _VERSION or kind != expected:
        raise CaptureFrameRefusal("capture_header_invalid")
    if expected == FrameKind.GO:
        valid = length == _GO.size
    elif expected == FrameKind.ACK:
        valid = length == _ACK.size
    else:
        valid = 2 <= length <= MAX_PUBLIC_BYTES
    if not valid:
        raise CaptureFrameRefusal("capture_length_invalid")
    return int(length)


def _frame(kind: FrameKind, body: bytes) -> bytes:
    """Encode one already validated body.

    Args:
        kind: Exact frame type.
        body: Validated body bytes.
    """
    return _HEADER.pack(_MAGIC, _VERSION, kind, len(body)) + body


def _body(raw: bytes, expected: FrameKind) -> bytes:
    """Require exactly one frame and its declared body.

    Args:
        raw: One complete candidate frame.
        expected: Frame kind required in the current phase.
    """
    if type(raw) is not bytes:
        raise CaptureFrameRefusal("capture_frame_invalid")
    length = parse_header(raw[:HEADER_BYTES], expected)
    if len(raw) != HEADER_BYTES + length:
        raise CaptureFrameRefusal("capture_length_invalid")
    return raw[HEADER_BYTES:]


def _baseline(raw: bytes) -> bytes:
    """Check the bounded canonical stage1 envelope and projection digests.

    Args:
        raw: Candidate exact stage1 DATA bytes.
    """
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_PUBLIC_BYTES or not raw.isascii():
        raise CaptureFrameRefusal("capture_baseline_invalid")
    try:
        data = json_loads_unique(raw)
        if (type(data) is not dict or data.keys() != _PROJECTIONS | _FLAGS.keys() | {"projection_sha256"}
                or any(data[key] is not value for key, value in _FLAGS.items())
                or any(type(data[key]) is not dict for key in _PROJECTIONS)
                or public_bytes(data["review"]) != _CLEAN_REVIEW
                or data["original_row"].keys() != _ROW_KEYS
                or data["browser_fields"].keys() != {*FIELDS, "admin_state"}
                or data["dns_settings"].keys() != _REQUIRED_DNS | {"listen_interfaces"}
                or any(type(value) not in (str, int, bool, type(None))
                       for key in ("original_row", "browser_fields") for value in data[key].values())
                or any(type(data["dns_settings"][key]) not in (str, int, bool) for key in _REQUIRED_DNS)
                or public_bytes(data) != raw):
            raise CaptureFrameRefusal("capture_baseline_invalid")
        interfaces = data["dns_settings"]["listen_interfaces"]
        if type(interfaces) is not list or any(type(interface) is not str for interface in interfaces):
            raise CaptureFrameRefusal("capture_baseline_invalid")
        digests = data["projection_sha256"]
        if type(digests) is not dict or digests != {
            key: hashlib.sha256(public_bytes(data[key])).hexdigest() for key in _PROJECTIONS
        }:
            raise CaptureFrameRefusal("capture_baseline_invalid")
        assert_public_review(data, set())
    except (ValueError, RecursionError):
        raise CaptureFrameRefusal("capture_baseline_invalid") from None
    return raw


class _Exchange:
    """Private original-thread exchange state with irreversible refusals."""

    def __init__(self, binding: CaptureBinding) -> None:
        """Start a single exchange on the current thread.

        Args:
            binding: Original capture and deadline expected by this endpoint.
        """
        self._binding = binding
        self._owner = threading.current_thread()
        self._original = self
        self._phase = "go"
        self._sample: ClockSample | None = None
        self._baseline = b""

    @contextmanager
    def _transition(self, expected: str, next_phase: str, sample: ClockSample) -> Iterator[None]:
        """Validate a phase boundary and advance only on normal return.

        Args:
            expected: Only allowed current phase.
            next_phase: Phase after successful validation.
            sample: Current externally supplied clock observation.
        """
        if threading.current_thread() is not self._owner or self is not self._original:
            raise CaptureFrameRefusal("capture_owner_invalid")
        current = self._phase
        self._phase = "failed"
        if current != expected:
            raise CaptureFrameRefusal("capture_phase_invalid")
        self._binding.remaining_ns(sample)
        if self._sample is not None and (sample.counter < self._sample.counter or sample.utc_ms < self._sample.utc_ms):
            raise CaptureFrameRefusal("capture_clock_regressed")
        self._sample = sample
        yield
        self._phase = next_phase

    def _go_body(self, sample: ClockSample) -> bytes:
        """Encode the original binding and the current controller sample.

        Args:
            sample: Validated controller clock sample.
        """
        binding = self._binding
        return _GO.pack(
            binding.run_id, binding.receiver_nonce, binding.capture_intent_sha256, binding.launch_intent_sha256,
            binding.process_receipt_sha256, binding.boot_sha256, binding.deadline_counter, binding.frequency,
            binding.deadline_utc_ms, sample.counter, sample.utc_ms,
        )

    def _ack_body(self, receipt_sha256: bytes) -> bytes:
        """Bind an acknowledgement to this original attempt and exact baseline.

        Args:
            receipt_sha256: Digest of the externally verified checkpoint receipt.
        """
        if not _fixed_bytes(receipt_sha256, 32):
            raise CaptureFrameRefusal("capture_ack_invalid")
        binding = self._binding
        return _ACK.pack(binding.run_id, binding.receiver_nonce, binding.capture_intent_sha256,
                         hashlib.sha256(self._baseline).digest(), receipt_sha256)


class CaptureControllerFrames(_Exchange):
    """Synthetic controller phases through provisional COMPLETE and EOF."""

    def go(self, sample: ClockSample) -> bytes:
        """Send the original GO once.

        Args:
            sample: Current controller clock observation.
        """
        with self._transition("go", "checkpoint", sample):
            return _frame(FrameKind.GO, self._go_body(sample))

    def accept_checkpoint(self, frame: bytes, sample: ClockSample) -> bytes:
        """Freeze the exact DATA for a separately handled checkpoint.

        Args:
            frame: Candidate CHECKPOINT frame.
            sample: Current controller clock observation.
        """
        with self._transition("checkpoint", "ack", sample):
            self._baseline = _baseline(_body(frame, FrameKind.CHECKPOINT))
            return self._baseline

    def acknowledge(self, receipt_sha256: bytes, sample: ClockSample) -> bytes:
        """Frame the digest supplied after external durable verification.

        Args:
            receipt_sha256: Exact verified checkpoint receipt digest.
            sample: Fresh controller clock observation after publication.
        """
        with self._transition("ack", "complete", sample):
            return _frame(FrameKind.ACK, self._ack_body(receipt_sha256))

    def accept_complete(self, frame: bytes, sample: ClockSample) -> None:
        """Require COMPLETE to contain the exact frozen CHECKPOINT bytes.

        Args:
            frame: Candidate COMPLETE frame.
            sample: Current controller clock observation.
        """
        with self._transition("complete", "eof", sample):
            if _body(frame, FrameKind.COMPLETE) != self._baseline:
                raise CaptureFrameRefusal("capture_complete_differs")

    def accept_eof(self, read: bytes, sample: ClockSample) -> bytes:
        """Check a future adapter's EOF result and return provisional DATA.

        Args:
            read: Exact empty bytes from the adapter's EOF check.
            sample: Current controller clock observation.
        """
        with self._transition("eof", "done", sample):
            if not _fixed_bytes(read, 0):
                raise CaptureFrameRefusal("capture_eof_invalid")
            return self._baseline


class CaptureChildFrames(_Exchange):
    """Synthetic child phases for one original capture handoff."""

    def accept_go(self, frame: bytes, sample: ClockSample) -> None:
        """Require an exact independently expected binding and parent sample.

        Args:
            frame: Candidate GO frame.
            sample: Current child clock observation.
        """
        with self._transition("go", "checkpoint", sample):
            body = _body(frame, FrameKind.GO)
            *_, counter, utc_ms = _GO.unpack(body)
            parent = ClockSample(self._binding.boot_sha256, counter, self._binding.frequency, utc_ms)
            self._binding.remaining_ns(parent)
            if body != self._go_body(parent) or counter > sample.counter or utc_ms > sample.utc_ms:
                raise CaptureFrameRefusal("capture_go_invalid")

    def checkpoint(self, data: bytes, sample: ClockSample) -> bytes:
        """Frame one exact stage1 checkpoint callback value.

        Args:
            data: Candidate canonical stage1 DATA.
            sample: Current child clock observation.
        """
        with self._transition("checkpoint", "ack", sample):
            self._baseline = _baseline(data)
            return _frame(FrameKind.CHECKPOINT, self._baseline)

    def accept_ack(self, frame: bytes, sample: ClockSample) -> bytes:
        """Require the receipt digest frame to bind this attempt and its DATA.

        Args:
            frame: Candidate ACK frame.
            sample: Current child clock observation.
        """
        with self._transition("ack", "complete", sample):
            body = _body(frame, FrameKind.ACK)
            receipt_sha256 = body[-32:]
            if body != self._ack_body(receipt_sha256):
                raise CaptureFrameRefusal("capture_ack_invalid")
            return receipt_sha256

    def complete(self, data: bytes, sample: ClockSample) -> bytes:
        """Frame the exact stage1 return after the final read guards.

        Args:
            data: Candidate canonical stage1 return DATA.
            sample: Current child clock observation.
        """
        with self._transition("complete", "done", sample):
            if type(data) is not bytes or data != self._baseline:
                raise CaptureFrameRefusal("capture_complete_differs")
            return _frame(FrameKind.COMPLETE, data)
