"""Diagnose QEMU COM2 ring-buffer contents around synthetic readiness challenges.

The caller supplies a known Linux kernel/initrd and a newly created empty state
directory on a GitHub-hosted runner. Guest bytes are inspected only in memory;
output contains lengths and byte categories, never the serial payload.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.installation import vm_acceptance

_QMP_READ_BYTES = vm_acceptance.NETWORK_RINGBUF_READ_BYTES
_QMP_BUFFER_BYTES = vm_acceptance.NETWORK_RINGBUF_BYTES
_MARKER_TIMEOUT = 60
_RESPONSE_TIMEOUT = 20
_EMPTY_CONFIRMATIONS = 2
_OVERALL_TIMEOUT = 180


class SmokeError(RuntimeError):
    """Report a fixed diagnostic failure without guest or host payload data."""


@dataclass
class ReadSummary:
    """Bounded counters for one production-reader invocation."""

    expected_line: bytes
    reads: int = 0
    byte_count: int = 0
    printable_ascii: int = 0
    line_feed: int = 0
    carriage_return: int = 0
    other_control: int = 0
    high_bit: int = 0
    complete_lines: int = 0
    exact_ready_lines: int = 0
    other_ascii_lines: int = 0
    non_ascii_lines: int = 0
    payload: bytearray | None = None

    def __post_init__(self) -> None:
        """Initialize the private in-memory payload buffer."""
        self.payload = bytearray()

    def add(self, encoded: Any) -> None:
        """Count one base64 QMP read without retaining more than the ring size."""
        self.reads += 1
        if not isinstance(encoded, str):
            return
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            return
        self.byte_count += len(chunk)
        self.line_feed += chunk.count(b"\n")
        self.carriage_return += chunk.count(b"\r")
        self.printable_ascii += sum(0x20 <= byte <= 0x7E for byte in chunk)
        self.high_bit += sum(byte >= 0x80 for byte in chunk)
        self.other_control += sum(byte < 0x20 and byte not in (0x0A, 0x0D) for byte in chunk)
        if self.payload is None:
            self.payload = bytearray()
        room = max(0, _QMP_BUFFER_BYTES - len(self.payload))
        self.payload.extend(chunk[:room])

    def record_lines(self) -> None:
        """Classify complete lines present in the bounded private payload."""
        payload = bytes(self.payload or b"")
        lines = payload.split(b"\n")
        self.complete_lines = len(lines) - 1
        for line in lines[: self.complete_lines]:
            normalized = line.removesuffix(b"\r")
            if normalized == self.expected_line:
                self.exact_ready_lines += 1
            elif all(0x20 <= byte <= 0x7E for byte in normalized):
                self.other_ascii_lines += 1
            else:
                self.non_ascii_lines += 1

    def json(self) -> dict[str, int | bool]:
        """Return a payload-free counter record."""
        self.record_lines()
        return {
            "reads": self.reads,
            "bytes": self.byte_count,
            "printable_ascii_bytes": self.printable_ascii,
            "line_feed_bytes": self.line_feed,
            "carriage_return_bytes": self.carriage_return,
            "other_control_bytes": self.other_control,
            "high_bit_bytes": self.high_bit,
            "complete_lines": self.complete_lines,
            "exact_ready_lines": self.exact_ready_lines,
            "other_ascii_lines": self.other_ascii_lines,
            "non_ascii_lines": self.non_ascii_lines,
            "partial_payload_bytes": len(bytes(self.payload or b"").rsplit(b"\n", 1)[-1]),
            "exact_ready_present": self.exact_ready_lines > 0,
        }


class ObservedQmp(vm_acceptance.Qmp):
    """Use the repository QMP transport and observe only ring-buffer counters."""

    def __init__(self, address: str, process: subprocess.Popen[bytes]):
        self.read_summary: ReadSummary | None = None
        super().__init__(address, process, abstract=True)

    def execute(self, command: str, arguments: dict[str, Any] | None = None) -> Any:
        """Count returned ring-buffer bytes while preserving the QMP result."""
        result = super().execute(command, arguments)
        if command == "ringbuf-read" and self.read_summary is not None:
            self.read_summary.add(result)
        return result


def _regular_file(path: Path, label: str) -> Path:
    """Admit one existing ordinary input file without following a leaf symlink."""
    candidate = path.absolute()
    try:
        info = candidate.lstat()
    except OSError as error:
        raise SmokeError(f"{label} is unavailable") from error
    if not candidate.is_file() or candidate.is_symlink() or info.st_size <= 0:
        raise SmokeError(f"{label} is not a nonempty ordinary file")
    return candidate


def _ovmf_files() -> tuple[Path, Path]:
    """Find stock OVMF code and vars without modifying the installed images."""
    root = Path("/usr/share/OVMF")
    for code_name, vars_name in (
        ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd"),
        ("OVMF_CODE.fd", "OVMF_VARS.fd"),
    ):
        code = root / code_name
        variables = root / vars_name
        if code.is_file() and variables.is_file():
            return _regular_file(code, "OVMF code"), _regular_file(variables, "OVMF variables")
    raise SmokeError("stock OVMF code and variables are unavailable")


def _require_state(path: Path) -> Path:
    """Require a caller-created empty ordinary state directory."""
    state = path.absolute()
    if not state.is_dir() or state.is_symlink() or any(state.iterdir()):
        raise SmokeError("state must be a caller-created empty ordinary directory")
    return state


def _read_debug_markers(path: Path) -> bytes:
    """Read the independent debugcon marker stream and admit only fixed markers."""
    try:
        markers = path.read_bytes()
    except FileNotFoundError:
        return b""
    if len(markers) > 16 or any(marker not in b"ROWXY" for marker in markers):
        raise SmokeError("debugcon marker stream is invalid")
    return markers


def _wait_markers(path: Path, expected: bytes, deadline: float) -> None:
    """Wait for an exact monotonically growing marker sequence."""
    while time.monotonic() < deadline:
        markers = _read_debug_markers(path)
        if markers.startswith(expected):
            return
        if not expected.startswith(markers):
            raise SmokeError("debugcon markers arrived out of order")
        time.sleep(0.1)
    raise SmokeError("guest debugcon marker deadline expired")


def _new_token(*, mixed_case: bool = False) -> str:
    """Create a fresh 32-character hexadecimal challenge token."""
    token = uuid.uuid4().hex
    return "aB" + token[2:] if mixed_case else token


def _send_line(qmp: ObservedQmp, value: str) -> None:
    """Type one bounded ASCII line through the synthetic guest keyboard."""
    vm_acceptance.type_text(qmp, value)


def _read_ready(qmp: ObservedQmp, token: str) -> tuple[dict[str, Any], bytes]:
    """Run the unchanged production parser and return sanitized observations."""
    expected = f"ATLASO-PROBE:{token}:READY".encode("ascii")
    summary = ReadSummary(expected)
    qmp.read_summary = summary
    parser_passed = False
    parser_result = "rejected"
    try:
        records = qmp.read_network_records(token, time.monotonic() + _RESPONSE_TIMEOUT, "READY")
        parser_passed = records == [expected.decode("ascii")]
        parser_result = "passed" if parser_passed else "unexpected_records"
    except vm_acceptance.ScreenTimeout:
        parser_result = "timeout"
    except vm_acceptance.AcceptanceError:
        parser_result = "rejected"
    finally:
        qmp.read_summary = None
    return {"parser": parser_result, **summary.json()}, bytes(summary.payload or b"")


def _drain_to_empty(qmp: ObservedQmp) -> tuple[dict[str, int | bool], bytes]:
    """Classify and drain one buffer phase through consecutive empty reads."""
    summary = ReadSummary(b"\0")
    reads = 0
    empty_reads = 0
    while reads < (_QMP_BUFFER_BYTES // _QMP_READ_BYTES) + _EMPTY_CONFIRMATIONS + 1:
        encoded = qmp.execute(
            "ringbuf-read",
            {"device": vm_acceptance.NETWORK_RINGBUF, "size": _QMP_READ_BYTES, "format": "base64"},
        )
        reads += 1
        if not isinstance(encoded, str):
            raise SmokeError("QMP ring-buffer response is invalid")
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise SmokeError("QMP ring-buffer response is invalid") from error
        summary.add(encoded)
        if chunk:
            empty_reads = 0
        else:
            empty_reads += 1
            if empty_reads >= _EMPTY_CONFIRMATIONS:
                return (
                    {**summary.json(), "empty_confirmations": empty_reads},
                    bytes(summary.payload or b""),
                )
    return {**summary.json(), "empty_confirmations": empty_reads}, bytes(summary.payload or b"")


class ReplayQmp:
    """Replay one bounded in-memory ring buffer through the production parser."""

    read_network_records = vm_acceptance.Qmp.read_network_records

    def __init__(self, payload: bytes, summary: ReadSummary):
        self.payload = payload
        self.offset = 0
        self.read_summary = summary

    def execute(self, command: str, arguments: dict[str, Any] | None = None) -> str:
        """Return one bounded replay chunk for the repository reader."""
        if command != "ringbuf-read" or arguments is None:
            raise SmokeError("production reader requested an unexpected replay operation")
        size = arguments.get("size")
        if not isinstance(size, int) or not 1 <= size <= _QMP_BUFFER_BYTES:
            raise SmokeError("production reader requested an invalid replay size")
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        encoded = base64.b64encode(chunk).decode("ascii")
        self.read_summary.add(encoded)
        return encoded


def _launch_qemu(
    kernel: Path, initrd: Path, state: Path,
) -> tuple[subprocess.Popen[bytes], ObservedQmp, str, Path, bool]:
    """Launch one bounded synthetic Linux guest with production COM2 topology."""
    qemu = shutil.which("qemu-system-x86_64")
    if qemu is None:
        raise SmokeError("QEMU is unavailable")
    ovmf_code, ovmf_vars = _ovmf_files()
    variables_copy = state / "OVMF_VARS.fd"
    shutil.copyfile(ovmf_vars, variables_copy)
    debugcon = state / "debugcon.markers"
    accelerator = "kvm" if Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    qmp_name = f"atlaso-{uuid.uuid4().hex}-hosted-serial"
    command = [
        qemu, "-name", "atlaso-hosted-serial-diagnostic", "-machine", f"q35,accel={accelerator}",
        "-cpu", "host" if accelerator == "kvm" else "max", "-smp", "2", "-m", "4096",
        "-display", "none", "-vga", "virtio", "-monitor", "none", "-no-reboot", "-no-shutdown",
        "-rtc", "base=utc,clock=host", "-S",
        "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive", f"if=pflash,format=raw,file={variables_copy}",
        "-kernel", str(kernel), "-initrd", str(initrd),
        "-append", "console=tty0 rdinit=/init", "-net", "none",
        "-chardev", f"ringbuf,id={vm_acceptance.NETWORK_RINGBUF},size={_QMP_BUFFER_BYTES}",
        "-device", f"isa-serial,chardev={vm_acceptance.NETWORK_RINGBUF},index=1",
        "-chardev", f"file,id=debugcon,path={debugcon}",
        "-device", "isa-debugcon,iobase=0xe9,chardev=debugcon",
        "-qmp", f"unix:{qmp_name},abstract=on,server=on,wait=off",
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    qmp: ObservedQmp | None = None
    try:
        qmp = ObservedQmp(qmp_name, process)
        actual_kvm = qmp.execute("query-kvm")
        enabled = isinstance(actual_kvm, dict) and actual_kvm.get("enabled") is True
        print(json.dumps({"schema": 1, "event": "accelerator", "accelerator": accelerator}), flush=True)
        if enabled != (accelerator == "kvm"):
            raise SmokeError("QEMU accelerator did not match the selected production mode")
        qmp.execute("cont")
        return process, qmp, accelerator, debugcon, enabled
    except Exception:
        if qmp is not None:
            qmp.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=20)
        raise


def run(kernel: Path, initrd: Path, state: Path) -> dict[str, Any]:
    """Measure pre-open bytes, then exercise direct and production-style challenges."""
    started = time.monotonic()
    overall_deadline = started + _OVERALL_TIMEOUT
    process, qmp, accelerator, debugcon, enabled = _launch_qemu(kernel, initrd, state)
    try:
        _wait_markers(debugcon, b"R", min(overall_deadline, time.monotonic() + _MARKER_TIMEOUT))
        before_open, before_open_payload = _drain_to_empty(qmp)
        before_open["clean"] = before_open["empty_confirmations"] >= _EMPTY_CONFIRMATIONS
        _send_line(qmp, "open")
        _wait_markers(debugcon, b"RO", min(overall_deadline, time.monotonic() + _MARKER_TIMEOUT))
        after_open, after_open_payload = _drain_to_empty(qmp)
        after_open["clean"] = after_open["empty_confirmations"] >= _EMPTY_CONFIRMATIONS
        pre_challenge_prefix = before_open_payload + after_open_payload

        first_token = _new_token()
        _send_line(qmp, first_token)
        _wait_markers(debugcon, b"ROW", min(overall_deadline, time.monotonic() + _MARKER_TIMEOUT))
        first, first_reply = _read_ready(qmp, first_token)

        replay_prefix = pre_challenge_prefix + first_reply
        dropped_prefix_bytes = max(0, len(replay_prefix) - _QMP_BUFFER_BYTES)
        replay_summary = ReadSummary(f"ATLASO-PROBE:{first_token}:READY".encode("ascii"))
        replay = ReplayQmp(replay_prefix[-_QMP_BUFFER_BYTES:], replay_summary)
        replay_result = "rejected"
        try:
            replay_records = replay.read_network_records(
                first_token, time.monotonic() + _RESPONSE_TIMEOUT, "READY",
            )
            replay_result = "passed" if replay_records == [f"ATLASO-PROBE:{first_token}:READY"] else "unexpected_records"
        except vm_acceptance.ScreenTimeout:
            replay_result = "timeout"
        except vm_acceptance.AcceptanceError:
            replay_result = "rejected"
        unfiltered_replay = {
            "parser": replay_result,
            "dropped_oldest_bytes_at_ring_capacity": dropped_prefix_bytes,
            **replay_summary.json(),
        }

        boundary, _boundary_payload = _drain_to_empty(qmp)
        boundary["clean"] = boundary["empty_confirmations"] >= _EMPTY_CONFIRMATIONS
        second_token = _new_token()
        _send_line(qmp, second_token)
        _wait_markers(debugcon, b"ROWX", min(overall_deadline, time.monotonic() + _MARKER_TIMEOUT))
        second, _second_payload = _read_ready(qmp, second_token)

        command_token = _new_token(mixed_case=True)
        command = (
            "test -c /dev/ttyS1 && exec 3>/dev/ttyS1 && printf '%s\\n' "
            f"ATLASO-PROBE:{command_token}:READY >&3"
        )
        _send_line(qmp, command)
        _wait_markers(debugcon, b"ROWXY", min(overall_deadline, time.monotonic() + _MARKER_TIMEOUT))
        command_round, _command_payload = _read_ready(qmp, command_token)

        return {
            "schema": 1,
            "result": "completed" if (
                before_open["clean"] and after_open["clean"] and first["parser"] == "passed" and boundary["clean"] and
                second["parser"] == "passed" and command_round["parser"] == "passed"
            ) else "failed",
            "accelerator": accelerator,
            "kvm_enabled": enabled,
            "debugcon_markers": "ROWXY",
            "direct_token_length": 32,
            "mixed_case_token_length": 32,
            "before_com2_open": before_open,
            "after_com2_open_before_challenge": after_open,
            "pre_challenge_prefix_bytes": len(pre_challenge_prefix),
            "handshake_1": first,
            "handshake_1_unfiltered_replay": unfiltered_replay,
            "clean_boundary": boundary,
            "handshake_2": second,
            "production_command_round": command_round,
        }
    finally:
        vm_acceptance.stop_qemu(process, qmp)


def main(argv: list[str] | None = None) -> int:
    """Run the hosted serial smoke and print only bounded sanitized JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--initrd", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        kernel = _regular_file(args.kernel, "kernel")
        initrd = _regular_file(args.initrd, "initrd")
        state = _require_state(args.state)
        result = run(kernel, initrd, state)
    except SmokeError as error:
        reason = str(error)
        print(json.dumps({"schema": 1, "result": "failed", "reason": reason}), flush=True)
        return 1
    except vm_acceptance.AcceptanceError:
        print(json.dumps({"schema": 1, "result": "failed", "reason": "qemu_acceptance_error"}), flush=True)
        return 1
    except OSError:
        print(json.dumps({"schema": 1, "result": "failed", "reason": "io_error"}), flush=True)
        return 1
    except (ValueError, subprocess.SubprocessError):
        print(json.dumps({"schema": 1, "result": "failed", "reason": "invalid_or_process_error"}), flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["result"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
