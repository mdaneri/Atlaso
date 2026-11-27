"""Run the bounded, disconnected UEFI acceptance case in QEMU."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from scripts.installation.manifest import digest

VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DISK_ROW = re.compile(r"(?im)^\s*.*?\b(64|4)\s*GiB\s*@\s*/d(?:ev|eu)/sd[a-z]\b")
REVIEW_DISK = re.compile(r"(?im)^[ \t]*[/f]de[vu]/sd[a-z]: [^\r\n]{1,72}\b(64|4)\s*GiB[ \t]*$")
STORAGE_LAYOUT_LABELS = (
    r"\broot installation target\b",
    r"\bsftp backup storage\b",
    r"\bvy?cfdt depot storage\b",
)
STORAGE_LAYOUT_MOUNTS = (
    r"[/+]",
    r"/mnt(?:-?/|-)atlaso-[vu]cf-backups",
    r"/mnt(?:-?/|-)atlaso-[vu]cf-offline-depot",
)
STORAGE_ROOT_DISK = re.compile(r"/d(?:ev|eu)/sd[a-z]\b", re.I)
CHECKS = [
    "disconnected_uefi_install",
    "selected_64g_target",
    "media_free_boot",
    "atlaso_services_active",
    "installed_application_version",
    "installed_application_commit",
    "unselected_4g_disk_unchanged",
]
INSTALL_SECONDS = 3 * 60 * 60
BOOT_SECONDS = 15 * 60
MINIMUM_FREE_BYTES = 16 * 1024**3
FIRST_NETWORK_DIAGNOSTICS_VERSION = (0, 9, 523)
NETWORK_PROBES = (
    ("IPv4 loopback ping", "ping", "127.0.0.1", "127.0.0.1", "reply"),
    ("IPv4 loopback traceroute", "traceroute", "127.0.0.1", "127.0.0.1", "reply"),
    ("IPv6 loopback ping", "ping", "::1", "::1", "reply"),
    ("IPv6 loopback traceroute", "traceroute", "::1", "::1", "reply"),
    ("localhost lookup", "dns", "localhost", "", "resolved"),
)
NETWORK_RESULT_SECONDS = 180
NETWORK_RINGBUF = "atlaso-probes"
NETWORK_RINGBUF_BYTES = 4096
NETWORK_RINGBUF_READ_BYTES = 1024
ACTIVE_STATES = "active|inactive|activating|deactivating|failed|reloading|refreshing|maintenance|unknown"
SERVICE_STATES = ACTIVE_STATES + "|unrecognized"
SERVICE_RESULT_STATES = (
    "success|resources|protocol|timeout|exit-code|signal|core-dump|watchdog|start-limit-hit|oom-kill|"
    "dependency|exec-condition|assert|skipped"
)
STARTUP_UNITS = (
    "atlaso.service", "atlaso-worker.service", "atlaso-bootstrap-https.service",
    "atlaso-data-disks.service", "atlaso-guest-agent-select.service", "atlaso-wan.service",
    "systemd-networkd-wait-online.service",
)
JOURNAL_SIGNALS = {
    "dependency failed": "dependency_failed",
    "start request repeated too quickly": "start_limit",
    "timed out": "timeout",
    "permission denied": "permission_denied",
    "no space left on device": "disk_full",
    "read-only file system": "read_only_file_system",
    "address already in use": "address_in_use",
    "no such file or directory": "missing_file",
    "modulenotfounderror": "missing_python_module",
    "importerror": "python_import_error",
    "traceback": "python_traceback",
}


class AcceptanceError(RuntimeError):
    """Represent a failed release VM acceptance checkpoint."""


class ScreenTimeout(AcceptanceError):
    """Represent an expected console response that OCR did not recognize in time."""


@dataclass
class FailureEvidence:
    """Retain only fixed labels, allowlisted service states and bounded status codes."""

    checkpoint: str = "prepare VM fixture"
    boot_screen: str | None = None
    qemu_exited: bool | None = None
    service_states: dict[str, list[str]] = field(default_factory=dict)
    units: dict[str, str] = field(default_factory=dict)
    unit_result: str | None = None
    exec_main_status: int | None = None
    journal_signals: list[str] = field(default_factory=list)
    collection: str = "not_attempted"

    def record_state(self, unit: str, state: str) -> None:
        """Record and log changed, normalized observations, keeping the last eight per unit.

        Args:
            unit: Atlaso systemd unit being checked.
            state: Allowlisted service or recognition state.
        """
        states = self.service_states.setdefault(unit, [])
        if not states or states[-1] != state:
            states.append(state)
            del states[:-8]
            print(f"{unit} state: {state}", flush=True)

    def write(self, receipt: Path, args: argparse.Namespace) -> None:
        """Seal a separate failure record after exact media and fixture admission.

        Args:
            receipt: Planned success receipt path used to derive the failure record path.
            args: Validated version, commit and ISO digest options.
        """
        write_new_json(failure_path(receipt), {
            "schema": 1,
            "kind": "atlaso-vm-acceptance-failure",
            "version": args.version,
            "commit": args.commit,
            "iso_sha256": args.sha256,
            **vars(self),
        })


def failure_path(receipt: Path) -> Path:
    """Return the diagnostic destination, separate from the publishable success receipt.

    Args:
        receipt: Planned success receipt path.
    """
    return receipt.with_name(receipt.stem + "-failure.json")


def fixture_intent(output: Path, receipt: Path, version: str, commit: str, iso_sha256: str) -> dict[str, Any]:
    """Capture output-directory identity before launching a VM process.

    Args:
        output: New directory that will own the VM fixture.
        receipt: Destination for the eventual acceptance receipt.
        version: Expected installed Atlaso version.
        commit: Expected installed source commit.
        iso_sha256: SHA-256 of the exact verified installation image.
    """
    info = output.stat(follow_symlinks=False)
    if not output.is_dir() or output.is_symlink():
        raise AcceptanceError("VM output root must be a newly created ordinary directory")
    return {
        "schema": 1,
        "kind": "atlaso-qemu-vm-fixture",
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "task": os.environ.get("GITHUB_RUN_ID") or os.environ.get("CODEX_THREAD_ID", ""),
        "version": version,
        "commit": commit,
        "iso_sha256": iso_sha256,
        "output": str(output),
        "output_identity": {"device": info.st_dev, "inode": info.st_ino},
        "receipt": str(receipt),
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    """Publish a durable JSON record without replacing an existing file.

    Args:
        path: New file to create exclusively.
        value: JSON record to serialize.
    """
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def require_inputs(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, dict[str, str]]:
    """Validate immutable inputs and absent task-owned output paths.

    Args:
        args: Parsed CLI options for the exact media and disposable fixture.
    """
    if not VERSION.fullmatch(args.version) or not COMMIT.fullmatch(args.commit):
        raise AcceptanceError("release version or source commit is malformed")
    if not SHA256.fullmatch(args.sha256):
        raise AcceptanceError("ISO SHA-256 is malformed")
    iso = Path(args.iso).absolute()
    if digest(iso) != args.sha256:
        raise AcceptanceError("installer ISO is not the expected immutable file")

    output = Path(args.output).absolute()
    receipt = Path(args.receipt).absolute()
    if not output.parent.is_dir() or not receipt.parent.is_dir():
        raise AcceptanceError("VM output and receipt parents must already exist")
    if shutil.disk_usage(output.parent).free < MINIMUM_FREE_BYTES:
        raise AcceptanceError("at least 16 GiB of runner space must remain after ISO reconstruction")
    intent = receipt.with_name(receipt.name + ".fixture-intent.json")
    if any(path.exists() or path.is_symlink() for path in (output, receipt, intent, failure_path(receipt))):
        raise AcceptanceError("VM output, receipt, ownership intent, and failure destinations must be absent")
    if receipt.parent == output or output == receipt or receipt.is_relative_to(output):
        raise AcceptanceError("durable VM receipt must be outside the disposable output root")
    socket_name = f"atlaso-{'0' * 32}-install-qmp.sock"
    if not args.abstract_sockets and len(os.fsencode(output / socket_name)) >= 108:
        raise AcceptanceError("VM control sockets exceed the supported local path length")
    if output.resolve(strict=False) == iso or output.resolve(strict=False) in iso.parents:
        raise AcceptanceError("VM output root overlaps the verified ISO")

    passwords = json.loads(sys.stdin.read(8192))
    if not isinstance(passwords, dict) or set(passwords) != {"admin", "root"}:
        raise AcceptanceError("credential input must contain admin and root values")
    for account, value in passwords.items():
        if not isinstance(value, str) or not value or len(value) > 512 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise AcceptanceError(f"{account} credential is outside the supported concealed-input range")

    for tool in ("qemu-system-x86_64", "qemu-img", "tesseract"):
        if shutil.which(tool) is None:
            raise AcceptanceError(f"required QEMU acceptance tool is unavailable: {tool}")
    if args.accelerator == "kvm" and (not Path("/dev/kvm").exists() or not os.access("/dev/kvm", os.R_OK | os.W_OK)):
        raise AcceptanceError("requested KVM acceleration is unavailable on this runner")
    ovmf_directory = Path(args.ovmf_directory)
    ovmf_code = ovmf_directory / "OVMF_CODE_4M.fd"
    ovmf_vars = ovmf_directory / "OVMF_VARS_4M.fd"
    if not ovmf_code.is_file() or not ovmf_vars.is_file():
        ovmf_code = ovmf_directory / "OVMF_CODE.fd"
        ovmf_vars = ovmf_directory / "OVMF_VARS.fd"
    if not ovmf_code.is_file() or not ovmf_vars.is_file():
        raise AcceptanceError("UEFI firmware files are unavailable on the hosted VM runner")
    args._ovmf_code = ovmf_code
    args._ovmf_vars = ovmf_vars
    output.mkdir()
    write_new_json(intent, fixture_intent(output, receipt, args.version, args.commit, args.sha256))
    return iso, output, receipt, intent, passwords


class Qmp:
    """Minimal QMP connection with a finite deadline for every reply."""

    def __init__(self, address: str, process: subprocess.Popen[bytes], *, abstract: bool):
        """Connect to the verified VM process.

        Args:
            address: Path or abstract name of the QMP socket.
            process: Exact QEMU subprocess that owns the fixture.
            abstract: Connect to a Linux abstract socket instead of a filesystem path.
        """
        self.address = address
        self.abstract = abstract
        self.process = process
        self.guest_requested_reboot = False
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AcceptanceError("QEMU stopped before its control socket opened")
            try:
                self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.connection.settimeout(90)
                self.connection.connect("\0" + address if abstract else address)
                peer_pid = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                if int.from_bytes(peer_pid[:4], byteorder=sys.byteorder, signed=True) != process.pid:
                    raise AcceptanceError("QEMU control socket peer differs from the exact VM process")
                self.stream = self.connection.makefile("rwb", buffering=0)
                self._read()
                self.execute("qmp_capabilities")
                return
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.25)
        raise AcceptanceError("QEMU control socket did not open before its deadline")

    def _read(self) -> dict[str, Any]:
        raw = self.stream.readline(1024 * 1024)
        if not raw or len(raw) >= 1024 * 1024:
            raise AcceptanceError("QEMU control reply was empty or exceeded its bound")
        value = json.loads(raw)
        if "error" in value:
            raise AcceptanceError("QEMU rejected a bounded acceptance command")
        return value

    def execute(self, command: str, arguments: dict[str, Any] | None = None) -> Any:
        """Send a QMP command and consume events until it replies.

        Args:
            command: QMP command name.
            arguments: Optional command-specific arguments.
        """
        request: dict[str, Any] = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request, separators=(",", ":")).encode() + b"\r\n")
        while True:
            response = self._read()
            if "return" in response:
                return response["return"]
            if "event" not in response:
                raise AcceptanceError("QEMU returned an unexpected control response")
            if response["event"] == "SHUTDOWN":
                data = response.get("data", {})
                self.guest_requested_reboot = data.get("guest") is True and data.get("reason") == "guest-reset"

    def send_key(self, *keys: str) -> None:
        """Send a key chord with a bounded hold time.

        Args:
            *keys: QEMU key codes pressed together.
        """
        self.execute(
            "send-key",
            {"keys": [{"type": "qcode", "data": key} for key in keys], "hold-time": 75},
        )
        time.sleep(0.1)

    def read_network_records(self, token: str, deadline: float, terminal: str) -> list[str]:
        """Read bounded UTF-8 records from the disk-only VM's in-memory COM2 ring buffer.

        Args:
            token: Per-check random token that binds records to this probe attempt.
            deadline: Monotonic deadline for collecting the complete fixed result.
            terminal: Exact token-bound record that ends this read.
        """
        pattern = re.compile(rf"ATLASO-PROBE:{re.escape(token)}:(?:READY|[1-5]:(?:PASS|FAIL)|DONE|EXIT:[0-9]{{1,3}})\Z")
        return self._read_ring_records(
            deadline,
            pattern,
            lambda record: record == f"ATLASO-PROBE:{token}:{terminal}"
            or (terminal == "EXIT" and record.startswith(f"ATLASO-PROBE:{token}:EXIT:")),
            "network diagnostic",
        )

    def read_service_records(self, token: str, deadline: float) -> list[str]:
        """Read token-bound, allowlisted service observations from the VM's COM2 ring buffer.

        Args:
            token: Per-service check token.
            deadline: Monotonic deadline for collecting the terminal record.
        """
        pattern = re.compile(
            rf"ATLASO-SERVICE:{re.escape(token)}:(?:READY|DONE|"
            rf"(?:APP|WORKER):(?:atlaso\.service|atlaso-worker\.service|-):(?:{SERVICE_STATES}):"
            rf"(?:{SERVICE_RESULT_STATES}|-):(?:[0-9]{{1,3}}|-))\Z"
        )
        return self._read_ring_records(
            deadline, pattern, lambda record: record == f"ATLASO-SERVICE:{token}:DONE", "service state",
        )

    def _read_serial_chunk(self, size: int) -> bytes:
        """Consume up to size bytes from COM2 without exposing the guest payload.

        Args:
            size: Maximum decoded byte count requested from QEMU.
        """
        encoded = self.execute("ringbuf-read", {"device": NETWORK_RINGBUF, "size": size, "format": "base64"})
        if not isinstance(encoded, str):
            raise AcceptanceError("QEMU returned an unexpected serial buffer response type")
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise AcceptanceError("QEMU returned an invalid base64 serial buffer response") from None
        if len(chunk) > size:
            raise AcceptanceError("QEMU returned more serial bytes than requested")
        return chunk

    def discard_serial_boot_output(self) -> int:
        """Consume the whole COM2 backlog in one read before the first guest challenge."""
        return len(self._read_serial_chunk(NETWORK_RINGBUF_BYTES))

    def _read_ring_records(
        self,
        deadline: float,
        pattern: re.Pattern[str],
        is_terminal: Callable[[str], bool],
        label: str,
    ) -> list[str]:
        """Read bounded, newline-delimited records for one token from the in-memory COM2 ring buffer.

        Args:
            deadline: Monotonic deadline for collecting the terminal record.
            pattern: Record allowlist for this protocol.
            is_terminal: Predicate for its final record.
            label: Fixed public channel name for validation errors.
        """
        records: list[str] = []
        pending = bytearray()
        received = 0
        while time.monotonic() < deadline:
            chunk = self._read_serial_chunk(NETWORK_RINGBUF_READ_BYTES)
            if chunk:
                received += len(chunk)
                if received > NETWORK_RINGBUF_BYTES:
                    raise AcceptanceError(f"{label} records exceeded their fixed buffer")
                pending.extend(chunk)
                while b"\n" in pending:
                    raw, _, remaining = pending.partition(b"\n")
                    pending = bytearray(remaining)
                    try:
                        record = raw.decode("ascii").removesuffix("\r")
                    except UnicodeDecodeError:
                        raise AcceptanceError(f"QEMU returned a non-ASCII {label} record") from None
                    if not pattern.fullmatch(record):
                        raise AcceptanceError(f"QEMU returned an invalid {label} record")
                    records.append(record)
                    if is_terminal(record):
                        if pending:
                            raise AcceptanceError(f"QEMU returned records after {label} completion")
                        return records
                    if label == "network diagnostic" and ":EXIT:" in record:
                        raise AcceptanceError("the guest returned a network diagnostic exit before readiness")
            else:
                time.sleep(0.25)
        raise ScreenTimeout(f"the guest did not return complete {label} records")

    def close(self) -> None:
        self.stream.close()
        self.connection.close()


def key_events(text: str) -> list[list[str]]:
    """Convert the admitted printable credential alphabet into QEMU key chords.

    Args:
        text: Text to translate through the supported guest keyboard layout.
    """
    shifted = {
        "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
        "*": "8", "(": "9", ")": "0", "_": "minus", "+": "equal", "{": "bracket_left",
        "}": "bracket_right", "|": "backslash", ":": "semicolon", '"': "apostrophe",
        "~": "grave_accent", "<": "comma", ">": "dot", "?": "slash",
    }
    plain = {
        " ": "spc",
        "-": "minus", "=": "equal", "[": "bracket_left", "]": "bracket_right",
        "\\": "backslash", ";": "semicolon", "'": "apostrophe", "`": "grave_accent",
        ",": "comma", ".": "dot", "/": "slash",
    }
    result = []
    for character in text:
        if "a" <= character <= "z" or "0" <= character <= "9":
            result.append([character])
        elif "A" <= character <= "Z":
            result.append(["shift", character.lower()])
        elif character in shifted:
            result.append(["shift", shifted[character]])
        elif character in plain:
            result.append([plain[character]])
        else:
            raise AcceptanceError("credential includes a character the VM keyboard cannot enter")
    return result


def type_text(qmp: Qmp, value: str) -> None:
    """Type a complete line through the guest keyboard.

    Args:
        qmp: Control connection for the selected fixture.
        value: Text to type before submitting the line.
    """
    for chord in key_events(value):
        qmp.send_key(*chord)
    qmp.send_key("ret")


def restore_highlighted_text(rows: list[bytearray]) -> None:
    """Restore dark glyphs where the Photon console reverses a selected field.

    Args:
        rows: Cropped rows with one for dark pixels and zero for light pixels.
    """
    width = len(rows[0])
    runs = re.compile(rb"\x01{%d,}" % max(24, width // 5))
    scanlines: dict[tuple[int, int], list[int]] = {}
    for y, row in enumerate(rows):
        for run in runs.finditer(row):
            if run.start() > 0 and run.end() < width:
                scanlines.setdefault(run.span(), []).append(y)

    occupied: set[int] = set()
    invert = bytes.maketrans(b"\x00\x01", b"\x01\x00")
    for left, right in sorted(scanlines, key=lambda bounds: bounds[0] - bounds[1]):
        matches = scanlines[left, right]
        top, bottom = matches[0], matches[-1]
        band = range(top, bottom + 1)
        # A selected VGA line has solid dark top and bottom scanlines.
        if not 5 <= bottom - top <= 31 or occupied.intersection(band):
            continue
        for y in band:
            rows[y][left:right] = rows[y][left:right].translate(invert)
        occupied.update(band)


def preprocess_ppm(raw: bytes, *, storage_layout: bool = False) -> tuple[bytes, bool]:
    """Crop the neutral-gray Photon dialog and enlarge it for reliable OCR.

    Full-frame QEMU screenshots are mostly blue background. The installer window
    uses a broad, low-chroma gray fill, so its rows and columns provide a stable
    crop even when the selected row changes color. Frames without that panel,
    such as the GRUB menu, retain the full image and use sparse-text OCR.

    Args:
        raw: Bytes of a raw RGB PPM screenshot returned by QMP.
        storage_layout: Restore reverse-video text and enlarge storage fields.
    """
    header = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255\s", raw)
    if header is None:
        raise AcceptanceError("QEMU screenshot is not a supported RGB PPM image")
    width, height = (int(header.group(1)), int(header.group(2)))
    pixels = raw[header.end():]
    if not (0 < width <= 4096 and 0 < height <= 4096) or len(pixels) != width * height * 3:
        raise AcceptanceError("QEMU screenshot dimensions or RGB data are invalid")

    row_threshold = max(12, width // 5)
    column_threshold = max(12, height // 8)
    row_counts = [0] * height
    column_counts = [0] * width
    for index in range(width * height):
        offset = index * 3
        red, green, blue = pixels[offset], pixels[offset + 1], pixels[offset + 2]
        if 128 <= red <= 224 and 128 <= green <= 224 and 128 <= blue <= 224 and max(red, green, blue) - min(red, green, blue) <= 16:
            row_counts[index // width] += 1
            column_counts[index % width] += 1

    active_rows = [index for index, count in enumerate(row_counts) if count >= row_threshold]
    active_columns = [index for index, count in enumerate(column_counts) if count >= column_threshold]
    cropped = bool(active_rows and active_columns)
    if cropped:
        left, right = max(0, active_columns[0] - 12), min(width, active_columns[-1] + 13)
        top, bottom = max(0, active_rows[0] - 12), min(height, active_rows[-1] + 13)
    else:
        left, top, right, bottom = 0, 0, width, height

    crop_width, crop_height = right - left, bottom - top
    scale = 3 if cropped else 2
    if cropped and storage_layout and max(crop_width, crop_height) <= 1024:
        scale = 5
    enlarged_width, enlarged_height = crop_width * scale, crop_height * scale
    enlarged = bytearray(enlarged_width * enlarged_height * 3)
    dark_rows = []
    if cropped:
        for y in range(top, bottom):
            start = (y * width + left) * 3
            line = pixels[start:start + crop_width * 3]
            dark_rows.append(bytearray(
                max(line[index:index + 3]) <= 96 for index in range(0, len(line), 3)
            ))
        if storage_layout:
            restore_highlighted_text(dark_rows)
    for y in range(crop_height):
        source = ((top + y) * width + left) * 3
        line = pixels[source:source + crop_width * 3]
        if cropped:
            expanded = b"".join(
                (b"\0\0\0" if dark else b"\xff\xff\xff") * scale for dark in dark_rows[y]
            )
        else:
            expanded = b"".join(line[index:index + 3] * scale for index in range(0, len(line), 3))
        row_start = y * scale * enlarged_width * 3
        for repeat in range(scale):
            start = row_start + repeat * enlarged_width * 3
            enlarged[start:start + len(expanded)] = expanded
    ppm = f"P6\n{enlarged_width} {enlarged_height}\n255\n".encode("ascii") + enlarged
    return ppm, cropped


def screen_text(qmp: Qmp, directory: Path) -> str:
    """OCR one transient QMP frame without retaining or logging guest pixels.

    Args:
        qmp: Control connection for the selected fixture.
        directory: Fixture directory used for transient image files.
    """
    image = directory / f"frame-{uuid.uuid4().hex}.ppm"
    prepared = directory / f"frame-{uuid.uuid4().hex}-ocr.ppm"
    try:
        qmp.execute("screendump", {"filename": str(image), "format": "ppm"})
        raw = image.read_bytes()
        for storage_layout in (False, True):
            prepared_bytes, cropped = preprocess_ppm(raw, storage_layout=storage_layout)
            prepared.write_bytes(prepared_bytes)
            result = subprocess.run(
                ["tesseract", str(prepared), "stdout", "--psm", "6" if cropped else "11"],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
                env={**os.environ, "OMP_THREAD_LIMIT": "1"},
            )
            if result.returncode:
                print(f"Console OCR could not read a frame (exit {result.returncode}).", flush=True)
                return ""
            if len(result.stdout) > 32768:
                raise AcceptanceError("guest screen text exceeded its fixed bound")
            if storage_layout or "storage layout" not in result.stdout.casefold():
                return result.stdout
            if is_combined_storage_layout_screen(result.stdout):
                return result.stdout
        return ""
    except subprocess.TimeoutExpired:
        print("Console OCR timed out on a frame.", flush=True)
        return ""
    finally:
        image.unlink(missing_ok=True)
        prepared.unlink(missing_ok=True)


def wait_screen(qmp: Qmp, directory: Path, predicate, label: str, seconds: float) -> str:
    """Wait for the expected guest checkpoint within its deadline.

    Args:
        qmp: Control connection for the selected fixture.
        directory: Fixture directory used for transient image files.
        predicate: Callable that accepts OCR text for the requested screen.
        label: Public checkpoint name to use in logs.
        seconds: Maximum time to wait for the checkpoint.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if qmp.process.poll() is not None:
            raise AcceptanceError("QEMU exited during the installation checkpoint")
        text = screen_text(qmp, directory)
        if predicate(text):
            print(f"Reached {label}.", flush=True)
            return text
        time.sleep(2)
    raise ScreenTimeout(f"guest did not reach the expected {label} screen")


def is_disk_selection_screen(text: str) -> bool:
    """Recognize the case-insensitive, OCR-rendered native selector heading.

    Args:
        text: Recognized text from the current installer screen.
    """
    return "select a disk" in text.casefold()


def is_combined_storage_layout_screen(text: str) -> bool:
    """Recognize the combined native storage page and each fixed role mount.

    Args:
        text: OCR text from one native Photon installer frame.
    """
    folded = text.casefold()
    mounts = re.findall(r"(?im)^[ \t]*(?:x|\|)?[ \t]*mount[ \t]*:[ \t]*(.+)$", folded)
    # Console OCR sometimes inserts spaces in a mount word or reads a VGA
    # hyphen as a dash. Keep the role order and the full path checks.
    mounts = [
        re.sub(r"[-–—]+", "-", re.sub(r"\s+", "", mount.rstrip().removesuffix("|").removesuffix(" x")))
        for mount in mounts
    ]
    return (
        "storage layout" in folded
        and all(re.search(pattern, text, re.I) is not None for pattern in STORAGE_LAYOUT_LABELS)
        and len(mounts) == len(STORAGE_LAYOUT_MOUNTS)
        and all(re.fullmatch(pattern, mount) for pattern, mount in zip(STORAGE_LAYOUT_MOUNTS, mounts, strict=True))
        and len(re.findall(r"(?im)^[ \t]*(?:x|\|)?[ \t]*volume[ \t]*:", text)) >= 3
        and storage_layout_root_disk(text) is not None
        and re.search(r"\b(auto|custom)\b", storage_layout_root_section(folded)) is not None
    )


def storage_layout_root_section(text: str) -> str:
    """Extract the displayed root assignment without relying on screen position.

    Args:
        text: OCR text from the combined native storage page.
    """
    folded = text.casefold()
    root_start = folded.find("root installation target")
    service_start = folded.find("sftp backup storage")
    if root_start < 0 or service_start <= root_start:
        return ""
    return text[root_start:service_start]


def is_auto_storage_layout_screen(text: str) -> bool:
    """Recognize the Auto layout after returning from the Custom editor.

    Args:
        text: OCR text from the combined native storage page.
    """
    return is_combined_storage_layout_screen(text) and re.search(
        r"\bauto\b", storage_layout_root_section(text), re.I,
    ) is not None


def initial_installer_screen(text: str) -> bool:
    """Recognize either current combined entry or a published disk selector.

    Args:
        text: OCR text from the first post-menu native installer page.
    """
    return is_combined_storage_layout_screen(text) or is_disk_selection_screen(text)


def storage_layout_root_disk(text: str) -> str | None:
    """Return the assigned root device shown on the combined storage page.

    Args:
        text: OCR text from the combined native storage page.
    """
    match = STORAGE_ROOT_DISK.search(storage_layout_root_section(text))
    return match.group(0).replace("/deu/", "/dev/") if match else None


def is_storage_layout_or_legacy_choice(text: str) -> bool:
    """Recognize the current combined page and the first published service page.

    Args:
        text: OCR text from one native Photon installer frame.
    """
    if "storage layout" in text.casefold():
        return is_combined_storage_layout_screen(text)
    return re.search(r"\bsftp backup storage\b", text, re.I) is not None


def is_custom_partition_editor_screen(text: str) -> bool:
    """Recognize Photon's editor after entering Custom from Storage layout.

    Args:
        text: OCR text from one native Photon installer frame.
    """
    folded = text.casefold()
    return "current partitions" in folded and "go back" in folded


def configure_storage_assignments(
    qmp: Qmp, output: Path, expected_root_disk: str, initial_screen: str | None = None,
    *, evidence: FailureEvidence | None = None,
) -> None:
    """Continue through the combined storage page or older sequential prompts.

    Args:
        qmp: Control connection for the disconnected installation fixture.
        output: Fixture directory used for transient screen observations.
        expected_root_disk: Exact device that the final review must erase.
        initial_screen: Already-observed combined page or legacy SFTP prompt.
        evidence: Hosted acceptance failure checkpoints, when collected.
    """
    screen = initial_screen or wait_screen(
        qmp, output, is_storage_layout_or_legacy_choice, "installer storage layout", 180,
    )
    if is_combined_storage_layout_screen(screen):
        for _ in range(2):
            if storage_layout_root_disk(screen) == expected_root_disk:
                break
            qmp.send_key("d")
            screen = wait_screen(
                qmp, output, is_combined_storage_layout_screen, "root installation target", 30,
            )
        if storage_layout_root_disk(screen) != expected_root_disk:
            raise AcceptanceError("combined storage layout did not select the exact 64 GiB installation target")
        if not is_auto_storage_layout_screen(screen):
            raise AcceptanceError("the disconnected Auto fixture did not begin in Auto layout mode")
        qmp.send_key("l")
        wait_screen(qmp, output, is_custom_partition_editor_screen, "Custom partition editor", 60)
        # Photon's native editor returns through its Back action.
        for key in ("left", "left", "ret"):
            qmp.send_key(key)
        screen = wait_screen(qmp, output, is_auto_storage_layout_screen, "Auto storage layout after Custom", 60)
        if storage_layout_root_disk(screen) != expected_root_disk:
            raise AcceptanceError("returning from Custom changed the selected Auto root device")
        for label in ("SFTP backup storage", "VCFDT depot storage"):
            if evidence is not None:
                evidence.checkpoint = label
            qmp.send_key("tab")
            wait_screen(
                qmp, output, is_combined_storage_layout_screen, f"combined {label} assignment", 30,
            )
        qmp.send_key("ret")
        return

    if evidence is not None:
        evidence.checkpoint = "VCFDT depot storage"
    qmp.send_key("ret")
    wait_screen(
        qmp, output,
        lambda text: re.search(r"\bvy?cfdt depot storage\b", text, re.I) is not None,
        "legacy VCFDT depot storage", 180,
    )
    qmp.send_key("ret")


def is_credential_prompt(text: str, account: str, confirmation: bool) -> bool:
    """Recognize only the expected concealed field in the signed installer sequence.

    Args:
        text: Recognized text from the current installer screen.
        account: Account name expected in the prompt.
        confirmation: Match the confirmation prompt when true.
    """
    action = r"confir[mn]" if confirmation else "set"
    return re.search(rf"\b{action} {re.escape(account)} pass[wu]ord\b", text, re.I) is not None


def enter_installer_passwords(qmp: Qmp, output: Path, passwords: dict[str, str]) -> None:
    """Enter credentials after recognizing either supported installer layout.

    Args:
        qmp: Control connection for the disconnected installer fixture.
        output: Fixture directory used for transient screen observations.
        passwords: Dedicated administrator and root passwords for the fixture.
    """
    def is_account_form(text: str) -> bool:
        """Recognize the full new form before entering any credential.

        Args:
            text: Recognized text from the current installer screen.
        """
        return all(re.search(pattern, text, re.I) for pattern in (
            r"account pass[wu]ords",
            r"confir[mn] ad[mn]in pass[wu]ord",
            r"confir[mn] root pass[wu]ord",
            r"continue",
        ))

    screen = wait_screen(
        qmp, output, lambda text: is_account_form(text) or is_credential_prompt(text, "admin", False),
        "concealed installer credential", 180,
    )
    if is_account_form(screen):
        for account in ("admin", "root"):
            type_text(qmp, passwords[account])
            type_text(qmp, passwords[account])
        qmp.send_key("ret")
        return

    for account, confirmation in (("admin", False), ("admin", True), ("root", False), ("root", True)):
        if (account, confirmation) != ("admin", False):
            wait_screen(
                qmp, output,
                lambda text, account=account, confirmation=confirmation: is_credential_prompt(text, account, confirmation),
                "concealed installer credential", 180,
            )
        type_text(qmp, passwords[account])


def wait_for_installer_reboot(qmp: Qmp, output: Path, deadline: float) -> None:
    """Wait for the successful installer's own reset before disconnecting its media.

    Args:
        qmp: Control connection for the installer fixture.
        output: Fixture directory used for transient image files.
        deadline: Absolute deadline on the monotonic clock.
    """
    while time.monotonic() < deadline:
        status = qmp.execute("query-status")["status"]
        if status == "shutdown" and qmp.guest_requested_reboot:
            print("The offline installer finished and requested its reboot.", flush=True)
            return
        if status != "running":
            raise AcceptanceError("the installer stopped without a guest-requested reboot")
        screen = screen_text(qmp, output).casefold()
        if "installation cancelled or failed" in screen or "kernel panic" in screen:
            raise AcceptanceError("the offline installer reported failure before reboot")
        time.sleep(4)
    raise AcceptanceError("the offline installer did not reboot before its deadline")


def start_qemu(
    iso: Path | None,
    output: Path,
    disk: Path,
    ovmf_vars: Path,
    ovmf_code: Path,
    socket_name: str,
    *,
    abstract_sockets: bool,
    accelerator: str,
) -> tuple[subprocess.Popen[bytes], Qmp]:
    """Start a UEFI fixture with an offline installer and isolated boot networking.

    Args:
        iso: Installation ISO to attach, or None for a disk-only boot.
        output: Owned directory containing the VM fixture files.
        disk: Writable target disk to attach.
        ovmf_vars: Writable UEFI variable store for this fixture.
        ovmf_code: Read-only UEFI firmware image.
        socket_name: Suffix identifying this boot's control socket.
        abstract_sockets: Use a Linux abstract control socket.
        accelerator: Select KVM, TCG, or automatic host capability detection.
    """
    unique = f"atlaso-{uuid.uuid4().hex}-{socket_name}"
    control = unique if abstract_sockets else str(output / f"{unique}.sock")
    acceleration = accelerator
    if accelerator == "auto":
        acceleration = "kvm" if Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    command = [
        "qemu-system-x86_64", "-name", "atlaso-installation-acceptance", "-machine", f"q35,accel={acceleration}",
        "-cpu", "host" if acceleration == "kvm" else "max", "-smp", "2", "-m", "4096", "-display", "none",
        "-vga", "std" if iso is not None else "virtio",
        "-no-reboot", "-no-shutdown", "-rtc", "base=utc,clock=host",
        "-S", "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive", f"if=pflash,format=raw,file={ovmf_vars}",
        "-boot", f"order={'d' if iso is not None else 'c'}",
        "-device", "virtio-scsi-pci,id=scsi0",
        "-drive", f"if=none,id=target,file={disk},format=qcow2",
        "-device", "scsi-hd,drive=target,bus=scsi0.0,channel=0,scsi-id=0,lun=0",
        "-drive", f"if=none,id=decoy,file={output / 'atlaso-unselected.qcow2'},format=qcow2",
        "-device", "scsi-hd,drive=decoy,bus=scsi0.0,channel=0,scsi-id=1,lun=0",
        "-netdev", "user,id=net0,restrict=on", "-device", "e1000,id=atlaso-eth0,netdev=net0,romfile=",
        "-qmp", f"unix:{control},abstract=on,server=on,wait=off" if abstract_sockets else f"unix:{control},server=on,wait=off",
    ]
    if iso is not None:
        command.extend([
            "-drive", f"if=none,id=cdrom,media=cdrom,readonly=on,file={iso}",
            "-device", "scsi-cd,drive=cdrom,bus=scsi0.0,channel=0,scsi-id=2,lun=0",
        ])
    else:
        command.extend([
            "-chardev", f"ringbuf,id={NETWORK_RINGBUF},size={NETWORK_RINGBUF_BYTES}",
            "-device", f"isa-serial,chardev={NETWORK_RINGBUF},index=1",
        ])
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    qmp = None
    try:
        qmp = Qmp(control, process, abstract=abstract_sockets)
        qmp.execute("set_link", {"name": "atlaso-eth0", "up": iso is None})
        qmp.execute("cont")
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
    return process, qmp


def stop_qemu(process: subprocess.Popen[bytes], qmp: Qmp) -> None:
    """Stop the exact fixture and verify its exit status.

    Args:
        process: QEMU subprocess launched for this boot.
        qmp: Control connection to close before stopping QEMU.
    """
    qmp.close()
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=20)
    if process.returncode not in (0, -15, 143):
        raise AcceptanceError("QEMU did not stop cleanly at the acceptance boundary")


def installed_console_ready(text: str) -> bool:
    """Recognize the appliance dashboard after the disk-only boot.

    Args:
        text: Recognized text from the disk-only guest console.
    """
    text = text.casefold()
    return "manage this appliance at" in text or (
        "atlaso appliance" in text and re.search(r"\bf4[^\n]{0,14}console", text) is not None
    )


def installed_login_prompt(text: str) -> bool:
    """Admit only the ordinary Photon login on the selected virtual terminal.

    Args:
        text: Recognized text from the selected Photon virtual terminal.
    """
    return re.search(r"\btty2\b", text, re.I) is not None and re.search(r"(?im)^[ \t]*[\w.-]+ login:[ \t]*$", text) is not None


def observe_boot_console(text: str, evidence: FailureEvidence) -> bool:
    """Remember the last recognized pre-login boot screen without saving its text.

    Args:
        text: Transient OCR text from the boot console.
        evidence: Record that receives a fixed boot screen category.
    """
    if installed_console_ready(text):
        evidence.boot_screen = "atlaso_console"
        return True
    for pattern, screen in (
        (r"kernel panic", "kernel_panic"),
        (r"emergency mode|dracut:/#", "emergency_shell"),
        (r"no bootable device|boot failed|uefi interactive shell", "firmware_boot_error"),
        (r"grub|photon os.*boot", "bootloader"),
        (r"\blogin:", "linux_login"),
        (r"a start job is running|\bstarting\b|\bstarted\b", "linux_startup"),
    ):
        if re.search(pattern, text, re.I):
            evidence.boot_screen = screen
            break
    return False


def run_console_command(qmp: Qmp, command: str) -> None:
    """Clear the authenticated shell frame before each independently checked command.

    Args:
        qmp: Control connection for the authenticated guest.
        command: Read-only shell command or its local variable setup.
    """
    qmp.send_key("ctrl", "l")
    type_text(qmp, command)


def installed_identity_command(attribute: str, expected_name: str) -> str:
    """Compare the release identity inside the guest to avoid OCR of a full source SHA.

    Args:
        attribute: Atlaso metadata attribute to compare.
        expected_name: Name of the guest shell environment variable holding the expected value.
    """
    return f"$P -BI -c 'import atlaso as a,os;print(a.{attribute}==os.getenv(\"{expected_name}\"))'"


def collect_service_failure(qmp: Qmp, output: Path, service: str, evidence: FailureEvidence) -> None:
    """Summarize a fixed set of startup units and classify recent warnings from the failing unit.

    Args:
        qmp: Control connection to the authenticated guest.
        output: Fixture directory used for transient console frames.
        service: Atlaso systemd unit that failed to confirm activation.
        evidence: Record that receives allowlisted unit and journal observations.
    """
    units = " ".join(STARTUP_UNITS)
    try:
        run_console_command(
            qmp,
            f"systemctl list-units --all --plain --no-legend --no-pager {units} "
            "| awk '{print $1,$3}'; "
            f"systemctl show -p Result -p ExecMainStatus {service}; printf 'UNITS %s\\n' DONE",
        )
        end = re.compile(r"(?im)^[ \t]*UNITS DONE[ \t]*$")
        result = wait_screen(qmp, output, end.search, "startup unit diagnostics", 20)
        for unit in STARTUP_UNITS:
            match = re.search(rf"(?im)^[ \t]*{re.escape(unit)}[ \t]+({ACTIVE_STATES})[ \t]*$", result)
            if match:
                evidence.units[unit] = match[1].casefold()
        match = re.search(
            r"(?im)^Result=(success|resources|protocol|timeout|exit-code|signal|core-dump|watchdog|"
            r"start-limit-hit|oom-kill|dependency|exec-condition|assert|skipped)[ \t]*$", result,
        )
        if match:
            evidence.unit_result = match[1].casefold()
        match = re.search(r"(?m)^ExecMainStatus=([0-9]{1,3})[ \t]*$", result)
        if match and int(match[1]) <= 255:
            evidence.exec_main_status = int(match[1])
        if not evidence.units and evidence.unit_result is None and evidence.exec_main_status is None:
            evidence.collection = "unit_summary_unavailable"
    except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError):
        evidence.collection = "unit_summary_unavailable"

    try:
        signals = "|".join(JOURNAL_SIGNALS)
        run_console_command(
            qmp,
            f"J=$(timeout 8 journalctl -b -u {service} -p warning -n 24 --no-pager -o cat 2>/dev/null); "
            "S=$?; if [ $S = 0 ]; then "
            f"printf '%s\\n' \"$J\" | grep -Eio '{signals}' | sort -fu; "
            "fi; printf 'JOURNAL %s\\n' \"$S\"; unset J S",
        )
        end = re.compile(r"(?im)^[ \t]*JOURNAL [0-9]{1,3}[ \t]*$")
        result = wait_screen(qmp, output, end.search, "startup journal diagnostics", 20)
        if not re.search(r"(?im)^[ \t]*JOURNAL 0[ \t]*$", result):
            raise AcceptanceError("the guest journal query did not complete")
        lines = {line.strip().casefold() for line in result.splitlines()}
        evidence.journal_signals = [code for text, code in JOURNAL_SIGNALS.items() if text in lines]
        if evidence.collection == "not_attempted":
            evidence.collection = "complete"
    except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError):
        evidence.collection = "journal_unavailable" if evidence.collection == "not_attempted" else "unavailable"


def service_observations(records: list[str], token: str, key: str, service: str) -> list[tuple[str, str, str]]:
    """Validate a complete reply before retaining any observation from it.

    Args:
        records: Serial reply lines in the order received.
        token: Challenge sent for this service check.
        key: Service label used by the guest probe, APP or WORKER.
        service: Expected systemd unit name.
    """
    prefix = f"ATLASO-SERVICE:{token}:"
    if len(records) < 3 or records[0] != prefix + "READY" or records[-1] != prefix + "DONE":
        raise AcceptanceError("the guest returned incomplete service state evidence")
    unavailable = f"{prefix}{key}:-:unrecognized:-:-"
    observation = re.compile(
        re.escape(f"{prefix}{key}:{service}:")
        + rf"({ACTIVE_STATES}):({SERVICE_RESULT_STATES}|-):([0-9]{{1,3}}|-)"
    )
    snapshots = []
    for index, record in enumerate(records[1:-1], 1):
        if record == unavailable:
            snapshots.append(("unrecognized", "-", "-"))
            continue
        match = observation.fullmatch(record)
        if match is None:
            raise AcceptanceError("the guest returned invalid service state evidence")
        state, result, status = match.groups()
        if status != "-" and int(status) > 255:
            raise AcceptanceError("the guest returned an invalid systemd exit status")
        if state == "active":
            if index != len(records) - 2:
                raise AcceptanceError("the guest returned service states after reporting active")
            if result == "-" or status == "-":
                raise AcceptanceError("the guest returned incomplete active systemd status")
        snapshots.append((state, result, status))
    return snapshots


def check_installed_services(qmp: Qmp, output: Path, evidence: FailureEvidence) -> None:
    """Require fresh serial-reported active states for both installed Atlaso services.

    Args:
        qmp: Control connection to the authenticated guest.
        output: Fixture directory used for transient console frames.
        evidence: Record that receives normalized service observations.
    """
    # Define the function once on the authenticated Bash console. Only the short
    # invocation for each unit is typed during its individual check.
    helper = r"""
        service_probe() {
            test -c /dev/ttyS1 && exec 3>/dev/ttyS1 || return 1;
            local prefix=ATLASO-SERVICE:$3 unit=$2 label=$1;
            printf '%s:READY\n' "$prefix" >&3;
            local stop=$((SECONDS+150)) remaining properties name value id state result status;
            while (( SECONDS < stop )); do
                remaining=$((stop-SECONDS)); (( remaining > 5 )) && remaining=5;
                id=; state=; result=; status=;
                if properties=$(timeout "$remaining" systemctl show -p Id -p ActiveState -p Result -p ExecMainStatus "$unit" 2>/dev/null); then
                    while IFS='=' read -r name value; do
                        case "$name" in
                            Id) id=$value ;;
                            ActiveState) state=$value ;;
                            Result) result=$value ;;
                            ExecMainStatus) status=$value ;;
                        esac;
                    done <<< "$properties";
                fi;
                (( SECONDS < stop )) || break;
                if [[ -z $id || -z $state || -z $result || -z $status ]]; then
                    id=-; state=unrecognized; result=-; status=-;
                fi;
                printf '%s:%s:%s:%s:%s:%s\n' "$prefix" "$label" "$id" "$state" "$result" "$status" >&3;
                [[ $id = "$unit" && $state = active ]] && break;
                remaining=$((stop-SECONDS)); (( remaining > 5 )) && remaining=5;
                (( remaining > 0 )) && sleep "$remaining";
            done;
            printf '%s:DONE\n' "$prefix" >&3;
        }
    """
    run_console_command(qmp, " ".join(line.strip() for line in helper.splitlines() if line.strip()))
    for key, service in zip(("APP", "WORKER"), STARTUP_UNITS[:2], strict=True):
        evidence.checkpoint = f"{service} active"
        token = uuid.uuid4().hex
        run_console_command(qmp, f"service_probe {key} {service} {token}")
        try:
            # The guest enforces 150 seconds for observations. Allow the final serial
            # records to arrive even when the hosted VM is slow to schedule.
            records = qmp.read_service_records(token, time.monotonic() + 165)
            snapshots = service_observations(records, token, key, service)
        except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError) as error:
            evidence.record_state(service, "unrecognized")
            collect_service_failure(qmp, output, service, evidence)
            raise AcceptanceError(f"{service} state could not be read in the media-free boot") from error

        for state, _, _ in snapshots:
            evidence.record_state(service, state)
        state, _, _ = snapshots[-1]
        if state == "active":
            continue

        collect_service_failure(qmp, output, service, evidence)
        # Keep the result and exit status from the same systemd snapshot.
        for observed, result, status in reversed(snapshots):
            if observed != "unrecognized":
                if result != "-":
                    evidence.unit_result = result
                if status != "-":
                    evidence.exec_main_status = int(status)
                break
        if state == "unrecognized":
            raise AcceptanceError(f"{service} state could not be read in the media-free boot")
        raise AcceptanceError(f"{service} remained {state} in the media-free boot")


def check_installed_network_diagnostics(qmp: Qmp, output: Path, evidence: FailureEvidence) -> None:
    """Require all offline network probes to pass under the installed service account.

    Args:
        qmp: Control connection to the authenticated guest.
        output: Fixture directory used for transient console frames.
        evidence: Failure record that receives the fixed checkpoint or probe name.
    """
    evidence.checkpoint = "network diagnostic channel readiness"
    token = uuid.uuid4().hex
    prefix = f"ATLASO-PROBE:{token}:"
    probes = [probe[1:] for probe in NETWORK_PROBES]
    program = textwrap.dedent(f"""\
        import os
        from atlaso.app.services.network_diagnostics import run_check

        with os.fdopen(3, "w", buffering=1, encoding="ascii") as result:
            passed_all = True
            for number, (kind, target, source, expected) in enumerate({probes!r}, 1):
                passed = run_check(kind, target, source, "auto").state == expected
                status = "PASS" if passed else "FAIL"
                print(f"{prefix}{{number}}:{{status}}", file=result)
                passed_all = passed_all and passed
            print("{prefix}DONE", file=result)
        raise SystemExit(0 if passed_all else 1)
        """).encode("ascii")
    encoded_program = base64.b64encode(program).decode("ascii")
    program_digest = hashlib.sha256(program).hexdigest()
    run_console_command(
        qmp,
        "test -c /dev/ttyS1 && exec 3>/dev/ttyS1 && "
        f"printf '%s\\n' {shlex.quote(prefix + 'READY')} >&3",
    )
    ready = qmp.read_network_records(token, time.monotonic() + 15, "READY")
    if ready != [prefix + "READY"]:
        raise AcceptanceError("the guest network diagnostic channel returned invalid readiness evidence")
    evidence.checkpoint = "installed network diagnostics"
    run_console_command(
        qmp,
        "timeout -k 2s 165s runuser -u atlaso -- env ATLASO_DRY_RUN_SYSTEM_ADAPTERS=false "
        f"$P -B -I -c \"import base64,hashlib; b=base64.b64decode('{encoded_program}',validate=True); "
        f"assert hashlib.sha256(b).hexdigest()=='{program_digest}'; "
        "exec(compile(b,'<atlaso-acceptance>','exec'))\" "
        "</dev/null >/dev/null 2>&1; S=$?; "
        f"printf 'ATLASO-PROBE:{token}:EXIT:%s\\n' \"$S\" >&3",
    )
    records = qmp.read_network_records(token, time.monotonic() + NETWORK_RESULT_SECONDS, "EXIT")
    if not records or not records[-1].startswith(prefix + "EXIT:"):
        raise AcceptanceError("the guest did not return complete network diagnostic records")
    exit_match = re.fullmatch(re.escape(prefix) + r"EXIT:([0-9]{1,3})", records[-1])
    if exit_match is None:
        raise AcceptanceError("the guest returned an invalid network diagnostic exit status")
    exit_code = int(exit_match[1])
    if records[-2:-1] != [prefix + "DONE"]:
        if exit_code in (124, 137):
            raise AcceptanceError("the installed network diagnostic process exceeded its execution deadline")
        raise AcceptanceError(f"the installed network diagnostic process exited before completing (exit {exit_code})")
    probe_records = records[:-2]
    if len(probe_records) != len(NETWORK_PROBES):
        raise AcceptanceError("the guest returned incomplete network diagnostic results")
    failures = []
    for number, (record, probe) in enumerate(zip(probe_records, NETWORK_PROBES, strict=True), 1):
        if record == f"{prefix}{number}:PASS":
            continue
        if record != f"{prefix}{number}:FAIL":
            raise AcceptanceError("the guest returned invalid network diagnostic results")
        failures.append(probe[0])
    if failures:
        evidence.checkpoint = f"installed network diagnostics: {failures[0]}"
        raise AcceptanceError(f"the installed Atlaso service account failed {failures[0]}")
    if exit_code != 0:
        raise AcceptanceError(f"the installed network diagnostic process exited unsuccessfully (exit {exit_code})")
    print("IPv4 and IPv6 loopback probes and localhost lookup verified.", flush=True)


def check_installed_application(qmp: Qmp, output: Path, version: str, commit: str, evidence: FailureEvidence) -> None:
    """Verify installed build metadata, services, and local diagnostic execution.

    Args:
        qmp: Control connection for the authenticated guest.
        output: Fixture directory used for transient image files.
        version: Expected installed Atlaso version.
        commit: Expected installed source commit.
        evidence: Sanitized failure information for the VM run.
    """
    for setup in ("P=/opt/atlaso/.venv/bin/python", f"export V={version}", f"export C={commit}"):
        run_console_command(qmp, setup)
    for attribute, expected_name, label in (
        ("__version__", "V", "installed Atlaso version"),
        ("__build_git_commit__", "C", "installed Atlaso source commit"),
    ):
        evidence.checkpoint = label
        run_console_command(qmp, installed_identity_command(attribute, expected_name))
        result = wait_screen(qmp, output, lambda text: re.search(r"(?im)^[ \t]*(true|false)[ \t]*$", text), label, 30)
        if not re.search(r"(?im)^[ \t]*true[ \t]*$", result):
            raise AcceptanceError(f"the {label} differs from the verified release")

    evidence.checkpoint = "clear serial boot output"
    discarded = qmp.discard_serial_boot_output()
    print(f"Discarded {discarded} serial boot bytes before the first guest challenge.", flush=True)
    check_installed_services(qmp, output, evidence)
    print("The installed version, source commit and both Atlaso services verified.", flush=True)

    if tuple(map(int, version.split("."))) >= FIRST_NETWORK_DIAGNOSTICS_VERSION:
        check_installed_network_diagnostics(qmp, output, evidence)


def verify_installed(
    qmp: Qmp, output: Path, version: str, commit: str, password: str, evidence: FailureEvidence,
) -> None:
    """Verify the production image through the ordinary authenticated native login.

    Args:
        qmp: Control connection for the disk-only guest.
        output: Fixture directory used for transient image files.
        version: Expected installed Atlaso version.
        commit: Expected installed source commit.
        password: Root password entered during this fixture's installation.
        evidence: Sanitized failure information for the VM run.
    """
    evidence.checkpoint = "media-free Atlaso appliance console"
    evidence.boot_screen = "unrecognized"
    wait_screen(qmp, output, lambda text: observe_boot_console(text, evidence), evidence.checkpoint, BOOT_SECONDS)
    qmp.send_key("alt", "f2")
    evidence.checkpoint = "native Photon tty2 login"
    wait_screen(qmp, output, installed_login_prompt, evidence.checkpoint, 60)
    type_text(qmp, "root")
    evidence.checkpoint = "concealed Photon root authentication"
    wait_screen(
        qmp, output,
        lambda text: re.search(r"(?im)^[ \t]*pass[wu]ord[ \t]*:[ \t]*$", text),
        "concealed Photon root authentication", 45,
    )
    type_text(qmp, password)
    evidence.checkpoint = "authenticated root shell"
    wait_screen(
        qmp, output, lambda text: re.search(r"(?m)^[ \t]*root@[^\r\n]{1,90}#[ \t]*$", text),
        "authenticated root shell", 45,
    )
    check_installed_application(qmp, output, version, commit, evidence)
    type_text(qmp, "exit")


def install(
    iso: Path, output: Path, args: argparse.Namespace, passwords: dict[str, str], evidence: FailureEvidence,
) -> None:
    """Install to the selected disk and verify the appliance without its media.

    Args:
        iso: Exact signed installer ISO admitted for testing.
        output: Owned output directory for this fixture.
        args: Validated firmware, accelerator, and control-socket options.
        passwords: Dedicated administrator and root passwords for the test guest.
        evidence: Sanitized failure information for the VM run.
    """
    disk = output / "atlaso-target.qcow2"
    decoy = output / "atlaso-unselected.qcow2"
    decoy_baseline = output / "atlaso-unselected-baseline.qcow2"
    vars_copy = output / "OVMF_VARS.fd"
    shutil.copyfile(args._ovmf_vars, vars_copy)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), "64G"], check=True, capture_output=True, timeout=30)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(decoy), "4G"], check=True, capture_output=True, timeout=30)
    shutil.copyfile(decoy, decoy_baseline)

    evidence.checkpoint = "start installer VM"
    process, qmp = start_qemu(iso, output, disk, vars_copy, args._ovmf_code, "install-qmp",
                                 abstract_sockets=args.abstract_sockets, accelerator=args.accelerator)
    try:
        timeout = time.monotonic() + INSTALL_SECONDS
        evidence.checkpoint = "UEFI installer menu"
        wait_screen(qmp, output, lambda text: "Install Atlaso offline" in text, evidence.checkpoint, 180)
        qmp.send_key("ret")
        evidence.checkpoint = "native storage layout or legacy disk selector"
        screen = wait_screen(qmp, output, initial_installer_screen, evidence.checkpoint, 600)
        if is_disk_selection_screen(screen):
            rows = list(DISK_ROW.finditer(screen))
            sizes = [row.group(1) for row in rows]
            if sizes.count("64") != 1 or sizes.count("4") != 1:
                raise AcceptanceError("native Photon menu did not expose one 64 GiB target and one 4 GiB decoy")
            target_index = sizes.index("64")
            for key in ("up", "up", *("down" for _ in range(target_index)), "ret"):
                qmp.send_key(key)
            evidence.checkpoint = "SFTP backup storage"
            configure_storage_assignments(qmp, output, "/dev/sda", evidence=evidence)
        else:
            configure_storage_assignments(qmp, output, "/dev/sda", screen, evidence=evidence)
        evidence.checkpoint = "destructive layout review"
        review = wait_screen(qmp, output, lambda text: "erase selected disks" in text.casefold(), evidence.checkpoint, 90)
        if REVIEW_DISK.findall(review) != ["64"]:
            raise AcceptanceError("destructive review did not identify only the intended 64 GiB target")
        qmp.send_key("left")
        qmp.send_key("ret")
        evidence.checkpoint = "concealed installer credentials"
        enter_installer_passwords(qmp, output, passwords)
        evidence.checkpoint = "installer-requested reboot"
        wait_for_installer_reboot(qmp, output, timeout)
    except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError):
        evidence.qemu_exited = process.poll() is not None
        raise
    finally:
        stop_qemu(process, qmp)

    evidence.checkpoint = "start media-free VM"
    process, qmp = start_qemu(None, output, disk, vars_copy, args._ovmf_code, "boot-qmp",
                             abstract_sockets=args.abstract_sockets, accelerator=args.accelerator)
    try:
        verify_installed(qmp, output, args.version, args.commit, passwords["root"], evidence)
    except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError):
        evidence.qemu_exited = process.poll() is not None
        raise
    finally:
        stop_qemu(process, qmp)

    evidence.checkpoint = "unselected disk comparison"
    comparison = subprocess.run(
        ["qemu-img", "compare", "-f", "qcow2", "-F", "qcow2", str(decoy_baseline), str(decoy)],
        capture_output=True,
        timeout=600,
    )
    if comparison.returncode != 0:
        raise AcceptanceError("the independent unselected 4 GiB disk changed")


def main() -> int:
    """Validate exact media and publish a receipt only after every checkpoint passes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--ovmf-directory", default="/usr/share/OVMF")
    parser.add_argument("--accelerator", choices=("auto", "kvm", "tcg"), default="auto")
    parser.add_argument("--abstract-sockets", action="store_true")
    args = parser.parse_args()
    try:
        iso, output, receipt, _, passwords = require_inputs(args)
        evidence = FailureEvidence()
        try:
            install(iso, output, args, passwords, evidence)
            evidence.checkpoint = "write successful acceptance receipt"
            value = {"schema": 1, "version": args.version, "commit": args.commit,
                     "iso_sha256": args.sha256, "checks": CHECKS}
            write_new_json(receipt, value)
        except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError):
            try:
                evidence.write(receipt, args)
            except OSError:
                print("Could not seal VM acceptance failure evidence.", file=sys.stderr)
            raise
        finally:
            passwords.clear()
        print("Atlaso VM acceptance passed.")
        return 0
    except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
