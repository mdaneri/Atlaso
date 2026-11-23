"""Run the bounded, disconnected UEFI acceptance case in QEMU."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

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
STORAGE_LAYOUT_MOUNTS = ("/", "/mnt/atlaso-vcf-backups", "/mnt/atlaso-vcf-offline-depot")
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


class AcceptanceError(RuntimeError):
    """Represent a failed release VM acceptance checkpoint."""


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
    if output.exists() or output.is_symlink() or receipt.exists() or intent.exists():
        raise AcceptanceError("VM output, receipt, and ownership intent destinations must be absent")
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


def preprocess_ppm(raw: bytes) -> tuple[bytes, bool]:
    """Crop the neutral-gray Photon dialog and enlarge it for reliable OCR.

    Full-frame QEMU screenshots are mostly blue background. The installer window
    uses a broad, low-chroma gray fill, so its rows and columns provide a stable
    crop even when the selected row changes color. Frames without that panel,
    such as the GRUB menu, retain the full image and use sparse-text OCR.

    Args:
        raw: Bytes of a raw RGB PPM screenshot returned by QMP.
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

    scale = 3 if cropped else 2
    crop_width, crop_height = right - left, bottom - top
    enlarged_width, enlarged_height = crop_width * scale, crop_height * scale
    enlarged = bytearray(enlarged_width * enlarged_height * 3)
    for y in range(crop_height):
        source = ((top + y) * width + left) * 3
        line = pixels[source:source + crop_width * 3]
        if cropped:
            expanded = b"".join(
                (b"\0\0\0" if max(line[index:index + 3]) <= 96 else b"\xff\xff\xff") * scale
                for index in range(0, len(line), 3)
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
        prepared_bytes, cropped = preprocess_ppm(image.read_bytes())
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
        return result.stdout
    except subprocess.TimeoutExpired:
        print("Console OCR timed out on a frame.", flush=True)
        return ""
    finally:
        image.unlink(missing_ok=True)
        prepared.unlink(missing_ok=True)


def wait_screen(qmp: Qmp, directory: Path, predicate, label: str, seconds: int) -> str:
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
    raise AcceptanceError(f"guest did not reach the expected {label} screen")


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
    root_start = folded.find("root installation target")
    service_start = folded.find("sftp backup storage")
    root_section = folded[root_start:service_start] if 0 <= root_start < service_start else ""
    return (
        "storage layout" in folded
        and all(re.search(pattern, text, re.I) is not None for pattern in STORAGE_LAYOUT_LABELS)
        and re.search(r"(?im)^\s*(?:x|\|)?\s*mount\s*:\s*/\s*(?:x|\|)?\s*$", root_section) is not None
        and all(re.search(rf"(?i)mount\s*:\s*{re.escape(mount)}(?:\s|$)", text) for mount in STORAGE_LAYOUT_MOUNTS[1:])
        and len(re.findall(r"(?im)^\s*(?:x|\|)?\s*volume\s*:", text)) >= 3
        and re.search(r"\b(auto|custom)\b", root_section) is not None
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
    return (
        "storage layout" not in text.casefold()
        and re.search(r"\bpartitions?\b", text, re.I) is not None
    )


def configure_storage_assignments(
    qmp: Qmp, output: Path, expected_root_disk: str, initial_screen: str | None = None,
) -> None:
    """Continue through the combined storage page or older sequential prompts.

    Args:
        qmp: Control connection for the disconnected installation fixture.
        output: Fixture directory used for transient screen observations.
        expected_root_disk: Exact device that the final review must erase.
        initial_screen: Already-observed combined page or legacy SFTP prompt.
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
        qmp.send_key("esc")
        screen = wait_screen(qmp, output, is_auto_storage_layout_screen, "Auto storage layout after Custom", 60)
        if storage_layout_root_disk(screen) != expected_root_disk:
            raise AcceptanceError("returning from Custom changed the selected Auto root device")
        for label in ("SFTP backup storage", "VCFDT depot storage"):
            qmp.send_key("tab")
            wait_screen(
                qmp, output, is_combined_storage_layout_screen, f"combined {label} assignment", 30,
            )
        qmp.send_key("ret")
        return

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


def check_installed_application(qmp: Qmp, output: Path, version: str, commit: str) -> None:
    """Verify installed build metadata, services, and local diagnostic execution.

    Args:
        qmp: Control connection for the authenticated guest.
        output: Fixture directory used for transient image files.
        version: Expected installed Atlaso version.
        commit: Expected installed source commit.
    """
    for setup in ("P=/opt/atlaso/.venv/bin/python", f"export V={version}", f"export C={commit}"):
        run_console_command(qmp, setup)
    for attribute, expected_name, label in (
        ("__version__", "V", "installed Atlaso version"),
        ("__build_git_commit__", "C", "installed Atlaso source commit"),
    ):
        run_console_command(qmp, installed_identity_command(attribute, expected_name))
        result = wait_screen(qmp, output, lambda text: re.search(r"(?im)^[ \t]*(true|false)[ \t]*$", text), label, 30)
        if not re.search(r"(?im)^[ \t]*true[ \t]*$", result):
            raise AcceptanceError(f"the {label} differs from the verified release")

    status_pattern = re.compile(r"(?im)^[ \t]*(active|inactive|activating|deactivating|failed|unknown)[ \t]*$")
    for service in ("atlaso.service", "atlaso-worker.service"):
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            run_console_command(qmp, f"systemctl is-active {service}")
            result = wait_screen(qmp, output, status_pattern.search, f"{service} state", 25)
            if [status.casefold() for status in status_pattern.findall(result)] == ["active"]:
                break
            time.sleep(5)
        else:
            raise AcceptanceError(f"{service} did not become active in the media-free boot")
    print("The installed version, source commit and both Atlaso services verified.", flush=True)

    # Exercise the installed implementation as the service account, with the ISO
    # removed and no network peer. Keep console evidence to a public status line.
    run_console_command(
        qmp,
        "runuser -u atlaso -- env ATLASO_DRY_RUN_SYSTEM_ADAPTERS=false $P -BI -c "
        "'from atlaso.app.services.network_diagnostics import run_check as r;"
        "assert all(r(k,a,a,\"auto\").state==\"reply\" for a in (\"127.0.0.1\",\"::1\") "
        "for k in (\"ping\",\"traceroute\"));"
        "assert r(\"dns\",\"localhost\",\"\",\"auto\").state==\"resolved\"' "
        ">/dev/null 2>&1 && echo PROBES-OK || echo PROBES-FAILED",
    )
    probe_status = re.compile(r"(?im)^[ \t]*PROBES-(OK|FAILED)[ \t]*$")
    result = wait_screen(qmp, output, probe_status.search, "installed network diagnostics", 55)
    if [status.upper() for status in probe_status.findall(result)] != ["OK"]:
        raise AcceptanceError("the installed Atlaso service account could not run its local network diagnostics")
    print("IPv4 and IPv6 loopback probes and localhost lookup verified.", flush=True)


def verify_installed(qmp: Qmp, output: Path, version: str, commit: str, password: str) -> None:
    """Verify the production image through the ordinary authenticated native login.

    Args:
        qmp: Control connection for the disk-only guest.
        output: Fixture directory used for transient image files.
        version: Expected installed Atlaso version.
        commit: Expected installed source commit.
        password: Root password entered during this fixture's installation.
    """
    wait_screen(qmp, output, installed_console_ready, "media-free Atlaso appliance console", BOOT_SECONDS)
    qmp.send_key("alt", "f2")
    wait_screen(qmp, output, installed_login_prompt, "native Photon tty2 login", 60)
    type_text(qmp, "root")
    wait_screen(
        qmp, output,
        lambda text: re.search(r"(?im)^[ \t]*pass[wu]ord[ \t]*:[ \t]*$", text),
        "concealed Photon root authentication", 45,
    )
    type_text(qmp, password)
    wait_screen(
        qmp, output, lambda text: re.search(r"(?m)^[ \t]*root@[^\r\n]{1,90}#[ \t]*$", text),
        "authenticated root shell", 45,
    )
    check_installed_application(qmp, output, version, commit)
    type_text(qmp, "exit")


def install(iso: Path, output: Path, args: argparse.Namespace, passwords: dict[str, str]) -> None:
    """Install to the selected disk and verify the appliance without its media.

    Args:
        iso: Exact signed installer ISO admitted for testing.
        output: Owned output directory for this fixture.
        args: Validated firmware, accelerator, and control-socket options.
        passwords: Dedicated administrator and root passwords for the test guest.
    """
    disk = output / "atlaso-target.qcow2"
    decoy = output / "atlaso-unselected.qcow2"
    decoy_baseline = output / "atlaso-unselected-baseline.qcow2"
    vars_copy = output / "OVMF_VARS.fd"
    shutil.copyfile(args._ovmf_vars, vars_copy)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), "64G"], check=True, capture_output=True, timeout=30)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(decoy), "4G"], check=True, capture_output=True, timeout=30)
    shutil.copyfile(decoy, decoy_baseline)

    process, qmp = start_qemu(iso, output, disk, vars_copy, args._ovmf_code, "install-qmp",
                                 abstract_sockets=args.abstract_sockets, accelerator=args.accelerator)
    try:
        timeout = time.monotonic() + INSTALL_SECONDS
        screen = wait_screen(qmp, output, lambda text: "Install Atlaso offline" in text, "UEFI installer menu", 180)
        qmp.send_key("ret")
        screen = wait_screen(qmp, output, initial_installer_screen, "native storage layout or legacy disk selector", 600)
        if is_disk_selection_screen(screen):
            rows = list(DISK_ROW.finditer(screen))
            sizes = [row.group(1) for row in rows]
            if sizes.count("64") != 1 or sizes.count("4") != 1:
                raise AcceptanceError("native Photon menu did not expose one 64 GiB target and one 4 GiB decoy")
            target_index = sizes.index("64")
            for key in ("up", "up", *("down" for _ in range(target_index)), "ret"):
                qmp.send_key(key)
            configure_storage_assignments(qmp, output, "/dev/sda")
        else:
            configure_storage_assignments(qmp, output, "/dev/sda", screen)
        review = wait_screen(qmp, output, lambda text: "erase selected disks" in text.casefold(), "destructive layout review", 90)
        if REVIEW_DISK.findall(review) != ["64"]:
            raise AcceptanceError("destructive review did not identify only the intended 64 GiB target")
        qmp.send_key("left")
        qmp.send_key("ret")
        enter_installer_passwords(qmp, output, passwords)
        wait_for_installer_reboot(qmp, output, timeout)
    finally:
        stop_qemu(process, qmp)

    process, qmp = start_qemu(None, output, disk, vars_copy, args._ovmf_code, "boot-qmp",
                             abstract_sockets=args.abstract_sockets, accelerator=args.accelerator)
    try:
        verify_installed(qmp, output, args.version, args.commit, passwords["root"])
    finally:
        stop_qemu(process, qmp)

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
        try:
            install(iso, output, args, passwords)
        finally:
            passwords.clear()
        value = {"schema": 1, "version": args.version, "commit": args.commit,
                 "iso_sha256": args.sha256, "checks": CHECKS}
        write_new_json(receipt, value)
        print("Atlaso VM acceptance passed.")
        return 0
    except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
