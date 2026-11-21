"""Run the bounded, disconnected UEFI acceptance case in QEMU."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
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
    """Capture output-directory identity before launching a VM process."""
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
    """Publish a durable JSON record without replacing an existing file."""
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def require_inputs(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, dict[str, str]]:
    """Validate immutable inputs and absent task-owned output paths."""
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
        self.execute(
            "send-key",
            {"keys": [{"type": "qcode", "data": key} for key in keys], "hold-time": 75},
        )
        time.sleep(0.1)

    def close(self) -> None:
        self.stream.close()
        self.connection.close()


def key_events(text: str) -> list[list[str]]:
    """Convert the admitted printable credential alphabet into QEMU key chords."""
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
    for chord in key_events(value):
        qmp.send_key(*chord)
    qmp.send_key("ret")


def preprocess_ppm(raw: bytes) -> tuple[bytes, bool]:
    """Crop the neutral-gray Photon dialog and enlarge it for reliable OCR.

    Full-frame QEMU screenshots are mostly blue background. The installer window
    uses a broad, low-chroma gray fill, so its rows and columns provide a stable
    crop even when the selected row changes color. Frames without that panel,
    such as the GRUB menu, retain the full image and use sparse-text OCR.
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
    """OCR one transient QMP frame without retaining or logging guest pixels."""
    image = directory / f"frame-{uuid.uuid4().hex}.ppm"
    prepared = directory / f"frame-{uuid.uuid4().hex}-ocr.ppm"
    try:
        qmp.execute("screendump", {"filename": str(image), "format": "ppm"})
        prepared_bytes, cropped = preprocess_ppm(image.read_bytes())
        prepared.write_bytes(prepared_bytes)
        result = subprocess.run(
            ["tesseract", str(prepared), "stdout", "--psm", "6" if cropped else "11"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if len(result.stdout) > 32768:
            raise AcceptanceError("guest screen text exceeded its fixed bound")
        return result.stdout
    except subprocess.SubprocessError as error:
        raise AcceptanceError("the bounded guest screen observer failed") from error
    finally:
        image.unlink(missing_ok=True)
        prepared.unlink(missing_ok=True)


def wait_screen(qmp: Qmp, directory: Path, predicate, label: str, seconds: int) -> str:
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
    """Recognize the case-insensitive, OCR-rendered native selector heading."""
    return "select a disk" in text.casefold()


def is_credential_prompt(text: str, account: str, confirmation: bool) -> bool:
    """Recognize only the expected concealed field in the signed installer sequence."""
    action = r"confir[mn]" if confirmation else "set"
    return re.search(rf"\b{action} {re.escape(account)} pass[wu]ord\b", text, re.I) is not None


def wait_for_installer_reboot(qmp: Qmp, output: Path, deadline: float) -> None:
    """Wait for the successful installer's own reset before disconnecting its media."""
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
    """Start a UEFI fixture with an offline installer and isolated boot networking."""
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
    """Recognize the appliance dashboard after the disk-only boot."""
    text = text.casefold()
    return "manage this appliance at" in text or (
        "atlaso appliance" in text and re.search(r"\bf4[^\n]{0,14}console", text) is not None
    )


def installed_login_prompt(text: str) -> bool:
    """Admit only the ordinary Photon login on the selected virtual terminal."""
    return re.search(r"\btty2\b", text, re.I) is not None and re.search(r"(?im)^[ \t]*[\w.-]+ login:[ \t]*$", text) is not None


def installed_probe(version: str, commit: str, first: int, second: int) -> str:
    """Build a read-only guest probe whose success line cannot come from shell echo."""
    program = (
        "import atlaso as a; "
        f"assert a.__version__ == '{version}' and a.__build_git_commit__ == '{commit}'; "
        f"print('ATLASO VERIFIED', {first}+{second})"
    )
    checks = (
        "systemctl is-active --quiet atlaso.service && "
        "systemctl is-active --quiet atlaso-worker.service"
    )
    return (
        f"for i in $(seq 60); do if {checks}; then break; fi; sleep 2; done; "
        f'if {checks}; then /opt/atlaso/.venv/bin/python -B -I -c "{program}"; '
        "else echo ATLASO SERVICES UNAVAILABLE; fi"
    )


def verify_installed(qmp: Qmp, output: Path, version: str, commit: str, password: str) -> None:
    """Verify the production image through the ordinary authenticated native login."""
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
    first = 1000 + secrets.randbelow(9000)
    second = 1000 + secrets.randbelow(9000)
    type_text(qmp, installed_probe(version, commit, first, second))
    marker = re.compile(rf"(?im)^[ \t]*atlaso verified {first + second}[ \t]*$")
    failure = re.compile(r"(?im)^[ \t]*atlaso services unavailable[ \t]*$")
    result = wait_screen(qmp, output, lambda text: marker.search(text) or failure.search(text),
                         "installed application verification result", 150)
    if not marker.search(result):
        raise AcceptanceError("Atlaso services did not become active in the media-free boot")
    print("The installed version, source commit and both Atlaso services verified.", flush=True)
    type_text(qmp, "exit")


def install(iso: Path, output: Path, args: argparse.Namespace, passwords: dict[str, str]) -> None:
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
        screen = wait_screen(qmp, output, is_disk_selection_screen, "native disk selection", 600)
        rows = list(DISK_ROW.finditer(screen))
        sizes = [row.group(1) for row in rows]
        if sizes.count("64") != 1 or sizes.count("4") != 1:
            raise AcceptanceError("native Photon menu did not expose one 64 GiB target and one 4 GiB decoy")
        target_index = sizes.index("64")
        for key in ("up", "up", *("down" for _ in range(target_index)), "ret"):
            qmp.send_key(key)
        for title, pattern in (
            ("SFTP backup storage", r"\bsftp backup storage\b"),
            ("VCFDT depot storage", r"\bvy?cfdt depot storage\b"),
        ):
            wait_screen(qmp, output, lambda text, pattern=pattern: re.search(pattern, text, re.I), title, 180)
            qmp.send_key("ret")
        review = wait_screen(qmp, output, lambda text: "erase selected disks" in text.casefold(), "destructive layout review", 90)
        if REVIEW_DISK.findall(review) != ["64"]:
            raise AcceptanceError("destructive review did not identify only the intended 64 GiB target")
        qmp.send_key("left")
        qmp.send_key("ret")
        for account in ("admin", "root"):
            secret = passwords[account]
            for confirmation in (False, True):
                wait_screen(qmp, output, lambda text, confirmation=confirmation, account=account: is_credential_prompt(text, account, confirmation),
                            "concealed installer credential", 180)
                type_text(qmp, secret)
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
