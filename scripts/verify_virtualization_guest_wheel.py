"""Verify the exact Atlaso wheel installed in a virtualization payload disk."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIST_INFO_PATTERN = re.compile(r"^atlaso-[^/]+\.dist-info$")


def _sha256(path: Path) -> str:
    """Return the lowercase SHA-256 digest of one file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _guestfish(disk: Path, commands: list[str]) -> list[str]:
    """Run bounded read-only libguestfs commands against one payload disk."""

    executable = shutil.which("guestfish")
    if executable is None:
        raise SystemExit("guestfish is required to verify the installed Atlaso wheel")
    result = subprocess.run(
        [executable, "--ro", "-a", str(disk)],
        input="\n".join(["run", *commands, "quit", ""]),
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )
    if result.returncode:
        diagnostic = "\n".join(result.stderr.splitlines()[-20:])
        raise SystemExit(f"guestfish rejected the system-content disk: {diagnostic}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _filesystem(disk: Path) -> str:
    """Return the sole ext filesystem exposed by the system-content VMDK."""

    lines = _guestfish(disk, ["list-filesystems"])
    filesystems = []
    for line in lines:
        device, separator, filesystem = line.partition(":")
        if separator and filesystem.strip() in {"ext2", "ext3", "ext4"}:
            filesystems.append(device.strip())
    if len(filesystems) != 1:
        raise SystemExit(
            "Atlaso system-content disk must expose exactly one ext filesystem"
        )
    return filesystems[0]


def _wheel_records(wheel: Path) -> tuple[str, dict[str, tuple[str, int]]]:
    """Return the wheel dist-info name and its immutable installed-file records."""

    try:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            record_names = [
                name for name in names if name.endswith(".dist-info/RECORD")
            ]
            if len(record_names) != 1:
                raise SystemExit("Atlaso wheel must contain exactly one RECORD")
            record_name = record_names[0]
            dist_info = PurePosixPath(record_name).parent.as_posix()
            if DIST_INFO_PATTERN.fullmatch(dist_info) is None:
                raise SystemExit("Atlaso wheel RECORD has an unexpected dist-info path")
            records: dict[str, tuple[str, int]] = {}
            rows = csv.reader(io.StringIO(archive.read(record_name).decode("utf-8")))
            for row in rows:
                if len(row) != 3:
                    raise SystemExit("Atlaso wheel RECORD contains an invalid row")
                name, encoded_digest, size_text = row
                member = PurePosixPath(name)
                if (
                    member.is_absolute()
                    or ".." in member.parts
                    or member.as_posix() != name
                ):
                    raise SystemExit("Atlaso wheel RECORD contains an unsafe path")
                if name == record_name:
                    if encoded_digest or size_text:
                        raise SystemExit(
                            "Atlaso wheel RECORD self-entry must be unhashed"
                        )
                    continue
                algorithm, separator, encoded = encoded_digest.partition("=")
                if (
                    separator != "="
                    or algorithm != "sha256"
                    or not size_text.isdecimal()
                ):
                    raise SystemExit(
                        "Atlaso wheel RECORD contains an unsupported digest"
                    )
                padding = "=" * (-len(encoded) % 4)
                try:
                    digest = base64.urlsafe_b64decode(encoded + padding).hex()
                except ValueError as exc:
                    raise SystemExit(
                        "Atlaso wheel RECORD contains an invalid digest"
                    ) from exc
                if len(digest) != 64 or name in records:
                    raise SystemExit(
                        "Atlaso wheel RECORD contains an invalid or duplicate entry"
                    )
                records[name] = (digest, int(size_text))
            if not records or not any(name.startswith("atlaso/") for name in records):
                raise SystemExit(
                    "Atlaso wheel RECORD does not cover the Atlaso package"
                )
            return dist_info, records
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise SystemExit(
            "Atlaso application wheel is not a valid wheel archive"
        ) from exc


def _system_vmdk(asset_root: Path) -> Path:
    """Resolve the OVA-validated system-content VMDK from provenance."""

    provenance_paths = sorted(asset_root.glob("*-provenance.json"))
    if len(provenance_paths) != 1:
        raise SystemExit("virtualization assets require one OVA provenance document")
    try:
        provenance: Any = json.loads(provenance_paths[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("OVA provenance is not valid JSON") from exc
    matches = [
        record
        for record in provenance.get("payloads", [])
        if isinstance(record, dict) and record.get("role") == "atlaso_system"
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("file"), str):
        raise SystemExit("OVA provenance does not identify one system-content VMDK")
    name = matches[0]["file"]
    if PurePosixPath(name).name != name:
        raise SystemExit("OVA provenance contains an unsafe system-content filename")
    path = asset_root / name
    if path.is_symlink() or not path.is_file():
        raise SystemExit("OVA system-content VMDK is missing or unsafe")
    return path


def verify_installed_wheel(
    asset_root: Path, wheel: Path, expected_digest: str
) -> dict[str, Any]:
    """Verify wheel-member bytes in the active venv on the system-content disk."""

    if DIGEST_PATTERN.fullmatch(expected_digest) is None:
        raise SystemExit("expected Atlaso wheel digest is invalid")
    if wheel.is_symlink() or not wheel.is_file() or _sha256(wheel) != expected_digest:
        raise SystemExit("Atlaso application wheel does not match the signed digest")
    dist_info, records = _wheel_records(wheel)
    disk = _system_vmdk(asset_root.resolve(strict=True))
    filesystem = _filesystem(disk)
    mount = f"mount-ro {filesystem} /"
    site_lines = _guestfish(
        disk,
        [mount, "realpath /opt-atlaso/.venv/lib/python3.14/site-packages"],
    )
    if len(site_lines) != 1 or not site_lines[0].startswith("/opt-atlaso/releases/"):
        raise SystemExit("active Atlaso site-packages path is missing or unsafe")
    site_packages = PurePosixPath(site_lines[0])
    with tempfile.TemporaryDirectory(prefix="atlaso-installed-wheel-") as temporary:
        output_root = Path(temporary)
        commands = [mount]
        destinations: dict[str, Path] = {}
        for index, name in enumerate(sorted(records)):
            destination = output_root / str(index)
            destinations[name] = destination
            guest_path = (site_packages / PurePosixPath(name)).as_posix()
            commands.append(f"download {guest_path} {destination.as_posix()}")
        _guestfish(disk, commands)
        for name, (expected_file_digest, expected_size) in records.items():
            installed = destinations[name]
            if (
                installed.is_symlink()
                or not installed.is_file()
                or installed.stat().st_size != expected_size
                or _sha256(installed) != expected_file_digest
            ):
                raise SystemExit(
                    f"installed Atlaso wheel member does not match: {name}"
                )
    return {
        "schema_version": 1,
        "kind": "atlaso-installed-wheel-verification",
        "wheel_sha256": expected_digest,
        "dist_info": dist_info,
        "files_verified": len(records),
    }


def main(argv: list[str] | None = None) -> int:
    """Run the protected installed-wheel verification command."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--expected-digest", required=True)
    args = parser.parse_args(argv)
    result = verify_installed_wheel(args.assets, args.wheel, args.expected_digest)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
