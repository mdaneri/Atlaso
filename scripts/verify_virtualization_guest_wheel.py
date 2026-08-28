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
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIST_INFO_PATTERN = re.compile(r"^[A-Za-z0-9_.]+-[A-Za-z0-9_.+!]+\.dist-info$")


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


def _installed_path(name: str, data_prefix: str) -> str:
    """Map one safe wheel member to its site-packages installation path."""

    for category in ("purelib", "platlib"):
        prefix = f"{data_prefix}/{category}/"
        if name.startswith(prefix):
            return name.removeprefix(prefix)
    if name.startswith(f"{data_prefix}/"):
        raise SystemExit("wheel contains data outside the active site-packages tree")
    return name


def _wheel_records(wheel: Path) -> tuple[str, dict[str, tuple[str, int]]]:
    """Return one wheel's dist-info name and installed site-packages records."""

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
            data_prefix = f"{dist_info.removesuffix('.dist-info')}.data"
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
                installed_name = _installed_path(name, data_prefix)
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
                if len(digest) != 64 or installed_name in records:
                    raise SystemExit(
                        "Atlaso wheel RECORD contains an invalid or duplicate entry"
                    )
                records[installed_name] = (digest, int(size_text))
            if not records:
                raise SystemExit("wheel RECORD contains no immutable installed files")
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


def _expected_environment(
    wheel: Path, wheelhouse: Path, expected_digest: str
) -> tuple[dict[str, tuple[str, int]], set[str]]:
    """Build the collision-free installed inventory from every signed wheel."""

    if DIGEST_PATTERN.fullmatch(expected_digest) is None:
        raise SystemExit("expected Atlaso wheel digest is invalid")
    if wheel.is_symlink() or not wheel.is_file() or _sha256(wheel) != expected_digest:
        raise SystemExit("Atlaso application wheel does not match the signed digest")
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise SystemExit("signed CPython 3.14 wheelhouse is missing or unsafe")
    dependency_wheels = sorted(wheelhouse.glob("*.whl"))
    if not dependency_wheels or any(path.is_symlink() for path in dependency_wheels):
        raise SystemExit("signed CPython 3.14 wheelhouse contains no safe wheels")
    records: dict[str, tuple[str, int]] = {}
    dist_infos: set[str] = set()
    for candidate in [*dependency_wheels, wheel]:
        dist_info, candidate_records = _wheel_records(candidate)
        if candidate == wheel and not any(
            name.startswith("atlaso/") for name in candidate_records
        ):
            raise SystemExit("Atlaso wheel RECORD does not cover the Atlaso package")
        if dist_info in dist_infos:
            raise SystemExit(
                f"signed wheel set contains duplicate distribution: {dist_info}"
            )
        dist_infos.add(dist_info)
        for name, record in candidate_records.items():
            if name in records:
                raise SystemExit(f"signed wheel installation paths collide: {name}")
            records[name] = record
    return records, dist_infos


def _normalized_tar_name(name: str) -> str:
    """Return one safe site-packages-relative tar member name."""

    while name.startswith("./"):
        name = name[2:]
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or path.as_posix() != name:
        raise SystemExit("guest site-packages archive contains an unsafe path")
    return name


def _allowed_generated_file(
    name: str, records: dict[str, tuple[str, int]], dist_infos: set[str]
) -> bool:
    """Return whether pip or CPython may generate this non-wheel file."""

    parent = PurePosixPath(name).parent.as_posix()
    if parent in dist_infos and PurePosixPath(name).name in {
        "INSTALLER",
        "RECORD",
        "REQUESTED",
        "direct_url.json",
    }:
        return True
    match = re.fullmatch(
        r"(.+)/__pycache__/([^/]+)\.cpython-314(?:\.opt-[12])?\.pyc", name
    )
    if match is None:
        return False
    return f"{match.group(1)}/{match.group(2)}.py" in records


def _verify_site_packages_archive(
    archive_path: Path,
    records: dict[str, tuple[str, int]],
    dist_infos: set[str],
) -> None:
    """Verify the exact active-environment inventory and immutable file bytes."""

    found: set[str] = set()
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            for member in archive:
                name = _normalized_tar_name(member.name)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise SystemExit(
                        f"guest site-packages contains an unsafe entry: {name}"
                    )
                if name in records:
                    if name in found:
                        raise SystemExit(
                            f"guest site-packages contains a duplicate file: {name}"
                        )
                    expected_digest, expected_size = records[name]
                    source = archive.extractfile(member)
                    if source is None:
                        raise SystemExit(
                            f"guest site-packages file is unreadable: {name}"
                        )
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        digest.update(chunk)
                    if size != expected_size or digest.hexdigest() != expected_digest:
                        raise SystemExit(
                            f"installed wheel member does not match: {name}"
                        )
                    found.add(name)
                elif not _allowed_generated_file(name, records, dist_infos):
                    raise SystemExit(
                        f"guest site-packages contains an unexpected file: {name}"
                    )
    except (OSError, tarfile.TarError) as exc:
        raise SystemExit("guest site-packages could not be read safely") from exc
    missing = sorted(set(records) - found)
    if missing:
        raise SystemExit(f"installed wheel member is missing: {missing[0]}")


def verify_installed_environment(
    asset_root: Path, wheel: Path, wheelhouse: Path, expected_digest: str
) -> dict[str, Any]:
    """Verify the complete signed wheel set in the active guest environment."""

    records, dist_infos = _expected_environment(wheel, wheelhouse, expected_digest)
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
    with tempfile.TemporaryDirectory(
        prefix="atlaso-installed-environment-"
    ) as temporary:
        archive_path = Path(temporary) / "site-packages.tar"
        _guestfish(
            disk,
            [mount, f"tar-out {site_packages.as_posix()} {archive_path.as_posix()}"],
        )
        _verify_site_packages_archive(archive_path, records, dist_infos)
    return {
        "schema_version": 1,
        "kind": "atlaso-installed-environment-verification",
        "wheel_sha256": expected_digest,
        "distributions_verified": len(dist_infos),
        "files_verified": len(records),
    }


def main(argv: list[str] | None = None) -> int:
    """Run the protected installed-wheel verification command."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--expected-digest", required=True)
    args = parser.parse_args(argv)
    result = verify_installed_environment(
        args.assets, args.wheel, args.wheelhouse, args.expected_digest
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
