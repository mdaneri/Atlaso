"""Verify the exact Atlaso wheel installed in a virtualization payload disk."""

from __future__ import annotations

import argparse
import base64
import configparser
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
CONSOLE_SCRIPT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ENTRY_POINT_PATTERN = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_.]*):([A-Za-z_][A-Za-z0-9_]*)$"
)
SOURCE_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DEPLOYED_TEXT_FILES = {
    "scripts/appliance/atlaso-helper": "/opt-atlaso/bin/atlaso-helper",
    "scripts/appliance/atlaso-install-boot-branding": "/opt-atlaso/bin/atlaso-install-boot-branding",
    "image/common/powershell/atlaso-vault-profile.ps1": "/opt-atlaso/bin/atlaso-vault-profile.ps1",
    "image/common/systemd/atlaso-console-manager.conf": "/etc/systemd/system.conf.d/atlaso-console.conf",
    "image/vmware-workstation/systemd/atlaso.service": "/etc/systemd/system/atlaso.service",
    "image/common/systemd/atlaso-worker.service": "/etc/systemd/system/atlaso-worker.service",
    "image/common/systemd/atlaso-require-data-disks.conf": "/etc/systemd/system/atlaso.service.d/atlaso-data-disks.conf",
    "image/common/systemd/nginx-atlaso-data-disks.conf": "/etc/systemd/system/nginx.service.d/atlaso-data-disks.conf",
    "image/common/boot/grub/theme.txt": "/boot/grub2/themes/atlaso/theme.txt",
}
DEPLOYED_BINARY_FILES = {
    "image/common/boot/grub/atlaso.png": "/boot/grub2/themes/atlaso/atlaso.png",
}


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


def _wheel_console_scripts(wheel: Path) -> dict[str, tuple[str, str]]:
    """Return the application wheel's bounded console-script entry points."""

    try:
        with zipfile.ZipFile(wheel) as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/entry_points.txt")]
            if len(names) != 1:
                raise SystemExit("Atlaso wheel must contain one entry-points document")
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.optionxform = str
            parser.read_string(archive.read(names[0]).decode("utf-8"))
    except (configparser.Error, OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise SystemExit("Atlaso wheel entry points are unreadable") from exc
    if not parser.has_section("console_scripts"):
        raise SystemExit("Atlaso wheel contains no console-script entry points")
    scripts: dict[str, tuple[str, str]] = {}
    for name, target in parser.items("console_scripts"):
        match = ENTRY_POINT_PATTERN.fullmatch(target.strip())
        if CONSOLE_SCRIPT_NAME_PATTERN.fullmatch(name) is None or match is None:
            raise SystemExit("Atlaso wheel contains an unsafe console-script entry point")
        scripts[name] = (match.group(1), match.group(2))
    if not scripts:
        raise SystemExit("Atlaso wheel contains no console-script entry points")
    return scripts


def _payload_vmdks(asset_root: Path) -> dict[str, Path]:
    """Resolve the OVA-validated Photon and system-content VMDKs."""

    provenance_paths = sorted(asset_root.glob("*-provenance.json"))
    if len(provenance_paths) != 1:
        raise SystemExit("virtualization assets require one OVA provenance document")
    try:
        provenance: Any = json.loads(provenance_paths[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("OVA provenance is not valid JSON") from exc
    payloads: dict[str, Path] = {}
    records = provenance.get("payloads", [])
    for role in ("photon_os", "atlaso_system"):
        matches = [
            record
            for record in records
            if isinstance(record, dict) and record.get("role") == role
        ]
        if len(matches) != 1 or not isinstance(matches[0].get("file"), str):
            raise SystemExit(f"OVA provenance does not identify one {role} VMDK")
        name = matches[0]["file"]
        if PurePosixPath(name).name != name:
            raise SystemExit("OVA provenance contains an unsafe payload filename")
        path = asset_root / name
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"OVA {role} VMDK is missing or unsafe")
        payloads[role] = path
    return payloads


def _git_source_bytes(repo_root: Path, source_commit: str, source_path: str) -> bytes:
    """Read one immutable source file from the admitted release commit."""

    result = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{source_commit}:{source_path}"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise SystemExit(f"admitted commit is missing deployed source: {source_path}")
    return result.stdout


def _git_trust_key_paths(repo_root: Path, source_commit: str) -> list[str]:
    """List the exact public update-trust keys in the admitted release commit."""

    directory = "image/common/update-trust"
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-tree", "-r", "--name-only", source_commit, directory],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    paths = [line for line in result.stdout.splitlines() if line.endswith(".pem")]
    if result.returncode or not paths or any(
        PurePosixPath(path).parent.as_posix() != directory for path in paths
    ):
        raise SystemExit("admitted commit has no safe update-trust key set")
    return sorted(paths)


def _download_guest_file(
    disk: Path, filesystem: str, guest_path: str, destination: Path
) -> bytes:
    """Download one required regular file from a read-only payload disk."""

    _guestfish(
        disk,
        [f"mount-ro {filesystem} /", f"download {guest_path} {destination.as_posix()}"],
    )
    try:
        if destination.is_symlink() or not destination.is_file():
            raise SystemExit(f"deployed system file is missing or unsafe: {guest_path}")
        return destination.read_bytes()
    except OSError as exc:
        raise SystemExit(f"deployed system file is unreadable: {guest_path}") from exc


def _verify_deployed_system_content(
    asset_root: Path, source_commit: str, repo_root: Path
) -> int:
    """Bind every release-refreshed non-wheel file to the admitted commit."""

    if SOURCE_COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise SystemExit("source commit must be a full lowercase Git SHA")
    payloads = _payload_vmdks(asset_root)
    filesystems = {role: _filesystem(disk) for role, disk in payloads.items()}
    text_targets = {
        source: (
            "atlaso_system" if target.startswith("/opt-atlaso/") else "photon_os",
            target,
        )
        for source, target in DEPLOYED_TEXT_FILES.items()
    }
    binary_targets = {
        source: ("photon_os", target)
        for source, target in DEPLOYED_BINARY_FILES.items()
    }
    verified = 0
    with tempfile.TemporaryDirectory(prefix="atlaso-system-content-") as temporary:
        temporary_root = Path(temporary)
        for source, (role, target) in {**text_targets, **binary_targets}.items():
            expected = _git_source_bytes(repo_root, source_commit, source)
            if source in text_targets:
                expected = expected.replace(b"\r\n", b"\n")
            actual = _download_guest_file(
                payloads[role],
                filesystems[role],
                target,
                temporary_root / f"file-{verified}",
            )
            if actual != expected:
                raise SystemExit(
                    f"deployed system file does not match admitted commit: {target}"
                )
            verified += 1
        trust_paths = _git_trust_key_paths(repo_root, source_commit)
        trust_names = [PurePosixPath(path).name for path in trust_paths]
        observed_names = _guestfish(
            payloads["photon_os"],
            [
                f"mount-ro {filesystems['photon_os']} /",
                "ls /etc/atlaso/update-trust.d",
            ],
        )
        if observed_names != trust_names:
            raise SystemExit(
                "deployed update-trust key set does not match admitted commit"
            )
        for source, name in zip(trust_paths, trust_names, strict=True):
            expected = _git_source_bytes(repo_root, source_commit, source)
            target = f"/etc/atlaso/update-trust.d/{name}"
            actual = _download_guest_file(
                payloads["photon_os"],
                filesystems["photon_os"],
                target,
                temporary_root / f"file-{verified}",
            )
            if actual != expected:
                raise SystemExit(
                    f"deployed system file does not match admitted commit: {target}"
                )
            verified += 1
    return verified


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


def _runtime_venv(site_packages: PurePosixPath) -> PurePosixPath:
    """Return the active release virtualenv containing one site-packages path."""

    suffix = PurePosixPath("lib/python3.14/site-packages")
    if tuple(site_packages.parts[-len(suffix.parts) :]) != suffix.parts:
        raise SystemExit("active Atlaso site-packages path has an invalid ABI layout")
    venv = site_packages.parents[2]
    if venv.name != ".venv" or not venv.as_posix().startswith(
        "/opt-atlaso/releases/"
    ):
        raise SystemExit("active Atlaso virtualenv path is missing or unsafe")
    return venv


def _console_script_bytes(
    python: str, module: str, function: str
) -> bytes:
    """Return pip's canonical POSIX console-script bytes for one entry point."""

    return (
        f"#!{python}\n"
        "# -*- coding: utf-8 -*-\n"
        "import re\n"
        "import sys\n"
        "if __name__ == '__main__':\n"
        f"    from {module} import {function}\n"
        "    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n"
        f"    sys.exit({function}())\n"
    ).encode("utf-8")


def _verify_runtime_archive(
    archive_path: Path,
    venv: PurePosixPath,
    console_scripts: dict[str, tuple[str, str]],
) -> None:
    """Verify the active interpreter link and signed-wheel console scripts."""

    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive:
                name = _normalized_tar_name(member.name)
                if "/" in name or name in members:
                    raise SystemExit("guest virtualenv bin archive is unsafe")
                members[name] = member
            current = "python"
            visited: set[str] = set()
            while True:
                if current in visited:
                    raise SystemExit("active virtualenv Python link contains a cycle")
                visited.add(current)
                member = members.get(current)
                if member is None or not member.issym():
                    raise SystemExit("active virtualenv Python is not a trusted symlink")
                target = member.linkname
                if target == "/usr/bin/python3.14":
                    break
                if target not in {"python", "python3", "python3.14"}:
                    raise SystemExit("active virtualenv Python targets an untrusted interpreter")
                current = target
            runtime_venv = venv.as_posix().replace("/opt-atlaso/", "/opt/atlaso/", 1)
            interpreters = {
                "/opt/atlaso/.venv/bin/python",
                f"{runtime_venv}/bin/python",
            }
            for name, (module, function) in console_scripts.items():
                member = members.get(name)
                if member is None or not member.isfile() or member.mode & 0o111 == 0:
                    raise SystemExit(f"active console script is missing or unsafe: {name}")
                source = archive.extractfile(member)
                if source is None:
                    raise SystemExit(f"active console script is unreadable: {name}")
                content = source.read(16 * 1024 + 1)
                expected = {
                    _console_script_bytes(python, module, function)
                    for python in interpreters
                }
                if content not in expected:
                    raise SystemExit(f"active console script does not match the signed wheel: {name}")
    except (OSError, tarfile.TarError) as exc:
        raise SystemExit("guest virtualenv bin directory could not be read safely") from exc


def verify_installed_environment(
    asset_root: Path,
    wheel: Path,
    wheelhouse: Path,
    expected_digest: str,
    source_commit: str,
    repo_root: Path,
) -> dict[str, Any]:
    """Verify the complete signed wheel set in the active guest environment."""

    records, dist_infos = _expected_environment(wheel, wheelhouse, expected_digest)
    console_scripts = _wheel_console_scripts(wheel)
    resolved_assets = asset_root.resolve(strict=True)
    disk = _payload_vmdks(resolved_assets)["atlaso_system"]
    filesystem = _filesystem(disk)
    mount = f"mount-ro {filesystem} /"
    site_lines = _guestfish(
        disk,
        [mount, "realpath /opt-atlaso/.venv/lib/python3.14/site-packages"],
    )
    if len(site_lines) != 1 or not site_lines[0].startswith("/opt-atlaso/releases/"):
        raise SystemExit("active Atlaso site-packages path is missing or unsafe")
    site_packages = PurePosixPath(site_lines[0])
    venv = _runtime_venv(site_packages)
    with tempfile.TemporaryDirectory(
        prefix="atlaso-installed-environment-"
    ) as temporary:
        archive_path = Path(temporary) / "site-packages.tar"
        _guestfish(
            disk,
            [mount, f"tar-out {site_packages.as_posix()} {archive_path.as_posix()}"],
        )
        _verify_site_packages_archive(archive_path, records, dist_infos)
        runtime_archive_path = Path(temporary) / "bin.tar"
        _guestfish(
            disk,
            [mount, f"tar-out {(venv / 'bin').as_posix()} {runtime_archive_path.as_posix()}"],
        )
        _verify_runtime_archive(runtime_archive_path, venv, console_scripts)
    system_files_verified = _verify_deployed_system_content(
        resolved_assets, source_commit, repo_root.resolve(strict=True)
    )
    return {
        "schema_version": 1,
        "kind": "atlaso-installed-environment-verification",
        "wheel_sha256": expected_digest,
        "distributions_verified": len(dist_infos),
        "files_verified": len(records),
        "console_scripts_verified": len(console_scripts),
        "system_files_verified": system_files_verified,
    }


def main(argv: list[str] | None = None) -> int:
    """Run the protected installed-wheel verification command."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args(argv)
    result = verify_installed_environment(
        args.assets,
        args.wheel,
        args.wheelhouse,
        args.expected_digest,
        args.source_commit,
        Path(__file__).resolve().parents[1],
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
