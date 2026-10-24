"""Prepare unsigned development-only installation inputs from admitted releases."""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

from scripts.installation import build
from scripts.installation.manifest import (
    DEVELOPMENT_KEY_ID,
    PHOTON_INSTALLER_SHA256,
    SOURCE_ISO_SHA512,
    inventory,
)


def _source_archive(repository: Path, commit: str) -> dict[str, bytes]:
    """Read files from an exact clean checkout commit, without main admission.

    Args:
        repository: Clean Atlaso checkout to archive.
        commit: Full source commit SHA expected at checkout HEAD.
    """
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("development source commit must be a full SHA")
    head = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != commit:
        raise ValueError("development source checkout HEAD differs from the requested commit")
    status = subprocess.check_output(
        ["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=all"],
        text=True,
    )
    if status:
        raise ValueError("development source checkout must be clean")
    archive = subprocess.check_output(
        ["git", "-C", str(repository), "archive", "--format=tar", commit]
    )
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        for member in stream:
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or path.is_absolute()
                or path.as_posix() != member.name
                or ".." in path.parts
                or "\\" in member.name
            ):
                if member.isdir():
                    continue
                raise ValueError("development source archive contains an unsafe entry")
            if member.name in files or member.size < 0 or member.size > 128 * 1024**2:
                raise ValueError("development source archive has a duplicate or oversized file")
            source = stream.extractfile(member)
            if source is None:
                raise ValueError("development source archive entry is unreadable")
            content = source.read()
            if len(content) != member.size:
                raise ValueError("development source archive entry length differs")
            files[member.name] = content
    if sum(map(len, files.values())) > 1024**3:
        raise ValueError("development source archive exceeds its allocation bound")
    if not files:
        raise ValueError("development source archive is empty")
    _validate_checkout(repository, commit, files)
    return files


def _validate_checkout(repository: Path, commit: str, files: dict[str, bytes]) -> None:
    """Reject stale, dirty, flagged, or byte-divergent tracked checkout files.

    Args:
        repository: Checkout expected to match the source archive.
        commit: Full source commit SHA expected at checkout HEAD.
        files: Exact tracked-file bytes from `git archive`.
    """
    head = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != commit:
        raise ValueError("development source checkout HEAD differs from the requested commit")
    status = subprocess.check_output(
        ["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=all"],
        text=True,
    )
    if status:
        raise ValueError("development source checkout must be clean")
    index = subprocess.check_output(
        ["git", "-C", str(repository), "ls-files", "-v", "-z"]
    )
    records = index.split(b"\0")
    tracked: set[str] = set()
    for record in records:
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" " or record[:1].islower() or record[:1] == b"S":
            raise ValueError("development source index has assume-unchanged or skip-worktree entries")
        tracked.add(record[2:].decode("utf-8", errors="strict"))
    if tracked != set(files):
        raise ValueError("development source tracked files differ from the archive")
    for name, expected in files.items():
        path = repository / Path(*PurePosixPath(name).parts)
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise ValueError("development source checkout file differs from its commit archive")


def prepare_payload(
    *,
    repository: Path,
    commit: str,
    software_version: str,
    software_commit: str,
    software: Path,
    rpms: Path,
    powercli: Path,
    output: Path,
    scratch: Path,
) -> None:
    """Prepare unsigned test inputs with PR source and main software identities.

    Args:
        repository: Clean checkout whose exact HEAD provides installer source.
        commit: Exact full SHA of the checkout and installer source.
        software_version: Version of the separately signed main software release.
        software_commit: Full main commit bound by the signed software release.
        software: Signed software release directory.
        rpms: Captured Photon RPM package directory.
        powercli: PowerCLI module directory accepted by Validate mode.
        output: Absent destination for the unsigned development payload.
        scratch: Existing private validation and repository-generation directory.
    """
    if output.exists() or output.is_symlink():
        raise ValueError("development installation payload output must be absent")
    build._require_ordinary_directory(output.parent)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", software_version):
        raise ValueError("development software version is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", software_commit):
        raise ValueError("development software commit must be a full SHA")

    source_files = _source_archive(repository, commit)
    subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", software_commit, "origin/main"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    from scripts.prepare_virtualization_source import verify_directory

    trust_key = repository / "image/common/update-trust/atlaso-release-2026-01.pem"
    software_identity = verify_directory(software, trust_key, software_version, software_commit)
    if software_identity.get("version") != software_version or software_identity.get("source_commit") != software_commit:
        raise ValueError("signed software identity differs from the admitted main release")

    for root in (rpms, powercli):
        build._validate_ordinary_tree(root)
    build._validate_ordinary_tree(software)
    build._require_ordinary_directory(scratch)
    total = sum(map(len, source_files.values())) + sum(
        item["size"] for root in (software, rpms, powercli) for item in inventory(root)
    )
    if total > 16 * 1024**3 or shutil.disk_usage(output.parent).free < total * 2 + 2 * 1024**3:
        raise ValueError("development installation payload exceeds its capacity admission")

    scratch_paths = {
        "input_rpm": scratch / "rpm-validation-input",
        "copied_rpm": scratch / "rpm-validation-copied",
        "repository": scratch / "rpm-repository-rebuild",
    }
    if any(path.exists() or path.is_symlink() for path in scratch_paths.values()):
        raise ValueError("development validation scratch work paths must be absent")
    for path in scratch_paths.values():
        path.mkdir()

    build.verify_rpms(rpms, repository, scratch_paths["input_rpm"])
    subprocess.run(
        [
            "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
            str(repository / "image/common/powershell/provision-powercli.ps1"),
            "-Mode", "Validate", "-ModuleRoot", str(powercli),
        ],
        check=True,
    )

    output.mkdir()
    source_root = output / "source"
    for name, content in source_files.items():
        target = source_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    build.verify_source(source_root, source_files)
    for name, root in (("software", software), ("rpms", rpms), ("powercli", powercli)):
        shutil.copytree(root, output / name)
    copied_software = verify_directory(output / "software", trust_key, software_version, software_commit)
    if copied_software != software_identity:
        raise ValueError("copied software release differs from its admitted identity")
    rpm_records = build.verify_rpms(output / "rpms", source_root, scratch_paths["copied_rpm"])
    subprocess.run(
        [
            "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
            str(repository / "image/common/powershell/provision-powercli.ps1"),
            "-Mode", "Validate", "-ModuleRoot", str(output / "powercli"),
        ],
        check=True,
    )
    build.rebuild_repository(output / "rpms", scratch_paths["repository"])
    _validate_checkout(repository, commit, source_files)

    (output / "rpm-repos").mkdir()
    configuration, repository_text = build.repository_configuration(source_root)
    (output / "tdnf.conf").write_text(configuration, encoding="utf-8")
    (output / "rpm-repos/atlaso-installation.repo").write_text(repository_text, encoding="utf-8")
    manifest = {
        "schema": 1,
        "architecture": "x86_64",
        "version": software_version,
        "source_commit": commit,
        "signing_key_id": DEVELOPMENT_KEY_ID,
        "development": {
            "schema": 1,
            "software_source_commit": software_commit,
            "non_production": True,
        },
        "photon_installer": "2.2",
        "photon_installer_sha256": PHOTON_INSTALLER_SHA256,
        "photon_iso_sha512": SOURCE_ISO_SHA512,
        "packages": build.package_selection(source_root),
        "files": inventory(output),
        "rpm_inventory": rpm_records,
    }
    from scripts.installation.manifest import MANIFEST, canonical_json

    (output / MANIFEST).write_bytes(canonical_json(manifest))
