"""Prepare and independently validate inputs for the offline ISO finalizer."""

from __future__ import annotations

import gzip
import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from scripts.installation.assets import _safe_name
from scripts.installation.manifest import (
    KEY_ID,
    MANIFEST,
    PHOTON_INSTALLER_SHA256,
    SOURCE_ISO_SHA512,
    canonical_json,
    digest,
    inventory,
)

MEDIA = "/mnt/atlaso-install/atlaso"
BASE_PACKAGES = {"filesystem", "bash", "linux", "linux-firmware", "photon-release", "rpm", "tdnf", "systemd", "util-linux", "ca-certificates", "grub2", "grub2-efi-image", "xfsprogs", "btrfs-progs", "dosfstools"}


def package_selection(source: Path) -> list[str]:
    """Reuse the shared provisioner's package selection, adding native boot assets.

    Args:
        source: Input source file or directory."""
    text = (source / "image/common/scripts/provision-atlaso.sh").read_text()
    commands = re.findall(r'run_tdnf "Photon appliance package installation" \\\n  install ([^\n]+)', text)
    if len(commands) != 1:
        raise ValueError("shared appliance package selection is ambiguous")
    packages = commands[0].replace("$GUEST_INTEGRATION_PACKAGES", "").split()
    if not packages or not all(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9+._-]*", name) for name in packages):
        raise ValueError("shared appliance package selection is invalid")
    return sorted(BASE_PACKAGES | set(packages))


def source_archive(repository: Path, commit: str) -> dict[str, bytes]:
    """Read only ordinary tracked files from one exact, main-reachable Git commit.

    Args:
        repository: Atlaso repository checkout used as the trusted source.
        commit: Full source commit SHA being prepared."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source commit must be a full SHA")
    subprocess.run(["git", "-C", str(repository), "merge-base", "--is-ancestor", commit, "origin/main"], check=True)
    archive = subprocess.check_output(["git", "-C", str(repository), "archive", "--format=tar", commit])
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        for item in stream:
            path = PurePosixPath(item.name)
            if item.isdir():
                continue
            if not item.isfile() or path.is_absolute() or ".." in path.parts or "\\" in item.name:
                raise ValueError("source snapshot contains a linked or unsafe entry")
            if item.name in files or item.size > 128 * 1024**2:
                raise ValueError("source snapshot contains a duplicate or oversized entry")
            handle = stream.extractfile(item)
            if handle is None:
                raise ValueError("source snapshot file is unreadable")
            files[item.name] = handle.read()
    if sum(map(len, files.values())) > 1024**3:
        raise ValueError("source snapshot exceeds its allocation bound")
    return files


def verify_source(source: Path, expected: dict[str, bytes]) -> None:
    """Bind every staged deployment source to the trusted exact-commit snapshot.

    Args:
        source: Input source file or directory.
        expected: Trusted file mapping expected from the source snapshot."""
    files = inventory(source)
    if {item["path"] for item in files} != set(expected):
        raise ValueError("installation deployment source inventory differs from Git")
    for name, content in expected.items():
        if (source / name).read_bytes() != content:
            raise ValueError("installation deployment source differs from Git")


def verify_rpms(root: Path, source: Path, scratch: Path) -> list[dict]:
    """Reuse the release RPM verification tool boundary and admitted Photon keys.

    Args:
        root: Root directory containing the files being checked.
        source: Input source file or directory.
        scratch: Existing private directory for temporary validation data."""
    from scripts.verify_virtualization_guest_wheel import (
        _photon_repository_inventory,
        _require_admitted_runtime_package,
        _run_runtime_tool,
    )

    packages = sorted(root.glob("*.rpm"))
    if not packages or any(path.name != "repodata" and path.suffix != ".rpm" for path in root.iterdir()):
        raise ValueError("installation RPM repository is empty or contains unexpected entries")
    database = scratch / "rpmdb"
    database.mkdir()
    _run_runtime_tool(["rpm", "--dbpath", str(database), "--initdb"])
    keys = sorted((source / "image/common/photon-rpm-gpg").glob("VMWARE-RPM-GPG-KEY*"))
    if not keys:
        raise ValueError("admitted Photon RPM keys are missing")
    imported_keys = 0
    for key in keys:
        try:
            _run_runtime_tool(["rpm", "--dbpath", str(database), "--import", str(key)])
        except SystemExit:
            # Some host crypto policies reject the admitted legacy certificate.
            # Retain the host policy: every package must still authenticate with
            # a successfully imported admitted key below, or the build fails.
            continue
        imported_keys += 1
    if not imported_keys:
        raise ValueError("no admitted Photon RPM key is supported by the builder")
    records = []
    admitted = _photon_repository_inventory()
    for package in packages:
        checksum = digest(package)
        # The summary format is stable across RPM versions; verbose output uses
        # separate signature lines on newer builders and has no summary marker.
        result = _run_runtime_tool(["rpmkeys", "--dbpath", str(database), "--checksig", str(package)])
        if "signatures OK" not in result:
            raise ValueError("installation RPM is not signed by an admitted Photon key")
        _require_admitted_runtime_package(package, "rpm", admitted)
        query = _run_runtime_tool(["rpm", "--dbpath", str(database), "-qp", "--qf", "ATLASO\\t%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n", str(package)])
        # Shared tool diagnostics may accompany successful stdout. Parse only
        # one explicitly marked metadata row, as the repository verifier does.
        rows = [line.split("\t")[1:] for line in query.splitlines() if line.startswith("ATLASO\t")]
        if len(rows) != 1 or len(rows[0]) != 3 or rows[0][2] not in {"x86_64", "noarch"}:
            raise ValueError("installation RPM architecture is unsupported")
        fields = rows[0]
        records.append({"file": package.name, "name": fields[0], "version": fields[1], "architecture": fields[2], "sha256": checksum})
    names = [item["name"] for item in records]
    if len(names) != len(set(names)) or not set(package_selection(source)) <= set(names):
        raise ValueError("installation RPM closure is incomplete or contains multiple package versions")
    if not next(item["version"] for item in records if item["name"] == "python3").startswith("3.14."):
        raise ValueError("installation requires the exact CPython 3.14 appliance ABI")
    return records


def capture_packages(repository: Path, output: Path) -> None:
    """Resolve the complete RPM closure during an authorized Photon build.

    Args:
        repository: Atlaso repository checkout used as the trusted source.
        output: Destination path for the generated output."""
    if output.exists() or output.is_symlink() or not output.is_absolute():
        raise ValueError("RPM capture requires an absent absolute caller-owned output")
    packages = package_selection(repository)
    output.mkdir()
    subprocess.run(["python3", str(repository / "image/common/scripts/configure_photon_repositories.py")], check=True)
    subprocess.run([
        "python3", str(repository / "scripts/run_tdnf_with_progress.py"), "--label", "Offline installation RPM closure",
        "--cache-dir", "/var/cache/tdnf", "--", "tdnf", "-y", "install", "--downloadonly", "--alldeps", "--downloaddir", str(output), *packages,
    ], check=True)
    if not any(output.glob("*.rpm")):
        raise ValueError("build-time RPM dependency resolution produced no packages")


def pack_inputs(payload: Path, output: Path) -> None:
    """Package ordinary candidate files without secret or environment discovery.

    Args:
        payload: Prepared candidate directory to package.
        output: Destination path for the generated output."""
    records = inventory(payload)
    names = sorted({item["path"] for item in records} | {MANIFEST})
    if sum((payload / name).stat().st_size for name in names) > 16 * 1024**3:
        raise ValueError("candidate inputs exceed the expansion bound")
    with output.open("xb") as target, gzip.GzipFile(filename="", mode="wb", fileobj=target, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            for name in names:
                path = payload / name
                digest(path)
                info = tarfile.TarInfo(name)
                info.size = path.stat().st_size
                info.mode = 0o644
                with path.open("rb") as handle:
                    archive.addfile(info, handle)


def unpack_inputs(archive: Path, destination: Path) -> None:
    """Extract a bounded candidate archive without links or path traversal.

    Args:
        archive: Newc cpio archive bytes to parse or rewrite.
        destination: Existing directory that receives the generated files."""
    digest(archive)
    if destination.exists() or destination.is_symlink():
        raise ValueError("candidate extraction destination must be absent")
    with tarfile.open(archive, "r:gz") as stream:
        members = []
        for member in stream:
            if len(members) >= 100000:
                raise ValueError("candidate archive file count exceeds its bound")
            members.append(member)
        names = set()
        size = 0
        if len(members) > 100000:
            raise ValueError("candidate archive file count exceeds its bound")
        for member in members:
            path = PurePosixPath(member.name)
            if not member.isfile() or path.is_absolute() or PureWindowsPath(member.name).drive or path.as_posix() != member.name or ".." in path.parts or ":" in member.name or "\\" in member.name or member.name in names or member.size < 0:
                raise ValueError("candidate archive contains an unsafe or duplicate entry")
            for component in path.parts:
                _safe_name(component)
            names.add(member.name)
            size += member.size
        if size > 16 * 1024**3 or shutil.disk_usage(destination.parent).free < size + 2 * 1024**3:
            raise ValueError("candidate extraction exceeds its capacity admission")
        destination.mkdir()
        for member in members:
            path = destination / member.name
            path.parent.mkdir(parents=True, exist_ok=True)
            source = stream.extractfile(member)
            if source is None:
                raise ValueError("candidate archive entry is unreadable")
            with path.open("xb") as target:
                shutil.copyfileobj(source, target)
            if path.stat().st_size != member.size:
                raise ValueError("candidate archive entry length differs")


def validate_candidate(root: Path, *, repository: Path, commit: str, version: str, trust_key: Path, scratch: Path) -> dict:
    """Revalidate an untrusted staged candidate before accessing a signing key.

    Args:
        root: Root directory containing the files being checked.
        repository: Atlaso repository checkout used as the trusted source.
        commit: Full source commit SHA being prepared.
        version: Software release version expected in the candidate.
        trust_key: Trusted public key used to verify signed metadata.
        scratch: Existing private directory for temporary validation data."""
    from scripts.prepare_virtualization_source import verify_directory

    source = root / "source"
    inventory(root)
    permitted = {"source", "software", "rpms", "powercli", "rpm-repos", MANIFEST, MANIFEST + ".sig", "tdnf.conf"}
    if {path.name for path in root.iterdir()} - permitted:
        raise ValueError("candidate contains unexpected top-level content")
    verify_source(source, source_archive(repository, commit))
    configuration, repository_text = repository_configuration(source)
    if (root / "tdnf.conf").read_text() != configuration or (root / "rpm-repos/atlaso-installation.repo").read_text() != repository_text:
        raise ValueError("candidate RPM repository configuration differs from its local-only contract")
    if {path.name for path in (root / "rpm-repos").iterdir()} != {"atlaso-installation.repo"}:
        raise ValueError("candidate contains an unexpected RPM repository definition")
    software = verify_directory(root / "software", trust_key, version, commit)
    records = verify_rpms(root / "rpms", source, scratch)
    subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(repository / "image/common/powershell/provision-powercli.ps1"), "-Mode", "Validate", "-ModuleRoot", str(root / "powercli")],
        check=True,
    )
    return {"software": software, "rpms": records}


def repository_configuration(source: Path) -> tuple[str, str]:
    """Render the same local-only repository configuration at preparation and signing.

    Args:
        source: Input source file or directory."""
    keys = " ".join(f"file://{MEDIA}/source/image/common/photon-rpm-gpg/{path.name}" for path in sorted((source / "image/common/photon-rpm-gpg").glob("VMWARE-RPM-GPG-KEY*")))
    configuration = f"[main]\nreposdir={MEDIA}/rpm-repos\ngpgcheck=1\nkeepcache=0\n"
    repository = f"[atlaso-installation]\nname=Atlaso offline installation\nbaseurl=file://{MEDIA}/rpms\nenabled=1\ngpgcheck=1\ngpgkey={keys}\n"
    return configuration, repository


def prepare_payload(*, repository: Path, commit: str, version: str, software: Path, rpms: Path, powercli: Path, output: Path) -> None:
    """Stage only verified-source inputs; preserve incomplete output on failure.

    Args:
        repository: Atlaso repository checkout used as the trusted source.
        commit: Full source commit SHA being prepared.
        version: Software release version expected in the candidate.
        software: Verified software release payload directory.
        rpms: Captured Photon RPM package directory.
        powercli: PowerCLI module directory accepted by Validate mode.
        output: Destination path for the generated output."""
    if output.exists() or output.is_symlink():
        raise ValueError("installation payload output must be absent")
    expected = source_archive(repository, commit)
    # Validate ordinary input trees before copying; no credential/configuration
    # from the source checkout or producer environment enters the payload.
    for root in (software, rpms, powercli):
        inventory(root)
    total = sum(len(item) for item in expected.values()) + sum(path.stat().st_size for root in (software, rpms, powercli) for path in root.rglob("*") if path.is_file())
    if total > 16 * 1024**3 or shutil.disk_usage(output.parent).free < total * 2 + 2 * 1024**3:
        raise ValueError("installation payload exceeds its capacity admission")
    output.mkdir()
    for name, content in expected.items():
        target = output / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    for name, source in (("software", software), ("rpms", rpms), ("powercli", powercli)):
        shutil.copytree(source, output / name)
    subprocess.run(["createrepo_c", "--checksum", "sha256", str(output / "rpms")], check=True)
    (output / "rpm-repos").mkdir()
    configuration, repository_text = repository_configuration(output / "source")
    (output / "tdnf.conf").write_text(configuration)
    (output / "rpm-repos/atlaso-installation.repo").write_text(repository_text)
    # The finalizer regenerates this inventory after independent input validation.
    value = {
        "schema": 1, "architecture": "x86_64", "version": version, "source_commit": commit,
        "signing_key_id": KEY_ID, "photon_installer": "2.2", "packages": package_selection(output / "source"),
        "photon_installer_sha256": PHOTON_INSTALLER_SHA256, "photon_iso_sha512": SOURCE_ISO_SHA512,
        "files": inventory(output),
    }
    (output / MANIFEST).write_bytes(canonical_json(value))


def _require_ordinary_directory(path: Path) -> Path:
    """Require a real directory and non-linked ancestry before repository mutation.

    Args:
        path: Filesystem path to the input or target."""
    absolute = Path(os.path.abspath(path))
    if absolute.resolve(strict=True) != absolute:
        raise ValueError("installation repository paths cannot contain symbolic links")
    chain = list(reversed((absolute, *absolute.parents)))
    for item in chain:
        info = item.lstat()
        if item.is_symlink() or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ValueError("installation repository paths cannot contain links or reparse points")
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("installation repository paths must have directory ancestry")
    return absolute


def _validate_ordinary_tree(root: Path) -> list[dict]:
    """Reject linked, special, or multiply-linked objects anywhere in a tree.

    Args:
        root: Root directory containing the files being checked."""
    root = _require_ordinary_directory(root)
    for path in root.rglob("*"):
        info = path.lstat()
        if path.is_symlink() or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ValueError("installation repository contains a link or reparse point")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("installation repository contains a special or multiply-linked file")
    return inventory(root)


def rebuild_repository(rpms: Path, scratch: Path) -> None:
    """Replace candidate RPM metadata with fresh SHA-256 metadata from its RPM files.

    Args:
        rpms: Captured Photon RPM package directory.
        scratch: Existing private directory for temporary validation data."""
    repository = _require_ordinary_directory(rpms)
    work = _require_ordinary_directory(scratch)
    metadata = repository / "repodata"
    generated = work / "rpm-metadata"
    untrusted = work / "untrusted-rpm-metadata"
    _validate_ordinary_tree(repository)
    if generated.exists() or generated.is_symlink() or untrusted.exists() or untrusted.is_symlink():
        raise ValueError("RPM metadata work paths must be absent")
    if metadata.exists() and not stat.S_ISDIR(metadata.lstat().st_mode):
        raise ValueError("existing RPM metadata must be an ordinary directory")
    entries = list(repository.iterdir())
    packages = [path for path in entries if path.name.endswith(".rpm") and stat.S_ISREG(path.lstat().st_mode)]
    if not packages:
        raise ValueError("RPM repository contains no packages")
    if any(path.name != "repodata" and path not in packages for path in entries):
        raise ValueError("RPM repository contains unexpected files")

    if metadata.exists():
        os.rename(metadata, untrusted)
    generated.mkdir()
    subprocess.run(
        ["createrepo_c", "--checksum", "sha256", "--outputdir", str(generated), str(repository)],
        check=True,
    )
    _validate_ordinary_tree(generated)
    generated_entries = list(generated.iterdir())
    generated_metadata = generated / "repodata"
    if len(generated_entries) != 1 or generated_entries[0].name != "repodata" or not stat.S_ISDIR(generated_metadata.lstat().st_mode):
        raise ValueError("createrepo_c output must contain only an ordinary repodata directory")
    generated_records = _validate_ordinary_tree(generated_metadata)
    if not generated_records:
        raise ValueError("createrepo_c produced empty repository metadata")
    shutil.copytree(generated_metadata, metadata)
    copied_records = _validate_ordinary_tree(metadata)
    if copied_records != generated_records:
        raise ValueError("copied RPM metadata differs from generated metadata")
