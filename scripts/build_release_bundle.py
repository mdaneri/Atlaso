#!/usr/bin/env python3
"""Provide the build release bundle repository utility."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from generate_third_party_notices import (  # noqa: E402 - local script path is established before importing the sibling module.
    generate_notice,
    locked_packages,
    vendored_records,
    wheel_records,
)

SUPPORTED_ABIS = ("cp314",)
RELEASE_OWNED_ASSETS = (
    (ROOT / "scripts/appliance/atlaso-helper", Path("bin/atlaso-helper")),
    (ROOT / "scripts/appliance/atlaso-mount-data-disks", Path("bin/atlaso-mount-data-disks")),
    (ROOT / "image/hyperv/systemd/atlaso.service", Path("systemd/atlaso.service")),
    (ROOT / "image/common/systemd/atlaso-worker.service", Path("systemd/atlaso-worker.service")),
    (ROOT / "image/common/systemd/atlaso-console.service", Path("systemd/atlaso-console.service")),
    (ROOT / "image/common/systemd/atlaso-data-disks.service", Path("systemd/atlaso-data-disks.service")),
    (
        ROOT / "image/common/systemd/atlaso-require-data-disks.conf",
        Path("systemd/atlaso.service.d/atlaso-data-disks.conf"),
    ),
    (ROOT / "image/common/systemd/atlaso-bootstrap-https.service", Path("systemd/atlaso-bootstrap-https.service")),
    (
        ROOT / "image/common/systemd/nginx-atlaso-data-disks.conf",
        Path("systemd/nginx.service.d/atlaso-data-disks.conf"),
    ),
    (
        ROOT / "image/common/udev/99-atlaso-disk-identity.rules",
        Path("udev/99-atlaso-disk-identity.rules"),
    ),
    (ROOT / "image/hyperv/data-disks.conf", Path("data-disks/hyperv.conf")),
    (ROOT / "image/vmware-workstation/data-disks.conf", Path("data-disks/vmware.conf")),
)


def run(
    command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run operation.

    Args:
        command: Command and arguments to execute.
        cwd: Working directory in which to execute the command.
        env: Environment variables supplied to the child process.


    Returns:
        The run result.
    """
    return subprocess.run(command, cwd=cwd, env=env, check=False, capture_output=True, text=True)


def git_value(args: list[str]) -> str:
    """Return git value.

    Args:
        args: Parsed command-line options consumed by the operation.


    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    result = run(["git", *args])
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def project_version() -> str:
    """Return project version.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    match = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise SystemExit("pyproject.toml does not define [project].version")
    return match.group(1)


def sha256(path: Path) -> str:
    """Return sha256.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(payload: dict) -> bytes:
    """Return canonical json.

    Args:
        payload: Validated request or task payload consumed by the operation.
    """
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Return signing key.

    Args:
        path: Filesystem or URL path to read, validate, or update.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("release signing key must be an Ed25519 private key")
    return key


def write_signature(path: Path, *, key_id: str, signature: bytes) -> None:
    """Persist signature.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        key_id: Identifier of the key.
        signature: Signature supplied by the caller.
    """
    path.write_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "key_id": key_id,
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )
    )


def copy_source(target: Path) -> None:
    """Handle copy source.

    Args:
        target: Target resource or location affected by the operation.
    """
    shutil.copytree(
        ROOT,
        target,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".pytest_cache",
            "build",
            "data",
            "dist",
            "output",
            "test-results",
            "test-vms",
            "__pycache__",
            "*.pyc",
        ),
    )


def build_application_wheel(target: Path, *, commit: str, built_at: str) -> Path:
    """Build application wheel.

    Args:
        target: Target resource or location affected by the operation.
        commit: Commit consumed by build application wheel.
        built_at: Built at consumed by build application wheel.


    Returns:
        The built application wheel.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    source = target / "source"
    copy_source(source)
    (source / "atlaso/_build.py").write_text(
        "\n".join(
            [
                '"""Build metadata generated by scripts/build_release_bundle.py."""',
                f'BUILD_VERSION = "{project_version()}"',
                f'GIT_COMMIT = "{commit}"',
                f'BUILD_TIME_UTC = "{built_at}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    wheel_dir = target / "application-wheel"
    wheel_dir.mkdir()
    build_time = datetime.fromisoformat(built_at.replace("Z", "+00:00"))
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = str(int(build_time.timestamp()))
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_NO_INDEX"] = "1"
    result = run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            str(source),
            "-w",
            str(wheel_dir),
        ],
        cwd=source,
        env=env,
    )
    if result.returncode != 0:
        raise SystemExit((result.stdout + "\n" + result.stderr).strip())
    wheels = list(wheel_dir.glob("atlaso-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("release build must produce exactly one Atlaso wheel")
    return wheels[0]


def deterministic_tar_gz(source: Path, output: Path) -> None:
    """Handle deterministic tar gz.

    Args:
        source: Source object or location from which data is obtained.
        output: Filesystem path associated with output.
    """
    def normalized(info: tarfile.TarInfo) -> tarfile.TarInfo:
        """Return normalized.

        Args:
            info: Info consumed by normalized.
        """
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        info.mtime = 0
        info.pax_headers = {}
        info.mode = (
            0o755
            if info.isdir()
            or info.name.endswith(("/atlaso-helper", "/atlaso-mount-data-disks", "/bin/python"))
            else 0o644
        )
        return info

    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
                    archive.add(path, arcname=path.relative_to(source).as_posix(), recursive=False, filter=normalized)


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    parser = argparse.ArgumentParser(description="Build a signed, offline Atlaso appliance release bundle.")
    parser.add_argument("--wheelhouses", type=Path, required=True, help="Directory containing the cp314 wheelhouse.")
    parser.add_argument("--lock", type=Path, default=ROOT / "requirements-appliance.lock")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/release")
    parser.add_argument("--repository", default="mdaneri/Atlaso")
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--commit", default="")
    parser.add_argument("--built-at", default="")
    args = parser.parse_args()

    commit = args.commit.strip() or git_value(["rev-parse", "HEAD"])
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise SystemExit("release commit must be a full lowercase hexadecimal commit")
    version = project_version()
    built_at = args.built_at.strip() or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    tag = f"v{version}"
    release_base = f"https://github.com/{args.repository}/releases/download/{tag}"
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    signing_key = load_signing_key(args.signing_key)

    with tempfile.TemporaryDirectory(prefix="atlaso-release-") as temporary:
        temp_root = Path(temporary)
        application_wheel = build_application_wheel(temp_root, commit=commit, built_at=built_at)
        bundle_root = temp_root / "bundle"
        (bundle_root / "packages").mkdir(parents=True)
        shutil.copy2(application_wheel, bundle_root / "packages" / application_wheel.name)
        shutil.copy2(args.lock, bundle_root / "requirements-appliance.lock")
        for abi in SUPPORTED_ABIS:
            source = args.wheelhouses.resolve() / abi
            wheels = sorted(source.glob("*.whl")) if source.exists() else []
            if not wheels:
                raise SystemExit(f"wheelhouse {abi} is missing or empty")
            wheelhouse_lock = source / "requirements-wheelhouse.lock"
            if not wheelhouse_lock.is_file():
                raise SystemExit(f"wheelhouse {abi} is missing requirements-wheelhouse.lock")
            destination = bundle_root / "wheelhouse" / abi
            destination.mkdir(parents=True)
            for wheel in wheels:
                shutil.copy2(wheel, destination / wheel.name)
            shutil.copy2(wheelhouse_lock, destination / wheelhouse_lock.name)
        expected_packages = locked_packages(args.lock)
        python_packages: dict[str, dict[str, str]] = {}
        for abi in SUPPORTED_ABIS:
            records = wheel_records(bundle_root / "wheelhouse" / abi, expected_packages)
            for name, record in records.items():
                if name in python_packages and python_packages[name] != record:
                    raise SystemExit(f"wheelhouses disagree on metadata for {record['name']}")
                python_packages[name] = record
        notice_path = bundle_root / "THIRD_PARTY_NOTICES.md"
        generate_notice(
            output=notice_path,
            version=version,
            python_records=python_packages,
            vendored=vendored_records(ROOT / "scripts/third_party_notices.json"),
            rpms=None,
        )
        for source, relative_destination in RELEASE_OWNED_ASSETS:
            destination = bundle_root / relative_destination
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        trust_source = ROOT / "image/common/update-trust"
        if trust_source.exists():
            shutil.copytree(trust_source, bundle_root / "trust")
        bundle_metadata = {
            "schema_version": 1,
            "version": version,
            "git_commit": commit,
            "built_at": built_at,
            "supported_python_abis": list(SUPPORTED_ABIS),
        }
        (bundle_root / "bundle-metadata.json").write_bytes(canonical_json(bundle_metadata))
        content_hashes = {
            path.relative_to(bundle_root).as_posix(): sha256(path)
            for path in sorted(bundle_root.rglob("*"))
            if path.is_file()
        }
        bundle_name = f"atlaso-appliance-{version}.tar.gz"
        bundle_path = output / bundle_name
        deterministic_tar_gz(bundle_root, bundle_path)
        release_summary = " ".join(
            git_value(["show", "-s", "--format=%s", commit]).split()
        )[:240]
        if not release_summary:
            raise SystemExit("release commit subject is empty")
        release_manifest = {
            "schema_version": 2,
            "kind": "atlaso-release",
            "updater_protocol": 2,
            "database_schema_version": 1,
            "version": version,
            "git_commit": commit,
            "summary": release_summary,
            "release_notes_url": f"https://github.com/mdaneri/Atlaso/releases/tag/v{version}",
            "built_at": built_at,
            "signing_key_id": args.signing_key_id,
            "supported_python_abis": list(SUPPORTED_ABIS),
            "bundle": {
                "url": f"{release_base}/{bundle_name}",
                "size": bundle_path.stat().st_size,
                "sha256": sha256(bundle_path),
            },
            "content_hashes": content_hashes,
        }
        release_manifest_bytes = canonical_json(release_manifest)
        manifest_path = output / "release-manifest.json"
        manifest_path.write_bytes(release_manifest_bytes)
        shutil.copy2(notice_path, output / f"atlaso-third-party-notices-{version}.md")
        write_signature(
            output / "release-manifest.json.sig",
            key_id=args.signing_key_id,
            signature=signing_key.sign(release_manifest_bytes),
        )

    print(json.dumps({"version": version, "commit": commit, "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
