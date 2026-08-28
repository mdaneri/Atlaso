#!/usr/bin/env python3
"""Verify and extract the exact software release used by a virtualization build."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from atlaso.app.services.release_updates import (  # noqa: E402
    signature_document,
    verify_signed_json,
)

COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAXIMUM_MEMBER_BYTES = 2_147_483_647


def _sha256(path: Path) -> str:
    """Return a lowercase SHA-256 digest.

    Args:
        path: Ordinary file to hash.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ordinary_file(path: Path, label: str) -> Path:
    """Resolve one required ordinary input file.

    Args:
        path: Candidate input.
        label: Human-readable role used in failures.
    """

    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"{label} must be an ordinary file: {path}")
    return path.resolve(strict=True)


def _safe_member_name(name: str) -> str:
    """Validate and normalize one bundle member name.

    Args:
        name: POSIX archive member path.
    """

    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise SystemExit(f"release bundle contains an unsafe member path: {name}")
    return path.as_posix()


def prepare(
    *,
    manifest_path: Path,
    signature_path: Path,
    bundle_path: Path,
    trust_key_path: Path,
    output: Path,
    expected_version: str,
    expected_commit: str,
) -> dict[str, str]:
    """Verify a signed software release and extract its exact Python inputs.

    Args:
        manifest_path: Signed release manifest.
        signature_path: Detached manifest signature.
        bundle_path: Immutable appliance bundle named by the manifest.
        trust_key_path: Selected checked-in Ed25519 public key.
        output: Empty destination for verified release inputs.
        expected_version: Exact synchronized Atlaso version.
        expected_commit: Exact successful-main commit.
    """

    if (
        SEMVER_PATTERN.fullmatch(expected_version) is None
        or COMMIT_PATTERN.fullmatch(expected_commit) is None
    ):
        raise SystemExit("expected software release identity is invalid")
    manifest_file = _ordinary_file(manifest_path, "release manifest")
    signature_file = _ordinary_file(signature_path, "release signature")
    bundle_file = _ordinary_file(bundle_path, "release bundle")
    trust_key_file = _ordinary_file(trust_key_path, "release trust key")
    raw_manifest = manifest_file.read_bytes()
    raw_signature = signature_file.read_bytes()
    if signature_document(raw_signature)["key_id"] != trust_key_file.stem:
        raise SystemExit("release signature does not use the selected named trust key")
    release = verify_signed_json(
        raw_manifest,
        raw_signature,
        trust_dir=trust_key_file.parent,
        document_kind="release",
    )
    if (
        release["version"] != expected_version
        or release["git_commit"] != expected_commit
    ):
        raise SystemExit(
            "signed software release does not match the requested version and commit"
        )
    if "cp314" not in release["supported_python_abis"]:
        raise SystemExit("signed software release does not support CPython 3.14")
    bundle = release["bundle"]
    expected_bundle_name = Path(urlparse(str(bundle["url"])).path).name
    if bundle_file.name != expected_bundle_name:
        raise SystemExit("release bundle filename does not match the signed manifest")
    if (
        bundle_file.stat().st_size != bundle["size"]
        or _sha256(bundle_file) != bundle["sha256"]
    ):
        raise SystemExit("release bundle does not match the signed size and digest")
    content_hashes = release.get("content_hashes")
    if not isinstance(content_hashes, dict) or not content_hashes:
        raise SystemExit("signed release manifest contains no bundle content hashes")
    if any(
        not isinstance(name, str)
        or _safe_member_name(name) != name
        or not isinstance(digest, str)
        or DIGEST_PATTERN.fullmatch(digest) is None
        for name, digest in content_hashes.items()
    ):
        raise SystemExit(
            "signed release manifest contains an invalid content hash record"
        )
    if output.exists():
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            raise SystemExit(
                "virtualization source output must be an empty ordinary directory"
            )
    else:
        output.mkdir(parents=True)
    output_root = output.resolve(strict=True)
    selected_names: set[str] = set()
    wheel_names: list[str] = []
    with tarfile.open(bundle_file, mode="r:gz") as archive:
        archive_files: dict[str, tarfile.TarInfo] = {}
        for member in archive.getmembers():
            name = _safe_member_name(member.name)
            if member.isdir():
                continue
            if (
                not member.isfile()
                or member.size <= 0
                or member.size >= MAXIMUM_MEMBER_BYTES
            ):
                raise SystemExit(
                    f"release bundle member is not a bounded regular file: {name}"
                )
            if name in archive_files:
                raise SystemExit(f"release bundle contains a duplicate member: {name}")
            archive_files[name] = member
        if set(archive_files) != set(content_hashes):
            raise SystemExit(
                "release bundle members do not exactly match the signed content hashes"
            )
        for name, member in sorted(archive_files.items()):
            if not (
                name.startswith("packages/")
                or name.startswith("wheelhouse/cp314/")
                or name in {"requirements-appliance.lock", "bundle-metadata.json"}
            ):
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise SystemExit(f"release bundle member is unreadable: {name}")
            destination = output_root.joinpath(*PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with destination.open("xb") as target:
                remaining = member.size
                while remaining:
                    block = extracted.read(min(1024 * 1024, remaining))
                    if not block:
                        raise SystemExit(f"release bundle member ended early: {name}")
                    target.write(block)
                    digest.update(block)
                    remaining -= len(block)
                if extracted.read(1):
                    raise SystemExit(
                        f"release bundle member exceeds its declared size: {name}"
                    )
            if digest.hexdigest() != content_hashes[name]:
                raise SystemExit(f"release bundle member digest mismatch: {name}")
            selected_names.add(name)
            if name.startswith("packages/") and name.endswith(".whl"):
                wheel_names.append(name)
    if len(wheel_names) != 1 or not wheel_names[0].startswith(
        f"packages/atlaso-{expected_version}-"
    ):
        raise SystemExit(
            "release bundle must contain exactly one versioned Atlaso application wheel"
        )
    required_prefixes = {"wheelhouse/cp314/requirements-wheelhouse.lock"}
    if not required_prefixes.issubset(selected_names):
        raise SystemExit("release bundle is missing the CPython 3.14 wheelhouse lock")
    wheel_path = output_root.joinpath(*PurePosixPath(wheel_names[0]).parts)
    source = {
        "schema_version": 1,
        "kind": "atlaso-virtualization-source",
        "version": expected_version,
        "source_commit": expected_commit,
        "source_software_tag": f"v{expected_version}",
        "release_manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "release_bundle_sha256": bundle["sha256"],
        "application_wheel": wheel_names[0],
        "application_wheel_sha256": _sha256(wheel_path),
        "python_abi": "cp314",
    }
    source_path = output_root / "virtualization-source.json"
    source_path.write_text(
        json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "source_metadata": str(source_path),
        "application_wheel": str(wheel_path),
        "wheelhouse": str(output_root / "wheelhouse" / "cp314"),
        "release_manifest_sha256": source["release_manifest_sha256"],
        "application_wheel_sha256": source["application_wheel_sha256"],
    }


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Optional command-line arguments.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args(argv)
    result = prepare(
        manifest_path=args.manifest,
        signature_path=args.signature,
        bundle_path=args.bundle,
        trust_key_path=args.trust_key,
        output=args.output,
        expected_version=args.expected_version,
        expected_commit=args.expected_commit,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
