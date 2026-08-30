#!/usr/bin/env python3
"""Verify an Atlaso virtualization artifact index and every indexed asset."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PRERELEASE_TAG_PATTERN = re.compile(
    r"^virtualization-v([0-9]+\.[0-9]+\.[0-9]+)-rc\.([1-9][0-9]*)$"
)
STABLE_TAG_PATTERN = re.compile(r"^virtualization-v([0-9]+\.[0-9]+\.[0-9]+)$")


def _canonical_json(value: Any) -> bytes:
    """Return the canonical UTF-8 JSON representation used by the signer.

    Args:
        value: JSON-compatible value to serialize.
    """

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _ordinary_file(path: Path, label: str) -> Path:
    """Resolve one required ordinary file without following a symlink input.

    Args:
        path: Candidate file path.
        label: Human-readable file role for failures.
    """

    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"{label} must be an ordinary file, not a symlink: {path}")
    return path.resolve(strict=True)


def _sha256(path: Path) -> str:
    """Return the SHA-256 digest of one indexed asset.

    Args:
        path: Indexed asset path.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _asset_role(name: str) -> str:
    """Return the only permitted signed role for one asset name.

    Args:
        name: Flat virtualization release asset name.
    """

    lower = name.lower()
    suffix_roles = (
        ("-hyperv-x86_64.zip", "hyperv_package"),
        (".ova", "canonical_ova"),
        (".ovf", "canonical_ovf"),
        (".mf", "ovf_manifest"),
        (".vmdk", "ova_payload_disk"),
        ("-provenance.json", "ova_provenance"),
    )
    for suffix, role in suffix_roles:
        if lower.endswith(suffix):
            return role
    exact_roles = {
        "import-atlaso-proxmox.sh": "proxmox_import_helper",
        "import-atlaso-kvm.sh": "kvm_import_helper",
        "validate_ova.py": "ova_validator",
        "normalize_libvirt.py": "libvirt_normalizer",
        "verify_virtualization_artifact_index.py": "artifact_index_verifier",
        "virtualization-source.json": "software_release_source",
        "windows-smoke-evidence.json": "windows_smoke_evidence",
        "proxmox-smoke-evidence.json": "proxmox_smoke_evidence",
        "kvm-smoke-evidence.json": "kvm_smoke_evidence",
    }
    try:
        return exact_roles[lower]
    except KeyError as exc:
        raise SystemExit(f"unsupported virtualization release asset: {name}") from exc


def verify(
    *,
    index_path: Path,
    signature_path: Path,
    trust_key_path: Path,
    asset_directory: Path,
    expected_version: str = "",
    expected_commit: str = "",
    expected_classification: str = "",
    expected_release_tag: str = "",
) -> dict[str, Any]:
    """Verify the detached signature, release identity, and every indexed asset.

    Args:
        index_path: Canonical artifact-index path.
        signature_path: Detached signature metadata path.
        trust_key_path: Trusted Ed25519 public-key path.
        asset_directory: Directory containing every indexed asset.
        expected_version: Optional expected Atlaso version.
        expected_commit: Optional expected full source commit.
        expected_classification: Optional expected prerelease or stable class.
        expected_release_tag: Optional expected virtualization tag.
    """

    index_file = _ordinary_file(index_path, "artifact index")
    signature_file = _ordinary_file(signature_path, "artifact-index signature")
    trust_key_file = _ordinary_file(trust_key_path, "trusted release public key")
    if asset_directory.is_symlink() or not asset_directory.is_dir():
        raise SystemExit("asset directory must be an ordinary directory, not a symlink")
    asset_root = asset_directory.resolve(strict=True)
    try:
        index_bytes = index_file.read_bytes()
        index = json.loads(index_bytes)
        signature = json.loads(signature_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"artifact index or signature is unreadable: {exc}") from exc
    if not isinstance(index, dict) or not isinstance(signature, dict):
        raise SystemExit("artifact index and signature must be JSON objects")
    if index_bytes != _canonical_json(index):
        raise SystemExit("artifact index is not canonical JSON")
    version = index.get("version")
    source_commit = index.get("source_commit")
    key_id = index.get("signing_key_id")
    classification = index.get("classification")
    release_tag = index.get("release_tag")
    tag_pattern = (
        PRERELEASE_TAG_PATTERN if classification == "prerelease" else STABLE_TAG_PATTERN
    )
    if (
        index.get("schema_version") != 2
        or index.get("kind") != "atlaso-virtualization-artifacts"
        or not isinstance(version, str)
        or SEMVER_PATTERN.fullmatch(version) is None
        or not isinstance(source_commit, str)
        or COMMIT_PATTERN.fullmatch(source_commit) is None
        or not isinstance(key_id, str)
        or KEY_ID_PATTERN.fullmatch(key_id) is None
        or classification not in {"prerelease", "stable"}
        or not isinstance(release_tag, str)
        or (tag_match := tag_pattern.fullmatch(release_tag)) is None
        or tag_match.group(1) != version
        or index.get("source_software_tag") != f"v{version}"
        or not isinstance(index.get("source_release_manifest_sha256"), str)
        or DIGEST_PATTERN.fullmatch(index["source_release_manifest_sha256"]) is None
        or not isinstance(index.get("application_wheel_sha256"), str)
        or DIGEST_PATTERN.fullmatch(index["application_wheel_sha256"]) is None
    ):
        raise SystemExit("artifact index identity is invalid")
    if expected_version and version != expected_version:
        raise SystemExit("artifact index version does not match --expected-version")
    if expected_commit and source_commit != expected_commit:
        raise SystemExit("artifact index commit does not match --expected-commit")
    if expected_classification and classification != expected_classification:
        raise SystemExit(
            "artifact index classification does not match --expected-classification"
        )
    if expected_release_tag and release_tag != expected_release_tag:
        raise SystemExit("artifact index tag does not match --expected-release-tag")
    if trust_key_file.stem != key_id:
        raise SystemExit(
            "trusted release public-key filename does not match the signed key identifier"
        )
    if (
        set(signature) != {"schema_version", "algorithm", "key_id", "signature"}
        or signature.get("schema_version") != 1
        or signature.get("algorithm") != "ed25519"
        or signature.get("key_id") != key_id
    ):
        raise SystemExit("artifact-index signature metadata is invalid")
    try:
        public_key = serialization.load_pem_public_key(trust_key_file.read_bytes())
        signature_bytes = base64.b64decode(str(signature["signature"]), validate=True)
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit(
            f"artifact-index signature or trust key is invalid: {exc}"
        ) from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise SystemExit("trusted release public key must be Ed25519")
    try:
        public_key.verify(signature_bytes, index_bytes)
    except InvalidSignature as exc:
        raise SystemExit("artifact-index signature verification failed") from exc

    records = index.get("assets")
    if not isinstance(records, list) or not records:
        raise SystemExit("artifact index contains no assets")
    verified_names: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "role",
            "size",
            "sha256",
        }:
            raise SystemExit("artifact index contains an invalid asset record")
        name = record.get("name")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or name in verified_names
        ):
            raise SystemExit(
                "artifact index contains an unsafe or duplicate asset name"
            )
        asset = _ordinary_file(asset_root / name, f"indexed asset {name}")
        size = asset.stat().st_size
        if (
            not isinstance(record.get("role"), str)
            or record["role"] != _asset_role(name)
            or not isinstance(record.get("size"), int)
            or record["size"] != size
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or _sha256(asset) != record["sha256"]
        ):
            raise SystemExit(
                f"indexed asset failed size, hash, or role verification: {name}"
            )
        verified_names.add(name)
    actual_names = {
        path.name
        for path in asset_root.iterdir()
        if path.name not in {index_file.name, signature_file.name}
    }
    if verified_names != actual_names:
        raise SystemExit("artifact index does not cover the exact asset set")
    expected_hyperv = {f"atlaso-v{version}-hyperv-x86_64.zip"}
    actual_hyperv = {
        name
        for name in verified_names
        if name.lower().endswith("-hyperv-x86_64.zip")
    }
    if actual_hyperv != expected_hyperv:
        raise SystemExit(
            "artifact index requires the exact canonical Hyper-V asset set; "
            f"expected {sorted(expected_hyperv)}, found {sorted(actual_hyperv)}"
        )
    return {
        "version": version,
        "source_commit": source_commit,
        "classification": classification,
        "release_tag": release_tag,
        "signing_key_id": key_id,
        "assets_verified": len(verified_names),
    }


def main(argv: list[str] | None = None) -> int:
    """Run the artifact-index verification command-line interface.

    Args:
        argv: Optional command-line argument sequence.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--asset-directory", type=Path, required=True)
    parser.add_argument("--expected-version", default="")
    parser.add_argument("--expected-commit", default="")
    parser.add_argument(
        "--expected-classification", choices=("prerelease", "stable"), default=""
    )
    parser.add_argument("--expected-release-tag", default="")
    args = parser.parse_args(argv)
    if (
        args.expected_version
        and SEMVER_PATTERN.fullmatch(args.expected_version) is None
    ):
        parser.error("--expected-version must be a dotted semantic version")
    if args.expected_commit and COMMIT_PATTERN.fullmatch(args.expected_commit) is None:
        parser.error("--expected-commit must be a full lowercase hexadecimal commit")
    result = verify(
        index_path=args.index,
        signature_path=args.signature,
        trust_key_path=args.trust_key,
        asset_directory=args.asset_directory,
        expected_version=args.expected_version,
        expected_commit=args.expected_commit,
        expected_classification=args.expected_classification,
        expected_release_tag=args.expected_release_tag,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
