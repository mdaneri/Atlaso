#!/usr/bin/env python3
"""Build a signed index for one complete Atlaso virtualization release set."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAXIMUM_GITHUB_ASSET_BYTES = 2_147_483_647
INDEX_NAME = "virtualization-artifact-index.json"
SIGNATURE_NAME = f"{INDEX_NAME}.sig"
SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PRERELEASE_TAG_PATTERN = re.compile(
    r"^virtualization-v([0-9]+\.[0-9]+\.[0-9]+)-rc\.([1-9][0-9]*)$"
)
STABLE_TAG_PATTERN = re.compile(r"^virtualization-v([0-9]+\.[0-9]+\.[0-9]+)$")


def _sha256(path: Path) -> str:
    """Return the SHA-256 digest of one release asset.

    Args:
        path: Release asset to hash.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON with one trailing newline.

    Args:
        value: JSON-compatible value to serialize.
    """

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Load one unencrypted Ed25519 release signing key.

    Args:
        path: PEM private-key path.
    """

    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("artifact-index signing key must be an Ed25519 private key")
    return key


def _asset_role(name: str) -> str:
    """Return the stable release role for one indexed asset name.

    Args:
        name: Flat release asset name.
    """

    lower = name.lower()
    if lower.endswith("-hyperv-x86_64.zip"):
        return "hyperv_package"
    if lower.endswith(".ova"):
        return "canonical_ova"
    if lower.endswith(".ovf"):
        return "canonical_ovf"
    if lower.endswith(".mf"):
        return "ovf_manifest"
    if lower.endswith(".vmdk"):
        return "ova_payload_disk"
    if lower.endswith("-provenance.json"):
        return "ova_provenance"
    if lower == "import-atlaso-proxmox.sh":
        return "proxmox_import_helper"
    if lower == "import-atlaso-kvm.sh":
        return "kvm_import_helper"
    if lower == "validate_ova.py":
        return "ova_validator"
    if lower == "normalize_libvirt.py":
        return "libvirt_normalizer"
    if lower == "verify_virtualization_artifact_index.py":
        return "artifact_index_verifier"
    if lower == "virtualization-source.json":
        return "software_release_source"
    if lower == "windows-smoke-evidence.json":
        return "windows_smoke_evidence"
    if lower == "proxmox-smoke-evidence.json":
        return "proxmox_smoke_evidence"
    if lower == "kvm-smoke-evidence.json":
        return "kvm_smoke_evidence"
    raise SystemExit(f"unsupported virtualization release asset: {name}")


def _require_virtualization_set(
    names: set[str], version: str, classification: str
) -> None:
    """Require every canonical and target-specific virtualization asset.

    Args:
        names: Exact flat asset-name set.
        version: Atlaso semantic version embedded in versioned names.
        classification: Prerelease or stable publication class.
    """

    requirements = {
        "canonical OVA": [name for name in names if name.lower().endswith(".ova")],
        "canonical OVF": [name for name in names if name.lower().endswith(".ovf")],
        "OVF manifest": [name for name in names if name.lower().endswith(".mf")],
        "OVA provenance": [
            name for name in names if name.lower().endswith("-provenance.json")
        ],
        "two payload VMDKs": [name for name in names if name.lower().endswith(".vmdk")],
        "Hyper-V ZIP": [
            name for name in names if name == f"atlaso-v{version}-hyperv-x86_64.zip"
        ],
    }
    expected_counts = {
        "canonical OVA": 1,
        "canonical OVF": 1,
        "OVF manifest": 1,
        "OVA provenance": 1,
        "two payload VMDKs": 2,
        "Hyper-V ZIP": 1,
    }
    for label, matches in requirements.items():
        if len(matches) != expected_counts[label]:
            raise SystemExit(
                f"virtualization release requires {label}; found {sorted(matches)}"
            )
    for helper in (
        "import-atlaso-proxmox.sh",
        "import-atlaso-kvm.sh",
        "validate_ova.py",
        "normalize_libvirt.py",
        "verify_virtualization_artifact_index.py",
    ):
        if helper not in names:
            raise SystemExit(f"virtualization release is missing {helper}")
    required_evidence = {"virtualization-source.json", "windows-smoke-evidence.json"}
    if classification == "stable":
        required_evidence |= {"proxmox-smoke-evidence.json", "kvm-smoke-evidence.json"}
    missing_evidence = required_evidence - names
    if missing_evidence:
        raise SystemExit(
            f"virtualization release is missing evidence: {sorted(missing_evidence)}"
        )


def _json_object(path: Path, label: str) -> dict[str, Any]:
    """Load one bounded evidence JSON object.

    Args:
        path: Evidence document path.
        label: Human-readable evidence role.
    """

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be a JSON object")
    return value


def _validate_evidence(
    asset_root: Path,
    version: str,
    commit: str,
    classification: str,
    release_manifest_sha256: str,
    application_wheel_sha256: str,
) -> None:
    """Bind signed source and smoke evidence to the exact release assets.

    Args:
        asset_root: Flat candidate asset directory.
        version: Expected Atlaso version.
        commit: Expected full source commit.
        classification: Prerelease or stable publication class.
        release_manifest_sha256: Expected signed software manifest digest.
        application_wheel_sha256: Expected embedded Atlaso wheel digest.
    """

    source = _json_object(
        asset_root / "virtualization-source.json", "software-release source evidence"
    )
    if (
        source.get("schema_version") != 1
        or source.get("kind") != "atlaso-virtualization-source"
        or source.get("version") != version
        or source.get("source_commit") != commit
        or source.get("source_software_tag") != f"v{version}"
        or source.get("python_abi") != "cp314"
        or source.get("release_manifest_sha256") != release_manifest_sha256
        or source.get("application_wheel_sha256") != application_wheel_sha256
        or DIGEST_PATTERN.fullmatch(str(source.get("release_manifest_sha256", "")))
        is None
        or DIGEST_PATTERN.fullmatch(str(source.get("release_bundle_sha256", "")))
        is None
        or DIGEST_PATTERN.fullmatch(str(source.get("application_wheel_sha256", "")))
        is None
    ):
        raise SystemExit(
            "software-release source evidence does not match the release identity"
        )
    ova = next(asset_root.glob("*.ova"))
    hyperv = asset_root / f"atlaso-v{version}-hyperv-x86_64.zip"
    windows = _json_object(
        asset_root / "windows-smoke-evidence.json", "Windows smoke evidence"
    )
    if (
        windows.get("schema_version") != 1
        or windows.get("kind") != "atlaso-windows-virtualization-smoke"
        or windows.get("version") != version
        or windows.get("source_commit") != commit
        or windows.get("vmware") != "success"
        or windows.get("hyperv") != "success"
        or windows.get("ova_sha256") != _sha256(ova)
        or windows.get("hyperv_sha256") != _sha256(hyperv)
    ):
        raise SystemExit(
            "Windows smoke evidence does not bind the exact virtualization assets"
        )
    if classification == "stable":
        for provider in ("proxmox", "kvm"):
            evidence = _json_object(
                asset_root / f"{provider}-smoke-evidence.json",
                f"{provider} smoke evidence",
            )
            if evidence != {
                "kind": f"atlaso-{provider}-smoke",
                "ova_sha256": _sha256(ova),
                "schema_version": 1,
                "source_commit": commit,
                "status": "success",
            }:
                raise SystemExit(
                    f"{provider} smoke evidence does not match the release identity"
                )


def main(argv: list[str] | None = None) -> int:
    """Build and sign the artifact index command-line entry point.

    Args:
        argv: Optional command-line argument sequence.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument(
        "--classification", choices=("prerelease", "stable"), required=True
    )
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-release-manifest-sha256", required=True)
    parser.add_argument("--application-wheel-sha256", required=True)
    parser.add_argument("--built-at", default="")
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--signing-key-id", required=True)
    args = parser.parse_args(argv)
    if SEMVER_PATTERN.fullmatch(args.version) is None:
        parser.error("--version must be a dotted semantic version")
    if COMMIT_PATTERN.fullmatch(args.commit) is None:
        parser.error("--commit must be a full lowercase hexadecimal commit")
    tag_match = (
        PRERELEASE_TAG_PATTERN.fullmatch(args.release_tag)
        if args.classification == "prerelease"
        else STABLE_TAG_PATTERN.fullmatch(args.release_tag)
    )
    if tag_match is None or tag_match.group(1) != args.version:
        parser.error("--release-tag does not match the classification and version")
    for value, option in (
        (args.source_release_manifest_sha256, "--source-release-manifest-sha256"),
        (args.application_wheel_sha256, "--application-wheel-sha256"),
    ):
        if DIGEST_PATTERN.fullmatch(value) is None:
            parser.error(f"{option} must be a lowercase SHA-256 digest")
    asset_root = args.assets.resolve(strict=True)
    if not asset_root.is_dir() or asset_root.is_symlink():
        parser.error("--assets must be an ordinary directory")
    output_names = {INDEX_NAME, SIGNATURE_NAME}
    assets = sorted(
        path for path in asset_root.iterdir() if path.name not in output_names
    )
    names = {path.name for path in assets}
    if len(names) != len(assets):
        parser.error("artifact names must be unique")
    _require_virtualization_set(names, args.version, args.classification)
    _validate_evidence(
        asset_root,
        args.version,
        args.commit,
        args.classification,
        args.source_release_manifest_sha256,
        args.application_wheel_sha256,
    )
    records = []
    for path in assets:
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"release asset must be an ordinary file: {path.name}")
        size = path.stat().st_size
        if size <= 0 or size >= MAXIMUM_GITHUB_ASSET_BYTES:
            raise SystemExit(
                f"release asset is empty or exceeds the GitHub size limit: {path.name}"
            )
        records.append(
            {
                "name": path.name,
                "role": _asset_role(path.name),
                "size": size,
                "sha256": _sha256(path),
            }
        )
    built_at = args.built_at.strip() or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    index = {
        "schema_version": 2,
        "kind": "atlaso-virtualization-artifacts",
        "classification": args.classification,
        "release_tag": args.release_tag,
        "version": args.version,
        "source_commit": args.commit,
        "source_software_tag": f"v{args.version}",
        "source_release_manifest_sha256": args.source_release_manifest_sha256,
        "application_wheel_sha256": args.application_wheel_sha256,
        "built_at": built_at,
        "signing_key_id": args.signing_key_id,
        "assets": records,
    }
    index_bytes = _canonical_json(index)
    key = _load_signing_key(args.signing_key)
    (asset_root / INDEX_NAME).write_bytes(index_bytes)
    signature = {
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id": args.signing_key_id,
        "signature": base64.b64encode(key.sign(index_bytes)).decode("ascii"),
    }
    (asset_root / SIGNATURE_NAME).write_bytes(_canonical_json(signature))
    print(
        json.dumps(
            {"index": INDEX_NAME, "assets": len(records), "version": args.version},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
