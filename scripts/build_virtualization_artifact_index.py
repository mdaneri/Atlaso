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


def _sha256(path: Path) -> str:
    """Return the SHA-256 digest of one release asset."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON with one trailing newline."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Load one unencrypted Ed25519 release signing key."""

    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("artifact-index signing key must be an Ed25519 private key")
    return key


def _asset_role(name: str) -> str:
    """Return the stable release role for one indexed asset name."""

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
    return "release_asset"


def _require_virtualization_set(names: set[str], version: str) -> None:
    """Require every canonical and target-specific virtualization asset."""

    requirements = {
        "canonical OVA": [name for name in names if name.lower().endswith(".ova")],
        "canonical OVF": [name for name in names if name.lower().endswith(".ovf")],
        "OVF manifest": [name for name in names if name.lower().endswith(".mf")],
        "OVA provenance": [name for name in names if name.lower().endswith("-provenance.json")],
        "two payload VMDKs": [name for name in names if name.lower().endswith(".vmdk")],
        "Hyper-V ZIP": [name for name in names if name == f"atlaso-v{version}-hyperv-x86_64.zip"],
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
            raise SystemExit(f"virtualization release requires {label}; found {sorted(matches)}")
    for helper in (
        "import-atlaso-proxmox.sh",
        "import-atlaso-kvm.sh",
        "validate_ova.py",
        "normalize_libvirt.py",
        "verify_virtualization_artifact_index.py",
    ):
        if helper not in names:
            raise SystemExit(f"virtualization release is missing {helper}")


def main(argv: list[str] | None = None) -> int:
    """Build and sign the artifact index command-line entry point."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--built-at", default="")
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--signing-key-id", required=True)
    args = parser.parse_args(argv)
    if SEMVER_PATTERN.fullmatch(args.version) is None:
        parser.error("--version must be a dotted semantic version")
    if re.fullmatch(r"[0-9a-f]{40}", args.commit) is None:
        parser.error("--commit must be a full lowercase hexadecimal commit")
    asset_root = args.assets.resolve(strict=True)
    if not asset_root.is_dir() or asset_root.is_symlink():
        parser.error("--assets must be an ordinary directory")
    output_names = {INDEX_NAME, SIGNATURE_NAME}
    assets = sorted(path for path in asset_root.iterdir() if path.name not in output_names)
    names = {path.name for path in assets}
    if len(names) != len(assets):
        parser.error("artifact names must be unique")
    _require_virtualization_set(names, args.version)
    records = []
    for path in assets:
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"release asset must be an ordinary file: {path.name}")
        size = path.stat().st_size
        if size <= 0 or size >= MAXIMUM_GITHUB_ASSET_BYTES:
            raise SystemExit(f"release asset is empty or exceeds the GitHub size limit: {path.name}")
        records.append(
            {
                "name": path.name,
                "role": _asset_role(path.name),
                "size": size,
                "sha256": _sha256(path),
            }
        )
    built_at = args.built_at.strip() or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    index = {
        "schema_version": 1,
        "kind": "atlaso-virtualization-artifacts",
        "version": args.version,
        "source_commit": args.commit,
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
    print(json.dumps({"index": INDEX_NAME, "assets": len(records), "version": args.version}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
