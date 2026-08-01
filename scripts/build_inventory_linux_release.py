#!/usr/bin/env python3
"""Build deterministic signed metadata for an Inventory Linux package."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$")


def canonical_json(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("release signing key must be an Ed25519 private key")
    return key


def package_version(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            payload = json.loads(archive.read("manifest.json"))
    except (OSError, KeyError, zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("Inventory Linux package manifest is missing or invalid.") from exc
    version = str(payload.get("version") or "")
    if (
        payload.get("schema_version") != 1
        or payload.get("kind") != "atlaso-inventory-linux"
        or INVENTORY_VERSION_RE.fullmatch(version) is None
    ):
        raise SystemExit("Inventory Linux package must use X.Y.Z+revision versioning.")
    expected_name = f"atlaso-inventory-linux-{version}.zip"
    if path.name != expected_name:
        raise SystemExit(f"Inventory Linux package must be named {expected_name}.")
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/inventory-linux-release")
    parser.add_argument("--repository", default="mdaneri/Atlaso")
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--built-at", required=True)
    args = parser.parse_args(argv)

    package = args.package.resolve()
    if not package.is_file():
        raise SystemExit("Inventory Linux package is missing.")
    if re.fullmatch(r"[0-9a-f]{40}", args.commit) is None:
        raise SystemExit("release commit must be a full lowercase hexadecimal commit")
    try:
        built_at = datetime.fromisoformat(args.built_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit("build timestamp must be ISO 8601") from exc
    if built_at.tzinfo is None:
        raise SystemExit("build timestamp must include a timezone")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) is None:
        raise SystemExit("release repository must use owner/name format")

    version = package_version(package)
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    published_package = output / package.name
    shutil.copy2(package, published_package)
    tag = f"inventory-linux-v{version}"
    encoded_tag = quote(tag, safe="")
    encoded_name = quote(package.name, safe="")
    manifest = {
        "schema_version": 1,
        "kind": "atlaso-inventory-linux-release",
        "version": version,
        "git_commit": args.commit,
        "built_at": args.built_at,
        "signing_key_id": args.signing_key_id,
        "architecture": "x86_64",
        "package": {
            "name": package.name,
            "url": (
                f"https://github.com/{args.repository}/releases/download/"
                f"{encoded_tag}/{encoded_name}"
            ),
            "size": published_package.stat().st_size,
            "sha256": sha256(published_package),
        },
    }
    raw_manifest = canonical_json(manifest)
    (output / "inventory-linux-manifest.json").write_bytes(raw_manifest)
    key = load_signing_key(args.signing_key.resolve())
    signature = {
        "schema_version": 1,
        "key_id": args.signing_key_id,
        "signature": base64.b64encode(key.sign(raw_manifest)).decode("ascii"),
    }
    (output / "inventory-linux-manifest.json.sig").write_bytes(canonical_json(signature))
    print(
        json.dumps(
            {"version": version, "tag": tag, "commit": args.commit, "output": str(output)},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
