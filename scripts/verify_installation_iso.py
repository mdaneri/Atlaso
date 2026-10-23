#!/usr/bin/env python3
"""Verify a signed installation release and optionally reconstruct its ISO."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.installation.assets import (  # noqa: E402 - script and zipapp entry-point bootstrap.
    _safe_name,
    _validate_manifest,
    verify_and_reassemble,
)
from scripts.installation.manifest import (  # noqa: E402 - script and zipapp entry-point bootstrap.
    digest,
    verify_signature,
)


def verify_release(assets: Path, trust_key: Path, scratch: Path, *, version: str, commit: str) -> dict:
    """Bind release assets and their reconstruction order to the selected identity."""
    index_path = assets / "installation-artifact-index.json"
    value = verify_signature(index_path, index_path.with_suffix(".json.sig"), trust_key, scratch=scratch)
    if value.get("schema") != 1 or value.get("kind") != "atlaso-installation" or value.get("architecture") != "x86_64":
        raise ValueError("installation release schema or architecture is unsupported")
    if value.get("version") != version or value.get("source_commit") != commit:
        raise ValueError("installation release differs from the selected version or source commit")
    _, _, _, records = _validate_manifest(value.get("asset_manifest"))
    verifier = value.get("verifier")
    if not isinstance(verifier, dict) or set(verifier) != {"name", "size", "sha256"} or verifier.get("name") != "verify-installation.pyz":
        raise ValueError("installation verifier identity is invalid")
    if type(verifier["size"]) is not int or not 0 < verifier["size"] < 2 * 1024**3 or not isinstance(verifier["sha256"], str):
        raise ValueError("installation verifier size or checksum is invalid")
    for record in [*records, verifier]:
        _safe_name(record["name"])
        path = assets / record["name"]
        if digest(path) != record["sha256"] or path.stat().st_size != record["size"]:
            raise ValueError("installation release asset size or checksum differs")
    return value


def main() -> int:
    """Verify everything before creating the caller-selected reconstructed ISO."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--trust-key", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--scratch", required=True, type=Path, help="Existing private temporary directory.")
    parser.add_argument("--output", type=Path, help="Absent destination for optional ISO reconstruction.")
    args = parser.parse_args()
    value = verify_release(args.assets, args.trust_key, args.scratch, version=args.version, commit=args.commit)
    if args.output is not None:
        verify_and_reassemble(value["asset_manifest"], args.assets, args.output)
    print(json.dumps({"version": value["version"], "iso": value["asset_manifest"]["iso"], "physical_hardware_acceptance": value.get("physical_hardware_acceptance")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
