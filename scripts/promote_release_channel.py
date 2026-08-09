#!/usr/bin/env python3
"""Provide the promote release channel repository utility."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from atlaso.app.services.release_updates import validate_release_manifest, verify_signed_json


def canonical_json(payload: dict) -> bytes:
    """Return canonical json."""
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    parser = argparse.ArgumentParser(description="Promote an immutable Atlaso release into a signed Pages channel.")
    parser.add_argument("--channel", required=True, choices=("stable", "preview", "development"))
    parser.add_argument("--release-manifest-url", required=True)
    parser.add_argument("--release-manifest", type=Path)
    parser.add_argument("--release-signature", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--signing-key-id", required=True)
    args = parser.parse_args()

    raw_release = (
        args.release_manifest.read_bytes()
        if args.release_manifest
        else urlopen(args.release_manifest_url, timeout=60).read()
    )
    release = json.loads(raw_release.decode("utf-8"))
    validate_release_manifest(release)
    if release["version"] != args.expected_version:
        raise SystemExit(
            f"release manifest version {release['version']} does not match requested {args.expected_version}"
        )
    signature = json.loads(args.release_signature.read_text(encoding="utf-8"))
    if signature.get("key_id") != args.signing_key_id or args.trusted_key.stem != args.signing_key_id:
        raise SystemExit("release signature does not use the selected named trust key")
    verified = verify_signed_json(
        raw_release,
        args.release_signature.read_bytes(),
        trust_dir=args.trusted_key.parent,
        document_kind="release",
    )
    if verified != release:
        raise SystemExit("verified release manifest does not match the promotion input")
    channel = {
        "schema_version": 2,
        "kind": "atlaso-channel",
        "channel": args.channel,
        "version": release["version"],
        "git_commit": release["git_commit"],
        "release_manifest_url": args.release_manifest_url,
        "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "signing_key_id": args.signing_key_id,
    }
    raw_channel = canonical_json(channel)
    key = serialization.load_pem_private_key(args.signing_key.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("channel signing key must be Ed25519")
    destination = args.site_root / "channels" / args.channel
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "manifest.json").write_bytes(raw_channel)
    (destination / "manifest.json.sig").write_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "key_id": args.signing_key_id,
                "signature": base64.b64encode(key.sign(raw_channel)).decode("ascii"),
            }
        )
    )
    print(f"promoted {release['version']} to {args.channel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
