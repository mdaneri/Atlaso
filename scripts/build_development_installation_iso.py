#!/usr/bin/env python3
"""Build a VMware-only installer test image without production signing material."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.installation.development import (  # noqa: E402 - direct-script repository bootstrap.
    prepare_payload,
)
from scripts.installation.iso import (  # noqa: E402 - direct-script repository bootstrap.
    build_iso,
)
from scripts.installation.manifest import (  # noqa: E402 - direct-script repository bootstrap.
    DEVELOPMENT_KEY_ID,
    MANIFEST,
    canonical_json,
    digest,
    verify_media,
)


def public_test_key():
    """Return a deliberately public fixture key that conveys no release authority."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # This seed is public test data, not a credential. Never accept it in the
    # production trust domain or export a development image as a release asset.
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def sign_test_manifest(payload: Path) -> bytes:
    """Sign explicitly marked test content with the publicly disclosed fixture.

    Args:
        payload: Prepared development payload directory.
    """
    from cryptography.hazmat.primitives import serialization

    value = json.loads((payload / MANIFEST).read_bytes())
    if value.get("signing_key_id") != DEVELOPMENT_KEY_ID or value.get("development", {}).get("non_production") is not True:
        raise ValueError("public test signing requires explicitly marked development inputs")
    key = public_test_key()
    content = canonical_json(value)
    (payload / MANIFEST).write_bytes(content)
    signature = {"schema_version": 1, "algorithm": "ed25519", "key_id": DEVELOPMENT_KEY_ID, "signature": base64.b64encode(key.sign(content)).decode("ascii")}
    with (payload / (MANIFEST + ".sig")).open("xb") as handle:
        handle.write(canonical_json(signature))
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def main() -> int:
    """Prepare and assemble an exact-source development ISO in caller-owned roots."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--software-version", required=True)
    parser.add_argument("--software-commit", required=True)
    for name in ("software", "rpms", "powercli", "payload", "scratch", "source-iso", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if not args.scratch.is_dir() or any(args.scratch.iterdir()) or args.output.exists() or args.output.is_symlink():
        raise ValueError("development build requires an empty owned scratch directory and absent ISO output")
    prepare_payload(repository=ROOT, commit=args.commit, software_version=args.software_version, software_commit=args.software_commit, software=args.software, rpms=args.rpms, powercli=args.powercli, output=args.payload, scratch=args.scratch)
    trust = args.scratch / "development-public-test.pem"
    with trust.open("xb") as handle:
        handle.write(sign_test_manifest(args.payload))
    verify_media(args.payload, trust, scratch=args.scratch, expected_key_id=DEVELOPMENT_KEY_ID)
    build_iso(args.source_iso, args.payload, args.output, trust_key=trust, development=True)
    print(json.dumps({"kind": "atlaso-installation-development", "source_commit": args.commit, "software_source_commit": args.software_commit, "iso_sha256": digest(args.output), "production_release": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
