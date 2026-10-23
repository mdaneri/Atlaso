#!/usr/bin/env python3
"""Prepare or finalize an offline ISO using existing Atlaso release inputs."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.installation.assets import (  # noqa: E402 - direct-script repository bootstrap.
    split_iso,
)
from scripts.installation.build import (  # noqa: E402 - direct-script repository bootstrap.
    capture_packages,
    pack_inputs,
    package_selection,
    prepare_payload,
    rebuild_repository,
    unpack_inputs,
    validate_candidate,
)
from scripts.installation.iso import (  # noqa: E402 - direct-script repository bootstrap.
    build_iso,
)
from scripts.installation.manifest import (  # noqa: E402 - direct-script repository bootstrap.
    KEY_ID,
    MANIFEST,
    PHOTON_INSTALLER_SHA256,
    SOURCE_ISO_SHA512,
    canonical_json,
    digest,
    inventory,
    verify_media,
)


def write_signed(path: Path, value: dict, key) -> None:
    """Write the existing detached Ed25519 JSON envelope without printing keys.

    Args:
        path: Filesystem path to the input or target.
        value: Value to validate or serialize.
        key: Signing key used to create detached metadata signatures."""
    content = canonical_json(value)
    path.write_bytes(content)
    signature = {"schema_version": 1, "algorithm": "ed25519", "key_id": KEY_ID, "signature": base64.b64encode(key.sign(content)).decode("ascii")}
    path.with_name(path.name + ".sig").write_bytes(canonical_json(signature))


def main() -> int:
    """Keep unsigned input preparation separate from the protected signer."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    packages = commands.add_parser("packages", help="Print the shared RPM selection for build-time dependency capture.")
    packages.add_argument("--source", type=Path, default=ROOT)
    capture = commands.add_parser("capture-rpms", help="Resolve dependencies on the canonical authorized Photon builder.")
    capture.add_argument("--output", type=Path, required=True)
    pack = commands.add_parser("pack-inputs", help="Archive a prepared unsigned candidate.")
    pack.add_argument("--payload", type=Path, required=True)
    pack.add_argument("--output", type=Path, required=True)
    split = commands.add_parser("split-inputs", help="Stage candidate input assets beneath GitHub's individual limit.")
    split.add_argument("--archive", type=Path, required=True)
    split.add_argument("--output", type=Path, required=True)
    unpack = commands.add_parser("unpack-inputs", help="Extract a bounded candidate in a protected validation job.")
    unpack.add_argument("--archive", type=Path, required=True)
    unpack.add_argument("--output", type=Path, required=True)
    prepare = commands.add_parser("prepare", help="Stage inputs in a caller-owned, absent destination.")
    validate = commands.add_parser("validate", help="Revalidate unsigned candidate inputs before signing-key access.")
    validate.add_argument("--scratch", type=Path, required=True)
    finalize = commands.add_parser("finalize", help="Independently validate, sign, and assemble in a protected hosted job.")
    for command in (prepare, validate, finalize):
        command.add_argument("--commit", required=True)
        command.add_argument("--version", required=True)
        command.add_argument("--payload", type=Path, required=True)
    for name in ("software", "rpms", "powercli"):
        prepare.add_argument("--" + name, type=Path, required=True)
    finalize.add_argument("--source-iso", type=Path, required=True)
    finalize.add_argument("--output", type=Path, required=True, help="Caller-owned empty output directory.")
    finalize.add_argument("--scratch", type=Path, required=True, help="Caller-owned empty validation directory.")
    finalize.add_argument("--signing-key", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "packages":
        print("\n".join(package_selection(args.source)))
        return 0
    if args.operation == "capture-rpms":
        capture_packages(ROOT, args.output)
        return 0
    if args.operation == "pack-inputs":
        pack_inputs(args.payload, args.output)
        return 0
    if args.operation == "unpack-inputs":
        unpack_inputs(args.archive, args.output)
        return 0
    if args.operation == "split-inputs":
        manifest = split_iso(args.archive, args.output)
        (args.output / "installation-inputs-index.json").write_bytes(canonical_json(manifest))
        return 0
    if args.operation == "prepare":
        prepare_payload(repository=ROOT, commit=args.commit, version=args.version, software=args.software, rpms=args.rpms, powercli=args.powercli, output=args.payload)
        return 0
    if args.operation == "validate":
        validate_candidate(args.payload, repository=ROOT, commit=args.commit, version=args.version, trust_key=ROOT / f"image/common/update-trust/{KEY_ID}.pem", scratch=args.scratch)
        return 0
    from scripts.build_virtualization_artifact_index import _load_signing_key

    if not args.output.is_dir() or any(args.output.iterdir()) or not args.scratch.is_dir() or any(args.scratch.iterdir()):
        raise ValueError("finalization requires empty caller-owned output and scratch directories")
    trust_key = ROOT / f"image/common/update-trust/{KEY_ID}.pem"
    validated = validate_candidate(args.payload, repository=ROOT, commit=args.commit, version=args.version, trust_key=trust_key, scratch=args.scratch)
    value = json.loads((args.payload / MANIFEST).read_bytes())
    expected = {"schema": 1, "architecture": "x86_64", "version": args.version, "source_commit": args.commit, "signing_key_id": KEY_ID, "photon_installer": "2.2", "photon_installer_sha256": PHOTON_INSTALLER_SHA256, "photon_iso_sha512": SOURCE_ISO_SHA512, "packages": package_selection(args.payload / "source"), "files": inventory(args.payload)}
    if value != expected:
        raise ValueError("candidate manifest differs from the independently validated inputs")
    rebuild_repository(args.payload / "rpms", args.scratch)
    value["files"] = inventory(args.payload)
    value["rpm_inventory"] = validated["rpms"]
    key = _load_signing_key(args.signing_key)
    write_signed(args.payload / MANIFEST, value, key)
    verify_media(args.payload, trust_key, scratch=args.scratch)
    iso = args.scratch / f"atlaso-installation-{args.version}-x86_64.iso"
    build_iso(args.source_iso, args.payload, iso, trust_key=trust_key)
    assets = split_iso(iso, args.output)
    verifier = args.output / "verify-installation.pyz"
    with zipfile.ZipFile(verifier, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ("scripts/__init__.py", "scripts/installation/__init__.py", "scripts/installation/assets.py", "scripts/installation/manifest.py"):
            archive.writestr(name, (ROOT / name).read_bytes())
        archive.writestr("__main__.py", (ROOT / "scripts/verify_installation_iso.py").read_bytes())
    index = {"schema": 1, "kind": "atlaso-installation", "architecture": "x86_64", "version": args.version, "source_commit": args.commit, "signing_key_id": KEY_ID, "asset_manifest": assets, "verifier": {"name": verifier.name, "size": verifier.stat().st_size, "sha256": digest(verifier)}, "physical_hardware_acceptance": "pending"}
    write_signed(args.output / "installation-artifact-index.json", index, key)
    print(json.dumps({"version": args.version, "assets": len(assets["assets"]), "physical_hardware_acceptance": "pending"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
