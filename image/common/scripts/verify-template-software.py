#!/usr/bin/env python3
"""Verify staged software against a host-authenticated release manifest digest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath


def verify(root: Path, manifest_digest: str, version: str, commit: str) -> dict:
    """Check the exact transferred input set before offline installation.

    Args:
        root: Staged ordinary software directory.
        manifest_digest: Digest authenticated by the host's signature verifier.
        version: Expected application version.
        commit: Expected source commit.
    """
    if root.is_symlink() or root.is_junction() or not root.is_dir():
        raise SystemExit("Software input must be an ordinary directory")
    files = {}
    for path in root.rglob("*"):
        if (
            path.is_symlink()
            or path.is_junction()
            or (not path.is_file() and not path.is_dir())
        ):
            raise SystemExit("Software input contains an unsafe entry")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = path
    manifest_path = files.get("release-manifest.json")
    if manifest_path is None or re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None:
        raise SystemExit("Authenticated software manifest is missing")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest_digest:
        raise SystemExit("Software manifest changed after signature verification")
    manifest = json.loads(raw)
    if (
        manifest.get("version") != version
        or manifest.get("git_commit") != commit
        or "cp314" not in manifest.get("supported_python_abis", [])
    ):
        raise SystemExit("Software version, source commit, or Python ABI mismatch")
    hashes = manifest.get("content_hashes", {})
    selected = {}
    for name, digest in hashes.items():
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or path.as_posix() != name
            or ".." in path.parts
            or "\\" in name
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise SystemExit("Unsafe software manifest entry")
        if name.startswith(("packages/", "wheelhouse/cp314/")) or name in {
            "requirements-appliance.lock",
            "bundle-metadata.json",
        }:
            selected[name] = digest
    expected = set(selected) | {
        "release-manifest.json",
        "release-manifest.json.sig",
        "virtualization-source.json",
    }
    if set(files) != expected:
        raise SystemExit("Software input does not contain the exact signed file set")
    for name, digest in selected.items():
        with files[name].open("rb") as handle:
            if hashlib.file_digest(handle, "sha256").hexdigest() != digest:
                raise SystemExit(f"Software input digest mismatch: {name}")
    wheels = [
        name
        for name in selected
        if name.startswith("packages/") and name.endswith(".whl")
    ]
    if (
        len(wheels) != 1
        or not wheels[0].startswith(f"packages/atlaso-{version}-")
        or "wheelhouse/cp314/requirements-wheelhouse.lock" not in selected
    ):
        raise SystemExit(
            "Software input lacks the application wheel or locked wheelhouse"
        )
    # --no-index does not prohibit direct URLs in a requirements file. Admit only
    # the canonical generated wheelhouse lock and require its complete inventory.
    locked_hashes = set()
    locked_names = set()
    lock = files["wheelhouse/cp314/requirements-wheelhouse.lock"].read_text(
        encoding="utf-8"
    )
    for line in lock.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+) --hash=sha256:([0-9a-f]{64})", line
        )
        if match is None or match[1] in locked_names or match[3] in locked_hashes:
            raise SystemExit(
                "Software wheelhouse lock is not a canonical offline hash lock"
            )
        locked_names.add(match[1])
        locked_hashes.add(match[3])
    dependency_hashes = {
        digest
        for name, digest in selected.items()
        if name.startswith("wheelhouse/cp314/") and name.endswith(".whl")
    }
    if not locked_hashes or locked_hashes != dependency_hashes:
        raise SystemExit(
            "Software wheelhouse does not contain the complete locked dependency set"
        )
    source = json.loads(files["virtualization-source.json"].read_bytes())
    expected_source = {
        "schema_version": 1,
        "kind": "atlaso-virtualization-source",
        "version": version,
        "source_commit": commit,
        "source_software_tag": f"v{version}",
        "release_manifest_sha256": manifest_digest,
        "release_bundle_sha256": manifest["bundle"]["sha256"],
        "application_wheel": wheels[0],
        "application_wheel_sha256": selected[wheels[0]],
        "python_abi": "cp314",
    }
    if source != expected_source:
        raise SystemExit(
            "Software source metadata does not match the authenticated manifest"
        )
    return source


def main() -> None:
    """Print only the verified application wheel path for the installer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    source = verify(args.root, args.manifest_sha256, args.version, args.commit)
    print(args.root / source["application_wheel"])


if __name__ == "__main__":
    main()
