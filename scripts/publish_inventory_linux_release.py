#!/usr/bin/env python3
"""Idempotently publish Inventory Linux assets and signed Pages pointers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from atlaso.app.services.release_updates import (  # noqa: E402 - repository root is added before importing Atlaso.
    inventory_version_tuple,
    signature_document,
    verify_signed_json,
)

GIT_RELEASE_USER_NAME = "github-actions[bot]"
GIT_RELEASE_USER_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run operation.

    Args:
        command: Command and arguments to execute.
        check: Whether a nonzero command status raises an exception.


    Returns:
        The run result.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    result = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"{command[0]} failed")
    return result


def sha256(path: Path) -> str:
    """Return sha256.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_manifest(
    manifest_path: Path,
    signature_path: Path,
    *,
    trusted_key: Path,
) -> dict:
    """Validate manifest.

    Args:
        manifest_path: Filesystem path used for manifest.
        signature_path: Filesystem path used for signature.
        trusted_key: Filesystem path associated with trusted key.


    Returns:
        The verify manifest result.
    """
    raw_manifest = manifest_path.read_bytes()
    raw_signature = signature_path.read_bytes()
    signature = signature_document(raw_signature)
    with tempfile.TemporaryDirectory(prefix="atlaso-inventory-trust-") as temp_value:
        trust_dir = Path(temp_value)
        shutil.copy2(trusted_key, trust_dir / f"{signature['key_id']}.pem")
        return verify_signed_json(
            raw_manifest,
            raw_signature,
            trust_dir=trust_dir,
            document_kind="inventory",
        )


def atomic_write(path: Path, content: bytes) -> None:
    """Handle atomic write.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        content: Document or file content to process.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def publish_pages(
    *,
    site_root: Path,
    manifest_path: Path,
    signature_path: Path,
    trusted_key: Path,
    manifest: dict,
    apply: bool = True,
) -> str:
    """Return publish pages.

    Args:
        site_root: Site root supplied by the caller.
        manifest_path: Filesystem path for the manifest.
        signature_path: Filesystem path for the signature.
        trusted_key: Trusted key supplied by the caller.
        manifest: Manifest supplied by the caller.
        apply: Apply supplied by the caller.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    version = str(manifest["version"])
    raw_manifest = manifest_path.read_bytes()
    raw_signature = signature_path.read_bytes()
    inventory_root = site_root / "updates" / "inventory-linux"
    version_root = inventory_root / "releases" / version
    for target, content in (
        (version_root / "manifest.json", raw_manifest),
        (version_root / "manifest.json.sig", raw_signature),
    ):
        if target.exists() and target.read_bytes() != content:
            raise SystemExit(f"Inventory Linux {version} Pages metadata already differs: {target.name}")

    latest_root = inventory_root / "latest"
    latest_manifest = latest_root / "manifest.json"
    latest_signature = latest_root / "manifest.json.sig"
    result = "advanced"
    if latest_manifest.exists() or latest_signature.exists():
        if not latest_manifest.is_file() or not latest_signature.is_file():
            raise SystemExit("Inventory Linux latest Pages pointer is incomplete.")
        latest = verify_manifest(
            latest_manifest,
            latest_signature,
            trusted_key=trusted_key,
        )
        ordering = inventory_version_tuple(str(latest["version"]))
        requested = inventory_version_tuple(version)
        if ordering > requested:
            raise SystemExit(
                f"Inventory Linux latest {latest['version']} cannot move backward to {version}."
            )
        if ordering == requested:
            if latest_manifest.read_bytes() != raw_manifest or latest_signature.read_bytes() != raw_signature:
                raise SystemExit(f"Inventory Linux latest {version} metadata is not byte-identical.")
            result = "already-current"

    if not apply:
        return result
    atomic_write(version_root / "manifest.json", raw_manifest)
    atomic_write(version_root / "manifest.json.sig", raw_signature)
    if result != "already-current":
        atomic_write(latest_manifest, raw_manifest)
        atomic_write(latest_signature, raw_signature)
    return result


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Command-line arguments to parse, or ``None`` to use the process arguments.


    Returns:
        The main result.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    args = parser.parse_args(argv)
    if re.fullmatch(r"[0-9a-f]{40}", args.commit) is None:
        raise SystemExit("release commit must be a full lowercase hexadecimal commit")

    assets_root = args.assets.resolve()
    manifest_path = assets_root / "inventory-linux-manifest.json"
    signature_path = assets_root / "inventory-linux-manifest.json.sig"
    manifest = verify_manifest(
        manifest_path,
        signature_path,
        trusted_key=args.trusted_key.resolve(),
    )
    if manifest["git_commit"] != args.commit:
        raise SystemExit("Inventory Linux manifest commit does not match the requested commit.")
    package_path = assets_root / str(manifest["package"]["name"])
    if (
        not package_path.is_file()
        or package_path.stat().st_size != manifest["package"]["size"]
        or sha256(package_path) != manifest["package"]["sha256"]
    ):
        raise SystemExit("Inventory Linux package does not match its signed manifest.")
    assets = sorted((package_path, manifest_path, signature_path))
    version = str(manifest["version"])
    tag = f"inventory-linux-v{version}"

    publish_pages(
        site_root=args.site_root.resolve(),
        manifest_path=manifest_path,
        signature_path=signature_path,
        trusted_key=args.trusted_key.resolve(),
        manifest=manifest,
        apply=False,
    )

    remote_tag = run(["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"]).stdout.strip()
    if remote_tag:
        tagged_commit = remote_tag.split()[0]
        peeled = run(["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}^{{}}"]).stdout.strip()
        if peeled:
            tagged_commit = peeled.split()[0]
        if tagged_commit != args.commit:
            raise SystemExit(f"{tag} already identifies {tagged_commit}, not {args.commit}")
    else:
        run(
            [
                "git",
                "-c",
                f"user.name={GIT_RELEASE_USER_NAME}",
                "-c",
                f"user.email={GIT_RELEASE_USER_EMAIL}",
                "tag",
                "-a",
                tag,
                args.commit,
                "-m",
                f"Atlaso Inventory Linux {version}",
            ]
        )
        run(["git", "push", "origin", f"refs/tags/{tag}"])

    existing = run(
        ["gh", "release", "view", tag, "--json", "tagName,isDraft,isPrerelease,assets"],
        check=False,
    )
    release_result = "published"
    if existing.returncode == 0:
        release = json.loads(existing.stdout)
        if release.get("tagName") != tag or release.get("isDraft") or release.get("isPrerelease"):
            raise SystemExit(f"{tag} is not an existing final Inventory Linux release.")
        expected_names = {path.name for path in assets}
        actual_names = {str(item.get("name") or "") for item in release.get("assets", [])}
        if actual_names != expected_names:
            raise SystemExit(
                f"{tag} already has different assets: expected {sorted(expected_names)}, found {sorted(actual_names)}"
            )
        with tempfile.TemporaryDirectory(prefix="atlaso-inventory-release-verify-") as temp_value:
            downloaded = Path(temp_value)
            run(["gh", "release", "download", tag, "--dir", str(downloaded)])
            mismatches = [
                path.name
                for path in assets
                if not (downloaded / path.name).is_file()
                or sha256(path) != sha256(downloaded / path.name)
            ]
        if mismatches:
            raise SystemExit(f"{tag} already contains mismatched assets: {', '.join(mismatches)}")
        release_result = "already-published"
    else:
        run(
            [
                "gh",
                "release",
                "create",
                tag,
                *[str(path) for path in assets],
                "--verify-tag",
                "--title",
                f"Atlaso Inventory Linux {version}",
                "--notes",
                f"Final Inventory Linux release built from `{args.commit}`.",
                "--latest=false",
            ]
        )

    pages_result = publish_pages(
        site_root=args.site_root.resolve(),
        manifest_path=manifest_path,
        signature_path=signature_path,
        trusted_key=args.trusted_key.resolve(),
        manifest=manifest,
    )
    print(
        json.dumps(
            {
                "tag": tag,
                "commit": args.commit,
                "release": release_result,
                "pages": pages_result,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
