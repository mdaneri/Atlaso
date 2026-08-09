"""Test inventory linux release behavior."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
KEY_ID = "inventory-test-key"


def load_script(module_name: str, filename: str):
    """Return script."""
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


builder = load_script("build_inventory_linux_release_test", "build_inventory_linux_release.py")
publisher = load_script("publish_inventory_linux_release_test", "publish_inventory_linux_release.py")


@pytest.fixture
def signing_key(tmp_path: Path) -> tuple[Path, Path]:
    """Return signing key."""
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def inventory_package(root: Path, version: str) -> Path:
    """Return inventory package."""
    package = root / f"atlaso-inventory-linux-{version}.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "atlaso-inventory-linux",
                    "version": version,
                }
            ),
        )
    return package


def build_assets(
    root: Path,
    signing_key: Path,
    *,
    version: str = "2026.05.1+8",
    commit: str = "a" * 40,
) -> Path:
    """Build assets.

    Returns:
        The built assets.
    """
    root.mkdir(parents=True, exist_ok=True)
    package = inventory_package(root, version)
    output = root / "release"
    assert builder.main(
        [
            "--package",
            str(package),
            "--output",
            str(output),
            "--signing-key",
            str(signing_key),
            "--signing-key-id",
            KEY_ID,
            "--commit",
            commit,
            "--built-at",
            "2026-07-31T12:00:00Z",
        ]
    ) == 0
    return output


def completed(
    command: list[str],
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    """Return completed."""
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_inventory_release_metadata_is_deterministic_and_exact(signing_key, tmp_path):
    """Verify that inventory release metadata is deterministic and exact."""
    private_path, public_path = signing_key
    first = build_assets(tmp_path / "first", private_path)
    second = build_assets(tmp_path / "second", private_path)
    for name in (
        "atlaso-inventory-linux-2026.05.1+8.zip",
        "inventory-linux-manifest.json",
        "inventory-linux-manifest.json.sig",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    manifest = publisher.verify_manifest(
        first / "inventory-linux-manifest.json",
        first / "inventory-linux-manifest.json.sig",
        trusted_key=public_path,
    )
    assert manifest["version"] == "2026.05.1+8"
    assert manifest["package"]["url"].endswith(
        "/inventory-linux-v2026.05.1%2B8/atlaso-inventory-linux-2026.05.1%2B8.zip"
    )


def test_inventory_pages_advance_monotonically_and_are_idempotent(signing_key, tmp_path):
    """Verify that inventory pages advance monotonically and are idempotent."""
    private_path, public_path = signing_key
    site = tmp_path / "site"
    newest = build_assets(tmp_path / "newest", private_path)
    manifest_path = newest / "inventory-linux-manifest.json"
    signature_path = newest / "inventory-linux-manifest.json.sig"
    manifest = publisher.verify_manifest(
        manifest_path,
        signature_path,
        trusted_key=public_path,
    )
    assert publisher.publish_pages(
        site_root=site,
        manifest_path=manifest_path,
        signature_path=signature_path,
        trusted_key=public_path,
        manifest=manifest,
    ) == "advanced"
    assert publisher.publish_pages(
        site_root=site,
        manifest_path=manifest_path,
        signature_path=signature_path,
        trusted_key=public_path,
        manifest=manifest,
    ) == "already-current"
    assert (site / "updates/inventory-linux/latest/manifest.json").read_bytes() == manifest_path.read_bytes()
    assert (site / "updates/inventory-linux/releases/2026.05.1+8/manifest.json.sig").is_file()

    conflicting = build_assets(
        tmp_path / "conflicting",
        private_path,
        commit="c" * 40,
    )
    conflicting_manifest = publisher.verify_manifest(
        conflicting / "inventory-linux-manifest.json",
        conflicting / "inventory-linux-manifest.json.sig",
        trusted_key=public_path,
    )
    with pytest.raises(SystemExit, match="Pages metadata already differs"):
        publisher.publish_pages(
            site_root=site,
            manifest_path=conflicting / "inventory-linux-manifest.json",
            signature_path=conflicting / "inventory-linux-manifest.json.sig",
            trusted_key=public_path,
            manifest=conflicting_manifest,
        )

    older = build_assets(tmp_path / "older", private_path, version="2026.05.1+7")
    older_manifest = publisher.verify_manifest(
        older / "inventory-linux-manifest.json",
        older / "inventory-linux-manifest.json.sig",
        trusted_key=public_path,
    )
    with pytest.raises(SystemExit, match="cannot move backward"):
        publisher.publish_pages(
            site_root=site,
            manifest_path=older / "inventory-linux-manifest.json",
            signature_path=older / "inventory-linux-manifest.json.sig",
            trusted_key=public_path,
            manifest=older_manifest,
        )


def test_inventory_publisher_creates_final_non_latest_release(signing_key, tmp_path, monkeypatch):
    """Verify that inventory publisher creates final non latest release."""
    private_path, public_path = signing_key
    commit = "a" * 40
    assets = build_assets(tmp_path / "assets", private_path, commit=commit)
    commands: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool = True):
        """Return fake run."""
        commands.append(command)
        if command[:3] == ["git", "ls-remote", "--tags"]:
            return completed(command)
        if command[:3] == ["gh", "release", "view"]:
            return completed(command, returncode=1, stderr="not found")
        return completed(command)

    monkeypatch.setattr(publisher, "run", fake_run)
    assert publisher.main(
        [
            "--commit",
            commit,
            "--assets",
            str(assets),
            "--site-root",
            str(tmp_path / "site"),
            "--trusted-key",
            str(public_path),
        ]
    ) == 0
    create = next(command for command in commands if command[:3] == ["gh", "release", "create"])
    assert "--latest=false" in create
    assert "--draft" not in create
    assert "--prerelease" not in create
    assert ["git", "push", "origin", "refs/tags/inventory-linux-v2026.05.1+8"] in commands


def test_inventory_publisher_rejects_tag_collision(signing_key, tmp_path, monkeypatch):
    """Verify that inventory publisher rejects tag collision."""
    private_path, public_path = signing_key
    assets = build_assets(tmp_path / "assets", private_path)

    def fake_run(command: list[str], *, check: bool = True):
        """Return fake run.

        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        if command[:3] == ["git", "ls-remote", "--tags"]:
            return completed(
                command,
                stdout=f"{'b' * 40}\trefs/tags/inventory-linux-v2026.05.1+8\n",
            )
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(publisher, "run", fake_run)
    with pytest.raises(SystemExit, match="already identifies"):
        publisher.main(
            [
                "--commit",
                "a" * 40,
                "--assets",
                str(assets),
                "--site-root",
                str(tmp_path / "site"),
                "--trusted-key",
                str(public_path),
            ]
        )


def test_inventory_publisher_accepts_byte_identical_existing_assets(signing_key, tmp_path, monkeypatch):
    """Verify that inventory publisher accepts byte identical existing assets."""
    private_path, public_path = signing_key
    commit = "a" * 40
    assets = build_assets(tmp_path / "assets", private_path, commit=commit)
    asset_names = [path.name for path in assets.iterdir() if path.is_file()]

    def fake_run(command: list[str], *, check: bool = True):
        """Return fake run.

        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        if command[:3] == ["git", "ls-remote", "--tags"]:
            return completed(command, stdout=f"{commit}\t{command[-1]}\n")
        if command[:3] == ["gh", "release", "view"]:
            return completed(
                command,
                stdout=json.dumps(
                    {
                        "tagName": "inventory-linux-v2026.05.1+8",
                        "isDraft": False,
                        "isPrerelease": False,
                        "assets": [{"name": name} for name in asset_names],
                    }
                ),
            )
        if command[:3] == ["gh", "release", "download"]:
            destination = Path(command[command.index("--dir") + 1])
            for source in assets.iterdir():
                if source.is_file():
                    shutil.copy2(source, destination / source.name)
            return completed(command)
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(publisher, "run", fake_run)
    assert publisher.main(
        [
            "--commit",
            commit,
            "--assets",
            str(assets),
            "--site-root",
            str(tmp_path / "site"),
            "--trusted-key",
            str(public_path),
        ]
    ) == 0


def test_inventory_publisher_rejects_existing_asset_collision(signing_key, tmp_path, monkeypatch):
    """Verify that inventory publisher rejects existing asset collision."""
    private_path, public_path = signing_key
    commit = "a" * 40
    assets = build_assets(tmp_path / "assets", private_path, commit=commit)

    def fake_run(command: list[str], *, check: bool = True):
        """Return fake run.

        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        if command[:3] == ["git", "ls-remote", "--tags"]:
            return completed(command, stdout=f"{commit}\t{command[-1]}\n")
        if command[:3] == ["gh", "release", "view"]:
            return completed(
                command,
                stdout=json.dumps(
                    {
                        "tagName": "inventory-linux-v2026.05.1+8",
                        "isDraft": False,
                        "isPrerelease": False,
                        "assets": [{"name": "unexpected.zip"}],
                    }
                ),
            )
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(publisher, "run", fake_run)
    with pytest.raises(SystemExit, match="different assets"):
        publisher.main(
            [
                "--commit",
                commit,
                "--assets",
                str(assets),
                "--site-root",
                str(tmp_path / "site"),
                "--trusted-key",
                str(public_path),
            ]
        )
