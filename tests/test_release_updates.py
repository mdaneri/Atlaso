"""Test release updates behavior."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atlaso.app.services.release_updates import (
    ReleaseManifestError,
    inventory_version_tuple,
    validate_inventory_release_manifest,
    validate_release_manifest,
    verify_signed_json,
)

ROOT = Path(__file__).resolve().parents[1]
KEY_ID = "test-release-key"


def load_script(module_name: str, filename: str):
    """Load one repository script as a test module.

    Args:
        module_name: Unique module name for the import.
        filename: Script filename under the repository scripts directory.

    Returns:
        The loaded script module.
    """
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "scripts" / filename)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


published_channel_check = load_script(
    "check_published_release_channel_script",
    "check_published_release_channel.py",
)


def canonical(payload: dict) -> bytes:
    """Return canonical.

    Args:
        payload: Validated request or task payload consumed by the operation.
    """
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def release_payload() -> dict:
    """Return release payload."""
    return {
        "schema_version": 2,
        "kind": "atlaso-release",
        "updater_protocol": 2,
        "database_schema_version": 1,
        "version": "0.9.0",
        "git_commit": "a" * 40,
        "built_at": "2026-07-23T12:00:00Z",
        "signing_key_id": KEY_ID,
        "supported_python_abis": ["cp314"],
        "bundle": {
            "url": "https://github.com/mdaneri/Atlaso/releases/download/v0.9.0/bundle.tar.gz",
            "size": 123,
            "sha256": "b" * 64,
        },
        "content_hashes": {"packages/atlaso.whl": "c" * 64},
    }


def inventory_payload() -> dict:
    """Return inventory payload."""
    return {
        "schema_version": 1,
        "kind": "atlaso-inventory-linux-release",
        "version": "2026.05.1+8",
        "git_commit": "a" * 40,
        "built_at": "2026-07-31T12:00:00Z",
        "signing_key_id": KEY_ID,
        "architecture": "x86_64",
        "package": {
            "name": "atlaso-inventory-linux-2026.05.1+8.zip",
            "url": "https://github.com/mdaneri/Atlaso/releases/download/inventory-linux-v2026.05.1%2B8/atlaso-inventory-linux-2026.05.1%2B8.zip",
            "size": 123,
            "sha256": "d" * 64,
        },
    }


def signed(payload: dict, private_key: Ed25519PrivateKey) -> tuple[bytes, bytes]:
    """Return signed.

    Args:
        payload: Validated request or task payload consumed by the operation.
        private_key: Private key supplied to the test scenario.
    """
    raw = canonical(payload)
    signature = canonical(
        {
            "schema_version": 1,
            "key_id": KEY_ID,
            "signature": base64.b64encode(private_key.sign(raw)).decode(),
        }
    )
    return raw, signature


@pytest.fixture
def trust(tmp_path):
    """Return trust.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / f"{KEY_ID}.pem").write_bytes(public_key)
    return private_key, trust_dir


def test_signed_release_verification_fails_closed(trust):
    """Verify that signed release verification fails closed.

    Args:
        trust: Trust supplied to the test scenario.
    """
    private_key, trust_dir = trust
    raw, signature = signed(release_payload(), private_key)

    assert verify_signed_json(raw, signature, trust_dir=trust_dir, document_kind="release")["version"] == "0.9.0"

    with pytest.raises(ReleaseManifestError, match="invalid"):
        verify_signed_json(raw + b" ", signature, trust_dir=trust_dir, document_kind="release")
    with pytest.raises(ReleaseManifestError, match="not trusted"):
        verify_signed_json(raw, signature, trust_dir=trust_dir / "missing", document_kind="release")
    with pytest.raises(ReleaseManifestError, match="valid JSON"):
        verify_signed_json(raw, b"not-json", trust_dir=trust_dir, document_kind="release")
    (trust_dir / f"{KEY_ID}.pem").write_text("not a key", encoding="utf-8")
    with pytest.raises(ReleaseManifestError, match="malformed"):
        verify_signed_json(raw, signature, trust_dir=trust_dir, document_kind="release")


def test_channel_pointer_must_match_named_key(trust):
    """Verify that channel pointer must match named key.

    Args:
        trust: Trust supplied to the test scenario.
    """
    private_key, trust_dir = trust
    channel = {
        "schema_version": 2,
        "kind": "atlaso-channel",
        "channel": "preview",
        "version": "0.9.0",
        "git_commit": "a" * 40,
        "release_manifest_url": "https://example.test/releases/v0.9.0/release-manifest.json",
        "issued_at": "2026-07-23T12:00:00Z",
        "signing_key_id": KEY_ID,
    }
    raw, signature = signed(channel, private_key)
    assert verify_signed_json(raw, signature, trust_dir=trust_dir, document_kind="channel")["channel"] == "preview"
    channel["signing_key_id"] = "another-key"
    mismatched_raw = canonical(channel)
    mismatched_signature = canonical(
        {
            "schema_version": 1,
            "key_id": KEY_ID,
            "signature": base64.b64encode(private_key.sign(mismatched_raw)).decode(),
        }
    )
    with pytest.raises(ReleaseManifestError, match="key IDs do not match"):
        verify_signed_json(mismatched_raw, mismatched_signature, trust_dir=trust_dir, document_kind="channel")


def test_signed_inventory_release_verification_detects_tampering(trust):
    """Verify that signed inventory release verification detects tampering.

    Args:
        trust: Trust supplied to the test scenario.
    """
    private_key, trust_dir = trust
    raw, signature = signed(inventory_payload(), private_key)
    assert verify_signed_json(
        raw,
        signature,
        trust_dir=trust_dir,
        document_kind="inventory",
    )["version"] == "2026.05.1+8"
    with pytest.raises(ReleaseManifestError, match="signature is invalid"):
        verify_signed_json(
            raw.replace(b'"size": 123', b'"size": 124'),
            signature,
            trust_dir=trust_dir,
            document_kind="inventory",
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"version": "2026.05.1"}, "X.Y.Z\\+revision"),
        ({"architecture": "aarch64"}, "x86_64"),
        ({"package": {"size": 0}}, "size"),
        ({"package": {"size": 2 * 1024 * 1024 * 1024 + 1}}, "size"),
        ({"package": {"sha256": "nope"}}, "SHA256"),
        ({"package": {"url": "http://github.com/example.zip"}}, "HTTPS URL"),
        ({"package": {"url": "https://example.test/example.zip"}}, "dedicated Atlaso release tag"),
        (
            {
                "package": {
                    "url": "https://github.com/mdaneri/Atlaso/releases/download/inventory-linux-v2026.05.1%2B9/atlaso-inventory-linux-2026.05.1%2B8.zip"
                }
            },
            "dedicated Atlaso release tag",
        ),
    ],
)
def test_inventory_release_manifest_fails_closed(mutation, message):
    """Verify that inventory release manifest fails closed.

    Args:
        mutation: Mutation supplied to the test scenario.
        message: Human-readable message associated with the operation.
    """
    payload = inventory_payload()
    for key, value in mutation.items():
        if key == "package":
            payload["package"].update(value)
        else:
            payload[key] = value
    with pytest.raises(ReleaseManifestError, match=message):
        validate_inventory_release_manifest(payload)


def test_inventory_version_order_includes_revision():
    """Verify that inventory version order includes revision."""
    assert inventory_version_tuple("2026.05.1+8") > inventory_version_tuple("2026.05.1+7")
    assert inventory_version_tuple("2026.06.0+1") > inventory_version_tuple("2026.05.99+99")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("updater_protocol", 0, "updater_protocol"),
        ("database_schema_version", 0, "database_schema_version"),
        ("version", "0.9", "semantic versioning"),
        ("built_at", "not-a-time", "ISO 8601"),
    ],
)
def test_release_manifest_requires_complete_v2_interface(field, value, message):
    """Verify that release manifest requires complete v2 interface.

    Args:
        field: Field supplied to the test scenario.
        value: Candidate value consumed by test release manifest requires complete v2 interface.
        message: Human-readable message associated with the operation.
    """
    payload = release_payload()
    payload[field] = value
    with pytest.raises(ReleaseManifestError, match=message):
        validate_release_manifest(payload)


def test_release_manifest_rejects_non_appliance_python_abi():
    """Verify that release manifest rejects non appliance python abi."""
    payload = release_payload()
    payload["supported_python_abis"] = ["cp313"]
    with pytest.raises(ReleaseManifestError, match="supported_python_abis"):
        validate_release_manifest(payload)


def test_release_workflows_use_successful_main_sha_and_promote_without_rebuilding():
    """Verify that release workflows use successful main sha and promote without rebuilding."""
    publication = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    inventory = (ROOT / ".github/workflows/inventory-linux-release.yml").read_text(
        encoding="utf-8"
    )
    inventory_publisher = (
        ROOT / "scripts/publish_inventory_linux_release.py"
    ).read_text(encoding="utf-8")
    promotion = (ROOT / ".github/workflows/promote-release.yml").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "github.event.workflow_run.head_branch == 'main'" in publication
    assert "github.event.workflow_run.event == 'push'" in publication
    assert (
        publication.count(
            "github.event.workflow_run.head_repository.full_name == github.repository"
        )
        == 1
    )
    assert "github.event_name == 'workflow_dispatch'" in publication
    assert "-f head_sha=\"$RELEASE_SHA\"" in publication
    assert "-f status=success" in publication
    assert "has no successful main push CI run" in publication
    assert "legacy bridge" not in publication
    assert 'cat > "$SITE_ROOT/index.html"' in publication
    assert "Everything your virtualization lab needs." in publication
    assert "Infrastructure • Storage • Identity • Networking • Lifecycle" in publication
    assert "The HTML page is informational." in publication
    assert "python scripts/check_published_release_channel.py" in publication
    assert "--expected-channel development" in publication
    publication_check = publication.split(
        "- name: Verify the published development channel",
        1,
    )[1]
    assert "/updates/channels/development/manifest.json" in publication_check
    assert '--expected-version "$VERSION"' in publication_check
    assert '--expected-commit "$RELEASE_SHA"' in publication_check
    assert "<script" not in publication
    assert publication.count("ref: ${{ needs.prepare.outputs.release_sha }}") == 2
    assert "actions/upload-artifact@v7" in publication
    assert publication.count("actions/download-artifact@v8") == 1
    assert "python-version: '3.14'" in publication
    assert "python-version: '3.14'" in promotion
    assert ci.count("python-version: '3.14'") == 3
    assert "cp312" not in publication
    assert "cp313" not in publication
    assert "actions/upload-artifact@v4" not in publication
    assert "actions/download-artifact@v4" not in publication
    assert '--commit "$RELEASE_SHA"' in publication
    assert "--expected-version \"$VERSION\"" in publication
    assert '--site-root "$SITE_ROOT/updates"' in publication
    assert 'test "$VERSION" = "0.9.18"' in publication
    assert "gh release download" in promotion
    assert "build_release_bundle.py" not in promotion
    assert "--expected-version \"$RELEASE_VERSION\"" in promotion
    assert "python scripts/check_published_release_channel.py" in promotion
    assert '--expected-channel "$RELEASE_CHANNEL"' in promotion
    promotion_check = promotion.split(
        "- name: Verify the published signed channel",
        1,
    )[1]
    assert '--expected-version "$RELEASE_VERSION"' in promotion_check
    assert '--expected-commit "$RELEASE_COMMIT"' in promotion_check
    assert "workflow_dispatch:" in inventory
    assert "workflow_run:" not in inventory
    assert "schedule:" not in inventory
    assert "environment: appliance-release" in inventory
    assert '-f head_sha="$RELEASE_SHA"' in inventory
    assert "-f branch=main" in inventory
    assert "-f event=push" in inventory
    assert "-f status=success" in inventory
    assert "has no successful main push CI run" in inventory
    assert "--latest=false" in inventory_publisher
    assert '"--draft"' not in inventory_publisher
    assert '"--prerelease"' not in inventory_publisher
    assert "inventory-linux-v" not in publication
    assert "--inventory-package" not in publication
    assert "development" not in inventory
    assert "preview" not in inventory
    assert "staging" not in inventory


def test_published_channel_check_verifies_pointer_release_and_compatibility(
    trust,
    monkeypatch,
):
    """Verify the live guard reaches signed release and ABI validation.

    Args:
        trust: Trust supplied to the test scenario.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    private_key, trust_dir = trust
    channel_url = "https://updates.example.test/channels/stable/manifest.json"
    release_url = "https://github.com/example/releases/download/v0.9.0/release-manifest.json"
    release = release_payload()
    channel = {
        "schema_version": 2,
        "kind": "atlaso-channel",
        "channel": "stable",
        "version": release["version"],
        "git_commit": release["git_commit"],
        "release_manifest_url": release_url,
        "issued_at": "2026-08-13T12:00:00Z",
        "signing_key_id": KEY_ID,
    }
    raw_channel, channel_signature = signed(channel, private_key)
    raw_release, release_signature = signed(release, private_key)
    documents = {
        channel_url: raw_channel,
        f"{channel_url}.sig": channel_signature,
        release_url: raw_release,
        f"{release_url}.sig": release_signature,
    }

    class Response:
        """Provide a bounded in-memory urlopen response."""

        def __init__(self, body: bytes):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return self.body

    monkeypatch.setattr(
        published_channel_check,
        "urlopen",
        lambda url, timeout: Response(documents[url]),
    )

    result = published_channel_check.verify_channel(
        channel_url,
        expected_channel="stable",
        expected_version="0.9.0",
        expected_commit="a" * 40,
        expected_python_abi="cp314",
        trusted_key=trust_dir / f"{KEY_ID}.pem",
        timeout_seconds=1,
    )

    assert result["channel"]["version"] == "0.9.0"
    assert result["release"]["git_commit"] == "a" * 40

    with pytest.raises(ValueError, match="does not support cp313"):
        published_channel_check.verify_channel(
            channel_url,
            expected_channel="stable",
            expected_version="0.9.0",
            expected_commit="a" * 40,
            expected_python_abi="cp313",
            trusted_key=trust_dir / f"{KEY_ID}.pem",
            timeout_seconds=1,
        )

    with pytest.raises(ValueError, match="expected v0.9.1"):
        published_channel_check.verify_channel(
            channel_url,
            expected_channel="stable",
            expected_version="0.9.1",
            expected_commit="b" * 40,
            expected_python_abi="cp314",
            trusted_key=trust_dir / f"{KEY_ID}.pem",
            timeout_seconds=1,
        )


def test_published_channel_check_imports_atlaso_from_a_clean_checkout(tmp_path: Path):
    """Verify direct workflow execution imports Atlaso without an installation.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts" / "check_published_release_channel.py"),
            "--help",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Verify a published Atlaso channel" in result.stdout


def test_published_channel_check_covers_pages_publication_window():
    """Verify default retries cover the bounded GitHub Pages publication window."""
    retry_window = (
        published_channel_check.DEFAULT_ATTEMPTS - 1
    ) * published_channel_check.DEFAULT_RETRY_DELAY_SECONDS

    assert retry_window >= published_channel_check.PAGES_PUBLICATION_WINDOW_SECONDS


def test_published_channel_check_fails_when_default_pointer_is_absent(
    trust,
    monkeypatch,
):
    """Verify the live guard reports a missing default channel.

    Args:
        trust: Trust supplied to the test scenario.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    _private_key, trust_dir = trust
    monkeypatch.setattr(
        published_channel_check,
        "urlopen",
        lambda url, timeout: (_ for _ in ()).throw(
            HTTPError(url, 404, "Not Found", {}, None)
        ),
    )

    with pytest.raises(SystemExit, match="failed verification.*404"):
        published_channel_check.main(
            [
                "--channel-url",
                "https://updates.example.test/channels/stable/manifest.json",
                "--expected-channel",
                "stable",
                "--expected-version",
                "0.9.0",
                "--expected-commit",
                "a" * 40,
                "--trusted-key",
                str(trust_dir / f"{KEY_ID}.pem"),
                "--attempts",
                "1",
            ]
        )


def test_pages_writers_share_multi_entry_publication_queue():
    """Verify every Pages writer preserves multiple pending publications."""
    workflow_root = ROOT / ".github" / "workflows"
    writers: set[Path] = set()
    queue_users: set[Path] = set()

    for path in workflow_root.glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if "HEAD:gh-pages" in text:
            writers.add(path)
            assert 'test -s "$SITE_ROOT/updates/channels/stable/manifest.json"' in text, path
            assert 'test -s "$SITE_ROOT/updates/channels/stable/manifest.json.sig"' in text, path
        if "group: atlaso-github-pages" not in text:
            continue
        queue_users.add(path)
        for declaration in text.split("group: atlaso-github-pages")[1:]:
            settings = "\n".join(declaration.splitlines()[:3])
            assert "queue: max" in settings, path
            assert "cancel-in-progress: false" in settings, path

    assert writers
    assert queue_users == writers

    inventory = (workflow_root / "inventory-linux-release.yml").read_text(
        encoding="utf-8"
    )
    build_job, publish_job = inventory.split("  build:\n", 1)[1].split(
        "  publish:\n", 1
    )
    assert "atlaso-github-pages" not in build_job
    assert "actions/upload-artifact@v7" in build_job
    assert "group: atlaso-github-pages" in publish_job
    assert "actions/download-artifact@v8" in publish_job
    assert "HEAD:gh-pages" in publish_job


def test_idempotent_publisher_refuses_existing_tag_for_another_commit(monkeypatch, tmp_path):
    """Verify that idempotent publisher refuses existing tag for another commit.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    spec = importlib.util.spec_from_file_location("publish_release", ROOT / "scripts/publish_release.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "release-manifest.json").write_text("{}", encoding="utf-8")
    requested = "a" * 40
    existing = "b" * 40

    def fake_run(command, *, check=True):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            check: Whether a nonzero command status raises an exception.


        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        import subprocess

        if command[:3] == ["git", "ls-remote", "--tags"]:
            return subprocess.CompletedProcess(command, 0, f"{existing}\trefs/tags/v0.9.0\n", "")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(module, "run", fake_run)
    monkeypatch.setattr(module, "version", lambda: "0.9.0")
    monkeypatch.setattr(
        "sys.argv",
        ["publish_release.py", "--commit", requested, "--assets", str(assets)],
    )
    with pytest.raises(SystemExit, match="already identifies"):
        module.main()


def test_idempotent_publisher_creates_annotated_tag_without_global_git_identity(
    monkeypatch,
    tmp_path,
):
    """Verify that idempotent publisher creates annotated tag without global git identity.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    spec = importlib.util.spec_from_file_location("publish_release", ROOT / "scripts/publish_release.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "release-manifest.json").write_text("{}", encoding="utf-8")
    requested = "a" * 40
    commands: list[list[str]] = []

    def fake_run(command, *, check=True):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            check: Whether a nonzero command status raises an exception.
        """
        import subprocess

        commands.append(command)
        if command[:3] == ["git", "ls-remote", "--tags"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["gh", "release", "view"]:
            return subprocess.CompletedProcess(command, 1, "", "release not found")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(module, "run", fake_run)
    monkeypatch.setattr(module, "version", lambda: "0.9.0")
    monkeypatch.setattr(
        "sys.argv",
        ["publish_release.py", "--commit", requested, "--assets", str(assets)],
    )

    assert module.main() == 0
    tag_command = next(command for command in commands if "tag" in command)
    assert tag_command[:6] == [
        "git",
        "-c",
        "user.name=github-actions[bot]",
        "-c",
        "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "tag",
    ]
    assert ["git", "push", "origin", "refs/tags/v0.9.0"] in commands


def test_deterministic_release_archive_normalizes_metadata(tmp_path):
    """Verify that deterministic release archive normalizes metadata.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    spec = importlib.util.spec_from_file_location("build_release_bundle", ROOT / "scripts/build_release_bundle.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source"
    source.mkdir()
    (source / "z.txt").write_text("same\n", encoding="utf-8")
    (source / "a").mkdir()
    (source / "a/data.txt").write_text("content\n", encoding="utf-8")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    module.deterministic_tar_gz(source, first)
    os.utime(source / "z.txt", (2_000_000_000, 2_000_000_000))
    module.deterministic_tar_gz(source, second)
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()


def test_abi_wheelhouse_lock_covers_exact_checked_in_versions(monkeypatch, tmp_path):
    """Verify that abi wheelhouse lock covers exact checked in versions.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    spec = importlib.util.spec_from_file_location(
        "write_wheelhouse_lock",
        ROOT / "scripts/write_wheelhouse_lock.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "example_pkg-1.2.3-py3-none-any.whl").write_bytes(b"wheel-one")
    (wheelhouse / "second-4.5.6-py3-none-any.whl").write_bytes(b"wheel-two")
    source_lock = tmp_path / "source.lock"
    source_lock.write_text("example-pkg==1.2.3\nsecond==4.5.6\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "write_wheelhouse_lock.py",
            "--wheelhouse",
            str(wheelhouse),
            "--source-lock",
            str(source_lock),
        ],
    )
    assert module.main() == 0
    runtime_lock = (wheelhouse / "requirements-wheelhouse.lock").read_text(encoding="utf-8")
    assert "example-pkg==1.2.3 --hash=sha256:" in runtime_lock
    assert "second==4.5.6 --hash=sha256:" in runtime_lock


def test_helper_offline_install_uses_only_locked_wheelhouse(monkeypatch, tmp_path):
    """Verify that helper offline install uses only locked wheelhouse.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    release = tmp_path / "release"
    (release / "wheelhouse/cp314").mkdir(parents=True)
    (release / "wheelhouse/cp314/dependency.whl").write_bytes(b"wheel")
    (release / "packages").mkdir()
    (release / "packages/atlaso-0.9.0-py3-none-any.whl").write_bytes(b"wheel")
    (release / "wheelhouse/cp314/requirements-wheelhouse.lock").write_text(
        "dependency==1.0 --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    captured: list[tuple[list[str], dict[str, str]]] = []

    def fake_command(command, *, success_codes=None, env=None):
        """Return fake command.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        captured.append((command, env or {}))
        if command[1:3] == ["-m", "venv"]:
            (Path(command[-1]) / "bin").mkdir(parents=True)
            (Path(command[-1]) / "bin/python").write_text("", encoding="utf-8")
        return {"command": command, "returncode": 0, "success": True, "stdout": "", "stderr": ""}

    monkeypatch.setattr(helper, "_command_payload", fake_command)
    commands = helper._install_release_venv(release, "cp314")
    assert all(command["success"] for command in commands)
    dependency_command, env = next(
        item for item in captured if "--require-hashes" in item[0]
    )
    assert "--no-index" in dependency_command
    assert "--find-links" in dependency_command
    assert env["PIP_CONFIG_FILE"] == "/dev/null"
    assert env["PIP_NO_INDEX"] == "1"


def test_photon_candidate_abi_uses_python_nevra_and_transaction_is_test_only(monkeypatch):
    """Verify that photon candidate abi uses python nevra and transaction is test only.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/tdnf")
    monkeypatch.setattr(
        helper,
        "_command_payload",
        lambda command, **_kwargs: {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": "VMware Photon Linux 5.0\npython3-3.14.5-2.ph5.x86_64\n",
            "stderr": "",
        },
    )
    command, abi = helper._candidate_photon_python_abi()
    assert command["success"] is True
    assert abi == "cp314"
    helper_text = (ROOT / "scripts/appliance/atlaso-helper").read_text(encoding="utf-8")
    assert '[tdnf, "-y", "update", "--testonly"]' in helper_text
    assert "--assumeno" not in helper_text


def test_helper_rejects_unsafe_release_archive(tmp_path):
    """Verify that helper rejects unsafe release archive.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    archive_path = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("../outside")
        payload = b"bad"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    with pytest.raises(ValueError, match="unsafe member"):
        helper._safe_extract_release(archive_path, tmp_path / "extract")


def test_sqlite_backup_restores_database_identity(monkeypatch, tmp_path):
    """Verify that sqlite backup restores database identity.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import sqlite3

    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    database = tmp_path / "atlaso.db"
    backup = tmp_path / "backup.db"
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("create table identity(value text)")
        connection.execute("insert into identity values ('before')")
        connection.commit()
    finally:
        connection.close()
    helper._sqlite_backup(backup)
    connection = sqlite3.connect(database)
    try:
        connection.execute("update identity set value='after'")
        connection.commit()
    finally:
        connection.close()
    helper._restore_sqlite_backup(backup)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("select value from identity").fetchone()[0] == "before"
    finally:
        connection.close()


def test_worker_restart_uses_matching_root_release_finalizer(client, monkeypatch, tmp_path):
    """Verify that worker restart uses matching root release finalizer.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    finalizer = tmp_path / "finalizer-status.json"
    finalizer.write_text(
        json.dumps(
            {
                "job_id": "job_release_finalizer",
                "status": "succeeded",
                "release": "0.9.0",
                "git_commit": "a" * 40,
                "verified_key_id": "atlaso-release-2026-01",
                "bundle_sha256": "b" * 64,
                "rolled_back": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_release_finalizer",
                type="appliance-update",
                status="running",
                created_by="admin",
                result='{"selected_streams":["atlaso_release"]}',
            )
        )
        db.commit()
        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, "job_release_finalizer")
        assert recovered.status == "succeeded"
        assert recovered.error is None
        result = json.loads(recovered.result)
        assert result["worker_recovery"] == "root_finalizer"
        assert result["release_transaction"]["verified_key_id"] == "atlaso-release-2026-01"


def test_worker_restart_fails_update_parent_after_children_commit(client, monkeypatch, tmp_path):
    """Verify that worker restart fails update parent after children commit.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    monkeypatch.setattr(
        worker,
        "APPLIANCE_UPDATE_FINALIZER_PATH",
        str(tmp_path / "missing-finalizer-status.json"),
    )
    with SessionLocal() as db:
        job = Job(
            id="job_update_children_committed",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {"selected_streams": ["powershell_modules", "photon_os"], "mode": "check"}
            ),
            result='{"status":"pending","success":false}',
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["powershell_modules", "photon_os"],
        )
        for step in steps:
            step.status = "succeeded"
            step.progress_percent = 100
            step.result = '{"status":"succeeded","success":true}'
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        assert recovered.status == "failed"
        assert recovered.progress_percent == 100
        assert "worker restarted" in (recovered.error or "")
        result = json.loads(recovered.result or "{}")
        assert result["status"] == "failed"
        assert result["success"] is False
        assert result["worker_recovery"] == "interrupted"
        assert [step.status for step in recovered.steps] == ["succeeded", "succeeded"]


def test_worker_restart_removes_interrupted_network_boot_upload(client, monkeypatch):
    """Verify that worker restart removes interrupted network boot upload.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    cleaned = []
    monkeypatch.setattr(worker, "cleanup_network_boot_upload", cleaned.append)
    with SessionLocal() as db:
        job = Job(
            id="job_" + ("e" * 32),
            type="pxe-media-sync",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {"environment": "inventory", "source": "upload"}
            ),
        )
        db.add(job)
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        assert cleaned == [job.id]
        assert db.get(Job, job.id).status == "failed"


def test_worker_restart_keeps_release_finalizer_scoped_to_its_child(client, monkeypatch, tmp_path):
    """Verify that worker restart keeps release finalizer scoped to its child.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select

    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    finalizer = tmp_path / "finalizer-status.json"
    finalizer.write_text(
        json.dumps(
            {
                "job_id": "job_release_partial_finalizer",
                "status": "succeeded",
                "release": "0.9.0",
                "git_commit": "a" * 40,
                "verified_key_id": "atlaso-release-2026-01",
                "bundle_sha256": "b" * 64,
                "rolled_back": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_FINALIZER_PATH", str(finalizer))
    with SessionLocal() as db:
        job = Job(
            id="job_release_partial_finalizer",
            type="appliance-update",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {"selected_streams": ["atlaso_release", "photon_os"], "mode": "run"}
            ),
            result='{"selected_streams":["atlaso_release","photon_os"]}',
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["atlaso_release", "photon_os"],
        )
        release_step = steps[0]
        release_step.status = "running"
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
        assert recovered.status == "failed"
        assert [(step.component_key, step.status) for step in steps] == [
            ("atlaso_release", "succeeded"),
            ("photon_os", "skipped"),
        ]
        assert "worker restarted" in (steps[-1].error or "")


@pytest.mark.parametrize("failure_stage", ["database_migration", "symlink_switch", "service_health"])
def test_failed_candidate_restores_previous_release_and_database(monkeypatch, tmp_path, failure_stage):
    """Verify that failed candidate restores previous release and database.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        failure_stage: Failure stage supplied to the test scenario.
    """
    import sqlite3

    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    home = tmp_path / "opt/atlaso"
    releases = home / "releases"
    previous = releases / "0.8.9"
    previous.mkdir(parents=True)
    (previous / ".venv").mkdir()
    current = home / "current"
    current.symlink_to(previous, target_is_directory=True)
    venv = home / ".venv"
    venv.symlink_to(Path("current/.venv"), target_is_directory=True)
    database = tmp_path / "atlaso.db"

    def set_identity(value: str) -> None:
        """Update identity.

        Args:
            value: Candidate value consumed by set identity.
        """
        connection = sqlite3.connect(database)
        try:
            connection.execute("create table if not exists identity(value text)")
            connection.execute("delete from identity")
            connection.execute("insert into identity values (?)", (value,))
            connection.commit()
        finally:
            connection.close()

    def get_identity() -> str:
        """Return identity."""
        connection = sqlite3.connect(database)
        try:
            return connection.execute("select value from identity").fetchone()[0]
        finally:
            connection.close()

    set_identity("before")
    metadata = canonical(
        {
            "schema_version": 1,
            "version": "0.9.0",
            "git_commit": "a" * 40,
            "built_at": "2026-07-23T12:00:00Z",
            "supported_python_abis": ["cp314"],
        }
    )
    bundle_buffer = io.BytesIO()
    with tarfile.open(fileobj=bundle_buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("bundle-metadata.json")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))
    bundle_bytes = bundle_buffer.getvalue()
    release = release_payload()
    release["supported_python_abis"] = ["cp314"]
    release["bundle"] = {
        "url": "https://example.test/bundle.tar.gz",
        "size": len(bundle_bytes),
        "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
    }
    release["content_hashes"] = {
        "bundle-metadata.json": hashlib.sha256(metadata).hexdigest(),
    }
    channel = {
        "channel": "development",
        "release_manifest_url": "https://example.test/release-manifest.json",
    }
    monkeypatch.setattr(helper, "ATLASO_HOME", home)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", releases)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_VENV_LINK", venv)
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", tmp_path / "finalizer.json")

    def replace_symlink(target: Path, link: Path) -> None:
        """Handle replace symlink.

        Args:
            target: Target resource or location affected by the operation.
            link: Filesystem path associated with link.


        Raises:
            OSError: If the operating-system operation fails.
        """
        if failure_stage == "symlink_switch" and target.name == "0.9.0":
            set_identity("after")
            raise OSError("injected symlink switch failure")
        link.unlink(missing_ok=True)
        link.symlink_to(target, target_is_directory=True)

    monkeypatch.setattr(helper, "_atomic_symlink", replace_symlink)
    monkeypatch.setattr(
        helper,
        "_download_signed_release_from_sources",
        lambda *_args: (channel, release, channel["release_manifest_url"], None),
    )
    monkeypatch.setattr(helper, "_fetch_http_bytes", lambda *_args: bundle_bytes)

    def install_venv(root: Path, _abi: str):
        """Return install venv.

        Args:
            root: Repository or filesystem root searched by the operation.
            _abi: Abi supplied to the test scenario.
        """
        (root / ".venv").mkdir()
        return [{"command": ["offline-install"], "returncode": 0, "success": True, "stdout": "", "stderr": ""}]

    monkeypatch.setattr(helper, "_install_release_venv", install_venv)
    monkeypatch.setattr(helper, "_install_release_owned_files", lambda *_args: [])
    migration_injected = False

    def service_command(action, *units):
        """Return service command.

        Args:
            action: Action supplied to the test scenario.
            *units: Additional positional arguments accepted by the callable.
        """
        nonlocal migration_injected
        if (
            failure_stage == "database_migration"
            and action == "start"
            and "atlaso.service" in units
            and not migration_injected
        ):
            set_identity("after")
            migration_injected = True
        return {
            "command": ["systemctl", action, *units],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_service_command", service_command)
    monkeypatch.setattr(
        helper,
        "_set_release_maintenance",
        lambda enabled: {
            "command": ["maintenance", str(enabled)],
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        },
    )
    health_attempts = iter([True] if failure_stage == "symlink_switch" else [False, True])

    def health():
        """Return health."""
        success = next(health_attempts)
        if not success and failure_stage == "service_health":
            set_identity("after")
        return {
            "command": ["health"],
            "returncode": 0 if success else 1,
            "success": success,
            "stdout": "",
            "stderr": "" if success else "candidate failed",
        }

    monkeypatch.setattr(helper, "_wait_for_atlaso_health", health)
    monkeypatch.setattr(helper, "_write_update_info", lambda _payload: None)

    with pytest.raises(ValueError, match="rolled back"):
        helper._apply_atlaso_release({}, {})

    assert current.resolve() == previous.resolve()
    assert get_identity() == "before"
    assert not (releases / "0.9.0").exists()
    assert json.loads((tmp_path / "finalizer.json").read_text(encoding="utf-8"))["rolled_back"] is True


@pytest.mark.parametrize("failure_stage", ["download", "signature", "extraction", "installation"])
def test_pre_switch_release_failures_leave_previous_release_and_database_untouched(
    monkeypatch,
    tmp_path,
    failure_stage,
):
    """Verify that pre switch release failures leave previous release and database untouched.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        failure_stage: Failure stage supplied to the test scenario.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    home = tmp_path / "opt/atlaso"
    previous = home / "releases/bootstrap-0.9.0"
    previous.mkdir(parents=True)
    (previous / ".venv").mkdir()
    current = home / "current"
    current.symlink_to(previous, target_is_directory=True)
    database = tmp_path / "atlaso.db"
    database.write_bytes(b"database-before")
    monkeypatch.setattr(helper, "ATLASO_HOME", home)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", home / "releases")
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_VENV_LINK", home / ".venv")
    monkeypatch.setattr(helper, "ATLASO_DATABASE_PATH", database)

    metadata = canonical(
        {
            "schema_version": 1,
            "version": "0.9.0",
            "git_commit": "a" * 40,
            "built_at": "2026-07-23T12:00:00Z",
            "supported_python_abis": ["cp314"],
        }
    )
    bundle_buffer = io.BytesIO()
    with tarfile.open(fileobj=bundle_buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("bundle-metadata.json")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))
    bundle_bytes = bundle_buffer.getvalue()
    release = release_payload()
    release["supported_python_abis"] = ["cp314"]
    release["bundle"] = {
        "url": "https://example.test/bundle.tar.gz",
        "size": len(bundle_bytes),
        "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
    }
    release["content_hashes"] = {
        "bundle-metadata.json": hashlib.sha256(metadata).hexdigest(),
    }
    channel = {
        "channel": "development",
        "release_manifest_url": "https://example.test/release-manifest.json",
    }
    if failure_stage == "signature":
        monkeypatch.setattr(
            helper,
            "_download_signed_release_from_sources",
            lambda *_args: (_ for _ in ()).throw(ValueError("injected invalid signature")),
        )
    else:
        monkeypatch.setattr(
            helper,
            "_download_signed_release_from_sources",
            lambda *_args: (channel, release, channel["release_manifest_url"], None),
        )
    if failure_stage == "download":
        monkeypatch.setattr(
            helper,
            "_fetch_http_bytes",
            lambda *_args: (_ for _ in ()).throw(OSError("injected download failure")),
        )
    else:
        monkeypatch.setattr(helper, "_fetch_http_bytes", lambda *_args: bundle_bytes)
    if failure_stage == "extraction":
        monkeypatch.setattr(
            helper,
            "_safe_extract_release",
            lambda *_args: (_ for _ in ()).throw(ValueError("injected extraction failure")),
        )
    if failure_stage == "installation":
        monkeypatch.setattr(
            helper,
            "_install_release_venv",
            lambda *_args: [
                {
                    "command": ["offline-install"],
                    "returncode": 1,
                    "success": False,
                    "stdout": "",
                    "stderr": "injected installation failure",
                }
            ],
        )

    with pytest.raises((OSError, ValueError)):
        helper._apply_atlaso_release({}, {})
    assert current.resolve() == previous.resolve()
    assert database.read_bytes() == b"database-before"
    assert not (home / "releases/0.9.0").exists()


def test_failed_revalidation_does_not_delete_an_existing_release(monkeypatch, tmp_path):
    """Verify that failed revalidation does not delete an existing release.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    home = tmp_path / "opt/atlaso"
    releases = home / "releases"
    previous = releases / "bootstrap-0.9.0"
    existing = releases / "0.9.0"
    previous.mkdir(parents=True)
    existing.mkdir(parents=True)
    marker = existing / "known-good"
    marker.write_text("preserve", encoding="utf-8")
    current = home / "current"
    current.symlink_to(previous, target_is_directory=True)
    release = release_payload()
    bundle = b"signed-bundle"
    release["bundle"] = {
        "url": "https://example.test/bundle.tar.gz",
        "size": len(bundle),
        "sha256": hashlib.sha256(bundle).hexdigest(),
    }
    monkeypatch.setattr(helper, "ATLASO_HOME", home)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", releases)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(
        helper,
        "_download_signed_release_from_sources",
        lambda *_args: (
            {"channel": "development"},
            release,
            "https://example.test/release-manifest.json",
            None,
        ),
    )
    monkeypatch.setattr(helper, "_fetch_http_bytes", lambda *_args: bundle)
    monkeypatch.setattr(
        helper,
        "_safe_extract_release",
        lambda *_args: (_ for _ in ()).throw(ValueError("injected extraction failure")),
    )

    with pytest.raises(ValueError, match="injected extraction failure"):
        helper._apply_atlaso_release({}, {})

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert current.resolve() == previous.resolve()


def test_authenticated_release_redirect_rejects_another_origin():
    """Verify that authenticated release redirect rejects another origin."""
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    source = "https://updates.example.test/channels/stable/manifest.json"
    request = helper.Request(source, headers={"Authorization": "Basic protected"})
    handler = helper._UpdateRedirectHandler(authenticated_origin=helper._url_origin(source))

    with pytest.raises(ValueError, match="another origin"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://redirect.example.test/manifest.json",
        )


def test_authenticated_release_redirect_preserves_same_origin_authorization():
    """Verify that authenticated release redirect preserves same origin authorization."""
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    source = "https://updates.example.test/channels/stable/manifest.json"
    request = helper.Request(source, headers={"Authorization": "Basic protected"})
    handler = helper._UpdateRedirectHandler(authenticated_origin=helper._url_origin(source))

    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://updates.example.test/releases/v0.9.0/manifest.json",
    )

    assert redirected.full_url == "https://updates.example.test/releases/v0.9.0/manifest.json"
    assert redirected.get_header("Authorization") == "Basic protected"


def test_release_redirect_rejects_https_downgrade_without_credentials():
    """Verify that release redirect rejects https downgrade without credentials."""
    from tests.test_appliance_update import load_helper_module

    helper = load_helper_module()
    source = "https://updates.example.test/channels/stable/manifest.json"
    handler = helper._UpdateRedirectHandler(authenticated_origin=None)

    with pytest.raises(ValueError, match="less secure scheme"):
        handler.redirect_request(
            helper.Request(source),
            None,
            302,
            "Found",
            {},
            "http://updates.example.test/manifest.json",
        )
