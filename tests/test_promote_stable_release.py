"""Verify exact GitHub Release metadata promotion and monotonic Latest handling."""

import json
import subprocess

import pytest

from scripts.installation import promote_stable_release as stable_release

COMMIT = "a" * 40
MANIFEST_SHA256 = "b" * 64
RELEASE_FINGERPRINT = "c" * 64
REPO = "mdaneri/Atlaso"


def release(tag: str, release_id: int, *, prerelease: bool) -> dict:
    """Create a published release metadata fixture.

    Args:
        tag: Release tag assigned to the fixture.
        release_id: GitHub numeric release ID.
        prerelease: Initial GitHub prerelease classification.
    """
    return {
        "id": release_id,
        "tag_name": tag,
        "draft": False,
        "prerelease": prerelease,
        "assets": [
            {
                "name": "release-manifest.json",
                "digest": f"sha256:{MANIFEST_SHA256}",
            }
        ],
        "body": "Original release notes",
    }


def arrange_promotion(monkeypatch, target: dict, published: list[dict]):
    """Stub remote release reads and record metadata writes.

    Args:
        monkeypatch: Fixture that replaces signing, tag, and GitHub dependencies.
        target: Release metadata to edit in place.
        published: Published releases available for Latest comparison.
    """
    requests = []

    def run(command, *, check=True, input_text=None):
        """Simulate release API calls and retain edit payloads.

        Args:
            command: Command line that would be passed to GitHub CLI.
            check: Whether the caller requested failure on a nonzero exit.
            input_text: JSON body of a metadata change, when supplied.
        """
        if "--method" in command:
            body = json.loads(input_text)
            requests.append(body)
            target.update(body)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(stable_release, "digest", lambda path: MANIFEST_SHA256)
    monkeypatch.setattr(
        stable_release,
        "verify_signed_json",
        lambda *args, **kwargs: {"version": target["tag_name"][1:], "git_commit": COMMIT},
    )
    monkeypatch.setattr(stable_release, "require_tag", lambda *args: None)
    monkeypatch.setattr(stable_release, "get_release", lambda *args: dict(target))
    monkeypatch.setattr(stable_release, "asset_records", lambda *args: {"release-manifest.json": (7, 2, f"sha256:{MANIFEST_SHA256}")})
    monkeypatch.setattr(stable_release, "release_fingerprint", lambda *args: RELEASE_FINGERPRINT)
    monkeypatch.setattr(stable_release, "release_list", lambda *args: published)
    monkeypatch.setattr(stable_release, "run", run)
    return requests


def test_promote_stable_advances_latest_to_the_highest_numeric_release(tmp_path, monkeypatch):
    """Make a physically accepted higher release stable and Latest.

    Args:
        tmp_path: Directory for the signed manifest fixture.
        monkeypatch: Fixture for replacing signing and GitHub dependencies.
    """
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    (tmp_path / "release-manifest.json.sig").write_text("{}", encoding="utf-8")
    target = release("v1.0.0", 42, prerelease=True)
    requests = arrange_promotion(monkeypatch, target, [release("v0.9.505", 1, prerelease=False), target])
    monkeypatch.setattr(stable_release, "latest_release", lambda *args: dict(target))

    stable_release.promote(
        REPO, "v1.0.0", COMMIT, manifest, MANIFEST_SHA256, RELEASE_FINGERPRINT
    )

    assert requests == [{"draft": False, "prerelease": False, "make_latest": "true"}]
    assert target["body"] == "Original release notes"


def test_older_stable_promotion_preserves_current_latest(tmp_path, monkeypatch):
    """Promote an older release while preserving GitHub Latest.

    Args:
        tmp_path: Directory for the signed manifest fixture.
        monkeypatch: Fixture for replacing signing and GitHub dependencies.
    """
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    (tmp_path / "release-manifest.json.sig").write_text("{}", encoding="utf-8")
    target = release("v1.0.0", 42, prerelease=True)
    current_latest = release("v1.2.0", 84, prerelease=False)
    requests = arrange_promotion(
        monkeypatch,
        target,
        [target, current_latest, release("v0.9.505", 1, prerelease=False)],
    )
    monkeypatch.setattr(stable_release, "latest_release", lambda *args: dict(current_latest))

    stable_release.promote(
        REPO, "v1.0.0", COMMIT, manifest, MANIFEST_SHA256, RELEASE_FINGERPRINT
    )

    assert requests == [{"draft": False, "prerelease": False, "make_latest": "false"}]
    assert target["body"] == "Original release notes"


def test_stable_release_metadata_promotion_is_idempotent(tmp_path, monkeypatch):
    """Accept a repeat request for the same stable release.

    Args:
        tmp_path: Directory for the signed manifest fixture.
        monkeypatch: Fixture for replacing signing and GitHub dependencies.
    """
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    (tmp_path / "release-manifest.json.sig").write_text("{}", encoding="utf-8")
    target = release("v1.0.0", 42, prerelease=False)
    requests = arrange_promotion(monkeypatch, target, [target])
    monkeypatch.setattr(stable_release, "latest_release", lambda *args: dict(target))

    stable_release.promote(
        REPO, "v1.0.0", COMMIT, manifest, MANIFEST_SHA256, RELEASE_FINGERPRINT
    )

    assert requests == [{"draft": False, "prerelease": False, "make_latest": "true"}]


def test_verify_only_revalidates_full_release_without_mutating_metadata(tmp_path, monkeypatch):
    """Bind physical evidence to current assets before a channel update.

    Args:
        tmp_path: Directory for the signed manifest fixture.
        monkeypatch: Fixture for replacing signing and GitHub dependencies.
    """
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    (tmp_path / "release-manifest.json.sig").write_text("{}", encoding="utf-8")
    target = release("v1.0.0", 42, prerelease=True)
    requests = arrange_promotion(monkeypatch, target, [release("v0.9.505", 1, prerelease=False)])

    stable_release.promote(
        REPO,
        "v1.0.0",
        COMMIT,
        manifest,
        MANIFEST_SHA256,
        RELEASE_FINGERPRINT,
        verify_only=True,
    )

    assert not requests


def test_release_fingerprint_mismatch_refuses_before_mutation(tmp_path, monkeypatch):
    """Reject a changed GitHub asset inventory before an edit.

    Args:
        tmp_path: Directory for the signed manifest fixture.
        monkeypatch: Fixture for replacing signing and GitHub dependencies.
    """
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    (tmp_path / "release-manifest.json.sig").write_text("{}", encoding="utf-8")
    target = release("v1.0.0", 42, prerelease=True)
    requests = arrange_promotion(monkeypatch, target, [])

    with pytest.raises(ValueError, match="fingerprint"):
        stable_release.promote(
            REPO,
            "v1.0.0",
            COMMIT,
            manifest,
            MANIFEST_SHA256,
            "d" * 64,
        )

    assert not requests
