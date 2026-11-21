"""Verify exact GitHub Release metadata promotion and monotonic Latest handling."""

import json
import subprocess

from scripts.installation import promote_stable_release as stable_release

COMMIT = "a" * 40
MANIFEST_SHA256 = "b" * 64
REPO = "mdaneri/Atlaso"


def release(tag: str, release_id: int, *, prerelease: bool) -> dict:
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
    requests = []

    def run(command, *, check=True, input_text=None):
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
    monkeypatch.setattr(stable_release, "asset_records", lambda *args: {"release-manifest.json": (7, 1, f"sha256:{MANIFEST_SHA256}")})
    monkeypatch.setattr(stable_release, "release_list", lambda *args: published)
    monkeypatch.setattr(stable_release, "run", run)
    return requests


def test_promote_stable_advances_latest_to_the_highest_numeric_release(tmp_path, monkeypatch):
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    (tmp_path / "release-manifest.json.sig").write_text("{}", encoding="utf-8")
    target = release("v1.0.0", 42, prerelease=True)
    requests = arrange_promotion(monkeypatch, target, [release("v0.9.505", 1, prerelease=False), target])
    monkeypatch.setattr(stable_release, "latest_release", lambda *args: dict(target))

    stable_release.promote(REPO, "v1.0.0", COMMIT, manifest, MANIFEST_SHA256)

    assert requests == [{"draft": False, "prerelease": False, "make_latest": "true"}]
    assert target["body"] == "Original release notes"


def test_older_stable_promotion_preserves_current_latest(tmp_path, monkeypatch):
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

    stable_release.promote(REPO, "v1.0.0", COMMIT, manifest, MANIFEST_SHA256)

    assert requests == [{"draft": False, "prerelease": False, "make_latest": "false"}]
    assert target["body"] == "Original release notes"


def test_stable_release_metadata_promotion_is_idempotent(tmp_path, monkeypatch):
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    (tmp_path / "release-manifest.json.sig").write_text("{}", encoding="utf-8")
    target = release("v1.0.0", 42, prerelease=False)
    requests = arrange_promotion(monkeypatch, target, [target])
    monkeypatch.setattr(stable_release, "latest_release", lambda *args: dict(target))

    stable_release.promote(REPO, "v1.0.0", COMMIT, manifest, MANIFEST_SHA256)

    assert requests == [{"draft": False, "prerelease": False, "make_latest": "true"}]
