"""Promote an accepted GitHub prerelease to the stable classification."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

from atlaso.app.services.release_updates import verify_signed_json
from scripts.installation.combined_release import (
    TRUST_KEY,
    asset_records,
    get_release,
    release_fingerprint,
    require_tag,
    run,
    version_key,
)
from scripts.installation.manifest import digest

COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def release_list(repo: str) -> list[dict]:
    """Read all release pages without truncating the semantic version comparison.

    Args:
        repo: GitHub repository in owner/name form.
    """
    releases = []
    page = 1
    while True:
        result = json.loads(
            run(
                [
                    "gh",
                    "api",
                    f"repos/{repo}/releases?per_page=100&page={page}",
                ]
            ).stdout
        )
        if not isinstance(result, list) or len(result) > 100:
            raise ValueError("GitHub returned an invalid release page")
        releases.extend(result)
        if len(result) < 100:
            return releases
        page += 1
        if page > 101:
            raise ValueError("release history exceeds the bounded Latest comparison")


def latest_version(releases: list[dict]) -> tuple[int, int, int]:
    """Return the highest published stable semantic version.

    Args:
        releases: GitHub release records to compare.
    """
    versions = []
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = release.get("tag_name")
        if isinstance(tag, str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
            versions.append(version_key(tag))
    return max(versions, default=(0, 0, 0))


def latest_release(repo: str) -> dict:
    """Read GitHub's current Latest release and reject an absent or malformed result.

    Args:
        repo: GitHub repository in owner/name form.
    """
    result = json.loads(run(["gh", "api", f"repos/{repo}/releases/latest"]).stdout)
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("id"), int)
        or not isinstance(result.get("tag_name"), str)
        or result.get("draft") is not False
        or result.get("prerelease") is not False
    ):
        raise ValueError("GitHub did not return a published stable Latest release")
    return result


def promote(
    repo: str,
    tag: str,
    commit: str,
    manifest: Path,
    manifest_sha256: str,
    fingerprint: str,
    *,
    verify_only: bool = False,
) -> None:
    """Verify the accepted release fingerprint or promote it without replacing content.

    Args:
        repo: GitHub repository in owner/name form.
        tag: Exact software release tag.
        commit: Full SHA of the physically accepted release commit.
        manifest: Downloaded release manifest with its detached signature alongside it.
        manifest_sha256: Manifest digest verified during physical acceptance admission.
        fingerprint: GitHub release and asset fingerprint verified during admission.
        verify_only: Revalidate the release without changing its GitHub classification.
    """
    if (
        not COMMIT.fullmatch(commit)
        or not SHA256.fullmatch(manifest_sha256)
        or not SHA256.fullmatch(fingerprint)
    ):
        raise ValueError("stable release identity is malformed")
    if digest(manifest) != manifest_sha256:
        raise ValueError("signed release manifest differs from physical admission")
    signature = manifest.with_name("release-manifest.json.sig")
    verified = verify_signed_json(
        manifest.read_bytes(),
        signature.read_bytes(),
        trust_dir=TRUST_KEY.parent,
        document_kind="release",
    )
    if verified.get("version") != tag[1:] or verified.get("git_commit") != commit:
        raise ValueError("signed release manifest differs from the accepted tag identity")

    require_tag(tag, commit)
    release = get_release(repo, tag)
    if release is None or release["draft"]:
        raise ValueError("stable promotion requires the exact public release")
    if type(release["prerelease"]) is not bool:
        raise ValueError("GitHub release classification is invalid")
    original_assets = asset_records(release, tag)
    if not original_assets:
        raise ValueError("stable promotion requires the complete published asset set")
    if release_fingerprint(release, tag, original_assets) != fingerprint:
        raise ValueError("published release fingerprint differs from physical admission")
    manifest_asset = original_assets.get(manifest.name)
    if (
        manifest_asset is None
        or manifest_asset[1] != manifest.stat().st_size
        or manifest_asset[2] != f"sha256:{manifest_sha256}"
    ):
        raise ValueError("published release manifest differs from physical admission")
    if verify_only:
        return

    candidate = version_key(tag)
    highest = latest_version(release_list(repo))
    make_latest = candidate >= highest
    previous_latest = None if make_latest else latest_release(repo)
    if previous_latest is not None and version_key(previous_latest["tag_name"]) != highest:
        raise ValueError("GitHub Latest conflicts with the highest published stable version")

    run(
        [
            "gh",
            "api",
            "--method",
            "PATCH",
            f"repos/{repo}/releases/{release['id']}",
            "--input",
            "-",
        ],
        input_text=json.dumps(
            {
                "draft": False,
                "prerelease": False,
                "make_latest": str(make_latest).lower(),
            }
        ),
    )

    current = get_release(repo, tag)
    require_tag(tag, commit)
    if (
        current is None
        or current["id"] != release["id"]
        or current["tag_name"] != tag
        or current["draft"]
        or current["prerelease"]
        or asset_records(current, tag) != original_assets
        or current.get("name") != release.get("name")
        or current.get("body") != release.get("body")
        or current.get("target_commitish") != release.get("target_commitish")
    ):
        raise ValueError("stable release metadata or assets changed during promotion")
    if release_fingerprint(current, tag, asset_records(current, tag)) != fingerprint:
        raise ValueError("stable release fingerprint changed during promotion")
    live_manifest = next(
        (asset for asset in current["assets"] if asset["name"] == manifest.name), None
    )
    if live_manifest is None or live_manifest["digest"] != f"sha256:{manifest_sha256}":
        raise ValueError("published signed release manifest changed during promotion")

    if make_latest:
        live_latest = latest_release(repo)
        if live_latest["id"] != release["id"] or live_latest["tag_name"] != tag:
            raise ValueError("GitHub did not advance Latest to the highest stable version")
    else:
        live_latest = latest_release(repo)
        if (
            live_latest["id"] != previous_latest["id"]
            or live_latest["tag_name"] != previous_latest["tag_name"]
        ):
            raise ValueError("GitHub Latest changed during an older release promotion")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    promote(
        os.environ["GITHUB_REPOSITORY"],
        args.tag,
        args.commit,
        args.manifest,
        args.manifest_sha256,
        args.fingerprint,
        verify_only=args.verify_only,
    )


if __name__ == "__main__":
    main()
