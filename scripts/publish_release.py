#!/usr/bin/env python3
"""Idempotently publish a versioned GitHub Release for one exact commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GIT_RELEASE_USER_NAME = "github-actions[bot]"
GIT_RELEASE_USER_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"{command[0]} failed")
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def version() -> str:
    result = run(["python", "scripts/version.py", "get"])
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--assets", type=Path, required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.commit) is None:
        raise SystemExit("release commit must be a full lowercase hexadecimal commit")
    assets = sorted(path.resolve() for path in args.assets.iterdir() if path.is_file())
    if not assets:
        raise SystemExit("release assets directory is empty")
    tag = f"v{version()}"

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
                f"LabFoundry {tag}",
            ]
        )
        run(["git", "push", "origin", f"refs/tags/{tag}"])

    existing = run(["gh", "release", "view", tag, "--json", "tagName,targetCommitish,assets"], check=False)
    if existing.returncode == 0:
        release = json.loads(existing.stdout)
        if release.get("tagName") != tag:
            raise SystemExit(f"GitHub Release lookup returned the wrong tag for {tag}")
        expected_names = {path.name for path in assets}
        actual_names = {item["name"] for item in release.get("assets", [])}
        if actual_names != expected_names:
            raise SystemExit(
                f"{tag} already has different assets: expected {sorted(expected_names)}, found {sorted(actual_names)}"
            )
        with tempfile.TemporaryDirectory(prefix="labfoundry-release-verify-") as temp_value:
            temp = Path(temp_value)
            run(["gh", "release", "download", tag, "--dir", str(temp)])
            mismatches = [
                path.name
                for path in assets
                if not (temp / path.name).is_file() or sha256(path) != sha256(temp / path.name)
            ]
        if mismatches:
            raise SystemExit(f"{tag} already contains mismatched assets: {', '.join(mismatches)}")
        print(json.dumps({"tag": tag, "commit": args.commit, "result": "already-published"}, sort_keys=True))
        return 0

    run(
        [
            "gh",
            "release",
            "create",
            tag,
            *[str(path) for path in assets],
            "--verify-tag",
            "--title",
            f"LabFoundry {tag}",
            "--notes",
            f"Signed appliance release built from `{args.commit}`.",
        ]
    )
    print(json.dumps({"tag": tag, "commit": args.commit, "result": "published"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
