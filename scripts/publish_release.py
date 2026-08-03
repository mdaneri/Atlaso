#!/usr/bin/env python3
"""Idempotently publish a versioned GitHub Release for one exact commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GIT_RELEASE_USER_NAME = "github-actions[bot]"
GIT_RELEASE_USER_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
MAXIMUM_GITHUB_ASSET_BYTES = 2_147_483_647
VMWARE_MANIFEST_PATTERN = re.compile(r"^SHA256\(([^/\\]+)\)= ([0-9a-f]{64})$")


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


def verify_vmware_release_assets(directory: Path, names: set[str]) -> None:
    manifests = sorted(name for name in names if name.lower().endswith(".mf"))
    descriptors = sorted(name for name in names if name.lower().endswith(".ovf"))
    disks = sorted(name for name in names if name.lower().endswith(".vmdk"))
    archives = sorted(name for name in names if name.lower().endswith(".ova"))
    allowed = set(manifests + descriptors + disks + archives)
    if names != allowed or len(manifests) != 1 or len(descriptors) != 1 or len(disks) != 2 or len(archives) > 1:
        raise SystemExit(f"release contains an invalid VMware appliance asset set: {sorted(names)}")

    for name in names:
        path = directory / name
        if not path.is_file() or path.stat().st_size > MAXIMUM_GITHUB_ASSET_BYTES:
            raise SystemExit(f"VMware release asset is missing or too large: {name}")

    expected_hashes: dict[str, str] = {}
    for line in (directory / manifests[0]).read_text(encoding="utf-8").splitlines():
        match = VMWARE_MANIFEST_PATTERN.fullmatch(line)
        if match is None or match.group(1) in expected_hashes:
            raise SystemExit(f"VMware release manifest contains an invalid entry: {line}")
        expected_hashes[match.group(1)] = match.group(2)
    payload_names = set(descriptors + disks)
    if set(expected_hashes) != payload_names:
        raise SystemExit("VMware release manifest does not cover the OVF descriptor and both payload VMDKs")
    mismatches = [name for name, expected in expected_hashes.items() if sha256(directory / name) != expected]
    if mismatches:
        raise SystemExit(f"VMware release assets failed manifest verification: {', '.join(sorted(mismatches))}")
    if archives:
        expected_members = set(manifests + descriptors + disks)
        try:
            with tarfile.open(directory / archives[0], mode="r:") as archive:
                members = [member for member in archive.getmembers() if member.isfile()]
                member_names = {member.name for member in members}
                if member_names != expected_members or len(members) != len(expected_members):
                    raise SystemExit("VMware OVA does not contain exactly the OVF package assets")
                for member in members:
                    stream = archive.extractfile(member)
                    digest = hashlib.sha256()
                    if stream is not None:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
                    if stream is None or digest.hexdigest() != sha256(directory / member.name):
                        raise SystemExit(f"VMware OVA contains different bytes for {member.name}")
        except tarfile.TarError as exc:
            raise SystemExit(f"VMware OVA is not a valid tar archive: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--assets", type=Path, required=True)
    args = parser.parse_args(argv)
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
                f"Atlaso {tag}",
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
        missing_names = expected_names - actual_names
        extra_names = actual_names - expected_names
        if missing_names:
            raise SystemExit(
                f"{tag} is missing expected assets: {sorted(missing_names)}; found {sorted(actual_names)}"
            )
        with tempfile.TemporaryDirectory(prefix="atlaso-release-verify-") as temp_value:
            temp = Path(temp_value)
            run(["gh", "release", "download", tag, "--dir", str(temp)])
            mismatches = [
                path.name
                for path in assets
                if not (temp / path.name).is_file() or sha256(path) != sha256(temp / path.name)
            ]
            if mismatches:
                raise SystemExit(f"{tag} already contains mismatched assets: {', '.join(mismatches)}")
            if extra_names:
                verify_vmware_release_assets(temp, extra_names)
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
            f"Atlaso {tag}",
            "--generate-notes",
            "--notes",
            f"Signed appliance release built from `{args.commit}`.",
        ]
    )
    print(json.dumps({"tag": tag, "commit": args.commit, "result": "published"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
