"""Stage and publish a combined Atlaso software and installation release."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path

from atlaso.app.services.release_updates import signature_document, verify_signed_json
from scripts.installation.assets import verify_and_reassemble
from scripts.installation.manifest import KEY_ID, digest
from scripts.prepare_virtualization_source import prepare
from scripts.publish_release import run
from scripts.verify_installation_iso import verify_release

FIRST_INSTALLATION_VERSION = (0, 9, 501)
VERSION = re.compile(r"v([0-9]+)\.([0-9]+)\.([0-9]+)")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
INDEX = "installation-artifact-index.json"
TRUST_KEY = (
    Path(__file__).resolve().parents[2] / f"image/common/update-trust/{KEY_ID}.pem"
)


def version_key(tag: str) -> tuple[int, ...]:
    """Read a canonical software release version for numeric comparisons."""
    match = VERSION.fullmatch(tag)
    if not match:
        raise ValueError("expected a software release tag vX.Y.Z")
    return tuple(map(int, match.groups()))


def software_names(tag: str) -> set[str]:
    """Return the signed software bundle and its three companion assets."""
    version = tag[1:]
    return {
        f"atlaso-appliance-{version}.tar.gz",
        f"atlaso-third-party-notices-{version}.md",
        "release-manifest.json",
        "release-manifest.json.sig",
    }


def release_assets(
    directory: Path,
    scratch: Path,
    tag: str,
    commit: str,
    *,
    legacy: bool = False,
    selected_wheel: Path | None = None,
) -> str | None:
    """Authenticate the complete release and return the checksum of the exact ISO."""
    version = tag[1:]
    names = {path.name for path in directory.iterdir()}
    expected = software_names(tag)
    if not expected <= names:
        raise ValueError("release is missing signed software assets")
    software = prepare(
        manifest_path=directory / "release-manifest.json",
        signature_path=directory / "release-manifest.json.sig",
        bundle_path=directory / f"atlaso-appliance-{version}.tar.gz",
        trust_key_path=TRUST_KEY,
        output=scratch / "software",
        expected_version=version,
        expected_commit=commit,
    )
    manifest_path = directory / "release-manifest.json"
    notice_hash = json.loads(manifest_path.read_bytes())["content_hashes"][
        "THIRD_PARTY_NOTICES.md"
    ]
    if digest(directory / f"atlaso-third-party-notices-{version}.md") != notice_hash:
        raise ValueError("release notice differs from the signed bundle")
    if (
        selected_wheel is not None
        and digest(selected_wheel) != software["application_wheel_sha256"]
    ):
        raise ValueError("selected wheel differs from the signed bundle")
    if legacy:
        if names != expected or version_key(tag) >= FIRST_INSTALLATION_VERSION:
            raise ValueError("unexpected software-only release assets")
        return None
    index = verify_release(
        directory, TRUST_KEY, scratch, version=version, commit=commit
    )
    iso = index["asset_manifest"]["iso"]
    expected |= {INDEX, INDEX + ".sig", index["verifier"]["name"]}
    expected |= {item["name"] for item in index["asset_manifest"]["assets"]}
    if (
        names != expected
        or iso["name"] != f"atlaso-installation-{version}-x86_64.iso"
        or index.get("software_release_manifest_sha256") != digest(manifest_path)
    ):
        raise ValueError("installation assets or their signed software binding differ")
    # Read the complete concatenation even when the assets have valid individual
    # digests. A signed part order must also produce the declared complete ISO.
    assembled = scratch / iso["name"]
    verify_and_reassemble(index["asset_manifest"], directory, assembled)
    assembled.unlink()
    return iso["sha256"]


def get_release(repo: str, tag: str) -> dict | None:
    """Find an exact draft or public release without treating API errors as absence."""
    owner, name = repo.split("/")
    query = """query($owner:String!,$name:String!,$tag:String!){
      repository(owner:$owner,name:$name){release(tagName:$tag){databaseId}}
    }"""
    repository = json.loads(
        run(
            [
                "gh",
                "api",
                "graphql",
                "-f",
                f"query={query}",
                "-f",
                f"owner={owner}",
                "-f",
                f"name={name}",
                "-f",
                f"tag={tag}",
            ]
        ).stdout
    )["data"]["repository"]
    if repository is None:
        raise ValueError("cannot resolve the release repository")
    selected = repository["release"]
    if selected is None:
        return None
    release = json.loads(
        run(["gh", "api", f"repos/{repo}/releases/{selected['databaseId']}"]).stdout
    )
    if release["tag_name"] != tag or release["prerelease"] is not False:
        raise ValueError("unexpected GitHub release identity or classification")
    return release


def asset_records(release: dict, tag: str) -> dict:
    """Admit safe, unique GitHub asset names and their uploaded digests."""
    allowed = software_names(tag) | {INDEX, INDEX + ".sig", "verify-installation.pyz"}
    iso_pattern = re.compile(
        rf"atlaso-installation-{re.escape(tag[1:])}-x86_64\.iso(?:\.part[0-9]{{4}})?"
    )
    records = {}
    for asset in release["assets"]:
        name = asset["name"]
        if (
            (name not in allowed and not iso_pattern.fullmatch(name))
            or name in records
            or asset["state"] != "uploaded"
            or not 0 < asset["size"] < 2 * 1024**3
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest") or "")
        ):
            raise ValueError("release contains an unexpected or incomplete asset")
        records[name] = (asset["id"], asset["size"], asset["digest"])
    return records


def require_tag(tag: str, commit: str, *, create: bool = False) -> None:
    """Require an exact tag target and create an annotated tag only for a new draft."""
    ref = f"refs/tags/{tag}"
    remote = run(["git", "ls-remote", "--tags", "origin", ref, ref + "^{}"]).stdout
    refs = dict(reversed(line.split()) for line in remote.splitlines())
    target = refs.get(ref + "^{}", refs.get(ref))
    if target is None and create:
        run(
            [
                "git",
                "-c",
                "user.name=github-actions[bot]",
                "-c",
                "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                "tag",
                "-a",
                tag,
                commit,
                "-m",
                f"Atlaso {tag}",
            ]
        )
        run(["git", "push", "origin", ref])
        require_tag(tag, commit)
    elif target != commit:
        raise ValueError("release tag is absent or points to a different commit")


def download_and_verify(
    repo: str,
    tag: str,
    commit: str,
    release: dict,
    directory: Path,
    scratch: Path,
    wheel: Path | None,
) -> tuple[dict, str | None]:
    """Download one exact asset set and verify both the installer and software."""
    require_tag(tag, commit)
    records = asset_records(release, tag)
    legacy = (
        not release["draft"]
        and set(records) == software_names(tag)
        and version_key(tag) < FIRST_INSTALLATION_VERSION
    )
    if not software_names(tag) <= records.keys() or (
        not legacy and INDEX not in records
    ):
        raise ValueError("release is incomplete; preserve it for reconciliation")
    if (
        shutil.disk_usage(directory.parent).free
        < 2 * sum(record[1] for record in records.values()) + 2 * 1024**3
    ):
        raise ValueError("insufficient free space to verify the complete release")
    directory.mkdir()
    scratch.mkdir()
    run(["gh", "release", "download", tag, "--repo", repo, "--dir", str(directory)])
    require_remote_bytes(records, directory)
    iso = release_assets(
        directory, scratch, tag, commit, legacy=legacy, selected_wheel=wheel
    )
    return records, iso


def require_remote_bytes(records: dict, directory: Path) -> None:
    """Compare the GitHub asset digest and size to every downloaded or staged file."""
    if set(records) != {path.name for path in directory.iterdir()}:
        raise ValueError("release asset inventory differs")
    for name, (_, size, checksum) in records.items():
        path = directory / name
        if path.stat().st_size != size or f"sha256:{digest(path)}" != checksum:
            raise ValueError(f"GitHub release asset bytes differ for {name}")


def stage(repo: str, tag: str, commit: str, directory: Path, scratch: Path) -> str:
    """Create a single complete hidden draft and verify the uploaded asset set."""
    if get_release(repo, tag) is not None:
        raise ValueError("release already exists; preserve it and retry verification")
    scratch.mkdir()
    iso = release_assets(directory, scratch, tag, commit)
    assert iso is not None
    summary = os.getenv("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as journal:
            journal.write(f"## Verified release assets for {tag} ({commit})\n\n")
            journal.write(f"Complete ISO SHA-256: {iso}\n\n")
            journal.write("| Asset | Bytes | SHA-256 |\n| --- | ---: | --- |\n")
            for path in sorted(directory.iterdir()):
                journal.write(
                    f"| {path.name} | {path.stat().st_size} | {digest(path)} |\n"
                )
    require_tag(tag, commit, create=True)
    run(
        [
            "gh",
            "release",
            "create",
            tag,
            *map(str, sorted(directory.iterdir())),
            "--repo",
            repo,
            "--draft",
            "--verify-tag",
            "--title",
            f"Atlaso {tag}",
            "--generate-notes",
            "--notes",
            f"Signed Atlaso software and offline x86-64 UEFI installer from `{commit}`. "
            "Secure Boot must be disabled. OVA and Hyper-V images have their own releases.",
        ]
    )
    release = get_release(repo, tag)
    if release is None or not release["draft"]:
        raise ValueError("GitHub did not retain the combined release as a draft")
    require_remote_bytes(asset_records(release, tag), directory)
    return iso


def latest_version(repo: str) -> tuple[int, ...]:
    """Read the highest published software version across all release pages."""
    tags = run(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/{repo}/releases?per_page=100",
            "--jq",
            ".[] | select(.draft == false and .prerelease == false) | .tag_name",
        ]
    ).stdout.splitlines()
    return max(
        (version_key(tag) for tag in tags if VERSION.fullmatch(tag)), default=(0, 0, 0)
    )


def verify_acceptance(repo: str, evidence: str, iso: str) -> None:
    """Require a same-repository acceptance record that names the approved digest."""
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(repo)}/(issues|pull)/([1-9][0-9]*)(?:#issuecomment-([1-9][0-9]*))?",
        evidence,
    )
    if not match:
        raise ValueError(
            "approval must reference acceptance evidence on a repository issue or pull request"
        )
    section, number, comment = match.groups()
    resource = f"repos/{repo}/issues/{number}"
    if comment:
        record = json.loads(
            run(["gh", "api", f"repos/{repo}/issues/comments/{comment}"]).stdout
        )
        if record["issue_url"] != f"https://api.github.com/{resource}":
            raise ValueError(
                "acceptance comment does not belong to the referenced issue or pull request"
            )
    else:
        endpoint = f"repos/{repo}/pulls/{number}" if section == "pull" else resource
        record = json.loads(run(["gh", "api", endpoint]).stdout)
    if not re.search(
        rf"(?<![0-9a-fA-F]){iso}(?![0-9a-fA-F])", record.get("body") or ""
    ):
        raise ValueError("acceptance evidence does not identify the approved SHA-256")


def publish(
    repo: str,
    tag: str,
    commit: str,
    release: dict,
    records: dict,
    iso: str | None,
    approved: str,
    evidence: str,
) -> None:
    """Publish an approved draft once and verify that GitHub serves the same assets."""
    if approved:
        if iso != approved or not SHA256.fullmatch(approved):
            raise ValueError(
                "maintainer approval does not match the verified ISO SHA-256"
            )
        verify_acceptance(repo, evidence, approved)
    elif release["draft"] or iso is not None:
        raise ValueError("combined release publication requires exact ISO approval")

    require_tag(tag, commit)
    current = get_release(repo, tag)
    if (
        current is None
        or current["id"] != release["id"]
        or current["draft"] != release["draft"]
        or asset_records(current, tag) != records
    ):
        raise ValueError("release state changed during verification")
    if current["draft"]:
        make_latest = version_key(tag) > latest_version(repo)
        body = (current["body"] or "") + (
            f"\n\nValidated installer SHA-256: `{iso}`\n\n"
            f"Installation acceptance evidence: {evidence}\n"
        )
        request = json.dumps(
            {"draft": False, "make_latest": str(make_latest).lower(), "body": body}
        )
        run(
            [
                "gh",
                "api",
                "--method",
                "PATCH",
                f"repos/{repo}/releases/{current['id']}",
                "--input",
                "-",
            ],
            input_text=request,
        )
    live = json.loads(run(["gh", "api", f"repos/{repo}/releases/tags/{tag}"]).stdout)
    require_tag(tag, commit)
    if (
        live["id"] != release["id"]
        or live["tag_name"] != tag
        or live["draft"]
        or live["prerelease"]
        or asset_records(live, tag) != records
    ):
        raise ValueError("published release differs from the verified release")


def channel_decision(directory: Path, tag: str, commit: str) -> str:
    """Authenticate the current development pointer and compare exact identities."""
    manifest = directory / "manifest.json"
    signature = directory / "manifest.json.sig"
    if not manifest.exists() and not signature.exists():
        return "advance"
    raw_signature = signature.read_bytes()
    if signature_document(raw_signature)["key_id"] != TRUST_KEY.stem:
        raise ValueError("existing development pointer uses a different trust key")
    current = verify_signed_json(
        manifest.read_bytes(),
        raw_signature,
        trust_dir=TRUST_KEY.parent,
        document_kind="channel",
    )
    if current["channel"] != "development":
        raise ValueError("existing development pointer names a different channel")
    candidate, active = version_key(tag), version_key("v" + current["version"])
    if candidate < active:
        return "skip"
    if candidate == active:
        if current["git_commit"] != commit:
            raise ValueError(
                "the development pointer has a conflicting commit for this version"
            )
        return "verify"
    return "advance"


def main() -> None:
    """Operate only on an admitted exact software commit in the protected workflow."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation", choices=("state", "stage", "verify", "publish", "channel")
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--wheel", type=Path)
    args = parser.parse_args()
    version = version_key(args.tag)
    if not COMMIT.fullmatch(args.commit):
        parser.error("commit must be an exact full SHA")
    if args.operation == "channel":
        if args.assets is None:
            parser.error("development pointer directory is required")
        print(channel_decision(args.assets, args.tag, args.commit))
        return
    repo = os.environ["GITHUB_REPOSITORY"]
    if args.operation == "state":
        release = get_release(repo, args.tag)
        if release is None and version < FIRST_INSTALLATION_VERSION:
            raise ValueError(
                "historical versions are eligible for recovery of existing releases only"
            )
        print(
            "absent"
            if release is None
            else "draft"
            if release["draft"]
            else "published"
        )
        return
    if args.assets is None or args.scratch is None:
        parser.error("assets and scratch paths are required")
    if args.operation == "stage":
        iso = stage(repo, args.tag, args.commit, args.assets, args.scratch)
    else:
        release = get_release(repo, args.tag)
        if release is None:
            raise ValueError("expected an existing GitHub Release")
        records, iso = download_and_verify(
            repo, args.tag, args.commit, release, args.assets, args.scratch, args.wheel
        )
        if args.operation == "publish":
            publish(
                repo,
                args.tag,
                args.commit,
                release,
                records,
                iso,
                os.getenv("VALIDATED_ISO_SHA256", ""),
                os.getenv("INSTALLATION_ACCEPTANCE_EVIDENCE", ""),
            )
    print(iso or "legacy")


if __name__ == "__main__":
    main()
