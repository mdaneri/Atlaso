"""Stage and publish a combined Atlaso software and installation release."""

from __future__ import annotations

import argparse
import hashlib
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

FIRST_INSTALLATION_VERSION = (0, 9, 506)
FIRST_PRERELEASE_VERSION = (0, 9, 517)
EXISTING_INSTALLER = ("v0.9.516", "623e6c40069062c2a2e8a0f11a1e9f9897dc5526")
EXISTING_INSTALLER_SHA256 = "b6bfcb1a7af1beaf9d3eb00e71cddc3ab692f0dbcf6a5f0c74d7fb0b8d27bef3"
VERSION = re.compile(r"v([0-9]+)\.([0-9]+)\.([0-9]+)")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
INDEX = "installation-artifact-index.json"
TRUST_KEY = (
    Path(__file__).resolve().parents[2] / f"image/common/update-trust/{KEY_ID}.pem"
)
VM_CHECKS = [
    "disconnected_uefi_install",
    "selected_64g_target",
    "media_free_boot",
    "atlaso_services_active",
    "installed_application_version",
    "installed_application_commit",
    "unselected_4g_disk_unchanged",
]


def version_key(tag: str) -> tuple[int, ...]:
    """Read a canonical software release version for numeric comparisons.

    Args:
        tag: Exact software release tag.
    """
    match = VERSION.fullmatch(tag)
    if not match:
        raise ValueError("expected a software release tag vX.Y.Z")
    return tuple(map(int, match.groups()))


def software_names(tag: str) -> set[str]:
    """Return the signed software bundle and its three companion assets.

    Args:
        tag: Exact software release tag.
    """
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
    """Authenticate the complete release and return the checksum of the exact ISO.

    Args:
        directory: Directory containing the complete asset set.
        scratch: Private scratch directory for extraction and verification.
        tag: Exact software release tag.
        commit: Full SHA of the admitted release commit.
        legacy: Whether to verify a historical software-only release.
        selected_wheel: Optional admitted application wheel to compare against the signed bundle.
    """
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
    """Find an exact draft or public release without treating API errors as absence.

    Args:
        repo: GitHub repository in owner/name form.
        tag: Exact software release tag.
    """
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
    if release["tag_name"] != tag or type(release["prerelease"]) is not bool:
        raise ValueError("unexpected GitHub release identity or classification")
    return release


def asset_records(release: dict, tag: str) -> dict:
    """Admit safe, unique GitHub asset names and their uploaded digests.

    Args:
        release: GitHub's metadata for the selected release.
        tag: Exact software release tag.
    """
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
    """Require an exact tag target and create an annotated tag only for a new draft.

    Args:
        tag: Exact software release tag.
        commit: Full SHA of the admitted release commit.
        create: Whether an absent release tag may be created.
    """
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
    """Download one exact asset set and verify both the installer and software.

    Args:
        repo: GitHub repository in owner/name form.
        tag: Exact software release tag.
        commit: Full SHA of the admitted release commit.
        release: GitHub's metadata for the selected release.
        directory: Absent destination for downloaded release assets.
        scratch: Absent destination for temporary verification data.
        wheel: Optional admitted application wheel to compare against the signed bundle.
    """
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
    """Compare the GitHub asset digest and size to every downloaded or staged file.

    Args:
        records: Expected GitHub asset IDs, sizes, and digests by filename.
        directory: Directory containing the complete asset set.
    """
    if set(records) != {path.name for path in directory.iterdir()}:
        raise ValueError("release asset inventory differs")
    for name, (_, size, checksum) in records.items():
        path = directory / name
        if path.stat().st_size != size or f"sha256:{digest(path)}" != checksum:
            raise ValueError(f"GitHub release asset bytes differ for {name}")


def release_fingerprint(release: dict, tag: str, records: dict) -> str:
    """Bind approval to the exact GitHub release and all asset identities.

    Args:
        release: GitHub metadata for the exact release.
        tag: Verified release tag.
        records: Asset IDs, sizes, and digests by filename.
    """
    identity = {"id": release["id"], "tag": tag, "assets": records}
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def stage(repo: str, tag: str, commit: str, directory: Path, scratch: Path) -> str:
    """Create a single complete hidden draft and verify the uploaded asset set.

    Args:
        repo: GitHub repository in owner/name form.
        tag: Exact software release tag.
        commit: Full SHA of the admitted release commit.
        directory: Directory containing the complete asset set.
        scratch: Absent destination for temporary verification data.
    """
    if get_release(repo, tag) is not None:
        raise ValueError("release already exists; preserve it and retry verification")
    if version_key(tag) < FIRST_PRERELEASE_VERSION:
        raise ValueError("new installer releases require version 0.9.517 or later")
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
            "--prerelease",
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


def verify_acceptance(repo: str, evidence: str, iso: str, *, physical: bool = False) -> None:
    """Require a same-repository acceptance record that names the approved digest.

    Args:
        repo: GitHub repository in owner/name form.
        evidence: GitHub issue, pull request, or comment URL recording media acceptance.
        iso: Verified SHA-256 of the complete installer ISO.
        physical: Require a physical acceptance comment from a current maintainer.
    """
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
    body = record.get("body") or ""
    if not re.search(rf"(?<![0-9a-fA-F]){iso}(?![0-9a-fA-F])", body):
        raise ValueError("acceptance evidence does not identify the approved SHA-256")
    if physical:
        if not comment or not re.search(r"^Representative physical acceptance: PASS\s*$", body, re.M):
            raise ValueError("stable promotion requires an explicit physical acceptance comment")
        login = record["user"]["login"]
        if not re.fullmatch(r"[A-Za-z0-9-]+", login):
            raise ValueError("physical acceptance author is not a GitHub user")
        permission = json.loads(
            run(["gh", "api", f"repos/{repo}/collaborators/{login}/permission"]).stdout
        )
        if permission["role_name"] not in {"admin", "maintain"}:
            raise ValueError("physical acceptance requires a current Atlaso maintainer")


def verify_vm_receipt(receipt: Path, tag: str, commit: str, iso: str) -> None:
    """Match the successful test job's exact installer identity and checkpoints.

    Args:
        receipt: JSON evidence from the successful VM acceptance job.
        tag: Verified release tag, including the leading v.
        commit: Full SHA of the release source commit.
        iso: SHA-256 of the reconstructed installer ISO.
    """
    if receipt.stat().st_size > 8192:
        raise ValueError("VM acceptance receipt exceeds its size bound")
    record = json.loads(receipt.read_bytes())
    if record != {
        "schema": 1,
        "version": tag[1:],
        "commit": commit,
        "iso_sha256": iso,
        "checks": VM_CHECKS,
    }:
        raise ValueError("VM acceptance receipt differs from the verified release")


def publish(
    repo: str,
    tag: str,
    commit: str,
    release: dict,
    records: dict,
    iso: str | None,
    acceptance: Path | None,
    run_id: str,
    run_attempt: str,
) -> None:
    """Publish an approved draft once and verify that GitHub serves the same assets.

    Args:
        repo: GitHub repository in owner/name form.
        tag: Exact software release tag.
        commit: Full SHA of the admitted release commit.
        release: GitHub's metadata for the selected release.
        records: Expected GitHub asset IDs, sizes, and digests by filename.
        iso: Verified SHA-256 of the complete installer ISO.
        acceptance: Receipt downloaded from the successful acceptance job in this run.
        run_id: GitHub Actions workflow run that executed the VM acceptance.
        run_attempt: Exact attempt that uploaded the receipt.
    """
    if iso is not None:
        if (tag, commit) == EXISTING_INSTALLER and iso != EXISTING_INSTALLER_SHA256:
            raise ValueError("v0.9.516 must retain the original signed ISO SHA-256")
        if (
            acceptance is None
            or not SHA256.fullmatch(iso)
            or not re.fullmatch(r"[1-9][0-9]*", run_id)
            or not re.fullmatch(r"[1-9][0-9]*", run_attempt)
        ):
            raise ValueError("publication requires exact ISO VM acceptance")
        verify_vm_receipt(acceptance, tag, commit, iso)
    elif release["draft"] or release["prerelease"]:
        raise ValueError("only an existing stable software-only release may be recovered")

    require_tag(tag, commit)
    current = get_release(repo, tag)
    if (
        current is None
        or current["id"] != release["id"]
        or current["draft"] != release["draft"]
        or current["prerelease"] != release["prerelease"]
        or asset_records(current, tag) != records
    ):
        raise ValueError("release state changed during verification")
    if current["draft"]:
        if version_key(tag) < FIRST_PRERELEASE_VERSION and (tag, commit) != EXISTING_INSTALLER:
            raise ValueError("this historical installer cannot be newly published")
        evidence = f"https://github.com/{repo}/actions/runs/{run_id}/attempts/{run_attempt}"
        body = (current["body"] or "") + (
            f"\n\nValidated installer SHA-256: `{iso}`\n\n"
            f"Automated VM acceptance: {evidence}\n"
        )
        request = json.dumps(
            {"draft": False, "prerelease": True, "make_latest": "false", "body": body}
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
        or live["prerelease"] != (current["draft"] or current["prerelease"])
        or asset_records(live, tag) != records
    ):
        raise ValueError("published release differs from the verified release")


def channel_decision(directory: Path, tag: str, commit: str) -> str:
    """Authenticate the current development pointer and compare exact identities.

    Args:
        directory: Directory containing the signed development pointer.
        tag: Exact software release tag.
        commit: Full SHA of the admitted release commit.
    """
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
        "operation",
        choices=("state", "stage", "verify", "iso-assets", "publish", "physical", "channel"),
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--vm-acceptance", type=Path)
    parser.add_argument("--release-fingerprint", type=Path)
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
    if args.operation == "iso-assets":
        release = get_release(repo, args.tag)
        if release is None:
            raise ValueError("ISO acceptance requires an existing release")
        require_tag(args.tag, args.commit)
        records = asset_records(release, args.tag)
        required = {INDEX, INDEX + ".sig", "verify-installation.pyz"}
        installer = records.keys() - software_names(args.tag)
        if not required < installer:
            raise ValueError("ISO acceptance requires a complete staged installer")
        print(json.dumps([
            {"id": records[name][0], "name": name, "size": records[name][1]}
            for name in sorted(installer)
        ], separators=(",", ":")))
        return
    if args.operation == "state":
        release = get_release(repo, args.tag)
        if release is None and version < FIRST_PRERELEASE_VERSION:
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
        if args.operation == "physical" and release["draft"]:
            raise ValueError("stable promotion requires a public release")
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
                args.vm_acceptance,
                os.getenv("GITHUB_RUN_ID", ""),
                os.getenv("GITHUB_RUN_ATTEMPT", ""),
            )
        if args.operation == "physical" and iso is not None:
            verify_acceptance(repo, os.getenv("INSTALLATION_ACCEPTANCE_EVIDENCE", ""), iso, physical=True)
            if args.release_fingerprint is not None:
                live = get_release(repo, args.tag)
                require_tag(args.tag, args.commit)
                if live is None or live["draft"] or live["id"] != release["id"] or asset_records(live, args.tag) != records:
                    raise ValueError("release assets changed during physical acceptance verification")
                with args.release_fingerprint.open("x", encoding="ascii") as stream:
                    stream.write(release_fingerprint(live, args.tag, records) + "\n")
    print(iso or "legacy")


if __name__ == "__main__":
    main()
