"""Exercise the combined release admission, approval, and recovery boundaries."""

import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts.installation import assets, combined_release, release_capture
from scripts.installation.manifest import digest, inventory

REPO = "mdaneri/Atlaso"
TAG = "v0.9.500"
COMMIT = "a" * 40
EVIDENCE = f"https://github.com/{REPO}/issues/542#issuecomment-123"


def write_software(directory, tag):
    """Stage the four named software files and the signed notice digest fixture."""
    version = tag[1:]
    notice = directory / f"atlaso-third-party-notices-{version}.md"
    notice.write_bytes(b"notices")
    manifest = directory / "release-manifest.json"
    manifest.write_text(
        json.dumps({"content_hashes": {"THIRD_PARTY_NOTICES.md": digest(notice)}})
    )
    for name in combined_release.software_names(tag) - {notice.name, manifest.name}:
        (directory / name).write_bytes(b"asset")
    return manifest


@pytest.mark.parametrize("split", [False, True])
def test_combined_release_verifies_the_exact_iso_and_software(
    tmp_path, monkeypatch, split
):
    directory = tmp_path / "release"
    directory.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    manifest = write_software(directory, TAG)
    monkeypatch.setattr(combined_release, "prepare", lambda **kwargs: {})
    iso = tmp_path / "atlaso-installation-0.9.500-x86_64.iso"
    iso.write_bytes(b"exact installer")
    if split:
        monkeypatch.setattr(assets, "GITHUB_ASSET_LIMIT", 8)
        monkeypatch.setattr(assets, "MAX_PART_BYTES", 6)
    index = {
        "asset_manifest": assets.split_iso(iso, directory, part_bytes=6),
        "verifier": {"name": "verify-installation.pyz"},
        "software_release_manifest_sha256": digest(manifest),
    }
    for name in (
        combined_release.INDEX,
        combined_release.INDEX + ".sig",
        "verify-installation.pyz",
    ):
        (directory / name).write_bytes(b"asset")
    monkeypatch.setattr(
        combined_release, "verify_release", lambda *args, **kwargs: index
    )
    assert combined_release.release_assets(directory, scratch, TAG, COMMIT) == digest(
        iso
    )
    assert not (scratch / iso.name).exists()

    index["software_release_manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="signed software binding"):
        combined_release.release_assets(directory, scratch, TAG, COMMIT)
    index["software_release_manifest_sha256"] = digest(manifest)
    index["asset_manifest"]["iso"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="reassembled ISO checksum"):
        combined_release.release_assets(directory, scratch, TAG, COMMIT)


def test_published_software_only_is_eligible_before_the_cutover(tmp_path, monkeypatch):
    monkeypatch.setattr(combined_release, "prepare", lambda **kwargs: {})
    write_software(tmp_path, "v0.9.499")
    assert (
        combined_release.release_assets(
            tmp_path, tmp_path, "v0.9.499", COMMIT, legacy=True
        )
        is None
    )
    other = tmp_path / "new"
    other.mkdir()
    write_software(other, TAG)
    with pytest.raises(ValueError, match="unexpected software-only"):
        combined_release.release_assets(other, other, TAG, COMMIT, legacy=True)


def test_partial_draft_stops_before_downloading_or_replacing_assets(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(combined_release, "require_tag", lambda *args: None)
    monkeypatch.setattr(
        combined_release,
        "asset_records",
        lambda *args: {name: {} for name in combined_release.software_names(TAG)},
    )
    with pytest.raises(ValueError, match="preserve it for reconciliation"):
        combined_release.download_and_verify(
            REPO,
            TAG,
            COMMIT,
            {"draft": True},
            tmp_path / "assets",
            tmp_path / "scratch",
            None,
        )
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    ("highest", "latest"), [((0, 9, 499), "true"), ((0, 9, 501), "false")]
)
def test_publish_checks_exact_approval_and_order_and_is_idempotent(
    monkeypatch, highest, latest
):
    iso = "b" * 64
    state = {
        "id": 42,
        "draft": True,
        "prerelease": False,
        "tag_name": TAG,
        "body": "Notes",
    }
    requests = []

    def gh(command, **kwargs):
        if command[-1].endswith("/issues/comments/123"):
            record = {
                "issue_url": f"https://api.github.com/repos/{REPO}/issues/542",
                "body": f"Accepted `{iso}`",
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(record), "")
        if "--method" in command:
            update = json.loads(kwargs["input_text"])
            requests.append(update)
            state.update(update)
        return subprocess.CompletedProcess(command, 0, json.dumps(state), "")

    monkeypatch.setattr(combined_release, "run", gh)
    monkeypatch.setattr(combined_release, "require_tag", lambda *args: None)
    monkeypatch.setattr(combined_release, "get_release", lambda *args: dict(state))
    monkeypatch.setattr(combined_release, "latest_version", lambda *args: highest)
    monkeypatch.setattr(combined_release, "asset_records", lambda *args: {})
    for invalid in ("", "f" * 64):
        with pytest.raises(ValueError, match="approval"):
            combined_release.publish(
                REPO, TAG, COMMIT, dict(state), {}, iso, invalid, EVIDENCE
            )
    with pytest.raises(ValueError, match="acceptance evidence"):
        combined_release.publish(
            REPO, TAG, COMMIT, dict(state), {}, iso, iso, "https://example.com"
        )
    assert not requests
    combined_release.publish(REPO, TAG, COMMIT, dict(state), {}, iso, iso, EVIDENCE)
    assert requests[0]["make_latest"] == latest
    assert EVIDENCE in requests[0]["body"]
    combined_release.publish(REPO, TAG, COMMIT, dict(state), {}, iso, iso, EVIDENCE)
    assert len(requests) == 1


def test_development_pointer_never_goes_backward_or_switches_commit(
    tmp_path, monkeypatch
):
    assert combined_release.channel_decision(tmp_path, TAG, COMMIT) == "advance"
    (tmp_path / "manifest.json").touch()
    (tmp_path / "manifest.json.sig").touch()
    monkeypatch.setattr(
        combined_release,
        "signature_document",
        lambda data: {"key_id": combined_release.TRUST_KEY.stem},
    )
    current = {"channel": "development", "version": "0.9.501", "git_commit": COMMIT}
    monkeypatch.setattr(
        combined_release, "verify_signed_json", lambda *args, **kwargs: current
    )
    assert combined_release.channel_decision(tmp_path, TAG, COMMIT) == "skip"
    current["version"] = "0.9.500"
    assert combined_release.channel_decision(tmp_path, TAG, COMMIT) == "verify"
    with pytest.raises(ValueError, match="conflicting commit"):
        combined_release.channel_decision(tmp_path, TAG, "b" * 40)


@pytest.mark.parametrize("compatibility", [True, False])
def test_admit_capture_rejects_incompatible_source_before_extraction(
    tmp_path, monkeypatch, compatibility
):
    capture = tmp_path / "original"
    capture.mkdir()
    for name in ("rpms", "powercli"):
        (capture / name).mkdir()
        (capture / name / "payload").write_text(name)
    fingerprint = "c" * 64
    metadata = {
        "schema": 1,
        "kind": "installation-refresh-capture",
        "repository": REPO,
        "source_commit": COMMIT,
        "source_input_sha256": fingerprint,
        "receipt_sha256": "d" * 64,
        "inventory": {name: inventory(capture / name) for name in ("rpms", "powercli")},
    }
    archive = tmp_path / "capture.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        raw = json.dumps(metadata).encode()
        document = tarfile.TarInfo("capture.json")
        document.size = len(raw)
        output.addfile(document, io.BytesIO(raw))
        for name in ("rpms", "powercli"):
            output.add(capture / name / "payload", arcname=f"{name}/payload")
    monkeypatch.setattr(
        release_capture,
        "source_input_sha256",
        lambda *args, **kwargs: fingerprint if compatibility else "e" * 64,
    )
    admitted = tmp_path / "admitted"
    if not compatibility:
        with pytest.raises(ValueError, match="source compatibility"):
            release_capture.admit(archive, admitted, Path.cwd(), REPO)
        assert not admitted.exists()
    else:
        release_capture.admit(archive, admitted, Path.cwd(), REPO)
        assert (admitted / "rpms/payload").read_text() == "rpms"


def test_evidence_must_bind_the_approved_digest_and_comment_parent(monkeypatch):
    record = {
        "issue_url": f"https://api.github.com/repos/{REPO}/issues/543",
        "body": "",
    }
    monkeypatch.setattr(
        combined_release,
        "run",
        lambda command: subprocess.CompletedProcess(command, 0, json.dumps(record), ""),
    )
    with pytest.raises(ValueError, match="does not belong"):
        combined_release.verify_acceptance(REPO, EVIDENCE, "b" * 64)
    record["issue_url"] = f"https://api.github.com/repos/{REPO}/issues/542"
    with pytest.raises(ValueError, match="does not identify"):
        combined_release.verify_acceptance(REPO, EVIDENCE, "b" * 64)


def test_portable_capture_fingerprint_preserves_existing_native_receipt_contract(
    tmp_path, monkeypatch
):
    from scripts.installation import build, refresh

    fingerprint_paths = [
        "image/common/powershell/powercli-lock.json",
        "image/common/scripts/configure_photon_repositories.py",
        "image/common/scripts/provision-atlaso.sh",
        "image/common/scripts/build-qemu-guest-agent-rpm.sh",
        "image/common/guest-agents/atlaso-qemu-guest-agent.spec",
        "image/common/guest-agents/qemu-guest-agent.service",
        "scripts/installation/guest_tools.py",
        "image/vmware-workstation/atlaso-photon.pkr.hcl",
        "image/common/photon-rpm-gpg/test.pub",
    ]
    monkeypatch.setattr(build, "package_selection", lambda _: ["kernel"])
    for name in fingerprint_paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"test\r\n")
    windows = refresh.source_input_sha256(tmp_path)
    portable = refresh.source_input_sha256(tmp_path, portable=True)
    assert windows != portable
    for name in fingerprint_paths:
        (tmp_path / name).write_bytes(b"test\n")
    assert refresh.source_input_sha256(tmp_path, portable=True) == portable
    assert refresh.source_input_sha256(tmp_path) == portable
