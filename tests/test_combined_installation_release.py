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
TAG = "v0.9.506"
COMMIT = "a" * 40
EVIDENCE = f"https://github.com/{REPO}/issues/542#issuecomment-123"


def write_software(directory, tag):
    """Stage the four named software files and the signed notice digest fixture.

    Args:
        directory: Directory to populate with fixture software assets.
        tag: Exact software release tag.
    """
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
    """Combined release verifies the exact iso and software.

    Args:
        tmp_path: Pytest fixture providing an isolated directory.
        monkeypatch: Pytest fixture for substituting external dependencies.
        split: Whether the fixture ISO spans multiple numbered parts.
    """
    directory = tmp_path / "release"
    directory.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    manifest = write_software(directory, TAG)
    monkeypatch.setattr(combined_release, "prepare", lambda **kwargs: {})
    iso = tmp_path / "atlaso-installation-0.9.506-x86_64.iso"
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
    """Published software only is eligible before the cutover.

    Args:
        tmp_path: Pytest fixture providing an isolated directory.
        monkeypatch: Pytest fixture for substituting external dependencies.
    """
    monkeypatch.setattr(combined_release, "prepare", lambda **kwargs: {})
    write_software(tmp_path, "v0.9.505")
    assert (
        combined_release.release_assets(
            tmp_path, tmp_path, "v0.9.505", COMMIT, legacy=True
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
    """Partial draft stops before downloading or replacing assets.

    Args:
        tmp_path: Pytest fixture providing an isolated directory.
        monkeypatch: Pytest fixture for substituting external dependencies.
    """
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
    ("tag", "commit", "allowed"),
    [
        ("v1.0.0", COMMIT, True),
        (*combined_release.EXISTING_INSTALLER, True),
        ("v0.9.517", COMMIT, False),
        ("v0.9.516", COMMIT, False),
    ],
)
def test_publication_requires_exact_vm_receipt_and_preserves_latest(
    tmp_path, monkeypatch, tag, commit, allowed
):
    """Publish the tested draft as a prerelease, without advancing Latest."""
    iso = (
        combined_release.EXISTING_INSTALLER_SHA256
        if (tag, commit) == combined_release.EXISTING_INSTALLER
        else "b" * 64
    )
    state = {
        "id": 42,
        "draft": True,
        "prerelease": False,
        "tag_name": tag,
        "body": "Notes",
    }
    requests = []

    def gh(command, **kwargs):
        if "--method" in command:
            update = json.loads(kwargs["input_text"])
            requests.append(update)
            state.update(update)
        return subprocess.CompletedProcess(command, 0, json.dumps(state), "")

    monkeypatch.setattr(combined_release, "run", gh)
    monkeypatch.setattr(combined_release, "require_tag", lambda *args: None)
    monkeypatch.setattr(combined_release, "get_release", lambda *args: dict(state))
    monkeypatch.setattr(combined_release, "asset_records", lambda *args: {})
    receipt = tmp_path / "receipt.json"
    outcome = {
        "schema": 1,
        "version": tag[1:],
        "commit": commit,
        "iso_sha256": iso,
        "checks": combined_release.VM_CHECKS,
    }
    for invalid in ({"iso_sha256": "f" * 64}, {"commit": "c" * 40}, {"checks": []}):
        receipt.write_text(json.dumps(outcome | invalid), encoding="utf-8")
        with pytest.raises(ValueError, match="receipt differs"):
            combined_release.publish(REPO, tag, commit, dict(state), {}, iso, receipt, "123", "1")
    with pytest.raises(ValueError, match="requires exact ISO VM acceptance"):
        combined_release.publish(REPO, tag, commit, dict(state), {}, iso, None, "123", "1")
    assert not requests
    receipt.write_text(json.dumps(outcome), encoding="utf-8")
    if (tag, commit) == combined_release.EXISTING_INSTALLER:
        with pytest.raises(ValueError, match="original signed ISO"):
            combined_release.publish(REPO, tag, commit, dict(state), {}, "f" * 64, receipt, "123", "1")
    if not allowed:
        with pytest.raises(ValueError, match="require version 1.0.0"):
            combined_release.publish(REPO, tag, commit, dict(state), {}, iso, receipt, "123", "1")
        assert not requests
        return
    combined_release.publish(REPO, tag, commit, dict(state), {}, iso, receipt, "123", "1")
    assert requests[0]["prerelease"] is True
    assert requests[0]["make_latest"] == "false"
    assert f"https://github.com/{REPO}/actions/runs/123/attempts/1" in requests[0]["body"]
    combined_release.publish(REPO, tag, commit, dict(state), {}, iso, receipt, "123", "2")
    assert len(requests) == 1


def test_development_pointer_never_goes_backward_or_switches_commit(
    tmp_path, monkeypatch
):
    """Development pointer never goes backward or switches commit.

    Args:
        tmp_path: Pytest fixture providing an isolated directory.
        monkeypatch: Pytest fixture for substituting external dependencies.
    """
    assert combined_release.channel_decision(tmp_path, TAG, COMMIT) == "advance"
    (tmp_path / "manifest.json").touch()
    (tmp_path / "manifest.json.sig").touch()
    monkeypatch.setattr(
        combined_release,
        "signature_document",
        lambda data: {"key_id": combined_release.TRUST_KEY.stem},
    )
    current = {"channel": "development", "version": "0.9.507", "git_commit": COMMIT}
    monkeypatch.setattr(
        combined_release, "verify_signed_json", lambda *args, **kwargs: current
    )
    assert combined_release.channel_decision(tmp_path, TAG, COMMIT) == "skip"
    current["version"] = "0.9.506"
    assert combined_release.channel_decision(tmp_path, TAG, COMMIT) == "verify"
    with pytest.raises(ValueError, match="conflicting commit"):
        combined_release.channel_decision(tmp_path, TAG, "b" * 40)


@pytest.mark.parametrize("compatibility", [True, False])
def test_admit_capture_rejects_incompatible_source_before_extraction(
    tmp_path, monkeypatch, compatibility
):
    """Admit capture rejects incompatible source before extraction.

    Args:
        tmp_path: Pytest fixture providing an isolated directory.
        monkeypatch: Pytest fixture for substituting external dependencies.
        compatibility: Whether the capture fingerprint matches the target source.
    """
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


def test_capture_archive_verification_uses_the_pinned_raw_bytes(tmp_path):
    """Reject a changed archive or invalid pin before archive admission.

    Args:
        tmp_path: Pytest fixture providing an isolated directory.
    """
    archive = tmp_path / "capture.tar.gz"
    archive.write_bytes(b"verified capture")
    expected = release_capture.digest(archive)
    release_capture.verify_archive(archive, expected)
    with pytest.raises(ValueError, match="protected pin is invalid"):
        release_capture.verify_archive(archive, f"sha256:{expected}")
    archive.write_bytes(b"changed capture")
    with pytest.raises(ValueError, match="SHA-256 differs"):
        release_capture.verify_archive(archive, expected)


def test_evidence_must_bind_the_approved_digest_and_comment_parent(monkeypatch):
    """Evidence must bind the approved digest and comment parent.

    Args:
        monkeypatch: Pytest fixture for substituting external dependencies.
    """
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


def test_physical_acceptance_requires_a_current_maintainer(monkeypatch):
    iso = "b" * 64
    record = {
        "issue_url": f"https://api.github.com/repos/{REPO}/issues/542",
        "body": f"Representative physical acceptance: PASS\n\nISO SHA-256 `{iso}`",
        "user": {"login": "atlaso-maintainer"},
    }
    permission = {"role_name": "write"}

    def gh(command):
        value = permission if command[-1].endswith("/permission") else record
        return subprocess.CompletedProcess(command, 0, json.dumps(value), "")

    monkeypatch.setattr(combined_release, "run", gh)
    with pytest.raises(ValueError, match="current Atlaso maintainer"):
        combined_release.verify_acceptance(REPO, EVIDENCE, iso, physical=True)
    permission["role_name"] = "maintain"
    combined_release.verify_acceptance(REPO, EVIDENCE, iso, physical=True)
    record["body"] = f"VM acceptance passed for `{iso}`"
    with pytest.raises(ValueError, match="explicit physical acceptance"):
        combined_release.verify_acceptance(REPO, EVIDENCE, iso, physical=True)


def test_portable_capture_fingerprint_preserves_existing_native_receipt_contract(
    tmp_path, monkeypatch
):
    """Portable capture fingerprint preserves existing native receipt contract.

    Args:
        tmp_path: Pytest fixture providing an isolated directory.
        monkeypatch: Pytest fixture for substituting external dependencies.
    """
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
