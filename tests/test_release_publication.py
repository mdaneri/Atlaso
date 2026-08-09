"""Test release publication behavior."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_script(module_name: str, filename: str):
    """Return script."""
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "scripts" / filename)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


publish_release = load_script("publish_release_script", "publish_release.py")
backfill_release_notes = load_script("backfill_release_notes_script", "backfill_release_notes.py")


def completed(
    command: list[str],
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    """Return completed."""
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def write_valid_vmware_ovf(path: Path, os_disk: str, tools_disk: str) -> None:
    """Persist valid vmware ovf.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        os_disk: Os disk supplied by the caller.
        tools_disk: Tools disk supplied by the caller.
    """
    path.write_text(
        f"""<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData">
  <References>
    <File ovf:id="file1" ovf:href="{os_disk}"/>
    <File ovf:id="file2" ovf:href="{tools_disk}"/>
  </References>
  <DiskSection>
    <Disk ovf:diskId="os" ovf:fileRef="file1" ovf:format="vmdk"/>
    <Disk ovf:diskId="tools" ovf:fileRef="file2" ovf:format="vmdk"/>
    <Disk ovf:diskId="atlaso-depot" ovf:capacity="500" ovf:capacityAllocationUnits="byte * 2^30" ovf:format="vmdk"/>
    <Disk ovf:diskId="atlaso-backups" ovf:capacity="500" ovf:capacityAllocationUnits="byte * 2^30" ovf:format="vmdk"/>
  </DiskSection>
  <VirtualSystem ovf:id="atlaso">
    <VirtualHardwareSection>
      <Item><rasd:ResourceType>17</rasd:ResourceType><rasd:AddressOnParent>0</rasd:AddressOnParent><rasd:HostResource>ovf:/disk/os</rasd:HostResource><rasd:ElementName>Hard disk 1 - Photon OS</rasd:ElementName></Item>
      <Item><rasd:ResourceType>17</rasd:ResourceType><rasd:AddressOnParent>1</rasd:AddressOnParent><rasd:HostResource>ovf:/disk/tools</rasd:HostResource><rasd:ElementName>Hard disk 2 - Atlaso System Content</rasd:ElementName></Item>
      <Item><rasd:ResourceType>17</rasd:ResourceType><rasd:AddressOnParent>2</rasd:AddressOnParent><rasd:HostResource>ovf:/disk/atlaso-depot</rasd:HostResource><rasd:ElementName>Hard disk 3 - VCF Offline Depot</rasd:ElementName></Item>
      <Item><rasd:ResourceType>17</rasd:ResourceType><rasd:AddressOnParent>3</rasd:AddressOnParent><rasd:HostResource>ovf:/disk/atlaso-backups</rasd:HostResource><rasd:ElementName>Hard disk 4 - VCF Backups</rasd:ElementName></Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
""",
        encoding="utf-8",
    )


def release_fixture(
    tag: str,
    commit: str,
    *,
    notes: str = "",
    release_id: int,
) -> dict[str, object]:
    """Return release fixture."""
    suffix = f"\n\n{notes}" if notes else ""
    return {
        "id": release_id,
        "tag_name": tag,
        "name": f"Atlaso {tag}",
        "body": f"Signed appliance release built from `{commit}`.{suffix}",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-07-26T00:00:00Z",
        "target_commitish": "main",
        "assets": [
            {
                "id": release_id * 10,
                "name": f"atlaso-{tag}.tar.gz",
                "size": 123,
                "digest": f"sha256:{release_id:064x}",
            }
        ],
    }


def test_publish_release_requests_generated_notes_and_keeps_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that publish release requests generated notes and keeps provenance."""
    commit = "a" * 40
    asset = tmp_path / "release-manifest.json"
    asset.write_text("{}", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool = True):
        """Return fake run."""
        calls.append(command)
        if command == ["python", "scripts/version.py", "get"]:
            return completed(command, stdout="0.9.30\n")
        if command[-1] == "refs/tags/v0.9.30":
            return completed(command, stdout=f"{commit}\trefs/tags/v0.9.30\n")
        if command[-1] == "refs/tags/v0.9.30^{}":
            return completed(command)
        if command[:4] == ["gh", "release", "view", "v0.9.30"]:
            return completed(command, returncode=1, stderr="release not found")
        return completed(command)

    monkeypatch.setattr(publish_release, "run", fake_run)

    assert (
        publish_release.main(["--commit", commit, "--assets", str(tmp_path)])
        == 0
    )
    create = next(command for command in calls if command[:3] == ["gh", "release", "create"])
    assert "--generate-notes" in create
    assert create[create.index("--notes") + 1] == (
        f"Signed appliance release built from `{commit}`."
    )
    assert create[create.index("--title") + 1] == "Atlaso v0.9.30"
    assert str(asset.resolve()) in create


def test_vmware_release_assets_require_two_manifest_verified_vmdks(tmp_path: Path):
    """Verify that vmware release assets require two manifest verified vmdks."""
    ovf = tmp_path / "Atlaso-Photon.ovf"
    os_disk = tmp_path / "Atlaso-Photon-disk1.vmdk"
    tools_disk = tmp_path / "Atlaso-Photon-disk2.vmdk"
    manifest = tmp_path / "Atlaso-Photon.mf"
    os_disk.write_bytes(b"os")
    tools_disk.write_bytes(b"tools")
    write_valid_vmware_ovf(ovf, os_disk.name, tools_disk.name)
    manifest.write_text(
        "\n".join(
            f"SHA256({path.name})= {publish_release.sha256(path)}"
            for path in (ovf, os_disk, tools_disk)
        )
        + "\n",
        encoding="utf-8",
    )
    names = {path.name for path in (ovf, os_disk, tools_disk, manifest)}

    publish_release.verify_vmware_release_assets(tmp_path, names)

    tools_disk.write_bytes(b"changed")
    with pytest.raises(SystemExit, match="failed manifest verification"):
        publish_release.verify_vmware_release_assets(tmp_path, names)


def test_vmware_release_assets_reject_invalid_empty_disk_topology(tmp_path: Path):
    """Verify that vmware release assets reject invalid empty disk topology."""
    ovf = tmp_path / "Atlaso-Photon.ovf"
    os_disk = tmp_path / "Atlaso-Photon-disk1.vmdk"
    tools_disk = tmp_path / "Atlaso-Photon-disk2.vmdk"
    os_disk.write_bytes(b"os")
    tools_disk.write_bytes(b"tools")
    write_valid_vmware_ovf(ovf, os_disk.name, tools_disk.name)
    ovf.write_text(ovf.read_text(encoding="utf-8").replace('ovf:capacity="500"', 'ovf:capacity="499"', 1), encoding="utf-8")

    with pytest.raises(SystemExit, match="not an empty 500 GiB disk"):
        publish_release.verify_vmware_ovf_topology(ovf, {ovf.name, os_disk.name, tools_disk.name})


def test_vmware_release_assets_accept_byte_equivalent_ova(tmp_path: Path):
    """Verify that vmware release assets accept byte equivalent ova."""
    ovf = tmp_path / "Atlaso-Photon.ovf"
    os_disk = tmp_path / "Atlaso-Photon-disk1.vmdk"
    tools_disk = tmp_path / "Atlaso-Photon-disk2.vmdk"
    manifest = tmp_path / "Atlaso-Photon.mf"
    ova = tmp_path / "Atlaso-Photon.ova"
    for path, content in ((os_disk, b"os"), (tools_disk, b"tools")):
        path.write_bytes(content)
    write_valid_vmware_ovf(ovf, os_disk.name, tools_disk.name)
    manifest.write_text(
        "\n".join(
            f"SHA256({path.name})= {publish_release.sha256(path)}"
            for path in (ovf, os_disk, tools_disk)
        )
        + "\n",
        encoding="utf-8",
    )
    with tarfile.open(ova, mode="w") as archive:
        for path in (ovf, manifest, os_disk, tools_disk):
            archive.add(path, arcname=path.name)

    publish_release.verify_vmware_release_assets(
        tmp_path,
        {path.name for path in (ovf, os_disk, tools_disk, manifest, ova)},
    )


def test_release_recovery_accepts_manifest_verified_vmware_assets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that release recovery accepts manifest verified vmware assets."""
    commit = "a" * 40
    core = tmp_path / "core"
    remote = tmp_path / "remote"
    core.mkdir()
    remote.mkdir()
    (core / "release-manifest.json").write_text("{}", encoding="utf-8")
    shutil.copy2(core / "release-manifest.json", remote / "release-manifest.json")
    ovf = remote / "Atlaso-Photon.ovf"
    os_disk = remote / "Atlaso-Photon-disk1.vmdk"
    tools_disk = remote / "Atlaso-Photon-disk2.vmdk"
    manifest = remote / "Atlaso-Photon.mf"
    os_disk.write_bytes(b"os")
    tools_disk.write_bytes(b"tools")
    write_valid_vmware_ovf(ovf, os_disk.name, tools_disk.name)
    manifest.write_text(
        "\n".join(
            f"SHA256({path.name})= {publish_release.sha256(path)}"
            for path in (ovf, os_disk, tools_disk)
        )
        + "\n",
        encoding="utf-8",
    )

    def fake_run(command: list[str], *, check: bool = True):
        """Return fake run.

        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        if command == ["python", "scripts/version.py", "get"]:
            return completed(command, stdout="0.9.71\n")
        if command[-1] == "refs/tags/v0.9.71":
            return completed(command, stdout=f"{commit}\trefs/tags/v0.9.71\n")
        if command[-1] == "refs/tags/v0.9.71^{}":
            return completed(command)
        if command[:4] == ["gh", "release", "view", "v0.9.71"]:
            assets = [{"name": path.name} for path in remote.iterdir()]
            return completed(command, stdout=json.dumps({"tagName": "v0.9.71", "assets": assets}))
        if command[:4] == ["gh", "release", "download", "v0.9.71"]:
            destination = Path(command[command.index("--dir") + 1])
            for path in remote.iterdir():
                shutil.copy2(path, destination / path.name)
            return completed(command)
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(publish_release, "run", fake_run)

    assert publish_release.main(["--commit", commit, "--assets", str(core)]) == 0


def test_release_note_categories_keep_dependencies_out_of_enhancements():
    """Verify that release note categories keep dependencies out of enhancements."""
    text = (ROOT / ".github" / "release.yml").read_text(encoding="utf-8")
    titles = re.findall(r"^\s+- title: (.+)$", text, flags=re.MULTILINE)
    assert titles == [
        "New and improved",
        "Fixes",
        "Documentation",
        "Dependency updates",
        "Other changes",
    ]
    enhancement = text.split("- title: New and improved", 1)[1].split("- title: Fixes", 1)[0]
    assert "- enhancement" in enhancement
    assert "exclude:" in enhancement
    assert "- dependencies" in enhancement


def test_historical_generated_notes_use_pull_request_labels(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that historical generated notes use pull request labels."""
    generated_body = """\
## What's Changed
* Add a feature by @example in https://github.com/mdaneri/Atlaso/pull/10
* Update a dependency by @dependabot in https://github.com/mdaneri/Atlaso/pull/11
* Fix a bug by @example in https://github.com/mdaneri/Atlaso/pull/12

## New Contributors
* @example made their first contribution in https://github.com/mdaneri/Atlaso/pull/10

**Full Changelog**: https://github.com/mdaneri/Atlaso/compare/v0.9.17...v0.9.18
"""
    labels = {
        10: [{"name": "enhancement"}],
        11: [{"name": "enhancement"}, {"name": "dependencies"}],
        12: [{"name": "bug"}],
    }

    def fake_gh_json(arguments: list[str], *, payload=None):
        """Return fake gh json."""
        if arguments[-1].endswith("/releases/generate-notes"):
            assert payload == {
                "tag_name": "v0.9.18",
                "previous_tag_name": "v0.9.17",
            }
            return {"body": generated_body}
        number = int(arguments[-1].rsplit("/", 1)[-1])
        return {"labels": labels[number]}

    monkeypatch.setattr(backfill_release_notes, "gh_json", fake_gh_json)

    notes = backfill_release_notes.generated_notes(
        "mdaneri/Atlaso",
        "v0.9.18",
        "v0.9.17",
    )

    assert notes.index("### New and improved") < notes.index("### Fixes")
    assert notes.index("### Fixes") < notes.index("### Dependency updates")
    enhancement_section = notes.split("### New and improved", 1)[1].split("### Fixes", 1)[0]
    dependency_section = notes.split("### Dependency updates", 1)[1].split("## New Contributors", 1)[0]
    assert "pull/10" in enhancement_section
    assert "pull/11" not in enhancement_section
    assert "pull/11" in dependency_section
    assert "## New Contributors" in notes
    assert "**Full Changelog**" in notes


def test_comparable_notes_ignores_generator_comment_and_blank_lines():
    """Verify that comparable notes ignores generator comment and blank lines."""
    github_notes = """\
<!-- Release notes generated using configuration in .github/release.yml at v0.9.30 -->

## What's Changed
### Fixes
* Fix release notes

**Full Changelog**: https://example.test/compare
"""
    backfill_notes = """\
<!-- Release notes grouped by Atlaso from GitHub-generated changes using .github/release.yml -->

## What's Changed

### Fixes
* Fix release notes


**Full Changelog**: https://example.test/compare
"""
    assert backfill_release_notes.comparable_notes(github_notes) == (
        backfill_release_notes.comparable_notes(backfill_notes)
    )


def test_already_configured_generated_notes_are_preserved():
    """Verify that already configured generated notes are preserved."""
    body = """\
<!-- Release notes generated using configuration in .github/release.yml at v0.9.30 -->

## What's Changed
### New and improved
* Generate grouped GitHub release notes in https://github.com/mdaneri/Atlaso/pull/146

**Full Changelog**: https://github.com/mdaneri/Atlaso/compare/v0.9.29...v0.9.30
"""
    assert backfill_release_notes.group_generated_notes("mdaneri/Atlaso", body) == body.strip()


def test_historical_notes_select_the_trailing_repository_pull_request(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that historical notes select the trailing repository pull request."""
    body = """\
## What's Changed
* Document https://github.com/mdaneri/Atlaso/pull/999 by @example in https://github.com/mdaneri/Atlaso/pull/10

**Full Changelog**: https://github.com/mdaneri/Atlaso/compare/v0.9.17...v0.9.18
"""
    requested: list[int] = []

    def fake_pull_request_labels(repository: str, number: int) -> set[str]:
        """Return fake pull request labels."""
        assert repository == "mdaneri/Atlaso"
        requested.append(number)
        return {"documentation"}

    monkeypatch.setattr(
        backfill_release_notes,
        "pull_request_labels",
        fake_pull_request_labels,
    )

    notes = backfill_release_notes.group_generated_notes("mdaneri/Atlaso", body)

    assert requested == [10]
    assert "### Documentation" in notes


def test_backfill_selects_published_range_and_previous_release(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that backfill selects published range and previous release."""
    commits = {
        "v0.9.17": "1" * 40,
        "v0.9.18": "2" * 40,
        "v0.9.19": "3" * 40,
        "v0.9.21": "4" * 40,
    }
    releases = [
        release_fixture(tag, commit, release_id=index)
        for index, (tag, commit) in enumerate(reversed(commits.items()), start=1)
    ]
    generated: list[tuple[str, str]] = []
    monkeypatch.setattr(
        backfill_release_notes,
        "tag_commit",
        lambda _repository, tag: commits[tag],
    )

    def fake_generated(_repository: str, tag: str, previous_tag: str) -> str:
        """Return fake generated."""
        generated.append((tag, previous_tag))
        return f"## Changes in {tag}"

    monkeypatch.setattr(backfill_release_notes, "generated_notes", fake_generated)

    plans = backfill_release_notes.plan_updates(
        releases,
        repository="mdaneri/Atlaso",
        start_tag="v0.9.18",
    )

    assert generated == [
        ("v0.9.18", "v0.9.17"),
        ("v0.9.19", "v0.9.18"),
        ("v0.9.21", "v0.9.19"),
    ]
    assert [plan.action for plan in plans] == ["update", "update", "update"]


def test_backfill_refuses_custom_or_mismatched_release_text(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that backfill refuses custom or mismatched release text."""
    commit = "5" * 40
    releases = [
        release_fixture("v0.9.17", "4" * 40, release_id=17),
        release_fixture(
            "v0.9.18",
            commit,
            notes="A manually curated summary.",
            release_id=18,
        ),
    ]
    monkeypatch.setattr(backfill_release_notes, "tag_commit", lambda _repository, _tag: commit)
    monkeypatch.setattr(
        backfill_release_notes,
        "generated_notes",
        lambda _repository, _tag, _previous: "## Generated changes",
    )

    with pytest.raises(SystemExit, match="manually customized"):
        backfill_release_notes.plan_updates(
            releases,
            repository="mdaneri/Atlaso",
            start_tag="v0.9.18",
        )

    releases[1]["body"] = "Signed appliance release built from `" + ("6" * 40) + "`."
    with pytest.raises(SystemExit, match="mismatched"):
        backfill_release_notes.plan_updates(
            releases,
            repository="mdaneri/Atlaso",
            start_tag="v0.9.18",
        )


def test_backfill_apply_updates_legacy_body_and_skips_matching_notes(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that backfill apply updates legacy body and skips matching notes."""
    first_release = release_fixture("v0.9.18", "7" * 40, release_id=18)
    second_release = release_fixture(
        "v0.9.19",
        "8" * 40,
        notes="## Existing generated notes",
        release_id=19,
    )
    first_body = "Signed appliance release built from `" + ("7" * 40) + "`.\n\n## Generated notes"
    plans = [
        backfill_release_notes.ReleaseNotePlan(
            tag="v0.9.18",
            previous_tag="v0.9.17",
            original_body=str(first_release["body"]),
            expected_body=first_body,
            action="update",
            identity=backfill_release_notes.release_identity(first_release),
        ),
        backfill_release_notes.ReleaseNotePlan(
            tag="v0.9.19",
            previous_tag="v0.9.18",
            original_body=str(second_release["body"]),
            expected_body=str(second_release["body"]),
            action="unchanged",
            identity=backfill_release_notes.release_identity(second_release),
        ),
    ]
    edits: list[tuple[str, str]] = []

    def fake_edit(_repository: str, tag: str, body: str) -> None:
        """Handle fake edit."""
        edits.append((tag, body))

    updated = dict(first_release)
    updated["body"] = first_body.replace("\n", "\r\n")
    responses = iter([first_release, updated])
    monkeypatch.setattr(backfill_release_notes, "edit_release_body", fake_edit)
    monkeypatch.setattr(
        backfill_release_notes,
        "release_by_tag",
        lambda _repository, _tag: next(responses),
    )

    backfill_release_notes.apply_plans(plans, repository="mdaneri/Atlaso")

    assert edits == [("v0.9.18", first_body)]


def test_backfill_apply_verifies_release_identity(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that backfill apply verifies release identity."""
    release = release_fixture("v0.9.18", "9" * 40, release_id=18)
    body = "Signed appliance release built from `" + ("9" * 40) + "`.\n\n## Generated notes"
    plan = backfill_release_notes.ReleaseNotePlan(
        tag="v0.9.18",
        previous_tag="v0.9.17",
        original_body=str(release["body"]),
        expected_body=body,
        action="update",
        identity=backfill_release_notes.release_identity(release),
    )
    changed = dict(release)
    changed["body"] = body
    changed["name"] = "Unexpected title"
    edits: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        backfill_release_notes,
        "edit_release_body",
        lambda *_args: edits.append(_args),
    )
    monkeypatch.setattr(backfill_release_notes, "release_by_tag", lambda *_args: changed)

    with pytest.raises(SystemExit, match="identity or assets changed after preflight"):
        backfill_release_notes.apply_plans([plan], repository="mdaneri/Atlaso")
    assert edits == []


def test_backfill_apply_refuses_body_changed_after_preflight(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that backfill apply refuses body changed after preflight."""
    release = release_fixture("v0.9.18", "a" * 40, release_id=18)
    body = "Signed appliance release built from `" + ("a" * 40) + "`.\n\n## Generated notes"
    plan = backfill_release_notes.ReleaseNotePlan(
        tag="v0.9.18",
        previous_tag="v0.9.17",
        original_body=str(release["body"]),
        expected_body=body,
        action="update",
        identity=backfill_release_notes.release_identity(release),
    )
    customized = dict(release)
    customized["body"] = str(release["body"]) + "\n\nMaintainer-authored notes."
    edits: list[tuple[object, ...]] = []
    monkeypatch.setattr(backfill_release_notes, "release_by_tag", lambda *_args: customized)
    monkeypatch.setattr(
        backfill_release_notes,
        "edit_release_body",
        lambda *_args: edits.append(_args),
    )

    with pytest.raises(SystemExit, match="body changed after preflight"):
        backfill_release_notes.apply_plans([plan], repository="mdaneri/Atlaso")
    assert edits == []


def test_backfill_preview_is_read_only_and_preflight_failure_blocks_apply(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify that backfill preview is read only and preflight failure blocks apply."""
    plan = backfill_release_notes.ReleaseNotePlan(
        tag="v0.9.18",
        previous_tag="v0.9.17",
        original_body="legacy body",
        expected_body="body",
        action="update",
        identity={},
    )
    apply_calls: list[list[object]] = []
    monkeypatch.setattr(backfill_release_notes, "load_releases", lambda _repository: [])
    monkeypatch.setattr(backfill_release_notes, "plan_updates", lambda *_args, **_kwargs: [plan])
    monkeypatch.setattr(backfill_release_notes, "print_plans", lambda _plans: None)
    monkeypatch.setattr(
        backfill_release_notes,
        "apply_plans",
        lambda plans, **_kwargs: apply_calls.append(plans),
    )

    assert (
        backfill_release_notes.main(
            ["--start-tag", "v0.9.18", "--repo", "mdaneri/Atlaso"]
        )
        == 0
    )
    assert apply_calls == []

    monkeypatch.setattr(
        backfill_release_notes,
        "plan_updates",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(SystemExit("GitHub API failed")),
    )
    with pytest.raises(SystemExit, match="GitHub API failed"):
        backfill_release_notes.main(
            ["--start-tag", "v0.9.18", "--repo", "mdaneri/Atlaso", "--apply"]
        )
    assert apply_calls == []
