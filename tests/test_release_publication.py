from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_script(module_name: str, filename: str):
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
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def release_fixture(
    tag: str,
    commit: str,
    *,
    notes: str = "",
    release_id: int,
) -> dict[str, object]:
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
    commit = "a" * 40
    asset = tmp_path / "release-manifest.json"
    asset.write_text("{}", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool = True):
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


def test_release_note_categories_keep_dependencies_out_of_enhancements():
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


def test_backfill_selects_published_range_and_previous_release(
    monkeypatch: pytest.MonkeyPatch,
):
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
        edits.append((tag, body))

    updated = dict(first_release)
    updated["body"] = first_body
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
