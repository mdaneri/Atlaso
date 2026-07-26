#!/usr/bin/env python3
"""Preview or backfill generated notes for published Atlaso GitHub Releases."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RELEASE_CONFIG_PATH = ".github/release.yml"
SEMVER_TAG_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
PULL_REQUEST_URL_RE = re.compile(r"https://github\.com/[^/\s]+/[^/\s]+/pull/(?P<number>[0-9]+)")
PROVENANCE_RE = re.compile(
    r"^Signed appliance release built from `(?P<commit>[0-9a-f]{40})`\.\s*(?P<notes>.*)$",
    flags=re.DOTALL,
)
RELEASE_NOTES_COMMENT_RE = re.compile(r"<!--\s*Release notes .*?-->\s*", flags=re.DOTALL)
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
BACKFILL_COMMENT = (
    "<!-- Release notes grouped by Atlaso from GitHub-generated changes "
    "using .github/release.yml -->"
)
CATEGORY_TITLES = (
    "New and improved",
    "Fixes",
    "Documentation",
    "Dependency updates",
    "Other changes",
)


@dataclass(frozen=True)
class ReleaseNotePlan:
    tag: str
    previous_tag: str
    original_body: str
    expected_body: str
    action: str
    identity: dict[str, Any]


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        input=input_text,
        text=True,
    )
    if check and result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"{command[0]} failed")
    return result


def gh_json(arguments: list[str], *, payload: dict[str, Any] | None = None) -> Any:
    command = ["gh", *arguments]
    input_text = None
    if payload is not None:
        command.extend(["--input", "-"])
        input_text = json.dumps(payload)
    result = run(command, input_text=input_text)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"GitHub returned invalid JSON for {' '.join(command[:3])}: {exc}") from exc


def repository_name(explicit: str | None) -> str:
    repository = explicit or os.environ.get("GITHUB_REPOSITORY", "").strip()
    if not repository:
        repository = run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]
        ).stdout.strip()
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise SystemExit(f"repository must use owner/name form; found {repository!r}")
    return repository


def parse_tag(tag: str) -> tuple[int, int, int]:
    match = SEMVER_TAG_RE.fullmatch(tag)
    if match is None:
        raise SystemExit(f"release tag must use vX.Y.Z semantic versioning; found {tag!r}")
    return tuple(int(part) for part in match.groups())


def load_releases(repository: str) -> list[dict[str, Any]]:
    pages = gh_json(
        [
            "api",
            "--method",
            "GET",
            "--paginate",
            "--slurp",
            f"repos/{repository}/releases?per_page=100",
        ]
    )
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise SystemExit("GitHub Releases response did not contain paginated release lists")
    releases = [release for page in pages for release in page]
    if any(not isinstance(release, dict) for release in releases):
        raise SystemExit("GitHub Releases response contained an invalid release")
    return releases


def published_semver_releases(releases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    published: list[dict[str, Any]] = []
    for release in releases:
        tag = release.get("tag_name")
        if (
            isinstance(tag, str)
            and SEMVER_TAG_RE.fullmatch(tag)
            and not release.get("draft", False)
            and release.get("published_at")
        ):
            published.append(release)
    return sorted(published, key=lambda release: parse_tag(str(release["tag_name"])))


def tag_commit(repository: str, tag: str) -> str:
    reference = gh_json(["api", f"repos/{repository}/git/ref/tags/{tag}"])
    if not isinstance(reference, dict) or not isinstance(reference.get("object"), dict):
        raise SystemExit(f"{tag} did not resolve to a GitHub tag object")
    target = reference["object"]
    seen: set[str] = set()
    while target.get("type") == "tag":
        sha = target.get("sha")
        if not isinstance(sha, str) or sha in seen:
            raise SystemExit(f"{tag} contains an invalid or cyclic annotated tag")
        seen.add(sha)
        annotated = gh_json(["api", f"repos/{repository}/git/tags/{sha}"])
        if not isinstance(annotated, dict) or not isinstance(annotated.get("object"), dict):
            raise SystemExit(f"{tag} annotated tag object is invalid")
        target = annotated["object"]
    commit = target.get("sha")
    if target.get("type") != "commit" or not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise SystemExit(f"{tag} does not resolve to a full commit SHA")
    return commit


def pull_request_labels(repository: str, number: int) -> set[str]:
    response = gh_json(["api", f"repos/{repository}/pulls/{number}"])
    labels = response.get("labels") if isinstance(response, dict) else None
    if not isinstance(labels, list):
        raise SystemExit(f"GitHub returned invalid labels for pull request #{number}")
    names = {
        str(label["name"])
        for label in labels
        if isinstance(label, dict) and isinstance(label.get("name"), str)
    }
    return names


def release_category(labels: set[str]) -> str:
    if "dependencies" in labels:
        return "Dependency updates"
    if "enhancement" in labels:
        return "New and improved"
    if "bug" in labels:
        return "Fixes"
    if "documentation" in labels:
        return "Documentation"
    return "Other changes"


def group_generated_notes(repository: str, body: str) -> str:
    lines = body.strip().splitlines()
    try:
        changes_index = lines.index("## What's Changed")
    except ValueError as exc:
        raise SystemExit("GitHub generated notes without a What's Changed section") from exc
    full_changelog_indexes = [
        index
        for index, line in enumerate(lines)
        if line.startswith("**Full Changelog**:")
    ]
    if len(full_changelog_indexes) != 1:
        raise SystemExit("GitHub generated notes without exactly one Full Changelog link")
    full_changelog_index = full_changelog_indexes[0]
    if full_changelog_index <= changes_index:
        raise SystemExit("GitHub generated notes placed Full Changelog before What's Changed")

    middle = lines[changes_index + 1 : full_changelog_index]
    extra_index = next(
        (index for index, line in enumerate(middle) if line.startswith("## ")),
        len(middle),
    )
    change_lines = [line for line in middle[:extra_index] if line.strip()]
    configured_headings = [
        line.removeprefix("### ")
        for line in change_lines
        if line.startswith("### ")
    ]
    if configured_headings:
        if any(title not in CATEGORY_TITLES for title in configured_headings):
            raise SystemExit("GitHub generated notes with an unknown release category")
        if any(not (line.startswith("### ") or line.startswith("* ")) for line in change_lines):
            raise SystemExit("GitHub generated an unsupported categorized What's Changed entry")
        return body.strip()
    if any(not line.startswith("* ") for line in change_lines):
        raise SystemExit("GitHub generated an unsupported What's Changed entry")
    extra_sections = "\n".join(middle[extra_index:]).strip()

    grouped: dict[str, list[str]] = {title: [] for title in CATEGORY_TITLES}
    for line in change_lines:
        match = PULL_REQUEST_URL_RE.search(line)
        if match is None:
            grouped["Other changes"].append(line)
            continue
        labels = pull_request_labels(repository, int(match.group("number")))
        grouped[release_category(labels)].append(line)

    blocks = [BACKFILL_COMMENT, "## What's Changed"]
    blocks.extend(
        f"### {title}\n" + "\n".join(grouped[title])
        for title in CATEGORY_TITLES
        if grouped[title]
    )
    if extra_sections:
        blocks.append(extra_sections)
    blocks.append(lines[full_changelog_index])
    return "\n\n".join(blocks)


def generated_notes(repository: str, tag: str, previous_tag: str) -> str:
    response = gh_json(
        ["api", "--method", "POST", f"repos/{repository}/releases/generate-notes"],
        payload={
            "tag_name": tag,
            "previous_tag_name": previous_tag,
        },
    )
    body = response.get("body") if isinstance(response, dict) else None
    if not isinstance(body, str) or not body.strip():
        raise SystemExit(f"GitHub generated an empty release-note body for {tag}")
    return group_generated_notes(repository, body)


def comparable_notes(notes: str) -> str:
    without_comment = RELEASE_NOTES_COMMENT_RE.sub("", notes).strip()
    return "\n".join(line.rstrip() for line in without_comment.splitlines() if line.strip())


def release_identity(release: dict[str, Any]) -> dict[str, Any]:
    assets = release.get("assets", [])
    if not isinstance(assets, list):
        raise SystemExit(f"{release.get('tag_name', 'release')} contains an invalid asset list")
    return {
        "id": release.get("id"),
        "tag_name": release.get("tag_name"),
        "name": release.get("name"),
        "draft": release.get("draft"),
        "prerelease": release.get("prerelease"),
        "target_commitish": release.get("target_commitish"),
        "assets": sorted(
            (
                asset.get("id"),
                asset.get("name"),
                asset.get("size"),
                asset.get("digest"),
            )
            for asset in assets
            if isinstance(asset, dict)
        ),
    }


def plan_updates(
    releases: list[dict[str, Any]],
    *,
    repository: str,
    start_tag: str,
) -> list[ReleaseNotePlan]:
    parse_tag(start_tag)
    ordered = published_semver_releases(releases)
    tags = [str(release["tag_name"]) for release in ordered]
    if start_tag not in tags:
        raise SystemExit(f"{start_tag} is not a published semantic-version release")
    start_index = tags.index(start_tag)
    if start_index == 0:
        raise SystemExit(f"{start_tag} has no preceding published semantic-version release")

    plans: list[ReleaseNotePlan] = []
    for index in range(start_index, len(ordered)):
        release = ordered[index]
        tag = tags[index]
        previous_tag = tags[index - 1]
        commit = tag_commit(repository, tag)
        notes = generated_notes(repository, tag, previous_tag)
        expected_body = f"Signed appliance release built from `{commit}`.\n\n{notes}"
        current_body = release.get("body")
        if not isinstance(current_body, str):
            raise SystemExit(f"{tag} has no text release body")
        match = PROVENANCE_RE.fullmatch(current_body.strip())
        if match is None or match.group("commit") != commit:
            raise SystemExit(f"{tag} has unexpected or mismatched release text; refusing to overwrite it")
        current_notes = match.group("notes").strip()
        if not current_notes:
            action = "update"
        elif comparable_notes(current_notes) == comparable_notes(notes):
            action = "unchanged"
        else:
            raise SystemExit(f"{tag} has unexpected or manually customized release notes; refusing to overwrite them")
        plans.append(
            ReleaseNotePlan(
                tag=tag,
                previous_tag=previous_tag,
                original_body=current_body.strip(),
                expected_body=expected_body,
                action=action,
                identity=release_identity(release),
            )
        )
    return plans


def print_plans(plans: list[ReleaseNotePlan]) -> None:
    for plan in plans:
        print(f"### {plan.tag} from {plan.previous_tag} [{plan.action}]")
        print()
        print(plan.expected_body)
        print()


def edit_release_body(repository: str, tag: str, body: str) -> None:
    run(
        ["gh", "release", "edit", tag, "--repo", repository, "--notes-file", "-"],
        input_text=body,
    )


def release_by_tag(repository: str, tag: str) -> dict[str, Any]:
    release = gh_json(["api", f"repos/{repository}/releases/tags/{tag}"])
    if not isinstance(release, dict):
        raise SystemExit(f"GitHub returned an invalid release after updating {tag}")
    return release


def apply_plans(plans: list[ReleaseNotePlan], *, repository: str) -> None:
    for plan in plans:
        if plan.action == "unchanged":
            continue
        current = release_by_tag(repository, plan.tag)
        if release_identity(current) != plan.identity:
            raise SystemExit(f"{plan.tag} release identity or assets changed after preflight")
        current_body = str(current.get("body", "")).strip()
        if current_body == plan.expected_body.strip():
            continue
        if current_body != plan.original_body:
            raise SystemExit(f"{plan.tag} release body changed after preflight; refusing to overwrite it")
        edit_release_body(repository, plan.tag, plan.expected_body)
        updated = release_by_tag(repository, plan.tag)
        if str(updated.get("body", "")).strip() != plan.expected_body.strip():
            raise SystemExit(f"{plan.tag} release body did not match after update")
        if release_identity(updated) != plan.identity:
            raise SystemExit(f"{plan.tag} release identity or assets changed while updating its body")
        print(json.dumps({"result": "updated", "tag": plan.tag}, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-tag", required=True, help="Oldest published vX.Y.Z release to inspect.")
    parser.add_argument("--repo", help="GitHub repository in owner/name form; defaults to the current repository.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply preflighted body updates. Without this flag the command is read-only.",
    )
    args = parser.parse_args(argv)

    if not (ROOT / RELEASE_CONFIG_PATH).is_file():
        raise SystemExit(f"{RELEASE_CONFIG_PATH} is required before generating release notes")
    repository = repository_name(args.repo)
    releases = load_releases(repository)
    plans = plan_updates(releases, repository=repository, start_tag=args.start_tag)
    print_plans(plans)
    if args.apply:
        apply_plans(plans, repository=repository)
    else:
        print(json.dumps({"result": "preview", "updates": sum(plan.action == "update" for plan in plans)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
