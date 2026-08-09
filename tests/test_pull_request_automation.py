"""Test pull request automation behavior."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ci_separates_approval_gated_bot_checks_from_required_contexts() -> None:
    """Verify that ci separates approval gated bot checks from required contexts."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("github.event_name == 'pull_request'") == 3
    assert workflow.count("github.actor == 'github-actions[bot]'") == 3
    for context in ("Version policy", "Repository checks", "Python tests"):
        assert f"'Approval-gated {context}'" in workflow
        assert f"|| '{context}'" in workflow


def test_auto_merge_branch_updates_are_explicit_and_race_safe() -> None:
    """Verify that auto merge branch updates are explicit and race safe."""
    workflow = (
        ROOT / ".github" / "workflows" / "update-auto-merge-prs.yml"
    ).read_text(encoding="utf-8")

    assert "push:" in workflow
    assert "- main" in workflow
    assert "workflow_dispatch:" not in workflow
    assert "pull-requests: write" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "--base main" in workflow
    assert ".isDraft == false" in workflow
    assert ".isCrossRepository == false" in workflow
    assert ".autoMergeRequest != null" in workflow
    assert '.mergeStateStatus == "UNKNOWN"' in workflow
    assert '.mergeStateStatus == "BEHIND"' in workflow
    assert 'sleep "$((attempt * 5))"' in workflow
    assert "pulls/$number/update-branch" in workflow
    assert '-f "expected_head_sha=$expected_head_sha"' in workflow
    assert "refresh-pull-request-version" in workflow
    assert "current_head_sha" in workflow
    assert '"repos/$GITHUB_REPOSITORY/dispatches"' in workflow
    assert "actions/checkout" not in workflow
    assert "pull_request_target" not in workflow


def test_trusted_version_refresh_validates_repository_dispatch_payload() -> None:
    """Verify that trusted version refresh validates repository dispatch payload."""
    workflow = (
        ROOT / ".github" / "workflows" / "version-bump.yml"
    ).read_text(encoding="utf-8")

    assert "repository_dispatch:" in workflow
    assert "- refresh-pull-request-version" in workflow
    assert "github.event.client_payload.pull_number" in workflow
    assert "github.event.client_payload.expected_head_sha" in workflow
    assert '"$base_ref" != "main"' in workflow
    assert '"$head_repository" != "$GITHUB_REPOSITORY"' in workflow
    assert '"$head_sha" != "$EXPECTED_HEAD_SHA"' in workflow
    assert "ref: ${{ steps.pull-request.outputs.head_sha }}" in workflow
    assert 'git -C target push origin "HEAD:${HEAD_REF}"' in workflow
    assert (
        "steps.changes.outputs.changed == 'true' || "
        "github.event_name == 'repository_dispatch'"
    ) in workflow
