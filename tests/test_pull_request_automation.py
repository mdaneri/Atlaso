from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ci_separates_approval_gated_bot_checks_from_required_contexts() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("github.event_name == 'pull_request'") == 3
    assert workflow.count("github.actor == 'github-actions[bot]'") == 3
    for context in ("Version policy", "Repository checks", "Python tests"):
        assert f"'Approval-gated {context}'" in workflow
        assert f"|| '{context}'" in workflow


def test_auto_merge_branch_updates_are_explicit_and_race_safe() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "update-auto-merge-prs.yml"
    ).read_text(encoding="utf-8")

    assert "push:" in workflow
    assert "- main" in workflow
    assert "workflow_dispatch:" in workflow
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
    assert "actions/checkout" not in workflow
    assert "pull_request_target" not in workflow
