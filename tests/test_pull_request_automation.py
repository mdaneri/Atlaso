"""Test pull request automation behavior."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ci_separates_diagnostic_checks_from_required_contexts() -> None:
    """Verify that CI separates diagnostic checks from required contexts."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("github.event_name == 'pull_request'") == 5
    assert workflow.count("github.actor == 'github-actions[bot]'") == 6
    for context in ("Version policy", "Repository checks", "Python tests"):
        assert f"'Approval-gated {context}'" in workflow
        assert f"'Trusted {context} validation'" in workflow
        assert f"|| '{context}'" in workflow
        assert workflow.count(context) >= 5


def test_trusted_ci_publishes_revalidated_required_statuses() -> None:
    """Verify that trusted CI bridges exact-head results into PR statuses."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "head_sha:" in workflow
    assert "pull_number:" in workflow
    assert "github.workflow }}-${{ github.event_name }}" in workflow
    assert "inputs.pull_number || github.ref" in workflow
    assert workflow.count("statuses: write") == 2
    assert workflow.count("pull-requests: read") == 2
    assert workflow.count("persist-credentials: false") == 6
    assert "github.event_name == 'workflow_dispatch'" in workflow
    assert "github.actor == 'github-actions[bot]'" in workflow
    assert '"$base_ref" != "main"' in workflow
    assert '"$base_sha" != "$BASE_SHA"' in workflow
    assert '"$head_repository" != "$GITHUB_REPOSITORY"' in workflow
    assert '"$head_sha" != "$HEAD_SHA"' in workflow
    assert workflow.count('"repos/$GITHUB_REPOSITORY/statuses/$HEAD_SHA"') == 2
    assert '{state: "pending", context: $context' in workflow
    assert "Trusted CI run $GITHUB_RUN_ID passed this validation" in workflow
    assert "PACKER_RESULT: ${{ needs.deployment-packer.result }}" in workflow
    assert 'if [[ "$PACKER_RESULT" != "success" ]]' in workflow
    assert 'post_status "Repository checks" "$repository_result"' in workflow
    finish_job = workflow.split("  trusted-contexts-finish:", maxsplit=1)[1]
    assert "actions/checkout" not in finish_job


def test_python_ci_installs_pinned_markdown_dependencies_before_pytest() -> None:
    """Keep the full suite bounded and backed by the locked npm dependency tree."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    python_job = workflow.split("  python-tests:", maxsplit=1)[1].split(
        "  trusted-contexts-finish:", maxsplit=1
    )[0]

    setup_node = python_job.index("      - uses: actions/setup-node@v7")
    npm_install = python_job.index("      - run: npm ci")
    pytest = python_job.index("      - run: python -m pytest")

    assert "          node-version: '22'" in python_job
    assert "          cache: npm" in python_job
    assert "    timeout-minutes: 45" in python_job
    assert setup_node < npm_install < pytest


def test_packer_ci_authenticates_plugins_without_exposing_fork_tokens() -> None:
    """Verify scoped Packer authentication and the tokenless fork fallback."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    packer_job = workflow.split("  deployment-packer:", maxsplit=1)[1].split(
        "  python-tests:", maxsplit=1
    )[0]
    job_preamble, authenticated_step = packer_job.split(
        "      - name: Validate the canonical Photon Packer target with authenticated plugin downloads",
        maxsplit=1,
    )
    authenticated_step, fork_step = authenticated_step.split(
        "      - name: Validate the fork Packer target without repository credentials",
        maxsplit=1,
    )

    assert "permissions:\n      contents: read" in packer_job
    assert "persist-credentials: false" in packer_job
    assert workflow.count("PACKER_GITHUB_API_TOKEN") == 1
    assert "PACKER_GITHUB_API_TOKEN" not in job_preamble
    assert (
        "if: github.event_name != 'pull_request' || "
        "github.event.pull_request.head.repo.full_name == github.repository"
        in authenticated_step
    )
    assert "PACKER_GITHUB_API_TOKEN: ${{ github.token }}" in authenticated_step
    assert "python scripts/check_deployment_assets.py --mode packer" in authenticated_step
    assert (
        "if: github.event_name == 'pull_request' && "
        "github.event.pull_request.head.repo.full_name != github.repository"
        in fork_step
    )
    assert "PACKER_GITHUB_API_TOKEN" not in fork_step
    assert "python scripts/check_deployment_assets.py --mode packer" in fork_step


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
    assert "id: candidate" in workflow
    assert 'candidate_head_sha="$(git -C target rev-parse HEAD)"' in workflow
    assert "for attempt in {1..12}" in workflow
    assert "sleep 2" in workflow
    assert '-f ref=main' in workflow
    assert '-f "inputs[head_sha]=${HEAD_SHA}"' in workflow
    assert '-f "inputs[pull_number]=${PR_NUMBER}"' in workflow
    assert (
        "steps.changes.outputs.changed == 'true' || "
        "github.event_name == 'repository_dispatch'"
    ) in workflow
