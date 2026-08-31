"""Test check repo policies behavior."""

import json
from pathlib import Path

from scripts.check_repo import (
    DEFAULT_MERGE_AUTHORITY_SECTION_ANCHORS,
    DEFAULT_MERGE_AUTHORITY_SECTION_MARKERS,
    LEGACY_TABULATOR_MARKER,
    LOCAL_TASK_BRANCH_ABSENT_MARKER,
    MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH,
    NON_TASK_OWNED_CHECKOUT_PRESERVED_MARKER,
    NON_TASK_OWNED_REMOTE_BRANCH_PRESERVED_MARKER,
    ORDERED_TERMINAL_CLEANUP_MARKERS,
    PRIMARY_CHECKOUT_REMOTE_GATE_MARKER,
    PRIMARY_CHECKOUT_RESTORED_MARKER,
    PRIMARY_CHECKOUT_RESUME_MARKER,
    PRIVATE_REMEDIATION_CLEANUP_MARKER,
    PRIVATE_REMEDIATION_REMOTE_MARKER,
    PROTECTED_PUBLICATION_WORKFLOWS,
    REMOTE_BRANCH_LEASE_MARKER,
    REQUIRED_POLICY_MARKERS,
    SCHEDULED_PR_MONITORING_SECTION_ANCHORS,
    SCHEDULED_PR_MONITORING_SECTION_END_ANCHORS,
    SCHEDULED_PR_MONITORING_SECTION_MARKERS,
    SPARK_WORKER_AGENT_PATH,
    SPARK_WORKER_ALLOWED_KEYS,
    SPARK_WORKER_REQUIRED_INSTRUCTION_MARKERS,
    SPARK_WORKER_REQUIRED_VALUES,
    TERMINAL_CLEANUP_ORDER_ANCHOR,
    TERMINAL_CLEANUP_ORDER_LINES,
    TERMINAL_CLEANUP_SECTION_ANCHORS,
    TERMINAL_CLEANUP_SECTION_MARKERS,
    TITLE_CONTROL_UNAVAILABLE_MARKER,
    WORKTREE_REMOVAL_REMOTE_GATE_MARKER,
    WORKTREE_REMOVAL_RESUME_MARKER,
    check_agent_policy_gate,
    check_merge_authority_transfer_fixtures,
    check_protected_workflow_caches,
    check_spark_worker_agent,
    check_ui_pattern_foundation,
    check_virtualization_legacy,
    collect_files,
    has_affirmative_default_merge_authority,
    is_checkable,
    merge_hold_directions,
    source_has_default_merge_authority,
)


def write_protected_workflows(root: Path, workflow: str) -> None:
    """Write the same focused workflow fixture to every protected path.

    Args:
        root: Temporary repository root.
        workflow: Workflow YAML source.
    """

    for relative_path in PROTECTED_PUBLICATION_WORKFLOWS:
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(workflow, encoding="utf-8")


def test_protected_workflow_cache_policy_accepts_cache_free_jobs(tmp_path: Path) -> None:
    """Protected jobs may configure Python without registering cache saves.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions:
  actions: read
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        with:
          python-version: '3.14'
""",
    )

    assert check_protected_workflow_caches(tmp_path) == []


def test_protected_workflow_cache_policy_uses_effective_job_permissions(
    tmp_path: Path,
) -> None:
    """A job override without Actions write cannot request a cache save.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions:
  actions: write
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: write
    steps:
      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: '3.14'
          cache: pip
""",
    )

    findings = check_protected_workflow_caches(tmp_path)

    assert len(findings) == len(PROTECTED_PUBLICATION_WORKFLOWS)
    assert all("without actions: write" in finding.message for finding in findings)


def test_protected_workflow_cache_policy_accepts_effective_actions_write(
    tmp_path: Path,
) -> None:
    """The parser does not reject a cache when effective permissions can save it.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions:
  actions: read
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      actions: write
    steps:
      - uses: actions/setup-python@v7
        with:
          python-version: '3.14'
          cache: 'pip'
""",
    )

    assert check_protected_workflow_caches(tmp_path) == []


def test_protected_workflow_cache_policy_stops_at_same_indent_step(tmp_path: Path) -> None:
    """A later action's cache input does not belong to inline setup-python.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
      - uses: example/cache-aware-action@v1
        with:
          cache: pip
""",
    )

    assert check_protected_workflow_caches(tmp_path) == []


def test_protected_workflow_cache_policy_honors_scalar_job_permissions(tmp_path: Path) -> None:
    """Scalar job permissions override a workflow-level Actions write grant.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: {actions: write, contents: read}
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/setup-python@v7
        with:
          cache: pip
""",
    )

    findings = check_protected_workflow_caches(tmp_path)

    assert len(findings) == len(PROTECTED_PUBLICATION_WORKFLOWS)
    assert all("without actions: write" in finding.message for finding in findings)


def test_protected_workflow_cache_policy_rejects_inline_cache_input(tmp_path: Path) -> None:
    """Flow-style setup-python inputs cannot bypass protected cache policy.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        with: {python-version: '3.14', cache: pip}
""",
    )

    findings = check_protected_workflow_caches(tmp_path)

    assert len(findings) == len(PROTECTED_PUBLICATION_WORKFLOWS)
    assert all("without actions: write" in finding.message for finding in findings)


def test_protected_workflow_cache_policy_rejects_complete_flow_step(tmp_path: Path) -> None:
    """A complete flow-style step is inspected independent of mapping order.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs: # protected publication jobs
  publish:
    runs-on: ubuntu-latest
    steps:
      - {with: {cache: pip, python-version: '3.14'}, uses: actions/setup-python@v7}
""",
    )

    findings = check_protected_workflow_caches(tmp_path)

    assert len(findings) == len(PROTECTED_PUBLICATION_WORKFLOWS)
    assert all("without actions: write" in finding.message for finding in findings)


def test_protected_workflow_cache_policy_ignores_environment_cache_key(tmp_path: Path) -> None:
    """Only setup-python action inputs participate in the cache policy.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        env:
          cache: pip
        with:
          python-version: '3.14'
""",
    )

    assert check_protected_workflow_caches(tmp_path) == []


def test_protected_workflow_cache_policy_uses_relative_job_indentation(tmp_path: Path) -> None:
    """Formatting-only job indentation cannot disable the protected policy.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs:
    publish:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/setup-python@v7
          with:
            cache: pip
""",
    )

    findings = check_protected_workflow_caches(tmp_path)

    assert len(findings) == len(PROTECTED_PUBLICATION_WORKFLOWS)


def test_protected_workflow_cache_policy_rejects_dynamic_cache_input(tmp_path: Path) -> None:
    """A nonempty expression is conservatively treated as cache-enabled.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        with:
          cache: ${{ matrix.cache }}
""",
    )

    findings = check_protected_workflow_caches(tmp_path)

    assert len(findings) == len(PROTECTED_PUBLICATION_WORKFLOWS)


def test_protected_workflow_cache_policy_accepts_wider_with_indentation(tmp_path: Path) -> None:
    """Direct action inputs are parsed independent of indentation width.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        with:
            cache: pip
""",
    )

    assert len(check_protected_workflow_caches(tmp_path)) == len(PROTECTED_PUBLICATION_WORKFLOWS)


def test_protected_workflow_cache_policy_accepts_indentless_steps(tmp_path: Path) -> None:
    """A valid indentless step sequence remains covered by policy.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/setup-python@v7
      with:
        cache: pip
""",
    )

    assert len(check_protected_workflow_caches(tmp_path)) == len(PROTECTED_PUBLICATION_WORKFLOWS)


def test_protected_workflow_cache_policy_accepts_bare_step_markers(tmp_path: Path) -> None:
    """A bare sequence marker cannot hide a setup-python cache input.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(
        tmp_path,
        """permissions: read-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      -
        uses: actions/setup-python@v7
        with:
          cache: pip
""",
    )

    assert len(check_protected_workflow_caches(tmp_path)) == len(PROTECTED_PUBLICATION_WORKFLOWS)


def test_protected_workflow_cache_policy_ignores_ordinary_ci(tmp_path: Path) -> None:
    """Ordinary CI cache policy remains outside protected publication checks.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    write_protected_workflows(tmp_path, "jobs: {}\n")
    ordinary = tmp_path / ".github/workflows/ci.yml"
    ordinary.write_text(
        """permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        with:
          python-version: '3.14'
          cache: pip
""",
        encoding="utf-8",
    )

    assert check_protected_workflow_caches(tmp_path) == []


def write_spark_worker_agent(
    root: Path,
    *,
    values: dict[str, str] | None = None,
    description: str = "Fast worker for focused Atlaso tasks.",
    instructions: str | None = None,
    sandbox_mode: str | None = None,
    tools: list[str] | None = None,
    approval_policy: str | None = None,
    extra_key: str | None = None,
) -> None:
    """Persist a Spark worker fixture.

    Args:
        root: Repository or filesystem root searched by the operation.
        values: Required scalar values to override for the fixture.
        description: Human-facing agent description.
        instructions: Developer instructions or the required marker set by default.
        sandbox_mode: Optional sandbox override used to exercise inheritance checks.
        tools: Optional tool override used to exercise inheritance checks.
        approval_policy: Optional approval override used to exercise inheritance checks.
        extra_key: Optional unsupported key used to exercise the exact allowlist.
    """
    config_values = {**SPARK_WORKER_REQUIRED_VALUES, **(values or {})}
    instruction_text = instructions or "\n".join(
        SPARK_WORKER_REQUIRED_INSTRUCTION_MARKERS
    )
    path = root / SPARK_WORKER_AGENT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f'name = "{config_values["name"]}"',
        f'description = "{description}"',
        f'model = "{config_values["model"]}"',
        (
            'model_reasoning_effort = '
            f'"{config_values["model_reasoning_effort"]}"'
        ),
    ]
    if sandbox_mode is not None:
        lines.append(f'sandbox_mode = "{sandbox_mode}"')
    if tools is not None:
        quoted_tools = ", ".join(f'"{tool}"' for tool in tools)
        lines.append(f"tools = [{quoted_tools}]")
    if approval_policy is not None:
        lines.append(f'approval_policy = "{approval_policy}"')
    if extra_key is not None:
        lines.append(f'{extra_key} = "unexpected"')
    lines.extend(("", 'developer_instructions = """', instruction_text, '"""'))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_merge_hold_directions_preserves_qualified_hold() -> None:
    """Verify a temporal qualifier does not hide an explicit merge hold."""
    assert merge_hold_directions(
        "Implement issue #602, but do not merge for now."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_preserves_hold_first_explanation() -> None:
    """Verify discussion words after a hold-first directive cannot hide it."""
    assert merge_hold_directions(
        "Do not merge because I need to explain the result."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_preserves_direct_hold_request() -> None:
    """Verify a present-tense user request remains an explicit hold."""
    assert merge_hold_directions(
        "I ask that you do not merge this pull request."
    ) == {"do not merge": "add"}
    assert merge_hold_directions(
        "I decided: do not merge this pull request."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_preserves_branch_targeted_hold() -> None:
    """Verify branch delivery remains a pull-request merge target."""
    assert merge_hold_directions(
        "Implement issue #602, but do not merge this branch."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_recognizes_merge_deferral() -> None:
    """Verify explicit deferrals are holds while CI gates remain resumable."""
    for instruction in (
        "Implement issue #602, but hold off on merging.",
        "Implement issue #602, but defer the merge.",
        "Implement issue #602, but refrain from merging.",
        "Implement issue #602, but wait before merging.",
    ):
        assert merge_hold_directions(instruction) == {"do not merge": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but merge only after CI passes."
    ) == {}
    assert merge_hold_directions(
        "Implement issue #602, but only merge after CI passes."
    ) == {}


def test_merge_hold_directions_recognizes_never_merge() -> None:
    """Verify never-merge wording preserves the permanent merge hold."""
    assert merge_hold_directions(
        "Implement issue #602, but never merge this pull request."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_preserves_shared_active_task_hold() -> None:
    """Verify another-PR wording cannot erase an active-task hold."""
    assert merge_hold_directions(
        "Do not merge this pull request or another PR #621."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_preserves_other_pr_reason() -> None:
    """Verify an unrelated PR used as rationale cannot erase this task's hold."""
    assert merge_hold_directions(
        "Do not merge this pull request because another PR #621 is pending."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_ignores_application_leave_open_object() -> None:
    """Verify application connection state cannot create a PR hold."""
    assert merge_hold_directions(
        "Implement keepalive support and leave open the connection."
    ) == {}


def test_merge_hold_directions_ignores_approval_state_feature() -> None:
    """Verify approval-state feature naming cannot create a task hold."""
    assert merge_hold_directions(
        "Implement support for a wait for approval state in the scheduler."
    ) == {}


def test_merge_hold_directions_binds_withdrawal_verb_to_hold() -> None:
    """Verify feature-oriented remove wording cannot withdraw an active hold."""
    assert merge_hold_directions(
        "Implement a remove control for the do not merge hold.",
        active_holds=("do not merge",),
    ) == {"do not merge": "add"}


def test_merge_hold_directions_accepts_current_withdrawal_adverb() -> None:
    """Verify current adverbs preserve an explicit withdrawal's meaning."""
    assert merge_hold_directions(
        "The do not merge hold is hereby withdrawn.",
        active_holds=("do not merge",),
    ) == {"do not merge": "remove"}


def test_merge_hold_directions_accepts_passive_withdrawal() -> None:
    """Verify passive withdrawal verbs remove an active hold."""
    assert merge_hold_directions(
        "The do not merge hold is lifted.",
        active_holds=("do not merge",),
    ) == {"do not merge": "remove"}


def test_merge_hold_directions_recognizes_owner_approval() -> None:
    """Verify possessive approval wording remains an explicit hold."""
    assert merge_hold_directions(
        "Implement issue #602, but wait for my approval before merging."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but wait for approval from the maintainer before merging."
    ) == {"wait for approval": "add"}


def test_merge_hold_directions_recognizes_first_person_approval() -> None:
    """Verify active first-person approval conditions remain explicit holds."""
    assert merge_hold_directions(
        "Implement issue #602, but wait until I approve."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but merge only after I approve."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but merge only if I approve."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but merge only after my approval."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but merge only after the maintainer approves."
    ) == {"wait for approval": "add"}


def test_merge_hold_directions_recognizes_equivalent_permission() -> None:
    """Verify equivalent current permissions withdraw active holds."""
    for instruction in (
        "Merge now.",
        "You can merge now.",
        "Go ahead and merge.",
        "Proceed with the merge now.",
    ):
        assert merge_hold_directions(
            instruction,
            active_holds=("do not merge",),
        ) == {"do not merge": "remove"}
    assert merge_hold_directions(
        "Do not merge now.", active_holds=("do not merge",)
    ) == {"do not merge": "add"}
    assert merge_hold_directions(
        "You cannot merge now.", active_holds=("do not merge",)
    ) == {"do not merge": "add"}


def test_merge_hold_directions_recognizes_modal_merge_prohibitions() -> None:
    """Verify modal denials remain explicit pull-request merge holds."""
    for instruction in (
        "You must not merge this PR.",
        "You may not merge this PR.",
        "You cannot merge this PR.",
        "You should not merge this PR.",
        "You are forbidden from merging this PR.",
        "You are not allowed to merge this PR.",
        "You are not authorized to merge this PR.",
        "You do not have permission to merge this PR.",
    ):
        assert merge_hold_directions(instruction) == {"do not merge": "add"}


def test_merge_hold_directions_scopes_numbered_pr_permission() -> None:
    """Verify permission for another numbered PR cannot withdraw this task's hold."""
    assert merge_hold_directions(
        "You may merge PR #621.",
        active_holds=("do not merge",),
        active_pull_request=620,
    ) == {}
    assert merge_hold_directions(
        "You may merge PR #620.",
        active_holds=("do not merge",),
        active_pull_request=620,
    ) == {"do not merge": "remove"}
    assert merge_hold_directions(
        "You may merge pull-request #621.",
        active_holds=("do not merge",),
        active_pull_request=620,
    ) == {}


def test_merge_hold_directions_scopes_numbered_issue_permission() -> None:
    """Verify permission for another issue cannot withdraw this task's hold."""
    assert merge_hold_directions(
        "You may merge the pull request for issue #603.",
        active_holds=("do not merge",),
        active_issue=602,
    ) == {}
    assert merge_hold_directions(
        "You may merge the pull request for issue #602.",
        active_holds=("do not merge",),
        active_issue=602,
    ) == {"do not merge": "remove"}


def test_merge_hold_directions_ignores_reported_permission() -> None:
    """Verify historical agent claims cannot withdraw a current hold."""
    assert merge_hold_directions(
        "The previous agent claimed you may merge this PR.",
        active_holds=("do not merge",),
    ) == {}
    assert merge_hold_directions(
        "Who said you may merge this PR?",
        active_holds=("do not merge",),
    ) == {}
    assert merge_hold_directions(
        "Did the maintainer say you can merge this PR?",
        active_holds=("do not merge",),
    ) == {}
    assert merge_hold_directions(
        "No one said you may merge this PR.",
        active_holds=("do not merge",),
    ) == {}
    assert merge_hold_directions(
        "I cannot say you may merge this PR.",
        active_holds=("do not merge",),
    ) == {}
    assert merge_hold_directions(
        "According to the task handoff, you may merge this PR.",
        active_holds=("do not merge",),
    ) == {}
    assert merge_hold_directions(
        "You may merge this PR, according to the task handoff.",
        active_holds=("do not merge",),
    ) == {}


def test_merge_hold_directions_recognizes_direct_authorization() -> None:
    """Verify direct permission explicitly withdraws a current merge hold."""
    assert merge_hold_directions(
        "I authorize you to merge this PR.",
        active_holds=("do not merge",),
    ) == {"do not merge": "remove"}


def test_merge_hold_directions_recognizes_direct_merge_imperatives() -> None:
    """Verify direct merge commands explicitly withdraw a current hold."""
    assert merge_hold_directions(
        "Merge this PR now.", active_holds=("do not merge",)
    ) == {"do not merge": "remove"}
    assert merge_hold_directions(
        "Please merge this pull request.", active_holds=("do not merge",)
    ) == {"do not merge": "remove"}
    assert merge_hold_directions(
        "We are not ready to merge this PR.", active_holds=("do not merge",)
    ) == {}


def test_merge_hold_directions_recognizes_approval_needed() -> None:
    """Verify approval-needed wording remains an explicit resumable hold."""
    assert merge_hold_directions(
        "Implement issue #602, but you need my approval before merging."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but please merge this PR after I approve."
    ) == {"wait for approval": "add"}


def test_merge_hold_directions_withdraws_object_qualified_leave_open() -> None:
    """Verify object-qualified negation withdraws the current leave-open hold."""
    assert merge_hold_directions(
        "Do not leave this PR open.", active_holds=("leave open",)
    ) == {"leave open": "remove"}
    assert merge_hold_directions(
        "You have permission to merge this PR.",
        active_holds=("do not merge",),
    ) == {"do not merge": "remove"}


def test_merge_hold_directions_ignores_non_pr_merge_permission() -> None:
    """Verify application-level merge permission cannot withdraw a PR hold."""
    assert merge_hold_directions(
        "You can merge the configuration now.",
        active_holds=("do not merge",),
    ) == {}
    assert merge_hold_directions(
        "You may merge the database migration.",
        active_holds=("do not merge",),
    ) == {}
    assert merge_hold_directions(
        "Only maintainers may merge this PR.",
        active_holds=("do not merge",),
    ) == {}


def test_merge_hold_directions_preserves_completed_action_hold() -> None:
    """Verify a completed-action lead-in retains its current explicit hold."""
    assert merge_hold_directions(
        "After I reviewed the status, do not merge this PR."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_preserves_merge_destination_hold() -> None:
    """Verify a named code-merge destination remains a pull-request hold."""
    assert merge_hold_directions(
        "Implement issue #602, but do not merge into main."
    ) == {"do not merge": "add"}


def test_merge_hold_directions_ignores_conditional_future_hold() -> None:
    """Verify a future condition does not restate an active hold unconditionally."""
    assert merge_hold_directions("If the user asks, do not merge this PR.") == {}


def test_merge_hold_directions_preserves_long_conditional_permission() -> None:
    """Verify a long conditional prefix cannot withdraw an active hold."""
    assert merge_hold_directions(
        "If the maintainer approves the final updated validation report, "
        "you can merge now.",
        active_holds=("do not merge",),
    ) == {}


def test_merge_hold_directions_recognizes_this_pull_request_hold() -> None:
    """Verify this-pull-request wording remains an explicit leave-open hold."""
    assert merge_hold_directions(
        "Implement issue #602, but keep this pull request open."
    ) == {"leave open": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but keep this pull request unmerged."
    ) == {"leave open": "add"}


def test_merge_hold_directions_recognizes_hyphenated_pull_request_holds() -> None:
    """Verify common hyphenated pull-request wording preserves every hold type."""
    assert merge_hold_directions("Do not merge this pull-request.") == {
        "do not merge": "add"
    }
    assert merge_hold_directions("Keep this pull-request open.") == {
        "leave open": "add"
    }
    assert merge_hold_directions("Only submit this pull-request.") == {
        "pr only": "add"
    }


def test_merge_hold_directions_recognizes_wait_for_ci_condition() -> None:
    """Verify waiting for CI remains a resumable gate, not a permanent hold."""
    assert merge_hold_directions(
        "Implement issue #602, but wait for CI to pass before merging."
    ) == {}


def test_merge_hold_directions_recognizes_plain_approval_condition() -> None:
    """Verify plain merge-after-approval wording remains a hold."""
    assert merge_hold_directions(
        "Implement issue #602, but merge after the maintainer approves."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but wait for the maintainer to approve before merging."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but wait for approval before deploying to staging."
    ) == {}
    assert merge_hold_directions(
        "Implement issue #602, but wait for approval to merge."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but merge only after the code owner approves."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but wait for code owner approval before merging."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but do not merge without my approval."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but do not merge prior to maintainer approval."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Implement issue #602, but merge after CI passes."
    ) == {}
    assert merge_hold_directions(
        "Implement issue #602, but wait for security review before merging."
    ) == {}
    assert merge_hold_directions(
        "Implement issue #602, but merge only after security review passes."
    ) == {}
    assert merge_hold_directions(
        "Implement issue #602, but merge only after QA review passes."
    ) == {}


def test_source_authority_excludes_no_commit_or_push_delivery() -> None:
    """Verify implementation requests that forbid delivery remain ineligible."""
    assert not source_has_default_merge_authority(
        ("Implement issue #602, but do not push any changes.",)
    )
    assert not source_has_default_merge_authority(
        ("Implement issue #602, but do not commit any changes.",)
    )


def test_object_qualified_auto_merge_denial_is_not_a_manual_hold() -> None:
    """Verify disabling auto-merge does not block guarded manual merge."""
    assert merge_hold_directions(
        "Do not merge this pull request automatically."
    ) == {}
    assert merge_hold_directions(
        "Do not merge this pull request via auto-merge."
    ) == {}


def test_merge_hold_directions_keeps_active_task_after_unrelated_clause() -> None:
    """Verify another PR cannot hide a later active-task hold."""
    assert merge_hold_directions(
        "For another PR, do not merge, but leave this pull request open."
    ) == {"leave open": "add"}


def test_generated_merge_decision_questions_are_not_affirmative() -> None:
    """Verify decision-only prompts do not manufacture merge authority."""
    assert not has_affirmative_default_merge_authority(
        "Determine whether to complete the guarded merge."
    )
    assert not has_affirmative_default_merge_authority(
        "Decide whether to complete the guarded merge."
    )
    assert not has_affirmative_default_merge_authority(
        "If the user asks, complete the guarded merge."
    )
    for verb in ("Evaluate", "Check", "Confirm"):
        assert not has_affirmative_default_merge_authority(
            f"{verb} whether to complete the guarded merge."
        )
    assert not has_affirmative_default_merge_authority(
        "If asked, complete the guarded merge."
    )
    assert not has_affirmative_default_merge_authority(
        "Complete the guarded merge if requested."
    )
    assert not has_affirmative_default_merge_authority(
        "Do you want me to complete the guarded merge?"
    )


def test_source_authority_excludes_patch_review() -> None:
    """Verify reviewing an existing patch is review-only work."""
    assert not source_has_default_merge_authority(
        ("Review the patch and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Review the proposed fix for issue #602 and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Can you explain how to fix issue #602?",)
    )
    assert not source_has_default_merge_authority(
        ("Is the fix for issue #602 correct?",)
    )
    assert not source_has_default_merge_authority(
        ("Evaluate the fix and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Check the implementation for bugs and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Verify the implementation and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Test the implementation and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Perform a code review of the implementation and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Review this implementation and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Summarize the implementation for issue #602.",)
    )
    assert not source_has_default_merge_authority(
        (
            "Implement issue #602. Instead, review the implementation and "
            "report findings.",
        )
    )
    assert not source_has_default_merge_authority(
        (
            "Implement issue #602. Review PR #602 instead and report findings.",
        )
    )
    assert not source_has_default_merge_authority(
        ("Review the implementation; do not modify it.",)
    )
    assert not source_has_default_merge_authority(
        ("Do not add any code; review the implementation and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Fix issue #602, but do not create a pull request.",)
    )
    assert not source_has_default_merge_authority(
        ("Fix issue #602, but do not open a pull request.",)
    )
    assert not source_has_default_merge_authority(
        ("Implement issue #602. Switch to review PR #602 and report findings.",)
    )
    assert not source_has_default_merge_authority(("Create a plan for issue #602.",))
    assert not source_has_default_merge_authority(("Update me on issue #602.",))
    assert not source_has_default_merge_authority(
        ("The implementation for issue #602 is not authorized.",)
    )


def test_source_authority_honors_later_stop_work() -> None:
    """Verify a later explicit stop-work instruction revokes eligibility."""
    assert not source_has_default_merge_authority(
        ("Implement issue #602.", "Stop work; only explain the failure.")
    )
    assert not source_has_default_merge_authority(
        ("Implement issue #602.", "Please stop work; only explain the failure.")
    )
    assert not source_has_default_merge_authority(
        ("Implement issue #602.", "Stop working on this task.")
    )
    assert not source_has_default_merge_authority(
        ("Implement issue #602.", "Cancel that request.")
    )
    assert source_has_default_merge_authority(
        ("Implement issue #602.", "Please stop work if CI fails.")
    )
    assert not source_has_default_merge_authority(
        (
            "Implement issue #602.",
            "Stop work on this task. Summarize the implementation.",
        )
    )
    assert not source_has_default_merge_authority(
        (
            "Implement issue #602.",
            "Stop work on this task. The implementation is incomplete.",
        )
    )


def test_source_authority_excludes_planning_a_fix() -> None:
    """Verify planning-only fix language does not grant implementation authority."""
    assert not source_has_default_merge_authority(("Plan a fix for issue #602.",))
    assert not source_has_default_merge_authority(
        ("Plan an implementation for issue #602.",)
    )


def test_source_authority_excludes_possessive_review_targets() -> None:
    """Verify possessive fix and patch reviews remain review-only."""
    assert not source_has_default_merge_authority(
        ("Review my fix for issue #602 and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Review our patch for issue #602 and report findings.",)
    )
    assert not source_has_default_merge_authority(
        ("Implement issue #602.", "Actually, just review it and report findings.")
    )


def test_merge_hold_directions_recognizes_indefinite_pr_only_instruction() -> None:
    """Verify indefinite articles preserve an explicit PR-only hold."""
    assert merge_hold_directions("Only open a pull request for issue #602.") == {
        "pr only": "add"
    }
    assert merge_hold_directions("Only create a PR for issue #602.") == {
        "pr only": "add"
    }
    assert merge_hold_directions("Only submit a pull request for issue #602.") == {
        "pr only": "add"
    }
    assert merge_hold_directions("Only prepare a PR for issue #602.") == {
        "pr only": "add"
    }


def test_merge_hold_directions_classifies_approval_until_as_resumable() -> None:
    """Verify an approval-until condition is the resumable approval hold."""
    assert merge_hold_directions(
        "Do not merge until the maintainer approves."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Do not merge unless the maintainer approves."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions(
        "Do not merge before the maintainer approves."
    ) == {"wait for approval": "add"}
    assert merge_hold_directions("Do not merge until approved.") == {
        "wait for approval": "add"
    }
    assert merge_hold_directions("Keep this PR open until I approve.") == {
        "wait for approval": "add"
    }
    assert merge_hold_directions("PR only until I approve.") == {
        "wait for approval": "add"
    }


def test_generated_authority_rejects_absence_of_authority() -> None:
    """Verify generated authority denials are not affirmative merge guidance."""
    assert not has_affirmative_default_merge_authority(
        "There is no authority to complete the guarded merge."
    )
    assert not has_affirmative_default_merge_authority(
        "Can I complete the guarded merge?"
    )
    assert not has_affirmative_default_merge_authority(
        "The phrase “Complete the guarded merge” is prohibited."
    )


def test_source_authority_excludes_diagnostic_how_to_questions() -> None:
    """Verify how-to and what-is-needed questions remain diagnostic."""
    assert not source_has_default_merge_authority(("How should we fix issue #602?",))
    assert not source_has_default_merge_authority(
        ("What is needed to implement issue #602?",)
    )
    assert not source_has_default_merge_authority(
        ("Please investigate how to fix issue #602.",)
    )
    assert not source_has_default_merge_authority(
        ("We discussed how to fix issue #602.",)
    )


def test_generated_authority_rejects_general_permission_questions() -> None:
    """Verify general merge-authority questions are not affirmative delivery."""
    assert not has_affirmative_default_merge_authority(
        "Do we have authority to complete the guarded merge?"
    )
    assert not has_affirmative_default_merge_authority(
        "The previous agent said to complete the guarded merge."
    )


def test_source_authority_keeps_workflow_policy_subject_eligible() -> None:
    """Verify workflow terminology alone does not exclude ordinary policy work."""
    assert source_has_default_merge_authority(
        ("Update the documentation for private vulnerability remediation.",)
    )
    assert source_has_default_merge_authority(
        ("Update the documentation for external fork workflows.",)
    )
    for instruction in (
        "Prepare a pull request for issue #602.",
        "Open a pull request for issue #602.",
        "Submit a pull request for issue #602.",
        "Revert the change introduced by PR #602.",
        "Roll back the change introduced by PR #602.",
        "Refactor the parser in scripts/check_repo.py.",
        "Repair the parser in scripts/check_repo.py.",
    ):
        assert source_has_default_merge_authority((instruction,))


def test_source_authority_excludes_negated_repair() -> None:
    """Verify an explicit repair denial does not grant implementation authority."""
    assert not source_has_default_merge_authority(("Do not repair issue #602.",))


def test_source_authority_excludes_ineligible_delivery_scopes() -> None:
    """Verify fork and existing-draft implementation scopes remain ineligible."""
    assert not source_has_default_merge_authority(
        ("Implement issue #602 in a fork.",)
    )
    assert not source_has_default_merge_authority(
        ("Fix the tests on draft PR #602.",)
    )
    assert not source_has_default_merge_authority(("Fix draft PR #602.",))
    assert not source_has_default_merge_authority(("Fix the draft PR #602.",))
    assert not source_has_default_merge_authority(
        ("Fix this security vulnerability.",)
    )
    assert not source_has_default_merge_authority(
        ("Implement issue #602 in my fork.",)
    )
    assert not source_has_default_merge_authority(
        ("Fix issue #602 on your fork.",)
    )


def test_source_authority_honors_coordinated_cancellation() -> None:
    """Verify same-instruction cancellation revokes implementation eligibility."""
    assert not source_has_default_merge_authority(
        ("Implement issue #602, but cancel this request.",)
    )


def test_source_authority_honors_workflow_reclassification() -> None:
    """Verify later ineligible workflow status revokes prior task authority."""
    for reclassification in (
        "This is private vulnerability remediation.",
        "The pull request is now a draft.",
        "Move the work to a fork.",
        "Convert the pull request to draft.",
        "Make this a draft PR.",
    ):
        assert not source_has_default_merge_authority(
            ("Implement issue #602.", reclassification)
        )
    assert not source_has_default_merge_authority(
        ("Implement issue #602.", "Instead, review PR #602 and report findings.")
    )


def test_generated_authority_rejects_conditional_approval() -> None:
    """Verify generated prompts cannot invent an approval prerequisite."""
    assert not has_affirmative_default_merge_authority(
        "Only if the maintainer approves, complete the guarded merge."
    )


def test_generated_authority_rejects_imperative_denial() -> None:
    """Verify negative action verbs cannot masquerade as merge authority."""
    for instruction in (
        "Skip the guarded squash merge.",
        "Avoid the guarded squash merge.",
        "Omit the guarded squash merge.",
        "Decline the guarded squash merge.",
        "Refrain from the guarded squash merge.",
        "Hold off on the guarded squash merge.",
        "Defer the guarded squash merge.",
        "Delay the guarded squash merge.",
        "Postpone the guarded squash merge.",
        "Pause the guarded squash merge.",
    ):
        assert not has_affirmative_default_merge_authority(instruction)

    assert not has_affirmative_default_merge_authority(
        "Plan the guarded squash merge, but do not execute it."
    )
    assert not has_affirmative_default_merge_authority(
        "Consider the guarded squash merge."
    )
    assert not has_affirmative_default_merge_authority(
        "This task lacks authority to complete the guarded merge."
    )
    assert not has_affirmative_default_merge_authority(
        "Ask whether to complete the guarded merge."
    )


def test_generated_permission_cannot_withdraw_source_hold(tmp_path: Path) -> None:
    """Verify agent-authored permission cannot remove a source hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "generated permission withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement issue #602, but do not merge.",
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": (
                            "Do not merge this pull request; you may merge now."
                        ),
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture generated permission withdrawal drops an "
        "explicit hold: do not merge"
    )


def test_generated_conditional_hold_cannot_weaken_source_hold(tmp_path: Path) -> None:
    """Verify generated text cannot make an unconditional source hold conditional.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "conditional generated hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement issue #602, but do not merge.",
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": "If the user asks, do not merge this PR.",
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture conditional generated hold drops an explicit "
        "hold: do not merge"
    )


def test_generated_withdrawal_cannot_invent_source_hold(tmp_path: Path) -> None:
    """Verify generated text cannot withdraw a hold absent from source.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "invented generated withdrawal",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement issue #602."}],
                        "generated": (
                            "The earlier do not merge instruction is withdrawn. "
                            "Complete the guarded merge."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture invented generated withdrawal withdraws a "
        "nonexistent source hold: do not merge"
    )


def test_spark_worker_agent_accepts_required_contract(tmp_path: Path) -> None:
    """Verify that the project Spark worker contract is accepted.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_spark_worker_agent(tmp_path)

    assert check_spark_worker_agent(tmp_path) == []


def test_spark_worker_agent_rejects_missing_file(tmp_path: Path) -> None:
    """Verify that the project Spark worker must remain checked in.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    findings = check_spark_worker_agent(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == tmp_path / SPARK_WORKER_AGENT_PATH
    assert findings[0].message == "required Spark worker agent is missing or unreadable"


def test_spark_worker_agent_rejects_invalid_toml(tmp_path: Path) -> None:
    """Verify that malformed custom-agent configuration fails clearly.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / SPARK_WORKER_AGENT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('name = "unterminated\n', encoding="utf-8")

    findings = check_spark_worker_agent(tmp_path)

    assert len(findings) == 1
    assert findings[0].message.startswith("invalid Spark worker TOML:")


def test_spark_worker_agent_rejects_incorrect_required_values(
    tmp_path: Path,
) -> None:
    """Verify that the worker keeps its stable identity, model, and effort.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    replacements = {
        "name": "other_worker",
        "model": "gpt-5.6-luna",
        "model_reasoning_effort": "low",
    }

    for key, replacement in replacements.items():
        write_spark_worker_agent(tmp_path, values={key: replacement})

        findings = check_spark_worker_agent(tmp_path)

        assert len(findings) == 1
        assert findings[0].message == (
            f"Spark worker {key} must equal {SPARK_WORKER_REQUIRED_VALUES[key]!r}"
        )


def test_spark_worker_agent_rejects_blank_required_text(tmp_path: Path) -> None:
    """Verify that the agent description and instructions remain substantive.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_spark_worker_agent(tmp_path, description="", instructions=" ")

    findings = check_spark_worker_agent(tmp_path)

    assert {finding.message for finding in findings} == {
        "Spark worker description must be non-empty",
        "Spark worker developer_instructions must be non-empty",
    }


def test_spark_worker_agent_rejects_missing_safety_instruction(
    tmp_path: Path,
) -> None:
    """Verify that the worker cannot lose a required scope restriction.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    missing_marker = "Do not make architecture decisions."
    instructions = "\n".join(
        marker
        for marker in SPARK_WORKER_REQUIRED_INSTRUCTION_MARKERS
        if marker != missing_marker
    )
    write_spark_worker_agent(tmp_path, instructions=instructions)

    findings = check_spark_worker_agent(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "required Spark worker instruction marker is missing: " + missing_marker
    )


def test_spark_worker_agent_rejects_sandbox_override(tmp_path: Path) -> None:
    """Verify that the worker inherits the parent permission mode.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_spark_worker_agent(tmp_path, sandbox_mode="workspace-write")

    findings = check_spark_worker_agent(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == "Spark worker must inherit the parent sandbox mode"


def test_spark_worker_agent_rejects_tool_override(tmp_path: Path) -> None:
    """Verify that the worker inherits the parent tool capabilities.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_spark_worker_agent(tmp_path, tools=[])

    findings = check_spark_worker_agent(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == "Spark worker must inherit the parent tools"


def test_spark_worker_agent_rejects_approval_policy_override(tmp_path: Path) -> None:
    """Verify that the worker inherits the parent approval policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_spark_worker_agent(tmp_path, approval_policy="never")

    findings = check_spark_worker_agent(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == "Spark worker must inherit the parent approval policy"


def test_spark_worker_agent_rejects_any_unsupported_key(tmp_path: Path) -> None:
    """Verify that future top-level overrides fail closed.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    extra_key = "future_permission_override"
    assert extra_key not in SPARK_WORKER_ALLOWED_KEYS
    write_spark_worker_agent(tmp_path, extra_key=extra_key)

    findings = check_spark_worker_agent(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "Spark worker contains unsupported top-level key: " + extra_key
    )


def test_deployment_assets_are_checkable_text() -> None:
    """Verify that every protected deployment asset class enters repository checks."""
    paths = (
        Path("image/vmware-workstation/atlaso-photon.pkr.hcl"),
        Path("image/common/systemd/atlaso-worker.service"),
        Path("image/common/systemd/atlaso-console-manager.conf"),
        Path("image/common/systemd/nginx-atlaso-data-disks.conf"),
        Path("image/common/sudoers.d/atlaso-helper"),
    )

    assert all(is_checkable(path) for path in paths)
    assert all(len(collect_files([str(path)])) == 1 for path in paths)


def test_virtualization_legacy_gate_rejects_retired_paths_and_qcow2_exporter(tmp_path: Path) -> None:
    """Repository checks fail closed on each retired virtualization surface.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    retired = tmp_path / "image/hyperv"
    retired.mkdir(parents=True)
    docs = tmp_path / "docs"
    docs.mkdir()
    retired_reference = "scripts/windows" + "/hyperv/run-smoke-test.ps1"
    (docs / "stale.md").write_text(f"See {retired_reference}.\n", encoding="utf-8")
    exporter = tmp_path / "scripts/windows/virtualization"
    exporter.mkdir(parents=True)
    (exporter / "legacy.txt").write_text("photon-os.qcow2\n", encoding="utf-8")
    (exporter / "legacy.ps1").write_text("$script:AllowedTargetNames = @('hyperv', 'kvm')\n", encoding="utf-8")
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("run: ./tests/powershell/Test-AtlasoHyperVSecureString.ps1\n", encoding="utf-8")

    findings = check_virtualization_legacy(tmp_path)

    assert any("retired Hyper-V development" in finding.message for finding in findings)
    assert any("retired virtualization reference" in finding.message for finding in findings)
    assert any("standalone QCOW2 release marker" in finding.message for finding in findings)
    assert any("standalone multi-target exporter marker" in finding.message for finding in findings)
    assert any("retired virtualization test command" in finding.message for finding in findings)


def write_policy_files(root: Path) -> None:
    """Persist policy files.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    for relative_path, markers in REQUIRED_POLICY_MARKERS.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        section_markers = TERMINAL_CLEANUP_SECTION_MARKERS.get(relative_path, ())
        section_anchor = TERMINAL_CLEANUP_SECTION_ANCHORS.get(relative_path)
        monitoring_markers = SCHEDULED_PR_MONITORING_SECTION_MARKERS.get(
            relative_path, ()
        )
        monitoring_anchor = SCHEDULED_PR_MONITORING_SECTION_ANCHORS.get(
            relative_path
        )
        monitoring_end_anchor = SCHEDULED_PR_MONITORING_SECTION_END_ANCHORS.get(
            relative_path
        )
        authority_markers = DEFAULT_MERGE_AUTHORITY_SECTION_MARKERS.get(
            relative_path, ()
        )
        authority_anchor = DEFAULT_MERGE_AUTHORITY_SECTION_ANCHORS.get(relative_path)
        other_markers = tuple(
            marker
            for marker in markers
            if marker not in section_markers
            and marker != section_anchor
            and marker not in monitoring_markers
            and marker != monitoring_anchor
            and marker not in authority_markers
            and marker != authority_anchor
        )
        policy_lines = list(other_markers)
        if monitoring_anchor is not None:
            monitoring_prefix = "" if monitoring_anchor.startswith("#") else "  "
            policy_lines.extend(
                (
                    monitoring_anchor,
                    *(monitoring_prefix + marker for marker in monitoring_markers),
                    monitoring_end_anchor or "- following monitoring policy",
                )
            )
        if authority_anchor is not None:
            authority_prefix = "" if authority_anchor.startswith("#") else "  "
            authority_heading = (
                ()
                if authority_anchor == monitoring_end_anchor
                else (authority_anchor,)
            )
            policy_lines.extend(
                (
                    *authority_heading,
                    *(authority_prefix + marker for marker in authority_markers),
                    "- following merge authority policy",
                )
            )
        if section_anchor is not None:
            content_prefix = "" if section_anchor.startswith("#") else "  "
            non_ordered_markers = tuple(
                content_prefix + marker
                for marker in section_markers
                if marker not in ORDERED_TERMINAL_CLEANUP_MARKERS[relative_path]
            )
            order_lines = (
                TERMINAL_CLEANUP_ORDER_LINES
                if section_anchor.startswith("#")
                else tuple(f"  {line}" for line in TERMINAL_CLEANUP_ORDER_LINES)
            )
            policy_lines.extend(
                (
                    section_anchor,
                    *non_ordered_markers,
                    content_prefix + TERMINAL_CLEANUP_ORDER_ANCHOR,
                    "",
                    *order_lines,
                    "- following policy",
                )
            )
        path.write_text("\n".join(policy_lines), encoding="utf-8")


def test_agent_policy_gate_accepts_all_required_entry_points(tmp_path: Path) -> None:
    """Verify that agent policy gate accepts all required entry points.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)

    assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_rejects_missing_marker(tmp_path: Path) -> None:
    """Verify that agent policy gate rejects missing marker.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace("delegating agent", ""),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: delegating agent"
    )


def test_agent_policy_gate_rejects_missing_spark_delegation_policy(
    tmp_path: Path,
) -> None:
    """Verify that Sol and Spark responsibilities remain in canonical policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "## Sol and Spark Delegation", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: ## Sol and Spark Delegation"
    )


def test_agent_policy_gate_rejects_missing_spark_model_substitution_policy(
    tmp_path: Path,
) -> None:
    """Verify that Spark fallback never substitutes another model.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "never substitutes another model", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: never substitutes another model"
    )


def test_agent_policy_gate_rejects_missing_task_title_traceability(
    tmp_path: Path,
) -> None:
    """Verify that the agent policy gate requires task title traceability.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "## Codex Task Title Traceability", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: "
        "## Codex Task Title Traceability"
    )


def test_agent_policy_gate_rejects_missing_task_title_capability_fallback(
    tmp_path: Path,
) -> None:
    """Verify that task title traceability remains capability-aware.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "### Unsupported title controls", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: "
        "### Unsupported title controls"
    )


def test_agent_policy_gate_rejects_missing_task_title_capability_guard(
    tmp_path: Path,
) -> None:
    """Verify that task title renaming requires supported controls.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "### Supported title controls", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: "
        "### Supported title controls"
    )


def test_agent_policy_gate_rejects_missing_schema_constrained_reporting(
    tmp_path: Path,
) -> None:
    """Verify that constrained outputs retain their schema boundary.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "### Schema-constrained reporting", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: "
        "### Schema-constrained reporting"
    )


def test_agent_policy_gate_rejects_missing_extended_merge_description(
    tmp_path: Path,
) -> None:
    """Verify that agent-performed squash merges require a detailed body.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "### Extended merge descriptions", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: "
        "### Extended merge descriptions"
    )


def test_agent_policy_gate_rejects_missing_pr_follow_through_contract(
    tmp_path: Path,
) -> None:
    """Verify that every agent entry point retains pull-request follow-through.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_markers = {
        Path("AGENTS.md"): "### Focused local validation and pull-request follow-through",
        Path("CONTRIBUTING.md"): "### Automated pull-request follow-through",
        Path(".github/copilot-instructions.md"): (
            "complete Python test suite belongs to GitHub CI"
        ),
        Path(".github/pull_request_template.md"): (
            "each post-opening pushed commit received one `@codex review` request"
        ),
        Path("docs/contribute/agent-policies.md"): (
            "### Focused local validation and pull-request follow-through"
        ),
    }

    for relative_path, marker in required_entry_markers.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_agent_policy_gate_rejects_missing_scheduled_pr_monitoring_contract(
    tmp_path: Path,
) -> None:
    """Verify that every agent entry point retains scheduled PR monitoring.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    shared_markers = (
        "current-task heartbeat",
        "four minutes",
        "persistent GitHub polling loops",
        "seen comment and review IDs",
        "delivery-complete merge-ready",
        "final bounded readback",
        "delete the exact current-task heartbeat",
        "linked-issue closure",
        "current `origin/main` reachability",
        "applicable post-merge workflow verification",
        "unmerged closed",
        "delivery-complete",
        "never delete unrelated",
        "already absent",
        "terminal evidence",
        "resumable holds",
        "ambiguous ownership",
        "exact retry condition",
        "never merely paused",
    )
    required_entry_markers = {
        Path("AGENTS.md"): (
            *shared_markers,
            "top-level pull-request comments",
            "inline review comments",
            "review submissions",
        ),
        Path("CONTRIBUTING.md"): (
            *shared_markers,
            "top-level pull-request comments",
            "inline review comments",
            "review submissions",
        ),
        Path(".github/copilot-instructions.md"): (
            *shared_markers,
            "top-level pull-request comments",
            "inline review comments",
            "review submissions",
        ),
        Path(".github/pull_request_template.md"): (
            *shared_markers,
            "top-level pull-request comment",
            "inline review comment",
            "review submission",
        ),
        Path("docs/contribute/agent-policies.md"): (
            *shared_markers,
            "top-level pull-request comments",
            "inline review comments",
            "review submissions",
        ),
    }

    for relative_path, markers in required_entry_markers.items():
        for marker in markers:
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            path.write_text(
                path.read_text(encoding="utf-8").replace(marker, ""),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert any(
                finding.path == path
                and finding.message
                == f"required agent policy marker is missing: {marker}"
                for finding in findings
            )


def test_agent_policy_gate_scopes_heartbeat_markers_to_monitoring_section(
    tmp_path: Path,
) -> None:
    """Verify that duplicate cleanup prose cannot satisfy heartbeat policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = "already absent"
    for relative_path in SCHEDULED_PR_MONITORING_SECTION_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        path.write_text(
            marker + "\n" + text.replace(marker, "", 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "pull-request monitoring section marker is missing: " + marker
        )


def test_agent_policy_gate_rejects_missing_default_merge_authorization(
    tmp_path: Path,
) -> None:
    """Verify that every agent entry point retains default merge authorization.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_markers = {
        Path("AGENTS.md"): "### Default merge authorization",
        Path("CONTRIBUTING.md"): "### Default merge authorization",
        Path(".github/copilot-instructions.md"): "Default merge authorization",
        Path(".github/pull_request_template.md"): "Default merge authorization",
        Path("docs/contribute/agent-policies.md"): (
            "### Default merge authorization"
        ),
    }

    for relative_path, marker in required_entry_markers.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_agent_policy_gate_scopes_merge_authority_provenance_to_its_section(
    tmp_path: Path,
) -> None:
    """Verify authority provenance cannot be satisfied by unrelated prose.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = "stale memory"
    for relative_path in DEFAULT_MERGE_AUTHORITY_SECTION_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        path.write_text(
            marker + "\n" + text.replace(marker, "", 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "default merge authority section marker is missing: " + marker
        )


def test_merge_authority_transfer_repository_fixtures_pass() -> None:
    """Verify the checked-in delegation and heartbeat examples preserve authority."""
    repository_root = Path(__file__).resolve().parents[1]

    assert check_merge_authority_transfer_fixtures(repository_root) == []


def test_merge_authority_transfer_rejects_invented_delegation_hold(
    tmp_path: Path,
) -> None:
    """Verify delegation text cannot manufacture a merge hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "invented delegation hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {"text": "Implement and deliver the change."}
                        ],
                        "generated": "Implement it, but do not merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture invented delegation hold invents a hold: do not merge"
    )


def test_merge_authority_transfer_rejects_dropped_heartbeat_hold(
    tmp_path: Path,
) -> None:
    """Verify heartbeat text retains a later explicit merge hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "dropped heartbeat hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement the change and wait for approval before "
                                    "merging."
                                ),
                                "add_holds": ["wait for approval"],
                            }
                        ],
                        "generated": "Merge when the checks pass.",
                        "expected_holds": ["wait for approval"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture dropped heartbeat hold drops an explicit hold: "
        "wait for approval"
    )


def test_merge_authority_transfer_rejects_merge_instruction_with_active_hold(
    tmp_path: Path,
) -> None:
    """Verify generated text cannot preserve and violate a hold simultaneously.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "contradictory active hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement the change, but do not merge.",
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": (
                            "Do not merge. Continue through guarded squash merge."
                        ),
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture contradictory active hold asserts merge authority "
        "while an explicit hold is active"
    )


def test_merge_authority_transfer_rejects_neutral_default_prompt(
    tmp_path: Path,
) -> None:
    """Verify a no-hold generated prompt affirmatively retains default authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "neutral default prompt",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement the issue completely."}],
                        "generated": "Watch the pull request until it is ready.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture neutral default prompt omits affirmative default authority"
    )


def test_merge_authority_transfer_rejects_generated_authority_denial(
    tmp_path: Path,
) -> None:
    """Verify a generated denial cannot satisfy affirmative default authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "generated authority denial",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement issue #602."}],
                        "generated": (
                            "There is no authority to complete the guarded merge."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture generated authority denial omits affirmative "
        "default authority"
    )


def test_merge_authority_transfer_rejects_quoted_generated_authority_denial(
    tmp_path: Path,
) -> None:
    """Verify quoted affirmative wording cannot hide a generated denial.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "quoted generated authority denial",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement issue #602."}],
                        "generated": (
                            "The phrase “Complete the guarded merge” is prohibited."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture quoted generated authority denial omits "
        "affirmative default authority"
    )


def test_merge_authority_transfer_rejects_generated_permission_question(
    tmp_path: Path,
) -> None:
    """Verify a generated permission question cannot satisfy default authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "generated permission question",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement issue #602."}],
                        "generated": "Can I complete the guarded merge?",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture generated permission question omits affirmative "
        "default authority"
    )


def test_merge_authority_transfer_applies_structured_hold_withdrawal(
    tmp_path: Path,
) -> None:
    """Verify a later explicit withdrawal restores default merge authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "withdrawn hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement the change, but do not merge.",
                                "add_holds": ["do not merge"],
                            },
                            {
                                "text": "The earlier do not merge hold is withdrawn.",
                                "remove_holds": ["do not merge"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_applies_standalone_merge_permission(
    tmp_path: Path,
) -> None:
    """Verify an unconditional merge permission removes an active hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "standalone merge permission",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement the change, but do not merge.",
                                "add_holds": ["do not merge"],
                            },
                            {
                                "text": "You may merge now.",
                                "remove_holds": ["do not merge"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_permission_overrides_repeated_hold_text(
    tmp_path: Path,
) -> None:
    """Verify current merge permission overrides repeated stale hold wording.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "permission overrides repeated hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement the change, but do not merge.",
                                "add_holds": ["do not merge"],
                            },
                            {
                                "text": (
                                    "Ignore the previous do not merge hold; you may "
                                    "merge now."
                                ),
                                "remove_holds": ["do not merge"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_scopes_standalone_permission_to_active_task(
    tmp_path: Path,
) -> None:
    """Verify permission for another PR does not remove this task's hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "unrelated PR merge permission",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement the change, but do not merge.",
                                "add_holds": ["do not merge"],
                            },
                            {
                                "text": "You may merge now for unrelated PR #621.",
                                "remove_holds": ["do not merge"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture unrelated PR merge permission instruction 2 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_recognizes_direct_hold_removals(
    tmp_path: Path,
) -> None:
    """Verify remove, lift, and cancel directly withdraw a named hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for verb in ("Remove", "Lift", "Cancel"):
        case_root = tmp_path / verb.casefold()
        path = case_root / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "name": f"{verb.casefold()} hold",
                            "default_merge_authority": True,
                            "instructions": [
                                {
                                    "text": "Implement the change, but do not merge.",
                                    "add_holds": ["do not merge"],
                                },
                                {
                                    "text": f"{verb} the do not merge hold.",
                                    "remove_holds": ["do not merge"],
                                },
                            ],
                            "generated": "Continue through guarded squash merge.",
                            "expected_holds": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        assert check_merge_authority_transfer_fixtures(case_root) == []


def test_merge_authority_transfer_applies_coordinated_hold_withdrawal(
    tmp_path: Path,
) -> None:
    """Verify one withdrawal suffix removes every hold in its coordinated list.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "coordinated hold withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement the change, but do not merge and leave "
                                    "the pull request open."
                                ),
                                "add_holds": ["do not merge", "leave open"],
                            },
                            {
                                "text": (
                                    "The do not merge and leave open holds are withdrawn."
                                ),
                                "remove_holds": ["do not merge", "leave open"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_scopes_coordinated_withdrawal_to_active_task(
    tmp_path: Path,
) -> None:
    """Verify a coordinated withdrawal for another PR leaves active holds intact.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "unrelated coordinated withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement the change, but do not merge and leave "
                                    "the pull request open."
                                ),
                                "add_holds": ["do not merge", "leave open"],
                            },
                            {
                                "text": (
                                    "For unrelated PR #621, the do not merge and leave "
                                    "open holds are withdrawn."
                                ),
                                "remove_holds": ["do not merge", "leave open"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture unrelated coordinated withdrawal instruction 2 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_ignores_quoted_hold_discussion(
    tmp_path: Path,
) -> None:
    """Verify documentation discussing quoted hold text does not add a hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "quoted hold discussion",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    'Update the documentation explaining the "do not '
                                    'merge" hold.'
                                ),
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Preserve the do not merge hold.",
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture quoted hold discussion instruction 1 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_ignores_unquoted_hold_discussion(
    tmp_path: Path,
) -> None:
    """Verify explanatory hold references do not depend on quotation style.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "unquoted hold discussion",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement issue #602. Explain when users say do "
                                    "not merge."
                                ),
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Preserve the do not merge hold.",
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture unquoted hold discussion instruction 1 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_ignores_application_merge_objects(
    tmp_path: Path,
) -> None:
    """Verify application merge language does not create a pull-request hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "application merge object",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement a merge algorithm, but do not merge "
                                    "adjacent entries."
                                ),
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Preserve the do not merge hold.",
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture application merge object instruction 1 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_ignores_holds_for_unrelated_prs(
    tmp_path: Path,
) -> None:
    """Verify a hold targeting another PR does not constrain the active task.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "unrelated PR hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement issue #602, but do not merge unrelated "
                                    "PR #621."
                                ),
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Preserve the do not merge hold.",
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture unrelated PR hold instruction 1 hold operations "
        "do not match its text"
    )


def test_merge_authority_transfer_preserves_active_clause_in_mixed_task_text(
    tmp_path: Path,
) -> None:
    """Verify another-PR prose does not erase this task's explicit hold clause.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "mixed task active hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement issue #602 and do not merge this pull "
                                    "request; also document unrelated PR #621."
                                ),
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Preserve the explicit do not merge instruction.",
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_recognizes_no_longer_need_withdrawal(
    tmp_path: Path,
) -> None:
    """Verify present no-longer-needed wording removes an approval hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "no longer need approval",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement the change, but wait for approval.",
                                "add_holds": ["wait for approval"],
                            },
                            {
                                "text": "You no longer need to wait for approval.",
                                "remove_holds": ["wait for approval"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_rejects_mislabeled_hold_removal(
    tmp_path: Path,
) -> None:
    """Verify active hold wording cannot be recorded as a withdrawal.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "mislabeled removal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement the change, but do not merge.",
                                "remove_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture mislabeled removal instruction 1 hold operations "
        "do not match its text"
    )


def test_merge_authority_transfer_normalizes_equivalent_hold_wording(
    tmp_path: Path,
) -> None:
    """Verify a common equivalent spelling retains the explicit hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "equivalent hold",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": "Implement the change, but please don't merge.",
                                "add_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Preserve the instruction: do not merge.",
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_rejects_negated_default_authority(
    tmp_path: Path,
) -> None:
    """Verify a negated merge marker cannot satisfy default authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "negated default authority",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement the issue completely."}],
                        "generated": "Do not carry the task through guarded merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture negated default authority omits affirmative "
        "default authority"
    )


def test_merge_authority_transfer_rejects_trailing_default_authority_negation(
    tmp_path: Path,
) -> None:
    """Verify a negation after the merge marker cannot satisfy authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "trailing default authority negation",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement the issue completely."}],
                        "generated": (
                            "Default merge authority does not apply to this task."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture trailing default authority negation omits "
        "affirmative default authority"
    )


def test_merge_authority_transfer_rejects_lexical_authority_prohibitions(
    tmp_path: Path,
) -> None:
    """Verify lexical prohibitions cannot satisfy affirmative merge authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for adjective in ("forbidden", "disallowed", "prohibited"):
        case_root = tmp_path / adjective
        path = case_root / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "name": f"merge {adjective}",
                            "default_merge_authority": True,
                            "instructions": [{"text": "Implement the issue."}],
                            "generated": f"Guarded squash merge is {adjective}.",
                            "expected_holds": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        findings = check_merge_authority_transfer_fixtures(case_root)

        assert len(findings) == 1
        assert findings[0].message == (
            f"merge authority fixture merge {adjective} omits affirmative "
            "default authority"
        )


def test_merge_authority_transfer_rejects_lexical_authority_denials(
    tmp_path: Path,
) -> None:
    """Verify direct lexical denials cannot satisfy affirmative authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    generated_prompts = (
        "This task lacks default merge authority.",
        "This task has no default merge authority.",
    )
    for index, generated in enumerate(generated_prompts):
        case_root = tmp_path / str(index)
        path = case_root / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "name": f"authority denial {index}",
                            "default_merge_authority": True,
                            "instructions": [{"text": "Implement the issue."}],
                            "generated": generated,
                            "expected_holds": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        findings = check_merge_authority_transfer_fixtures(case_root)

        assert len(findings) == 1
        assert findings[0].message == (
            f"merge authority fixture authority denial {index} omits affirmative "
            "default authority"
        )


def test_merge_authority_transfer_rejects_nonoperational_authority_mentions(
    tmp_path: Path,
) -> None:
    """Verify policy documentation text is not an operational merge instruction.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "authority policy mention",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement the issue."}],
                        "generated": "Document the default merge authority policy.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture authority policy mention omits affirmative default "
        "authority"
    )


def test_merge_authority_transfer_rejects_documented_guarded_merge_mentions(
    tmp_path: Path,
) -> None:
    """Verify documentation subjects are not operational guarded-merge actions.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "document guarded merge",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement the issue."}],
                        "generated": "Document how to complete the guarded merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture document guarded merge omits affirmative default "
        "authority"
    )


def test_merge_authority_transfer_rejects_test_subject_merge_mentions(
    tmp_path: Path,
) -> None:
    """Verify test-subject wording is not an operational merge action.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "test guarded merge prompt",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement the issue."}],
                        "generated": "Test detection of guarded squash merge prompts.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture test guarded merge prompt omits affirmative default "
        "authority"
    )


def test_merge_authority_transfer_rejects_second_instruction_condition(
    tmp_path: Path,
) -> None:
    """Verify guarded merge cannot be conditioned on a second instruction.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    generated_prompts = (
        "Perform the guarded squash merge only after receiving a second merge "
        "instruction.",
        "Only after another merge instruction, perform the guarded squash merge.",
    )
    for index, generated in enumerate(generated_prompts, start=1):
        path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "name": f"second instruction condition {index}",
                            "default_merge_authority": True,
                            "instructions": [
                                {"text": "Implement the issue completely."}
                            ],
                            "generated": generated,
                            "expected_holds": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        findings = check_merge_authority_transfer_fixtures(tmp_path)

        assert len(findings) == 1
        assert findings[0].message == (
            f"merge authority fixture second instruction condition {index} omits "
            "affirmative default authority"
        )


def test_merge_authority_transfer_rejects_ambiguous_generated_hold_direction(
    tmp_path: Path,
) -> None:
    """Verify generated text cannot both withdraw and add the same hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "ambiguous generated direction",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement the issue completely."}],
                        "generated": (
                            "The earlier do not merge hold is withdrawn. Do not merge. "
                            "Continue through guarded squash merge."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture ambiguous generated direction has ambiguous "
        "generated hold direction: do not merge"
    )


def test_merge_authority_transfer_matches_each_hold_direction(
    tmp_path: Path,
) -> None:
    """Verify mixed additions and withdrawals cannot be reversed.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "reversed mixed directions",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement the change; the do not merge instruction "
                                    "is withdrawn; "
                                    "wait for approval."
                                ),
                                "add_holds": ["do not merge"],
                                "remove_holds": ["wait for approval"],
                            }
                        ],
                        "generated": "Do not merge.",
                        "expected_holds": ["do not merge"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture reversed mixed directions instruction 1 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_binds_withdrawal_to_matching_hold(
    tmp_path: Path,
) -> None:
    """Verify one hold's withdrawal does not reverse another hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "bound hold withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement the change. The do not merge instruction "
                                    "is withdrawn, but "
                                    "wait for approval."
                                ),
                                "add_holds": ["wait for approval"],
                                "remove_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Wait for approval before merging.",
                        "expected_holds": ["wait for approval"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_binds_comma_separated_hold_withdrawal(
    tmp_path: Path,
) -> None:
    """Verify comma-separated withdrawal does not reverse a later hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "comma-bound withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Withdraw the wait for approval requirement, keep "
                                    "the pull request open."
                                ),
                                "remove_holds": ["wait for approval", "leave open"],
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture comma-bound withdrawal instruction 1 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_applies_same_instruction_scope_transition(
    tmp_path: Path,
) -> None:
    """Verify a later clause can restore implementation authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "same instruction scope transition",
                        "default_merge_authority": False,
                        "instructions": [
                            {
                                "text": (
                                    "This is no longer review-only; implement issue "
                                    "#602 completely."
                                )
                            }
                        ],
                        "generated": "Only report the findings.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture same instruction scope transition declared "
        "default authority does not match its source instructions"
    )


def test_merge_authority_transfer_rejects_negated_hold_withdrawal(
    tmp_path: Path,
) -> None:
    """Verify negating a withdrawal leaves the explicit hold active.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "negated hold withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement the change. The do not merge hold is not "
                                    "withdrawn."
                                ),
                                "remove_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture negated hold withdrawal instruction 1 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_rejects_passively_negated_withdrawal(
    tmp_path: Path,
) -> None:
    """Verify passive negation cannot withdraw an explicit hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "passively negated hold withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement the change. The do not merge instruction "
                                    "has not been withdrawn."
                                ),
                                "remove_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture passively negated hold withdrawal instruction 1 "
        "hold operations do not match its text"
    )


def test_merge_authority_transfer_rejects_modal_negated_withdrawal(
    tmp_path: Path,
) -> None:
    """Verify cannot-be wording leaves an explicit hold active.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "modal negated hold withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Implement the change. The do not merge hold cannot "
                                    "be withdrawn."
                                ),
                                "remove_holds": ["do not merge"],
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture modal negated hold withdrawal instruction 1 hold "
        "operations do not match its text"
    )


def test_merge_authority_transfer_rejects_noncurrent_hold_withdrawals(
    tmp_path: Path,
) -> None:
    """Verify future and conditional statements cannot withdraw a hold.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    statements = (
        "The do not merge hold will be withdrawn tomorrow.",
        "Do not merge unless the hold is withdrawn.",
        "The do not merge hold is withdrawn only after CI succeeds.",
    )
    for index, statement in enumerate(statements):
        case_root = tmp_path / str(index)
        path = case_root / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "name": f"noncurrent withdrawal {index}",
                            "default_merge_authority": True,
                            "instructions": [
                                {
                                    "text": f"Implement the change. {statement}",
                                    "remove_holds": ["do not merge"],
                                }
                            ],
                            "generated": "Continue through guarded squash merge.",
                            "expected_holds": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        findings = check_merge_authority_transfer_fixtures(case_root)

        assert len(findings) == 1
        assert findings[0].message == (
            f"merge authority fixture noncurrent withdrawal {index} instruction 1 "
            "hold operations do not match its text"
        )


def test_merge_authority_transfer_applies_leading_only_review_transition(
    tmp_path: Path,
) -> None:
    """Verify a later leading-only review instruction removes eligibility.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "leading only review",
                        "default_merge_authority": True,
                        "instructions": [
                            {"text": "Implement issue #602 completely."},
                            {"text": "Only review the pull request now."},
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture leading only review declared default authority "
        "does not match its source instructions"
    )


def test_merge_authority_transfer_excludes_review_object_markers(
    tmp_path: Path,
) -> None:
    """Verify a reviewed implementation noun does not restore task authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "review implementation object",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Only review the implementation."}],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture review implementation object declared default "
        "authority does not match its source instructions"
    )


def test_merge_authority_transfer_excludes_direct_review_requests(
    tmp_path: Path,
) -> None:
    """Verify reviewing an implementation does not grant implementation authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "direct implementation review",
                        "default_merge_authority": True,
                        "instructions": [
                            {"text": "Review the implementation and report findings."}
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture direct implementation review declared default "
        "authority does not match its source instructions"
    )


def test_merge_authority_transfer_excludes_audit_only_requests(
    tmp_path: Path,
) -> None:
    """Verify auditing an implementation does not grant implementation authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "audit implementation",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Audit the implementation and report findings."
                                )
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture audit implementation declared default authority "
        "does not match its source instructions"
    )


def test_merge_authority_transfer_keeps_review_after_negated_work_ineligible(
    tmp_path: Path,
) -> None:
    """Verify negated work does not suppress a later review-only exclusion.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "negated implementation review",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Do not implement anything; review the "
                                    "implementation and report findings."
                                )
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture negated implementation review declared default "
        "authority does not match its source instructions"
    )


def test_merge_authority_transfer_keeps_implementation_before_review_eligible(
    tmp_path: Path,
) -> None:
    """Verify a review step does not erase earlier implementation scope.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "implementation then review",
                        "default_merge_authority": False,
                        "instructions": [
                            {
                                "text": (
                                    "Implement issue #602, then review the "
                                    "implementation."
                                )
                            }
                        ],
                        "generated": "Complete the implementation and review it.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture implementation then review declared default authority "
        "does not match its source instructions"
    )


def test_merge_authority_transfer_rejects_open_as_draft_eligibility(
    tmp_path: Path,
) -> None:
    """Verify opening a pull request as a draft remains ineligible.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "open as draft",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Deliver the change by opening the pull request as "
                                    "a draft."
                                )
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture open as draft declared default authority does not "
        "match its source instructions"
    )


def test_merge_authority_transfer_keeps_draft_feature_work_eligible(
    tmp_path: Path,
) -> None:
    """Verify feature wording about draft pull requests remains implementation work.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "draft feature declared ineligible",
                        "default_merge_authority": False,
                        "instructions": [
                            {"text": "Implement support for draft pull requests."}
                        ],
                        "generated": "Describe the requested feature.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture draft feature declared ineligible declared default "
        "authority does not match its source instructions"
    )


def test_merge_authority_transfer_keeps_fork_feature_work_eligible(
    tmp_path: Path,
) -> None:
    """Verify fork-PR feature wording remains ordinary implementation work.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "fork feature declared ineligible",
                        "default_merge_authority": False,
                        "instructions": [
                            {"text": "Implement support for fork pull requests."}
                        ],
                        "generated": "Describe the requested feature.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture fork feature declared ineligible declared default "
        "authority does not match its source instructions"
    )


def test_merge_authority_transfer_rejects_explicit_no_change_eligibility(
    tmp_path: Path,
) -> None:
    """Verify a no-change instruction cannot create implementation authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "explicit no change",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Do not implement any changes; only explain the "
                                    "failure."
                                )
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture explicit no change declared default authority "
        "does not match its source instructions"
    )


def test_merge_authority_transfer_rejects_negated_authority_verbs(
    tmp_path: Path,
) -> None:
    """Verify negated work verbs cannot create implementation authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for verb in ("fix", "resolve", "solve", "deliver"):
        case_root = tmp_path / verb
        path = case_root / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "name": f"negated {verb}",
                            "default_merge_authority": True,
                            "instructions": [
                                {
                                    "text": (
                                        f"Do not {verb} issue #602; only explain the "
                                        "failure."
                                    )
                                }
                            ],
                            "generated": "Continue through guarded squash merge.",
                            "expected_holds": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        findings = check_merge_authority_transfer_fixtures(case_root)

        assert len(findings) == 1
        assert findings[0].message == (
            f"merge authority fixture negated {verb} declared default authority "
            "does not match its source instructions"
        )


def test_merge_authority_transfer_preserves_coordinated_work_negation(
    tmp_path: Path,
) -> None:
    """Verify one negation remains scoped across a coordinated work-verb list.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "coordinated negated work",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Do not implement, fix, or deliver any changes; "
                                    "only explain the failure."
                                )
                            }
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture coordinated negated work declared default authority "
        "does not match its source instructions"
    )


def test_merge_authority_transfer_keeps_implementation_constraints_eligible(
    tmp_path: Path,
) -> None:
    """Verify a dependency constraint does not turn implementation into no-work.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "implementation constraint",
                        "default_merge_authority": False,
                        "instructions": [
                            {"text": "Implement issue #602 without adding dependencies."}
                        ],
                        "generated": "Implement without adding dependencies.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture implementation constraint declared default authority "
        "does not match its source instructions"
    )


def test_merge_authority_transfer_rejects_invented_approval_condition(
    tmp_path: Path,
) -> None:
    """Verify generated prompts cannot invent approval-before-merge gates.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "invented approval condition",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Implement issue #602 completely."}],
                        "generated": (
                            "Perform the guarded squash merge only after maintainer "
                            "approval."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture invented approval condition invents a hold: "
        "wait for approval"
    )


def test_merge_authority_transfer_rejects_invented_approval_qualifier(
    tmp_path: Path,
) -> None:
    """Verify generated prompts cannot invent approval-qualified merges.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "invented approval qualifier",
                        "default_merge_authority": True,
                        "instructions": [{"text": "Update issue #602 completely."}],
                        "generated": (
                            "Perform the guarded squash merge only with maintainer "
                            "approval."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture invented approval qualifier invents a hold: "
        "wait for approval"
    )


def test_merge_authority_transfer_requires_authority_for_existing_pr_work(
    tmp_path: Path,
) -> None:
    """Verify explicit existing ordinary PR work grants default authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "existing ordinary PR work",
                        "default_merge_authority": False,
                        "instructions": [
                            {
                                "text": (
                                    "Work on existing ordinary PR #620 and address its "
                                    "review feedback."
                                )
                            }
                        ],
                        "generated": "Address the review feedback and leave the PR open.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture existing ordinary PR work declared default authority "
        "does not match its source instructions"
    )


def test_merge_authority_transfer_requires_authority_for_existing_pr_feedback(
    tmp_path: Path,
) -> None:
    """Verify direct existing-PR feedback work grants default authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "existing PR feedback",
                        "default_merge_authority": False,
                        "instructions": [
                            {
                                "text": (
                                    "Address review feedback on existing ordinary PR "
                                    "#620."
                                )
                            }
                        ],
                        "generated": "Address the requested feedback.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture existing PR feedback declared default authority "
        "does not match its source instructions"
    )


def test_merge_authority_transfer_requires_authority_for_update_requests(
    tmp_path: Path,
) -> None:
    """Verify ordinary update requests grant default merge authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "ordinary update",
                        "default_merge_authority": False,
                        "instructions": [
                            {"text": "Update the documentation for issue #602."}
                        ],
                        "generated": "Stop after updating the documentation.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture ordinary update declared default authority does not "
        "match its source instructions"
    )


def test_merge_authority_transfer_requires_authority_for_patch_requests(
    tmp_path: Path,
) -> None:
    """Verify ordinary patch requests grant default merge authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "ordinary patch",
                        "default_merge_authority": False,
                        "instructions": [{"text": "Patch issue #602 completely."}],
                        "generated": "Stop after applying the patch.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture ordinary patch declared default authority does not "
        "match its source instructions"
    )


def test_merge_authority_transfer_distinguishes_auto_merge_choice(
    tmp_path: Path,
) -> None:
    """Verify disabling auto-merge retains guarded manual merge authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "manual merge only",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Do not merge automatically; perform the guarded "
                                    "squash merge after every gate passes."
                                )
                            }
                        ],
                        "generated": (
                            "Keep auto-merge disabled and perform the guarded squash "
                            "merge after every gate passes."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_rejects_default_authority_for_ineligible_task(
    tmp_path: Path,
) -> None:
    """Verify review-only work cannot gain default merge authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "review-only generated merge",
                        "default_merge_authority": False,
                        "instructions": [
                            {"text": "Review the pull request and report findings only."}
                        ],
                        "generated": (
                            "Continue through guarded squash merge when every gate "
                            "passes."
                        ),
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture review-only generated merge asserts default "
        "authority for an ineligible task"
    )


def test_merge_authority_transfer_validates_declared_source_eligibility(
    tmp_path: Path,
) -> None:
    """Verify fixture eligibility agrees with current source instructions.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    cases = (
        (
            "review-only declared eligible",
            True,
            "Review the pull request and report findings only.",
        ),
        (
            "implementation declared ineligible",
            False,
            "Implement the issue completely and deliver its pull request.",
        ),
        (
            "fix declared ineligible",
            False,
            "Fix issue #602 completely.",
        ),
        (
            "implementation noun declared ineligible",
            False,
            "Complete the implementation for issue #602.",
        ),
        (
            "pull-request delivery declared ineligible",
            False,
            "Perform pull-request delivery for issue #602.",
        ),
        (
            "diagnostic resolve declared eligible",
            True,
            "Investigate how to resolve issue #602 without making changes.",
        ),
    )

    for name, declared_authority, instruction in cases:
        path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "name": name,
                            "default_merge_authority": declared_authority,
                            "instructions": [{"text": instruction}],
                            "generated": "Continue through guarded squash merge.",
                            "expected_holds": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        findings = check_merge_authority_transfer_fixtures(tmp_path)

        assert len(findings) == 1
        assert findings[0].message == (
            f"merge authority fixture {name} declared default authority does not "
            "match its source instructions"
        )


def test_merge_authority_transfer_applies_eligibility_changes_in_order(
    tmp_path: Path,
) -> None:
    """Verify the latest explicit scope change determines task eligibility.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    cases = (
        {
            "name": "later implementation scope",
            "default_merge_authority": True,
            "instructions": [
                {"text": "Review the pull request and report findings only."},
                {"text": "Now implement the issue and deliver its pull request."},
            ],
            "generated": "Continue through guarded squash merge.",
            "expected_holds": [],
        },
        {
            "name": "later review-only scope",
            "default_merge_authority": False,
            "instructions": [
                {"text": "Implement the issue and deliver its pull request."},
                {"text": "Instead, review the pull request and report findings only."},
            ],
            "generated": "Review the pull request and report findings.",
            "expected_holds": [],
        },
    )

    for case in cases:
        path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"cases": [case]}), encoding="utf-8")

        assert check_merge_authority_transfer_fixtures(tmp_path) == []


def test_merge_authority_transfer_rejects_hold_only_eligibility_transition(
    tmp_path: Path,
) -> None:
    """Verify a hold and its withdrawal cannot create implementation authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "review-only hold withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Review the pull request and report findings only."
                                )
                            },
                            {
                                "text": "Do not merge.",
                                "add_holds": ["do not merge"],
                            },
                            {
                                "text": "The do not merge hold is withdrawn.",
                                "remove_holds": ["do not merge"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture review-only hold withdrawal declared default "
        "authority does not match its source instructions"
    )


def test_merge_authority_transfer_rejects_wait_hold_eligibility_transition(
    tmp_path: Path,
) -> None:
    """Verify wait-for-approval wording cannot create implementation authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = tmp_path / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "name": "review-only wait hold withdrawal",
                        "default_merge_authority": True,
                        "instructions": [
                            {
                                "text": (
                                    "Review the pull request and report findings only."
                                )
                            },
                            {
                                "text": "Wait for approval before merging.",
                                "add_holds": ["wait for approval"],
                            },
                            {
                                "text": "The wait for approval hold is withdrawn.",
                                "remove_holds": ["wait for approval"],
                            },
                        ],
                        "generated": "Continue through guarded squash merge.",
                        "expected_holds": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = check_merge_authority_transfer_fixtures(tmp_path)

    assert len(findings) == 1
    assert findings[0].message == (
        "merge authority fixture review-only wait hold withdrawal declared default "
        "authority does not match its source instructions"
    )


def test_agent_policy_gate_rejects_missing_default_merge_authority_contract(
    tmp_path: Path,
) -> None:
    """Verify that policy surfaces grant default merge authority.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_points = (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("docs/contribute/agent-policies.md"),
        Path("docs/reference/full-technical-reference.md"),
    )
    marker = "default merge authority"

    for relative_path in required_entry_points:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_agent_policy_gate_rejects_missing_unrelated_issue_tracking(
    tmp_path: Path,
) -> None:
    """Verify that agent entry points retain separate unrelated-issue tracking.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_markers = {
        Path("AGENTS.md"): "### Unrelated issue discoveries",
        Path("CONTRIBUTING.md"): "### Unrelated issue discoveries",
        Path(".github/copilot-instructions.md"): (
            "evidence-backed unrelated problem"
        ),
        Path(".github/pull_request_template.md"): (
            "Evidence-backed issues discovered outside"
        ),
        Path("docs/contribute/agent-policies.md"): (
            "outside that scope is discovered"
        ),
    }

    for relative_path, marker in required_entry_markers.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_agent_policy_gate_rejects_missing_merge_base_guard(tmp_path: Path) -> None:
    """Verify that direct agent merges require server-enforced base freshness.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_points = (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("docs/contribute/agent-policies.md"),
        Path("docs/reference/full-technical-reference.md"),
    )
    marker = "strict up-to-date required checks"

    for relative_path in required_entry_points:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_agent_policy_gate_rejects_missing_explicit_merge_hold(
    tmp_path: Path,
) -> None:
    """Verify that policy surfaces retain the explicit merge hold override.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_points = (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("docs/contribute/agent-policies.md"),
        Path("docs/reference/full-technical-reference.md"),
    )
    marker = "explicit merge hold"

    for relative_path in required_entry_points:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_agent_policy_gate_rejects_missing_non_task_owned_cleanup_contract(
    tmp_path: Path,
) -> None:
    """Verify that existing owner branches retain non-destructive cleanup.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_points = (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("docs/contribute/agent-policies.md"),
        Path("docs/reference/full-technical-reference.md"),
    )

    markers = (
        NON_TASK_OWNED_REMOTE_BRANCH_PRESERVED_MARKER,
        NON_TASK_OWNED_CHECKOUT_PRESERVED_MARKER,
    )

    for marker in markers:
        for relative_path in required_entry_points:
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            path.write_text(
                path.read_text(encoding="utf-8").replace(marker, "", 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"required agent policy marker is missing: {marker}"
            )


def test_agent_policy_gate_rejects_missing_preserved_remote_resume_contract(
    tmp_path: Path,
) -> None:
    """Verify interrupted cleanup accepts a verified preserved remote.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_points = (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("docs/contribute/agent-policies.md"),
        Path("docs/reference/full-technical-reference.md"),
    )

    resume_markers = (
        WORKTREE_REMOVAL_REMOTE_GATE_MARKER,
        PRIMARY_CHECKOUT_REMOTE_GATE_MARKER,
    )

    for marker in resume_markers:
        for relative_path in required_entry_points:
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            path.write_text(
                path.read_text(encoding="utf-8").replace(marker, "", 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            expected_prefix = (
                "completed-task cleanup section marker is missing: "
                if relative_path in TERMINAL_CLEANUP_SECTION_MARKERS
                else "required agent policy marker is missing: "
            )
            assert findings[0].message == expected_prefix + marker


def test_agent_policy_gate_rejects_missing_merge_queue_guard(tmp_path: Path) -> None:
    """Verify that direct merges fail closed when a merge queue is required.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_markers = {
        Path("AGENTS.md"): "no merge queue is required",
        Path("CONTRIBUTING.md"): "no required merge queue",
        Path(".github/copilot-instructions.md"): "when a merge queue is required",
        Path(".github/pull_request_template.md"): "no merge queue is required",
        Path("docs/contribute/agent-policies.md"): "no required merge queue",
    }

    for relative_path, marker in required_entry_markers.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_agent_policy_gate_requires_completed_task_cleanup_contract(
    tmp_path: Path,
) -> None:
    """Verify that every agent entry point retains terminal cleanup enforcement.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace("`cleanup-ready`", ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "required agent policy marker is missing: `cleanup-ready`"
        )


def test_agent_policy_gate_requires_done_title_suffix(tmp_path: Path) -> None:
    """Verify that terminal cleanup retains the exact idempotent title suffix.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace('" · Done"', ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            'required agent policy marker is missing: " · Done"'
        )


def test_agent_policy_gate_scopes_cleanup_contract_markers(tmp_path: Path) -> None:
    """Verify that an incidental summary cannot satisfy the operative cleanup contract.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for marker in (
            '`cleanup-ready`',
            '" · Done"',
            LOCAL_TASK_BRANCH_ABSENT_MARKER,
            REMOTE_BRANCH_LEASE_MARKER,
            PRIVATE_REMEDIATION_CLEANUP_MARKER,
            PRIVATE_REMEDIATION_REMOTE_MARKER,
            PRIMARY_CHECKOUT_RESUME_MARKER,
            PRIMARY_CHECKOUT_RESTORED_MARKER,
            TITLE_CONTROL_UNAVAILABLE_MARKER,
            WORKTREE_REMOVAL_RESUME_MARKER,
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8")
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            section_start = text.index(anchor)
            before_section = text[:section_start]
            cleanup_section = text[section_start:].replace(marker, "", 1)
            path.write_text(
                marker + "\n" + before_section + cleanup_section,
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_requires_terminal_cleanup_order(tmp_path: Path) -> None:
    """Verify that branch, worktree, and title transitions remain ordered.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path, markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        order_prefix = "" if anchor.startswith("#") else "  "
        earlier_summary = "\n".join(order_prefix + marker for marker in markers)
        summary_position = text.index(anchor) + len(anchor)
        text_with_summary = (
            text[:summary_position]
            + "\n"
            + earlier_summary
            + text[summary_position:]
        )
        reversed_order_lines = tuple(
            f"{order_prefix}{position}. {marker}"
            for position, marker in enumerate(reversed(markers), start=1)
        )
        expected_order_lines = tuple(
            order_prefix + line for line in TERMINAL_CLEANUP_ORDER_LINES
        )
        path.write_text(
            text_with_summary.replace(
                "\n".join(expected_order_lines),
                "\n".join(reversed_order_lines),
            ),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "completed-task cleanup markers must remain ordered: "
            + " -> ".join(markers)
        )


def test_agent_policy_gate_ignores_incidental_marker_order(tmp_path: Path) -> None:
    """Verify that only the operative cleanup section controls lifecycle ordering.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path, markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        summary_prefix = "" if anchor.startswith("#") else "  "
        summary_position = text.index(anchor) + len(anchor)
        path.write_text(
            text[:summary_position]
            + "\n"
            + "\n".join(summary_prefix + marker for marker in reversed(markers))
            + text[summary_position:],
            encoding="utf-8",
        )

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_rejects_duplicate_cleanup_sections(tmp_path: Path) -> None:
    """Verify that a stale compliant cleanup section cannot mask another copy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        path.write_text(
            path.read_text(encoding="utf-8") + "\n" + anchor,
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "completed-task cleanup section must appear exactly once: " + anchor
        )


def test_agent_policy_gate_rejects_suffixed_cleanup_headings(tmp_path: Path) -> None:
    """Verify that a suffixed heading cannot replace the canonical anchor.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(anchor, anchor + " (legacy)", 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "completed-task cleanup section is missing: " + anchor
        )


def test_agent_policy_gate_rejects_html_wrapped_cleanup_headings(
    tmp_path: Path,
) -> None:
    """Verify rendered raw HTML text cannot become a Markdown heading anchor.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        for replacement in (
            f"<div>{anchor}</div>",
            f"<div>\n{anchor}\n</div>",
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(
                anchor,
                replacement,
                1,
            )
            path.write_text(text, encoding="utf-8")

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                "completed-task cleanup section is missing: " + anchor
            )


def test_agent_policy_gate_honors_indented_heading_boundaries(tmp_path: Path) -> None:
    """Verify that valid indented headings end heading-based cleanup sections.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        heading_level = len(anchor) - len(anchor.lstrip("#"))
        path.write_text(
            text + f"\n   {'#' * heading_level} Outside cleanup\n{marker}\n",
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_honors_empty_atx_heading_boundaries(tmp_path: Path) -> None:
    """Verify that empty same-level ATX headings end cleanup sections.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        heading_level = len(anchor) - len(anchor.lstrip("#"))
        path.write_text(
            text + f"\n{'#' * heading_level}\n{marker}\n",
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_honors_setext_heading_boundaries(tmp_path: Path) -> None:
    """Verify that Setext headings end heading-based cleanup sections.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        for underline in ("===", "---"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            path.write_text(
                text + f"\nOutside cleanup\n{underline}\n{marker}\n",
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_preserves_thematic_breaks_after_list_items(
    tmp_path: Path,
) -> None:
    """Verify a thematic break after a list item remains inside the section.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        path.write_text(
            text.replace(
                "- following policy",
                f"- contextual item\n---\n{marker}\n- following policy",
                1,
            ),
            encoding="utf-8",
        )

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_honors_multiline_setext_heading_boundaries(
    tmp_path: Path,
) -> None:
    """Verify every title line is excluded from the preceding section.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        path.write_text(
            text + f"\n{marker} title line\nFollowing section\n---\n",
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_honors_all_list_item_boundaries(tmp_path: Path) -> None:
    """Verify that every top-level Markdown list item ends cleanup list items.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if anchor.startswith("#"):
            continue
        for delimiter in ("*", "+", "1.", "1)"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            path.write_text(
                text + f"\n{delimiter} Outside cleanup\n{marker}\n",
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_honors_top_level_block_boundaries(tmp_path: Path) -> None:
    """Verify that unrelated top-level blocks end cleanup list items.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if anchor.startswith("#"):
            continue
        boundaries = (
            ("## Following policy", ""),
            ("---", ""),
            ("```text\nexample\n```\n", "  "),
            ("<!-- boundary -->\n", "  "),
            ("<div>\nexample\n</div>\n", "  "),
        )
        for boundary, marker_prefix in boundaries:
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            path.write_text(
                text.replace(
                    sibling,
                    f"\n{boundary}\n{marker_prefix}{marker}" + sibling,
                    1,
                ),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_ignores_fenced_cleanup_markers(tmp_path: Path) -> None:
    """Verify that fenced examples cannot satisfy cleanup section markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        fence_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        fenced_marker = (
            f"{fence_prefix}```text\n{fence_prefix}{marker}\n{fence_prefix}```"
        )
        path.write_text(
            text + "\n" + fenced_marker + "\n"
            if anchor.startswith("#")
            else text.replace(
                "\n- following policy",
                "\n" + fenced_marker + "\n- following policy",
                1,
            ),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_preserves_invalid_backtick_fence_info_strings(
    tmp_path: Path,
) -> None:
    """Verify backticks in a would-be info string keep the line visible.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f"```invalid`info {marker}",
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_ignores_link_reference_cleanup_markers(
    tmp_path: Path,
) -> None:
    """Verify that link-reference metadata cannot satisfy cleanup markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        definition_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        definition = (
            f'\n{definition_prefix}[cleanup-marker]: '
            f'https://example.invalid "{marker}"'
        )
        path.write_text(
            text + definition
            if anchor.startswith("#")
            else text.replace(sibling, definition + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_preserves_invalid_reference_definition_tails(
    tmp_path: Path,
) -> None:
    """Verify invalid reference tails remain visible policy prose.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for visible_line in (
            f"[handoff]: ordinary visible prose containing {marker}",
            f"[handoff]: https://example.invalid extra prose containing {marker}",
            f'[handoff]: https://example.invalid extra "prose containing {marker}',
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(
                marker,
                visible_line,
                1,
            )
            path.write_text(text, encoding="utf-8")

            assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_definitions_inside_paragraphs(
    tmp_path: Path,
) -> None:
    """Verify definition-shaped paragraph continuations stay visible.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(
            marker,
            "ordinary visible prose\n"
            f"{content_prefix}[handoff]: https://example.invalid/{marker}",
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_ignores_multiline_link_reference_titles(
    tmp_path: Path,
) -> None:
    """Verify that multiline reference titles cannot satisfy cleanup markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        path.write_text(
            text
            + '\n[cleanup-marker]: https://example.invalid\n'
            + f'  "{marker}"',
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_ignores_fenced_terminal_order(tmp_path: Path) -> None:
    """Verify that a fenced terminal sequence is not operative policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path, markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        order_prefix = "" if anchor.startswith("#") else "  "
        order_block = "\n".join(
            (
                order_prefix + TERMINAL_CLEANUP_ORDER_ANCHOR,
                "",
                *(order_prefix + line for line in TERMINAL_CLEANUP_ORDER_LINES),
            )
        )
        incidental_markers = "\n".join(order_prefix + marker for marker in markers)
        fenced_order = "\n".join(
            order_prefix + line if line else order_prefix
            for line in ("```text", *order_block.splitlines(), "```")
        )
        text_without_order = text.replace(order_block, incidental_markers, 1)
        path.write_text(
            text_without_order + "\n" + fenced_order + "\n"
            if anchor.startswith("#")
            else text_without_order.replace(
                "\n- following policy",
                "\n" + fenced_order + "\n- following policy",
                1,
            ),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "completed-task cleanup markers must remain ordered: "
            + " -> ".join(markers)
        )


def test_agent_policy_gate_ignores_commented_cleanup_sections(tmp_path: Path) -> None:
    """Verify that an HTML-commented cleanup section is not operative policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        text = path.read_text(encoding="utf-8")
        section_start = text.index(anchor)
        path.write_text(
            text[:section_start] + "<!--\n" + text[section_start:] + "\n-->\n",
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "completed-task cleanup section is missing: " + anchor
        )


def test_agent_policy_gate_ignores_inline_html_metadata_markers(tmp_path: Path) -> None:
    """Verify that invisible inline HTML attributes cannot satisfy markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for attribute_value in (marker, f"example > {marker}"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            html_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            hidden_marker = (
                f'\n{html_prefix}<span data-example="{attribute_value}"></span>'
            )
            path.write_text(
                text + hidden_marker
                if anchor.startswith("#")
                else text.replace(sibling, hidden_marker + sibling, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_ignores_inline_link_metadata_markers(tmp_path: Path) -> None:
    """Verify that invisible link and image metadata cannot satisfy markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for image_prefix in ("", "!"):
            for destination in (
                "https://example.invalid",
                r"https://example.invalid/foo\)",
                "https://example.invalid/foo_(bar)",
                "<https://example.invalid/foo)>" ,
            ):
                write_policy_files(tmp_path)
                path = tmp_path / relative_path
                anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
                link_prefix = "" if anchor.startswith("#") else "  "
                text = path.read_text(encoding="utf-8").replace(marker, "", 1)
                hidden_marker = (
                    f'\n{link_prefix}{image_prefix}[example]'
                    f'({destination} "{marker}")'
                )
                path.write_text(
                    text + hidden_marker
                    if anchor.startswith("#")
                    else text.replace(sibling, hidden_marker + sibling, 1),
                    encoding="utf-8",
                )

                findings = check_agent_policy_gate(tmp_path)

                assert len(findings) == 1
                assert findings[0].path == path
                assert findings[0].message == (
                    f"completed-task cleanup section marker is missing: {marker}"
                )


def test_agent_policy_gate_preserves_invalid_inline_link_suffixes(
    tmp_path: Path,
) -> None:
    """Verify invalid inline-link-shaped policy remains visible.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f"[handoff](invalid destination {marker})",
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_unresolved_reference_suffixes(
    tmp_path: Path,
) -> None:
    """Verify unresolved full-reference policy remains visible.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f"[handoff][{marker}]",
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_ignores_reference_link_metadata_markers(
    tmp_path: Path,
) -> None:
    """Verify reference identifiers cannot satisfy cleanup markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for image_prefix in ("", "!"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            link_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            hidden_marker = (
                f"\n{link_prefix}{image_prefix}[example][{marker}]"
                f"\n\n{link_prefix}[{marker}]: https://example.invalid"
            )
            path.write_text(
                text + hidden_marker
                if anchor.startswith("#")
                else text.replace(sibling, hidden_marker + sibling, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_ignores_nested_image_metadata_markers(
    tmp_path: Path,
) -> None:
    """Verify image metadata nested in link labels cannot satisfy markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        link_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        hidden_marker = (
            f'\n{link_prefix}[visible ![example]'
            f'(https://example.invalid "{marker}")]'
            f'(https://example.invalid)'
        )
        path.write_text(
            text + hidden_marker
            if anchor.startswith("#")
            else text.replace(sibling, hidden_marker + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_ignores_multiline_reference_destinations(
    tmp_path: Path,
) -> None:
    """Verify continuation destinations cannot satisfy cleanup markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for destination in (
            f"https://example.invalid/{marker}",
            f"https://example.invalid/foo((bar))/{marker}",
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            link_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            hidden_marker = (
                f"\n{link_prefix}[policy-example]:"
                f"\n{link_prefix}  {destination}"
            )
            path.write_text(
                text + hidden_marker
                if anchor.startswith("#")
                else text.replace(sibling, hidden_marker + sibling, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_ignores_multiline_reference_titles(
    tmp_path: Path,
) -> None:
    """Verify reference titles spanning lines cannot satisfy cleanup markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for destination_on_continuation in (False, True):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            link_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            if destination_on_continuation:
                hidden_marker = (
                    f'\n{link_prefix}[policy-example]:'
                    f'\n{link_prefix}  https://example.invalid "title'
                    f'\n{link_prefix}  {marker}"'
                )
            else:
                hidden_marker = (
                    f'\n{link_prefix}[policy-example]: https://example.invalid "title'
                    f'\n{link_prefix}  {marker}"'
                )
            path.write_text(
                text + hidden_marker
                if anchor.startswith("#")
                else text.replace(sibling, hidden_marker + sibling, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_ignores_escaped_reference_title_delimiters(
    tmp_path: Path,
) -> None:
    """Verify escaped title delimiters cannot expose reference metadata.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        link_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        hidden_marker = (
            f'\n{link_prefix}[hidden]: /destination '
            f'"metadata with \\" and {marker}"'
        )
        path.write_text(
            text + hidden_marker
            if anchor.startswith("#")
            else text.replace(sibling, hidden_marker + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_preserves_whitespace_only_reference_labels(
    tmp_path: Path,
) -> None:
    """Verify an empty normalized reference label remains visible prose.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f'[   ]: /destination "{marker}"',
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_overlong_reference_labels(
    tmp_path: Path,
) -> None:
    """Verify a label beyond CommonMark's limit remains visible prose.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    overlong_label = "x" * 1000
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f'[{overlong_label}]: /destination "{marker}"',
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_ignores_escaped_reference_label_metadata(
    tmp_path: Path,
) -> None:
    """Verify escaped label brackets do not expose reference metadata.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        link_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        hidden_marker = (
            f"\n{link_prefix}[policy\\]]: https://example.invalid/{marker}"
        )
        path.write_text(
            text + hidden_marker
            if anchor.startswith("#")
            else text.replace(sibling, hidden_marker + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_ignores_multiline_reference_label_metadata(
    tmp_path: Path,
) -> None:
    """Verify multiline labels do not expose reference metadata.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        link_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        hidden_marker = (
            f"\n{link_prefix}[handoff][policy label]"
            f"\n\n{link_prefix}[policy\n{link_prefix} label]: "
            f"https://example.invalid/{marker}"
        )
        path.write_text(
            text + hidden_marker
            if anchor.startswith("#")
            else text.replace(sibling, hidden_marker + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_ignores_raw_html_block_markers(tmp_path: Path) -> None:
    """Verify raw HTML container bodies cannot satisfy markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for tag_name in (
            "script",
            "style",
            "pre",
            "code",
            "textarea",
            "xmp",
            "template",
            "noscript",
            "iframe",
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            html_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            hidden_marker = (
                f"\n{html_prefix}<{tag_name}>\n"
                f"{html_prefix}{marker}\n{html_prefix}</{tag_name}>"
            )
            path.write_text(
                text + hidden_marker
                if anchor.startswith("#")
                else text.replace(sibling, hidden_marker + sibling, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_preserves_policy_after_raw_text_comments(
    tmp_path: Path,
) -> None:
    """Verify comment tokens inside closed raw-text blocks do not escape them.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        for tag_name in ("script", "style", "textarea", "pre"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(
                marker,
                f"<{tag_name}>\n{content_prefix}<!--\n"
                f"{content_prefix}</{tag_name}>\n{content_prefix}{marker}",
                1,
            )
            path.write_text(text, encoding="utf-8")

            assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_ignores_nested_raw_html_container_markers(
    tmp_path: Path,
) -> None:
    """Verify nested same-name inert containers cannot expose hidden markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        html_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        hidden_marker = (
            f"\n{html_prefix}visible <template><template></template>"
            f"{marker}</template>"
        )
        path.write_text(
            text + hidden_marker
            if anchor.startswith("#")
            else text.replace(sibling, hidden_marker + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_ignores_html_metadata_element_markers(
    tmp_path: Path,
) -> None:
    """Verify title and head metadata bodies cannot satisfy policy markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for tag_name in ("title", "head"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            html_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            hidden_marker = (
                f"\n{html_prefix}<{tag_name}>{marker}</{tag_name}>"
            )
            path.write_text(
                text + hidden_marker
                if anchor.startswith("#")
                else text.replace(sibling, hidden_marker + sibling, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_ignores_raw_html_policy_sections(tmp_path: Path) -> None:
    """Verify a raw HTML code container cannot replace operative policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for tag_name in (
            "script",
            "style",
            "pre",
            "code",
            "textarea",
            "xmp",
            "template",
            "noscript",
            "iframe",
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            text = path.read_text(encoding="utf-8")
            section_start = text.index(anchor)
            section_end = text.index(sibling, section_start)
            path.write_text(
                text[:section_start]
                + f"<{tag_name}>\n"
                + text[section_start:section_end]
                + f"\n</{tag_name}>"
                + text[section_end:],
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                "completed-task cleanup section is missing: " + anchor
            )


def test_agent_policy_gate_ignores_hidden_html_policy_sections(
    tmp_path: Path,
) -> None:
    """Verify an HTML hidden attribute makes the wrapped policy non-operative.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        text = path.read_text(encoding="utf-8")
        section_start = text.index(anchor)
        section_end = text.index(sibling, section_start)
        path.write_text(
            text[:section_start]
            + '<div class="policy" hidden>\n'
            + text[section_start:section_end]
            + "\n</div>"
            + text[section_end:],
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "completed-task cleanup section is missing: " + anchor
        )


def test_agent_policy_gate_ignores_unclosed_hidden_html_policy(
    tmp_path: Path,
) -> None:
    """Verify hidden containers remain non-operative through end of input.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for opening_tag in (
            "<div hidden>",
            '<div style="display:none">',
            "<template>",
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(
                marker,
                opening_tag + "\n" + marker,
                1,
            )
            path.write_text(text, encoding="utf-8")

            findings = check_agent_policy_gate(tmp_path)

            assert any(
                finding.path == path
                and finding.message
                == f"completed-task cleanup section marker is missing: {marker}"
                for finding in findings
            )


def test_agent_policy_gate_ignores_css_hidden_html_policy_sections(
    tmp_path: Path,
) -> None:
    """Verify inline display-none CSS makes wrapped policy non-operative.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for style in (
            "display:none",
            "display&#58;none",
            "display:/**/none",
            r"display:\6e one",
            "display:inline; display:none",
            "display:none !important; display:inline",
            "display:none; display:bogus",
            "display:none; display:calc(1)",
            "color:red; DISPLAY: none !important;",
            "visibility:hidden",
            "visibility:hidden; visibility:bogus",
            "visibility:hidden; visibility:calc(1)",
            "visibility: collapse !important",
            "content-visibility:hidden",
            "content-visibility:hidden; content-visibility:bogus",
            "content-visibility:hidden; content-visibility:calc(1)",
            "opacity:0",
            "opacity:-1",
            "opacity:-0.5",
            "opacity:-10%",
            "opacity:calc(0)",
            "opacity:min(0, 1)",
            "opacity:max(0, 0)",
            "opacity:clamp(0, 0, 1)",
            "opacity:0; opacity:bogus",
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            text = path.read_text(encoding="utf-8")
            section_start = text.index(anchor)
            section_end = text.index(sibling, section_start)
            path.write_text(
                text[:section_start]
                + f'<div class="policy" style="{style}">\n'
                + text[section_start:section_end]
                + "\n</div>"
                + text[section_end:],
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                "completed-task cleanup section is missing: " + anchor
            )


def test_agent_policy_gate_preserves_visible_css_cascade_results(
    tmp_path: Path,
) -> None:
    """Verify later or important visible declarations keep policy operative.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for style in (
            "display:none; display:inline",
            "display:none !important; display:inline !important",
            "display:inline !important; display:none",
            "visibility:hidden; visibility:visible",
            "content-visibility:hidden; content-visibility:visible",
            "opacity:0; opacity:1",
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(
                marker,
                f'<span style="{style}">{marker}</span>',
                1,
            )
            path.write_text(text, encoding="utf-8")

            assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_policy_after_hidden_void_elements(
    tmp_path: Path,
) -> None:
    """Verify hidden void elements cannot consume following visible policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for void_tag in (
            "<input hidden>",
            '<img style="display:none">',
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            content_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(
                marker,
                f"{void_tag}\n{content_prefix}{marker}",
                1,
            )
            path.write_text(text, encoding="utf-8")

            assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_policy_after_same_line_code_html(
    tmp_path: Path,
) -> None:
    """Verify a closed inline code element cannot consume following policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f"<code>example</code>\n{content_prefix}{marker}",
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_honors_fences_before_html_comments(
    tmp_path: Path,
) -> None:
    """Verify comment-like fenced text cannot consume later visible policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        replacement = (
            f"```text\n{content_prefix}<!--\n{content_prefix}```\n"
            f"{content_prefix}{marker}\n{content_prefix}-->"
        )
        text = path.read_text(encoding="utf-8").replace(marker, replacement, 1)
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_comment_openers_in_code_spans(
    tmp_path: Path,
) -> None:
    """Verify inline-code comment text cannot consume later visible policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        path.write_text("`literal <!--`\n" + text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_rejects_over_indented_fence_closers(
    tmp_path: Path,
) -> None:
    """Verify a four-space delimiter remains literal fenced content.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(
            anchor,
            anchor + "\n```text\n    ```",
            1,
        )
        path.write_text(text, encoding="utf-8")

        findings = check_agent_policy_gate(tmp_path)

        assert any(
            finding.message
            == f"completed-task cleanup section marker is missing: {marker}"
            for finding in findings
        )


def test_agent_policy_gate_preserves_comment_openers_in_tag_attributes(
    tmp_path: Path,
) -> None:
    """Verify comment-like quoted attributes do not hide rendered policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f'<span title="<!--">{marker}</span>',
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_visible_inline_html_content(
    tmp_path: Path,
) -> None:
    """Verify ordinary inline HTML retains rendered policy text.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for tag_name, visible_prefix in (
            ("span", ""),
            ("em", "Required: "),
            ("code", "Required: "),
        ):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(
                marker,
                f'{visible_prefix}<{tag_name} data-example="metadata">'
                f'{marker}</{tag_name}>',
                1,
            )
            path.write_text(text, encoding="utf-8")

            assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_visible_raw_html_block_content(
    tmp_path: Path,
) -> None:
    """Verify ordinary raw HTML blocks retain rendered policy text.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for tag_name in ("div", "section"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            content_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(
                marker,
                f'<{tag_name} data-example="metadata">\n'
                f'{content_prefix}{marker}\n{content_prefix}</{tag_name}>',
                1,
            )
            path.write_text(text, encoding="utf-8")

            assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_ignores_unterminated_raw_html_blocks(
    tmp_path: Path,
) -> None:
    """Verify blank-line-terminated raw HTML bodies cannot satisfy markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for tag_name in ("iframe", "template"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            html_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            hidden_marker = (
                f"\n{html_prefix}<{tag_name}>\n{html_prefix}{marker}\n\n"
            )
            path.write_text(
                text + hidden_marker
                if anchor.startswith("#")
                else text.replace(sibling, hidden_marker + sibling, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_ignores_raw_html_directive_markers(
    tmp_path: Path,
) -> None:
    """Verify raw processing instructions and declarations cannot satisfy markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    directives = (
        f'<?atlaso example="{marker}"?>',
        f'<?atlaso example="{marker}"',
        f"<![CDATA[{marker}]]>",
        f"<![CDATA[{marker}",
        f"<!ATLASO {marker}>",
        f"<!ATLASO {marker}",
    )
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for directive in directives:
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            html_prefix = "" if anchor.startswith("#") else "  "
            text = path.read_text(encoding="utf-8").replace(marker, "", 1)
            hidden_marker = f"\n{html_prefix}{directive}"
            path.write_text(
                text + hidden_marker
                if anchor.startswith("#")
                else text.replace(sibling, hidden_marker + sibling, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"completed-task cleanup section marker is missing: {marker}"
            )


def test_agent_policy_gate_preserves_policy_after_void_html(tmp_path: Path) -> None:
    """Verify void HTML tags do not consume following operative policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for void_element in ("<br>", '<img alt="divider">'):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
            text = path.read_text(encoding="utf-8")
            path.write_text(
                text.replace(anchor, void_element + "\n" + anchor, 1),
                encoding="utf-8",
            )

            assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_ignores_indented_cleanup_markers(tmp_path: Path) -> None:
    """Verify that indented code cannot satisfy cleanup section markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        indentation = "    " if anchor.startswith("#") else "         "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        insertion = f"\n{indentation}{marker}"
        path.write_text(
            text.replace(anchor, anchor + "\n" + insertion, 1)
            if anchor.startswith("#")
            else text.replace(sibling, insertion + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_accepts_rendered_list_continuation_markers(
    tmp_path: Path,
) -> None:
    """Verify that list-relative prose indentation remains operative.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if anchor.startswith("#"):
            continue
        for indentation in ("    ", "     "):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(
                f"  {marker}",
                f"{indentation}{marker}",
                1,
            )
            path.write_text(text, encoding="utf-8")

            assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_ignores_indented_terminal_order(tmp_path: Path) -> None:
    """Verify that an indented terminal sequence is not operative policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path, markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        order_prefix = "" if anchor.startswith("#") else "  "
        code_prefix = "    " if anchor.startswith("#") else "      "
        order_block = "\n".join(
            (
                order_prefix + TERMINAL_CLEANUP_ORDER_ANCHOR,
                "",
                *(order_prefix + line for line in TERMINAL_CLEANUP_ORDER_LINES),
            )
        )
        indented_order = "\n".join(
            code_prefix + line if line else code_prefix for line in order_block.splitlines()
        )
        incidental_markers = "\n".join(order_prefix + marker for marker in markers)
        path.write_text(
            text.replace(
                order_block,
                incidental_markers + "\n" + indented_order,
                1,
            ),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "completed-task cleanup markers must remain ordered: "
            + " -> ".join(markers)
        )


def test_agent_policy_gate_ignores_quoted_cleanup_markers(tmp_path: Path) -> None:
    """Verify that quoted examples and lazy continuations cannot satisfy markers.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        quote_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        insertion = f"\n{quote_prefix}> quoted example\n{quote_prefix}{marker}"
        path.write_text(
            text.replace(anchor, anchor + insertion, 1)
            if anchor.startswith("#")
            else text.replace(sibling, insertion + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_ignores_nested_quote_lazy_continuations(
    tmp_path: Path,
) -> None:
    """Verify lazy prose after nested quoted paragraphs stays non-operative.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        quote_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        insertion = f"\n{quote_prefix}> > quoted example\n{quote_prefix}{marker}"
        path.write_text(
            text.replace(anchor, anchor + insertion, 1)
            if anchor.startswith("#")
            else text.replace(sibling, insertion + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_keeps_invalid_fences_in_lazy_block_quotes(
    tmp_path: Path,
) -> None:
    """Verify invalid backtick info cannot interrupt a quoted paragraph.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        quote_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        insertion = (
            f"\n{quote_prefix}> quoted example\n"
            f"{quote_prefix}```invalid {marker}"
        )
        path.write_text(
            text.replace(anchor, anchor + insertion, 1)
            if anchor.startswith("#")
            else text.replace(sibling, insertion + sibling, 1),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_preserves_policy_after_quoted_headings(
    tmp_path: Path,
) -> None:
    """Verify a quoted heading cannot start lazy paragraph continuation.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f"> # Example\n{content_prefix}{marker}",
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_headings_after_block_quotes(tmp_path: Path) -> None:
    """Verify that an ATX heading ends a block quote without a blank line.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        heading_level = len(anchor) - len(anchor.lstrip("#"))
        path.write_text(
            text
            + "\n> quoted example\n"
            + f"{'#' * heading_level} Following policy\n\n{marker}\n",
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_preserves_html_blocks_after_block_quotes(
    tmp_path: Path,
) -> None:
    """Verify visible block HTML interrupts a quote without a blank line.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        text = path.read_text(encoding="utf-8").replace(
            marker,
            f"> quoted example\n{content_prefix}<div>{marker}</div>",
            1,
        )
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_keeps_noninitial_ordered_items_in_lazy_block_quotes(
    tmp_path: Path,
) -> None:
    """Verify that ordered items starting above one remain lazy quote continuations.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if not anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        path.write_text(
            text.replace(
                anchor,
                anchor + f"\n> quoted example\n2. {marker}",
                1,
            ),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_ignores_indented_code_after_paragraph_ordered_text(
    tmp_path: Path,
) -> None:
    """Verify noninterrupting ordered prose cannot create list indentation.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        replacement = (
            f"paragraph\n{content_prefix}2. prose\n{content_prefix}\n"
            f"{content_prefix}    {marker}"
        )
        text = path.read_text(encoding="utf-8").replace(marker, replacement, 1)
        path.write_text(text, encoding="utf-8")

        findings = check_agent_policy_gate(tmp_path)

        assert any(
            finding.path == path
            and finding.message
            == f"completed-task cleanup section marker is missing: {marker}"
            for finding in findings
        )


def test_agent_policy_gate_applies_wide_list_padding_to_indented_code(
    tmp_path: Path,
) -> None:
    """Verify five-space list padding leaves four code-indent spaces.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        replacement = f"-     example\n{content_prefix}      {marker}"
        text = path.read_text(encoding="utf-8").replace(marker, replacement, 1)
        path.write_text(text, encoding="utf-8")

        findings = check_agent_policy_gate(tmp_path)

        assert any(
            finding.path == path
            and finding.message
            == f"completed-task cleanup section marker is missing: {marker}"
            for finding in findings
        )


def test_agent_policy_gate_keeps_empty_list_markers_in_lazy_block_quotes(
    tmp_path: Path,
) -> None:
    """Verify empty list markers do not interrupt quoted paragraphs.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        for list_marker in ("-", "*", "+", "1.", "1)"):
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            text = path.read_text(encoding="utf-8").replace(
                marker,
                f"> quoted example\n{content_prefix}{list_marker}\n"
                f"{content_prefix}{marker}",
                1,
            )
            path.write_text(text, encoding="utf-8")

            findings = check_agent_policy_gate(tmp_path)

            assert any(
                finding.path == path
                and finding.message
                == f"completed-task cleanup section marker is missing: {marker}"
                for finding in findings
            )


def test_agent_policy_gate_preserves_deeply_nested_list_policy(
    tmp_path: Path,
) -> None:
    """Verify deep-list content is not mistaken for indented code.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        content_prefix = "" if anchor.startswith("#") else "  "
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        replacement = (
            f"- outer\n{content_prefix}  - inner\n"
            f"{content_prefix}    - deep\n{content_prefix}      {marker}"
        )
        text = path.read_text(encoding="utf-8").replace(marker, replacement, 1)
        path.write_text(text, encoding="utf-8")

        assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_preserves_list_items_after_block_quotes(
    tmp_path: Path,
) -> None:
    """Verify that a top-level sibling list item ends a nested block quote.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    marker = '`cleanup-ready`'
    sibling = "\n- following policy"
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        if anchor.startswith("#"):
            continue
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8").replace(marker, "", 1)
        path.write_text(
            text.replace(
                sibling,
                "\n  > quoted example" + sibling + f"\n\n  {marker}",
                1,
            ),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"completed-task cleanup section marker is missing: {marker}"
        )


def test_agent_policy_gate_ignores_quoted_terminal_order(tmp_path: Path) -> None:
    """Verify that a block-quoted terminal sequence is not operative policy.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path, markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
        order_prefix = "" if anchor.startswith("#") else "  "
        order_block = "\n".join(
            (
                order_prefix + TERMINAL_CLEANUP_ORDER_ANCHOR,
                "",
                *(order_prefix + line for line in TERMINAL_CLEANUP_ORDER_LINES),
            )
        )
        quote_prefix = "> " if anchor.startswith("#") else "  > "
        quoted_order = "\n".join(
            quote_prefix + line.lstrip() for line in order_block.splitlines()
        )
        incidental_markers = "\n".join(order_prefix + marker for marker in markers)
        path.write_text(
            text.replace(
                order_block,
                incidental_markers + "\n" + quoted_order,
                1,
            ),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            "completed-task cleanup markers must remain ordered: "
            + " -> ".join(markers)
        )


def test_agent_policy_gate_rejects_fourth_terminal_transition(tmp_path: Path) -> None:
    """Verify that the terminal lifecycle contains exactly three transitions.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path, markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items():
        for delimiter in (".", ")"):
            for permitted_indent in range(3):
                write_policy_files(tmp_path)
                path = tmp_path / relative_path
                text = path.read_text(encoding="utf-8")
                anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
                order_prefix = "" if anchor.startswith("#") else "  "
                expected_order = "\n".join(
                    order_prefix + line for line in TERMINAL_CLEANUP_ORDER_LINES
                )
                path.write_text(
                    text.replace(
                        expected_order,
                        expected_order
                        + f"\n{order_prefix}{' ' * permitted_indent}"
                        + f"4{delimiter} archived",
                        1,
                    ),
                    encoding="utf-8",
                )

                findings = check_agent_policy_gate(tmp_path)

                assert len(findings) == 1
                assert findings[0].path == path
                assert findings[0].message == (
                    "completed-task cleanup markers must remain ordered: "
                    + " -> ".join(markers)
                )


def test_agent_policy_gate_accepts_nested_terminal_instructions(tmp_path: Path) -> None:
    """Verify nested numbered guidance beneath each state is not a transition.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path in ORDERED_TERMINAL_CLEANUP_MARKERS:
        for nested_indent in (3, 4):
            for terminal_line in TERMINAL_CLEANUP_ORDER_LINES:
                write_policy_files(tmp_path)
                path = tmp_path / relative_path
                text = path.read_text(encoding="utf-8")
                anchor = TERMINAL_CLEANUP_SECTION_ANCHORS[relative_path]
                order_prefix = "" if anchor.startswith("#") else "  "
                rendered_line = order_prefix + terminal_line
                nested_prefix = order_prefix + " " * nested_indent
                path.write_text(
                    text.replace(
                        rendered_line,
                        rendered_line + f"\n{nested_prefix}1. Preserve traceability",
                        1,
                    ),
                    encoding="utf-8",
                )

                assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_rejects_missing_entry_point(tmp_path: Path) -> None:
    """Verify that agent policy gate rejects missing entry point.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    missing_path = tmp_path / ".github" / "copilot-instructions.md"
    missing_path.unlink()

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == missing_path
    assert findings[0].message == (
        "required agent policy entry point is missing or unreadable"
    )


def test_agent_policy_gate_rejects_missing_private_remediation_marker(
    tmp_path: Path,
) -> None:
    """Verify that the canonical private vulnerability workflow remains enforced.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    security_path = tmp_path / "SECURITY.md"
    security_path.write_text(
        security_path.read_text(encoding="utf-8").replace(
            "temporary private fork", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == security_path
    assert findings[0].message == (
        "required agent policy marker is missing: temporary private fork"
    )


def test_agent_policy_gate_rejects_missing_detailed_private_remediation_marker(
    tmp_path: Path,
) -> None:
    """Verify that detailed agent policy retains private remediation enforcement.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    policy_path = tmp_path / "docs" / "contribute" / "agent-policies.md"
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8").replace(
            "temporary private fork", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == policy_path
    assert findings[0].message == (
        "required agent policy marker is missing: temporary private fork"
    )


def test_agent_policy_gate_requires_private_follow_through_replacement(
    tmp_path: Path,
) -> None:
    """Verify that private forks replace unavailable integration follow-through.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_markers = {
        Path("AGENTS.md"): "advisory-side maintainer review",
        Path("CONTRIBUTING.md"): "advisory-side maintainer review",
        Path(".github/copilot-instructions.md"): "advisory-side maintainer review",
        Path(".github/pull_request_template.md"): "advisory-side maintainer review",
        Path("SECURITY.md"): "advisory-side maintainer review",
        Path("docs/contribute/agent-policies.md"): "Advisory-side maintainer review",
    }

    for relative_path, marker in required_entry_markers.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_agent_policy_gate_requires_private_complete_python_validation(
    tmp_path: Path,
) -> None:
    """Verify that private Python changes assign the complete suite locally.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_markers = {
        Path("AGENTS.md"): "test suite locally when required",
        Path("CONTRIBUTING.md"): "complete Python test suite locally",
        Path(".github/copilot-instructions.md"): "complete Python test suite locally",
        Path(".github/pull_request_template.md"): (
            "complete Python test suite ran locally"
        ),
        Path("SECURITY.md"): "complete Python test suite locally",
        Path("docs/contribute/agent-policies.md"): (
            "complete Python test suite locally"
        ),
    }

    for relative_path, marker in required_entry_markers.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        path.write_text(
            path.read_text(encoding="utf-8").replace(marker, ""),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {marker}"
        )


def test_pr_template_scopes_ci_owned_python_suite_to_ordinary_prs(
    tmp_path: Path,
) -> None:
    """Verify that the CI-owned suite checkbox excludes private-fork PRs.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    template_path = tmp_path / ".github/pull_request_template.md"
    marker = "For an ordinary pull request, focused local tests/checks passed"
    template_path.write_text(
        template_path.read_text(encoding="utf-8").replace(marker, ""),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == template_path
    assert findings[0].message == (
        f"required agent policy marker is missing: {marker}"
    )


def test_agent_policy_gate_rejects_missing_ui_guide(tmp_path: Path) -> None:
    """Verify that agent policy gate rejects missing ui guide.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    missing_path = tmp_path / "docs" / "contribute" / "ui-design-guide.md"
    missing_path.unlink()

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == missing_path
    assert findings[0].message == (
        "required agent policy entry point is missing or unreadable"
    )


def test_agent_policy_gate_rejects_missing_ui_gate(tmp_path: Path) -> None:
    """Verify that agent policy gate rejects missing ui gate.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_policy_files(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "## Mandatory UI Design Guide Gate", ""
        ),
        encoding="utf-8",
    )

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == agents_path
    assert findings[0].message == (
        "required agent policy marker is missing: "
        "## Mandatory UI Design Guide Gate"
    )


def write_ui_foundation_fixture(root: Path) -> None:
    """Persist ui foundation fixture.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    static = root / "atlaso" / "app" / "static"
    templates = root / "atlaso" / "app" / "templates"
    static.mkdir(parents=True)
    templates.mkdir(parents=True)
    (static / "ui-patterns.js").write_text(
        "globalThis.AtlasoUiPatterns = { createGrid() { return new global.Tabulator(); }, "
        "createWizard() {} };\n",
        encoding="utf-8",
    )
    (static / "app.js").write_text(
        "globalThis.AtlasoUiPatterns.createGrid({ element: '#grid' });\n",
        encoding="utf-8",
    )
    (templates / "wizard.html").write_text(
        """
<form class="vcf-sddc-wizard-panel" data-atlaso-wizard>
  <section data-atlaso-wizard-step="identity"></section>
  <button data-atlaso-wizard-nav="identity"></button>
  <div data-atlaso-wizard-error></div>
  <button data-atlaso-wizard-back></button>
  <button data-atlaso-wizard-next></button>
  <button data-atlaso-wizard-cancel></button>
  <button data-atlaso-wizard-submit></button>
</form>
""".strip(),
        encoding="utf-8",
    )


def test_ui_pattern_foundation_accepts_shared_entry_points(tmp_path: Path) -> None:
    """Verify that ui pattern foundation accepts shared entry points.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_ui_foundation_fixture(tmp_path)

    assert check_ui_pattern_foundation(tmp_path) == []


def test_ui_pattern_foundation_rejects_new_raw_tabulator(tmp_path: Path) -> None:
    """Verify that ui pattern foundation rejects new raw tabulator.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_ui_foundation_fixture(tmp_path)
    path = tmp_path / "atlaso" / "app" / "static" / "new-page.js"
    path.write_text("new window.Tabulator('#new-grid');\n", encoding="utf-8")

    findings = check_ui_pattern_foundation(tmp_path)

    assert any(
        finding.path == path
        and finding.message == "raw Tabulator construction is forbidden; use AtlasoUiPatterns.createGrid"
        for finding in findings
    )


def test_ui_pattern_foundation_rejects_raw_tabulator_in_template(tmp_path: Path) -> None:
    """Verify that ui pattern foundation rejects raw tabulator in template.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_ui_foundation_fixture(tmp_path)
    path = tmp_path / "atlaso" / "app" / "templates" / "inline-grid.html"
    path.write_text(
        "<script>\nnew Tabulator('#new-grid');\n</script>\n",
        encoding="utf-8",
    )

    findings = check_ui_pattern_foundation(tmp_path)

    assert any(
        finding.path == path
        and finding.line == 2
        and finding.message
        == "raw Tabulator construction is forbidden; use AtlasoUiPatterns.createGrid"
        for finding in findings
    )


def test_ui_pattern_foundation_rejects_completed_legacy_marker(tmp_path: Path) -> None:
    """Verify that ui pattern foundation rejects completed legacy marker.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_ui_foundation_fixture(tmp_path)
    path = tmp_path / "atlaso" / "app" / "static" / "app.js"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            f"/* {LEGACY_TABULATOR_MARKER} */ new Tabulator('#bypass');\n"
        )

    findings = check_ui_pattern_foundation(tmp_path)

    assert any(
        finding.path == path
        and finding.message == "the completed #117 legacy Tabulator marker is forbidden"
        for finding in findings
    )


def test_ui_pattern_foundation_rejects_wizard_without_shared_contract(tmp_path: Path) -> None:
    """Verify that ui pattern foundation rejects wizard without shared contract.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_ui_foundation_fixture(tmp_path)
    path = tmp_path / "atlaso" / "app" / "templates" / "bypass.html"
    path.write_text(
        '<form class="vcf-sddc-wizard-panel"><button>Next</button></form>\n',
        encoding="utf-8",
    )

    findings = check_ui_pattern_foundation(tmp_path)

    assert any(
        finding.path == path and finding.message == "wizard form must declare data-atlaso-wizard"
        for finding in findings
    )


def test_ui_pattern_foundation_rejects_page_step_controller(tmp_path: Path) -> None:
    """Verify that ui pattern foundation rejects page step controller.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    write_ui_foundation_fixture(tmp_path)
    path = tmp_path / "atlaso" / "app" / "static" / "new-wizard.js"
    path.write_text(
        'document.querySelectorAll("[data-atlaso-wizard-step]");\n',
        encoding="utf-8",
    )

    findings = check_ui_pattern_foundation(tmp_path)

    assert any(
        finding.path == path
        and finding.message
        == "page-specific wizard step control is forbidden; use AtlasoUiPatterns.createWizard"
        for finding in findings
    )
