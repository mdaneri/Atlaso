"""Test check repo policies behavior."""

from pathlib import Path

from scripts.check_repo import (
    LEGACY_TABULATOR_MARKER,
    LOCAL_TASK_BRANCH_ABSENT_MARKER,
    MAINTAINER_BREAK_GLASS_SHARED_MARKERS,
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
    check_protected_workflow_caches,
    check_spark_worker_agent,
    check_ui_pattern_foundation,
    check_virtualization_legacy,
    collect_files,
    is_checkable,
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
        other_markers = tuple(
            marker
            for marker in markers
            if marker not in section_markers
            and marker != section_anchor
            and marker not in monitoring_markers
            and marker != monitoring_anchor
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
        "merged, closed, or merge-ready",
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


def test_agent_policy_gate_rejects_missing_maintainer_break_glass_contract(
    tmp_path: Path,
) -> None:
    """Verify policy surfaces preserve the complete automation prohibition.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_points = (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("SECURITY.md"),
        Path("docs/contribute/agent-policies.md"),
        Path("docs/reference/full-technical-reference.md"),
    )

    for marker in MAINTAINER_BREAK_GLASS_SHARED_MARKERS:
        for relative_path in required_entry_points:
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            original = path.read_text(encoding="utf-8")
            assert marker in original
            path.write_text(
                original.replace(marker, "", 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"required agent policy marker is missing: {marker}"
            )

    prohibition = (
        "automation must never use or request a ruleset or administrative bypass"
    )
    for relative_path in required_entry_points:
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        original = path.read_text(encoding="utf-8")
        assert prohibition in original
        path.write_text(
            original.replace(
                prohibition,
                "automation may use or request a ruleset or administrative bypass",
                1,
            ),
            encoding="utf-8",
        )

        findings = check_agent_policy_gate(tmp_path)

        assert len(findings) == 1
        assert findings[0].path == path
        assert findings[0].message == (
            f"required agent policy marker is missing: {prohibition}"
        )

    nonoperative_replacements = (
        f"<!-- {prohibition} -->",
        f"```text\n{prohibition}\n```",
        f"<del>{prohibition}</del>",
        f"<s>{prohibition}</s>",
        f"<strike>{prohibition}</strike>",
        f"<del><del>retired</del> {prohibition}</del>",
        f"<s><s>retired</s> {prohibition}</s>",
        f"<strike><strike>retired</strike> {prohibition}</strike>",
        f"<del><s>retired</del> {prohibition}</s>",
        f"<s><strike>retired</s> {prohibition}</strike>",
        f"<del/>retired {prohibition}</del>",
        f"<s/>retired {prohibition}</s>",
        f"<strike/>retired {prohibition}</strike>",
        f"~~{prohibition}~~",
        f"~~retired `~~` {prohibition}~~",
        f"policy ~~~~{prohibition}~~ remains",
        f"~~retired~~~~~{prohibition}~~",
        f"~~retired.~~{prohibition}~~",
        f"~~retired$~~{prohibition}~~",
        f"]~~~~retired~~~~active~~{prohibition}~~",
    )
    for replacement in nonoperative_replacements:
        for relative_path in required_entry_points:
            write_policy_files(tmp_path)
            path = tmp_path / relative_path
            original = path.read_text(encoding="utf-8")
            assert prohibition in original
            path.write_text(
                original.replace(prohibition, replacement, 1),
                encoding="utf-8",
            )

            findings = check_agent_policy_gate(tmp_path)

            assert len(findings) == 1
            assert findings[0].path == path
            assert findings[0].message == (
                f"required agent policy marker is missing: {prohibition}"
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
