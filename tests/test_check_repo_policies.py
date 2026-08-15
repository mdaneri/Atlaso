"""Test check repo policies behavior."""

from pathlib import Path

from scripts.check_repo import (
    LEGACY_TABULATOR_MARKER,
    ORDERED_TERMINAL_CLEANUP_MARKERS,
    REQUIRED_POLICY_MARKERS,
    TERMINAL_CLEANUP_SECTION_ANCHORS,
    check_agent_policy_gate,
    check_ui_pattern_foundation,
    collect_files,
    is_checkable,
)


def test_deployment_assets_are_checkable_text() -> None:
    """Verify that every protected deployment asset class enters repository checks."""
    paths = (
        Path("image/hyperv/atlaso-photon.pkr.hcl"),
        Path("image/common/systemd/atlaso-worker.service"),
        Path("image/common/systemd/atlaso-console-manager.conf"),
        Path("image/common/systemd/nginx-atlaso-data-disks.conf"),
        Path("image/vmware-workstation/sudoers.d/atlaso-helper"),
    )

    assert all(is_checkable(path) for path in paths)
    assert all(len(collect_files([str(path)])) == 1 for path in paths)


def write_policy_files(root: Path) -> None:
    """Persist policy files.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    for relative_path, markers in REQUIRED_POLICY_MARKERS.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        ordered_markers = ORDERED_TERMINAL_CLEANUP_MARKERS.get(relative_path, ())
        section_anchor = TERMINAL_CLEANUP_SECTION_ANCHORS.get(relative_path)
        other_markers = tuple(
            marker
            for marker in markers
            if marker not in ordered_markers and marker != section_anchor
        )
        policy_lines = list(other_markers)
        if section_anchor is not None:
            policy_lines.extend((section_anchor, *ordered_markers, "- following policy"))
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


def test_agent_policy_gate_rejects_missing_explicit_merge_authorization(
    tmp_path: Path,
) -> None:
    """Verify that every agent entry point requires explicit merge authorization.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_markers = {
        Path("AGENTS.md"): "### Explicit merge authorization",
        Path("CONTRIBUTING.md"): "### Explicit merge authorization",
        Path(".github/copilot-instructions.md"): "Explicit merge authorization",
        Path(".github/pull_request_template.md"): "Explicit merge authorization",
        Path("docs/contribute/agent-policies.md"): (
            "### Explicit merge authorization"
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


def test_agent_policy_gate_rejects_missing_explicit_merge_instruction(
    tmp_path: Path,
) -> None:
    """Verify that agent entry points require an explicit merge instruction.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    required_entry_points = (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("docs/contribute/agent-policies.md"),
    )
    marker = "explicit merge instruction"

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


def test_agent_policy_gate_requires_terminal_cleanup_order(tmp_path: Path) -> None:
    """Verify that branch, worktree, and title transitions remain ordered.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    for relative_path, markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items():
        write_policy_files(tmp_path)
        path = tmp_path / relative_path
        text = path.read_text(encoding="utf-8")
        earlier_summary = "\n".join(markers)
        path.write_text(
            earlier_summary
            + "\n"
            + text.replace("\n".join(markers), "\n".join(reversed(markers))),
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
        path.write_text(
            "\n".join(reversed(markers))
            + "\n"
            + path.read_text(encoding="utf-8"),
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
