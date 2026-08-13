"""Test check repo policies behavior."""

from pathlib import Path

from scripts.check_repo import (
    LEGACY_TABULATOR_MARKER,
    REQUIRED_POLICY_MARKERS,
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
        path.write_text("\n".join(markers), encoding="utf-8")


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
