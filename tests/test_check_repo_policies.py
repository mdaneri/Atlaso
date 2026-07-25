from pathlib import Path

from scripts.check_repo import REQUIRED_POLICY_MARKERS, check_agent_policy_gate


def write_policy_files(root: Path) -> None:
    for relative_path, markers in REQUIRED_POLICY_MARKERS.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(markers), encoding="utf-8")


def test_agent_policy_gate_accepts_all_required_entry_points(tmp_path: Path) -> None:
    write_policy_files(tmp_path)

    assert check_agent_policy_gate(tmp_path) == []


def test_agent_policy_gate_rejects_missing_marker(tmp_path: Path) -> None:
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


def test_agent_policy_gate_rejects_missing_entry_point(tmp_path: Path) -> None:
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
    write_policy_files(tmp_path)
    missing_path = tmp_path / "docs" / "ui-design-guide.md"
    missing_path.unlink()

    findings = check_agent_policy_gate(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == missing_path
    assert findings[0].message == (
        "required agent policy entry point is missing or unreadable"
    )


def test_agent_policy_gate_rejects_missing_ui_gate(tmp_path: Path) -> None:
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
