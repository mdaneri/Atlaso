"""Check operative resource gates and title readback across cleanup documents."""

from pathlib import Path

import pytest

from scripts.check_repo import (
    TERMINAL_CLEANUP_ORDER_LINES,
    VALIDATION_RESOURCE_POLICY_MARKERS,
    VALIDATION_RESOURCE_SECTION_ANCHORS,
    check_validation_resource_policy,
)


def write_resource_policies(root: Path) -> None:
    """Write minimal valid resource contracts for all required entry points."""
    for relative, anchor in VALIDATION_RESOURCE_SECTION_ANCHORS.items():
        prefix = "" if anchor.startswith("#") else "  "
        lines = [anchor, "", *(prefix + marker for marker in VALIDATION_RESOURCE_POLICY_MARKERS)]
        lines += ["", prefix + "Terminal order:", "", *(prefix + line for line in TERMINAL_CLEANUP_ORDER_LINES)]
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_resource_policy_accepts_complete_contract(tmp_path: Path) -> None:
    """The same operative contract is valid in headings and nested checklist items."""
    write_resource_policies(tmp_path)
    assert check_validation_resource_policy(tmp_path) == []


@pytest.mark.parametrize("relative", VALIDATION_RESOURCE_SECTION_ANCHORS)
@pytest.mark.parametrize("marker", VALIDATION_RESOURCE_POLICY_MARKERS)
@pytest.mark.parametrize("replacement", ["", "<!-- {marker} -->", "```text\n{marker}\n```", "outside"])
def test_resource_policy_rejects_missing_or_hidden_requirement(
    tmp_path: Path, relative: Path, marker: str, replacement: str
) -> None:
    """Every ownership, retention, tooling, and readback requirement must be operative."""
    write_resource_policies(tmp_path)
    path = tmp_path / relative
    prefix = "" if VALIDATION_RESOURCE_SECTION_ANCHORS[relative].startswith("#") else "  "
    text = path.read_text(encoding="utf-8")
    rendered = replacement.format(marker=marker).replace("\n", "\n" + prefix)
    if replacement == "outside":
        text = marker + "\n\n" + text.replace(marker, "")
    else:
        text = text.replace(marker, rendered)
    path.write_text(text, encoding="utf-8")
    findings = check_validation_resource_policy(tmp_path)
    assert [(finding.path, finding.message) for finding in findings] == [
        (path, f"validation-resource policy marker is missing: {marker}")
    ]


@pytest.mark.parametrize("relative", VALIDATION_RESOURCE_SECTION_ANCHORS)
@pytest.mark.parametrize("mutation", ["missing", "reordered", "old_order", "extra"])
def test_resource_policy_requires_release_before_terminal_cleanup(
    tmp_path: Path, relative: Path, mutation: str
) -> None:
    """Resource release cannot be omitted, postponed, or hidden by an extra transition."""
    write_resource_policies(tmp_path)
    path = tmp_path / relative
    prefix = "" if VALIDATION_RESOURCE_SECTION_ANCHORS[relative].startswith("#") else "  "
    old = "\n".join(prefix + line for line in TERMINAL_CLEANUP_ORDER_LINES)
    markers = [line.split(". ", 1)[1] for line in TERMINAL_CLEANUP_ORDER_LINES]
    if mutation in {"missing", "old_order"}:
        markers.pop(0)
    elif mutation == "reordered":
        markers[0], markers[1] = markers[1], markers[0]
    else:
        markers.append("archived")
    new = "\n".join(f"{prefix}{index}. {marker}" for index, marker in enumerate(markers, 1))
    if mutation == "missing":
        new = "\n".join(prefix + line for line in TERMINAL_CLEANUP_ORDER_LINES[1:])
    path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    findings = check_validation_resource_policy(tmp_path)
    assert len(findings) == 1
    assert findings[0].path == path
    assert "release must precede" in findings[0].message


@pytest.mark.parametrize("relative", VALIDATION_RESOURCE_SECTION_ANCHORS)
def test_resource_policy_requires_document_and_unique_section(tmp_path: Path, relative: Path) -> None:
    """Missing documents and ambiguous operative sections fail closed."""
    write_resource_policies(tmp_path)
    path = tmp_path / relative
    text = path.read_text(encoding="utf-8")
    path.write_text(text + "\n" + text, encoding="utf-8")
    assert any("exactly once" in finding.message for finding in check_validation_resource_policy(tmp_path))
    path.unlink()
    assert any("missing or unreadable" in finding.message for finding in check_validation_resource_policy(tmp_path))
