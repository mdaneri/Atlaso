#!/usr/bin/env python3
"""Repository-wide syntax and content checks for Atlaso.

The checker is intentionally lightweight so it can run as a pre-commit hook on
changed files and as a full-repo smoke test before pushing a branch.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

SKIP_PARTS = {
    ".git",
    ".build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site",
    "test-results",
}

SKIP_PREFIXES = (
    Path("atlaso/app/static/vendor"),
    Path("third_party"),
    Path("VCFDT"),
    Path("vcfDownloadTool"),
)

TEXT_SUFFIXES = {
    ".conf",
    ".css",
    ".hcl",
    ".htm",
    ".html",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".svg",
    ".service",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]+\]\(([^)]+)\)")
TABULATOR_CONSTRUCTOR_RE = re.compile(
    r"\bnew\s+(?:(?:window|globalThis|global)\.)?Tabulator\s*\("
)
HTML_FORM_RE = re.compile(
    r"<form\b(?P<attributes>[^>]*)>(?P<body>.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)
UI_PATTERN_FOUNDATION = Path("atlaso/app/static/ui-patterns.js")
LEGACY_TABULATOR_MARKER = "atlaso-legacy-tabulator: #117"
WIZARD_REQUIRED_MARKERS = (
    "data-atlaso-wizard-step",
    "data-atlaso-wizard-nav",
    "data-atlaso-wizard-error",
    "data-atlaso-wizard-back",
    "data-atlaso-wizard-next",
    "data-atlaso-wizard-cancel",
    "data-atlaso-wizard-submit",
)
FORBIDDEN_PAGE_WIZARD_CONTROLLER_MARKERS = (
    'querySelectorAll("[data-atlaso-wizard-step]")',
    "querySelectorAll('[data-atlaso-wizard-step]')",
    'querySelectorAll("[data-atlaso-wizard-nav]")',
    "querySelectorAll('[data-atlaso-wizard-nav]')",
    "dataset.atlasoWizardStep",
    "dataset.atlasoWizardNav",
)

REQUIRED_POLICY_MARKERS = {
    Path("AGENTS.md"): (
        "## Mandatory Agent Startup Gate",
        "## Codex Task Title Traceability",
        "### Supported title controls",
        "Short description · Issue #<issue> · PR #<pr>",
        "### Unsupported title controls",
        "### Schema-constrained reporting",
        "## Mandatory UI Design Guide Gate",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "docs/contribute/ui-design-guide.md",
        "first progress update",
        "delegating agent",
        "direct-edit Tabulator",
        "custom/other",
        "explicit maintainer approval",
        "private vulnerability remediation",
        "advisory-side maintainer review",
        "test suite locally when required",
        "### Focused local validation and pull-request follow-through",
        "Python test suite locally",
        "ready for review",
        "@codex review",
        "exact head",
        "reviewThreads",
        "### Unrelated issue discoveries",
        "### Explicit merge authorization",
        "explicit merge instruction",
        "strict up-to-date required checks",
        "no merge queue is required",
        "--match-head-commit <head-sha>",
        "### Extended merge descriptions",
        "## Completed Task Cleanup",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        '" · Done"',
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
    ),
    Path("CONTRIBUTING.md"): (
        "## Automated contributors and coding agents",
        "## User-interface contributions",
        "Mandatory Agent Startup Gate",
        "Mandatory UI Design Guide Gate",
        "docs/contribute/ui-design-guide.md",
        "custom/other",
        "delegated agent",
        "### Automated pull-request follow-through",
        "Python test suite locally",
        "ready for review",
        "@codex review",
        "exact head",
        "review threads",
        "### Unrelated issue discoveries",
        "### Explicit merge authorization",
        "explicit merge instruction",
        "strict up-to-date required checks",
        "no required merge queue",
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
        "private vulnerability remediation",
        "advisory-side maintainer review",
        "complete Python test suite locally",
        "### Completed task cleanup",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        '" · Done"',
    ),
    Path(".github/copilot-instructions.md"): (
        "Mandatory Agent Startup Gate",
        "Mandatory UI Design Guide Gate",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "docs/contribute/ui-design-guide.md",
        "custom/other",
        "linked GitHub issue",
        "complete Python test suite belongs to GitHub CI",
        "ready for review",
        "@codex review",
        "exact head",
        "review threads",
        "Explicit merge authorization",
        "explicit merge instruction",
        "strict up-to-date required checks",
        "when a merge queue is required",
        "evidence-backed unrelated problem",
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
        "private vulnerability remediation",
        "advisory-side maintainer review",
        "complete Python test suite locally",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        '" · Done"',
    ),
    Path("SECURITY.md"): (
        "## Privately fixing a validated vulnerability",
        "draft repository security advisory",
        "temporary private fork",
        "current default branch",
        "workspace repositories",
        "`UNSTABLE`",
        "`gh pr merge`",
        "Merge pull request(s)",
        "only one pull request may target `main`",
        "Publishing the advisory is a separate explicit action",
        "Explicit maintainer authorization",
        "coordinated disclosure",
        "advisory-side maintainer review",
        "complete Python test suite locally",
    ),
    Path("docs/contribute/agent-policies.md"): (
        "# Detailed agent policies",
        "## Mandatory Agent Startup Gate",
        "## Repository Delivery Workflow",
        "private vulnerability remediation",
        "temporary private fork",
        "`gh pr merge`",
        "Publishing is a separate explicit action",
        "explicit maintainer authorization",
        "Advisory-side maintainer review",
        "complete Python test suite locally",
        "### Focused local validation and pull-request follow-through",
        "Python test suite locally",
        "ready for review",
        "@codex review",
        "exact head",
        "reviewThreads",
        "outside that scope is discovered",
        "### Explicit merge authorization",
        "explicit merge instruction",
        "strict up-to-date required checks",
        "no required merge queue",
        "### Completed task cleanup",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        '" · Done"',
    ),
    Path(".github/pull_request_template.md"): (
        "Closes #",
        "Mandatory Agent Startup Gate",
        "For an ordinary pull request, focused local tests/checks passed",
        "complete Python test suite",
        "ready for review",
        "each post-opening pushed commit received one `@codex review` request",
        "request as the exact",
        "authoritative review threads",
        "Explicit merge authorization",
        "explicit merge instruction",
        "strict up-to-date required checks",
        "no merge queue is required",
        "Evidence-backed issues discovered outside",
        "docs/contribute/ui-design-guide.md",
        "custom/other",
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
        "private vulnerability-remediation pull request",
        "advisory-side maintainer review",
        "complete Python test suite ran locally",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        '" · Done"',
    ),
    Path("docs/contribute/ui-design-guide.md"): (
        "# Atlaso UI Design Guide",
        "Tabulator is the only data-grid implementation",
        "Physical Interfaces",
        "ESX Storage",
        "Tasks",
        "Audit Events",
        "Automation Schedules",
        "Reviewed semantic-table exemptions",
        "Custom/other",
        "explicit maintainer approval",
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
    ),
}

ORDERED_TERMINAL_CLEANUP_MARKERS = {
    path: (
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
    )
    for path in (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("docs/contribute/agent-policies.md"),
    )
}

TERMINAL_CLEANUP_SECTION_ANCHORS = {
    Path("AGENTS.md"): "## Completed Task Cleanup",
    Path("CONTRIBUTING.md"): "### Completed task cleanup",
    Path(".github/copilot-instructions.md"): (
        "- after an authorized merge and all remaining activity,"
    ),
    Path(".github/pull_request_template.md"): (
        "- [ ] After any authorized merge and remaining post-merge activity,"
    ),
    Path("docs/contribute/agent-policies.md"): "### Completed task cleanup",
}

PRIVATE_REMEDIATION_CLEANUP_MARKER = "`advisory_cleanup_ready`"
PRIVATE_REMEDIATION_REMOTE_MARKER = "`advisory_remote_branch_absent`"
TERMINAL_CLEANUP_SECTION_MARKERS = {
    path: (
        "`cleanup-ready`",
        *ordered_markers,
        '" · Done"',
        PRIVATE_REMEDIATION_CLEANUP_MARKER,
        PRIVATE_REMEDIATION_REMOTE_MARKER,
    )
    for path, ordered_markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items()
}

TERMINAL_CLEANUP_ORDER_ANCHOR = "Terminal order:"
TERMINAL_CLEANUP_ORDER_LINES = tuple(
    f"{position}. {marker}"
    for position, marker in enumerate(
        next(iter(ORDERED_TERMINAL_CLEANUP_MARKERS.values())), start=1
    )
)


@dataclass(frozen=True)
class Finding:
    """Represent finding.

    Attributes:
        path: Path maintained by this finding.
        message: Message maintained by this finding.
        line: Line maintained by this finding.
    """
    path: Path
    message: str
    line: int | None = None

    def render(self) -> str:
        """Render operation.

        Returns:
            The render result.
        """
        display = self.path.relative_to(ROOT) if self.path.is_absolute() else self.path
        if self.line is None:
            return f"{display}: {self.message}"
        return f"{display}:{self.line}: {self.message}"


def relative_path(path: Path) -> Path:
    """Return relative path.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    try:
        return path.resolve().relative_to(ROOT)
    except ValueError:
        return path


def should_skip(path: Path) -> bool:
    """Return whether skip.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    rel = relative_path(path)
    if any(part in SKIP_PARTS or part.startswith(".venv") for part in rel.parts):
        return True
    return any(rel == prefix or rel.is_relative_to(prefix) for prefix in SKIP_PREFIXES)


def is_checkable(path: Path) -> bool:
    """Return whether checkable.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    rel = relative_path(path)
    return (
        len(rel.parts) >= 4
        and rel.parts[0] == "image"
        and rel.parent.name == "sudoers.d"
    )


def collect_files(paths: list[str]) -> list[Path]:
    """Return collect files.

    Args:
        paths: Paths consumed by collect files.
    """
    if paths:
        candidates: list[Path] = []
        for raw in paths:
            path = Path(raw)
            if not path.is_absolute():
                path = ROOT / path
            if path.is_dir():
                candidates.extend(path.rglob("*"))
            elif path.exists():
                candidates.append(path)
    else:
        candidates = list(ROOT.rglob("*"))

    files = []
    for path in candidates:
        if path.is_file() and not should_skip(path) and is_checkable(path):
            files.append(path.resolve())
    return sorted(set(files), key=lambda item: str(relative_path(item)))


def read_text(path: Path) -> tuple[str | None, Finding | None]:
    """Return text.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, Finding(path, f"cannot read file: {exc}")
    if b"\x00" in data:
        return None, Finding(path, "contains NUL bytes")
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return None, Finding(path, f"must be UTF-8 text: {exc}")


def line_for_offset(text: str, offset: int) -> int:
    """Return line for offset.

    Args:
        text: Text content consumed by the operation.
        offset: Offset consumed by line for offset.
    """
    return text.count("\n", 0, offset) + 1


def check_common_text(path: Path, text: str) -> list[Finding]:
    """Check common text.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check common text result.
    """
    findings: list[Finding] = []
    for index, line in enumerate(text.splitlines(), start=1):
        if line.startswith("<<<<<<< ") or line == "=======" or line.startswith(">>>>>>> "):
            findings.append(Finding(path, "contains unresolved merge conflict marker", index))
    return findings


def check_python(path: Path, text: str) -> list[Finding]:
    """Check python.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check python result.
    """
    try:
        ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return [Finding(path, exc.msg, exc.lineno)]
    return []


def check_json(path: Path, text: str) -> list[Finding]:
    """Check json.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check json result.
    """
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return [Finding(path, exc.msg, exc.lineno)]
    return []


def check_toml(path: Path, text: str) -> list[Finding]:
    """Check toml.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check toml result.
    """
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [Finding(path, str(exc))]
    return []


def check_jinja(path: Path, text: str) -> list[Finding]:
    """Check jinja.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check jinja result.
    """
    try:
        from jinja2 import Environment
        from jinja2.exceptions import TemplateSyntaxError
    except ImportError:
        return [Finding(path, "Jinja2 is required for template checks; run pip install -e .[dev]")]

    env = Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"])
    try:
        env.parse(text)
    except TemplateSyntaxError as exc:
        return [Finding(path, exc.message, exc.lineno)]
    return []


def strip_css_noise(text: str) -> str:
    """Return strip css noise.

    Args:
        text: Text content consumed by the operation.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    return text


def check_css(path: Path, text: str) -> list[Finding]:
    """Check css.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check css result.
    """
    findings: list[Finding] = []
    stack: list[tuple[str, int]] = []
    pairs = {"{": "}", "(": ")", "[": "]"}
    closing = {value: key for key, value in pairs.items()}
    for index, char in enumerate(strip_css_noise(text)):
        if char in pairs:
            stack.append((char, line_for_offset(text, index)))
        elif char in closing:
            if not stack or stack[-1][0] != closing[char]:
                findings.append(Finding(path, f"unexpected '{char}'", line_for_offset(text, index)))
                continue
            stack.pop()
    for char, line in stack:
        findings.append(Finding(path, f"unclosed '{char}'", line))
    return findings


def check_javascript(path: Path) -> list[Finding]:
    """Check javascript.

    Args:
        path: Filesystem or URL path to read, validate, or update.

    Returns:
        The check javascript result.
    """
    node = shutil.which("node")
    if node is None:
        return [Finding(path, "Node.js is required for JavaScript syntax checks")]
    result = subprocess.run(
        [node, "--check", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return []
    detail = (result.stderr or result.stdout).strip().splitlines()
    message = detail[-1] if detail else "node --check failed"
    return [Finding(path, message)]


def markdown_link_target_exists(path: Path, target: str) -> bool:
    """Return markdown link target exists.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        target: Resource targeted by the operation.
    """
    target = target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    target = unquote(target)
    if not target or target.startswith(("#", "/", "http://", "https://", "mailto:")):
        return True
    file_part = target.split("#", 1)[0]
    if not file_part:
        return True
    return (path.parent / file_part).exists()


def check_markdown(path: Path, text: str) -> list[Finding]:
    """Check markdown.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check markdown result.
    """
    findings: list[Finding] = []
    in_fence = False
    fence_line: int | None = None
    for index, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            fence_line = index if in_fence else None
            continue
        if in_fence:
            continue
        for match in MARKDOWN_LINK_RE.finditer(line):
            target = match.group(1)
            if not markdown_link_target_exists(path, target):
                findings.append(Finding(path, f"local Markdown link target not found: {target}", index))
    if in_fence:
        findings.append(Finding(path, "unclosed fenced code block", fence_line))
    return findings


def check_file(path: Path) -> list[Finding]:
    """Check file.

    Args:
        path: Filesystem or URL path to read, validate, or update.

    Returns:
        The check file result.
    """
    text, error = read_text(path)
    if error is not None:
        return [error]
    assert text is not None

    suffix = path.suffix.lower()
    findings = check_common_text(path, text)
    if suffix == ".py":
        findings.extend(check_python(path, text))
    elif suffix == ".json":
        findings.extend(check_json(path, text))
    elif suffix == ".toml":
        findings.extend(check_toml(path, text))
    elif suffix in {".html", ".htm"}:
        findings.extend(check_jinja(path, text))
    elif suffix == ".css":
        findings.extend(check_css(path, text))
    elif suffix == ".js":
        findings.extend(check_javascript(path))
    elif suffix == ".md":
        findings.extend(check_markdown(path, text))
    elif suffix == ".svg":
        findings.extend(check_xmlish_svg(path, text))
    return findings


def check_agent_policy_gate(root: Path) -> list[Finding]:
    """Require agent policy entry points and their non-negotiable markers.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    findings: list[Finding] = []
    for relative_path, markers in REQUIRED_POLICY_MARKERS.items():
        path = root / relative_path
        text, error = read_text(path)
        if error is not None:
            findings.append(Finding(path, "required agent policy entry point is missing or unreadable"))
            continue
        assert text is not None
        missing_required_markers = tuple(marker for marker in markers if marker not in text)
        for marker in missing_required_markers:
            findings.append(
                Finding(path, f"required agent policy marker is missing: {marker}")
            )
        ordered_markers = ORDERED_TERMINAL_CLEANUP_MARKERS.get(relative_path)
        section_markers = TERMINAL_CLEANUP_SECTION_MARKERS.get(relative_path, ())
        section_anchor = TERMINAL_CLEANUP_SECTION_ANCHORS.get(relative_path)
        section_anchor_count = (
            sum(
                line == section_anchor
                if section_anchor.startswith("#")
                else line.startswith(section_anchor)
                for line in text.splitlines()
            )
            if section_anchor is not None
            else 0
        )
        cleanup_section = (
            extract_markdown_policy_section(text, section_anchor)
            if section_anchor is not None and section_anchor_count == 1
            else None
        )
        if section_anchor is not None and section_anchor_count == 0:
            findings.append(
                Finding(
                    path,
                    f"completed-task cleanup section is missing: {section_anchor}",
                )
            )
        elif section_anchor is not None and section_anchor_count > 1:
            findings.append(
                Finding(
                    path,
                    "completed-task cleanup section must appear exactly once: "
                    + section_anchor,
                )
            )
        if section_markers and cleanup_section is not None:
            missing_section_markers = tuple(
                marker for marker in section_markers if marker not in cleanup_section
            )
            for marker in missing_section_markers:
                if marker not in missing_required_markers:
                    findings.append(
                        Finding(
                            path,
                            f"completed-task cleanup section marker is missing: {marker}",
                        )
                    )
        if ordered_markers is not None and cleanup_section is not None:
            order_lines = extract_terminal_cleanup_order(cleanup_section)
            if order_lines != TERMINAL_CLEANUP_ORDER_LINES:
                findings.append(
                    Finding(
                        path,
                        "completed-task cleanup markers must remain ordered: "
                        + " -> ".join(ordered_markers),
                    )
                )
    return findings


def extract_terminal_cleanup_order(cleanup_section: str) -> tuple[str, ...] | None:
    """Return the three numbered transitions following the terminal-order anchor.

    Args:
        cleanup_section: Canonical cleanup heading section or top-level list item.
    """
    lines = cleanup_section.splitlines()
    anchors = tuple(
        index
        for index, line in enumerate(lines)
        if line.strip() == TERMINAL_CLEANUP_ORDER_ANCHOR
    )
    if len(anchors) != 1:
        return None
    transitions = tuple(
        line.strip()
        for line in lines[anchors[0] + 1 :]
        if line.strip()
    )
    expected_count = len(TERMINAL_CLEANUP_ORDER_LINES)
    order_lines = transitions[:expected_count]
    if (
        len(transitions) > expected_count
        and re.fullmatch(r"\d+[.)]\s+.+", transitions[expected_count]) is not None
    ):
        order_lines += (transitions[expected_count],)
    return order_lines


def extract_markdown_policy_section(text: str, anchor: str) -> str | None:
    """Return the canonical heading section or top-level list item at ``anchor``.

    Args:
        text: Markdown policy entry point.
        anchor: Exact heading or top-level list-item prefix for the cleanup policy.
    """
    lines = text.splitlines(keepends=True)
    starts = tuple(
        index
        for index, line in enumerate(lines)
        if (line.rstrip("\r\n") == anchor if anchor.startswith("#") else line.startswith(anchor))
    )
    if len(starts) != 1:
        return None
    start = starts[0]

    if anchor.startswith("#"):
        heading_level = len(anchor) - len(anchor.lstrip("#"))
        for end in range(start + 1, len(lines)):
            heading_match = re.match(r" {0,3}(#{1,6})[ \t]+", lines[end])
            if heading_match is not None and len(heading_match.group(1)) <= heading_level:
                return "".join(lines[start:end])
            title_line = lines[end].rstrip("\r\n")
            title_indent = len(title_line) - len(title_line.lstrip(" "))
            setext_match = (
                re.fullmatch(r" {0,3}(=+|-+)[ \t]*(?:\r?\n)?", lines[end + 1])
                if end + 1 < len(lines) and title_line.strip() and title_indent <= 3
                else None
            )
            if setext_match is not None:
                next_level = 1 if setext_match.group(1).startswith("=") else 2
                if next_level <= heading_level:
                    return "".join(lines[start:end])
    else:
        for end in range(start + 1, len(lines)):
            if re.match(r"(?:[-+*]|\d+[.)])\s+", lines[end]) is not None:
                return "".join(lines[start:end])
    return "".join(lines[start:])


def check_ui_pattern_foundation(root: Path) -> list[Finding]:
    """Require new grids and every wizard to use the shared browser foundation.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    findings: list[Finding] = []
    foundation_path = root / UI_PATTERN_FOUNDATION
    foundation_text, foundation_error = read_text(foundation_path)
    if foundation_error is not None:
        return [Finding(foundation_path, "shared UI-pattern foundation is missing or unreadable")]
    assert foundation_text is not None
    for marker in ("AtlasoUiPatterns", "createGrid", "createWizard"):
        if marker not in foundation_text:
            findings.append(Finding(foundation_path, f"shared UI-pattern API marker is missing: {marker}"))

    static_root = root / "atlaso" / "app" / "static"
    for path in static_root.rglob("*.js") if static_root.exists() else []:
        relative = path.relative_to(root)
        if relative.is_relative_to(Path("atlaso/app/static/vendor")):
            continue
        text, error = read_text(path)
        if error is not None:
            findings.append(error)
            continue
        assert text is not None
        constructors = list(TABULATOR_CONSTRUCTOR_RE.finditer(text))
        if relative == UI_PATTERN_FOUNDATION:
            if len(constructors) != 1:
                findings.append(
                    Finding(path, "shared UI-pattern foundation must contain exactly one Tabulator constructor")
                )
        else:
            for match in constructors:
                findings.append(
                    Finding(
                        path,
                        "raw Tabulator construction is forbidden; use AtlasoUiPatterns.createGrid",
                        line_for_offset(text, match.start()),
                    )
                )
            if LEGACY_TABULATOR_MARKER in text:
                findings.append(
                    Finding(path, "the completed #117 legacy Tabulator marker is forbidden")
                )
        if relative != UI_PATTERN_FOUNDATION:
            for marker in FORBIDDEN_PAGE_WIZARD_CONTROLLER_MARKERS:
                offset = text.find(marker)
                if offset >= 0:
                    findings.append(
                        Finding(
                            path,
                            "page-specific wizard step control is forbidden; use AtlasoUiPatterns.createWizard",
                            line_for_offset(text, offset),
                        )
                    )

    template_root = root / "atlaso" / "app" / "templates"
    for path in template_root.rglob("*.html") if template_root.exists() else []:
        text, error = read_text(path)
        if error is not None:
            findings.append(error)
            continue
        assert text is not None
        for match in TABULATOR_CONSTRUCTOR_RE.finditer(text):
            findings.append(
                Finding(
                    path,
                    "raw Tabulator construction is forbidden; use AtlasoUiPatterns.createGrid",
                    line_for_offset(text, match.start()),
                )
            )
        for match in HTML_FORM_RE.finditer(text):
            attributes = match.group("attributes")
            body = match.group("body")
            if "wizard" not in attributes.lower():
                continue
            if "data-atlaso-wizard" not in attributes:
                findings.append(
                    Finding(
                        path,
                        "wizard form must declare data-atlaso-wizard",
                        line_for_offset(text, match.start()),
                    )
                )
                continue
            form_text = attributes + body
            for marker in WIZARD_REQUIRED_MARKERS:
                if marker not in form_text:
                    findings.append(
                        Finding(
                            path,
                            f"wizard form is missing shared foundation marker: {marker}",
                            line_for_offset(text, match.start()),
                        )
                    )
    return findings


def check_xmlish_svg(path: Path, text: str) -> list[Finding]:
    """Check xmlish svg.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check xmlish svg result.
    """
    import xml.etree.ElementTree as ET

    try:
        ET.fromstring(text)
    except ET.ParseError as exc:
        return [Finding(path, str(exc))]
    return []


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Command-line arguments to parse, or ``None`` to use the process arguments.


    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser(description="Run Atlaso repository checks.")
    parser.add_argument("paths", nargs="*", help="Optional files or directories to check.")
    args = parser.parse_args(argv)

    files = collect_files(args.paths)
    findings: list[Finding] = []
    for path in files:
        findings.extend(check_file(path))
    findings.extend(check_agent_policy_gate(ROOT))
    findings.extend(check_ui_pattern_foundation(ROOT))

    if findings:
        print(f"Repository checks failed with {len(findings)} issue(s):", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding.render()}", file=sys.stderr)
        return 1

    print(f"Repository checks passed for {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
