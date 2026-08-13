"""Enforce repository-wide Python documentation conventions."""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

ARGUMENT_ENTRY = re.compile(
    r"^    (?P<stars>\*{0,2})(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*\([^)]*\))?:\s+(?P<description>\S.*)$"
)
SECTION_HEADING = re.compile(r"^[A-Z][A-Za-z ]+:$")


def _tracked_python_files(root: Path) -> list[Path]:
    """Return tracked Python source files, including extensionless entry points.

    Args:
        root: Repository root containing the tracked source files.

    Returns:
        Sorted paths for tracked ``.py`` files and Python shebang scripts.
    """
    output = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=root,
    )
    paths: list[Path] = []
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        path = root / raw_path.decode("utf-8")
        if path.suffix == ".py":
            paths.append(path)
            continue
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            first_line = stream.readline(200).decode("utf-8", errors="ignore")
        if first_line.startswith("#!") and "python" in first_line.lower():
            paths.append(path)
    return sorted(paths)


def _definition_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return explicit source parameter spellings for a function definition.

    Args:
        node: Parsed function or asynchronous-function definition.

    Returns:
        Parameter spellings in signature order, including variadic markers and excluding implicit
        ``self`` and ``cls``.
    """
    parameters = [
        argument.arg
        for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        if argument.arg not in {"self", "cls"}
    ]
    if node.args.vararg is not None:
        parameters.append(f"*{node.args.vararg.arg}")
    if node.args.kwarg is not None:
        parameters.append(f"**{node.args.kwarg.arg}")
    return parameters


def _documented_parameters(docstring: str | None) -> tuple[list[str], list[str]]:
    """Parse parameter entries from a Google-style docstring.

    Args:
        docstring: Cleaned function docstring, or ``None`` when it is absent.

    Returns:
        A pair containing documented names and malformed argument-entry lines.
    """
    if not docstring:
        return [], []

    names: list[str] = []
    malformed: list[str] = []
    in_arguments = False
    for line in docstring.splitlines():
        if line in {"Args:", "Arguments:", "Keyword Args:"}:
            in_arguments = True
            continue
        if in_arguments and SECTION_HEADING.fullmatch(line):
            in_arguments = False
            continue
        if not in_arguments or not line.startswith("    ") or line.startswith("        "):
            continue
        match = ARGUMENT_ENTRY.fullmatch(line)
        if match is None:
            malformed.append(line.strip())
            continue
        names.append(f"{match.group('stars')}{match.group('name')}")
    return names, malformed


def test_all_python_parameters_are_documented() -> None:
    """Require exact Google-style documentation for every explicit parameter."""
    root = Path(__file__).resolve().parents[1]
    failures: list[str] = []

    for path in _tracked_python_files(root):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            parameters = _definition_parameters(node)
            if not parameters:
                continue
            documented, malformed = _documented_parameters(ast.get_docstring(node, clean=True))
            missing = [name for name in parameters if name not in documented]
            unknown = [name for name in documented if name not in parameters]
            duplicates = sorted({name for name in documented if documented.count(name) > 1})
            if missing or unknown or duplicates or malformed:
                detail = []
                if missing:
                    detail.append(f"missing={missing}")
                if unknown:
                    detail.append(f"unknown={unknown}")
                if duplicates:
                    detail.append(f"duplicates={duplicates}")
                if malformed:
                    detail.append(f"malformed={malformed}")
                relative_path = path.relative_to(root)
                failures.append(f"{relative_path}:{node.lineno} {node.name}: {'; '.join(detail)}")

    assert not failures, "Python parameter documentation errors:\n" + "\n".join(failures)
