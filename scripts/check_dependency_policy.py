#!/usr/bin/env python3
"""Validate Atlaso's minimum-age policy for generated Python locks."""

from __future__ import annotations

import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MINIMUM_AGE_DAYS = 7
UPLOAD_CUTOFF = f"P{MINIMUM_AGE_DAYS}D"
INDEX_URL = "https://pypi.org/simple"
PIN_RE = re.compile(
    r"^[A-Za-z0-9_.-]+==[^\s\\;]+(?:\s*;\s*[^\\]+)?\s*\\?$"
)
HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}")
PIP_COMMAND_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:(?:python(?:\d+(?:\.\d+)*)?(?:\.exe)?|py(?:\.exe)?)\s+-m\s+)?"
    r"pip(?:\d+(?:\.\d+)*)?\s+[^\s;&|]+"
    r"(?P<args>.*?)(?=(?:&&|\|\||;)|$)"
)
WORKFLOW_REQUIREMENT_RE = re.compile(
    r"(?<!\S)(?:--requirement(?:=|\s+)|-r(?:=|\s*))"
    r"(?:['\"])?(?P<path>[^\s'\"]+)"
)
RUN_RE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<value>.*)$")
TRUSTED_ATLASO_REFS = {
    "",
    "${{ github.workflow_sha }}",
    "main",
    "refs/heads/main",
}
TRUSTED_ROOT_REFS_BY_WORKFLOW = {
    "inventory-linux-release.yml": {"${{ inputs.release_sha }}"},
    "release.yml": {"${{ needs.prepare.outputs.release_sha }}"},
    "virtualization-windows-candidate.yml": {
        "${{ needs.admit.outputs.release_sha }}"
    },
}


@dataclass(frozen=True)
class LockPolicy:
    """Represent lock policy.

    Attributes:
        path: Path maintained by this lockpolicy.
        inputs: Inputs maintained by this lockpolicy.
        allow_unsafe: Whether unsafe is permitted.
    """
    path: str
    inputs: tuple[str, ...]
    allow_unsafe: bool


@dataclass(frozen=True)
class CheckoutSource:
    """Describe the repository and revision behind a checkout destination."""

    repository: str
    ref: str


LOCK_POLICIES = (
    LockPolicy(
        "requirements-appliance-bootstrap.lock",
        ("requirements-appliance-bootstrap.in",),
        True,
    ),
    LockPolicy(
        "requirements-appliance.lock",
        ("pyproject.toml", "requirements-appliance-bootstrap.in"),
        True,
    ),
    LockPolicy("requirements-docs.lock", ("requirements-docs.in",), False),
    LockPolicy(
        "requirements-static-analysis.lock",
        ("requirements-static-analysis.in",),
        False,
    ),
    LockPolicy(
        "requirements-release-tools.lock",
        ("requirements-release-tools.in",),
        True,
    ),
    LockPolicy(
        "requirements-onepassword-deploy.lock",
        ("requirements-onepassword-deploy.in",),
        False,
    ),
    LockPolicy(
        "requirements-virtualization-smoke.lock",
        ("requirements-virtualization-smoke.in",),
        False,
    ),
)


def _workflow_job_scope(lines: list[str], index: int) -> int:
    """Return the line index that identifies the enclosing workflow job.

    Args:
        lines: Workflow source lines.
        index: Zero-based line index within the workflow.
    """
    line_indent = len(lines[index]) - len(lines[index].lstrip())
    for steps_index in range(index, -1, -1):
        candidate = lines[steps_index]
        if candidate.strip() != "steps:":
            continue
        steps_indent = len(candidate) - len(candidate.lstrip())
        if steps_indent >= line_indent:
            continue
        for parent_index in range(steps_index - 1, -1, -1):
            parent = lines[parent_index]
            parent_indent = len(parent) - len(parent.lstrip())
            if parent.strip() and parent_indent < steps_indent:
                return parent_index
        return steps_index
    return -1


def _workflow_checkout_sources(
    lines: list[str],
) -> tuple[
    dict[tuple[int, str], CheckoutSource],
    dict[int, list[tuple[int, CheckoutSource]]],
]:
    """Return checkout destinations and root replacements grouped by job.

    Args:
        lines: Workflow source lines.
    """
    checkout_paths: dict[tuple[int, str], CheckoutSource] = {}
    root_checkouts: dict[int, list[tuple[int, CheckoutSource]]] = {}
    for index, line in enumerate(lines):
        if "uses: actions/checkout@" not in line:
            continue
        job_scope = _workflow_job_scope(lines, index)
        step_indent = len(line) - len(line.lstrip())
        for step_line in reversed(lines[: index + 1]):
            if re.match(r"\s*-\s", step_line):
                step_indent = len(step_line) - len(step_line.lstrip())
                break
        checkout_path = ""
        repository = "${{ github.repository }}"
        ref = ""
        for candidate in lines[index + 1 :]:
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= step_indent:
                break
            path_match = re.fullmatch(
                r"\s*path:\s*['\"]?([A-Za-z0-9._-]+)['\"]?\s*", candidate
            )
            if path_match:
                checkout_path = path_match.group(1)
            repository_match = re.fullmatch(
                r"\s*repository:\s*['\"]?([^'\"]+?)['\"]?\s*", candidate
            )
            if repository_match:
                repository = repository_match.group(1).strip()
            ref_match = re.fullmatch(
                r"\s*ref:\s*['\"]?([^'\"]+?)['\"]?\s*", candidate
            )
            if ref_match:
                ref = ref_match.group(1).strip()
        source = CheckoutSource(repository, ref)
        if checkout_path:
            checkout_paths[(job_scope, checkout_path)] = source
        else:
            root_checkouts.setdefault(job_scope, []).append((index + 1, source))
    return checkout_paths, root_checkouts


def _continued_commands(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Join shell and PowerShell continuation lines into logical commands.

    Args:
        lines: Workflow line numbers and command text.
    """
    commands: list[tuple[int, str]] = []
    start_line = 0
    parts: list[str] = []
    for line_number, line in lines:
        stripped = line.strip()
        if not parts:
            start_line = line_number
        continued = stripped.endswith(("\\", "`"))
        parts.append(stripped[:-1].rstrip() if continued else stripped)
        if not continued:
            commands.append((start_line, " ".join(parts)))
            parts = []
    if parts:
        commands.append((start_line, " ".join(parts)))
    return commands


def _workflow_run_commands(lines: list[str]) -> list[tuple[int, str]]:
    """Return logical commands from every workflow run value.

    Args:
        lines: Workflow source lines.
    """
    commands: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = RUN_RE.match(lines[index])
        if not match:
            index += 1
            continue
        line_number = index + 1
        value = match.group("value").strip()
        run_indent = len(match.group("indent"))
        if value and not value.startswith(("|", ">")):
            commands.append((line_number, value))
            index += 1
            continue

        block: list[tuple[int, str]] = []
        index += 1
        while index < len(lines):
            candidate = lines[index]
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and candidate_indent <= run_indent:
                break
            block.append((index + 1, candidate))
            index += 1
        if value.startswith(">"):
            if block:
                commands.append((block[0][0], " ".join(line.strip() for _, line in block)))
        else:
            commands.extend(_continued_commands(block))
    return commands


def _workflow_requirement_paths(lines: list[str]) -> list[tuple[int, str]]:
    """Return workflow line numbers and pip requirement arguments.

    Args:
        lines: Workflow source lines.
    """
    references: list[tuple[int, str]] = []
    for line_number, command in _workflow_run_commands(lines):
        for pip_command in PIP_COMMAND_RE.finditer(command):
            references.extend(
                (line_number, match.group("path"))
                for match in WORKFLOW_REQUIREMENT_RE.finditer(
                    pip_command.group("args")
                )
            )
    return references


def _validate_workflow_locks(root: Path, policy_paths: set[str]) -> list[str]:
    """Validate workflow lock references against tracked generated locks.

    Args:
        root: Repository or filesystem root searched by the operation.
        policy_paths: Generated locks covered by the minimum-age policy.
    """
    errors: list[str] = []
    workflow_root = root / ".github" / "workflows"
    for workflow in sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml"))):
        try:
            text = workflow.read_text(encoding="utf-8")
        except OSError:
            errors.append(f"{workflow.relative_to(root)}: workflow is unreadable")
            continue
        lines = text.splitlines()
        checkout_paths, root_checkouts = _workflow_checkout_sources(lines)
        for line_number, reference in _workflow_requirement_paths(lines):
            normalized = reference.replace("\\", "/")
            relative = PurePosixPath(normalized)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                errors.append(
                    f"{workflow.relative_to(root)}:{line_number}: workflow requirement "
                    f"path must be a literal repository lock: {reference}"
                )
                continue

            policy_path = relative.as_posix()
            tracked_path = root.joinpath(*relative.parts)
            job_scope = _workflow_job_scope(lines, line_number - 1)
            checkout_source = checkout_paths.get((job_scope, relative.parts[0]))
            if checkout_source is not None and len(relative.parts) > 1:
                if checkout_source.repository not in {
                    "${{ github.repository }}",
                    "mdaneri/Atlaso",
                }:
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: checkout-prefixed "
                        "workflow requirement is not sourced from Atlaso: "
                        f"{reference}"
                    )
                    continue
                if checkout_source.ref not in TRUSTED_ATLASO_REFS:
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: checkout-prefixed "
                        "workflow requirement uses an untrusted Atlaso ref: "
                        f"{reference}"
                    )
                    continue
                policy_path = PurePosixPath(*relative.parts[1:]).as_posix()
                tracked_path = root.joinpath(*relative.parts[1:])
            else:
                active_root = next(
                    (
                        source
                        for checkout_line, source in reversed(
                            root_checkouts.get(job_scope, [])
                        )
                        if checkout_line < line_number
                    ),
                    None,
                )
                if active_root is not None and active_root.repository not in {
                    "${{ github.repository }}",
                    "mdaneri/Atlaso",
                }:
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: root workflow "
                        "requirement is not sourced from Atlaso: "
                        f"{reference}"
                    )
                    continue
                trusted_root_refs = TRUSTED_ATLASO_REFS | (
                    TRUSTED_ROOT_REFS_BY_WORKFLOW.get(workflow.name, set())
                )
                if active_root is not None and active_root.ref not in trusted_root_refs:
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: root workflow "
                        "requirement uses an untrusted Atlaso ref: "
                        f"{reference}"
                    )
                    continue

            if not tracked_path.is_file():
                errors.append(
                    f"{workflow.relative_to(root)}:{line_number}: workflow requirement "
                    f"path is missing: {reference}"
                )
                continue
            if policy_path not in policy_paths:
                errors.append(
                    f"{workflow.relative_to(root)}:{line_number}: workflow requirement "
                    f"lock is outside the generated dependency policy inventory: {reference}"
                )
    return errors


def _pip_update_block(lines: list[str]) -> list[str]:
    """Return pip update block.

    Args:
        lines: Source or output lines being parsed.
    """
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.strip() == "- package-ecosystem: pip"
        ),
        -1,
    )
    if start < 0:
        return []
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("  - package-ecosystem:")
        ),
        len(lines),
    )
    return lines[start:end]


def _lock_command(lines: list[str]) -> list[str]:
    """Return lock command.

    Args:
        lines: Source or output lines being parsed.
    """
    command_line = next(
        (line.removeprefix("#    ") for line in lines if line.startswith("#    pip-compile ")),
        "",
    )
    return shlex.split(command_line, posix=True) if command_line else []


def validate(root: Path = ROOT) -> list[str]:
    """Validate operation.

    Args:
        root: Repository or filesystem root searched by the operation.


    Returns:
        The validate result.
    """
    errors: list[str] = []
    policy_paths = {policy.path for policy in LOCK_POLICIES}
    errors.extend(_validate_workflow_locks(root, policy_paths))
    dependabot_path = root / ".github" / "dependabot.yml"
    try:
        pip_block = _pip_update_block(
            dependabot_path.read_text(encoding="utf-8").splitlines()
        )
    except OSError:
        pip_block = []
    required_cooldown_lines = {
        "    cooldown:",
        f"      default-days: {MINIMUM_AGE_DAYS}",
        "      include:",
        '        - "*"',
    }
    if not pip_block:
        errors.append(f"{dependabot_path.relative_to(root)}: pip update configuration is missing")
    elif not required_cooldown_lines.issubset(set(pip_block)):
        errors.append(
            f"{dependabot_path.relative_to(root)}: pip updates must apply a "
            f"{MINIMUM_AGE_DAYS}-day cooldown to all dependencies"
        )

    for policy in LOCK_POLICIES:
        path = root / policy.path
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            errors.append(f"{policy.path}: generated lock is missing or unreadable")
            continue

        if "# This file is autogenerated by pip-compile with Python 3.14" not in lines:
            errors.append(f"{policy.path}: lock must be generated with Python 3.14")
        command = _lock_command(lines)
        if not command:
            errors.append(f"{policy.path}: pip-compile generation command is missing")
        else:
            required_options = {
                "--generate-hashes",
                f"--index-url={INDEX_URL}",
                "--no-emit-index-url",
                f"--output-file={policy.path}",
                f"--uploaded-prior-to={UPLOAD_CUTOFF}",
            }
            missing_options = sorted(required_options - set(command))
            if missing_options:
                errors.append(
                    f"{policy.path}: generation command is missing "
                    f"{', '.join(missing_options)}"
                )
            if policy.allow_unsafe and "--allow-unsafe" not in command:
                errors.append(f"{policy.path}: generation command must preserve --allow-unsafe")
            if not policy.allow_unsafe and "--allow-unsafe" in command:
                errors.append(f"{policy.path}: unexpected --allow-unsafe generation option")
            missing_inputs = [value for value in policy.inputs if value not in command]
            if missing_inputs:
                errors.append(
                    f"{policy.path}: generation command is missing inputs "
                    f"{', '.join(missing_inputs)}"
                )

        requirement_indexes = [
            index
            for index, line in enumerate(lines)
            if line
            and not line[0].isspace()
            and not line.startswith("#")
            and not line.startswith("--")
        ]
        if not requirement_indexes:
            errors.append(f"{policy.path}: lock contains no package requirements")
            continue
        for offset, index in enumerate(requirement_indexes):
            if not PIN_RE.fullmatch(lines[index]):
                errors.append(
                    f"{policy.path}:{index + 1}: requirement must use an exact == pin"
                )
                continue
            next_requirement = (
                requirement_indexes[offset + 1]
                if offset + 1 < len(requirement_indexes)
                else len(lines)
            )
            if not any(
                HASH_RE.search(line) for line in lines[index:next_requirement]
            ):
                errors.append(
                    f"{policy.path}:{index + 1}: pinned requirement has no SHA256 hash"
                )

    return errors


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    errors = validate()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"All {len(LOCK_POLICIES)} Python locks enforce the "
        f"{MINIMUM_AGE_DAYS}-day package age policy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
