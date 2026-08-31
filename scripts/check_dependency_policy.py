#!/usr/bin/env python3
"""Validate Atlaso's minimum-age policy for generated Python locks."""

from __future__ import annotations

import json
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
PYTHON_LAUNCHER_RE = re.compile(
    r"(?:python(?:\d+(?:\.\d+)*)?(?:\.exe)?|py(?:\.exe)?)",
    re.IGNORECASE,
)
PIP_LAUNCHER_RE = re.compile(
    r"pip(?:\d+(?:\.\d+)*)?(?:\.exe)?", re.IGNORECASE
)
PIP_MODULE_RE = re.compile(
    r"pip(?:\d+(?:\.\d+)*)?(?:\.__main__)?", re.IGNORECASE
)
RUN_RE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<value>.*)$")
TRUSTED_ATLASO_REFS = {
    "",
    "${{ github.workflow_sha }}",
    "main",
    "refs/heads/main",
}
TRUSTED_ROOT_REFS_BY_WORKFLOW = {
    "ci.yml": {
        "${{ github.event_name == 'workflow_dispatch' && inputs.head_sha || github.sha }}"
    },
    "inventory-linux-release.yml": {"${{ inputs.release_sha }}"},
    "release.yml": {"${{ needs.prepare.outputs.release_sha }}"},
    "virtualization-windows-candidate.yml": {
        "${{ needs.admit.outputs.release_sha }}"
    },
}
TRUSTED_PREFIXED_REFS_BY_WORKFLOW = {
    "wheel.yml": {"${{ steps.target.outputs.commit }}"},
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
    condition: str
    fallible: bool


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


def _yaml_scalar(line: str, key: str) -> str | None:
    """Return a simple YAML scalar with optional quotes and comment removed.

    Args:
        line: YAML source line.
        key: Mapping key expected on the line.
    """
    match = re.fullmatch(rf"\s*(?:-\s+)?{re.escape(key)}:\s*(.*?)\s*", line)
    if not match:
        return None
    value = match.group(1).strip()
    if value.startswith("'"):
        quoted = re.fullmatch(r"'((?:''|[^'])*)'(?:\s+#.*)?", value)
        if not quoted:
            return None
        return quoted.group(1).replace("''", "'")
    if value.startswith('"'):
        quoted = re.fullmatch(r'("(?:\\.|[^"\\])*")(?:\s+#.*)?', value)
        if not quoted:
            return None
        try:
            decoded = json.loads(quoted.group(1))
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, str) else None
    return re.split(r"\s+#", value, maxsplit=1)[0].rstrip()


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
    dict[tuple[int, str], list[tuple[int, CheckoutSource]]],
    dict[int, list[tuple[int, CheckoutSource]]],
]:
    """Return checkout destinations and root replacements grouped by job.

    Args:
        lines: Workflow source lines.
    """
    checkout_paths: dict[tuple[int, str], list[tuple[int, CheckoutSource]]] = {}
    root_checkouts: dict[int, list[tuple[int, CheckoutSource]]] = {}
    for index, line in enumerate(lines):
        action = _yaml_scalar(line, "uses")
        if action is None or not re.fullmatch(r"actions/checkout@[^\s]+", action):
            continue
        job_scope = _workflow_job_scope(lines, index)
        step_index = index
        step_indent = len(line) - len(line.lstrip())
        for candidate_index in range(index, -1, -1):
            step_line = lines[candidate_index]
            if re.match(r"\s*-\s", step_line):
                step_index = candidate_index
                step_indent = len(step_line) - len(step_line.lstrip())
                break
        step_end = len(lines)
        for candidate_index in range(step_index + 1, len(lines)):
            candidate = lines[candidate_index]
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and candidate_indent <= step_indent:
                step_end = candidate_index
                break
        condition = next(
            (
                value
                for candidate in lines[step_index:step_end]
                if len(candidate) - len(candidate.lstrip()) == step_indent + 2
                and (value := _yaml_scalar(candidate, "if")) is not None
            ),
            "",
        )
        continue_on_error = next(
            (
                value
                for candidate in lines[step_index:step_end]
                if len(candidate) - len(candidate.lstrip()) == step_indent + 2
                and (
                    value := _yaml_scalar(candidate, "continue-on-error")
                )
                is not None
            ),
            "false",
        )
        checkout_path = ""
        repository = "${{ github.repository }}"
        ref = ""
        with_indent = -1
        for candidate in lines[index + 1 : step_end]:
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and candidate_indent <= step_indent:
                break
            if candidate.strip() == "with:" and candidate_indent == step_indent + 2:
                with_indent = candidate_indent
                continue
            if with_indent < 0:
                continue
            if candidate.strip() and candidate_indent <= with_indent:
                with_indent = -1
                continue
            if candidate_indent != with_indent + 2:
                continue
            path_value = _yaml_scalar(candidate, "path")
            if path_value is not None and re.fullmatch(
                r"[A-Za-z0-9._/-]+", path_value
            ):
                checkout_path = PurePosixPath(path_value).as_posix()
            repository_value = _yaml_scalar(candidate, "repository")
            if repository_value is not None:
                repository = repository_value.strip()
            ref_value = _yaml_scalar(candidate, "ref")
            if ref_value is not None:
                ref = ref_value.strip()
        source = CheckoutSource(
            repository,
            ref,
            condition,
            continue_on_error.strip().lower() != "false",
        )
        if checkout_path and checkout_path != ".":
            checkout_paths.setdefault((job_scope, checkout_path), []).append(
                (index + 1, source)
            )
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


def _folded_commands(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Return blank-separated commands from a folded YAML scalar.

    Args:
        lines: Workflow line numbers and folded scalar text.
    """
    commands: list[tuple[int, str]] = []
    paragraph: list[tuple[int, str]] = []
    for line_number, line in lines:
        if not line.strip():
            if paragraph:
                commands.append(
                    (
                        paragraph[0][0],
                        " ".join(text.strip() for _, text in paragraph),
                    )
                )
                paragraph = []
            continue
        paragraph.append((line_number, line))
    if paragraph:
        commands.append(
            (paragraph[0][0], " ".join(text.strip() for _, text in paragraph))
        )
    return commands


def _shell_command_segments(command: str) -> list[str]:
    """Split shell commands only at unquoted command separators.

    Args:
        command: Shell or PowerShell command text.
    """
    segments: list[str] = []
    part: list[str] = []
    quote = ""
    index = 0
    while index < len(command):
        character = command[index]
        if character == "\\" and quote != "'" and index + 1 < len(command):
            part.extend((character, command[index + 1]))
            index += 2
            continue
        if character == "`" and quote != "'" and index + 1 < len(command):
            part.append(command[index + 1])
            index += 2
            continue
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                quote = ""
            part.append(character)
            index += 1
            continue
        separator_length = 0
        if not quote and character == ";":
            separator_length = 1
        elif not quote and command[index : index + 2] in {"&&", "||"}:
            separator_length = 2
        elif not quote and character == "|":
            separator_length = 1
        if separator_length:
            segment = "".join(part).strip()
            if segment:
                segments.append(segment)
            part = []
            index += separator_length
            continue
        part.append(character)
        index += 1
    segment = "".join(part).strip()
    if segment:
        segments.append(segment)
    return segments


def _shell_tokens(segment: str) -> list[str]:
    """Return shell tokens while preserving Windows path separators.

    Args:
        segment: Command text with outer separators already removed.
    """
    # PowerShell treats Windows path separators literally, while POSIX shlex
    # consumes them as escapes. Doubling path-like separators preserves both
    # forms without hiding an intentionally escaped option such as ``\-r``.
    tokenizable = re.sub(r"\\(?=[A-Za-z0-9_.])", r"\\\\", segment)
    try:
        return shlex.split(tokenizable, posix=True)
    except ValueError:
        return []


def _segment_uses_shell_grouping(segment: str) -> bool:
    """Return whether a segment contains unquoted shell grouping syntax.

    Args:
        segment: Command text with outer separators already removed.
    """
    quote = ""
    index = 0
    while index < len(segment):
        character = segment[index]
        if character == "\\" and quote != "'" and index + 1 < len(segment):
            index += 2
            continue
        if character == "`" and quote != "'" and index + 1 < len(segment):
            index += 2
            continue
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                quote = ""
        elif not quote and character in {"(", ")"}:
            return True
        elif not quote and character in {"{", "}"}:
            previous = segment[index - 1] if index else " "
            following = segment[index + 1] if index + 1 < len(segment) else " "
            if previous.isspace() and following.isspace():
                return True
        index += 1
    return False


def _segment_directory_action(segment: str) -> tuple[str, str] | None:
    """Return a shell directory-stack action performed by one command segment.

    Args:
        segment: Command text with outer separators already removed.
    """
    tokens = _shell_tokens(segment)
    while tokens and tokens[0] == "&":
        tokens.pop(0)
    if not tokens:
        return None
    command = tokens[0].replace("\\", "/").rsplit("/", maxsplit=1)[-1].lower()
    if command == "popd":
        return ("pop", "")
    if command in {"cd", "pushd"}:
        arguments = [token for token in tokens[1:] if token != "--"]
        return ("push" if command == "pushd" else "change", arguments[0] if arguments else "")
    if command == "pop-location":
        return ("pop", "")
    if command in {"set-location", "push-location"}:
        arguments = tokens[1:]
        if arguments[:1] in (["-Path"], ["-LiteralPath"]):
            arguments = arguments[1:]
        return (
            "push" if command == "push-location" else "change",
            arguments[0] if arguments else "",
        )
    return None


def _segment_requirement_paths(segment: str) -> list[str]:
    """Return requirement paths from one quote-aware shell command segment.

    Args:
        segment: Command text with outer separators already removed.
    """
    tokens = _shell_tokens(segment)
    if not tokens:
        return []
    pip_index = -1
    for index, token in enumerate(tokens):
        launcher = token.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
        if PIP_LAUNCHER_RE.fullmatch(launcher):
            pip_index = index
            break
        if PYTHON_LAUNCHER_RE.fullmatch(launcher):
            option_index = index + 1
            while option_index < len(tokens):
                option = tokens[option_index]
                if option == "-m":
                    if (
                        option_index + 1 < len(tokens)
                        and PIP_MODULE_RE.fullmatch(tokens[option_index + 1])
                    ):
                        pip_index = option_index + 1
                    break
                if option.startswith("-m") and len(option) > 2:
                    if PIP_MODULE_RE.fullmatch(option[2:]):
                        pip_index = option_index
                    break
                if option in {"-", "--", "-c"} or not option.startswith("-"):
                    break
                if option in {"-W", "-X", "--check-hash-based-pycs"}:
                    option_index += 1
                option_index += 1
            if pip_index >= 0:
                break
    if pip_index < 0 or pip_index + 1 >= len(tokens):
        return []

    paths: list[str] = []
    arguments = tokens[pip_index + 2 :]
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-r", "--requirement"}:
            if index + 1 < len(arguments):
                paths.append(arguments[index + 1])
                index += 2
                continue
        elif argument.startswith("--requirement="):
            paths.append(argument.removeprefix("--requirement="))
        elif argument.startswith("-r") and len(argument) > 2:
            paths.append(argument[2:])
        index += 1
    return paths


def _workflow_step_working_directory(lines: list[str], index: int) -> str:
    """Return the literal working-directory value that applies to one run step.

    Args:
        lines: Workflow source lines.
        index: Zero-based line index within the run step.
    """
    run_indent = len(lines[index]) - len(lines[index].lstrip())
    step_index = index
    for candidate_index in range(index, -1, -1):
        candidate = lines[candidate_index]
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if re.match(r"\s*-\s", candidate) and candidate_indent <= run_indent:
            step_index = candidate_index
            break
    step_indent = len(lines[step_index]) - len(lines[step_index].lstrip())
    step_end = len(lines)
    for candidate_index in range(step_index + 1, len(lines)):
        candidate = lines[candidate_index]
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if candidate.strip() and candidate_indent <= step_indent:
            step_end = candidate_index
            break
    for candidate in lines[step_index:step_end]:
        candidate_indent = len(candidate) - len(candidate.lstrip())
        value = _yaml_scalar(candidate, "working-directory")
        if value is not None and candidate_indent == step_indent + 2:
            return value.strip()
    return ""


def _workflow_step_condition(lines: list[str], index: int) -> str:
    """Return the direct step condition for a workflow source line.

    Args:
        lines: Workflow source lines.
        index: Zero-based line index within the step.
    """
    line_indent = len(lines[index]) - len(lines[index].lstrip())
    step_index = index
    for candidate_index in range(index, -1, -1):
        candidate = lines[candidate_index]
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if re.match(r"\s*-\s", candidate) and candidate_indent <= line_indent:
            step_index = candidate_index
            break
    step_indent = len(lines[step_index]) - len(lines[step_index].lstrip())
    step_end = len(lines)
    for candidate_index in range(step_index + 1, len(lines)):
        candidate = lines[candidate_index]
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if candidate.strip() and candidate_indent <= step_indent:
            step_end = candidate_index
            break
    for candidate in lines[step_index:step_end]:
        candidate_indent = len(candidate) - len(candidate.lstrip())
        value = _yaml_scalar(candidate, "if")
        if value is not None and candidate_indent == step_indent + 2:
            return value.strip()
    return ""


def _workflow_job_working_directory(lines: list[str], index: int) -> str:
    """Return the enclosing job's default run working directory.

    Args:
        lines: Workflow source lines.
        index: Zero-based line index within the job.
    """
    job_scope = _workflow_job_scope(lines, index)
    if job_scope < 0:
        return ""
    job_indent = len(lines[job_scope]) - len(lines[job_scope].lstrip())
    job_end = len(lines)
    for candidate_index in range(job_scope + 1, len(lines)):
        candidate = lines[candidate_index]
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if candidate.strip() and candidate_indent <= job_indent:
            job_end = candidate_index
            break
    defaults_indent = -1
    run_indent = -1
    for candidate in lines[job_scope + 1 : job_end]:
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if candidate.strip() == "defaults:" and candidate_indent == job_indent + 2:
            defaults_indent = candidate_indent
            run_indent = -1
            continue
        if defaults_indent >= 0 and candidate.strip() == "run:" and candidate_indent == defaults_indent + 2:
            run_indent = candidate_indent
            continue
        value = _yaml_scalar(candidate, "working-directory")
        if value is not None and run_indent >= 0 and candidate_indent == run_indent + 2:
            return value.strip()
    return ""


def _workflow_default_working_directory(lines: list[str]) -> str:
    """Return the workflow-level default run working directory.

    Args:
        lines: Workflow source lines.
    """
    defaults_indent = -1
    run_indent = -1
    for candidate in lines:
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if candidate.strip() == "defaults:" and candidate_indent == 0:
            defaults_indent = 0
            run_indent = -1
            continue
        if defaults_indent >= 0 and candidate.strip() == "run:" and candidate_indent == 2:
            run_indent = candidate_indent
            continue
        value = _yaml_scalar(candidate, "working-directory")
        if value is not None and run_indent >= 0 and candidate_indent == 4:
            return value.strip()
        if candidate.strip() and candidate_indent == 0 and candidate.strip() != "defaults:":
            defaults_indent = -1
            run_indent = -1
    return ""


def _workflow_effective_working_directory(lines: list[str], index: int) -> str:
    """Return step, job, or workflow working directory in precedence order.

    Args:
        lines: Workflow source lines.
        index: Zero-based line index within the run step.
    """
    return (
        _workflow_step_working_directory(lines, index)
        or _workflow_job_working_directory(lines, index)
        or _workflow_default_working_directory(lines)
    )


def _workflow_run_commands(lines: list[str]) -> list[tuple[int, str, str, int]]:
    """Return logical commands from every workflow run value.

    Args:
        lines: Workflow source lines.
    """
    commands: list[tuple[int, str, str, int]] = []
    index = 0
    while index < len(lines):
        match = RUN_RE.match(lines[index])
        if not match:
            index += 1
            continue
        line_number = index + 1
        value = _yaml_scalar(lines[index], "run")
        if value is None:
            value = match.group("value").strip()
        run_indent = len(match.group("indent"))
        if value and not value.startswith(("|", ">")):
            working_directory = _workflow_effective_working_directory(lines, index)
            commands.append((line_number, value, working_directory, index))
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
            for command_line, command in _folded_commands(block):
                working_directory = _workflow_effective_working_directory(
                    lines, command_line - 1
                )
                commands.append(
                    (
                        command_line,
                        command,
                        working_directory,
                        line_number,
                    )
                )
        else:
            for command_line, command in _continued_commands(block):
                working_directory = _workflow_effective_working_directory(
                    lines, command_line - 1
                )
                commands.append(
                    (command_line, command, working_directory, line_number)
                )
    return commands


def _workflow_requirement_paths(lines: list[str]) -> list[tuple[int, str, str]]:
    """Return workflow line numbers and pip requirement arguments.

    Args:
        lines: Workflow source lines.
    """
    references: list[tuple[int, str, str]] = []
    active_scope = -1
    active_directory = ""
    directory_stack: list[str] = []
    for line_number, command, working_directory, run_scope in _workflow_run_commands(lines):
        if run_scope != active_scope:
            active_scope = run_scope
            active_directory = working_directory
            directory_stack = []
        for segment in _shell_command_segments(command):
            if _segment_uses_shell_grouping(segment):
                # Grouped commands have their own directory lifetime. Reject any
                # later requirement in this run scope instead of trusting a
                # partial shell-state interpretation.
                active_directory = "${{ unsupported-shell-grouping }}"
            directory_action = _segment_directory_action(segment)
            if directory_action is not None:
                action, directory_change = directory_action
                if action == "pop":
                    if directory_stack:
                        active_directory = directory_stack.pop()
                    continue
                if action == "push":
                    directory_stack.append(active_directory)
                change_path = PurePosixPath(directory_change.replace("\\", "/"))
                if active_directory and not change_path.is_absolute():
                    active_directory = (
                        PurePosixPath(active_directory.replace("\\", "/"))
                        / change_path
                    ).as_posix()
                else:
                    active_directory = change_path.as_posix()
                continue
            references.extend(
                (line_number, path, active_directory)
                for path in _segment_requirement_paths(segment)
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
        for line_number, reference, working_directory in _workflow_requirement_paths(lines):
            normalized = reference.replace("\\", "/")
            relative = PurePosixPath(normalized)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                errors.append(
                    f"{workflow.relative_to(root)}:{line_number}: workflow requirement "
                    f"path must be a literal repository lock: {reference}"
                )
                continue

            if working_directory:
                normalized_working_directory = working_directory.replace("\\", "/")
                working_path = PurePosixPath(normalized_working_directory)
                if (
                    working_path.is_absolute()
                    or ".." in working_path.parts
                    or not re.fullmatch(
                        r"[A-Za-z0-9._/-]+", normalized_working_directory
                    )
                ):
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: workflow working "
                        "directory must be a literal repository path: "
                        f"{working_directory}"
                    )
                    continue
                relative = working_path / relative

            policy_path = relative.as_posix()
            tracked_path = root.joinpath(*relative.parts)
            job_scope = _workflow_job_scope(lines, line_number - 1)
            command_condition = _workflow_step_condition(lines, line_number - 1)
            checkout_source = next(
                (
                    source
                    for checkout_line, source in reversed(
                        checkout_paths.get((job_scope, relative.parts[0]), [])
                    )
                    if checkout_line < line_number
                ),
                None,
            )
            if checkout_source is not None and len(relative.parts) > 1:
                if checkout_source.fallible:
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: checkout-prefixed "
                        "workflow requirement uses fallible checkout metadata: "
                        f"{reference}"
                    )
                    continue
                if checkout_source.condition and checkout_source.condition != command_condition:
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: checkout-prefixed "
                        "workflow requirement uses conditional checkout metadata: "
                        f"{reference}"
                    )
                    continue
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
                trusted_prefixed_refs = TRUSTED_ATLASO_REFS | (
                    TRUSTED_PREFIXED_REFS_BY_WORKFLOW.get(workflow.name, set())
                )
                if checkout_source.ref not in trusted_prefixed_refs:
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
                if active_root is not None and active_root.fallible:
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: root workflow "
                        "requirement uses fallible checkout metadata: "
                        f"{reference}"
                    )
                    continue
                if (
                    active_root is not None
                    and active_root.condition
                    and active_root.condition != command_condition
                ):
                    errors.append(
                        f"{workflow.relative_to(root)}:{line_number}: root workflow "
                        "requirement uses conditional checkout metadata: "
                        f"{reference}"
                    )
                    continue
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
