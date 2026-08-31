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
SHELL_LAUNCHERS = {"bash", "dash", "ksh", "sh", "zsh"}
RUN_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?(?:run|'run'|\"run\"):\s*(?P<value>.*)$"
)
ALIAS_RE = re.compile(r"\*[A-Za-z_][A-Za-z0-9_.-]*")
UNSUPPORTED_RUN_ALIAS_PREFIX = "unsupported-run-alias:"
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
    key_pattern = rf"(?:{re.escape(key)}|'{re.escape(key)}'|\"{re.escape(key)}\")"
    match = re.fullmatch(rf"\s*(?:-\s+)?{key_pattern}:\s*(.*?)\s*", line)
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


def _yaml_plain_scalar(
    lines: list[str],
    index: int,
    key: str,
) -> tuple[str | None, int]:
    """Return a complete plain scalar and the next unread line.

    Args:
        lines: YAML source lines.
        index: Zero-based index of the mapping key line.
        key: Mapping key expected on the current line.
    """
    line = lines[index]
    line_indent = len(line) - len(line.lstrip())
    key_indent = line_indent + (2 if re.match(r"\s*-\s+", line) else 0)
    value = _yaml_scalar(line, key)
    key_pattern = rf"(?:{re.escape(key)}|'{re.escape(key)}'|\"{re.escape(key)}\")"
    source_match = re.fullmatch(rf"\s*(?:-\s+)?{key_pattern}:\s*(.*?)\s*", line)
    source = source_match.group(1).strip() if source_match else ""
    if value is None and source.startswith(("'", '"')):
        cursor = index + 1
        parts = [source]
        while cursor < len(lines):
            candidate = lines[cursor]
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and candidate_indent <= key_indent:
                break
            if candidate.strip():
                parts.append(candidate.strip())
            cursor += 1
        value = _yaml_scalar(f"{key}: {' '.join(parts)}", key)
        return value, cursor
    if value is None or value.startswith(("|", ">")):
        return value, index + 1
    parts = [value] if value else []
    cursor = index + 1
    while cursor < len(lines):
        candidate = lines[cursor]
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if candidate.strip() and candidate_indent <= key_indent:
            break
        if candidate.strip():
            parts.append(candidate.strip())
        cursor += 1
    return " ".join(parts), cursor


def _flow_parts(value: str) -> list[str] | None:
    """Split a flow-mapping body at top-level commas.

    Args:
        value: Flow-mapping text without its outer braces.
    """
    parts: list[str] = []
    part: list[str] = []
    quote = ""
    depth = 0
    index = 0
    while index < len(value):
        character = value[index]
        if quote == '"' and character == "\\" and index + 1 < len(value):
            part.extend((character, value[index + 1]))
            index += 2
            continue
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                if quote == "'" and index + 1 < len(value) and value[index + 1] == "'":
                    part.extend((character, value[index + 1]))
                    index += 2
                    continue
                quote = ""
            part.append(character)
            index += 1
            continue
        if not quote and character in "{[(":
            depth += 1
        elif not quote and character in "}])":
            depth -= 1
            if depth < 0:
                return None
        if not quote and depth == 0 and character == ",":
            if not "".join(part).strip():
                return None
            parts.append("".join(part).strip())
            part = []
            index += 1
            continue
        part.append(character)
        index += 1
    if quote or depth:
        return None
    final = "".join(part).strip()
    if final:
        parts.append(final)
    elif parts:
        return None
    return parts


def _flow_key_value(item: str) -> tuple[str, str] | None:
    """Split one flow-mapping item at its top-level colon.

    Args:
        item: One comma-delimited flow-mapping item.
    """
    quote = ""
    depth = 0
    index = 0
    while index < len(item):
        character = item[index]
        if quote == '"' and character == "\\" and index + 1 < len(item):
            index += 2
            continue
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                if quote == "'" and index + 1 < len(item) and item[index + 1] == "'":
                    index += 2
                    continue
                quote = ""
            index += 1
            continue
        if not quote and character in "{[(":
            depth += 1
        elif not quote and character in "}])":
            depth -= 1
            if depth < 0:
                return None
        elif not quote and depth == 0 and character == ":":
            key = item[:index].strip()
            if not key:
                return None
            return key, item[index + 1 :].strip()
        index += 1
    return None


def _yaml_inline_scalar(value: str) -> object:
    """Decode the scalar subset used by workflow flow mappings.

    Args:
        value: Inline YAML scalar source.
    """
    value = value.strip()
    if value.startswith("'"):
        quoted = re.fullmatch(r"'((?:''|[^'])*)'", value)
        return quoted.group(1).replace("''", "'") if quoted else value
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return value
        return decoded if isinstance(decoded, str) else value
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() in {"null", "~"}:
        return None
    return value


def _yaml_flow_mapping(value: str) -> dict[str, object] | None:
    """Return a semantic flow-style YAML mapping without dependencies.

    Args:
        value: YAML source expected to contain one flow mapping.
    """
    value = value.strip()
    if not value.startswith("{") or not value.endswith("}"):
        return None
    parts = _flow_parts(value[1:-1])
    if parts is None:
        return None
    parsed: dict[str, object] = {}
    for item in parts:
        pair = _flow_key_value(item)
        if pair is None:
            return None
        key_source, value_source = pair
        key = _yaml_inline_scalar(key_source)
        if not isinstance(key, str):
            return None
        if value_source.startswith("{"):
            nested = _yaml_flow_mapping(value_source)
            if nested is None:
                return None
            parsed[key] = nested
        else:
            parsed[key] = _yaml_inline_scalar(value_source)
    return parsed


def _yaml_flow_step(line: str) -> dict[str, object] | None:
    """Return a semantic single-line flow-style workflow step.

    Args:
        line: Workflow source line.
    """
    match = re.match(r"\s*-\s*(\{.*\})\s*(?:#.*)?$", line)
    if not match:
        return None
    return _yaml_flow_mapping(match.group(1))


def _yaml_value_text(value: object, unsupported: str) -> str:
    """Return a scalar value as workflow source metadata.

    Args:
        value: Parsed YAML value.
        unsupported: Fail-closed marker for non-scalar values.
    """
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return value.strip()
    return unsupported


def _is_alias_value(value: str | object) -> bool:
    """Return whether a YAML value is a bare alias reference.

    Args:
        value: Parsed or source YAML value to inspect.
    """
    return isinstance(value, str) and bool(ALIAS_RE.fullmatch(value))


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
    dict[int, list[int]],
]:
    """Return checkout destinations and root replacements grouped by job.

    Args:
        lines: Workflow source lines.
    """
    checkout_paths: dict[tuple[int, str], list[tuple[int, CheckoutSource]]] = {}
    root_checkouts: dict[int, list[tuple[int, CheckoutSource]]] = {}
    dynamic_checkouts: dict[int, list[int]] = {}
    for index, line in enumerate(lines):
        if re.fullmatch(
            rf"\s*-\s+{ALIAS_RE.pattern}\s*(?:#.*)?",
            line,
        ):
            job_scope = _workflow_job_scope(lines, index)
            dynamic_checkouts.setdefault(job_scope, []).append(index + 1)
            continue
        flow_step = _yaml_flow_step(line)
        action = (
            _yaml_value_text(flow_step.get("uses"), "")
            if flow_step is not None and "uses" in flow_step
            else _yaml_plain_scalar(lines, index, "uses")[0]
        )
        if _is_alias_value(action) or (
            isinstance(action, str) and action.startswith("&")
        ):
            job_scope = _workflow_job_scope(lines, index)
            dynamic_checkouts.setdefault(job_scope, []).append(index + 1)
            continue
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
        condition = (
            _yaml_value_text(flow_step.get("if"), "${{ unsupported-flow-if }}")
            if flow_step is not None and "if" in flow_step
            else next(
                (
                    value
                    for candidate in lines[step_index:step_end]
                    if len(candidate) - len(candidate.lstrip()) == step_indent + 2
                    and (value := _yaml_scalar(candidate, "if")) is not None
                ),
                "",
            )
        )
        continue_on_error = (
            _yaml_value_text(
                flow_step.get("continue-on-error"),
                "${{ unsupported-flow-continue-on-error }}",
            )
            if flow_step is not None and "continue-on-error" in flow_step
            else next(
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
        )
        checkout_path = ""
        dynamic_path = False
        repository = "${{ github.repository }}"
        ref = ""

        def apply_checkout_inputs(inputs: dict[str, object]) -> None:
            """Apply parsed checkout inputs to the current source record.

            Args:
                inputs: Semantic checkout input values from the workflow step.
            """
            nonlocal checkout_path, dynamic_path, repository, ref
            if "path" in inputs:
                path_value = inputs["path"]
                if isinstance(path_value, str) and re.fullmatch(
                    r"[A-Za-z0-9._/-]+", path_value
                ):
                    checkout_path = PurePosixPath(path_value).as_posix()
                else:
                    dynamic_path = True
            if "repository" in inputs:
                repository = _yaml_value_text(
                    inputs["repository"], "${{ unsupported-flow-repository }}"
                )
            if "ref" in inputs:
                ref = _yaml_value_text(
                    inputs["ref"], "${{ unsupported-flow-ref }}"
                )

        if flow_step is not None and "with" in flow_step:
            flow_inputs = flow_step["with"]
            if isinstance(flow_inputs, dict) and all(
                isinstance(key, str) for key in flow_inputs
            ):
                apply_checkout_inputs(flow_inputs)
            else:
                dynamic_path = True
                repository = "${{ unsupported-flow-with }}"
        with_indent = -1
        for candidate_index in range(index + 1, step_end):
            candidate = lines[candidate_index]
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and candidate_indent <= step_indent:
                break
            if candidate_indent == step_indent + 2:
                with_value = _yaml_scalar(candidate, "with")
                if with_value is not None:
                    if with_value:
                        flow_inputs = _yaml_flow_mapping(with_value)
                        if flow_inputs is not None:
                            apply_checkout_inputs(flow_inputs)
                        else:
                            dynamic_path = True
                            repository = "${{ unsupported-flow-with }}"
                        with_indent = -1
                    else:
                        with_indent = candidate_indent
                    continue
            if with_indent < 0:
                continue
            if candidate.strip() and candidate_indent <= with_indent:
                with_indent = -1
                continue
            if candidate_indent != with_indent + 2:
                continue
            path_value = _yaml_plain_scalar(lines, candidate_index, "path")[0]
            if path_value is not None:
                if re.fullmatch(r"[A-Za-z0-9._/-]+", path_value):
                    checkout_path = PurePosixPath(path_value).as_posix()
                else:
                    dynamic_path = True
            repository_value = _yaml_plain_scalar(
                lines, candidate_index, "repository"
            )[0]
            if repository_value is not None:
                repository = repository_value.strip()
            ref_value = _yaml_plain_scalar(lines, candidate_index, "ref")[0]
            if ref_value is not None:
                ref = ref_value.strip()
        source = CheckoutSource(
            repository,
            ref,
            condition,
            continue_on_error.strip().lower() != "false",
        )
        if dynamic_path:
            dynamic_checkouts.setdefault(job_scope, []).append(index + 1)
        elif checkout_path and checkout_path != ".":
            checkout_paths.setdefault((job_scope, checkout_path), []).append(
                (index + 1, source)
            )
        else:
            root_checkouts.setdefault(job_scope, []).append((index + 1, source))
    return checkout_paths, root_checkouts, dynamic_checkouts


def _shell_line_content(line: str) -> tuple[str, str]:
    """Return executable line content and its active continuation marker.

    Args:
        line: One shell or PowerShell source line.
    """
    quote = ""
    index = 0
    comment_index = len(line)
    while index < len(line):
        character = line[index]
        if character in {"\\", "`"} and quote != "'" and index + 1 < len(line):
            index += 2
            continue
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                quote = ""
        elif (
            character == "#"
            and not quote
            and (index == 0 or line[index - 1].isspace())
        ):
            comment_index = index
            break
        index += 1
    content = line[:comment_index].rstrip()
    if not content or content[-1] not in {"\\", "`"} or quote == "'":
        return content, ""
    marker = content[-1]
    marker_count = len(content) - len(content.rstrip(marker))
    return content, marker if marker_count % 2 else ""


def _continued_commands(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Join shell and PowerShell continuation lines into logical commands.

    Args:
        lines: Workflow line numbers and command text.
    """
    commands: list[tuple[int, str]] = []
    start_line = 0
    parts: list[str] = []
    for line_number, line in lines:
        content, marker = _shell_line_content(line.strip())
        if not parts:
            start_line = line_number
        continued = bool(marker)
        parts.append(content[:-1].rstrip() if continued else content)
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
    base_indent = min(
        (
            len(line) - len(line.lstrip())
            for _, line in lines
            if line.strip()
        ),
        default=0,
    )
    paragraph: list[tuple[int, str]] = []

    def flush_paragraph() -> None:
        if paragraph:
            commands.append(
                (
                    paragraph[0][0],
                    " ".join(text.strip() for _, text in paragraph),
                )
            )
            paragraph.clear()

    for line_number, line in lines:
        if not line.strip():
            flush_paragraph()
            continue
        indent = len(line) - len(line.lstrip())
        if indent > base_indent:
            flush_paragraph()
            commands.append((line_number, line.strip()))
            continue
        paragraph.append((line_number, line))
    flush_paragraph()
    return commands


def _shell_command_segments(command: str) -> tuple[list[str], bool]:
    """Split shell commands and identify stateful control separators.

    Args:
        command: Shell or PowerShell command text.
    """
    segments: list[str] = []
    stateful_control = False
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
            stateful_control = True
        elif not quote and character in {"&", "|"}:
            separator_length = 1
            stateful_control = True
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
    return segments, stateful_control


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
    if tokens and (
        tokens[0].replace("\\", "/").rsplit("/", maxsplit=1)[-1].lower()
        in {"builtin", "command"}
    ):
        tokens.pop(0)
        while tokens and tokens[0].startswith("-"):
            option = tokens.pop(0)
            if option == "--":
                break
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
    for eval_index, token in enumerate(tokens):
        launcher = token.replace("\\", "/").rsplit("/", maxsplit=1)[-1].lower()
        if launcher != "eval":
            continue
        command_index = eval_index + 1
        if command_index < len(tokens) and tokens[command_index] == "--":
            command_index += 1
        if command_index < len(tokens):
            return _segment_requirement_paths(" ".join(tokens[command_index:]))
        return []
    for shell_index, token in enumerate(tokens):
        launcher = token.replace("\\", "/").rsplit("/", maxsplit=1)[-1].lower()
        if launcher not in SHELL_LAUNCHERS:
            continue
        for option_index in range(shell_index + 1, len(tokens)):
            option = tokens[option_index]
            if option == "--":
                break
            if option.startswith("-") and "c" in option.lstrip("-"):
                if option_index + 1 < len(tokens):
                    return _segment_requirement_paths(tokens[option_index + 1])
                return []
            if not option.startswith("-"):
                break
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
        elif argument.startswith("-") and not argument.startswith("--"):
            cluster = argument[1:]
            requirement_index = cluster.find("r")
            if requirement_index >= 0:
                attached = cluster[requirement_index + 1 :]
                if attached:
                    paths.append(attached)
                elif index + 1 < len(arguments):
                    paths.append(arguments[index + 1])
                    index += 2
                    continue
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
    flow_step = _yaml_flow_step(lines[index])
    if flow_step is not None and "if" in flow_step:
        return _yaml_value_text(flow_step["if"], "${{ unsupported-flow-if }}")
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
        flow_step = _yaml_flow_step(lines[index])
        if flow_step is not None and "run" in flow_step:
            line_number = index + 1
            run_value = flow_step["run"]
            if _is_alias_value(run_value):
                flow_directory = flow_step.get("working-directory")
                working_directory = (
                    _yaml_value_text(
                        flow_directory,
                        "${{ unsupported-flow-working-directory }}",
                    )
                    if flow_directory is not None
                    else _workflow_effective_working_directory(lines, index)
                )
                commands.append(
                    (
                        line_number,
                        f"{UNSUPPORTED_RUN_ALIAS_PREFIX}{run_value}",
                        working_directory,
                        index,
                    )
                )
                index += 1
                continue
            if isinstance(run_value, str):
                flow_directory = flow_step.get("working-directory")
                working_directory = (
                    _yaml_value_text(
                        flow_directory, "${{ unsupported-flow-working-directory }}"
                    )
                    if flow_directory is not None
                    else _workflow_effective_working_directory(lines, index)
                )
                flow_lines = [
                    (line_number + offset, command_line)
                    for offset, command_line in enumerate(run_value.splitlines())
                ]
                for command_line, command in _continued_commands(flow_lines):
                    if command:
                        commands.append(
                            (command_line, command, working_directory, index)
                        )
            index += 1
            continue
        match = RUN_RE.match(lines[index])
        if not match:
            index += 1
            continue
        line_number = index + 1
        value, next_index = _yaml_plain_scalar(lines, index, "run")
        if value is None:
            value = match.group("value").strip()
            next_index = index + 1
        if _is_alias_value(value):
            working_directory = _workflow_effective_working_directory(lines, index)
            commands.append(
                (
                    line_number,
                    f"{UNSUPPORTED_RUN_ALIAS_PREFIX}{value}",
                    working_directory,
                    index,
                )
            )
            index += 1
            continue
        run_indent = len(match.group("indent"))
        if value and not value.startswith(("|", ">")):
            working_directory = _workflow_effective_working_directory(lines, index)
            commands.append((line_number, value, working_directory, index))
            index = next_index
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
        if command.startswith(UNSUPPORTED_RUN_ALIAS_PREFIX):
            references.append(
                (
                    line_number,
                    command,
                    working_directory,
                )
            )
            continue
        segments, stateful_control = _shell_command_segments(command)
        uncertain_directory = stateful_control and any(
            _segment_directory_action(segment) is not None for segment in segments
        )
        if uncertain_directory:
            active_directory = "${{ unsupported-shell-directory-control }}"
            directory_stack = []
        for segment in segments:
            if _segment_uses_shell_grouping(segment):
                # Grouped commands have their own directory lifetime. Reject any
                # later requirement in this run scope instead of trusting a
                # partial shell-state interpretation.
                active_directory = "${{ unsupported-shell-grouping }}"
            directory_action = _segment_directory_action(segment)
            if directory_action is not None:
                if uncertain_directory:
                    continue
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
        checkout_paths, root_checkouts, dynamic_checkouts = (
            _workflow_checkout_sources(lines)
        )
        for line_number, reference, working_directory in _workflow_requirement_paths(lines):
            if reference.startswith(UNSUPPORTED_RUN_ALIAS_PREFIX):
                alias = reference.removeprefix(UNSUPPORTED_RUN_ALIAS_PREFIX)
                errors.append(
                    f"{workflow.relative_to(root)}:{line_number}: run command uses "
                    f"YAML alias and cannot be policy validated: {alias}"
                )
                continue
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
            if any(
                checkout_line < line_number
                for checkout_line in dynamic_checkouts.get(job_scope, [])
            ):
                errors.append(
                    f"{workflow.relative_to(root)}:{line_number}: workflow "
                    "requirement uses nonliteral checkout path metadata: "
                    f"{reference}"
                )
                continue
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
