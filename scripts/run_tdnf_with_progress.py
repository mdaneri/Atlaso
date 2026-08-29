#!/usr/bin/env python3
"""Run a TDNF operation with compact, Packer-friendly progress output."""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TDNF_ERROR_LINE_RE = re.compile(r"^(?:Error(?:\(\d+\))?\s*:|Disabling Repo:)")


def _format_duration(seconds: float) -> str:
    """Render duration.

    Args:
        seconds: Seconds consumed by format duration.


    Returns:
        The format duration result.
    """
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def _format_size(size: int) -> str:
    """Render size.

    Args:
        size: Size consumed by format size.


    Returns:
        The format size result.

    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    value = float(max(0, size))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def _directory_size(path: Path) -> str:
    """Return directory size.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    try:
        total = 0
        for root, _directories, files in os.walk(path):
            for name in files:
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    continue
        return _format_size(total)
    except OSError:
        return "unavailable"


def _failure_tail(path: Path, line_limit: int) -> list[str]:
    """Return failure tail.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        line_limit: Line limit supplied by the caller.
    """
    try:
        text = path.read_bytes().decode("utf-8", errors="replace")
    except OSError as exc:
        return [f"Could not read captured TDNF output: {exc}"]
    normalized = ANSI_ESCAPE_RE.sub("", text).replace("\r", "\n")
    lines = [line.rstrip() for line in normalized.splitlines() if line.strip()]
    return lines[-line_limit:]


def _reported_tdnf_failure(path: Path) -> bool:
    """Return whether TDNF reported an error while returning success.

    Args:
        path: Captured TDNF transcript to inspect.
    """

    try:
        with path.open("r", encoding="utf-8", errors="replace") as transcript:
            for line in transcript:
                normalized = ANSI_ESCAPE_RE.sub("", line).strip()
                if TDNF_ERROR_LINE_RE.match(normalized):
                    return True
    except OSError:
        return True
    return False


def run(
    command: list[str],
    *,
    label: str,
    cache_dir: Path,
    heartbeat_seconds: float,
    failure_tail_lines: int,
) -> int:
    """Run operation.

    Args:
        command: Command and arguments to execute or validate.
        label: Human-readable label used in validation output.
        cache_dir: Cache dir supplied by the caller.
        heartbeat_seconds: Heartbeat seconds supplied by the caller.
        failure_tail_lines: Failure tail lines supplied by the caller.

    Returns:
        The run result.
    """
    started = time.monotonic()
    print(
        f"==> Atlaso appliance: {label} started "
        f"(status every {_format_duration(heartbeat_seconds)})",
        flush=True,
    )

    with tempfile.NamedTemporaryFile(
        prefix="atlaso-tdnf-", suffix=".log", delete=False
    ) as output:
        output_path = Path(output.name)
        process = subprocess.Popen(
            command,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=os.name == "posix",
        )

    def forward_signal(signum: int, _frame: object) -> None:
        """Handle forward signal.

        Args:
            signum: Signum consumed by forward signal.
            _frame: Frame consumed by forward signal.
        """
        try:
            if os.name == "posix":
                os.killpg(process.pid, signum)
            else:
                process.send_signal(signum)
        except ProcessLookupError:
            pass

    previous_handlers: dict[int, object] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, forward_signal)

    try:
        while True:
            try:
                status = process.wait(timeout=heartbeat_seconds)
                break
            except subprocess.TimeoutExpired:
                elapsed = _format_duration(time.monotonic() - started)
                cache_size = _directory_size(cache_dir)
                print(
                    f"==> Atlaso appliance: {label} still running "
                    f"({elapsed}; TDNF cache {cache_size})",
                    flush=True,
                )
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)

    elapsed = _format_duration(time.monotonic() - started)
    reported_failure = status == 0 and _reported_tdnf_failure(output_path)
    if status == 0 and not reported_failure:
        print(f"==> Atlaso appliance: {label} completed in {elapsed}", flush=True)
    else:
        failure_reason = (
            "reported an error despite exit status 0"
            if reported_failure
            else f"exit status {status}"
        )
        print(
            f"==> Atlaso appliance: {label} failed after {elapsed} "
            f"({failure_reason}); last TDNF output:",
            file=sys.stderr,
            flush=True,
        )
        for line in _failure_tail(output_path, failure_tail_lines):
            print(line, file=sys.stderr)

    try:
        output_path.unlink()
    except OSError:
        pass
    return 1 if reported_failure else status


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Command-line arguments to parse, or ``None`` to use the process arguments.


    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--label", required=True, help="Operator-facing operation name."
    )
    parser.add_argument("--cache-dir", type=Path, default=Path("/var/cache/tdnf"))
    parser.add_argument("--heartbeat-seconds", type=float, default=30)
    parser.add_argument("--failure-tail-lines", type=int, default=200)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    if args.heartbeat_seconds <= 0:
        parser.error("--heartbeat-seconds must be greater than zero")
    if args.failure_tail_lines <= 0:
        parser.error("--failure-tail-lines must be greater than zero")

    return run(
        command,
        label=args.label,
        cache_dir=args.cache_dir,
        heartbeat_seconds=args.heartbeat_seconds,
        failure_tail_lines=args.failure_tail_lines,
    )


if __name__ == "__main__":
    raise SystemExit(main())
