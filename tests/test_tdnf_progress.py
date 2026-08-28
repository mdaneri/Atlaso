"""Test tdnf progress behavior."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path("scripts/run_tdnf_with_progress.py").resolve()


def run_progress_wrapper(
    tmp_path: Path, child_source: str, *extra_args: str
) -> subprocess.CompletedProcess[str]:
    """Run progress wrapper.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        child_source: Child source supplied to the test scenario.
        *extra_args: Additional positional arguments accepted by the callable.


    Returns:
        The run progress wrapper result.
    """
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "download.rpm").write_bytes(b"x" * 2048)
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--label",
            "Photon OS update",
            "--cache-dir",
            str(cache),
            "--heartbeat-seconds",
            "0.05",
            *extra_args,
            "--",
            sys.executable,
            "-c",
            child_source,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_progress_wrapper_emits_heartbeats_without_streaming_raw_output(tmp_path):
    """Verify that progress wrapper emits heartbeats without streaming raw output.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    result = run_progress_wrapper(
        tmp_path,
        "import time; print('raw transaction output', flush=True); time.sleep(0.14)",
    )

    assert result.returncode == 0
    assert "Photon OS update started" in result.stdout
    assert "Photon OS update still running" in result.stdout
    assert "TDNF cache 2.0 KiB" in result.stdout
    assert "Photon OS update completed" in result.stdout
    assert "raw transaction output" not in result.stdout
    assert result.stderr == ""


def test_progress_wrapper_replays_bounded_normalized_tail_on_failure(tmp_path):
    """Verify that progress wrapper replays bounded normalized tail on failure.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    result = run_progress_wrapper(
        tmp_path,
        "import sys; "
        "[sys.stdout.write(f'line-{index:03d}\\r') for index in range(205)]; "
        "sys.stdout.flush(); "
        "print('final failure', file=sys.stderr); "
        "raise SystemExit(7)",
        "--failure-tail-lines",
        "3",
    )

    assert result.returncode == 7
    assert "failed after" in result.stderr
    assert "exit status 7" in result.stderr
    assert "line-203" in result.stderr
    assert "line-204" in result.stderr
    assert "final failure" in result.stderr
    assert "line-202" not in result.stderr


def test_progress_wrapper_rejects_tdnf_error_with_zero_exit_status(tmp_path):
    """Treat a repository error reported with status zero as fatal."""

    result = run_progress_wrapper(
        tmp_path,
        "print(\"Error: Failed to synchronize cache for repo 'photon-updates'\"); "
        "print(\"Disabling Repo: 'photon-updates'\")",
    )

    assert result.returncode == 1
    assert "reported an error despite exit status 0" in result.stderr
    assert "Failed to synchronize cache" in result.stderr
    assert "Disabling Repo" in result.stderr
