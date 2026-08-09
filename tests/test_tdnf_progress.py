"""Test tdnf progress behavior."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


SCRIPT = Path("scripts/run_tdnf_with_progress.py").resolve()


def run_progress_wrapper(tmp_path: Path, child_source: str, *extra_args: str) -> subprocess.CompletedProcess[str]:
    """Run progress wrapper.

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
    """Verify that progress wrapper emits heartbeats without streaming raw output."""
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
    """Verify that progress wrapper replays bounded normalized tail on failure."""
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
