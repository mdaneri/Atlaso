"""Behavior tests for Inventory Linux's verified Buildroot download cache."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = REPOSITORY_ROOT / "image" / "inventory-linux" / "build.sh"


def _bash_path() -> str:
    """Return Bash or skip when no compatible shell is available."""
    if os.name == "nt":
        for candidate in (
            Path("C:/Program Files/Git/bin/bash.exe"),
            Path("C:/Program Files/Git/usr/bin/bash.exe"),
        ):
            if candidate.is_file():
                return str(candidate)
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash is required for Inventory Linux cache behavior tests")
    return bash


def _run_cache_fixture(
    tmp_path: Path, *, upstream_payload: bytes
) -> tuple[subprocess.CompletedProcess[str], Path, Path, Path]:
    """Run the real cache logic with bounded fake download and extraction commands.

    Args:
        tmp_path: Isolated test directory.
        upstream_payload: Bytes emitted by the fake curl command.

    Returns:
        Completed process, archive path, unrelated sentinel, and tar marker.
    """
    fixture_root = tmp_path / "fixture"
    script_directory = fixture_root / "repo" / "image" / "inventory-linux"
    script_directory.mkdir(parents=True)
    valid_payload = b"verified Buildroot fixture archive"
    expected_digest = hashlib.sha256(valid_payload).hexdigest()
    command_shims = r'''
git() {
  printf '0\n'
}
curl() {
  local output=""
  while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == "--output" ]]; then
      output="$2"
      shift 2
      continue
    fi
    shift
  done
  printf '%s' "${ATLASO_TEST_UPSTREAM_PAYLOAD}" >"${output}"
  printf 'downloaded\n' >>"${ATLASO_TEST_CURL_LOG}"
}
tar() {
  printf 'invoked\n' >"${ATLASO_TEST_TAR_MARKER}"
  return 42
}
'''
    script_text = BUILD_SCRIPT.read_text(encoding="utf-8").replace(
        'buildroot_sha256="ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58"',
        f'buildroot_sha256="{expected_digest}"',
    )
    script_text = script_text.replace("set -euo pipefail\n", f"set -euo pipefail\n{command_shims}\n", 1)
    fixture_script = script_directory / "build.sh"
    fixture_script.write_text(script_text, encoding="utf-8", newline="\n")
    fixture_script.chmod(0o755)

    source_root = fixture_root / "cache"
    download_directory = source_root / "downloads"
    download_directory.mkdir(parents=True)
    archive_path = download_directory / "buildroot-2026.05.1.tar.xz"
    archive_path.write_bytes(b"corrupt cached archive")
    unrelated_sentinel = download_directory / "unrelated-cache-entry"
    unrelated_sentinel.write_bytes(b"preserve")

    curl_log = fixture_root / "curl.log"
    tar_marker = fixture_root / "tar.marker"
    environment = os.environ.copy()
    environment.update(
        {
            "ATLASO_INVENTORY_BUILD_ROOT": source_root.as_posix(),
            "ATLASO_TEST_UPSTREAM_PAYLOAD": upstream_payload.decode("ascii"),
            "ATLASO_TEST_CURL_LOG": curl_log.as_posix(),
            "ATLASO_TEST_TAR_MARKER": tar_marker.as_posix(),
        }
    )
    result = subprocess.run(
        [_bash_path(), fixture_script.as_posix()],
        cwd=fixture_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    return result, archive_path, unrelated_sentinel, tar_marker


def test_corrupt_buildroot_cache_is_reacquired_and_atomically_promoted(tmp_path: Path) -> None:
    """An ordinary rerun must replace the exact corrupt archive before extraction.

    Args:
        tmp_path: Isolated test directory.
    """
    valid_payload = b"verified Buildroot fixture archive"
    result, archive_path, unrelated_sentinel, tar_marker = _run_cache_fixture(
        tmp_path, upstream_payload=valid_payload
    )

    assert result.returncode == 42
    assert archive_path.read_bytes() == valid_payload
    assert unrelated_sentinel.read_bytes() == b"preserve"
    assert tar_marker.is_file()
    assert not list(archive_path.parent.glob(f"{archive_path.name}.part.*"))


def test_invalid_buildroot_download_is_not_promoted(tmp_path: Path) -> None:
    """A checksum failure must remove the exact bad cache and unique partial download.

    Args:
        tmp_path: Isolated test directory.
    """
    result, archive_path, unrelated_sentinel, tar_marker = _run_cache_fixture(
        tmp_path, upstream_payload=b"invalid Buildroot download"
    )

    assert result.returncode != 0
    assert not archive_path.exists()
    assert unrelated_sentinel.read_bytes() == b"preserve"
    assert not tar_marker.exists()
    assert not list(archive_path.parent.glob(f"{archive_path.name}.part.*"))
