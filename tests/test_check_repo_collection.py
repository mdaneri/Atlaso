"""Repository discovery must separate source validation from local task state."""

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from scripts import check_repo


def test_default_scan_prunes_task_state_and_checks_tracked_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ignored malformed fixtures must not hide a tracked malformed source.

    Args:
        tmp_path: Isolated repository fixture root.
        monkeypatch: Replaces the checker root and guards directory traversal.
    """
    monkeypatch.setattr(check_repo, "ROOT", tmp_path)
    (tmp_path / ".gitignore").write_text("/.atlaso-local/\n", encoding="utf-8")
    local = tmp_path / ".atlaso-local"
    local.mkdir()
    (local / "invalid.json").write_text("{", encoding="utf-8")
    (local / "vendor.txt").write_bytes(b"\xff\xfeVendor metadata")
    source = tmp_path / "tracked.json"
    source.write_text("{", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.json"], check=True)
    ignored = subprocess.run(
        ["git", "-C", str(tmp_path), "check-ignore", ".atlaso-local/invalid.json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert ignored.stdout.strip() == ".atlaso-local/invalid.json"
    original_scandir = os.scandir

    def guarded_scandir(path: str | os.PathLike[str]) -> Iterator[os.DirEntry[str]]:
        """Fail if discovery even attempts to enumerate excluded directories.

        Args:
            path: Directory requested by the discovery walker.
        """
        assert Path(path) not in (local, tmp_path / ".git")
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", guarded_scandir)
    assert check_repo.collect_files([]) == [source]
    assert any(
        "Expecting property name" in finding.message
        for finding in check_repo.check_file(source)
    )


@pytest.mark.parametrize("selection", ["file", "directory", "root"])
@pytest.mark.parametrize("payload", [b"{", b"\xff\xfeVendor metadata"])
def test_explicit_paths_still_validate_local_fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: str, payload: bytes
) -> None:
    """Explicit paths deliberately include malformed task-local content.

    Args:
        tmp_path: Isolated repository fixture root.
        monkeypatch: Replaces the checker root.
        selection: Explicit file, local directory, or repository root selection.
        payload: Malformed JSON or non-UTF-8 fixture bytes.
    """
    monkeypatch.setattr(check_repo, "ROOT", tmp_path)
    local = tmp_path / ".atlaso-local"
    local.mkdir()
    fixture = local / "invalid.json"
    fixture.write_bytes(payload)
    selected = {"file": fixture, "directory": local, "root": tmp_path}[selection]
    assert check_repo.collect_files([str(selected)]) == [fixture]
    assert check_repo.check_file(fixture)


def test_default_exclusion_is_root_scoped_and_does_not_require_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Source archives and untracked sources keep the existing check surface.

    Args:
        tmp_path: Isolated source archive fixture root.
        monkeypatch: Replaces the checker root.
    """
    monkeypatch.setattr(check_repo, "ROOT", tmp_path)
    paths = [
        "source.json",
        "tests/.atlaso-local/fixture.json",
        ".atlaso-local-example/fixture.json",
        "image/common/sudoers.d/atlaso",
    ]
    for name in paths + [".atlaso-local/invalid.json", "node_modules/invalid.json"]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{", encoding="utf-8")
    assert check_repo.collect_files([]) == sorted(
        (tmp_path / name for name in paths), key=lambda path: str(path.relative_to(tmp_path))
    )


def test_explicit_paths_preserve_existing_exclusions_and_deduplication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The local-state exception does not bypass existing vendor exclusions.

    Args:
        tmp_path: Isolated repository fixture root.
        monkeypatch: Replaces the checker root.
    """
    monkeypatch.setattr(check_repo, "ROOT", tmp_path)
    local = tmp_path / ".atlaso-local"
    vendor = local / "node_modules" / "invalid.json"
    vendor.parent.mkdir(parents=True)
    vendor.write_text("{", encoding="utf-8")
    source = local / "valid.json"
    source.write_text("{}", encoding="utf-8")
    assert check_repo.collect_files(
        [".atlaso-local", str(source), str(vendor), "missing.json"]
    ) == [source]
