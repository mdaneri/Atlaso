"""Keep pytest validation links safe during Windows generated-tree cleanup."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from scripts.completed_task_cleanup import Cleanup, Refusal
from scripts.completed_task_files import FileRefusal, WindowsFiles

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows symbolic-link cleanup contract")


def _symlink(path: Path, target: str | Path, *, directory: bool = False) -> None:
    """Create a symbolic link or skip where the Windows host lacks link privileges."""
    try:
        path.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Windows symbolic links are unavailable: {exc}")


def test_pytest_internal_links_are_snapshotted_as_leaf_entries_and_removed(tmp_path: Path) -> None:
    """Allow internal link leaves without traversing targets, including a current/.venv chain.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
    """
    root = tmp_path / "pytest-validation"
    root.mkdir()
    release = root / "release-fixture"
    release.mkdir()
    (release / "runtime.txt").write_text("runtime", encoding="utf-8")
    venv = root / ".venv"
    venv.mkdir()
    (venv / "python.exe").write_text("fixture", encoding="utf-8")

    _symlink(release / ".venv", venv, directory=True)
    current_target = root / "current-target"
    _symlink(current_target, release, directory=True)
    _symlink(root / "current", current_target, directory=True)
    _symlink(root / "current-alias", Path("current"), directory=True)
    _symlink(root / "runtime-link", release / "runtime.txt")
    _symlink(root / "dangling-cache", Path("not-created"))

    files = WindowsFiles(allow_internal_symlinks=True)
    snapshot = files.snapshot(root)

    assert {"current", "current-target", "current-alias", str(Path("release-fixture") / ".venv"),
            "runtime-link", "dangling-cache"} <= set(snapshot)
    assert str(Path("current") / "runtime.txt") not in snapshot
    assert str(Path("current") / ".venv" / "python.exe") not in snapshot
    assert str(Path("release-fixture") / ".venv" / "python.exe") not in snapshot
    for name in ("current", "current-target", "current-alias", str(Path("release-fixture") / ".venv"),
                 "runtime-link", "dangling-cache"):
        assert snapshot[name]["identity"]
        assert snapshot[name]["stamp"]
        assert len(snapshot[name]["link_sha256"]) == 64

    files.remove(root, snapshot)
    assert not os.path.lexists(root)


def test_default_snapshot_rejects_internal_links_and_linked_roots(tmp_path: Path) -> None:
    """Keep ordinary snapshots strict and refuse a link as the root or an ancestor.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
    """
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    (real_root / "child").mkdir()
    (real_root / "child" / "output.txt").write_text("output", encoding="utf-8")
    internal_link = real_root / "internal-link"
    _symlink(internal_link, Path("child"), directory=True)

    files = WindowsFiles()
    try:
        with pytest.raises(FileRefusal):
            files.snapshot(real_root)
    finally:
        internal_link.unlink(missing_ok=True)

    linked_root = tmp_path / "linked-root"
    _symlink(linked_root, real_root, directory=True)
    try:
        with pytest.raises(FileRefusal):
            WindowsFiles(allow_internal_symlinks=True).snapshot(linked_root)
    finally:
        linked_root.unlink(missing_ok=True)

    linked_parent = tmp_path / "linked-parent"
    _symlink(linked_parent, real_root, directory=True)
    try:
        with pytest.raises(FileRefusal):
            WindowsFiles(allow_internal_symlinks=True).snapshot(linked_parent / "child")
    finally:
        linked_parent.unlink(missing_ok=True)
    files.remove(real_root, files.snapshot(real_root))


def test_internal_link_mode_rejects_external_targets_and_junctions(tmp_path: Path) -> None:
    """Reject links that escape the root and all junction reparse tags without touching targets.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
    """
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "keep.txt"
    sentinel.write_text("user-owned", encoding="utf-8")

    root = tmp_path / "pytest-validation"
    root.mkdir()
    external_link = root / "external-link"
    _symlink(external_link, external, directory=True)
    try:
        with pytest.raises(FileRefusal):
            WindowsFiles(allow_internal_symlinks=True).snapshot(root)
    finally:
        external_link.unlink(missing_ok=True)
    assert sentinel.read_text(encoding="utf-8") == "user-owned"

    junction_root = tmp_path / "pytest-junction-root"
    junction_root.mkdir()
    junction = junction_root / "external-junction"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
        check=False,
        capture_output=True,
        text=True,
    )
    if linked.returncode != 0:
        if os.path.lexists(junction):
            junction.rmdir()
        pytest.skip("Windows junction creation is unavailable")
    try:
        with pytest.raises(FileRefusal):
            WindowsFiles(allow_internal_symlinks=True).snapshot(junction_root)
    finally:
        junction.rmdir()
    assert sentinel.read_text(encoding="utf-8") == "user-owned"
    sentinel.unlink()
    external.rmdir()
    root.rmdir()
    junction_root.rmdir()


@pytest.mark.parametrize("change", ["target", "object"])
def test_remove_preserves_tree_when_a_link_changes_after_snapshot(tmp_path: Path, change: str) -> None:
    """Reject a changed link before deleting any snapshotted output.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
        change: Whether the raw target or the link object changes after inspection.
    """
    root = tmp_path / "pytest-validation"
    root.mkdir()
    first_target = root / "first-target.txt"
    first_target.write_text("first", encoding="utf-8")
    replacement_target = root / "replacement-target.txt"
    replacement_target.write_text("replacement", encoding="utf-8")
    guarded = root / "keep-until-revalidated.txt"
    guarded.write_text("preserve", encoding="utf-8")
    link = root / "current"
    _symlink(link, first_target)

    files = WindowsFiles(allow_internal_symlinks=True)
    snapshot = files.snapshot(root)
    if change == "target":
        link.unlink()
        _symlink(link, replacement_target)
    else:
        replacement_link = tmp_path / "replacement-link"
        _symlink(replacement_link, first_target)
        link.unlink()
        replacement_link.replace(link)

    with pytest.raises(FileRefusal):
        files.remove(root, snapshot)
    assert guarded.read_text(encoding="utf-8") == "preserve"
    assert link.exists()
    WindowsFiles(allow_internal_symlinks=True).remove(
        root, WindowsFiles(allow_internal_symlinks=True).snapshot(root)
    )


def test_remove_refuses_children_added_after_snapshot(tmp_path: Path) -> None:
    """A new ordinary child blocks pinned release and leaves the complete tree intact.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
    """
    root = tmp_path / "pytest-validation"
    root.mkdir()
    output = root / "pytest-current"
    output.mkdir()
    original = output / "result.txt"
    original.write_text("original", encoding="utf-8")
    files = WindowsFiles(allow_internal_symlinks=True)
    snapshot = files.snapshot(root)

    added = output / "late-result.txt"
    added.write_text("late", encoding="utf-8")
    with pytest.raises(FileRefusal):
        files.remove(root, snapshot)
    assert original.read_text(encoding="utf-8") == "original"
    assert added.read_text(encoding="utf-8") == "late"
    files.remove(root, files.snapshot(root))


def test_remove_pins_all_links_before_disposing_any_entry(tmp_path: Path) -> None:
    """A link changed after inventory comparison is caught before the first pinned deletion.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
    """
    root = tmp_path / "pytest-validation"
    root.mkdir()
    target = root / "target.txt"
    target.write_text("target", encoding="utf-8")
    guarded = root / "keep-until-revalidated.txt"
    guarded.write_text("preserve", encoding="utf-8")
    link = root / "current"
    _symlink(link, target)
    replacement_target = root / "replacement.txt"
    replacement_target.write_text("replacement", encoding="utf-8")

    class ReplaceAfterInventory(WindowsFiles):
        """Replace a link after remove's fresh snapshot and before handle pinning."""

        def remove_pinned(self, checked_root: Path, expected: dict[str, dict]) -> None:
            """Replace the link in the race window before the base implementation pins entries.

            Args:
                checked_root: Generated-tree root passed to the pinned release operation.
                expected: Complete preflight snapshot expected by the removal operation.
            """
            link.unlink()
            _symlink(link, replacement_target)
            super().remove_pinned(checked_root, expected)

    files = ReplaceAfterInventory(allow_internal_symlinks=True)
    snapshot = files.snapshot(root)
    with pytest.raises(FileRefusal, match="changed before pinned release"):
        files.remove(root, snapshot)
    assert guarded.read_text(encoding="utf-8") == "preserve"
    assert target.read_text(encoding="utf-8") == "target"
    assert replacement_target.read_text(encoding="utf-8") == "replacement"
    release_files = WindowsFiles(allow_internal_symlinks=True)
    release_files.remove(root, release_files.snapshot(root))


def test_generated_snapshot_refuses_tracked_and_protected_tree_entries(tmp_path: Path) -> None:
    """Apply generated-tree exclusions without creating nested Git repositories.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
    """
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    generated = worktree / "pytest-output"
    generated.mkdir()
    resource = {"path": str(generated), "root_identity": list(WindowsFiles().snapshot(generated)["."]["identity"]),
                "cleanup_tool": "PytestGeneratedTree"}
    cleanup = object.__new__(Cleanup)
    cleanup.target = worktree
    cleanup.git = lambda *_args: "tracked.txt"
    with pytest.raises(Refusal, match="tracked source"):
        cleanup.generated_snapshot(resource)

    cleanup.git = lambda *_args: ""
    marker_root = worktree / "marker-output"
    marker_root.mkdir()
    marker_resource = {**resource, "path": str(marker_root),
                       "root_identity": list(WindowsFiles().snapshot(marker_root)["."]["identity"])}
    nested = marker_root / "nested"
    nested.mkdir()
    git_marker = nested / ".git"
    recovery_root = nested / ".atlaso-local"
    try:
        git_marker.write_text("fixture marker", encoding="utf-8")
        with pytest.raises(Refusal, match="Nested repositories"):
            cleanup.generated_snapshot(marker_resource)

        git_marker.unlink()
        recovery_root.mkdir()
        with pytest.raises(Refusal, match="credential/recovery"):
            cleanup.generated_snapshot(marker_resource)
    finally:
        git_marker.unlink(missing_ok=True)
        if recovery_root.exists():
            recovery_root.rmdir()
        files = WindowsFiles()
        files.remove(marker_root, files.snapshot(marker_root))
        files.remove(generated, files.snapshot(generated))


def test_pytest_generated_snapshot_allows_only_known_top_level_validation_roots(tmp_path: Path) -> None:
    """Allow the receipted .atlaso-local validation root while refusing unknown children.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
    """
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    validation_root = worktree / ".atlaso-local"
    validation_root.mkdir()
    pytest_root = validation_root / "pytest"
    pytest_root.mkdir()
    validation_identity = WindowsFiles().snapshot(validation_root)["."]["identity"]
    (pytest_root / "pytest-current").mkdir()
    resource = {"path": str(validation_root),
                "root_identity": list(validation_identity),
                "cleanup_tool": "PytestGeneratedTree"}
    cleanup = object.__new__(Cleanup)
    cleanup.target = worktree
    cleanup.repository = "example/Atlaso"
    cleanup.git = lambda *_args: ""
    unknown = validation_root / "credentials"
    try:
        _files, snapshot = cleanup.generated_snapshot(resource)
        assert str(Path("pytest") / "pytest-current") in snapshot

        unknown.mkdir()
        with pytest.raises(Refusal, match="unknown or credential/recovery"):
            cleanup.generated_snapshot(resource)
    finally:
        if unknown.exists():
            unknown.rmdir()
        files = WindowsFiles()
        files.remove(validation_root, files.snapshot(validation_root))


def test_local_state_admits_only_resource_validated_pytest_links(tmp_path: Path) -> None:
    """Permit a validation link only when its root is a validated pytest resource.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
    """
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    validation_root = worktree / ".atlaso-local"
    validation_root.mkdir()
    pytest_root = validation_root / "pytest"
    pytest_root.mkdir()
    validation_identity = WindowsFiles().snapshot(validation_root)["."]["identity"]
    release = pytest_root / "release"
    release.mkdir()
    (release / "runtime.txt").write_text("fixture", encoding="utf-8")
    link = pytest_root / "current"
    _symlink(link, release, directory=True)
    manifest = tmp_path / "pytest-owner.json"
    manifest.write_text('{"owner":"test"}', encoding="utf-8")
    source = "a" * 40
    resource = {
        "id": "pytest-validation",
        "kind": "generated_tree",
        "task_id": "pytest-link-test",
        "source_commit": source,
        "repository": "example/Atlaso",
        "pr": 965,
        "path": str(validation_root),
        "root_identity": list(validation_identity),
        "cleanup_tool": "PytestGeneratedTree",
        "ownership_manifest": {
            "path": str(manifest),
            "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        },
    }
    cleanup = object.__new__(Cleanup)
    cleanup.target = worktree
    cleanup.repository = "example/Atlaso"
    cleanup.root = tmp_path
    cleanup.handoff = {
        "task_id": "pytest-link-test",
        "repository": "example/Atlaso",
        "pr": 965,
        "worktree_identity": [worktree.stat().st_dev, worktree.stat().st_ino],
        "resources": [resource],
    }
    cleanup.branch = "enhancement/965-pytest-link-cleanup"
    cleanup.head = source
    cleanup.gates = []
    cleanup.require_direct_task_ref = lambda: None
    cleanup.worktrees = lambda: [{
        "worktree": str(worktree),
        "branch": f"refs/heads/{cleanup.branch}",
        "HEAD": source,
    }]
    cleanup.git = lambda *_args: ""
    cleanup.verify_tracked_contents = lambda: None

    try:
        cleanup.local_state()

        cleanup.handoff["resources"] = []
        with pytest.raises(Refusal):
            cleanup.local_state()
    finally:
        link.unlink(missing_ok=True)
        files = WindowsFiles()
        files.remove(validation_root, files.snapshot(validation_root))
