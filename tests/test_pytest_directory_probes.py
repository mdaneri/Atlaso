"""Keep the narrow synthetic directory-gate probe profile creation-bound and pinned."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.completed_task_cleanup import Cleanup, Refusal
from scripts.completed_task_files import FileRefusal, WindowsFiles
from scripts.pytest_directory_probes import PytestDirectoryProbeFiles

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows pinned generated-tree cleanup contract")

_SELECTOR = "pytest-probe/test_real_directory_gate_prune123/worktree/.atlaso-local"
_PROBE = Path(_SELECTOR)


def _owned_probe(tmp_path: Path) -> tuple[Path, dict, Path, Path]:
    """Create the exact harmless probe tree inside an ordinary test-owned output root.

    Args:
        tmp_path: Pytest-owned fixture parent used only for this test's isolated output.
    """
    root = tmp_path / "probe-validation-output"
    probe = root / _PROBE
    (probe / "nested empty").mkdir(parents=True)
    payload = probe / "result with spaces.txt"
    payload.write_bytes(b"generated")
    target = tmp_path
    resource = {
        "path": str(root),
        "root_identity": list(WindowsFiles().snapshot(root)["."]["identity"]),
        "cleanup_tool": "PytestGeneratedTree",
        "synthetic_directory_probes": [_SELECTOR],
    }
    return root, resource, target, payload


def _cleanup(root: Path, resource: dict) -> None:
    """Dispose a restored probe root through its exact owning profile.

    Args:
        root: Test-owned output root whose contents were restored to the fixed profile.
        resource: Profile resource carrying the exact selected nested root.
    """
    files = PytestDirectoryProbeFiles(resource["synthetic_directory_probes"])
    files.remove(root, files.snapshot(root))
    assert not root.exists()


def _cleanup_instance(target: Path) -> Cleanup:
    """Bind the real resource integration to a synthetic ordinary worktree.

    Args:
        target: Parent directory that contains the test-owned resource root.
    """
    cleanup = object.__new__(Cleanup)
    cleanup.target = target
    cleanup.git = lambda *_arguments: ""
    return cleanup


def _symlink(path: Path, target: Path) -> None:
    """Create a Windows file link or skip when the host lacks link privileges.

    Args:
        path: Test-owned link leaf within the selected probe.
        target: Test-owned regular file used as the link target.
    """
    try:
        path.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Windows symbolic links are unavailable: {exc}")


def test_selected_synthetic_directory_probe_is_snapshotted_and_removed(tmp_path: Path) -> None:
    """Accept the fixed explicit profile through real Cleanup integration and remove its root.

    Args:
        tmp_path: Pytest-owned fixture parent for the disposable output root.
    """
    root, resource, target, _payload = _owned_probe(tmp_path)
    try:
        cleanup = _cleanup_instance(target)
        files, snapshot = cleanup.generated_snapshot(resource)
        assert str(_PROBE / "nested empty") in snapshot
        assert str(_PROBE / "result with spaces.txt") in snapshot
        files.remove(root, snapshot)
        assert not root.exists()
    finally:
        if root.exists():
            _cleanup(root, resource)


def test_selected_probe_passes_full_resource_preview_schema(tmp_path: Path) -> None:
    """Accept the selector through the resource schema with original manifest binding and no mutation.

    Args:
        tmp_path: Pytest-owned root containing separate source, output, and durable evidence scopes.
    """
    root, resource, target, payload = _owned_probe(tmp_path / "worktree")
    manifest = tmp_path / "original.json"
    manifest.write_bytes(b'{"owner":"synthetic-probe-test"}')
    resource.update({"id": "probe-output", "kind": "generated_tree", "task_id": "probe-test",
                     "source_commit": "a" * 40, "repository": "example/Atlaso", "pr": 967,
                     "ownership_manifest": {"path": str(manifest),
                                            "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}})
    cleanup = _cleanup_instance(target)
    cleanup.root = tmp_path
    cleanup.repo = tmp_path / "primary"
    cleanup.evidence = tmp_path / "evidence"
    cleanup.handoff_path = tmp_path / "handoff.json"
    cleanup.config = tmp_path / "config.toml"
    cleanup.repository = "example/Atlaso"
    cleanup.handoff = {"task_id": "probe-test", "pr": 967, "resources": [resource]}
    cleanup.head = "a" * 40
    cleanup.digest = "b" * 64
    cleanup.execute = False
    cleanup.gates = []
    cleanup.proposed = []
    cleanup.controller = SimpleNamespace(call=lambda *_args: {
        "ownership_verified": True, "inactive": True, "retained": False,
        "supported_cleanup": True, "evidence_preserved": True, "absent": False,
    })
    try:
        cleanup.resources()
        assert cleanup.proposed[0]["action"] == "remove exact generated tree through checked handles"
        assert payload.read_bytes() == b"generated"
        assert cleanup.gates == []
    finally:
        _cleanup(root, resource)


@pytest.mark.parametrize("mode", ["default", "missing-selector"])
def test_synthetic_probe_requires_explicit_profile_selection(tmp_path: Path, mode: str) -> None:
    """Reject nested recovery roots unless the explicit probe profile selects them.

    Args:
        tmp_path: Pytest-owned fixture parent for the disposable output root.
        mode: Whether to omit the profile field or supply an empty selection.
    """
    root, resource, target, _payload = _owned_probe(tmp_path)
    if mode == "default":
        resource.pop("synthetic_directory_probes")
    else:
        resource["synthetic_directory_probes"] = []
    try:
        with pytest.raises((Refusal, FileRefusal)):
            _cleanup_instance(target).generated_snapshot(resource)
    finally:
        resource["synthetic_directory_probes"] = [_SELECTOR]
        _cleanup(root, resource)


@pytest.mark.parametrize("selector", [
    "pytest-other/test_real_directory_gate_prune124/worktree/.atlaso-local",
    "pytest-probe/test_real_directory_gate_prune123/worktree/.atlaso-local",
    "../pytest-probe/test_real_directory_gate_prune123/worktree/.atlaso-local",
    "pytest-probe/test_real_directory_gate_prune123/worktree/not-recovery",
])
def test_synthetic_probe_rejects_unlisted_duplicate_traversal_and_bad_shapes(
    tmp_path: Path, selector: str,
) -> None:
    """Reject selectors outside the exact bounded profile, including duplicates.

    Args:
        tmp_path: Pytest-owned fixture parent for the disposable output root.
        selector: Invalid selector or duplicate selector list to reject.
    """
    root, resource, target, _payload = _owned_probe(tmp_path)
    resource["synthetic_directory_probes"] = [_SELECTOR, selector] if selector == _SELECTOR else [selector]
    try:
        with pytest.raises((Refusal, FileRefusal)):
            _cleanup_instance(target).generated_snapshot(resource)
    finally:
        resource["synthetic_directory_probes"] = [_SELECTOR]
        _cleanup(root, resource)


def test_synthetic_probe_rejects_an_additional_nested_recovery_root(tmp_path: Path) -> None:
    """Require selectors to cover every nested recovery root in the snapshotted tree.

    Args:
        tmp_path: Pytest-owned fixture parent for the disposable output root.
    """
    root, resource, target, _payload = _owned_probe(tmp_path)
    extra = root / "pytest-extra" / "test_real_directory_gate_prune124" / "worktree" / ".atlaso-local"
    extra.mkdir(parents=True)
    try:
        with pytest.raises((Refusal, FileRefusal), match="Unlisted or missing"):
            _cleanup_instance(target).generated_snapshot(resource)
    finally:
        extra.rmdir()
        extra.parent.rmdir()
        extra.parent.parent.rmdir()
        extra.parent.parent.parent.rmdir()
        _cleanup(root, resource)


@pytest.mark.parametrize("shape", ["wrong-bytes", "extra-entry", "directory-payload", "file-directory", "link"])
def test_synthetic_probe_rejects_changed_or_extra_contents_and_restores_fixture(
    tmp_path: Path, shape: str,
) -> None:
    """Reject content, entry, type, and link deviations from the fixed synthetic tree.

    Args:
        tmp_path: Pytest-owned fixture parent for the disposable output root.
        shape: Probe mutation used to exercise the strict profile boundary.
    """
    root, resource, target, payload = _owned_probe(tmp_path)
    probe = root / _PROBE
    extra = probe / "extra.txt"
    nested_empty = probe / "nested empty"
    link_target = root / "link target.txt"
    try:
        if shape == "wrong-bytes":
            payload.write_bytes(b"tampered!")
        elif shape == "extra-entry":
            extra.write_text("extra", encoding="utf-8")
        elif shape == "directory-payload":
            payload.unlink()
            payload.mkdir()
        elif shape == "file-directory":
            nested_empty.rmdir()
            nested_empty.write_text("not a directory", encoding="utf-8")
        else:
            link_target.write_bytes(b"generated")
            payload.unlink()
            _symlink(payload, link_target)

        with pytest.raises((Refusal, FileRefusal)):
            _cleanup_instance(target).generated_snapshot(resource)
    finally:
        if payload.is_symlink():
            payload.unlink()
        if payload.is_dir():
            payload.rmdir()
        if shape == "file-directory" and nested_empty.is_file():
            nested_empty.unlink()
        if not nested_empty.exists():
            nested_empty.mkdir()
        payload.write_bytes(b"generated")
        extra.unlink(missing_ok=True)
        link_target.unlink(missing_ok=True)
        _cleanup(root, resource)


def test_pinned_probe_payload_change_blocks_every_disposal(tmp_path: Path) -> None:
    """Catch same-size content replacement after inventory and before any pinned deletion.

    Args:
        tmp_path: Pytest-owned fixture parent for the disposable output root.
    """
    root, resource, target, payload = _owned_probe(tmp_path)
    original_stamp = payload.stat()

    class ReplaceAfterInventory(PytestDirectoryProbeFiles):
        """Inject a content replacement after snapshot verification and before handle pinning."""

        def __init__(self) -> None:
            """Select the one creation-bound probe root used by this test."""
            super().__init__([_SELECTOR])
            self.disposals = 0

        def remove_pinned(self, checked_root: Path, expected: dict[str, dict]) -> None:
            """Change bytes while preserving size and mtime before the fresh pinned pass.

            Args:
                checked_root: Resource root passed by the ordinary removal entry point.
                expected: Preflight snapshot that the pinned pass must verify.
            """
            payload.write_bytes(b"tampered!")
            os.utime(payload, ns=(original_stamp.st_atime_ns, original_stamp.st_mtime_ns))
            super().remove_pinned(checked_root, expected)

        def dispose(self, handle: int) -> None:
            """Count disposal calls to prove failure occurs before the first deletion.

            Args:
                handle: Exact pinned handle passed to the normal disposer.
            """
            self.disposals += 1
            super().dispose(handle)

    files = ReplaceAfterInventory()
    try:
        _files, snapshot = _cleanup_instance(target).generated_snapshot(resource)
        with pytest.raises(FileRefusal, match="payload changed before pinned release"):
            files.remove(root, snapshot)
        assert files.disposals == 0
        assert payload.read_bytes() == b"tampered!"
        assert (root / _PROBE / "nested empty").is_dir()
    finally:
        payload.write_bytes(b"generated")
        os.utime(payload, ns=(original_stamp.st_atime_ns, original_stamp.st_mtime_ns))
        _cleanup(root, resource)
