"""Exercise native configuration copy, refusal, and interrupted-release recovery without secrets."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from scripts import onepassword_task_configuration as configuration
from scripts.completed_task_cleanup import Cleanup, Refusal
from scripts.completed_task_files import FileRefusal, WindowsFiles
from scripts.pytest_git_fixtures import FixtureGit, PytestGitFixtures, publish

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Requires Windows pinned security and deletion APIs")


@pytest.fixture
def owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Create synthetic source bytes and use the production owner for their task-local copy.

    Args:
        tmp_path: Creation-receipted pytest validation output parent.
        monkeypatch: Replace Git discovery only; retain native ACL, identity, and deletion checks.
    """
    permitted = tmp_path / "permitted"
    permitted.mkdir()
    evidence = permitted / "receipts"
    evidence.mkdir()
    home = tmp_path / "codex-home"
    home.mkdir()
    config = home / "config.toml"
    config.write_text("[desktop]\ngit-worktree-root = " + json.dumps(str(permitted)), encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(home))
    primary = tmp_path / "synthetic-primary"
    primary.mkdir()
    source = primary / ".atlaso-local"
    source.mkdir()
    files = configuration.ConfigurationFiles()
    files.restrict(source)
    # Original fixture identity is durable before synthetic data is written or used.
    publish(evidence / "synthetic-source-created.json",
            {"path": str(source), "identity": files.snapshot(source)["."]["identity"]})
    values = (b"synthetic-atlaso-environment", b"fixed non-secret ciphertext fixture " * 3)
    for name, value in zip(configuration.NAMES, values, strict=True):
        path = source / name
        path.write_bytes(value)
        files.restrict(path)
    source_snapshot = files.inventory(source)
    publish(evidence / "synthetic-source-sealed.json", {"entries": source_snapshot})
    monkeypatch.setattr(configuration, "ENVIRONMENT_SHA256", hashlib.sha256(values[0]).hexdigest())
    worktree = permitted / "task"
    worktree.mkdir()
    binding = {"id": "configuration", "task_id": "test-task", "repository": "example/Atlaso",
               "source_commit": "a" * 40, "path": str(worktree / ".atlaso-local")}
    tool = configuration.OnePasswordTaskConfiguration(config, evidence / "config.json", binding)
    monkeypatch.setattr(tool, "git_identity", lambda: primary)
    monkeypatch.setattr(FixtureGit, "git", lambda _self, *args: "ignored" if "check-ignore" in args else "")
    manifest = tool.copy_from_primary()
    resource = {**binding, "kind": "configuration", "cleanup_tool": configuration.TOOL, "pr": 1044,
                "ownership_manifest": manifest}
    yield tool, resource, source
    if tool.root.exists():
        tool.release([str(tool.root)])
    # This is the harness's creation-receipted fixed synthetic source, outside any real
    # primary checkout. Use the same exact-handle owner primitive, never recursive removal.
    files.remove_configuration(source, source_snapshot)


def request(resource: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """Build a fresh controller request using independently selected fixture identity.

    Args:
        resource: Exact fixture resource approved by the simulated controller.
        **fields: Additional release scopes or intentionally altered request fields.
    """
    return {"resource": resource, "handoff_sha256": "b" * 64, **fields}


def test_copy_and_configuration_resource_contract_preserve_source(owner):
    """Copy ciphertext unchanged, release only the task copy, and support absence retries.

    Args:
        owner: New native configuration owner and its fixed synthetic primary source.
    """
    tool, resource, source = owner
    original = {name: (source / name).read_bytes() for name in configuration.NAMES}
    assert all((tool.root / name).read_bytes() == original[name] for name in configuration.NAMES)
    assert tool.controller_call("resource.inspect", request(resource), resource)["absent"] is False
    assert tool.controller_call("resource.release", request(resource, removal_scopes=[str(tool.root)]), resource) == {
        "success": True,
    }
    assert tool.controller_call("resource.inspect", request(resource), resource)["absent"] is True
    assert tool.release([str(tool.root)]) == {"success": True}
    assert {name: (source / name).read_bytes() for name in configuration.NAMES} == original


@pytest.mark.parametrize("name", ["recovery.json", "credential-cleanup", "runtime.lock", ".git"])
def test_recovery_or_uninventoried_state_refuses_entire_release(owner, name):
    """Do not delete either configuration file while unknown state survives.

    Args:
        owner: New native configuration owner and source.
        name: Unexpected runtime, recovery, lock, or Git entry.
    """
    tool, _resource, _source = owner
    extra = tool.root / name
    extra.write_text("synthetic residue", encoding="utf-8")
    try:
        with pytest.raises(Refusal, match="recovery residue"):
            tool.release([str(tool.root)])
        assert all((tool.root / item).exists() for item in configuration.NAMES)
        assert not tool.stage(".prepared").exists()
    finally:
        extra.unlink()


def test_changed_ciphertext_with_preserved_mtime_refuses(owner):
    """Hash verification catches same-size mutations that timestamp checks cannot see.

    Args:
        owner: New native configuration owner and source.
    """
    tool, _resource, _source = owner
    path = tool.root / configuration.NAMES[1]
    original, info = path.read_bytes(), path.stat()
    path.write_bytes(b"X" + original[1:])
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    try:
        with pytest.raises(Refusal, match="bytes changed"):
            tool.release([str(tool.root)])
    finally:
        path.write_bytes(original)
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))


def test_replaced_file_refuses_even_identical_bytes(owner):
    """An identical replacement has no original creation identity.

    Args:
        owner: New native configuration owner and source.
    """
    tool, _resource, _source = owner
    path = tool.root / configuration.NAMES[1]
    held = tool.root.parent / "held-original"
    path.rename(held)
    path.write_bytes(held.read_bytes())
    tool.files.restrict(path)
    try:
        with pytest.raises(Refusal, match="identity or bytes"):
            tool.release([str(tool.root)])
    finally:
        path.unlink()
        held.rename(path)


def test_hard_link_refuses_before_any_deletion(owner):
    """Sharing the ciphertext inode blocks the entire copy release.

    Args:
        owner: New native configuration owner and source.
    """
    tool, _resource, _source = owner
    alias = tool.root.parent / "ciphertext-alias"
    os.link(tool.root / configuration.NAMES[1], alias)
    try:
        with pytest.raises(FileRefusal, match="hard-linked"):
            tool.release([str(tool.root)])
        assert all((tool.root / name).exists() for name in configuration.NAMES)
    finally:
        alias.unlink()


@pytest.mark.parametrize("sddl", ["D:P(A;;FA;;;WD)", "D:(A;;FA;;;SY)"])
def test_unsafe_acl_refuses_and_preserves(owner, sddl):
    """Refuse broad access, missing user access, and inherited ACL state.

    Args:
        owner: New native configuration owner and source.
        sddl: Unsafe fixed synthetic security descriptor.
    """
    tool, _resource, _source = owner
    path = tool.root / configuration.NAMES[1]
    descriptor = ctypes.c_void_p()
    assert tool.files.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None)
    try:
        assert tool.files.security.SetFileSecurityW(str(path), 4, descriptor)
        with pytest.raises((Refusal, FileRefusal)):
            tool.release([str(tool.root)])
        assert path.exists()
    finally:
        tool.files.kernel.LocalFree(descriptor)
        tool.files.restrict(path)


def test_active_reader_refuses_disposition(owner):
    """An existing consumer's open handle prevents release, retaining both files.

    Args:
        owner: New native configuration owner and source.
    """
    tool, _resource, _source = owner
    with tool.files.opened(tool.root / configuration.NAMES[1]):
        with pytest.raises(FileRefusal, match="Cannot pin"):
            tool.release([str(tool.root)])
    assert all((tool.root / name).exists() for name in configuration.NAMES)


def test_interrupted_release_resumes_from_original_prepared_inventory(owner, monkeypatch):
    """A failed second disposition permits retry only for the surviving original objects.

    Args:
        owner: New native configuration owner and source.
        monkeypatch: Inject a single interrupted deletion after the selector is released.
    """
    tool, _resource, source = owner
    original = WindowsFiles.dispose
    calls = 0

    def interrupted(self, handle):
        """Dispose the first object, then simulate an interrupted owning-tool release.

        Args:
            self: Native pinned-files implementation.
            handle: Already verified exact object selected for disposal.
        """
        nonlocal calls
        calls += 1
        if calls == 2:
            raise FileRefusal("synthetic interruption")
        original(self, handle)

    with monkeypatch.context() as scoped:
        scoped.setattr(WindowsFiles, "dispose", interrupted)
        with pytest.raises(FileRefusal, match="synthetic interruption"):
            tool.release([str(tool.root)])
    assert not (tool.root / configuration.NAMES[0]).exists()
    assert (tool.root / configuration.NAMES[1]).exists()
    assert tool.inspect()["absent"] is False
    assert tool.release([str(tool.root)]) == {"success": True}
    assert all((source / name).exists() for name in configuration.NAMES)


def test_reappearance_after_completed_release_is_preserved(owner):
    """A completed receipt cannot authorize deleting a new configuration generation.

    Args:
        owner: New native configuration owner and source.
    """
    tool, _resource, _source = owner
    tool.release([str(tool.root)])
    tool.root.mkdir()
    try:
        with pytest.raises(Refusal, match="reappeared"):
            tool.release([str(tool.root)])
        assert tool.root.is_dir()
    finally:
        tool.root.rmdir()


@pytest.mark.parametrize("field,value", [
    ("kind", "generated_tree"), ("cleanup_tool", "other"), ("pr", 0), ("task_id", "other-task"),
    ("repository", "other/Atlaso"), ("source_commit", "c" * 40),
    ("ownership_manifest", {"path": "elsewhere", "sha256": "d" * 64}),
])
def test_controller_binding_refuses_mismatched_approval(owner, field, value):
    """The owning adapter never broadens a controller's exact approved resource.

    Args:
        owner: New native configuration owner and source.
        field: Resource identity field to corrupt.
        value: Unapproved replacement identity.
    """
    tool, resource, _source = owner
    wrong = {**resource, field: value}
    with pytest.raises(Refusal):
        tool.controller_call("resource.release", request(wrong, removal_scopes=[str(tool.root)]), wrong)
    assert all((tool.root / name).exists() for name in configuration.NAMES)


def test_scope_and_creation_provenance_are_required(owner):
    """Neither missing original evidence nor an expanded scope can authorize release.

    Args:
        owner: New native configuration owner and source.
    """
    tool, _resource, _source = owner
    with pytest.raises(Refusal, match="scope differs"):
        tool.release([str(tool.worktree)])
    held = tool.receipt.with_name("held-creation")
    tool.receipt.rename(held)
    try:
        with pytest.raises(FileNotFoundError):
            tool.release([str(tool.root)])
    finally:
        held.rename(tool.receipt)


def test_copy_refuses_existing_configuration_without_adoption(owner):
    """Repeated setup cannot overwrite or retrofit provenance for an existing copy.

    Args:
        owner: New native configuration owner and source.
    """
    tool, _resource, _source = owner
    with pytest.raises(Refusal, match="never adopt"):
        tool.copy_from_primary()


def test_pending_receipt_refuses_without_mutation(owner):
    """Interrupted publication requires explicit reconciliation.

    Args:
        owner: New native configuration owner and source.
    """
    tool, _resource, _source = owner
    pending = tool.stage(".prepared.pending")
    pending.write_text("synthetic interrupted publication", encoding="utf-8")
    try:
        with pytest.raises(Refusal, match="Pending"):
            tool.release([str(tool.root)])
    finally:
        pending.unlink()


@pytest.mark.parametrize("directory", [False, True])
def test_reparse_file_or_root_is_preserved(owner, directory):
    """Refuse both linked configuration leaves and a linked configuration root.

    Args:
        owner: New native configuration owner and source.
        directory: Whether to replace the entire configuration root with a link.
    """
    tool, _resource, _source = owner
    path = tool.root if directory else tool.root / configuration.NAMES[1]
    held = tool.worktree / "held-object"
    path.rename(held)
    try:
        try:
            path.symlink_to(held, target_is_directory=directory)
        except OSError:
            pytest.skip("Host does not grant symbolic-link creation")
        with pytest.raises((Refusal, FileRefusal)):
            tool.release([str(tool.root)])
    finally:
        if path.is_symlink():
            path.unlink()
        held.rename(path)


def test_real_git_primary_registration_and_repository_binding(owner, monkeypatch):
    """Exercise real Git discovery with exclusively registered disposable repositories.

    Args:
        owner: Native fixture providing a permitted root and durable evidence directory.
        monkeypatch: Restore the real contained Git runner for this integration check.
    """
    tool, _resource, source = owner
    config = Path(os.environ["CODEX_HOME"]) / "config.toml"
    root = tool.permitted / "git-graph"
    binding = {**tool.binding, "id": "git-graph", "path": str(root)}
    graph = PytestGitFixtures(config, tool.receipt.parent / "graph.json", binding)
    graph.create()
    with monkeypatch.context() as scoped:
        scoped.setattr(FixtureGit, "git", Cleanup.git)
        runner = FixtureGit(root)
        primary, linked = root / "primary", root / "linked"
        runner.git("init", "--initial-branch=main", str(primary))
        graph.register(primary)
        (primary / "tracked.txt").write_text("synthetic source", encoding="utf-8")
        (primary / ".gitignore").write_text("/.atlaso-local/\n", encoding="utf-8")
        runner.git("-C", str(primary), "add", "tracked.txt", ".gitignore")
        runner.git("-C", str(primary), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                   "-c", "commit.gpgsign=false", "commit", "-m", "fixture")
        runner.git("-C", str(primary), "remote", "add", "origin", "https://github.com/example/Atlaso.git")
        head = runner.git("-C", str(primary), "rev-parse", "HEAD")
        runner.git("-C", str(primary), "worktree", "add", "--detach", str(linked), "HEAD")
        graph.register(linked)
        actual = configuration.OnePasswordTaskConfiguration(config, tool.receipt.parent / "real-git.json",
            {**tool.binding, "id": "real-git", "source_commit": head, "path": str(linked / ".atlaso-local")})
        assert actual.git_identity() == primary
        fixture_source = primary / ".atlaso-local"
        source.rename(fixture_source)
        try:
            actual.copy_from_primary()
            assert actual.release([str(actual.root)]) == {"success": True}
            assert all((fixture_source / name).exists() for name in configuration.NAMES)
        finally:
            fixture_source.rename(source)
        runner.git("-C", str(primary), "remote", "set-url", "origin", "https://github.com/other/Atlaso.git")
        with pytest.raises(Refusal, match="Repository binding"):
            actual.git_identity()
        graph.seal()
        assert graph.release([str(root)]) == {"success": True}
        assert actual.inspect()["absent"] is True
