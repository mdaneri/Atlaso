"""Exercise destructive cleanup against disposable Git repositories and checked output trees."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.completed_task_cleanup import (
    Cleanup,
    Refusal,
    configured_root,
    ordinary,
    read_handoff,
)
from scripts.completed_task_files import (
    FileRefusal,
    WindowsFiles,
    cleanup_lock,
    ensure_durable_directory,
    publish_durable_file,
    read_bounded_regular,
)


class Bridge:
    """Model independent live supported-tool readbacks, recording every requested mutation."""

    def __init__(self) -> None:
        """Initialize an eligible controller without hidden ownership defaults in production."""
        self.calls: list[str] = []
        self.block = ""
        self.resource_absent = False
        self.release_ok = True
        self.title: str | None = None

    def call(self, operation: str, payload: dict) -> dict:
        """Answer the bounded test protocol while allowing failed gates to be injected."""
        self.calls.append(operation)
        if operation == "task.inspect":
            result = dict.fromkeys(("identity_verified", "exclusive_ownership_verified", "idle", "unpinned",
                                   "holds_clear", "downstream_clear", "inventory_verified", "post_merge_complete",
                                   "reviews_complete", "supported_tools_used"), True)
            result.update(handoff_sha256=payload["sha256"], evidence_refs=["test-only-independent-readback"])
            result["inventory_empty_verified"] = True
            result["observed_title"] = self.title or payload["handoff"]["task_title"]
            result["post_merge_runs"] = [{"id": 1, "run_attempt": 1, "workflow_id": 10,
                                          "head_sha": payload["handoff"]["merge"], "event": "push"}]
            if self.block:
                result[self.block] = False
            return result
        if operation == "resource.inspect":
            return {"ownership_verified": True, "inactive": True, "retained": False,
                    "supported_cleanup": True, "evidence_preserved": True, "absent": self.resource_absent,
                    "removal_scopes": []}
        if operation == "resource.release":
            self.resource_absent = self.release_ok
            return {"success": self.release_ok}
        assert operation == "task.title"
        self.title = payload["expected_title"]
        return {"persisted_readback": True, "observed_title": payload["expected_title"]}


def git(path: Path, *arguments: str) -> str:
    """Run real Git against only pytest-owned repository roots."""
    return subprocess.check_output(["git", "-C", str(path), *arguments], text=True, encoding="utf-8").strip()


@pytest.fixture
def cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Cleanup:
    """Create a real merged disposable task; substitute only external GitHub/controller boundaries."""
    root = tmp_path / "configured"
    root.mkdir()
    primary = tmp_path / "primary"
    primary.mkdir()
    git(primary, "init", "--initial-branch=main")
    git(primary, "config", "user.name", "Cleanup Test")
    git(primary, "config", "user.email", "cleanup@example.invalid")
    (primary / "source.txt").write_text("base", encoding="utf-8")
    git(primary, "add", ".")
    git(primary, "commit", "-m", "base")
    target = root / "task"
    git(primary, "worktree", "add", "-b", "enhancement/760-test", str(target))
    (target / "source.txt").write_text("change", encoding="utf-8")
    git(target, "commit", "-am", "task")
    head = git(target, "rev-parse", "HEAD")
    git(primary, "merge", "--squash", "enhancement/760-test")
    git(primary, "commit", "-m", "merged")
    merge = git(primary, "rev-parse", "HEAD")
    bare = tmp_path / "remote.git"
    git(primary, "clone", "--bare", str(primary), str(bare))
    git(primary, "remote", "add", "origin", str(bare))
    handoff = {"schema": 1, "primary_checkout": str(primary), "worktree": str(target),
               "worktree_identity": [target.stat().st_dev, target.stat().st_ino],
               "branch": "enhancement/760-test", "head": head, "merge": merge,
               "repository": "example/Atlaso", "pr": 761, "issues": [760],
               "resources": [], "task_id": "test-task", "description": "Cleanup",
               "task_title": "Cleanup · Issue #760 · PR #761"}
    handoff_path = root / "handoff.json"
    handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
    config = tmp_path / "config.toml"
    config.write_text("[desktop]\ngit-worktree-root = " + json.dumps(str(root)), encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    monkeypatch.chdir(primary)
    instance = Cleanup(handoff_path, root / "evidence", config, True, Bridge())
    command = instance.command

    def external(arguments: list[str], **kwargs: object) -> str:
        """Retain real Git mutations and return deterministic remote-service evidence."""
        if arguments[:4] == ["git", "remote", "get-url", "origin"]:
            return "https://github.com/example/Atlaso.git"
        if arguments == ["git", "remote", "get-url", "--push", "--all", "origin"]:
            return "https://github.com/example/Atlaso.git"
        if arguments[:3] == ["gh", "pr", "view"]:
            return json.dumps({"closingIssuesReferences": [{"number": 760}]})
        return command(arguments, **kwargs)

    def api(endpoint: str) -> object:
        """Supply exact PR/issue/main/workflow evidence independently of fixture handoff reads."""
        if endpoint == "pulls/761":
            return {"merged": True, "merge_commit_sha": merge, "head": {"sha": head,
                    "ref": "enhancement/760-test", "repo": {"full_name": "example/Atlaso"}}, "base": {"ref": "main"}}
        if endpoint == "issues/760":
            return {"state": "closed", "labels": [{"name": "enhancement"}]}
        if endpoint == "git/ref/heads/main":
            return {"object": {"sha": merge}}
        if endpoint.startswith("compare/"):
            return {"status": "identical"}
        assert endpoint == "actions/runs/1"
        return {"id": 1, "run_attempt": 1, "workflow_id": 10, "head_sha": merge, "event": "push",
                "repository": {"full_name": "example/Atlaso"}, "status": "completed", "conclusion": "success"}

    monkeypatch.setattr(instance, "command", external)
    monkeypatch.setattr(instance, "api", api)
    return instance


def test_eligible_cleanup_and_title_only_retry(cleanup: Cleanup) -> None:
    """Real leased ref deletion and Git worktree removal survive a complete retry."""
    result = cleanup.run()
    assert result["status"] == "complete"
    assert result["gates"].index("validation_resources_released") < result["gates"].index("remote_branch_absent")
    assert result["gates"].index("remote_branch_absent") < result["gates"].index("worktree_removed")
    assert not cleanup.target.exists()
    assert not cleanup.git("ls-remote", "--refs", "origin", "refs/heads/" + cleanup.branch)
    assert not cleanup.git("for-each-ref", "--format=%(objectname)", "refs/heads/" + cleanup.branch)
    assert list(cleanup.evidence.glob("*.json"))
    assert cleanup.run()["status"] == "complete"


@pytest.mark.parametrize("reappeared", ["remote", "resource", "none"])
def test_fresh_process_retry_recovers_completed_gates(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, reappeared: str) -> None:
    """A newly constructed CLI instance cannot repeat deletion after a failed title transition."""
    cleanup.handoff["resources"] = [resource_identity(cleanup, "retry-resource")]
    cleanup.handoff_path.write_text(json.dumps(cleanup.handoff), encoding="utf-8")
    cleanup.digest = hashlib.sha256(cleanup.handoff_path.read_bytes()).hexdigest()
    original = cleanup.controller.call

    def fail_title(operation: str, payload: dict) -> dict:
        """Stop after durable deletion gates but before the supported title operation."""
        if operation == "task.title":
            raise Refusal("title unavailable")
        return original(operation, payload)

    monkeypatch.setattr(cleanup.controller, "call", fail_title)
    with pytest.raises(Refusal, match="title unavailable"):
        cleanup.run()
    if reappeared == "remote":
        cleanup.git("push", "origin", f"{cleanup.head}:refs/heads/{cleanup.branch}")
    elif reappeared == "resource":
        cleanup.controller.resource_absent = False
    monkeypatch.setattr(cleanup.controller, "call", original)
    retry = Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    monkeypatch.setattr(retry, "command", cleanup.command)
    monkeypatch.setattr(retry, "api", cleanup.api)
    assert "worktree_removed" in retry.gates
    releases = cleanup.controller.calls.count("resource.release")
    if reappeared == "none":
        assert retry.run()["status"] == "complete"
    else:
        with pytest.raises(Refusal, match="reappeared|Aggregate resource absence"):
            retry.run()
    assert cleanup.controller.calls.count("resource.release") == releases


def test_durable_directory_publishes_every_new_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Nested evidence roots publish each directory entry before any child can be journaled."""
    from scripts import completed_task_files

    original = completed_task_files.publish_durable_file
    published = []

    def publish(source: Path, destination: Path) -> None:
        """Record native durable directory publication and verify parent-first ordering."""
        assert source.is_dir() and source.parent == destination.parent
        original(source, destination)
        published.append(destination)

    monkeypatch.setattr(completed_task_files, "publish_durable_file", publish)
    target = tmp_path / "new-parent" / "evidence"
    ensure_durable_directory(target)
    assert published == [target.parent, target]
    assert target.is_dir()
    ensure_durable_directory(target)
    assert len(published) == 2


def test_directory_publication_failure_blocks_cleanup(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Failure to persist the evidence root cannot be followed by resource or ref mutation."""
    from scripts import completed_task_files

    def fail_publication(source: Path, destination: Path) -> None:
        """Leave the staged directory for independent reconciliation."""
        raise FileRefusal("directory publication failed")

    monkeypatch.setattr(completed_task_files, "publish_durable_file", fail_publication)
    with pytest.raises(FileRefusal, match="directory publication failed"):
        cleanup.run()
    assert not cleanup.gates
    assert "resource.release" not in cleanup.controller.calls
    assert cleanup.target.exists()
    assert cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")
    with pytest.raises(FileRefusal, match="Pending evidence-directory"):
        cleanup.run()


def test_failed_journal_write_does_not_publish_gate(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """An fsync failure leaves an explicit incomplete journal and no claimed completed gate."""
    original = os.fsync

    def failed_fsync(descriptor: int) -> None:
        """Model a storage failure while persisting transition evidence."""
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            original(descriptor)
            return
        raise OSError("fixture fsync failure")

    monkeypatch.setattr(os, "fsync", failed_fsync)
    with pytest.raises(OSError, match="fixture fsync failure"):
        cleanup.record("validation_resources_released")
    assert "validation_resources_released" not in cleanup.gates
    with pytest.raises(Refusal, match="incomplete journal write"):
        Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)


def test_visible_journal_requires_recovery_flush(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """A visible rename with a failed directory flush cannot become a trusted gate on restart."""
    from scripts import completed_task_cleanup

    original_sync = completed_task_cleanup.sync_directory

    def failed_publication(source: Path, destination: Path) -> None:
        """Model POSIX rename succeeding before its parent-directory fsync fails."""
        source.rename(destination)
        raise OSError("fixture directory flush failure")

    monkeypatch.setattr(completed_task_cleanup, "publish_durable_file", failed_publication)
    with pytest.raises(OSError, match="directory flush failure"):
        cleanup.record("validation_resources_released")
    assert not cleanup.gates
    assert list(cleanup.evidence.glob("*.json"))
    flushed = []

    def failed_recovery(path: Path) -> None:
        """Refuse to trust the visible entry while storage still rejects durability."""
        flushed.append(path)
        raise OSError("fixture recovery flush failure")

    monkeypatch.setattr(completed_task_cleanup, "sync_directory", failed_recovery)
    with pytest.raises(OSError, match="recovery flush failure"):
        Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    assert flushed == [cleanup.evidence]
    assert cleanup.target.exists() and not cleanup.controller.calls
    monkeypatch.setattr(completed_task_cleanup, "sync_directory", original_sync)
    retry = Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    assert retry.gates == ["validation_resources_released"]


def test_failed_durable_publication_does_not_publish_gate(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failure publishing the directory entry cannot advance reported cleanup gates."""
    def failed_publication(source: Path, destination: Path) -> None:
        """Model the durable rename failing after file contents have been flushed."""
        raise FileRefusal("fixture durable publication failure")

    monkeypatch.setattr("scripts.completed_task_cleanup.publish_durable_file", failed_publication)
    with pytest.raises(FileRefusal, match="durable publication failure"):
        cleanup.record("remote_branch_absent")
    assert "remote_branch_absent" not in cleanup.gates
    assert list(cleanup.evidence.glob("*.pending"))


def test_durable_file_publication_preserves_existing_destination(tmp_path: Path) -> None:
    """The native publication path moves a staged file without replacing existing evidence."""
    source, destination = tmp_path / "staged", tmp_path / "published"
    source.write_bytes(b"evidence")
    publish_durable_file(source, destination)
    assert not source.exists() and destination.read_bytes() == b"evidence"
    source.write_bytes(b"different")
    with pytest.raises(FileRefusal, match="new name"):
        publish_durable_file(source, destination)
    assert destination.read_bytes() == b"evidence"


@pytest.mark.parametrize("urls", ["https://github.com/other/Atlaso.git", "https://github.com/example/Atlaso.git\nhttps://github.com/other/Atlaso.git"])
def test_separate_push_destination_blocks_cleanup(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, urls: str) -> None:
    """A matching fetch URL does not authorize deletion at a fork or additional push URL."""
    original = cleanup.command

    def redirected(arguments: list[str], **kwargs: object) -> str:
        """Keep the verified fetch remote while substituting effective push destinations."""
        if arguments == ["git", "remote", "get-url", "--push", "--all", "origin"]:
            return urls
        return original(arguments, **kwargs)

    monkeypatch.setattr(cleanup, "command", redirected)
    with pytest.raises(Refusal, match="push URLs differ"):
        cleanup.run()
    assert cleanup.target.exists()
    assert not cleanup.evidence.exists()


@pytest.mark.skipif(os.name != "nt", reason="Win32 path normalization")
@pytest.mark.parametrize("suffix", [".", " "])
def test_win32_alias_removal_scope_is_rejected(cleanup: Cleanup, suffix: str) -> None:
    """Trailing dots/spaces cannot disguise a protected checkout from lexical containment."""
    resource = resource_identity(cleanup, "alias-vm")
    with pytest.raises(Refusal, match="Win32-normalized"):
        cleanup.removal_scopes(resource, {"removal_scopes": [str(cleanup.target) + suffix]})
    assert cleanup.target.exists()


def test_cumulative_evidence_uses_recoverable_references(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Multiple accepted payloads never inflate the cumulative journal beyond its restore limit."""
    from scripts import completed_task_cleanup as command

    monkeypatch.setattr(command, "MAX_EVIDENCE_BYTES", 6000)
    cleanup.resource_evidence = [{"snapshot": "a" * 4000}, {"snapshot": "b" * 4000}]
    cleanup.record("cleanup_prepared")
    records = list(cleanup.evidence.glob("*.json"))
    assert records and all(path.stat().st_size <= 6000 for path in records)
    assert len(list(cleanup.evidence.glob("*.evidence"))) == 2
    retry = Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    assert retry.gates == ["cleanup_prepared"]


def test_remote_main_disappearing_after_release_is_refused(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty successful ls-remote result preserves structured failure after earlier gates."""
    original = cleanup.command

    def vanished(arguments: list[str], **kwargs: object) -> str:
        """Remove main's advertised ref only after the aggregate resource gate."""
        if arguments == ["git", "ls-remote", "--refs", "origin", "refs/heads/main"] \
                and "validation_resources_released" in cleanup.gates:
            return ""
        return original(arguments, **kwargs)

    monkeypatch.setattr(cleanup, "command", vanished)
    with pytest.raises(Refusal, match="Main changed"):
        cleanup.run()
    assert "validation_resources_released" in cleanup.gates
    assert cleanup.target.exists()


def test_handoff_outside_permitted_root_is_refused(cleanup: Cleanup) -> None:
    """An ordinary external handoff does not establish permitted durable evidence storage."""
    outside = cleanup.root.parent / "external-handoff.json"
    outside.write_bytes(cleanup.handoff_path.read_bytes())
    with pytest.raises(Refusal, match="handoff outside the target, beneath the configured root"):
        Cleanup(outside, cleanup.evidence, cleanup.config, True, cleanup.controller)
    assert not cleanup.controller.calls
    assert not cleanup.evidence.exists()


def test_github_reads_ignore_environment_host(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """API and PR reads name github.com even when the CLI default points to enterprise."""
    monkeypatch.setenv("GH_HOST", "enterprise.example.invalid")
    original = cleanup.command
    calls = []

    def capture(arguments: list[str], **kwargs: object) -> str:
        """Capture host selection without sending fixture traffic to a remote service."""
        if arguments[:2] == ["gh", "api"]:
            calls.append(arguments)
            return "{}"
        if arguments[:3] == ["gh", "pr", "view"]:
            calls.append(arguments)
        return original(arguments, **kwargs)

    monkeypatch.setattr(cleanup, "command", capture)
    Cleanup.api(cleanup, "pulls/761")
    cleanup.execute = False
    cleanup.run()
    assert calls[0] == ["gh", "api", "--hostname", "github.com", "repos/example/Atlaso/pulls/761"]
    assert any(arguments[arguments.index("--repo") + 1] == "github.com/example/Atlaso"
               for arguments in calls if "--repo" in arguments)


@pytest.mark.parametrize("kind", ["artifact", "generated_tree"])
def test_scope_cannot_remove_another_inventoried_resource(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """An artifact cleanup cannot consume a VM before its own provider cleanup runs."""
    artifact = resource_identity(cleanup, "artifact", kind)
    if kind == "generated_tree":
        artifact["root_identity"] = [1, 2, 3]
    vm = resource_identity(cleanup, "nested-vm")
    artifact["path"] = str(cleanup.root / "artifacts")
    vm["path"] = str(cleanup.root / "artifacts" / "vm" / "guest.vmx")
    cleanup.handoff["resources"] = [artifact, vm]
    original = cleanup.controller.call

    def scopes(operation: str, payload: dict) -> dict:
        """Report the artifact tool's complete recursive removal root."""
        result = original(operation, payload)
        if operation == "resource.inspect":
            result["removal_scopes"] = [artifact["path"]]
        return result

    monkeypatch.setattr(cleanup.controller, "call", scopes)
    with pytest.raises(Refusal, match="another resource"):
        cleanup.run()
    assert "resource.release" not in cleanup.controller.calls
    assert cleanup.target.exists()


def test_external_ownership_manifest_is_refused(cleanup: Cleanup) -> None:
    """A matching hash outside the permitted durable root cannot authorize cleanup."""
    resource = resource_identity(cleanup, "external-manifest")
    outside = cleanup.root.parent / "external-owner.json"
    outside.write_bytes(Path(resource["ownership_manifest"]["path"]).read_bytes())
    resource["ownership_manifest"]["path"] = str(outside)
    cleanup.handoff["resources"] = [resource]
    with pytest.raises(Refusal, match="Ownership manifest must be beneath"):
        cleanup.resources()
    assert "resource.release" not in cleanup.controller.calls
    assert not cleanup.evidence.exists()


@pytest.mark.parametrize("dangling", [False, True])
def test_symbolic_task_ref_preserves_backup(cleanup: Cleanup, dangling: bool) -> None:
    """A task alias must never delete an unrelated branch or count as an absent ref."""
    cleanup.git("worktree", "remove", str(cleanup.target))
    if not dangling:
        cleanup.git("update-ref", "refs/heads/backup", cleanup.head)
    cleanup.git("symbolic-ref", f"refs/heads/{cleanup.branch}", "refs/heads/backup")
    with pytest.raises(Refusal, match="Symbolic task ref"):
        cleanup.run()
    assert cleanup.git("symbolic-ref", f"refs/heads/{cleanup.branch}") == "refs/heads/backup"
    if not dangling:
        assert cleanup.git("rev-parse", "refs/heads/backup") == cleanup.head
    assert cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_index_hidden_edits_preserved(cleanup: Cleanup, flag: str) -> None:
    """Git status alone cannot authorize removal when index flags hide user content."""
    cleanup.git("-C", str(cleanup.target), "update-index", flag, "source.txt")
    source = cleanup.target / "source.txt"
    source.write_text("hidden user edit", encoding="utf-8")
    assert not cleanup.git("-C", str(cleanup.target), "status", "--porcelain")
    with pytest.raises(Refusal, match="Index assume-unchanged"):
        cleanup.run()
    assert source.read_text(encoding="utf-8") == "hidden user edit"
    assert cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")


@pytest.mark.parametrize("locator", ["provider", "auxiliary"])
def test_complete_scope_inventory_precedes_release(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, locator: str) -> None:
    """Provider-only and auxiliary filesystem roots cannot be consumed by an earlier tool."""
    first = resource_identity(cleanup, "first")
    second = resource_identity(cleanup, "second")
    if locator == "auxiliary":
        second["path"] = str(cleanup.root / "separate-locator")
    cleanup.handoff["resources"] = [first, second]
    original = cleanup.controller.call

    def inspect(operation: str, payload: dict) -> dict:
        """Expose overlapping tool scopes not present in the handoff's locators."""
        result = original(operation, payload)
        if operation == "resource.inspect":
            suffix = "shared" if payload["resource"]["id"] == "first" else "shared/auxiliary"
            result["removal_scopes"] = [str(cleanup.root / suffix)]
        return result

    monkeypatch.setattr(cleanup.controller, "call", inspect)
    with pytest.raises(Refusal, match="scopes intersect"):
        cleanup.resources()
    assert "resource.release" not in cleanup.controller.calls


def test_unavailable_title_records_terminal_gate(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """The capability exception retains evidence and the canonical terminal sequence."""
    original = cleanup.controller.call

    def unavailable(operation: str, payload: dict) -> dict:
        """Return explicit supported-runtime capability evidence at the title stage."""
        if operation == "task.title":
            return {"capability": "unavailable", "capability_evidence": "supported tool inventory has no title controls"}
        return original(operation, payload)

    monkeypatch.setattr(cleanup.controller, "call", unavailable)
    assert cleanup.run()["gates"][-1] == "task_title_done"
    assert any("capability_unavailable" in path.read_text() for path in cleanup.evidence.glob("*.evidence"))


@pytest.mark.parametrize("kind", ["oversized", "directory"])
def test_invalid_handoff_rejected_before_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """Malformed input is refused without reading or opening the input payload."""
    path = tmp_path / "handoff"
    if kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"x" * 262145)

    def forbidden_open(*args: object, **kwargs: object) -> None:
        """Any attempt to open the rejected payload makes the regression fail."""
        pytest.fail("invalid input was opened")

    monkeypatch.setattr(Path, "open", forbidden_open)
    with pytest.raises(Refusal, match="bounded regular"):
        read_handoff(path)


def test_preview_does_not_mutate(cleanup: Cleanup) -> None:
    """Preview performs no fetch, journal write, resource release, ref mutation, or rename."""
    cleanup.execute = False
    before = cleanup.git("show-ref")
    assert cleanup.run()["status"] == "preview"
    assert cleanup.git("show-ref") == before
    assert cleanup.target.is_dir()
    assert not cleanup.evidence.exists()
    assert cleanup.controller.calls == ["task.inspect"]


@pytest.mark.parametrize("field", ["idle", "unpinned", "holds_clear", "exclusive_ownership_verified",
                                  "inventory_verified", "post_merge_complete", "downstream_clear"])
def test_live_task_refusals_preserve_everything(cleanup: Cleanup, field: str) -> None:
    """Activity, pinning, holds, ownership, and unfinished downstream work fail before deletion."""
    cleanup.controller.block = field
    with pytest.raises(Refusal, match=field):
        cleanup.run()
    assert cleanup.target.exists()
    assert not cleanup.evidence.exists()


@pytest.mark.parametrize("mutation", ["dirty", "untracked", "locked", "remote", "local", "identity"])
def test_changed_git_or_filesystem_state_blocks(cleanup: Cleanup, mutation: str) -> None:
    """Concurrent ownership and content changes block all destructive transitions."""
    if mutation == "dirty":
        (cleanup.target / "source.txt").write_text("user edits", encoding="utf-8")
    elif mutation == "untracked":
        (cleanup.target / "notes.txt").write_text("user notes", encoding="utf-8")
    elif mutation == "locked":
        cleanup.git("worktree", "lock", str(cleanup.target))
    elif mutation == "remote":
        cleanup.git("push", "origin", f"{cleanup.merge}:refs/heads/{cleanup.branch}", "--force")
    elif mutation == "local":
        cleanup.git("update-ref", "refs/heads/" + cleanup.branch, cleanup.merge)
    else:
        cleanup.handoff["worktree_identity"] = [0, 0]
    with pytest.raises(Refusal):
        cleanup.run()
    assert cleanup.target.exists()


def resource_identity(cleanup: Cleanup, identity: str, kind: str = "vm") -> dict:
    """Bind test-owned resources to durable fixture manifest bytes and exact provider identity."""
    manifest = cleanup.root / f"{identity}-owner.json"
    manifest.write_text(json.dumps({"task_id": "test-task", "repository": cleanup.repository,
                                    "pr": cleanup.handoff["pr"], "provider_id": identity}), encoding="utf-8")
    return {"id": identity, "kind": kind, "task_id": "test-task", "source_commit": cleanup.head,
            "repository": cleanup.repository, "pr": cleanup.handoff["pr"], "provider_id": identity,
            "cleanup_tool": "fixture-owning-tool", "ownership_manifest": {
                "path": str(manifest), "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}}


def test_incomplete_resource_release_blocks_ref_deletion(cleanup: Cleanup) -> None:
    """A failed owning tool leaves the exact remote/local branches and worktree intact."""
    cleanup.handoff["resources"] = [resource_identity(cleanup, "fixture-vm")]
    cleanup.controller.release_ok = False
    with pytest.raises(Refusal, match="Owning tool failed"):
        cleanup.run()
    assert cleanup.target.exists()
    assert cleanup.git("ls-remote", "--refs", "origin", "refs/heads/" + cleanup.branch)
    assert "task.title" not in cleanup.controller.calls


@pytest.mark.parametrize("protected", ["target", "repo", "root", "evidence"])
def test_owning_scope_cannot_remove_checkout_or_evidence(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, protected: str) -> None:
    """A VMX locator cannot hide an owning tool's broader destructive directory."""
    cleanup.handoff["resources"] = [resource_identity(cleanup, "broad-vm")]
    original = cleanup.controller.call

    def broad_scope(operation: str, payload: dict) -> dict:
        """Report the actual owning-tool scope, independently of the resource locator."""
        result = original(operation, payload)
        if operation == "resource.inspect":
            result["removal_scopes"] = [str(getattr(cleanup, protected))]
        return result

    monkeypatch.setattr(cleanup.controller, "call", broad_scope)
    with pytest.raises(Refusal, match="[Rr]emoval scope"):
        cleanup.run()
    assert "resource.release" not in cleanup.controller.calls
    assert cleanup.target.exists() and cleanup.repo.exists()


def test_unrelated_manual_workflow_does_not_block_cleanup(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the controller's applicable run identities are checked, not same-SHA manual runs."""
    original = cleanup.api

    def unrelated(endpoint: str) -> object:
        """A failed manual run sharing the commit is not part of the applicable chain."""
        if endpoint.startswith("actions/runs?"):
            return {"total_count": 1, "workflow_runs": [{"status": "completed", "conclusion": "failure"}]}
        return original(endpoint)

    monkeypatch.setattr(cleanup, "api", unrelated)
    assert cleanup.run()["status"] == "complete"


@pytest.mark.parametrize("field,value", [("conclusion", "failure"), ("run_attempt", 2), ("workflow_id", 11)])
def test_applicable_run_must_match_successful_identity(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, field: str, value: object) -> None:
    """A changed attempt, wrong workflow, or failed applicable run cannot pass cleanup."""
    original = cleanup.api

    def changed(endpoint: str) -> object:
        """Substitute one invalid field in the direct GitHub run readback."""
        result = original(endpoint)
        if endpoint == "actions/runs/1":
            result[field] = value
        return result

    monkeypatch.setattr(cleanup, "api", changed)
    with pytest.raises(Refusal, match="Applicable post-merge run"):
        cleanup.run()
    assert not cleanup.evidence.exists()


def test_resume_after_worktree_removed_before_local_ref(cleanup: Cleanup) -> None:
    """Interrupted cleanup can finish only the exact unreferenced matching local ref."""
    cleanup.git("worktree", "remove", str(cleanup.target))
    assert cleanup.run()["status"] == "complete"
    assert not cleanup.git("for-each-ref", "--format=%(objectname)", "refs/heads/" + cleanup.branch)


@pytest.mark.parametrize("value", ['"invalid"', "7", "true", "[]"])
def test_nontable_desktop_config_is_refused(cleanup: Cleanup, value: str) -> None:
    """Syntactically valid wrong-type configuration returns a repairable refusal."""
    cleanup.config.write_text(f"desktop = {value}\n", encoding="utf-8")
    with pytest.raises(Refusal, match="desktop must be a TOML table"):
        configured_root(cleanup.config)


def test_late_nontable_config_preserves_gates(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """A config rewrite after remote deletion leaves the worktree and completed gate available for retry."""
    original = cleanup.record

    def rewrite(gate: str) -> None:
        """Change the active config only after the remote-absence gate is durable."""
        original(gate)
        if gate == "remote_branch_absent":
            cleanup.config.write_text('desktop = "invalid"\n', encoding="utf-8")

    monkeypatch.setattr(cleanup, "record", rewrite)
    with pytest.raises(Refusal, match="desktop must be a TOML table"):
        cleanup.run()
    assert "remote_branch_absent" in cleanup.gates
    assert "worktree_removed" not in cleanup.gates
    assert cleanup.target.is_dir()
    assert not cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")


@pytest.mark.parametrize("reappeared", ["remote", "local", "worktree", "resource"])
def test_title_response_rechecks_absence(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, reappeared: str) -> None:
    """Reappearance during the supported title call prevents terminal completion."""
    if reappeared == "resource":
        cleanup.handoff["resources"] = [resource_identity(cleanup, "reappearing")]
        cleanup.controller.resource_absent = True
    original = cleanup.controller.call

    def changed(operation: str, payload: dict) -> dict:
        """Return successful title readback after recreating a previously absent task object."""
        result = original(operation, payload)
        if operation == "task.title":
            if reappeared == "remote":
                cleanup.git("push", "origin", f"{cleanup.head}:refs/heads/{cleanup.branch}")
            elif reappeared == "local":
                cleanup.git("update-ref", f"refs/heads/{cleanup.branch}", cleanup.head)
            elif reappeared == "worktree":
                cleanup.target.mkdir()
            else:
                cleanup.controller.resource_absent = False
        return result

    monkeypatch.setattr(cleanup.controller, "call", changed)
    with pytest.raises(Refusal):
        cleanup.run()
    assert "task_title_done" not in cleanup.gates
    assert "task_title_readback_verified" in cleanup.gates
    if reappeared == "remote":
        assert cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")
    elif reappeared == "local":
        assert cleanup.git("rev-parse", f"refs/heads/{cleanup.branch}") == cleanup.head
    elif reappeared == "worktree":
        assert cleanup.target.exists()


@pytest.mark.parametrize("kind", ["directory", "oversized"])
def test_config_requires_bounded_regular_file(cleanup: Cleanup, kind: str) -> None:
    """Active configuration cannot block on a special file or consume an unbounded payload."""
    if kind == "directory":
        cleanup.config.unlink()
        cleanup.config.mkdir()
    else:
        cleanup.config.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(FileRefusal, match="bounded regular single-link"):
        configured_root(cleanup.config)


def test_title_retry_after_task_history_pruned(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Durable ancestry gates let title-only retries survive actual Git object pruning."""
    cleanup.handoff["resources"] = [resource_identity(cleanup, "pruned-resource")]
    cleanup.handoff_path.write_text(json.dumps(cleanup.handoff), encoding="utf-8")
    cleanup.digest = hashlib.sha256(cleanup.handoff_path.read_bytes()).hexdigest()
    original = cleanup.controller.call

    def failed_title(operation: str, payload: dict) -> dict:
        """Interrupt after refs and worktree are durably absent."""
        if operation == "task.title":
            raise Refusal("title unavailable")
        return original(operation, payload)

    monkeypatch.setattr(cleanup.controller, "call", failed_title)
    with pytest.raises(Refusal, match="title unavailable"):
        cleanup.run()
    assert "resource_ancestry_verified:pruned-resource" in cleanup.gates
    cleanup.git("reflog", "expire", "--expire=now", "--all")
    cleanup.git("gc", "--prune=now")
    cleanup.command(["git", "cat-file", "-e", cleanup.head], allowed=(1, 128))
    monkeypatch.setattr(cleanup.controller, "call", original)
    retry = Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    monkeypatch.setattr(retry, "command", cleanup.command)
    monkeypatch.setattr(retry, "api", cleanup.api)
    assert retry.run()["status"] == "complete"


@pytest.mark.parametrize("name", ["tâche-日本語", pytest.param("task\nline", marks=pytest.mark.skipif(os.name == "nt", reason="Windows forbids newline paths"))])
def test_verbatim_worktree_paths(cleanup: Cleanup, name: str) -> None:
    """Git's NUL porcelain preserves Unicode and newline paths through complete cleanup."""
    target = cleanup.root / name
    cleanup.git("worktree", "move", str(cleanup.target), str(target))
    cleanup.target = target
    cleanup.handoff["worktree"] = str(target)
    cleanup.handoff_path.write_text(json.dumps(cleanup.handoff), encoding="utf-8")
    cleanup.digest = hashlib.sha256(cleanup.handoff_path.read_bytes()).hexdigest()
    cleanup.git("config", "core.quotePath", "true")
    assert any(item["worktree"] == target.as_posix() for item in cleanup.worktrees())
    assert cleanup.run()["status"] == "complete"
    assert not target.exists()


@pytest.mark.parametrize("alternate", [False, True])
def test_exclusive_cleanup_lock_between_processes(cleanup: Cleanup, alternate: bool) -> None:
    """A second interpreter cannot enter cleanup even with differently serialized handoff bytes."""
    handoff = cleanup.handoff_path
    if alternate:
        handoff = cleanup.root / "alternate-handoff.json"
        handoff.write_text(json.dumps(dict(reversed(list(cleanup.handoff.items()))), indent=4), encoding="utf-8")
        assert hashlib.sha256(handoff.read_bytes()).hexdigest() != cleanup.digest
    code = """import sys
from pathlib import Path
from scripts.completed_task_cleanup import Cleanup, Controller
from scripts.completed_task_files import FileRefusal
try:
    cleanup = Cleanup(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), True, Controller())
    cleanup.reconcile = lambda: print('acquired')
    cleanup.run()
except FileRefusal:
    print('blocked')
"""
    arguments = [sys.executable, "-B", "-c", code, str(handoff), str(cleanup.root / "alternate-evidence"), str(cleanup.config)]
    environment = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    with cleanup_lock(cleanup.root, cleanup.lock_digest):
        result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=15, check=True)
        assert result.stdout.strip() == "blocked"
    result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=15, check=True)
    assert result.stdout.strip() == "acquired"


def test_stale_instance_refreshes_journal_under_lock(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """An instance created before another completes recovers its gates after taking ownership."""
    cleanup.handoff["resources"] = [resource_identity(cleanup, "serialized-resource")]
    cleanup.handoff_path.write_text(json.dumps(cleanup.handoff), encoding="utf-8")
    cleanup.digest = hashlib.sha256(cleanup.handoff_path.read_bytes()).hexdigest()
    stale = Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    monkeypatch.setattr(stale, "command", cleanup.command)
    monkeypatch.setattr(stale, "api", cleanup.api)
    assert not stale.gates
    assert cleanup.run()["status"] == "complete"
    releases = cleanup.controller.calls.count("resource.release")
    assert stale.run()["status"] == "complete"
    assert cleanup.controller.calls.count("resource.release") == releases


@pytest.mark.parametrize("change", ["holds_clear", "idle", "downstream_clear", "issue", "workflow"])
def test_title_response_rechecks_full_eligibility(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    """Task or GitHub changes during title readback cannot receive the terminal gate."""
    original_call, original_api = cleanup.controller.call, cleanup.api
    after_title = False

    def title(operation: str, payload: dict) -> dict:
        """Withdraw eligibility only after the successful title response."""
        nonlocal after_title
        result = original_call(operation, payload)
        if operation == "task.title":
            after_title = True
            if change not in {"issue", "workflow"}:
                cleanup.controller.block = change
        return result

    def changed_api(endpoint: str) -> object:
        """Model independently observed issue/workflow changes during title mutation."""
        result = original_api(endpoint)
        if after_title and isinstance(result, dict):
            if change == "issue" and endpoint.startswith("issues/"):
                result["state"] = "open"
            if change == "workflow" and endpoint.startswith("actions/runs/"):
                result["status"] = "in_progress"
        return result

    monkeypatch.setattr(cleanup.controller, "call", title)
    monkeypatch.setattr(cleanup, "api", changed_api)
    with pytest.raises(Refusal):
        cleanup.run()
    assert "task_title_readback_verified" in cleanup.gates
    assert "task_title_done" not in cleanup.gates


@pytest.mark.parametrize("branch", [None, 42, True, [], {}])
def test_branch_type_refused(cleanup: Cleanup, branch: object) -> None:
    """Malformed branch values receive a structured refusal before string operations."""
    path = cleanup.root / "invalid-branch.json"
    path.write_text(json.dumps({**cleanup.handoff, "branch": branch}), encoding="utf-8")
    with pytest.raises(Refusal, match="Branch must be a string"):
        Cleanup(path, cleanup.evidence, cleanup.config, True, cleanup.controller)


@pytest.mark.skipif(os.name != "nt", reason="Windows generated-tree contract")
def test_nested_recovery_root_preserved(cleanup: Cleanup) -> None:
    """Recovery directories anywhere under generated output require their own release path."""
    path = cleanup.target / "cache"
    recovery = path / "nested" / ".atlaso-local"
    recovery.mkdir(parents=True)
    marker = recovery / "recovery.json"
    marker.write_text("fixture recovery state", encoding="utf-8")
    (cleanup.repo / ".git/info/exclude").write_text("cache/\n", encoding="utf-8")
    identity = WindowsFiles().snapshot(path)["."]["identity"]
    cleanup.handoff["resources"] = [{**resource_identity(cleanup, "recovery-cache", "generated_tree"),
                                     "path": str(path), "root_identity": identity}]
    with pytest.raises(Refusal, match="Nested credential/recovery"):
        cleanup.run()
    assert marker.read_text() == "fixture recovery state"
    assert "resource_release_prepared:recovery-cache" not in cleanup.gates


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell entry point")
def test_wrapper_ignores_external_python_imports(cleanup: Cleanup) -> None:
    """Inherited startup hooks and a regular scripts package cannot replace the checked-in command."""
    external = cleanup.root / "external-python"
    package = external / "scripts"
    package.mkdir(parents=True)
    marker = external / "executed.txt"
    injected = f"from pathlib import Path; Path({str(marker)!r}).write_text('external')\n"
    (external / "sitecustomize.py").write_text(injected, encoding="utf-8")
    (package / "__init__.py").write_text(injected, encoding="utf-8")
    (package / "completed_task_cleanup.py").write_text(injected, encoding="utf-8")
    wrapper = Path(__file__).resolve().parents[1] / "scripts" / "cleanup-completed-task.ps1"
    result = subprocess.run(["pwsh", "-NoProfile", "-File", str(wrapper), "-Handoff", str(cleanup.root / "missing.json"),
                             "-Evidence", str(cleanup.evidence), "-Config", str(cleanup.config)],
                            env={**os.environ, "PYTHONPATH": str(external)}, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert json.loads(result.stdout)["status"] == "refused"
    assert not marker.exists()


def test_config_and_primary_protection(cleanup: Cleanup) -> None:
    """Missing configuration and primary-checkout targets never gain deletion authority."""
    cleanup.config.write_text("[desktop]\n", encoding="utf-8")
    with pytest.raises(Refusal, match="missing"):
        configured_root(cleanup.config)
    with pytest.raises(Refusal):
        ordinary(Path("relative"))


@pytest.mark.skipif(os.name != "nt", reason="Windows no-follow handle contract")
def test_generated_tree_handles_delete_only_snapshot(tmp_path: Path) -> None:
    """An ordinary output tree is removed through exact handles, while replacement is rejected."""
    root = tmp_path / "output"
    root.mkdir()
    child = root / "cache"
    child.mkdir()
    (child / "result.txt").write_text("output", encoding="utf-8")
    files = WindowsFiles()
    snapshot = files.snapshot(root)
    (child / "new.txt").write_text("concurrent output", encoding="utf-8")
    with pytest.raises(FileRefusal, match="changed"):
        files.remove(root, snapshot)
    assert root.exists()
    files.remove(root, files.snapshot(root))
    assert not root.exists()


def test_primary_and_outside_root_are_refused(cleanup: Cleanup) -> None:
    """Constructor rejects primary and out-of-root targets before invoking any controller."""
    handoff_path = cleanup.root / "bad-handoff.json"
    for target in (cleanup.repo, cleanup.root.parent / "unowned"):
        handoff_path.write_text(json.dumps({**cleanup.handoff, "worktree": str(target)}), encoding="utf-8")
        with pytest.raises(Refusal):
            Cleanup(handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    assert not cleanup.controller.calls


@pytest.mark.parametrize("problem", ["missing", "unreadable", "unsafe"])
def test_primary_target_precedes_root_resolution(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, problem: str) -> None:
    """Verified primary targets receive restoration guidance even when root configuration is unusable."""
    from scripts import completed_task_cleanup

    if problem == "missing":
        cleanup.config.write_text("[desktop]\n", encoding="utf-8")
    elif problem == "unreadable":
        cleanup.config.unlink()
        cleanup.config.mkdir()
    else:
        cleanup.config.write_text("[desktop]\ngit-worktree-root = " + json.dumps(cleanup.root.anchor), encoding="utf-8")
    handoff_path = cleanup.root / "primary-handoff.json"
    handoff_path.write_text(json.dumps({**cleanup.handoff, "worktree": str(cleanup.repo)}), encoding="utf-8")

    def forbidden_root(config: Path) -> Path:
        """Root configuration must not be consulted for the independently verified primary target."""
        pytest.fail("primary target consulted worktree-root configuration")

    monkeypatch.setattr(completed_task_cleanup, "configured_root", forbidden_root)
    with pytest.raises(Refusal, match="documented restoration workflow"):
        Cleanup(handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    assert cleanup.repo.is_dir() and cleanup.target.is_dir()
    assert not cleanup.controller.calls


def test_lease_rejects_remote_change_after_check(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """The actual server-side lease protects a ref changed after all read-only observations."""
    original = cleanup.command
    changed = False

    def race(arguments: list[str], **kwargs: object) -> str:
        """Change the fixture ref immediately before its guarded deletion request."""
        nonlocal changed
        if arguments[:3] == ["git", "push", "origin"] and not changed:
            changed = True
            original(["git", "push", "origin", f"{cleanup.merge}:refs/heads/{cleanup.branch}", "--force"])
        return original(arguments, **kwargs)

    monkeypatch.setattr(cleanup, "command", race)
    with pytest.raises(Refusal, match="git failed"):
        cleanup.run()
    assert cleanup.target.exists()
    assert cleanup.git("ls-remote", "--refs", "origin", "refs/heads/" + cleanup.branch).startswith(cleanup.merge)
    assert "task.title" not in cleanup.controller.calls


def test_title_failure_leaves_resumable_evidence(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale persisted title cannot mark completion after otherwise successful cleanup."""
    original = cleanup.controller.call

    def stale(operation: str, payload: dict) -> dict:
        """Return an explicit stale title to exercise the final independent readback gate."""
        if operation == "task.title":
            return {"persisted_readback": True, "observed_title": "old title"}
        return original(operation, payload)

    monkeypatch.setattr(cleanup.controller, "call", stale)
    with pytest.raises(Refusal, match="Persisted title differs"):
        cleanup.run()
    assert not cleanup.target.exists()
    assert "task_title_done" not in cleanup.gates
    assert list(cleanup.evidence.glob("*.json"))
    monkeypatch.setattr(cleanup.controller, "call", original)
    assert cleanup.run()["status"] == "complete"


@pytest.mark.skipif(os.name != "nt", reason="Windows no-follow handle contract")
def test_generated_resource_integrates_with_real_git(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Generated caches are inventoried and released before the remote-ref transition."""
    path = cleanup.target / "cache"
    path.mkdir()
    (path / "result.txt").write_text("generated", encoding="utf-8")
    (cleanup.repo / ".git/info/exclude").write_text("cache/\n", encoding="utf-8")
    identity = WindowsFiles().snapshot(path)["."]["identity"]
    cleanup.handoff["resources"] = [{**resource_identity(cleanup, "generated-cache", "generated_tree"),
                                     "path": str(path), "root_identity": identity}]
    original = cleanup.controller.call

    def inspect(operation: str, payload: dict) -> dict:
        """Independently observe absence instead of trusting the cleanup result."""
        result = original(operation, payload)
        if operation == "resource.inspect":
            result["absent"] = not path.exists()
        return result

    monkeypatch.setattr(cleanup.controller, "call", inspect)
    assert cleanup.run()["status"] == "complete"
    assert not path.exists()
    assert cleanup.gates.index("resource_released:generated-cache") < cleanup.gates.index("remote_branch_absent")


@pytest.mark.skipif(os.name != "nt", reason="Windows no-follow handle contract")
@pytest.mark.parametrize("field", ["ownership_verified", "inactive", "retained", "supported_cleanup", "evidence_preserved"])
def test_generated_resource_fresh_eligibility(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    """A tree becoming active, retained, or unowned after initial inspection survives cleanup."""
    path = cleanup.target / "cache"
    path.mkdir()
    content = path / "result.txt"
    content.write_text("preserve", encoding="utf-8")
    (cleanup.repo / ".git/info/exclude").write_text("cache/\n", encoding="utf-8")
    identity = WindowsFiles().snapshot(path)["."]["identity"]
    cleanup.handoff["resources"] = [{**resource_identity(cleanup, "cache", "generated_tree"),
                                     "path": str(path), "root_identity": identity}]
    original = cleanup.controller.call
    inspections = 0

    def changed(operation: str, payload: dict) -> dict:
        """Withdraw one resource-specific guarantee on the final fresh readback."""
        nonlocal inspections
        result = original(operation, payload)
        if operation == "resource.inspect":
            inspections += 1
            result["absent"] = False
            if inspections > 1:
                result[field] = field == "retained"
        return result

    monkeypatch.setattr(cleanup.controller, "call", changed)
    with pytest.raises(Refusal, match="Generated resource release eligibility changed"):
        cleanup.run()
    assert content.read_text() == "preserve"
    assert "resource_release_prepared:cache" not in cleanup.gates
    assert cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")


@pytest.mark.parametrize("kind", ["directory", "oversized", "hardlink"])
def test_manifest_requires_bounded_regular_file(cleanup: Cleanup, kind: str) -> None:
    """Malformed manifest objects are rejected before release rather than read without bounds."""
    resource = resource_identity(cleanup, "invalid-manifest")
    path = Path(resource["ownership_manifest"]["path"])
    if kind == "directory":
        path.unlink()
        path.mkdir()
    elif kind == "oversized":
        path.write_bytes(b"x" * 262145)
    else:
        path.with_suffix(".alias").hardlink_to(path)
    cleanup.handoff["resources"] = [resource]
    with pytest.raises(FileRefusal, match="bounded regular single-link"):
        cleanup.resources()
    assert "resource.release" not in cleanup.controller.calls


def test_bounded_reader_rechecks_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A size change observed after the read cannot authorize manifest hash acceptance."""
    path = tmp_path / "evidence.json"
    path.write_bytes(b"small")
    assert read_bounded_regular(path, 256) == b"small"
    original = os.fstat
    calls = 0

    def changed(descriptor: int) -> os.stat_result:
        """Model growth at the post-read identity check."""
        nonlocal calls
        calls += 1
        result = original(descriptor)
        if calls == 2:
            fields = list(result)
            fields[6] += 1
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(os, "fstat", changed)
    with pytest.raises(FileRefusal, match="changed during"):
        read_bounded_regular(path, 256)


@pytest.mark.parametrize("ignored", [False, True])
def test_empty_directory_requires_release(cleanup: Cleanup, ignored: bool) -> None:
    """An empty Git-invisible lock/artifact directory cannot disappear with its worktree."""
    path = cleanup.target / "empty-lock"
    path.mkdir()
    if ignored:
        (cleanup.repo / ".git/info/exclude").write_text("empty-lock/\n", encoding="utf-8")
    assert not cleanup.git("-C", str(cleanup.target), "status", "--porcelain", "--untracked-files=all")
    with pytest.raises(Refusal, match="Unreleased directory"):
        cleanup.run()
    assert path.is_dir()
    assert "remote_branch_absent" not in cleanup.gates
    assert cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")


def test_tracked_parent_directories_are_allowed(cleanup: Cleanup) -> None:
    """Ordinary source layout is distinguished from unrelated empty directories."""
    directory = cleanup.target / "source" / "nested"
    directory.mkdir(parents=True)
    (directory / "tracked.txt").write_text("source", encoding="utf-8")
    cleanup.git("-C", str(cleanup.target), "add", "source/nested/tracked.txt")
    cleanup.verify_directory_release()


@pytest.mark.parametrize("kind", ["journal", "blob"])
def test_recovery_rejects_nonregular_evidence(cleanup: Cleanup, kind: str) -> None:
    """A matching recovery filename cannot cause a special-file read before retry refusal."""
    cleanup.resource_evidence.append({"operation": "test", "evidence_refs": ["preserved"]})
    cleanup.record("cleanup_prepared")
    path = next(cleanup.evidence.glob("*.json" if kind == "journal" else "*.evidence"))
    path.unlink()
    path.mkdir()
    with pytest.raises(FileRefusal, match="bounded regular single-link"):
        Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    assert cleanup.target.exists()
    assert cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")


@pytest.mark.skipif(os.name != "nt", reason="Windows no-follow handle contract")
@pytest.mark.parametrize("nested", [False, True])
def test_generated_tree_preserves_bare_repository(cleanup: Cleanup, nested: bool) -> None:
    """Bare clones at the root or nested beneath generated output need separate ownership cleanup."""
    path = cleanup.target / "cache"
    path.mkdir()
    repository = path / "nested.git" if nested else path
    cleanup.git("init", "--bare", str(repository))
    (cleanup.repo / ".git/info/exclude").write_text("cache/\n", encoding="utf-8")
    identity = WindowsFiles().snapshot(path)["."]["identity"]
    cleanup.handoff["resources"] = [{**resource_identity(cleanup, "bare-cache", "generated_tree"),
                                     "path": str(path), "root_identity": identity}]
    with pytest.raises(Refusal, match="Bare repositories"):
        cleanup.run()
    assert cleanup.git("--git-dir", str(repository), "rev-parse", "--is-bare-repository") == "true"
    assert "resource_release_prepared:bare-cache" not in cleanup.gates
    assert cleanup.git("ls-remote", "--refs", "origin", f"refs/heads/{cleanup.branch}")


def test_uninventoried_ignored_file_blocks_before_remote_deletion(cleanup: Cleanup) -> None:
    """Ignored user/configuration files cannot slip through Git's clean-worktree check."""
    (cleanup.repo / ".git/info/exclude").write_text("secret.txt\n", encoding="utf-8")
    (cleanup.target / "secret.txt").write_text("fixture only", encoding="utf-8")
    with pytest.raises(Refusal, match="Unreleased ignored"):
        cleanup.run()
    assert cleanup.git("ls-remote", "--refs", "origin", "refs/heads/" + cleanup.branch)


def test_supported_script_policy_cannot_disappear(tmp_path: Path) -> None:
    """Each required controller policy rejects removed or comment-hidden command instructions."""
    from scripts.check_repo import (
        COMPLETED_TASK_COMMAND_MARKERS,
        check_completed_task_command_policy,
    )

    for relative in ("AGENTS.md", "CONTRIBUTING.md", "docs/contribute/agent-policies.md"):
        for marker in COMPLETED_TASK_COMMAND_MARKERS:
            path = tmp_path / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            heading = "## Completed Task Cleanup" if relative == "AGENTS.md" else "### Completed task cleanup"
            text = heading + "\n\n" + "\n\n".join(COMPLETED_TASK_COMMAND_MARKERS)
            path.write_text(text.replace(marker, "<!-- " + marker + " -->"), encoding="utf-8")
            assert any(marker in finding.message for finding in check_completed_task_command_policy(tmp_path))


def test_controller_rejects_saved_response(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    """A saved response cannot authorize a new invocation even if its result claims eligibility."""
    import io

    from scripts.completed_task_cleanup import Controller

    monkeypatch.setattr("sys.stdin", io.StringIO('{"id":"old-request","result":{"idle":true}}\n'))
    with pytest.raises(Refusal, match="fresh request"):
        Controller().call("task.inspect", {"sha256": "test"})
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["kind"] == "controller_request" and emitted["id"] != "old-request"


@pytest.mark.parametrize("value", [None, True, 123, "response", [], ["response"]])
def test_controller_rejects_non_object_json(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    """Valid JSON of the wrong shape produces a structured refusal instead of AttributeError."""
    import io

    from scripts.completed_task_cleanup import Controller

    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(value) + "\n"))
    with pytest.raises(Refusal, match="must be a JSON object"):
        Controller().call("task.title", {"task_id": "fixture-task"})


def test_changed_handoff_blocks_before_mutation(cleanup: Cleanup) -> None:
    """A replaced durable handoff cannot be used after its original digest was admitted."""
    cleanup.handoff_path.write_text("{}", encoding="utf-8")
    with pytest.raises(Refusal, match="Handoff changed"):
        cleanup.run()
    assert cleanup.target.exists()
    assert not cleanup.evidence.exists()


def test_main_preserves_gates_on_late_controller_refusal(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    """The CLI returns completed gate evidence when malformed input arrives at the final title request."""
    import io

    from scripts import completed_task_cleanup as command

    class LateRequest:
        """Model already completed transitions without deleting real fixture resources."""

        gates = ["validation_resources_released", "remote_branch_absent", "worktree_removed"]
        proposed = []

        def run(self) -> dict:
            """Exercise the real bridge parser at the final protocol boundary."""
            return command.Controller().call("task.title", {"task_id": "fixture-task"})

    monkeypatch.setattr(command, "Cleanup", lambda *args: LateRequest())
    monkeypatch.setattr("sys.argv", ["cleanup", "--handoff", "fixture", "--evidence", "fixture", "--config", "fixture"])
    monkeypatch.setattr("sys.stdin", io.StringIO("[]\n"))
    assert command.main() == 1
    result = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert result["status"] == "refused"
    assert result["gates"] == LateRequest.gates
    assert "JSON object" in result["retry_condition"]


@pytest.mark.parametrize("field", ["repository", "pr", "ownership_manifest", "provider_id", "cleanup_tool"])
def test_resource_identity_must_be_complete(cleanup: Cleanup, field: str) -> None:
    """Incomplete resources cannot reach any owning-tool release request."""
    resource = resource_identity(cleanup, "missing-field")
    resource.pop(field)
    cleanup.handoff["resources"] = [resource]
    with pytest.raises(Refusal):
        cleanup.run()
    assert "resource.release" not in cleanup.controller.calls
    assert cleanup.target.exists()


@pytest.mark.parametrize("defect", ["duplicate", "kind", "extra", "task", "source", "ancestry"])
def test_entire_inventory_is_validated_before_release(cleanup: Cleanup, defect: str) -> None:
    """A malformed later resource cannot cause partial release of an earlier valid resource."""
    first, later = resource_identity(cleanup, "first-valid"), resource_identity(cleanup, "later-invalid")
    if defect == "duplicate":
        later["id"] = first["id"]
    elif defect == "kind":
        later["kind"] = "unsupported"
    elif defect == "extra":
        later["unexpected"] = True
    elif defect == "task":
        later["task_id"] = "other-owner"
    elif defect == "source":
        later["source_commit"] = "invalid"
    else:
        later["source_commit"] = "0" * 40
    cleanup.handoff["resources"] = [first, later]
    with pytest.raises(Refusal):
        cleanup.resources()
    assert "resource.release" not in cleanup.controller.calls
    assert not cleanup.gates
    assert cleanup.target.exists()
    # The same full preflight also applies when recovering earlier completed gates.
    cleanup.gates = ["resource_released:first-valid"]
    with pytest.raises(Refusal):
        cleanup.resources()
    assert "resource.release" not in cleanup.controller.calls


def test_live_title_must_match_recorded_title(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """A controller's generic identity assertion cannot replace exact task-title readback."""
    original = cleanup.controller.call

    def renamed(operation: str, payload: dict) -> dict:
        """Simulate a concurrently renamed task while every other observation remains eligible."""
        result = original(operation, payload)
        if operation == "task.inspect":
            result["observed_title"] = "Different task"
        return result

    monkeypatch.setattr(cleanup.controller, "call", renamed)
    with pytest.raises(Refusal, match="Live task title differs"):
        cleanup.run()
    assert not cleanup.evidence.exists()


@pytest.mark.parametrize("description", [None, True, 123, [], {}])
def test_invalid_description_refuses_before_release(cleanup: Cleanup, description: object) -> None:
    """Malformed title input cannot reach a controller or release a validation resource."""
    handoff = dict(cleanup.handoff, description=description)
    handoff["resources"] = [resource_identity(cleanup, "preserve")]
    cleanup.handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
    with pytest.raises(Refusal, match="description must be a string"):
        Cleanup(cleanup.handoff_path, cleanup.evidence, cleanup.config, True, cleanup.controller)
    assert not cleanup.controller.calls
    assert cleanup.target.exists()
    assert not cleanup.evidence.exists()


def test_lost_resource_evidence_blocks_aggregate_gate(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """Evidence lost after release blocks ref and worktree removal despite resource absence."""
    cleanup.handoff["resources"] = [resource_identity(cleanup, "lost-evidence")]
    original = cleanup.controller.call
    inspections = 0

    def lost_evidence(operation: str, payload: dict) -> dict:
        """Preserve initial evidence but invalidate it on the final aggregate inspection."""
        nonlocal inspections
        result = original(operation, payload)
        if operation == "resource.inspect":
            inspections += 1
            if inspections >= 4:
                result["evidence_preserved"] = False
        return result

    monkeypatch.setattr(cleanup.controller, "call", lost_evidence)
    with pytest.raises(Refusal, match="Aggregate resource absence"):
        cleanup.run()
    assert "resource.release" in cleanup.controller.calls
    assert "validation_resources_released" not in cleanup.gates
    assert cleanup.target.exists()
    assert cleanup.git("ls-remote", "--refs", "origin", "refs/heads/" + cleanup.branch)


def test_earlier_resource_reappearance_blocks_aggregate_gate(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch) -> None:
    """A resource reappearing while another is processed prevents the aggregate release gate."""
    cleanup.handoff["resources"] = [resource_identity(cleanup, "first"), resource_identity(cleanup, "second")]
    original = cleanup.controller.call

    def reappeared(operation: str, payload: dict) -> dict:
        """Make the first provider disappear, then reappear at final inventory readback."""
        result = original(operation, payload)
        if operation == "resource.inspect" and payload["resource"]["id"] == "first" \
                and "resource_released:second" in cleanup.gates:
            result["absent"] = False
        return result

    monkeypatch.setattr(cleanup.controller, "call", reappeared)
    with pytest.raises(Refusal, match="Aggregate resource absence"):
        cleanup.run()
    assert "validation_resources_released" not in cleanup.gates
    assert cleanup.target.exists()


@pytest.mark.parametrize("gate", ["remote_branch_absent", "local_task_branch_absent"])
def test_recreated_matching_ref_invalidates_completed_gate(cleanup: Cleanup, monkeypatch: pytest.MonkeyPatch, gate: str) -> None:
    """Same-SHA ref recreation still invalidates a previously completed absence gate."""
    original = cleanup.record

    def recreate(completed: str) -> None:
        """Recreate the exact ref after its successful absence journal record."""
        original(completed)
        if completed == gate:
            if gate == "remote_branch_absent":
                cleanup.git("push", "origin", f"{cleanup.head}:refs/heads/{cleanup.branch}")
            else:
                cleanup.git("update-ref", f"refs/heads/{cleanup.branch}", cleanup.head)

    monkeypatch.setattr(cleanup, "record", recreate)
    with pytest.raises(Refusal, match="branch reappeared"):
        cleanup.run()
    assert "task.title" not in cleanup.controller.calls
    assert "task_title_done" not in cleanup.gates


@pytest.mark.skipif(os.name != "nt", reason="Windows junction contract")
def test_reparse_output_preserves_external_target(tmp_path: Path) -> None:
    """Neither inspection nor generated-tree deletion follows a junction to another owner."""
    external = tmp_path / "external"
    external.mkdir()
    (external / "keep.txt").write_text("user owned", encoding="utf-8")
    link = tmp_path / "output"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(external)], check=True, capture_output=True)
    with pytest.raises(Refusal, match="Reparse"):
        ordinary(link)
    with pytest.raises(FileRefusal, match="Reparse"):
        WindowsFiles().snapshot(link)
    assert (external / "keep.txt").read_text(encoding="utf-8") == "user owned"
