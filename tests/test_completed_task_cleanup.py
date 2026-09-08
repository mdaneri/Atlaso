"""Exercise destructive cleanup against disposable Git repositories and checked output trees."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts.completed_task_cleanup import Cleanup, Refusal, configured_root, ordinary
from scripts.completed_task_files import FileRefusal, WindowsFiles


class Bridge:
    """Model independent live supported-tool readbacks, recording every requested mutation."""

    def __init__(self) -> None:
        """Initialize an eligible controller without hidden ownership defaults in production."""
        self.calls: list[str] = []
        self.block = ""
        self.resource_absent = False
        self.release_ok = True

    def call(self, operation: str, payload: dict) -> dict:
        """Answer the bounded test protocol while allowing failed gates to be injected."""
        self.calls.append(operation)
        if operation == "task.inspect":
            result = dict.fromkeys(("identity_verified", "exclusive_ownership_verified", "idle", "unpinned",
                                   "holds_clear", "downstream_clear", "inventory_verified", "post_merge_complete",
                                   "reviews_complete", "supported_tools_used"), True)
            result.update(handoff_sha256=payload["sha256"], evidence_refs=["test-only-independent-readback"])
            result["inventory_empty_verified"] = True
            if self.block:
                result[self.block] = False
            return result
        if operation == "resource.inspect":
            return {"ownership_verified": True, "inactive": True, "retained": False,
                    "supported_cleanup": True, "evidence_preserved": True, "absent": self.resource_absent}
        if operation == "resource.release":
            self.resource_absent = self.release_ok
            return {"success": self.release_ok}
        assert operation == "task.title"
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
               "resources": [], "task_id": "test-task", "description": "Cleanup"}
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
        return {"total_count": 1, "workflow_runs": [{"status": "completed", "conclusion": "success"}]}

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


def test_incomplete_resource_release_blocks_ref_deletion(cleanup: Cleanup) -> None:
    """A failed owning tool leaves the exact remote/local branches and worktree intact."""
    cleanup.handoff["resources"] = [{"id": "fixture-vm", "kind": "vm", "task_id": "test-task",
                                     "source_commit": cleanup.head}]
    cleanup.controller.release_ok = False
    with pytest.raises(Refusal, match="Owning tool failed"):
        cleanup.run()
    assert cleanup.target.exists()
    assert cleanup.git("ls-remote", "--refs", "origin", "refs/heads/" + cleanup.branch)
    assert "task.title" not in cleanup.controller.calls


def test_resume_after_worktree_removed_before_local_ref(cleanup: Cleanup) -> None:
    """Interrupted cleanup can finish only the exact unreferenced matching local ref."""
    cleanup.git("worktree", "remove", str(cleanup.target))
    assert cleanup.run()["status"] == "complete"
    assert not cleanup.git("for-each-ref", "--format=%(objectname)", "refs/heads/" + cleanup.branch)


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
    cleanup.handoff["resources"] = [{"id": "generated-cache", "kind": "generated_tree", "path": str(path),
                                     "root_identity": identity, "task_id": "test-task", "source_commit": cleanup.head}]
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


def test_changed_handoff_blocks_before_mutation(cleanup: Cleanup) -> None:
    """A replaced durable handoff cannot be used after its original digest was admitted."""
    cleanup.handoff_path.write_text("{}", encoding="utf-8")
    with pytest.raises(Refusal, match="Handoff changed"):
        cleanup.run()
    assert cleanup.target.exists()
    assert not cleanup.evidence.exists()


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
