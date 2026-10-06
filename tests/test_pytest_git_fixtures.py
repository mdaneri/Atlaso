"""Exercise creation-bound Windows pytest Git fixture ownership and cleanup."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Iterator

import pytest

from scripts.completed_task_cleanup import Refusal
from scripts.pytest_git_fixtures import (
    MAX_REPOSITORIES,
    TOOL,
    FixtureGit,
    PytestGitFixtures,
)


def run_git(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Run Git with inherited GIT_* redirections removed.

    Args:
        arguments: Exact local Git argument vector.
    """
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
    )


def git(path: Path, *arguments: str) -> str:
    """Run a local Git command for a fixture contained by the owning artifact.

    Args:
        path: Repository root used as Git's explicit working directory.
        *arguments: Exact local Git argument vector.
    """
    return run_git(["git", "-C", str(path), *arguments]).stdout.strip()


class GitFixtureOwner:
    """Create and release one independently receipted fixture artifact."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "artifact") -> None:
        """Bind one fresh configured root, external receipt, and task/source identity.

        Args:
            tmp_path: Pytest-owned validation parent for all fixture roots and receipts.
            monkeypatch: Scoped environment substitutions restored after the test.
            name: Unique leaf for this independently owned fixture.
        """
        self.permitted = tmp_path / "permitted"
        self.permitted.mkdir(exist_ok=True)
        self.receipts = self.permitted / "receipts"
        self.receipts.mkdir(exist_ok=True)
        codex_home = tmp_path / "codex-home"
        codex_home.mkdir(exist_ok=True)
        self.config = codex_home / "config.toml"
        self.config.write_text(
            "[desktop]\ngit-worktree-root = " + json.dumps(str(self.permitted)) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        self.root = self.permitted / name
        self.receipt = self.receipts / f"{name}.json"
        repository_root = Path(__file__).resolve().parents[1]
        source_commit = run_git(["git", "-C", str(repository_root), "rev-parse", "HEAD"]).stdout.strip()
        self.binding = {
            "id": f"test-{name}",
            "task_id": f"pytest-{tmp_path.name}",
            "repository": "example/Atlaso",
            "source_commit": source_commit,
            "path": str(self.root),
        }
        self.owner = PytestGitFixtures(self.config, self.receipt, self.binding)
        self.owner.create()
        self.sealed = False

    def ordinary_repo(self, name: str = "ordinary") -> Path:
        """Initialize and immediately register an ordinary fixture repository.

        Args:
            name: Repository directory relative to this fixture root.
        """
        path = self.root / name
        run_git(["git", "init", "--initial-branch=main", str(path)])
        self.owner.register(path)
        git(path, "config", "user.name", "Fixture Test")
        git(path, "config", "user.email", "fixture@example.invalid")
        (path / "tracked.txt").write_text("fixture source\n", encoding="utf-8")
        git(path, "add", "tracked.txt")
        git(path, "commit", "-m", "fixture source")
        return path

    def bare_repo(self, name: str = "bare.git") -> Path:
        """Initialize and immediately register a bare fixture repository.

        Args:
            name: Bare repository directory relative to this fixture root.
        """
        path = self.root / name
        run_git(["git", "init", "--bare", str(path)])
        self.owner.register(path)
        return path

    def seal(self) -> Path:
        """Seal the completed fixture and return its bounded resource manifest path."""
        manifest = self.owner.seal()
        self.sealed = True
        return manifest

    def release(self) -> dict[str, bool]:
        """Release the controller-observed exact fixture scope through the owning API."""
        inspected = self.owner.inspect()
        return self.owner.release(inspected["removal_scopes"])

    def resource(self, manifest: Path) -> dict[str, object]:
        """Build the exact approved resource identity for the direct controller adapter.

        Args:
            manifest: Bounded ownership manifest returned by fixture sealing.
        """
        return {
            **self.binding,
            "kind": "artifact",
            "cleanup_tool": TOOL,
            "pr": 767,
            "ownership_manifest": {
                "path": str(manifest),
                "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            },
        }


@pytest.fixture
def git_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[GitFixtureOwner]:
    """Supply an owned Windows fixture and release it through its checked handle tool.

    Args:
        tmp_path: Pytest-owned validation parent for the artifact and durable receipts.
        monkeypatch: Scoped environment substitutions restored after the test.
    """
    if os.name != "nt":
        pytest.skip("Pytest Git fixture release requires Windows no-follow handles")
    fixture = GitFixtureOwner(tmp_path, monkeypatch)
    yield fixture
    if fixture.sealed:
        fixture.release()


def test_owned_repo_graph_releases_through_resource_contract(git_fixture: GitFixtureOwner) -> None:
    """Release ordinary, bare, and linked Git metadata only after independent inspection.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
    """
    ordinary = git_fixture.ordinary_repo()
    linked = git_fixture.root / "linked-worktree"
    git(ordinary, "worktree", "add", "--detach", str(linked), "HEAD")
    git_fixture.owner.register(linked)
    git_fixture.bare_repo()
    manifest = git_fixture.seal()

    resource = git_fixture.resource(manifest)
    payload = {"resource": resource, "handoff_sha256": "a" * 64}
    inspected = git_fixture.owner.controller_call("resource.inspect", payload, resource)
    assert all(type(inspected[key]) is bool for key in (
        "ownership_verified", "inactive", "retained", "supported_cleanup", "evidence_preserved", "absent",
    ))
    assert {key: inspected[key] for key in (
        "ownership_verified", "inactive", "retained", "supported_cleanup", "evidence_preserved", "absent",
    )} == {
        "ownership_verified": True,
        "inactive": True,
        "retained": False,
        "supported_cleanup": True,
        "evidence_preserved": True,
        "absent": False,
    }
    assert inspected["removal_scopes"] == [str(git_fixture.root)]

    released = git_fixture.owner.controller_call(
        "resource.release",
        {**payload, "removal_scopes": inspected["removal_scopes"]},
        resource,
    )
    assert released == {"success": True}
    absent = git_fixture.owner.controller_call("resource.inspect", payload, resource)
    assert absent["absent"] is True
    assert absent["ownership_verified"] is True
    assert not git_fixture.root.exists()


@pytest.mark.parametrize("mutation", ["content", "identity", "lock"])
def test_changed_fixture_is_preserved_until_original_state_returns(
    git_fixture: GitFixtureOwner,
    mutation: str,
) -> None:
    """Detect content, handle-identity, and active-lock changes before release.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
        mutation: Fixture defect that must block cleanup until it is repaired.
    """
    repository = git_fixture.ordinary_repo()
    tracked = repository / "tracked.txt"
    original = tracked.read_bytes()
    original_stat = tracked.stat()
    if mutation == "content":
        git_fixture.seal()
        tracked.write_bytes(original.replace(b"source", b"sourcf"))
        os.utime(tracked, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        with pytest.raises(Refusal, match="identity or contents changed"):
            git_fixture.owner.inspect()
        tracked.write_bytes(original)
        os.utime(tracked, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    elif mutation == "identity":
        git_fixture.seal()
        backup = git_fixture.receipts / "tracked.backup"
        original_identity = git_fixture.owner.files.snapshot(repository)["tracked.txt"]["identity"]
        git_fixture.owner.record(".identity-backup", {
            "binding": git_fixture.binding,
            "path": str(backup),
            "identity": original_identity,
            "sha256": hashlib.sha256(original).hexdigest(),
        })
        tracked.rename(backup)
        tracked.write_bytes(original)
        os.utime(tracked, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        with pytest.raises(Refusal, match="identity or contents changed"):
            git_fixture.owner.inspect()
        tracked.unlink()
        backup.rename(tracked)
        saved = git_fixture.owner.load(".identity-backup")
        assert saved["path"] == str(backup)
        assert git_fixture.owner.files.snapshot(repository)["tracked.txt"]["identity"] == saved["identity"]
    else:
        lock = repository / ".git" / "index.lock"
        lock.write_bytes(b"active fixture lock")
        with pytest.raises(Refusal, match="Active Git lock"):
            git_fixture.owner.seal()
        lock.unlink()
        git_fixture.seal()
    assert git_fixture.owner.inspect()["absent"] is False


def test_fixture_scope_must_match_controller_preflight(git_fixture: GitFixtureOwner) -> None:
    """Reject an altered removal scope without preparing or deleting the fixture.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
    """
    git_fixture.ordinary_repo()
    git_fixture.seal()
    with pytest.raises(Refusal, match="scope differs"):
        git_fixture.owner.release([str(git_fixture.root.parent)])
    assert git_fixture.root.exists()
    assert not git_fixture.receipt.with_name(git_fixture.receipt.name + ".prepared").exists()


def test_release_pins_sealed_hashes_before_any_deletion(
    git_fixture: GitFixtureOwner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a restored-timestamp mutation in the gap after inspection, before deleting anything.

    Args:
        git_fixture: Creation-bound fixture with an independently sealed file inventory.
        monkeypatch: Scoped injection of a concurrent writer just before handle-based release.
    """
    repository = git_fixture.ordinary_repo()
    tracked = repository / "tracked.txt"
    original = tracked.read_bytes()
    stamp = tracked.stat()
    git_fixture.seal()
    before = git_fixture.owner.files.snapshot(git_fixture.root)
    remove = git_fixture.owner.files.remove

    def race(root: Path, expected: dict[str, dict]) -> None:
        """Model a same-size writer restoring its timestamp after the last content inspection.

        Args:
            root: Exact fixture release root.
            expected: Original sealed file hashes passed to the deletion primitive.
        """
        tracked.write_bytes(original.replace(b"source", b"sourcf"))
        os.utime(tracked, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        remove(root, expected)

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(git_fixture.owner.files, "remove", race)
            with pytest.raises(Refusal, match="Pinned fixture contents differ"):
                git_fixture.release()
        assert git_fixture.owner.files.snapshot(git_fixture.root) == before
    finally:
        tracked.write_bytes(original)
        os.utime(tracked, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert git_fixture.owner.inspect()["absent"] is False


@pytest.mark.parametrize("state", ["foreign", "locked"])
def test_live_unrecorded_worktree_registration_blocks_sealing(
    git_fixture: GitFixtureOwner,
    state: str,
) -> None:
    """Preserve a newly created foreign or locked registration until Git removes it.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
        state: Whether the linked worktree is foreign to the receipt inventory or Git-locked.
    """
    repository = git_fixture.ordinary_repo()
    linked = git_fixture.root / f"{state}-worktree"
    git(repository, "worktree", "add", "--detach", str(linked), "HEAD")
    head = git(repository, "rev-parse", "HEAD")
    identity = git_fixture.owner.files.snapshot(linked)["."]["identity"]
    if state == "locked":
        git_fixture.owner.register(linked)
        git_fixture.owner.record(".locked-worktree", {
            "binding": git_fixture.binding,
            "path": str(linked),
            "identity": identity,
            "source_commit": git_fixture.binding["source_commit"],
            "worktree_head": head,
        })
        git(repository, "worktree", "lock", "--reason=fixture test", str(linked))
    else:
        git_fixture.owner.record(".foreign-worktree", {
            "binding": git_fixture.binding,
            "path": str(linked),
            "identity": identity,
            "source_commit": git_fixture.binding["source_commit"],
            "worktree_head": head,
        })
    with pytest.raises(Refusal, match="Foreign, shared, locked, or missing"):
        git_fixture.owner.seal()

    saved = git_fixture.owner.load(f".{state}-worktree" if state == "locked" else ".foreign-worktree")
    assert git_fixture.owner.files.snapshot(linked)["."]["identity"] == saved["identity"]
    if state == "locked":
        git(repository, "worktree", "unlock", str(linked))
        assert linked.exists()
    else:
        git(repository, "worktree", "remove", "--force", str(linked))
        assert not linked.exists()
    git_fixture.seal()


def test_replaced_empty_root_identity_is_removed_before_original_restoration(
    git_fixture: GitFixtureOwner,
) -> None:
    """Reject a replacement root and remove it only after checking its recorded identity.

    Args:
        git_fixture: New empty Windows artifact with its original root identity receipted.
    """
    original = git_fixture.root
    backup = git_fixture.permitted / "artifact-original"
    creation = git_fixture.owner.load()
    original.rename(backup)
    git_fixture.owner.record(".root-original", {
        "binding": git_fixture.binding,
        "path": str(backup),
        "identity": creation["root_identity"],
    })
    original.mkdir()
    replacement_identity = git_fixture.owner.files.snapshot(original)["."]["identity"]
    git_fixture.owner.record(".root-replacement", {
        "binding": git_fixture.binding,
        "path": str(original),
        "identity": replacement_identity,
    })
    with pytest.raises(Refusal, match="root creation identity changed"):
        git_fixture.owner.original()

    saved = git_fixture.owner.load(".root-replacement")
    current = git_fixture.owner.files.snapshot(original)
    assert current["."]["identity"] == saved["identity"]
    assert set(current) == {"."}
    git_fixture.owner.files.remove(original, current)
    assert not original.exists()
    backup_record = git_fixture.owner.load(".root-original")
    assert git_fixture.owner.files.snapshot(backup)["."]["identity"] == backup_record["identity"]
    backup.rename(original)
    assert git_fixture.owner.original()["root_identity"] == creation["root_identity"]
    git_fixture.ordinary_repo()
    git_fixture.seal()


@pytest.mark.parametrize("changed", [False, True])
def test_seal_resumes_after_inventory_publication(
    git_fixture: GitFixtureOwner,
    monkeypatch: pytest.MonkeyPatch,
    changed: bool,
) -> None:
    """Publish a missing manifest only when the durable sealed state still matches.

    Args:
        git_fixture: Creation-bound fixture with external immutable receipts.
        monkeypatch: Scoped interruption restored before retry.
        changed: Whether to verify changed contents are preserved before restoration.
    """
    repository = git_fixture.ordinary_repo()
    record = git_fixture.owner.record

    def interrupted(suffix: str, value: dict) -> Path:
        """Interrupt after sealed publication and before manifest publication.

        Args:
            suffix: Durable receipt stage selected by seal.
            value: Exact evidence selected for publication.
        """
        if suffix == ".manifest":
            raise OSError("interrupted before manifest publication")
        return record(suffix, value)

    monkeypatch.setattr(git_fixture.owner, "record", interrupted)
    with pytest.raises(OSError, match="before manifest publication"):
        git_fixture.owner.seal()
    sealed = git_fixture.receipt.with_name(git_fixture.receipt.name + ".sealed")
    original_sealed = sealed.read_bytes()
    monkeypatch.setattr(git_fixture.owner, "record", record)
    if changed:
        tracked = repository / "tracked.txt"
        original = tracked.read_bytes()
        stamp = tracked.stat()
        tracked.write_bytes(original.replace(b"source", b"sourcf"))
        os.utime(tracked, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        try:
            with pytest.raises(Refusal, match="previously sealed inventory"):
                git_fixture.owner.seal()
            assert not sealed.with_name(sealed.name + ".pending").exists()
            assert sealed.read_bytes() == original_sealed
        finally:
            tracked.write_bytes(original)
            os.utime(tracked, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    manifest = git_fixture.seal()
    assert git_fixture.owner.seal() == manifest
    assert sealed.read_bytes() == original_sealed
    assert not sealed.with_name(sealed.name + ".pending").exists()
    assert git_fixture.owner.inspect()["evidence_preserved"] is True


def test_full_repository_journal_refuses_before_publication(
    git_fixture: GitFixtureOwner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve a usable creation journal when capacity prevents another registration.

    Args:
        git_fixture: Creation-bound artifact with one real registered repository.
        monkeypatch: Scoped capacity readback restored before seal and release.
    """
    git_fixture.ordinary_repo()
    records = git_fixture.owner.repositories()
    before = {path.name: path.read_bytes() for path in git_fixture.receipts.iterdir()}
    with monkeypatch.context() as context:
        context.setattr(git_fixture.owner, "repositories", lambda: records * MAX_REPOSITORIES)
        with pytest.raises(Refusal, match="journal is at capacity"):
            git_fixture.owner.register(git_fixture.root / "overflow")
    assert {path.name: path.read_bytes() for path in git_fixture.receipts.iterdir()} == before
    assert git_fixture.owner.repositories() == records
    git_fixture.seal()
    assert git_fixture.release() == {"success": True}


def test_pending_seal_receipt_blocks_inspect_and_can_be_reconciled(git_fixture: GitFixtureOwner) -> None:
    """Refuse an interrupted manifest publication, then resume after exact reconciliation.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
    """
    git_fixture.ordinary_repo()
    manifest = git_fixture.seal()
    pending = manifest.with_name(manifest.name + ".pending")
    pending.write_bytes(b"interrupted manifest publication")
    with pytest.raises(Refusal, match="Pending fixture receipt"):
        git_fixture.owner.inspect()
    pending.unlink()
    assert git_fixture.owner.inspect()["absent"] is False


def test_interrupted_subset_release_can_resume_from_sealed_survivors(
    git_fixture: GitFixtureOwner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resume an interrupted deletion after validating surviving identities and content.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
        monkeypatch: Scoped method replacement restored after the test.
    """
    git_fixture.ordinary_repo()
    payload = git_fixture.root / "generated"
    payload.mkdir()
    (payload / "result.txt").write_text("owned result\n", encoding="utf-8")
    git_fixture.seal()
    remove = git_fixture.owner.files.remove

    def interrupted(root: Path, expected: dict[str, dict]) -> None:
        """Delete one sealed subtree through checked handles, then model a process interruption.

        Args:
            root: Artifact root passed to the interrupted owning release.
            expected: Current complete Windows handle snapshot for that root.
        """
        assert root == git_fixture.root
        assert expected
        child_snapshot = git_fixture.owner.files.snapshot(payload)
        child_snapshot["result.txt"]["sha256"] = hashlib.sha256((payload / "result.txt").read_bytes()).hexdigest()
        remove(payload, child_snapshot)
        raise OSError("fixture release interrupted after one checked subtree")

    monkeypatch.setattr(git_fixture.owner.files, "remove", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        git_fixture.release()
    assert not payload.exists()
    assert git_fixture.owner.inspect()["absent"] is False

    monkeypatch.setattr(git_fixture.owner.files, "remove", remove)
    assert git_fixture.release() == {"success": True}
    assert git_fixture.owner.inspect()["absent"] is True


def test_absent_root_requires_durable_absence_finalization(
    git_fixture: GitFixtureOwner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep controller completion blocked after deletion until owning release saves absence.

    Args:
        git_fixture: Creation-bound artifact with durable receipts outside its removal scope.
        monkeypatch: Scoped interruption restored before owning-tool recovery.
    """
    git_fixture.ordinary_repo()
    manifest = git_fixture.seal()
    resource = git_fixture.resource(manifest)
    payload = {"resource": resource, "handoff_sha256": "a" * 64}
    record = git_fixture.owner.record

    def interrupted(suffix: str, value: dict) -> Path:
        """Model interruption before publishing the independent absence receipt.

        Args:
            suffix: Receipt stage selected by the owning tool.
            value: Exact durable evidence to publish.
        """
        if suffix == ".absent":
            raise OSError("interrupted before absence publication")
        return record(suffix, value)

    monkeypatch.setattr(git_fixture.owner, "record", interrupted)
    with pytest.raises(OSError, match="before absence publication"):
        git_fixture.release()
    inspected = git_fixture.owner.controller_call("resource.inspect", payload, resource)
    assert inspected["absent"] is True
    assert inspected["evidence_preserved"] is False
    assert not git_fixture.receipt.with_name(git_fixture.receipt.name + ".absent").exists()
    monkeypatch.setattr(git_fixture.owner, "record", record)
    assert git_fixture.owner.controller_call(
        "resource.release", {**payload, "removal_scopes": inspected["removal_scopes"]}, resource,
    ) == {"success": True}
    assert git_fixture.owner.controller_call("resource.inspect", payload, resource)["evidence_preserved"] is True


@pytest.mark.parametrize("invalid", [{"absent": False}, {"removal_scopes": ["foreign"]}])
def test_invalid_absence_receipt_blocks_completion(git_fixture: GitFixtureOwner, invalid: dict) -> None:
    """Reject invalid durable absence evidence even when the original root is gone.

    Args:
        git_fixture: Creation-bound fixture released through its owning tool.
        invalid: Absence receipt field replaced with invalid state.
    """
    git_fixture.ordinary_repo()
    git_fixture.seal()
    git_fixture.release()
    path = git_fixture.receipt.with_name(git_fixture.receipt.name + ".absent")
    original = path.read_bytes()
    value = json.loads(original)
    path.write_text(json.dumps({**value, **invalid}), encoding="utf-8")
    try:
        with pytest.raises(Refusal, match="absence evidence is invalid"):
            git_fixture.owner.inspect()
    finally:
        path.write_bytes(original)


def test_foreign_common_directory_and_worktree_registrations_block_sealing(
    git_fixture: GitFixtureOwner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reject Git metadata that resolves outside the fixture or registers a foreign worktree.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
        monkeypatch: Scoped command adapter replacement restored after the test.
        tmp_path: Pytest-owned validation parent used for a synthetic foreign identity.
    """
    repository = git_fixture.ordinary_repo()
    original_git = FixtureGit.git
    foreign = tmp_path / "foreign-git-state"

    def foreign_common(runner: FixtureGit, *arguments: str) -> str:
        """Model a live Git common-dir readback outside the owned artifact.

        Args:
            runner: Contained command adapter bound to the fixture root.
            *arguments: Requested Git command arguments.
        """
        if "--git-common-dir" in arguments:
            return str(foreign)
        return original_git(runner, *arguments)

    monkeypatch.setattr(FixtureGit, "git", foreign_common)
    with pytest.raises(Refusal, match="External Git metadata"):
        git_fixture.owner.seal()

    monkeypatch.setattr(FixtureGit, "git", original_git)
    original_common = git(repository, "rev-parse", "--path-format=absolute", "--git-common-dir")

    def foreign_worktree(runner: FixtureGit, *arguments: str) -> str:
        """Model an independently observed registration outside the fixture inventory.

        Args:
            runner: Contained command adapter bound to the fixture root.
            *arguments: Requested Git command arguments.
        """
        if "--git-common-dir" in arguments:
            return original_common
        if "--porcelain" in arguments and "worktree" in arguments and "list" in arguments:
            head = git(repository, "rev-parse", "HEAD")
            return (f"worktree {repository}\0HEAD {head}\0branch refs/heads/main\0\0"
                    f"worktree {foreign}\0HEAD {head}\0detached\0\0")
        return original_git(runner, *arguments)

    monkeypatch.setattr(FixtureGit, "git", foreign_worktree)
    with pytest.raises(Refusal, match="Foreign, shared, locked, or missing"):
        git_fixture.owner.seal()
    monkeypatch.setattr(FixtureGit, "git", original_git)
    git_fixture.seal()


@pytest.mark.parametrize("defect", ["alternates", "nested-repository", "bare-repository"])
def test_shared_or_uninventoried_git_metadata_blocks_sealing(
    git_fixture: GitFixtureOwner,
    defect: str,
) -> None:
    """Reject an alternate object store or nested Git repository absent from creation records.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
        defect: Git topology defect that must be reconciled before sealing.
    """
    repository = git_fixture.ordinary_repo()
    cleanup_path: Path
    if defect == "alternates":
        cleanup_path = repository / ".git" / "objects" / "info" / "alternates"
        cleanup_path.write_text("C:/outside/objects\n", encoding="utf-8")
        with pytest.raises(Refusal, match="Shared object storage"):
            git_fixture.owner.seal()
        cleanup_path.unlink()
    else:
        cleanup_path = git_fixture.root / "unregistered"
        if defect == "bare-repository":
            run_git(["git", "init", "--bare", str(cleanup_path)])
        else:
            cleanup_path.mkdir()
        git_fixture.owner.record(".nested-probe", {
            "binding": git_fixture.binding,
            "path": str(cleanup_path),
            "identity": git_fixture.owner.files.snapshot(cleanup_path)["."]["identity"],
        })
        if defect != "bare-repository":
            metadata = cleanup_path / ".git"
            metadata.mkdir()
            (metadata / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        message = "Uninventoried bare Git repository" if defect == "bare-repository" else "Uninventoried nested Git repository"
        with pytest.raises(Refusal, match=message):
            git_fixture.owner.seal()
        recorded = git_fixture.owner.load(".nested-probe")
        assert recorded["path"] == str(cleanup_path)
        assert git_fixture.owner.files.snapshot(cleanup_path)["."]["identity"] == recorded["identity"]
        removal = git_fixture.owner.files.snapshot(cleanup_path)
        for relative, entry in removal.items():
            if not entry["directory"]:
                entry["sha256"] = hashlib.sha256((cleanup_path / relative).read_bytes()).hexdigest()
        git_fixture.owner.files.remove(cleanup_path, removal)
    git_fixture.seal()


def test_pending_prepared_receipt_blocks_release_before_deletion(git_fixture: GitFixtureOwner) -> None:
    """Preserve the fixture if prepared-release receipt publication was interrupted.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
    """
    git_fixture.ordinary_repo()
    git_fixture.seal()
    prepared = git_fixture.receipt.with_name(git_fixture.receipt.name + ".prepared")
    pending = prepared.with_name(prepared.name + ".pending")
    pending.write_bytes(b"interrupted prepared receipt")
    with pytest.raises(FileExistsError):
        git_fixture.release()
    assert git_fixture.root.exists()
    pending.unlink()
    assert git_fixture.release() == {"success": True}


@pytest.mark.parametrize("defect", ["manifest", "task", "scope", "handoff", "request-resource"])
def test_controller_adapter_rejects_resource_binding_mismatches(
    git_fixture: GitFixtureOwner,
    defect: str,
) -> None:
    """Reject stale ownership, task, scope, or request bindings before release preparation.

    Args:
        git_fixture: New Windows artifact whose creation receipt is outside its removal scope.
        defect: Controller request mismatch to reject without deleting the artifact.
    """
    git_fixture.ordinary_repo()
    manifest = git_fixture.seal()
    resource = git_fixture.resource(manifest)
    payload: dict[str, object] = {"resource": resource, "handoff_sha256": "a" * 64}
    operation = "resource.inspect"
    approved = resource
    if defect == "manifest":
        approved = {**resource, "ownership_manifest": {**resource["ownership_manifest"], "sha256": "0" * 64}}
        payload["resource"] = approved
    elif defect == "task":
        approved = {**resource, "task_id": "another-task"}
        payload["resource"] = approved
    elif defect == "scope":
        operation = "resource.release"
        payload["removal_scopes"] = [str(git_fixture.root.parent)]
    elif defect == "handoff":
        payload["handoff_sha256"] = "invalid"
    else:
        payload["resource"] = {**resource, "id": "another-resource"}

    with pytest.raises(Refusal):
        git_fixture.owner.controller_call(operation, payload, approved)
    assert git_fixture.root.exists()
    assert not git_fixture.receipt.with_name(git_fixture.receipt.name + ".prepared").exists()
