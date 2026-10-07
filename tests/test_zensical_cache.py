"""Exercise creation-bound Zensical cache sealing and cleanup."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Iterator

import pytest

from scripts import build_docs
from scripts.completed_task_cleanup import Refusal
from scripts.completed_task_files import FileRefusal
from scripts.zensical_cache import MARKER_CONTENT, MARKER_NAME, TOOL, ZensicalCache

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Zensical cache cleanup requires Windows handle safeguards")


class CacheOwner:
    """Supply a contained checkout and external durable receipt for one test cache."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Prepare active Codex configuration without creating the cache or receipt.

        Args:
            root: Pytest-owned validation directory beneath the task validation root.
            monkeypatch: Scoped environment substitutions restored after the test.
        """
        self.permitted = root / "permitted"
        self.permitted.mkdir(parents=True)
        self.evidence = self.permitted / "evidence"
        self.evidence.mkdir()
        self.codex_home = root / "codex-home"
        self.codex_home.mkdir()
        self.config = self.codex_home / "config.toml"
        self.config.write_text(
            "[desktop]\ngit-worktree-root = " + json.dumps(str(self.permitted)) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("CODEX_HOME", str(self.codex_home))
        self.checkout = self.permitted / "checkout"
        self.checkout.mkdir()
        self.receipt = self.evidence / "zensical-cache.json"
        self.binding = {
            "id": "test-zensical-cache",
            "task_id": f"pytest-{root.name}",
            "repository": "mdaneri/Atlaso",
            "source_commit": "a" * 40,
            "path": str(self.checkout / ".cache"),
        }
        self.owner = ZensicalCache(self.config, self.receipt, self.binding)

    def seal(self) -> Path:
        """Complete the cache and return its durable controller manifest."""
        return self.owner.seal()

    def resource(self, manifest: Path) -> dict[str, object]:
        """Build the exact resource identity expected by the live controller adapter."""
        return {
            **self.binding,
            "kind": "artifact",
            "cleanup_tool": TOOL,
            "pr": 920,
            "ownership_manifest": {
                "path": str(manifest),
                "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            },
        }


@pytest.fixture
def cache_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[CacheOwner]:
    """Yield an exclusively created cache and release it after tests that seal it."""
    fixture = CacheOwner(tmp_path, monkeypatch)
    fixture.owner.begin()
    yield fixture
    if fixture.receipt.exists() and fixture.owner._path(".manifest").exists():
        fixture.owner.release([str(fixture.owner.root)])


def test_generation_is_recorded_before_cache_use(cache_owner: CacheOwner) -> None:
    """Record the original empty root before any builder content is added."""
    generation = cache_owner.owner.generations()[0]
    assert generation["root_identity"] == cache_owner.owner.files.snapshot(cache_owner.owner.root)["."]["identity"]
    assert (cache_owner.owner.root / MARKER_NAME).read_bytes() == MARKER_CONTENT
    assert cache_owner.receipt.exists()


def test_existing_cache_cannot_be_adopted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A cache that predates its receipt is never adopted as task-owned."""
    fixture = CacheOwner(tmp_path, monkeypatch)
    cache = fixture.owner.root
    cache.mkdir()
    with pytest.raises(Refusal, match="new cache and receipt paths"):
        fixture.owner.begin()
    assert not fixture.receipt.exists()
    assert cache.is_dir()


def test_receipt_parent_ancestor_refuses_before_cache_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A worktree-root receipt is rejected before creating cache or receipt files."""
    fixture = CacheOwner(tmp_path, monkeypatch)
    receipt = fixture.permitted / "cache-receipt.json"
    owner = ZensicalCache(fixture.config, receipt, fixture.binding)
    with pytest.raises(Refusal, match="separate evidence directory"):
        owner.begin()
    assert not owner.root.exists()
    assert not receipt.exists()
    assert not list(fixture.permitted.glob(receipt.name + "*"))


def test_seal_and_controller_release(cache_owner: CacheOwner) -> None:
    """Seal hashes, inspect the approved artifact, then release and verify its absence."""
    (cache_owner.owner.root / "objects").mkdir()
    payload = cache_owner.owner.root / "objects" / "index.bin"
    payload.write_bytes(b"document cache contents")
    manifest = cache_owner.seal()
    resource = cache_owner.resource(manifest)
    request = {"resource": resource, "handoff_sha256": "b" * 64}
    inspected = cache_owner.owner.controller_call("resource.inspect", request, resource)
    assert inspected["removal_scopes"] == [str(cache_owner.owner.root)]
    assert inspected["ownership_verified"] is True
    assert inspected["inactive"] is True
    result = cache_owner.owner.controller_call(
        "resource.release",
        {**request, "removal_scopes": inspected["removal_scopes"]},
        resource,
    )
    assert result == {"success": True}
    absent = cache_owner.owner.controller_call("resource.inspect", request, resource)
    assert absent["absent"] is True
    assert absent["evidence_preserved"] is True
    assert not cache_owner.owner.root.exists()


def test_changed_file_content_blocks_release(cache_owner: CacheOwner) -> None:
    """A same-size edit with restored timestamps still fails the sealed content hash."""
    path = cache_owner.owner.root / "index.bin"
    path.write_bytes(b"original")
    cache_owner.seal()
    original_stat = path.stat()
    path.write_bytes(b"tampered")
    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    with pytest.raises(Refusal, match="identity or contents changed"):
        cache_owner.owner.inspect()
    path.write_bytes(b"original")
    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))


def test_prepared_retry_allows_only_missing_entries(cache_owner: CacheOwner) -> None:
    """An interrupted release may lose sealed entries but cannot gain or replace any."""
    path = cache_owner.owner.root / "index.bin"
    path.write_bytes(b"original")
    cache_owner.seal()
    cache_owner.owner._record(".prepared", {
        "sealed_sha256": hashlib.sha256(cache_owner.owner._path(".sealed").read_bytes()).hexdigest(),
    })
    path.unlink()
    assert cache_owner.owner.inspect()["absent"] is False
    (cache_owner.owner.root / "new.bin").write_bytes(b"new")
    with pytest.raises(Refusal, match="entries differ from the sealed inventory"):
        cache_owner.owner.inspect()
    (cache_owner.owner.root / "new.bin").unlink()
    cache_owner.owner.release([str(cache_owner.owner.root)])


def test_prepared_retry_allows_missing_marker(cache_owner: CacheOwner) -> None:
    """A marker removed during an interrupted prepared release remains an allowed missing entry."""
    cache_owner.seal()
    cache_owner.owner._record(".prepared", {
        "sealed_sha256": hashlib.sha256(cache_owner.owner._path(".sealed").read_bytes()).hexdigest(),
    })
    (cache_owner.owner.root / MARKER_NAME).unlink()
    assert cache_owner.owner.inspect()["absent"] is False
    cache_owner.owner.release([str(cache_owner.owner.root)])


def test_replaced_checkout_identity_blocks_readback(cache_owner: CacheOwner) -> None:
    """A replaced checkout cannot inherit the cache's durable ownership evidence."""
    cache_owner.seal()
    cache_owner.owner.release([str(cache_owner.owner.root)])
    backup = cache_owner.permitted / "checkout-original"
    cache_owner.checkout.rename(backup)
    cache_owner.checkout.mkdir()
    with pytest.raises(Refusal, match="checkout identity differs"):
        cache_owner.owner.inspect()
    cache_owner.checkout.rmdir()
    backup.rename(cache_owner.checkout)
    assert cache_owner.owner.inspect()["absent"] is True


def test_hard_link_blocks_cache_sealing(cache_owner: CacheOwner) -> None:
    """Cache entries with shared filesystem identity cannot be released."""
    path = cache_owner.owner.root / "shared.bin"
    path.write_bytes(b"shared")
    alias = cache_owner.evidence / "shared-alias.bin"
    os.link(path, alias)
    with pytest.raises(FileRefusal, match="hard-linked"):
        cache_owner.seal()
    alias.unlink()


def test_cache_reappearance_after_absence_is_refused(cache_owner: CacheOwner) -> None:
    """A new cache directory cannot inherit an already published absence receipt."""
    cache_owner.seal()
    cache_owner.owner.release([str(cache_owner.owner.root)])
    cache_owner.owner.root.mkdir()
    with pytest.raises(Refusal, match="root identity differs"):
        cache_owner.owner.inspect()
    cache_owner.owner.root.rmdir()
    assert cache_owner.owner.inspect()["absent"] is True


def test_pending_publication_blocks_inspection(cache_owner: CacheOwner) -> None:
    """Incomplete durable evidence requires reconciliation before any retry."""
    cache_owner.seal()
    pending = cache_owner.owner._path(".prepared").with_name(cache_owner.owner.receipt.name + ".prepared.pending")
    pending.write_bytes(b"pending")
    with pytest.raises(Refusal, match="Pending Zensical cache evidence"):
        cache_owner.owner.inspect()
    pending.unlink()


def test_git_metadata_blocks_sealing(cache_owner: CacheOwner) -> None:
    """Generic cache cleanup refuses Git worktrees and never uses the Git fixture remover."""
    (cache_owner.owner.root / ".git").mkdir()
    with pytest.raises(Refusal, match="Git metadata"):
        cache_owner.seal()
    (cache_owner.owner.root / ".git").rmdir()


def test_controller_rejects_changed_manifest_hash(cache_owner: CacheOwner) -> None:
    """The approved manifest digest is checked on every fresh controller request."""
    resource = cache_owner.resource(cache_owner.seal())
    resource["ownership_manifest"] = {**resource["ownership_manifest"], "sha256": "0" * 64}
    with pytest.raises(Refusal, match="manifest differs"):
        cache_owner.owner.controller_call(
            "resource.inspect",
            {"resource": resource, "handoff_sha256": "c" * 64},
            resource,
        )


@pytest.mark.parametrize("build_status", [0, 2])
def test_owned_build_pins_and_seals_cache_on_success_or_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    build_status: int,
) -> None:
    """The native builder cannot replace its recorded root, and both outcomes seal evidence."""
    cache_owner = CacheOwner(tmp_path, monkeypatch)
    monkeypatch.setattr(build_docs, "ROOT", cache_owner.checkout)
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> object:
        """Capture build arguments and model builder output while the cache root is pinned."""
        calls.append(command)
        if "zensical" in command:
            assert "--clean" not in command
            replacement = cache_owner.checkout / ".cache-replacement"
            with pytest.raises(OSError):
                cache_owner.owner.root.rename(replacement)
            (cache_owner.owner.root / "render-cache.bin").write_bytes(b"builder output")
            return type("ProcessResult", (), {"returncode": build_status})()
        return type("ProcessResult", (), {"returncode": 0})()

    monkeypatch.setattr(build_docs.subprocess, "run", run)
    result = build_docs.main([
        "--cache-receipt", str(cache_owner.receipt),
        "--task-id", cache_owner.binding["task_id"],
        "--resource-id", cache_owner.binding["id"],
        "--source-commit", cache_owner.binding["source_commit"],
    ])
    assert result == build_status
    assert len(calls) == (1 if build_status else 2)
    assert cache_owner.owner._path(".manifest").is_file()
    assert json.loads(cache_owner.receipt.read_text(encoding="utf-8"))["binding"] == cache_owner.binding
    assert cache_owner.owner.inspect()["absent"] is False
    cache_owner.owner.release([str(cache_owner.owner.root)])

