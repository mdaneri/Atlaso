"""Own, seal, and release one creation-bound Zensical cache generation."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Any, Concatenate, Iterator

from scripts.completed_task_cleanup import (
    beneath,
    configured_root,
    ordinary,
    require,
)
from scripts.completed_task_files import (
    cleanup_lock,
    publish_durable_file,
    read_bounded_regular,
)
from scripts.pytest_git_fixtures import FixtureFiles

CACHE_NAME = ".cache"
MARKER_NAME = ".atlaso-zensical-cache"
MARKER_CONTENT = b"atlaso-zensical-cache-v1"
TOOL = "ZensicalCache"
MAX_INVENTORY_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 50_000


def _pinned_checkout[**P, R](
    method: Callable[Concatenate[ZensicalCache, P], R],
) -> Callable[Concatenate[ZensicalCache, P], R]:
    """Hold checkout ancestors throughout one cache lifecycle operation."""
    @wraps(method)
    def wrapped(self: ZensicalCache, /, *args: P.args, **kwargs: P.kwargs) -> R:
        with self.files.ancestors(self.root):
            return method(self, *args, **kwargs)

    return wrapped


def _sha256(path: Path, limit: int = MAX_RECEIPT_BYTES) -> str:
    """Hash a bounded, ordinary file without following its final path entry."""
    return hashlib.sha256(read_bounded_regular(path, limit)).hexdigest()


def _publish(path: Path, value: dict[str, Any]) -> None:
    """Durably publish a new JSON record without replacing creation evidence."""
    ordinary(path)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    require(len(payload) <= MAX_RECEIPT_BYTES, "Zensical cache evidence exceeds the bounded receipt limit.")
    pending = path.with_name(path.name + ".pending")
    with pending.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    publish_durable_file(pending, path)


class ZensicalCache:
    """Manage exactly one cache root created by this task and durably receipted before use."""

    def __init__(self, config: Path, receipt: Path, binding: dict[str, Any]) -> None:
        """Bind the active Codex root, checkout-local cache, receipt, and task identity.

        Args:
            config: Active CODEX_HOME/config.toml.
            receipt: New durable receipt path outside the checkout and cache.
            binding: Exact id, task_id, repository, source_commit, and cache path.
        """
        self.permitted = configured_root(config)
        self.receipt = ordinary(receipt)
        require(set(binding) == {"id", "task_id", "repository", "source_commit", "path"}
                and all(isinstance(value, str) and value for value in binding.values())
                and re.fullmatch(r"[0-9a-f]{40}", binding["source_commit"]),
                "Invalid Zensical cache task/resource binding.")
        self.binding = dict(binding)
        self.root = ordinary(Path(binding["path"]))
        self.checkout = self.root.parent
        require(self.root.name == CACHE_NAME and beneath(self.checkout, self.permitted)
                and beneath(receipt, self.permitted) and not receipt.is_relative_to(self.checkout),
                "Zensical cache and durable receipt must be contained beneath the configured root.")
        require(not {".git", ".atlaso-local"} & {part.casefold() for part in self.root.relative_to(self.permitted).parts},
                "Git metadata and credential/recovery roots are not eligible Zensical caches.")
        self.files = FixtureFiles()
        self.lock_id = hashlib.sha256(str(receipt).casefold().encode("utf-8")).hexdigest()

    def _pending(self) -> list[Path]:
        return [path for path in self.receipt.parent.glob(self.receipt.name + "*")
                if path.name.endswith(".pending")]

    def _check_pending(self) -> None:
        require(not self._pending(), "Pending Zensical cache evidence requires reconciliation before retry.")

    def _path(self, suffix: str) -> Path:
        return self.receipt.with_name(self.receipt.name + suffix)

    def _record(self, suffix: str, value: dict[str, Any]) -> Path:
        path = self._path(suffix)
        with self.files.ancestors(path.parent):
            _publish(path, {"schema": 1, "binding": self.binding, **value})
        return path

    def _load(self, suffix: str = "") -> dict[str, Any]:
        self._check_pending()
        value = json.loads(read_bounded_regular(ordinary(self._path(suffix)), MAX_RECEIPT_BYTES))
        require(isinstance(value, dict) and value.get("schema") == 1 and value.get("binding") == self.binding,
                "Zensical cache receipt differs from original task/resource provenance.")
        return dict(value)

    def generations(self) -> list[dict[str, Any]]:
        """Load the original generation journal and reject gaps or duplicates."""
        self._check_pending()
        records = sorted(path for path in self.receipt.parent.glob(self.receipt.name + ".generation-*")
                         if not path.name.endswith(".pending"))
        require(len(records) == 1 and records[0].name == self.receipt.name + ".generation-0000",
                "Zensical cache generation journal is missing, duplicated, or incomplete.")
        return [self._load(".generation-0000")]

    def begin(self) -> None:
        """Exclusively create, record, and mark the cache before builder use."""
        self.create_generation()

    def create_generation(self) -> None:
        """Exclusively create and record the one cache generation used by this build."""
        with cleanup_lock(self.permitted, self.lock_id):
            self._check_pending()
            require(not self.checkout.is_relative_to(self.receipt.parent),
                    "Zensical cache receipts must use a separate evidence directory outside checkout ancestors.")
            require(not list(self.receipt.parent.glob(self.receipt.name + "*")) and not self.root.exists(),
                    "Zensical cache creation requires new cache and receipt paths; preserve existing state.")
            require(self.checkout.is_dir() and self.receipt.parent.is_dir(),
                    "Zensical cache checkout and receipt directory must exist.")
            with self.files.ancestors(self.root), self.files.opened(self.checkout, directory=True) as (
                    _, checkout_identity, _):
                self.root.mkdir()
                with self.files.opened(self.root, directory=True) as (_, root_identity, _):
                    self._record("", {"root_identity": list(root_identity),
                                      "checkout_identity": list(checkout_identity)})
                    self._record(".generation-0000", {"root_identity": list(root_identity)})
                    marker = self.root / MARKER_NAME
                    with marker.open("xb") as stream:
                        stream.write(MARKER_CONTENT)
                        stream.flush()
                        os.fsync(stream.fileno())
                    self._verify_marker()

    @contextmanager
    def pin(self) -> Iterator[None]:
        """Validate and hold the exact checkout and cache roots during a build."""
        with self.files.ancestors(self.root):
            original = self._original()
            with self.files.opened(self.root, directory=True) as (_, identity, _):
                require(list(identity) == original["root_identity"],
                        "Zensical cache root identity changed before build pinning.")
                yield

    def _verify_marker(self) -> None:
        marker = self.root / MARKER_NAME
        content = read_bounded_regular(marker, 1024)
        require(content == MARKER_CONTENT, "Zensical cache ownership marker is missing or invalid.")

    def _inventory(self) -> dict[str, dict[str, Any]]:
        """Capture bounded identities and content hashes, rejecting Git and recovery layouts."""
        snapshot = self.files.snapshot(self.root)
        require(len(snapshot) <= MAX_ENTRIES, "Zensical cache exceeds the bounded entry limit.")
        total = 0
        for relative, entry in snapshot.items():
            path = self.root / relative
            folded = path.name.casefold()
            require(folded not in {".git", ".atlaso-local"} and not folded.endswith(".lock"),
                    "Git metadata, active locks, or credential/recovery state block cache ownership.")
            if entry["directory"]:
                require(not ((path / "HEAD").exists() and (path / "objects").is_dir()),
                        "Nested bare Git metadata blocks Zensical cache ownership.")
                continue
            info = path.lstat()
            require(info.st_nlink == 1, "Hard-linked Zensical cache files are not eligible for cleanup.")
            content = read_bounded_regular(path, MAX_FILE_BYTES)
            total += len(content)
            require(total <= MAX_INVENTORY_BYTES, "Zensical cache contents exceed the bounded inventory limit.")
            entry["sha256"] = hashlib.sha256(content).hexdigest()
        plain = {key: {field: value for field, value in entry.items() if field != "sha256"}
                 for key, entry in snapshot.items()}
        require(self.files.snapshot(self.root) == plain, "Zensical cache changed during inventory capture.")
        return snapshot

    def _original(self) -> dict[str, Any]:
        ordinary(self.root)
        original = self._load()
        generations = self.generations()
        require(original.get("schema") == 1 and len(generations) == 1
                and original.get("root_identity") == generations[-1].get("root_identity"),
                "Zensical cache creation receipt is invalid.")
        with self.files.opened(self.checkout, directory=True) as (_, checkout_identity, _):
            require(list(checkout_identity) == original.get("checkout_identity"),
                    "Zensical cache checkout identity differs from its original binding.")
        if self.root.exists():
            require(self.files.snapshot(self.root)["."]["identity"] == original["root_identity"],
                    "Zensical cache root identity differs from its original generation.")
        return original

    @_pinned_checkout
    def seal(self) -> Path:
        """Seal completed cache contents and publish a small controller-facing manifest."""
        with cleanup_lock(self.permitted, self.lock_id):
            self._original()
            require(not self._path(".prepared").exists(), "Prepared cache release cannot be resealed.")
            self._verify_marker()
            entries = self._inventory()
            sealed_value = {
                "binding": self.binding,
                "root_identity": self.generations()[-1]["root_identity"],
                "entries": entries,
                "provenance": {
                    str(self.receipt): _sha256(self.receipt),
                    str(self._path(".generation-0000")): _sha256(self._path(".generation-0000")),
                },
            }
            sealed_path = self._path(".sealed")
            if sealed_path.exists():
                require(self._load(".sealed") == {"schema": 1, **sealed_value},
                        "Zensical cache differs from its previously sealed inventory.")
            else:
                self._record(".sealed", sealed_value)
            manifest_value = {"binding": self.binding, "sealed_sha256": _sha256(sealed_path)}
            manifest_path = self._path(".manifest")
            if manifest_path.exists():
                require(self._load(".manifest") == {"schema": 1, **manifest_value},
                        "Zensical cache manifest differs from its sealed inventory.")
                return manifest_path
            return self._record(".manifest", manifest_value)

    finish = seal

    @_pinned_checkout
    def inspect(self) -> dict[str, Any]:
        """Return fresh ownership, manifest, and exact-scope absence evidence."""
        self._original()
        manifest = self._load(".manifest")
        sealed_path = self._path(".sealed")
        sealed_digest = _sha256(sealed_path)
        require(manifest.get("sealed_sha256") == sealed_digest,
                "Zensical cache sealed inventory differs from its manifest.")
        sealed = self._load(".sealed")
        for name, digest in sealed["provenance"].items():
            path = ordinary(Path(name))
            require(path.parent == self.receipt.parent and path.name.startswith(self.receipt.name)
                    and _sha256(path) == digest, "Original Zensical cache creation provenance changed.")
        prepared_path = self._path(".prepared")
        prepared = prepared_path.exists()
        if prepared:
            require(self._load(".prepared").get("sealed_sha256") == sealed_digest,
                    "Prepared Zensical cache release differs from its sealed inventory.")
        absent = not self.root.exists()
        require(not absent or prepared, "Absent Zensical cache lacks prepared release evidence.")
        if not absent:
            current = self._inventory()
            expected = sealed["entries"]
            require(set(current) <= set(expected) and (prepared or set(current) == set(expected)),
                    "Zensical cache entries differ from the sealed inventory.")
            for relative, entry in current.items():
                original = expected[relative]
                require(entry["identity"] == original["identity"]
                        and entry["directory"] == original["directory"]
                        and (entry["directory"] and prepared or entry == original),
                        "Zensical cache identity or contents changed after sealing.")
            if not prepared:
                self._verify_marker()
        absent_path = self._path(".absent")
        require(not absent_path.with_name(absent_path.name + ".pending").exists(),
                "Pending Zensical cache absence receipt requires reconciliation.")
        evidence_preserved = not absent
        if absent_path.exists():
            absence = self._load(".absent")
            require(absent and absence.get("absent") is True
                    and absence.get("removal_scopes") == [str(self.root)],
                    "Zensical cache absence evidence is invalid.")
            evidence_preserved = True
        return {
            "ownership_verified": True,
            "inactive": True,
            "retained": False,
            "supported_cleanup": True,
            "evidence_preserved": evidence_preserved,
            "absent": absent,
            "removal_scopes": [str(self.root)],
        }

    @_pinned_checkout
    def release(self, removal_scopes: list[str]) -> dict[str, bool]:
        """Release exactly the sealed cache root and durably verify absence."""
        with cleanup_lock(self.permitted, self.lock_id):
            require(removal_scopes == [str(self.root)],
                    "Zensical cache release scope differs from controller preflight.")
            inspected = self.inspect()
            prepared_path = self._path(".prepared")
            if not prepared_path.exists():
                self._record(".prepared", {"sealed_sha256": _sha256(self._path(".sealed"))})
            if not inspected["absent"]:
                self.inspect()
                current = self._inventory()
                sealed = self._load(".sealed")["entries"]
                require(set(current) <= set(sealed), "New Zensical cache entries appeared before release.")
                expected = {
                    relative: ({**entry, "identity": sealed[relative]["identity"],
                                "directory": sealed[relative]["directory"]}
                               if entry["directory"] else sealed[relative])
                    for relative, entry in current.items()
                }
                self.files.remove(self.root, expected)
            require(self.inspect()["absent"] is True, "Zensical cache absence readback failed.")
            absent_path = self._path(".absent")
            if not absent_path.exists():
                self._record(".absent", {"absent": True, "removal_scopes": removal_scopes})
            else:
                require(self._load(".absent").get("absent") is True,
                        "Zensical cache absence receipt is invalid.")
            return {"success": True}

    def controller_call(self, operation: str, payload: dict[str, Any], resource: dict[str, Any]) -> dict[str, Any]:
        """Serve approved resource.inspect/release requests from the live cleanup controller.

        The controller must independently prove task quiescence and exclusive ownership.
        Receipt evidence establishes object ownership, not activity state.
        """
        require(payload.get("resource") == resource and resource.get("kind") == "artifact"
                and resource.get("cleanup_tool") == TOOL
                and all(resource.get(key) == self.binding[key] for key in self.binding),
                "Controller resource differs from independently verified Zensical cache provenance.")
        require(type(resource.get("pr")) is int and resource["pr"] > 0
                and isinstance(payload.get("handoff_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", payload["handoff_sha256"]),
                "Zensical cache PR/handoff binding is missing.")
        manifest = self._path(".manifest")
        require(resource.get("ownership_manifest") == {"path": str(manifest), "sha256": _sha256(manifest, 262144)},
                "Zensical cache manifest differs from controller approval.")
        if operation == "resource.inspect":
            return self.inspect()
        require(operation == "resource.release", "Unsupported Zensical cache owning-tool operation.")
        return self.release(payload.get("removal_scopes", []))
