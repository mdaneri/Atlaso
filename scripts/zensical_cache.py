"""Own, seal, and release one creation-bound Zensical cache generation."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from contextlib import ExitStack, contextmanager
from functools import wraps
from pathlib import Path
from typing import Any, Concatenate, Iterator

from scripts.completed_task_cleanup import (
    Refusal,
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
MAX_ATTEMPTS = 100


def _pinned_checkout[**P, R](
    method: Callable[Concatenate[ZensicalCache, P], R],
) -> Callable[Concatenate[ZensicalCache, P], R]:
    """Hold checkout ancestors throughout one cache lifecycle operation.

    Args:
        method: Lifecycle method whose checkout ancestors must remain pinned.
    """
    @wraps(method)
    def wrapped(self: ZensicalCache, /, *args: P.args, **kwargs: P.kwargs) -> R:
        """Run the lifecycle method while checkout ancestors remain pinned.

        Args:
            *args: Positional arguments forwarded to the lifecycle method.
            **kwargs: Keyword arguments forwarded to the lifecycle method.
        """
        if method.__name__ in {"inspect", "release"}:
            ancestors = self._existing_ancestors()
        else:
            ancestors = self.files.ancestors(self.root)
        with ancestors:
            return method(self, *args, **kwargs)

    return wrapped


def _sha256(path: Path, limit: int = MAX_RECEIPT_BYTES) -> str:
    """Hash a bounded, ordinary file without following its final path entry.

    Args:
        path: Bounded regular file whose bytes are hashed.
        limit: Maximum number of bytes to read.
    """
    return hashlib.sha256(read_bounded_regular(path, limit)).hexdigest()


def _publish(path: Path, value: dict[str, Any]) -> None:
    """Durably publish a new JSON record without replacing creation evidence.

    Args:
        path: New durable receipt path.
        value: JSON receipt fields to publish without replacement.
    """
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

    @contextmanager
    def claim(self) -> Iterator[None]:
        """Hold the task's cleanup mutex across one complete owned build lifecycle.

        The wrapper uses this outer claim while ``begin`` and ``seal`` acquire the
        same mutex reentrantly. This prevents another process from entering
        between generation creation, the native build, sealing, and redirects.
        """
        with cleanup_lock(self.permitted, self.lock_id):
            yield

    @contextmanager
    def _existing_ancestors(self) -> Iterator[None]:
        """Pin every existing cache ancestor, allowing only a verified missing suffix."""
        with ExitStack() as stack:
            for parent in reversed(self.root.parents):
                if not os.path.lexists(parent):
                    break
                stack.enter_context(self.files.opened(parent, directory=True))
            yield

    def _stage_path(self, suffix: str) -> Path:
        """Return the path for one fixed or numbered lifecycle stage.

        Args:
            suffix: Fixed receipt suffix or exact numbered attempt stage.
        """
        return self.receipt.with_name(self.receipt.name + suffix)

    def _path(self, suffix: str) -> Path:
        """Resolve sealed and manifest stages to the latest completed attempt.

        Args:
            suffix: Fixed receipt suffix or current inventory stage.
        """
        if suffix in {".sealed", ".manifest"}:
            attempts = self._attempt_numbers()
            if attempts:
                return self._stage_path(f".attempt-{attempts[-1]:04d}{suffix}")
        return self._stage_path(suffix)

    def _read_receipt(self, path: Path) -> dict[str, Any]:
        """Read a bounded receipt and require the immutable task binding.

        Args:
            path: Exact durable receipt path to read.
        """
        self._check_pending()
        value = json.loads(read_bounded_regular(ordinary(path), MAX_RECEIPT_BYTES))
        require(isinstance(value, dict) and value.get("schema") == 1 and value.get("binding") == self.binding,
                "Zensical cache receipt differs from original task/resource provenance.")
        return dict(value)

    def _record(self, suffix: str, value: dict[str, Any]) -> Path:
        """Durably publish one new stage receipt bound to this cache.

        Args:
            suffix: Receipt stage suffix.
            value: Stage-specific JSON evidence bound to the task.
        """
        path = self._path(suffix)
        with self.files.ancestors(path.parent):
            _publish(path, {"schema": 1, "binding": self.binding, **value})
        return path

    def _load(self, suffix: str = "") -> dict[str, Any]:
        """Load and validate one bounded durable receipt.

        Args:
            suffix: Receipt stage suffix to read.
        """
        self._check_pending()
        return self._read_receipt(self._path(suffix))

    def _attempt_numbers(self) -> list[int]:
        """Find exact numbered attempt stages and reject malformed or gapped sequences."""
        self._check_pending()
        prefix = self.receipt.name + ".attempt-"
        pattern = re.compile(re.escape(prefix) + r"([0-9]{4})(?:\.(?:ready|sealed|manifest))?\Z")
        numbers: set[int] = set()
        for path in self.receipt.parent.iterdir():
            if not path.name.startswith(prefix):
                continue
            match = pattern.fullmatch(path.name)
            if match is None:
                raise Refusal("Malformed Zensical cache attempt receipt; reconcile before retry.")
            numbers.add(int(match.group(1)))
        require(len(numbers) <= MAX_ATTEMPTS and numbers == set(range(1, len(numbers) + 1)),
                "Zensical cache attempt sequence is oversized or incomplete.")
        return sorted(numbers)

    def _attempts(self) -> list[dict[str, Any]]:
        """Validate the append-only attempt chain against each preceding manifest."""
        attempts: list[dict[str, Any]] = []
        numbers = self._attempt_numbers()
        previous_manifest = self._stage_path(".manifest")
        for number in numbers:
            start_path = self._stage_path(f".attempt-{number:04d}")
            ready_path = self._stage_path(f".attempt-{number:04d}.ready")
            sealed_path = self._stage_path(f".attempt-{number:04d}.sealed")
            manifest_path = self._stage_path(f".attempt-{number:04d}.manifest")
            require(start_path.is_file(), "Zensical cache attempt lacks its durable start receipt.")
            start = self._read_receipt(start_path)
            require(set(start) == {"schema", "binding", "attempt", "prior_manifest_sha256"},
                    "Zensical cache attempt start receipt has unexpected fields.")
            previous_number = number - 1
            previous_sealed = (self._stage_path(f".attempt-{previous_number:04d}.sealed")
                               if previous_number else self._stage_path(".sealed"))
            prior_manifest_value = self._read_receipt(previous_manifest)
            require(prior_manifest_value.get("sealed_sha256") == _sha256(previous_sealed),
                    "Zensical cache preceding manifest differs from its sealed inventory.")
            prior_digest = _sha256(previous_manifest)
            require(start.get("attempt") == number and start.get("prior_manifest_sha256") == prior_digest,
                    "Zensical cache attempt is not bound to the preceding manifest.")
            ready = self._read_receipt(ready_path) if ready_path.exists() else None
            if ready is not None:
                require(set(ready) == {"schema", "binding", "attempt", "prior_manifest_sha256", "root_identity"}
                        and ready.get("attempt") == number
                        and ready.get("prior_manifest_sha256") == prior_digest
                        and ready.get("root_identity") == self._load().get("root_identity"),
                        "Zensical cache ready receipt differs from its original generation.")
            sealed = self._read_receipt(sealed_path) if sealed_path.exists() else None
            manifest = self._read_receipt(manifest_path) if manifest_path.exists() else None
            if sealed is not None:
                require(ready is not None and set(sealed) == {
                    "schema", "binding", "root_identity", "entries", "provenance", "attempt", "prior_manifest_sha256",
                } and sealed.get("attempt") == number
                        and sealed.get("prior_manifest_sha256") == prior_digest,
                        "Zensical cache attempt seal differs from its ready receipt.")
                expected_provenance = {
                    str(self.receipt): _sha256(self.receipt),
                    str(self._stage_path(".generation-0000")): _sha256(self._stage_path(".generation-0000")),
                    str(start_path): _sha256(start_path),
                    str(ready_path): _sha256(ready_path),
                    str(previous_manifest): prior_digest,
                }
                require(sealed.get("root_identity") == self._load().get("root_identity")
                        and sealed.get("provenance") == expected_provenance,
                        "Zensical cache attempt seal lost its immutable creation or prior-attempt provenance.")
                if manifest is not None:
                    require(set(manifest) == {
                        "schema", "binding", "sealed_sha256", "attempt", "prior_manifest_sha256",
                    } and manifest.get("attempt") == number
                            and manifest.get("prior_manifest_sha256") == prior_digest
                            and manifest.get("sealed_sha256") == _sha256(sealed_path),
                            "Zensical cache attempt manifest differs from its sealed inventory.")
            else:
                require(manifest is None, "Zensical cache attempt manifest lacks a sealed inventory.")
            if number < numbers[-1]:
                require(ready is not None and sealed is not None and manifest is not None,
                        "An earlier Zensical cache attempt is incomplete.")
            attempts.append({
                "number": number,
                "start": start,
                "ready": ready,
                "sealed": sealed,
                "manifest": manifest,
                "start_path": start_path,
                "ready_path": ready_path,
                "sealed_path": sealed_path,
                "manifest_path": manifest_path,
                "prior_manifest_path": previous_manifest,
                "prior_manifest_sha256": prior_digest,
            })
            previous_manifest = manifest_path
        return attempts

    def generations(self) -> list[dict[str, Any]]:
        """Load the original generation journal and reject gaps or duplicates."""
        self._check_pending()
        records = sorted(path for path in self.receipt.parent.glob(self.receipt.name + ".generation-*")
                         if not path.name.endswith(".pending"))
        require(len(records) == 1 and records[0].name == self.receipt.name + ".generation-0000",
                "Zensical cache generation journal is missing, duplicated, or incomplete.")
        return [self._load(".generation-0000")]

    def begin(self) -> None:
        """Create or resume an owned empty cache attempt before builder use."""
        self.create_generation()

    def create_generation(self) -> None:
        """Create the original generation or append a numbered repeat-build attempt."""
        with cleanup_lock(self.permitted, self.lock_id):
            self._check_pending()
            require(not self.checkout.is_relative_to(self.receipt.parent),
                    "Zensical cache receipts must use a separate evidence directory outside checkout ancestors.")
            require(self.checkout.is_dir() and self.receipt.parent.is_dir(),
                    "Zensical cache checkout and receipt directory must exist.")
            if self.receipt.exists():
                original = self._load()
                self._verify_checkout(original)
                attempts = self._attempts()
                require(not self._path(".prepared").exists() and not self._path(".absent").exists(),
                        "Released Zensical cache cannot begin another build attempt.")
                if (not self._stage_path(".sealed").exists()
                        and not self._stage_path(".manifest").exists() and not attempts):
                    self._resume_bootstrap(original)
                    return
                current = self.inspect()
                previous_complete = (attempts[-1]["manifest"] is not None if attempts
                                     else self._stage_path(".manifest").is_file())
                require(current["absent"] is False and previous_complete,
                        "Zensical cache has an unfinished build attempt; seal or reconcile before retry.")
                prior_manifest = self._path(".manifest")
                attempt_number = (attempts[-1]["number"] if attempts else 0) + 1
                require(attempt_number <= MAX_ATTEMPTS,
                        "Zensical cache build-attempt limit reached; preserve the cache.")
                prior_digest = _sha256(prior_manifest)
                with self.files.ancestors(self.root), self.files.opened(self.root, directory=True) as (
                        _, root_identity, _):
                    require(list(root_identity) == original["root_identity"],
                            "Zensical cache root identity changed before the next build attempt.")
                    self._record(f".attempt-{attempt_number:04d}", {
                        "attempt": attempt_number,
                        "prior_manifest_sha256": prior_digest,
                    })
                    previous_sealed = self._read_receipt(
                        attempts[-1]["sealed_path"] if attempts else self._stage_path(".sealed"))
                    self._reset_from_inventory(previous_sealed["entries"])
                    self._record(f".attempt-{attempt_number:04d}.ready", {
                        "attempt": attempt_number,
                        "prior_manifest_sha256": prior_digest,
                        "root_identity": original["root_identity"],
                    })
                return

            require(not list(self.receipt.parent.glob(self.receipt.name + "*")) and not self.root.exists(),
                    "Zensical cache creation requires new cache and receipt paths; preserve existing state.")
            with self.files.ancestors(self.root), self.files.opened(self.checkout, directory=True) as (
                    _, checkout_identity, _):
                self.root.mkdir()
                rollback_snapshot: dict[str, dict[str, Any]] | None = None
                try:
                    with self.files.opened(self.root, directory=True) as (_, root_identity, _):
                        try:
                            self._record("", {"root_identity": list(root_identity),
                                               "checkout_identity": list(checkout_identity)})
                        except (OSError, RuntimeError):
                            if not list(self.receipt.parent.glob(self.receipt.name + "*")):
                                try:
                                    snapshot = self.files.snapshot(self.root)
                                    if set(snapshot) == {"."} and snapshot["."]["identity"] == list(root_identity):
                                        rollback_snapshot = snapshot
                                except (OSError, RuntimeError):
                                    pass
                            raise
                        self._record(".generation-0000", {"root_identity": list(root_identity)})
                        marker = self.root / MARKER_NAME
                        with marker.open("xb") as stream:
                            stream.write(MARKER_CONTENT)
                            stream.flush()
                            os.fsync(stream.fileno())
                        self._verify_marker()
                except (OSError, RuntimeError):
                    if rollback_snapshot is not None:
                        try:
                            self.files.remove(self.root, rollback_snapshot)
                        except (OSError, RuntimeError):
                            pass
                    raise

    def _verify_checkout(self, original: dict[str, Any]) -> None:
        """Require the exact checkout identity captured by the original receipt.

        Args:
            original: Durable creation receipt carrying the original checkout identity.
        """
        with self.files.opened(self.checkout, directory=True) as (_, checkout_identity, _):
            require(list(checkout_identity) == original.get("checkout_identity"),
                    "Zensical cache checkout identity differs from its original binding.")

    def _resume_bootstrap(self, original: dict[str, Any]) -> None:
        """Finish only original-receipted empty or marker-only bootstrap work.

        Args:
            original: Durable original receipt that proves cache and checkout identities.
        """
        ordinary(self.root)
        with self.files.ancestors(self.root), self.files.opened(self.root, directory=True) as (_, identity, _):
            require(list(identity) == original.get("root_identity"),
                    "Zensical cache root identity differs from its original receipt.")
            generation_paths = sorted(
                path for path in self.receipt.parent.glob(self.receipt.name + ".generation-*")
                if not path.name.endswith(".pending")
            )
            require(len(generation_paths) <= 1 and all(
                path.name == self.receipt.name + ".generation-0000" for path in generation_paths
            ), "Zensical cache generation receipt is malformed; reconcile before retry.")
            require(not self._attempt_numbers() and not any(
                self._stage_path(suffix).exists() for suffix in (".sealed", ".manifest", ".prepared", ".absent")
            ), "Zensical cache bootstrap is no longer resumable.")
            current = self.files.snapshot(self.root)
            require(set(current) <= {".", MARKER_NAME},
                    "Unreceipted Zensical cache contents block bootstrap recovery.")
            if MARKER_NAME in current:
                require(not current[MARKER_NAME]["directory"], "Zensical cache marker has an invalid type.")
                self._verify_marker()
            if generation_paths:
                generation = self._read_receipt(generation_paths[0])
                require(generation.get("root_identity") == original.get("root_identity"),
                        "Zensical cache generation receipt differs from its original identity.")
            else:
                self._record(".generation-0000", {"root_identity": original["root_identity"]})
            if MARKER_NAME not in current:
                marker = self.root / MARKER_NAME
                with marker.open("xb") as stream:
                    stream.write(MARKER_CONTENT)
                    stream.flush()
                    os.fsync(stream.fileno())
            self._verify_marker()

    def _reset_from_inventory(self, previous: dict[str, dict[str, Any]]) -> None:
        """Remove only known prior cache children and leave the exact owner marker.

        Args:
            previous: Previously sealed full cache inventory with original identities and hashes.
        """
        self._verify_marker()
        current = self._inventory()
        require(set(current) <= set(previous) and MARKER_NAME in current,
                "Zensical cache changed before repeat-build reset; preserve it.")
        for relative, entry in current.items():
            original = previous[relative]
            require(entry["identity"] == original["identity"]
                    and entry["directory"] == original["directory"]
                    and (entry["directory"] or entry == original),
                    "Zensical cache identity or file contents changed before repeat-build reset.")
        top_level = sorted({Path(relative).parts[0] for relative in current if relative != "."
                            and Path(relative).parts[0] != MARKER_NAME})
        for name in top_level:
            subset: dict[str, dict[str, Any]] = {}
            for relative, entry in current.items():
                parts = Path(relative).parts
                if parts and parts[0] == name and len(parts) == 1:
                    subset["."] = entry
                elif parts and parts[0] == name:
                    subset[str(Path(*parts[1:]))] = entry
            self.files.remove(self.root / name, subset)
        reset = self._inventory()
        require(set(reset) == {".", MARKER_NAME},
                "Repeat-build reset did not leave an empty marked cache.")

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
        if os.path.lexists(self.checkout):
            with self.files.opened(self.checkout, directory=True) as (_, checkout_identity, _):
                require(list(checkout_identity) == original.get("checkout_identity"),
                        "Zensical cache checkout identity differs from its original binding.")
        else:
            require(not os.path.lexists(self.root) and self._path(".prepared").is_file(),
                    "Missing checkout requires prepared cache provenance and exact cache absence.")
        if os.path.lexists(self.root):
            require(self.files.snapshot(self.root)["."]["identity"] == original["root_identity"],
                    "Zensical cache root identity differs from its original generation.")
        return original

    @_pinned_checkout
    def seal(self) -> Path:
        """Seal completed cache contents and publish a small controller-facing manifest."""
        with cleanup_lock(self.permitted, self.lock_id):
            original = self._original()
            require(not self._path(".prepared").exists(), "Prepared cache release cannot be resealed.")
            attempts = self._attempts()
            if attempts and attempts[-1]["manifest"] is not None:
                self.inspect()
                latest_number = int(attempts[-1]["number"])
                return self._stage_path(f".attempt-{latest_number:04d}.manifest")
            if attempts:
                attempt = attempts[-1]
                if attempt["ready"] is None:
                    previous_sealed_path = (attempts[-2]["sealed_path"] if len(attempts) > 1
                                            else self._stage_path(".sealed"))
                    previous_sealed = self._read_receipt(previous_sealed_path)
                    self._reset_from_inventory(previous_sealed["entries"])
                    self._record(f".attempt-{attempt['number']:04d}.ready", {
                        "attempt": attempt["number"],
                        "prior_manifest_sha256": attempt["prior_manifest_sha256"],
                        "root_identity": original["root_identity"],
                    })
                    attempt = self._attempts()[-1]
            self._verify_marker()
            entries = self._inventory()
            sealed_value = {
                "binding": self.binding,
                "root_identity": original["root_identity"],
                "entries": entries,
                "provenance": {
                    str(self.receipt): _sha256(self.receipt),
                    str(self._path(".generation-0000")): _sha256(self._path(".generation-0000")),
                },
            }
            if attempts:
                number = attempt["number"]
                sealed_value.update({
                    "attempt": number,
                    "prior_manifest_sha256": attempt["prior_manifest_sha256"],
                })
                sealed_value["provenance"].update({
                    str(attempt["start_path"]): _sha256(attempt["start_path"]),
                    str(attempt["ready_path"]): _sha256(attempt["ready_path"]),
                    str(attempt["prior_manifest_path"]): attempt["prior_manifest_sha256"],
                })
            sealed_path = self._path(".sealed")
            if sealed_path.exists():
                require(self._load(".sealed") == {"schema": 1, **sealed_value},
                        "Zensical cache differs from its previously sealed inventory.")
            else:
                self._record(".sealed", sealed_value)
            manifest_value = {"binding": self.binding, "sealed_sha256": _sha256(sealed_path)}
            if attempts:
                manifest_value.update({
                    "attempt": attempt["number"],
                    "prior_manifest_sha256": attempt["prior_manifest_sha256"],
                })
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
        attempts = self._attempts()
        require(not attempts or attempts[-1]["ready"] is not None
                and attempts[-1]["sealed"] is not None
                and attempts[-1]["manifest"] is not None,
                "Zensical cache has an unfinished build attempt; seal or reconcile before inspection.")
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
        # The original generation, sealed content inventory, and prepared receipt
        # remain durable ownership evidence even when interruption happens after
        # removal but before the optional final .absent receipt is published. The
        # enclosing controller can complete its release gate from that provenance
        # plus this fresh namespace absence; release() still publishes .absent on
        # an uninterrupted run.
        evidence_preserved = True
        if absent_path.exists():
            absence = self._load(".absent")
            require(absent and absence.get("absent") is True
                    and absence.get("removal_scopes") == [str(self.root)],
                    "Zensical cache absence evidence is invalid.")
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
        """Release exactly the sealed cache root and durably verify absence.

        Args:
            removal_scopes: Exact filesystem scopes independently approved by the controller.
        """
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

        Args:
            operation: Fresh resource.inspect or resource.release controller operation.
            payload: Nonce-bound controller request with handoff identity and removal scopes.
            resource: Exact artifact identity independently approved by the controller.
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
