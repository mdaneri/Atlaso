"""Own and release creation-bound Windows pytest Git fixture artifacts."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from scripts.completed_task_cleanup import (
    Cleanup,
    beneath,
    configured_root,
    ordinary,
    require,
)
from scripts.completed_task_files import (
    FileRefusal,
    WindowsFiles,
    cleanup_lock,
    publish_durable_file,
    read_bounded_regular,
)

TOOL = "PytestGitFixtures"
MAX_MANIFEST = 64 * 1024 * 1024


class FixtureFiles(WindowsFiles):
    """Retain exact-handle safeguards while permitting immutable disposable Git objects."""

    def dispose(self, handle: int) -> None:
        """Delete an owned Git object through its handle without changing path-based permissions.

        Args:
            handle: Exact-object handle whose identity and stamp were verified by inherited removal.
        """
        # FileDispositionInfoEx: DELETE | IGNORE_READONLY_ATTRIBUTE. Keep ordinary close
        # semantics and share restrictions; never enable POSIX deletion of active handles.
        disposition = ctypes.c_uint32(0x11)
        if not self.kernel.SetFileInformationByHandle(handle, 21, ctypes.byref(disposition), 4):
            raise FileRefusal("Exact Git fixture deletion failed; preserve remaining entries and retry after inspection.")

    def digest(self, handle: int) -> str:
        """Hash bytes from the already pinned read/delete handle without reopening the path.

        Args:
            handle: Exact ordinary file handle held against replacement and writers.
        """
        self.kernel.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                        ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        self.kernel.ReadFile.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(65536)
        count = ctypes.c_uint32()
        digest = hashlib.sha256()
        total = 0
        while True:
            if not self.kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
                raise FileRefusal("Cannot verify pinned fixture contents; preserve the tree.")
            if not count.value:
                return digest.hexdigest()
            total += count.value
            require(total <= MAX_MANIFEST, "Pinned fixture content exceeds the bounded inventory limit.")
            digest.update(buffer.raw[:count.value])

    def remove(self, root: Path, expected: dict[str, dict[str, Any]]) -> None:
        """Pin and verify the entire sealed tree before deleting any exact object.

        Args:
            root: Exact creation-bound artifact or explicitly receipted test subtree.
            expected: Sealed identities, file stamps and content hashes; current directory stamps.
        """
        plain = {key: {field: value for field, value in entry.items() if field != "sha256"}
                 for key, entry in expected.items()}
        require(self.snapshot(root) == plain, "Fixture changed before pinned release; preserve it.")
        with self.ancestors(root), ExitStack() as stack:
            pinned = {}
            for relative in sorted(expected, key=lambda value: len(Path(value).parts)):
                entry = expected[relative]
                owner = ExitStack()
                stack.callback(owner.close)
                handle, identity, stamp = owner.enter_context(self.opened(
                    root / relative, delete=True, directory=entry["directory"]))
                require(list(identity) == entry["identity"] and (entry["directory"] or list(stamp) == entry["stamp"]),
                        "Fixture identity or contents changed before pinned release.")
                if not entry["directory"]:
                    require(self.digest(handle) == entry.get("sha256"), "Pinned fixture contents differ from the sealed hash.")
                pinned[relative] = (handle, owner)
            # Keep every checked object pinned until its disposition. Close each child before
            # disposing its parent; new children cause nonempty-directory refusal, never a sweep.
            for relative in sorted(expected, key=lambda value: len(Path(value).parts), reverse=True):
                handle, owner = pinned[relative]
                self.dispose(handle)
                owner.close()
                require(not (root / relative).exists(), "Pinned fixture absence readback failed.")


class FixtureGit(Cleanup):
    """Reuse the contained, bounded Git command runner without task/PR cleanup transitions."""

    def __init__(self, root: Path) -> None:
        """Select the independently contained fixture command working directory.

        Args:
            root: Verified fixture directory for bounded child commands.
        """
        self.repo = root


def publish(path: Path, value: dict[str, Any]) -> None:
    """Publish a new flushed receipt without replacing existing provenance.

    Args:
        path: New durable evidence filename outside the disposable root.
        value: Bounded JSON receipt to persist before proceeding.
    """
    ordinary(path)
    payload = json.dumps(value, sort_keys=True).encode("utf-8")
    require(len(payload) <= MAX_MANIFEST, "Fixture receipt exceeds the bounded evidence limit.")
    pending = path.with_name(path.name + ".pending")
    with pending.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    publish_durable_file(pending, path)


class PytestGitFixtures:
    """Release only complete, exclusive Git fixture graphs with original creation evidence."""

    def __init__(self, config: Path, receipt: Path, binding: dict[str, Any]) -> None:
        """Bind supported configuration, durable provenance, and independent task/resource identity.

        Args:
            config: Active Codex configuration, never a fixture-supplied replacement.
            receipt: Original creation receipt outside every removal root.
            binding: Independently verified id, task_id, repository, source_commit, and path.
        """
        self.permitted = configured_root(config)
        self.receipt = ordinary(receipt)
        self.binding = binding
        require(set(binding) == {"id", "task_id", "repository", "source_commit", "path"}
                and all(isinstance(value, str) and value for value in binding.values())
                and re.fullmatch(r"[0-9a-f]{40}", binding["source_commit"]), "Invalid fixture task/resource binding.")
        self.root = ordinary(Path(binding["path"]))
        require(beneath(self.root, self.permitted) and beneath(receipt, self.permitted)
                and not receipt.is_relative_to(self.root), "Fixture/evidence containment is unproven.")
        require(not {".git", ".atlaso-local"} & {part.casefold() for part in self.root.relative_to(self.permitted).parts},
                "Fixture root must not be Git metadata or credential/recovery state.")
        self.files = FixtureFiles()
        self.lock_id = hashlib.sha256(str(receipt).casefold().encode()).hexdigest()

    def record(self, suffix: str, value: dict[str, Any]) -> Path:
        """Persist a new stage receipt outside the removal scope.

        Args:
            suffix: Fixed receipt stage or zero-based repository creation sequence.
            value: Provenance or prepared/absence evidence to publish durably.
        """
        path = self.receipt.with_name(self.receipt.name + suffix)
        publish(path, value)
        return path

    def load(self, suffix: str = "") -> dict[str, Any]:
        """Read a bounded pinned receipt and reject incomplete publication.

        Args:
            suffix: Exact stage suffix to retrieve.
        """
        path = self.receipt.with_name(self.receipt.name + suffix)
        require(not path.with_name(path.name + ".pending").exists(), "Pending fixture receipt requires reconciliation.")
        value = json.loads(read_bounded_regular(ordinary(path), MAX_MANIFEST))
        require(isinstance(value, dict) and value.get("binding") == self.binding,
                "Fixture receipt does not match independent task/resource provenance.")
        return dict(value)

    def create(self) -> None:
        """Create an exclusively new empty fixture root and record its identity before use."""
        with cleanup_lock(self.permitted, self.lock_id), self.files.ancestors(self.root):
            require(not list(self.receipt.parent.glob(self.receipt.name + "*")) and not self.root.exists(),
                    "Fixture creation must use new paths without earlier or pending provenance.")
            self.root.mkdir()
            snapshot = self.files.snapshot(self.root)
            self.record("", {"schema": 1, "binding": self.binding, "root_identity": snapshot["."]["identity"]})

    def original(self) -> dict[str, Any]:
        """Require the original creation identity and durable external receipt on every operation."""
        creation = self.load()
        require(creation.get("schema") == 1, "Unsupported fixture creation receipt.")
        if self.root.exists():
            require(self.files.snapshot(self.root)["."]["identity"] == creation["root_identity"],
                    "Fixture root creation identity changed.")
        return creation

    def repositories(self) -> list[dict[str, Any]]:
        """Read the contiguous creation journal; gaps or interrupted publication block release."""
        records = sorted(self.receipt.parent.glob(self.receipt.name + ".repo-*"))
        require(len(records) <= 1000, "Fixture repository inventory exceeds its bounded limit.")
        result = []
        for index, path in enumerate(records):
            suffix = f".repo-{index:04d}"
            require(path.name == self.receipt.name + suffix, "Fixture repository journal is incomplete.")
            result.append(self.load(suffix))
        return result

    def register(self, repository: Path) -> None:
        """Record each new ordinary/bare repository or linked worktree immediately after creation.

        Args:
            repository: Exact just-created repository/worktree root beneath this artifact.
        """
        with cleanup_lock(self.permitted, self.lock_id):
            self.original()
            require(not self.receipt.with_name(self.receipt.name + ".sealed").exists(), "Sealed fixtures cannot add repositories.")
            repository = ordinary(repository)
            require(beneath(repository, self.root), "Repository creation lies outside the fixture root.")
            records = self.repositories()
            require(str(repository) not in {item["path"] for item in records}, "Duplicate fixture repository creation.")
            identity = self.files.snapshot(repository)["."]["identity"]
            self.record(f".repo-{len(records):04d}", {"binding": self.binding, "path": str(repository), "identity": identity})

    def topology(self, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        """Independently verify common directories and every registered worktree are exclusively internal.

        Args:
            snapshot: Current no-follow tree inventory checked against original repository receipts.
        """
        records = self.repositories()
        require(records, "No original repository creation receipts; never retrofit fixture ownership.")
        paths = {ordinary(Path(record["path"])) for record in records}
        runner = FixtureGit(self.root)
        result = []
        common_dirs = set()
        for record in records:
            path = ordinary(Path(record["path"]))
            require(beneath(path, self.root) and snapshot[str(path.relative_to(self.root))]["identity"] == record["identity"],
                    "Fixture repository creation identity differs.")
            common = ordinary(Path(runner.git("-C", str(path), "rev-parse", "--path-format=absolute", "--git-common-dir")))
            git_dir = ordinary(Path(runner.git("-C", str(path), "rev-parse", "--absolute-git-dir")))
            require(beneath(common, self.root) and beneath(git_dir, self.root), "External Git metadata blocks fixture release.")
            common_dirs.add(common)
            for metadata in (common, git_dir):
                require(not (metadata / "objects/info/alternates").exists()
                        and not (metadata / "objects/info/http-alternates").exists(),
                        "Shared object storage or redirected common metadata blocks fixture release.")
            require(not (common / "commondir").exists(), "Redirected common Git metadata blocks fixture release.")
            blocks = runner.git("-C", str(path), "worktree", "list", "--porcelain", "-z").split("\0\0")
            registrations = []
            for block in blocks:
                fields: dict[str, str] = {}
                for line in block.split("\0"):
                    if line:
                        key, _, value = line.partition(" ")
                        fields[key] = value
                if not fields:
                    continue
                registered = ordinary(Path(fields["worktree"]))
                require(registered in paths and "locked" not in fields and "prunable" not in fields,
                        "Foreign, shared, locked, or missing fixture worktree blocks release.")
                registrations.append(str(registered))
            require(str(path) in registrations, "Unregistered Git metadata reference blocks fixture release.")
            result.append({"path": str(path), "common": str(common), "git_dir": str(git_dir), "registrations": registrations})
        for relative, entry in snapshot.items():
            path = self.root / relative
            require(not path.name.endswith(".lock") and path.name.casefold() != ".atlaso-local",
                    "Active Git lock or credential/recovery state blocks fixture release.")
            if path.name.casefold() == ".git":
                require(path.parent in paths, "Uninventoried nested Git repository blocks release.")
            # Ref backends differ (loose refs, packed refs, reftable). Treat even a partial
            # HEAD/object-store graph as repository metadata rather than assuming loose refs.
            if entry["directory"] and (path / "HEAD").exists() and (path / "objects").is_dir():
                require(path in common_dirs, "Uninventoried bare Git repository blocks release.")
        return result

    def inventory(self) -> dict[str, Any]:
        """Capture bounded content hashes as well as handle identities to detect restored timestamps."""
        snapshot = self.files.snapshot(self.root)
        total = 0
        for relative, entry in snapshot.items():
            if not entry["directory"]:
                payload = read_bounded_regular(self.root / relative, MAX_MANIFEST)
                total += len(payload)
                require(total <= MAX_MANIFEST, "Fixture contents exceed the bounded inventory limit.")
                entry["sha256"] = hashlib.sha256(payload).hexdigest()
        current = self.files.snapshot(self.root)
        require(current == {key: {field: value for field, value in item.items() if field != "sha256"}
                            for key, item in snapshot.items()}, "Fixture changed during inventory capture.")
        return snapshot

    def seal(self) -> Path:
        """Seal quiescent validation contents while retaining original root/repository identities."""
        with cleanup_lock(self.permitted, self.lock_id):
            self.original()
            snapshot = self.inventory()
            topology = self.topology(snapshot)
            require(snapshot == self.inventory(), "Fixture changed during Git topology inspection.")
            provenance = {str(self.receipt): hashlib.sha256(read_bounded_regular(self.receipt, MAX_MANIFEST)).hexdigest()}
            for index, _ in enumerate(self.repositories()):
                path = self.receipt.with_name(self.receipt.name + f".repo-{index:04d}")
                provenance[str(path)] = hashlib.sha256(read_bounded_regular(path, MAX_MANIFEST)).hexdigest()
            sealed = self.record(".sealed", {"binding": self.binding, "entries": snapshot, "topology": topology,
                                             "provenance": provenance})
            return self.record(".manifest", {"binding": self.binding, "sealed_sha256": hashlib.sha256(
                read_bounded_regular(sealed, MAX_MANIFEST)).hexdigest()})

    def inspect(self) -> dict[str, Any]:
        """Return fresh owning-tool evidence compatible with live resource.inspect."""
        self.original()
        manifest = self.load(".manifest")
        require(manifest.get("sealed_sha256") == hashlib.sha256(read_bounded_regular(
            self.receipt.with_name(self.receipt.name + ".sealed"), MAX_MANIFEST)).hexdigest(),
            "Sealed fixture inventory changed after manifest publication.")
        sealed = self.load(".sealed")
        for name, digest in sealed["provenance"].items():
            path = ordinary(Path(name))
            require(path.parent == self.receipt.parent and path.name.startswith(self.receipt.name)
                    and hashlib.sha256(read_bounded_regular(path, MAX_MANIFEST)).hexdigest() == digest,
                    "Original fixture creation provenance changed.")
        prepared_path = self.receipt.with_name(self.receipt.name + ".prepared")
        prepared = prepared_path.exists()
        if prepared:
            require(self.load(".prepared").get("sealed_sha256") == hashlib.sha256(
                read_bounded_regular(self.receipt.with_name(self.receipt.name + ".sealed"), MAX_MANIFEST)).hexdigest(),
                "Prepared fixture evidence differs from the sealed inventory.")
        absent = not self.root.exists()
        require(not absent or prepared, "Absent fixture lacks prepared release evidence.")
        if not absent:
            snapshot = self.inventory()
            expected = sealed["entries"]
            require(set(snapshot) <= set(expected) and (prepared or set(snapshot) == set(expected)),
                    "Fixture entries changed before release; preserve remaining data.")
            for relative, entry in snapshot.items():
                original = expected[relative]
                require(entry["identity"] == original["identity"] and entry["directory"] == original["directory"]
                        and (entry["directory"] or entry == original), "Fixture identity or contents changed.")
            if not prepared:
                require(self.topology(snapshot) == sealed["topology"], "Fixture Git registration graph changed.")
        absence_path = self.receipt.with_name(self.receipt.name + ".absent")
        require(not absence_path.with_name(absence_path.name + ".pending").exists(),
                "Pending fixture absence receipt requires reconciliation.")
        evidence_preserved = not absent
        if absence_path.exists():
            absence = self.load(".absent")
            require(absent and absence.get("absent") is True
                    and absence.get("removal_scopes") == [str(self.root)], "Fixture absence evidence is invalid.")
            evidence_preserved = True
        return {"ownership_verified": True, "inactive": True, "retained": False, "supported_cleanup": True,
                "evidence_preserved": evidence_preserved, "absent": absent, "removal_scopes": [str(self.root)]}

    def release(self, removal_scopes: list[str]) -> dict[str, bool]:
        """Release exact sealed handles, then preserve independently observed root absence.

        Args:
            removal_scopes: Exact scopes already verified by the live cleanup controller.
        """
        with cleanup_lock(self.permitted, self.lock_id):
            require(removal_scopes == [str(self.root)], "Fixture release scope differs from controller preflight.")
            inspected = self.inspect()
            prepared = self.receipt.with_name(self.receipt.name + ".prepared")
            if not prepared.exists():
                self.record(".prepared", {"binding": self.binding, "sealed_sha256": hashlib.sha256(
                    read_bounded_regular(self.receipt.with_name(self.receipt.name + ".sealed"), MAX_MANIFEST)).hexdigest()})
            if not inspected["absent"]:
                self.inspect()
                snapshot = self.files.snapshot(self.root)
                sealed = self.load(".sealed")["entries"]
                require(set(snapshot) <= set(sealed), "New fixture entries appeared before release.")
                expected = {relative: {**entry, "identity": sealed[relative]["identity"],
                                       "directory": sealed[relative]["directory"]} if entry["directory"] else sealed[relative]
                            for relative, entry in snapshot.items()}
                self.files.remove(self.root, expected)
            require(self.inspect()["absent"] is True, "Fixture absence readback failed.")
            absence = self.receipt.with_name(self.receipt.name + ".absent")
            if not absence.exists():
                self.record(".absent", {"binding": self.binding, "absent": True, "removal_scopes": removal_scopes})
            else:
                require(self.load(".absent").get("absent") is True, "Fixture absence evidence is invalid.")
            return {"success": True}

    def controller_call(self, operation: str, payload: dict[str, Any], resource: dict[str, Any]) -> dict[str, Any]:
        """Dispatch an independently approved exact resource through the live controller contract.

        Args:
            operation: Only resource.inspect or resource.release is supported.
            payload: Fresh nonce-bound controller request including its handoff digest and scopes.
            resource: Exact resource independently approved by the controller from originating-task evidence.
        """
        require(payload.get("resource") == resource and resource.get("kind") == "artifact"
                and resource.get("cleanup_tool") == TOOL
                and all(resource.get(key) == self.binding[key] for key in self.binding),
                "Controller resource differs from independently verified fixture provenance.")
        require(type(resource.get("pr")) is int and resource["pr"] > 0
                and isinstance(payload.get("handoff_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", payload["handoff_sha256"]), "Fixture PR/handoff binding is missing.")
        manifest = self.receipt.with_name(self.receipt.name + ".manifest")
        require(resource.get("ownership_manifest") == {"path": str(manifest), "sha256": hashlib.sha256(
            read_bounded_regular(manifest, 262144)).hexdigest()}, "Fixture ownership manifest differs from controller approval.")
        if operation == "resource.inspect":
            return self.inspect()
        require(operation == "resource.release", "Unsupported fixture owning-tool operation.")
        return self.release(payload.get("removal_scopes", []))
