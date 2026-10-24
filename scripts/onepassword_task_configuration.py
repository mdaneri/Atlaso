"""Own creation-receipted task copies of Windows 1Password ciphertext configuration.

The live cleanup controller owns task/PR eligibility and process/downstream inactivity.
This owner checks the filesystem and original creation evidence without decrypting data.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from scripts.completed_task_cleanup import beneath, configured_root, ordinary, require
from scripts.completed_task_files import (
    FileRefusal,
    WindowsFiles,
    cleanup_lock,
    read_bounded_regular,
)
from scripts.pytest_git_fixtures import FixtureFiles, FixtureGit, publish

TOOL = "OnePasswordTaskConfiguration"
NAMES = ("onepassword-environment-id", "onepassword-service-account-token.dpapi")
ENVIRONMENT_SHA256 = "fe14b62fb2d23460202299784cb1080b9e0fcf202ed5d75b4843202cd68bdf06"


class ConfigurationFiles(FixtureFiles):
    """Check restrictive ACLs on pinned objects and never read plaintext credentials."""

    security: Any
    sid: str

    def __init__(self) -> None:
        """Bind the Windows security APIs used only by this configuration owner."""
        if sys.platform != "win32":
            raise FileRefusal("Task configuration ownership requires Windows security and handle APIs.")
        super().__init__()
        self.security = ctypes.WinDLL("advapi32", use_last_error=True)
        pointer = ctypes.c_void_p
        self.security.GetSecurityInfo.argtypes = [
            pointer, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(pointer), pointer,
            ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer),
        ]
        self.security.GetSecurityInfo.restype = ctypes.c_uint32
        self.security.GetSecurityDescriptorControl.argtypes = [
            pointer, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_uint32),
        ]
        self.security.GetAclInformation.argtypes = [pointer, pointer, ctypes.c_uint32, ctypes.c_int]
        self.security.GetAce.argtypes = [pointer, ctypes.c_uint32, ctypes.POINTER(pointer)]
        self.security.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(ctypes.c_wchar_p)]
        self.security.OpenProcessToken.argtypes = [pointer, ctypes.c_uint32, ctypes.POINTER(pointer)]
        self.security.GetTokenInformation.argtypes = [
            pointer, ctypes.c_int, pointer, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
        ]
        self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(pointer), pointer,
        ]
        self.security.SetFileSecurityW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, pointer]
        self.kernel.GetCurrentProcess.restype = pointer
        self.kernel.LocalFree.argtypes = [pointer]
        self.kernel.LocalFree.restype = pointer
        token = pointer()
        require(self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)),
                "Cannot verify current Windows identity.")
        try:
            size = ctypes.c_uint32()
            self.security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            require(self.security.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)),
                    "Cannot verify current Windows identity.")
            self.sid = self.sid_text(ctypes.cast(buffer, ctypes.POINTER(pointer))[0])
        finally:
            self.kernel.CloseHandle(token)

    def sid_text(self, sid: Any) -> str:
        """Convert a security identifier, freeing only the API's allocated string.

        Args:
            sid: SID pointer inside a live token, descriptor, or ACL allocation.
        """
        value = ctypes.c_wchar_p()
        require(self.security.ConvertSidToStringSidW(sid, ctypes.byref(value)), "Cannot inspect configuration ACL identity.")
        try:
            return str(value.value)
        finally:
            self.kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))

    def restrict(self, path: Path) -> None:
        """Protect a newly created empty object before writing any ciphertext.

        Args:
            path: Exact object just created exclusively by this invocation.
        """
        descriptor = ctypes.c_void_p()
        sddl = f"O:{self.sid}D:P(A;;FA;;;{self.sid})(A;;FA;;;SY)"
        require(self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None), "Cannot prepare restrictive configuration ACL.")
        try:
            require(self.security.SetFileSecurityW(str(path), 0x80000004, descriptor),
                    "Cannot protect new configuration; preserve it for reconciliation.")
        finally:
            self.kernel.LocalFree(descriptor)

    def created_entry(self, descriptor: int, data: bytes) -> dict[str, Any]:
        """Record the original file identity through its still-open creation descriptor.

        Args:
            descriptor: Descriptor opened exclusively for this new ciphertext copy.
            data: Selector or ciphertext bytes just flushed, used only for their digest.
        """
        if sys.platform != "win32":
            raise FileRefusal("Configuration creation identity requires Windows file handles.")
        import msvcrt

        information = (ctypes.c_uint32 * 13)()
        require(self.kernel.GetFileInformationByHandle(msvcrt.get_osfhandle(descriptor), information)
                and not information[0] & (0x10 | 0x400) and information[10] == 1,
                "Cannot receipt the original configuration file identity.")
        return {"identity": [information[7], information[11], information[12]],
                "stamp": [information[5], information[6], information[8], information[9]],
                "directory": False, "sha256": hashlib.sha256(data).hexdigest()}

    def acl(self, handle: int) -> None:
        """Verify ownership, protected inheritance, and only user/SYSTEM allow ACEs.

        Args:
            handle: No-follow READ_CONTROL handle pinned against replacement and writers.
        """
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        require(self.security.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None,
                                             ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0,
                "Cannot inspect pinned configuration security.")
        try:
            control, revision = ctypes.c_ushort(), ctypes.c_uint32()
            require(self.security.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision))
                    and control.value & 0x1000 and self.sid_text(owner) == self.sid and dacl.value,
                    "Configuration must be current-user owned with inherited access disabled.")
            information = (ctypes.c_uint32 * 3)()
            require(self.security.GetAclInformation(dacl, information, ctypes.sizeof(information), 2)
                    and 0 < information[0] <= 32, "Configuration requires a bounded restrictive ACL.")
            readers = set()
            for index in range(information[0]):
                ace = ctypes.c_void_p()
                require(self.security.GetAce(dacl, index, ctypes.byref(ace)), "Cannot inspect configuration ACL.")
                address = ace.value
                if address is None:
                    raise RuntimeError("Configuration ACL entry has no address.")
                header = (ctypes.c_ubyte * 4).from_address(address)
                require(header[0] == 0 and not header[1] & 0x10,
                        "Unsupported or inherited configuration ACL rule.")
                sid = self.sid_text(address + 8)
                require(sid in {self.sid, "S-1-5-18"}, "Configuration grants access outside current user and SYSTEM.")
                mask = ctypes.c_uint32.from_address(address + 4).value
                if mask & (1 | 0x80000000 | 0x10000000):
                    readers.add(sid)
            require(readers == {self.sid, "S-1-5-18"}, "Current user and SYSTEM must both have configuration read access.")
        finally:
            self.kernel.LocalFree(descriptor)

    def inventory(self, root: Path) -> dict[str, Any]:
        """Read only the fixed configuration pair; extra runtime/recovery state blocks release.

        Args:
            root: Exact task-local configuration root.
        """
        with self.ancestors(root), self.opened(root, directory=True, read_security=True) as (handle, identity, _stamp):
            self.acl(handle)
            require({child.name for child in root.iterdir()} <= set(NAMES),
                    "Additional configuration, active state, or credential recovery residue blocks cleanup.")
            entries: dict[str, Any] = {".": {"identity": list(identity), "directory": True}}
            for name in NAMES:
                path = root / name
                if not os.path.lexists(path):
                    continue
                with self.opened(path, read_security=True) as (handle, identity, stamp):
                    self.acl(handle)
                    size = path.stat().st_size
                    require((1 <= size <= 1024) if name == NAMES[0] else (32 <= size <= 65536),
                            "Configuration size is outside the supported bound.")
                    entries[name] = {"identity": list(identity), "stamp": list(stamp),
                                     "directory": False, "sha256": self.digest(handle)}
            return entries

    def remove_configuration(self, root: Path, expected: dict[str, Any]) -> None:
        """Pin and verify every remaining original object before disposing any of them.

        Args:
            root: Exact receipted .atlaso-local directory.
            expected: Remaining creation-bound identities and ciphertext hashes.
        """
        with self.ancestors(root), ExitStack() as stack:
            pinned = {}
            for name, entry in expected.items():
                owner = ExitStack()
                stack.callback(owner.close)
                handle, identity, stamp = owner.enter_context(self.opened(
                    root / name, delete=True, directory=entry["directory"], read_security=True))
                self.acl(handle)
                require(list(identity) == entry["identity"] and
                        (entry["directory"] or (list(stamp) == entry["stamp"] and self.digest(handle) == entry["sha256"])),
                        "Configuration changed before pinned release.")
                pinned[name] = (handle, owner)
            require({child.name for child in root.iterdir()} == set(expected) - {"."},
                    "New configuration or recovery state appeared before release.")
            for name in [*sorted(set(expected) - {"."}), "."]:
                handle, owner = pinned[name]
                # Ordinary disposition refuses open consumers and nonempty directories.
                WindowsFiles.dispose(self, handle)
                owner.close()
                require(not os.path.lexists(root / name), "Configuration absence readback failed.")


class OnePasswordTaskConfiguration:
    """Create and release only receipted task copies through the configuration contract."""

    def __init__(self, config: Path, receipt: Path, binding: dict[str, Any]) -> None:
        """Bind independent task, repository, creation commit, and exact configuration path.

        Args:
            config: Active supported Codex config.toml.
            receipt: New external durable creation receipt, never beneath the worktree.
            binding: Exact id, task_id, repository, source_commit, and path approved by the caller.
        """
        self.permitted = configured_root(config)
        self.receipt = ordinary(receipt)
        self.binding = dict(binding)
        require(set(binding) == {"id", "task_id", "repository", "source_commit", "path"}
                and all(isinstance(value, str) and 0 < len(value) <= 1024 for value in binding.values())
                and re.fullmatch(r"[0-9a-f]{40}", binding["source_commit"])
                and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", binding["repository"]),
                "Invalid configuration task/resource binding.")
        self.root = ordinary(Path(binding["path"]))
        self.worktree = self.root.parent
        require(self.root.name == ".atlaso-local" and beneath(self.worktree, self.permitted)
                and beneath(receipt, self.permitted) and not receipt.is_relative_to(self.worktree),
                "Configuration/evidence containment is unproven.")
        require(not self.worktree.is_relative_to(self.receipt.parent),
                "Configuration receipts must use a separate evidence directory outside checkout ancestors.")
        require(self.receipt.parent.is_dir(), "Configuration receipt directory must already exist.")
        require(not {".git", ".atlaso-local"} & {
            part.casefold() for path in (self.worktree, self.receipt) for part in path.relative_to(self.permitted).parts
        }, "Configuration worktree and evidence must not be nested in Git or credential/recovery state.")
        self.files = ConfigurationFiles()
        self.lock_id = hashlib.sha256(str(self.root).casefold().encode()).hexdigest()

    def stage(self, suffix: str) -> Path:
        """Derive a fixed receipt-stage path outside the removal scope.

        Args:
            suffix: Fixed creation, prepared, or absence suffix.
        """
        return self.receipt.with_name(self.receipt.name + suffix)

    def load(self, suffix: str = "") -> dict[str, Any]:
        """Read immutable bounded provenance, refusing incomplete publication.

        Args:
            suffix: Exact receipt-stage suffix.
        """
        path = self.stage(suffix)
        require(not path.with_name(path.name + ".pending").exists(), "Pending configuration receipt requires reconciliation.")
        value = json.loads(read_bounded_regular(ordinary(path), 262144))
        require(isinstance(value, dict) and value.get("schema") == 1 and value.get("binding") == self.binding,
                "Configuration receipt differs from independent creation provenance.")
        return dict(value)

    def record(self, suffix: str, **value: Any) -> None:
        """Publish new non-secret evidence without replacing previous stages.

        Args:
            suffix: Fixed receipt stage.
            **value: Sanitized identities, hashes, or absence evidence.
        """
        publish(self.stage(suffix), {"schema": 1, "binding": self.binding, **value})

    def git_identity(self) -> Path:
        """Independently discover the primary and verify the exact registered task checkout."""
        runner = FixtureGit(self.worktree)
        common = ordinary(Path(runner.git("rev-parse", "--path-format=absolute", "--git-common-dir")))
        primary = common.parent
        require(common.name == ".git" and primary != self.worktree
                and ordinary(Path(runner.git("rev-parse", "--show-toplevel"))) == self.worktree,
                "Primary or task checkout identity is unproven.")
        registrations = runner.git("worktree", "list", "--porcelain", "-z").split("\0\0")
        require(any(block.startswith(f"worktree {self.worktree.as_posix()}\0") for block in registrations)
                and any(block.startswith(f"worktree {primary.as_posix()}\0") for block in registrations),
                "Primary or task worktree is not registered.")
        urls = runner.git("remote", "get-url", "--all", "origin").splitlines()
        require(urls == [f"https://github.com/{self.binding['repository']}.git"],
                "Repository binding differs from the configuration source.")
        runner.git("merge-base", "--is-ancestor", self.binding["source_commit"], "HEAD")
        return primary

    def copy_from_primary(self) -> dict[str, str]:
        """Exclusively create the supported pair and receipt original identities before use."""
        with cleanup_lock(self.permitted, self.lock_id):
            primary = self.git_identity()
            require(not primary.is_relative_to(self.receipt.parent),
                    "Configuration receipts must use a separate evidence directory outside primary checkout ancestors.")
            require(not os.path.lexists(self.root) and not any(
                path.name.casefold().startswith(self.receipt.name.casefold()) for path in self.receipt.parent.iterdir()),
                    "Copy requires new configuration and receipt paths; never adopt or replace existing state.")
            source = ordinary(primary / ".atlaso-local")
            with self.files.ancestors(source), ExitStack() as stack:
                source_handle, _identity, _stamp = stack.enter_context(self.files.opened(
                    source, directory=True, read_security=True))
                self.files.acl(source_handle)
                source_entries = {}
                for name in NAMES:
                    handle, identity, _stamp = stack.enter_context(self.files.opened(
                        source / name, read_security=True))
                    self.files.acl(handle)
                    data = read_bounded_regular(source / name, 1024 if name == NAMES[0] else 65536)
                    if name == NAMES[0]:
                        selector = data.decode("utf-8").strip()
                        require(len(data.decode("utf-8").splitlines()) == 1
                                and hashlib.sha256(selector.encode()).hexdigest() == ENVIRONMENT_SHA256,
                                "Source selector does not identify the pinned Atlaso Environment.")
                    else:
                        require(32 <= len(data) <= 65536, "Source ciphertext size is outside the supported bound.")
                    source_entries[name] = (data, list(identity))
                runner = FixtureGit(self.worktree)
                for name in NAMES:
                    for checkout, path in ((self.worktree, self.root / name), (primary, source / name)):
                        require(runner.git("-C", str(checkout), "check-ignore", "--", str(path)),
                                "Source and task configuration must be Git ignored.")
                        require(not runner.git("-C", str(checkout), "ls-files", "--", str(path)),
                                "Tracked configuration is forbidden.")
                with self.files.ancestors(self.root):
                    self.root.mkdir()
                    self.files.restrict(self.root)
                    with self.files.opened(self.root, directory=True) as (_handle, identity, _stamp):
                        info = self.worktree.stat()
                        self.record("", root_identity=list(identity), worktree_identity=[info.st_dev, info.st_ino],
                                    primary=str(primary), source_identities={key: item[1] for key, item in source_entries.items()})
                        expected = {".": {"identity": list(identity), "directory": True}}
                        for name, (data, _identity) in source_entries.items():
                            # Record through the original creation handle before any file can be
                            # replaced; sealing must match these identities and the source bytes.
                            with (self.root / name).open("xb") as stream:
                                self.files.restrict(self.root / name)
                                stream.write(data)
                                stream.flush()
                                os.fsync(stream.fileno())
                                expected[name] = self.files.created_entry(stream.fileno(), data)
                        entries = self.files.inventory(self.root)
                        require(entries == expected, "Configuration changed during copy; preserve creation evidence.")
                        self.record(".sealed", entries=entries, creation_sha256=hashlib.sha256(
                            read_bounded_regular(self.receipt, 262144)).hexdigest())
            return {"path": str(self.stage(".sealed")), "sha256": hashlib.sha256(
                read_bounded_regular(self.stage(".sealed"), 262144)).hexdigest()}

    @contextmanager
    def pinned_worktree(self) -> Iterator[None]:
        """Keep the checkout or nearest surviving ancestor pinned during recovery checks."""
        existing = ordinary(self.worktree)
        while not existing.exists():
            existing = existing.parent
        with self.files.ancestors(existing / "unused-pin-leaf"):
            yield

    def inspect(self) -> dict[str, Any]:
        """Verify original identities, safe partial-release recovery, and exact removal scope."""
        with self.pinned_worktree():
            return self.inspect_pinned()

    def inspect_pinned(self) -> dict[str, Any]:
        """Check configuration receipts while checkout ancestors remain pinned."""
        creation, sealed = self.load(), self.load(".sealed")
        require(sealed.get("creation_sha256") == hashlib.sha256(read_bounded_regular(self.receipt, 262144)).hexdigest()
                and sealed["entries"]["."]["identity"] == creation["root_identity"]
                and set(sealed["entries"]) == {".", *NAMES}, "Invalid original configuration inventory.")
        if self.worktree.exists():
            info = self.worktree.stat()
            require([info.st_dev, info.st_ino] == creation["worktree_identity"], "Task checkout creation identity changed.")
            require(self.git_identity() == Path(creation["primary"]), "Primary configuration binding changed.")
        prepared = self.stage(".prepared").exists()
        require(not self.stage(".prepared.pending").exists() and not self.stage(".absent.pending").exists(),
                "Pending configuration release evidence requires reconciliation.")
        if prepared:
            require(self.load(".prepared").get("sealed_sha256") == hashlib.sha256(
                read_bounded_regular(self.stage(".sealed"), 262144)).hexdigest(), "Prepared configuration inventory changed.")
        absent = not os.path.lexists(self.root)
        require(prepared or not absent, "Unprepared configuration absence cannot establish release.")
        if not absent:
            require(not self.stage(".absent").exists(), "Released configuration reappeared; preserve it.")
            current = self.files.inventory(self.root)
            require(set(current) <= set(sealed["entries"]) and (prepared or set(current) == set(sealed["entries"])),
                    "Configuration disappeared without a prepared release.")
            require(all(entry == sealed["entries"].get(name) for name, entry in current.items()),
                    "Configuration identity or bytes changed; preserve it.")
        if self.stage(".absent").exists():
            require(self.load(".absent").get("absent") is True and absent, "Invalid configuration absence receipt.")
        return {"ownership_verified": True, "inactive": True, "retained": False, "supported_cleanup": True,
                "evidence_preserved": True, "absent": absent, "removal_scopes": [str(self.root)]}

    def release(self, removal_scopes: list[str]) -> dict[str, bool]:
        """Release a freshly controller-approved inactive copy through exact Windows handles.

        Args:
            removal_scopes: Exact scope independently approved by the live cleanup controller.
        """
        with cleanup_lock(self.permitted, self.lock_id), self.pinned_worktree():
            require(removal_scopes == [str(self.root)], "Configuration release scope differs from controller preflight.")
            inspected = self.inspect()
            if not self.stage(".prepared").exists():
                self.record(".prepared", sealed_sha256=hashlib.sha256(
                    read_bounded_regular(self.stage(".sealed"), 262144)).hexdigest())
            if not inspected["absent"]:
                self.inspect()
                current = self.files.inventory(self.root)
                expected = {name: self.load(".sealed")["entries"][name] for name in current}
                require(current == expected, "Configuration changed before final release.")
                self.files.remove_configuration(self.root, expected)
            require(self.inspect()["absent"], "Configuration release absence is unproven.")
            if not self.stage(".absent").exists():
                self.record(".absent", absent=True)
            return {"success": True}

    def controller_call(self, operation: str, payload: dict[str, Any], resource: dict[str, Any]) -> dict[str, Any]:
        """Adapt a resource approved independently for ownership, inactivity, and retention.

        Args:
            operation: resource.inspect or resource.release from completed-task cleanup.
            payload: Fresh request containing exact resource, handoff digest, and release scopes.
            resource: Controller-approved configuration resource, including PR and original manifest.
        """
        require(payload.get("resource") == resource and resource.get("kind") == "configuration"
                and resource.get("cleanup_tool") == TOOL
                and all(resource.get(key) == value for key, value in self.binding.items()),
                "Controller configuration differs from independently verified provenance.")
        require(type(resource.get("pr")) is int and resource["pr"] > 0
                and isinstance(payload.get("handoff_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", payload["handoff_sha256"]), "Configuration PR/handoff binding is missing.")
        require(resource.get("ownership_manifest") == {"path": str(self.stage(".sealed")), "sha256": hashlib.sha256(
            read_bounded_regular(self.stage(".sealed"), 262144)).hexdigest()}, "Configuration manifest differs from approval.")
        if operation == "resource.inspect":
            return self.inspect()
        require(operation == "resource.release", "Unsupported configuration owning-tool operation.")
        return self.release(payload.get("removal_scopes", []))
