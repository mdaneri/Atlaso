"""Native module-index derivation contract without a VM or host filesystem writes."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest


@pytest.mark.skipif(os.name != "posix", reason="Native kmod compatibility dispatcher")
def test_native_kmod_dispatch_uses_production_argv_without_mocking():
    """Exercise the actual compatibility dispatcher using the production prefix.

    Help exits before module discovery or writes. Keeping both production prefix
    arguments catches the invalid kmod-subcommand form as well as the correct
    executable-basename entry point. The descriptor and byte proof is covered by
    the independent native-tree fixtures.
    """
    executable = shutil.which("kmod")
    if executable is None:
        pytest.skip("Native kmod executable is not installed")
    source = Path("image/common/scripts/verify-photon-package-state.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    function = next(node for node in module.body if isinstance(node, ast.FunctionDef)
                    and node.name == "verify_installation_module_indexes")
    calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "run"
             and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"]
    assert len(calls) == 1 and isinstance(calls[0].args[0], ast.List)
    arguments = [ast.literal_eval(node) for node in calls[0].args[0].elts[:2]]
    result = subprocess.run(
        [*arguments, "--help"], executable=executable, check=False, timeout=10,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )
    assert result.returncode == 0 and not result.stderr
    assert 0 < len(result.stdout) <= 65536 and b"depmod" in result.stdout.lower()


@pytest.mark.skipif(os.name == "nt", reason="Native POSIX descriptor-relative filesystem operations")
@pytest.mark.parametrize("linked", [False, True])
def test_module_snapshot_uses_real_relative_descriptors(tmp_path, monkeypatch, linked):
    """Use real file descriptors with synthetic root ownership in an owned fixture.

    Args:
        tmp_path: Originally owned pytest output root.
        monkeypatch: Normalize only fixture ownership and original-input constants.
        linked: Add an unadmitted link to a private sibling fixture.
    """
    spec = importlib.util.spec_from_file_location("_real_module_fd_fixture", "image/common/scripts/verify-photon-package-state.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    root = tmp_path / "modules"
    (root / "dracut").mkdir(parents=True)
    payload = {"kernel.ko.xz": b"known module", "dracut/input.conf": b"public input"}
    for name, data in payload.items():
        (root / name).write_bytes(data)
    for name in verifier.INSTALLATION_MODULE_GENERATED:
        (root / name).write_bytes(b"" if name == "modules.devname" else b"public generated index")
    for path in [root, *root.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)
    if linked:
        private = tmp_path / "private.txt"
        private.write_bytes(b"private sibling fixture sentinel")
        (root / "unadmitted.ko.xz").symlink_to(private)
    rows = [["dracut", "d", 0o755, 0, "", "root", "root"]]
    rows += [[name, "f", 0o644, len(data), hashlib.sha256(data).hexdigest(), "root", "root"] for name, data in payload.items()]
    namespace = [row[:4] + [""] + row[5:] for row in rows]
    monkeypatch.setattr(verifier, "INSTALLATION_MODULE_INPUT_COUNT", 3)
    monkeypatch.setattr(verifier, "INSTALLATION_MODULE_INPUT_BYTES", 24)
    monkeypatch.setattr(verifier, "INSTALLATION_MODULE_INPUT_SHA256", hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest())
    monkeypatch.setattr(verifier, "INSTALLATION_MODULE_NAMESPACE_SHA256", hashlib.sha256(json.dumps(sorted(namespace), separators=(",", ":")).encode()).hexdigest())
    original_stat, original_fstat = os.stat, os.fstat
    fixture_inodes = {(path.lstat().st_dev, path.lstat().st_ino) for path in [root, *root.rglob("*")]}

    def owned(metadata):
        """Normalize only the owned synthetic fixture's UID/GID for this unit test.

        Args:
            metadata: Real native metadata to preserve except fixture ownership.
        """
        if (metadata.st_dev, metadata.st_ino) not in fixture_inodes:
            return metadata
        fields = {name: getattr(metadata, name) for name in verifier._INSTALLATION_STABLE_FIELDS}
        fields.update(st_uid=0, st_gid=0)
        return SimpleNamespace(**fields)

    def native_stat(*args, **kwargs):
        """Retain native descriptor-relative lookup and no-follow semantics.

        Args:
            *args: Native stat arguments.
            **kwargs: Native descriptor and link options.
        """
        return owned(original_stat(*args, **kwargs))

    reads = []
    original_read = verifier._read_installation_tmpfiles

    def read(path, mode, maximum_bytes, policy_name, *, directory_fd=None, allow_empty=False):
        """Observe and reuse the real nonblocking, no-follow bounded reader.

        Args:
            path: Public relative input name.
            mode: Required native permission bits.
            maximum_bytes: Existing reader's bound.
            policy_name: Fixed public diagnostic category.
            directory_fd: Retained parent descriptor.
            allow_empty: Explicit native index empty-file admission.
        """
        assert directory_fd is not None and not path.is_absolute()
        reads.append(str(path))
        return original_read(path, mode, maximum_bytes, policy_name, directory_fd=directory_fd, allow_empty=allow_empty)

    monkeypatch.setattr(os, "stat", native_stat)
    monkeypatch.setattr(os, "fstat", lambda descriptor: owned(original_fstat(descriptor)))
    monkeypatch.setattr(verifier, "_read_installation_tmpfiles", read)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if linked:
            with pytest.raises(ValueError, match="installation module"):
                verifier._installation_module_snapshot(descriptor)
            assert reads == []
        else:
            _stamps, indexes = verifier._installation_module_snapshot(descriptor)
            assert set(indexes) == verifier.INSTALLATION_MODULE_GENERATED
            assert len(reads) == 13
    finally:
        os.close(descriptor)


def _name(path):
    """Normalize fixture selectors while preserving live guest path semantics.

    Args:
        path: Public fixture pathname.
    """
    return str(path).replace("\\", "/")


class NativeTree:
    """Model retained descriptors as object references, independently of paths."""

    def __init__(self):
        """Create an isolated native directory and public binary fixture."""
        self.next_id = 900000
        self.root = self.node("/", "d", 0o755, 7)
        self.fds = {}
        self.reads = []
        self.snapshots = 0
        self.runs = 0
        self.input_state = 1
        self.change = ""
        self.stage = "/run/.atlaso-depmod-" + str(os.getpid())
        self.deleted = []
        self.real = {name: getattr(os, name) for name in ("open", "close", "fstat", "stat", "scandir", "mkdir", "readlink", "unlink", "rmdir")}
        for name in ("/usr", "/usr/bin", "/usr/lib", "/usr/lib/modules", "/usr/lib/modules/6.12.113-6.ph5",
                     "/etc", "/usr/local", "/usr/local/lib"):
            self.add(name, "d", 0o755)
        self.add("/run", "d", 0o755, device=9)
        self.add("/proc", "d", 0o555, device=10)
        self.add("/lib", "l", 0o777, target="usr/lib")
        self.add("/lib64", "l", 0o777, target="usr/lib")
        self.add("/usr/lib/libkmod.so.2", "l", 0o777, target="libkmod.so.2.5.1")
        self.add("/usr/bin/kmod", "f", 0o755, data=b"public native binary")
        self.add("/usr/lib/libkmod.so.2.5.1", "f", 0o755, data=b"public native library")

    def node(self, path, kind, mode, device, *, data=b"", target=""):
        """Create one object whose identity survives a pathname replacement.

        Args:
            path: Original absolute public fixture selector.
            kind: Directory, file or symbolic-link category.
            mode: Permission bits.
            device: Fixture filesystem identity.
            data: Public synthetic file bytes.
            target: Public synthetic symbolic-link target.
        """
        self.next_id += 1
        return SimpleNamespace(path=path, kind=kind, mode=mode, device=device, data=data, target=target,
                               inode=self.next_id, stamp=1, uid=0, gid=0, links=1, children={}, size=None)

    def lookup(self, path, parent=None):
        """Resolve a fixture selector through its retained parent object.

        Args:
            path: Relative or absolute public fixture selector.
            parent: Optional retained directory descriptor.
        """
        value = _name(path)
        capability = "/proc/" + str(os.getpid()) + "/fd/"
        if value.startswith(capability):
            descriptor, _, remainder = value[len(capability):].partition("/")
            current = self.fds[int(descriptor)]
            value = remainder
        else:
            current = self.root if value.startswith("/") or parent is None else self.fds[parent]
        for component in value.strip("/").split("/") if value.strip("/") else []:
            if current.kind != "d" or component not in current.children:
                raise FileNotFoundError("installation fixture absence")
            current = current.children[component]
        return current

    def add(self, path, kind, mode, *, data=b"", target="", device=None):
        """Publish one child only inside the isolated fixture tree.

        Args:
            path: Absolute public fixture selector.
            kind: Directory, file or symbolic-link category.
            mode: Native permission bits.
            data: Public synthetic file contents.
            target: Public symbolic-link target.
            device: Optional replacement filesystem identity.
        """
        value = PurePosixPath(_name(path))
        parent = self.lookup(value.parent)
        node = self.node(str(value), kind, mode, parent.device if device is None else device, data=data, target=target)
        parent.children[value.name] = node
        parent.stamp += 1
        return node

    def metadata(self, node):
        """Return complete object metadata used by the real verifier.

        Args:
            node: Retained fixture object.
        """
        kinds = {"d": stat.S_IFDIR, "f": stat.S_IFREG, "l": stat.S_IFLNK}
        size = 4096 if node.kind == "d" else len(node.target) if node.kind == "l" else len(node.data)
        return SimpleNamespace(st_dev=node.device, st_ino=node.inode, st_mode=kinds[node.kind] | node.mode,
                               st_uid=node.uid, st_gid=node.gid, st_nlink=(2 + sum(x.kind == "d" for x in node.children.values())) if node.kind == "d" else node.links,
                               st_size=size if node.size is None else node.size, st_mtime_ns=node.stamp,
                               st_ctime_ns=node.stamp, st_mtime=node.stamp, st_ctime=node.stamp)

    def native(self, path):
        """Identify only the fixed public native fixture namespace.

        Args:
            path: Candidate host or fixture selector.
        """
        value = _name(path)
        return value in {"/", "/usr", "/etc", "/run", "/proc", "/lib", "/lib64"} or value.startswith(("/usr/", "/etc/", "/run/", "/proc/" + str(os.getpid()) + "/fd/"))

    def open(self, path, flags, *args, dir_fd=None, **kwargs):
        """Open a modeled directory only with the real no-follow flags.

        Args:
            path: Public directory selector.
            flags: Native descriptor flags.
            *args: Ordinary host open arguments.
            dir_fd: Retained fixture parent descriptor.
            **kwargs: Ordinary host open options.
        """
        if dir_fd not in self.fds and not self.native(path):
            return self.real["open"](path, flags, *args, dir_fd=dir_fd, **kwargs)
        node = self.lookup(path, dir_fd)
        if ((self.change == "scratch-open-race" and node.path == self.stage)
                or (self.change == "scratch-child-open-race" and node.path == self.stage + "/usr")):
            parent = self.fds[dir_fd]
            node = self.node(node.path, "d", 0o700, 9)
            parent.children[_name(path)] = node
        if node.kind != "d" or not flags & os.O_NOFOLLOW or not flags & os.O_DIRECTORY:
            raise ValueError("installation no-follow directory refused")
        self.next_id += 1
        self.fds[self.next_id] = node
        return self.next_id

    def close(self, descriptor):
        """Release exactly one modeled or unrelated host descriptor.

        Args:
            descriptor: Retained descriptor.
        """
        if descriptor in self.fds:
            del self.fds[descriptor]
        else:
            self.real["close"](descriptor)

    def fstat(self, descriptor):
        """Observe the retained object rather than its current pathname.

        Args:
            descriptor: Modeled or unrelated host descriptor.
        """
        return self.metadata(self.fds[descriptor]) if descriptor in self.fds else self.real["fstat"](descriptor)

    def stat(self, path, *args, dir_fd=None, **kwargs):
        """Observe modeled leaves without following links or touching the host.

        Args:
            path: Public fixture or unrelated host selector.
            *args: Ordinary host stat arguments.
            dir_fd: Retained fixture parent descriptor.
            **kwargs: Ordinary host stat options.
        """
        if dir_fd in self.fds or self.native(path):
            return self.metadata(self.lookup(path, dir_fd))
        return self.real["stat"](path, *args, dir_fd=dir_fd, **kwargs)

    def scandir(self, path="."):
        """Yield a bounded modeled namespace through the retained directory.

        Args:
            path: Modeled descriptor or unrelated host path.
        """
        if path in self.fds:
            return contextlib.nullcontext(iter(SimpleNamespace(name=name) for name in self.fds[path].children))
        return self.real["scandir"](path)

    def mkdir(self, path, mode=0o777, *, dir_fd=None):
        """Create only a child of the owned modeled scratch root.

        Args:
            path: Relative scratch directory component.
            mode: Private directory permissions.
            dir_fd: Retained fixture parent descriptor.
        """
        if dir_fd in self.fds:
            parent = self.fds[dir_fd]
            assert (parent.path == "/run" or parent.path.startswith(self.stage)) and mode == 0o700
            name = _name(path)
            if name in parent.children:
                raise FileExistsError("installation fixture scratch collision")
            child = self.add(parent.path + "/" + name, "d", mode)
            if child.path == self.stage and self.change == "scratch-owner":
                child.uid = 1
            elif child.path == self.stage and self.change == "scratch-device":
                child.device = 8
        else:
            self.real["mkdir"](path, mode, dir_fd=dir_fd)

    def unlink(self, path, *, dir_fd=None):
        """Remove only an explicitly verified scratch child.

        Args:
            path: Fixed generated index name.
            dir_fd: Retained creation-owned parent descriptor.
        """
        if dir_fd not in self.fds:
            return self.real["unlink"](path, dir_fd=dir_fd)
        parent = self.fds[dir_fd]
        assert parent.path.startswith(self.stage + "/")
        name = _name(path)
        assert parent.children[name].kind == "f"
        self.deleted.append(parent.children.pop(name).path)
        parent.stamp += 1

    def rmdir(self, path, *, dir_fd=None):
        """Remove an empty original scratch directory, without recursion.

        Args:
            path: Single original directory component.
            dir_fd: Retained creation-owned parent descriptor.
        """
        if dir_fd not in self.fds:
            return self.real["rmdir"](path, dir_fd=dir_fd)
        parent = self.fds[dir_fd]
        name = _name(path)
        child = parent.children[name]
        assert child.path.startswith(self.stage) and child.kind == "d" and not child.children
        self.deleted.append(parent.children.pop(name).path)
        parent.stamp += 1

    def readlink(self, path, *args, dir_fd=None, **kwargs):
        """Read only a fixed native fixture alias.

        Args:
            path: Public fixture or unrelated host selector.
            *args: Ordinary host readlink arguments.
            dir_fd: Retained fixture parent descriptor.
            **kwargs: Ordinary host readlink options.
        """
        if dir_fd in self.fds:
            return self.lookup(path, dir_fd).target
        return self.real["readlink"](path, *args, dir_fd=dir_fd, **kwargs)


@pytest.mark.parametrize("change", [
    "", "empty-config", "recorded-mount", "capability", "unrecorded-mount", "nested-mount", "runtime-mount",
    "ancestor-mode", "ancestor-owner", "alias-target", "alias-owner", "binary", "library",
    "configuration", "configuration-after", "configuration-created", "inputs", "inputs-after",
    "index-after", "native-error", "native-stdout", "native-stderr", "native-timeout",
    "scratch-owner", "scratch-device", "output-extra", "output-missing", "output-bytes",
    "output-owner", "output-mode", "output-link", "output-filesystem", "output-limit",
    "output-read-race", "output-parent-replaced", "binary-after", "alias-after", "ancestor-after",
    "scratch-collision", "scratch-mount-before", "scratch-mount-after", "proc-mount-after",
    "mount-row-after", "layout-after", "cleanup-file-race", "cleanup-obstruction", "empty-native-index",
    "scratch-open-race", "scratch-child-open-race", "binary-mount", "config-mount", "library-mount-after",
])
def test_native_module_derivation_requires_exact_inputs_and_owned_output(change, monkeypatch, capsys):
    """Validate native execution, bounded output, drift and cleanup independently.

    Args:
        change: Independent public fixture fault.
        monkeypatch: Isolate native operations from every host or guest resource.
        capsys: Verify private fixture diagnostics never reach public output.
    """
    spec = importlib.util.spec_from_file_location("_module_derivation_fixture", "image/common/scripts/verify-photon-package-state.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    tree = NativeTree()
    tree.change = change
    module = "/usr/lib/modules/6.12.113-6.ph5"
    indexes = {name: b"public native index" for name in verifier.INSTALLATION_MODULE_GENERATED}
    if change == "empty-native-index":
        indexes["modules.devname"] = b""
    if change == "scratch-collision":
        tree.add(tree.stage, "d", 0o700)
        tree.add(tree.stage + "/private-retained", "f", 0o600, data=b"private retained sentinel")
    binaries = tuple((path, len(tree.lookup(path).data), hashlib.sha256(tree.lookup(path).data).hexdigest())
                     for path in ("/usr/bin/kmod", "/usr/lib/libkmod.so.2.5.1"))
    monkeypatch.setattr(verifier, "INSTALLATION_KMOD_FILES", binaries)
    if change == "ancestor-mode":
        tree.lookup("/usr/bin").mode = 0o777
    elif change == "ancestor-owner":
        tree.lookup("/usr/lib").uid = 1
    elif change == "alias-target":
        tree.lookup("/lib").target = "private"
    elif change == "alias-owner":
        tree.lookup("/usr/lib/libkmod.so.2").uid = 1
    elif change in {"binary", "library"}:
        tree.lookup(binaries[0 if change == "binary" else 1][0]).data = b"private changed binary"
    if change in {"empty-config", "configuration", "configuration-after"}:
        tree.add("/etc/depmod.d", "d", 0o755)
    if change == "configuration":
        tree.add("/etc/depmod.d/private.conf", "f", 0o644, data=b"private configuration sentinel")
    original_lstat = Path.lstat

    def lstat(path, *args, **kwargs):
        """Keep modeled native pathname observations separate from real paths.

        Args:
            path: Public fixture or unrelated host path.
            *args: Ordinary pathlib arguments.
            **kwargs: Ordinary pathlib options.
        """
        return tree.metadata(tree.lookup(path)) if tree.native(path) else original_lstat(path, *args, **kwargs)

    def snapshot(descriptor):
        """Reuse the independently tested immutable namespace snapshot seam.

        Args:
            descriptor: Retained native module root.
        """
        assert tree.fds[descriptor].path == module
        tree.snapshots += 1
        if change == "inputs":
            raise ValueError("installation original module input differs")
        actual = dict(indexes)
        if tree.snapshots > 1 and change == "index-after":
            actual[sorted(actual)[0]] = b"private changed index"
        if tree.snapshots > 1 and change == "cleanup-file-race":
            tree.lookup(tree.stage + "/usr/lib/modules/6.12.113-6.ph5/" + sorted(indexes)[0]).stamp += 1
        elif tree.snapshots > 1 and change == "cleanup-obstruction":
            tree.add(tree.stage + "/usr/lib/modules/6.12.113-6.ph5/private-retained", "f", 0o600)
        return {"input": (tree.input_state,)}, actual

    def read(path, mode, maximum_bytes, policy_name, *, directory_fd=None, allow_empty=False):
        """Supply public modeled bytes through the existing bounded reader seam.

        Args:
            path: Fixed public relative file.
            mode: Required native permissions.
            maximum_bytes: Explicit bounded read limit.
            policy_name: Fixed native policy category.
            directory_fd: Retained parent descriptor.
            allow_empty: Explicit native index empty-file admission.
        """
        assert directory_fd in tree.fds and policy_name in {"native kmod", "derived module index"}
        node = tree.lookup(path, directory_fd)
        if (node.kind != "f" or node.mode != mode or node.uid or node.gid or node.links != 1
                or not (0 if allow_empty else 1) <= len(node.data) <= maximum_bytes):
            raise ValueError("installation bounded fixture read refused")
        tree.reads.append(node.path)
        if change == "output-read-race" and policy_name == "derived module index":
            node.stamp += 1
        return node.data

    def run(arguments, **kwargs):
        """Exercise the exact native output-only command with no ambient secrets.

        Args:
            arguments: Fixed native argument vector.
            **kwargs: Explicit process isolation and bounds.
        """
        tree.runs += 1
        assert arguments[:7] == ["depmod", "-a", "-b", "/", "-m", "/usr/lib/modules", "-o"]
        assert tree.lookup(arguments[7]) is tree.lookup(tree.stage)
        assert arguments[8:] == ["-C", "/dev/null", "6.12.113-6.ph5"]
        assert kwargs == dict(executable="/usr/bin/kmod", cwd="/", env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"},
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=60, check=False, umask=0o022)
        if change == "native-timeout":
            raise subprocess.TimeoutExpired("private fixture command", 60)
        generated = tree.stage + "/usr/lib/modules/6.12.113-6.ph5"
        for name, data in indexes.items():
            tree.add(generated + "/" + name, "f", 0o644, data=data)
        selected = tree.lookup(generated + "/" + sorted(indexes)[0])
        if change == "output-extra":
            tree.add(generated + "/private-extra", "f", 0o644, data=b"private output sentinel")
        elif change == "output-missing":
            del tree.lookup(generated).children[sorted(indexes)[0]]
        elif change == "output-bytes":
            selected.data = b"private changed index"
        elif change == "output-owner":
            selected.uid = 1
        elif change == "output-mode":
            selected.mode = 0o600
        elif change == "output-link":
            selected.kind = "l"
            selected.target = "/private"
        elif change == "output-filesystem":
            selected.device = 8
        elif change == "output-limit":
            selected.size = 17 * 1024 * 1024
        elif change == "output-parent-replaced":
            parent = tree.lookup(tree.stage)
            parent.children["usr"] = tree.node(tree.stage + "/usr", "d", 0o700, 9)
        elif change == "binary-after":
            tree.lookup("/usr/bin/kmod").stamp += 1
        elif change == "alias-after":
            tree.lookup("/lib").stamp += 1
        elif change == "ancestor-after":
            tree.lookup("/usr/lib").stamp += 1
        elif change == "configuration-after":
            tree.add("/etc/depmod.d/private.conf", "f", 0o644, data=b"private configuration sentinel")
        elif change == "configuration-created":
            tree.add("/etc/depmod.d", "d", 0o755)
        elif change == "inputs-after":
            tree.input_state += 1
        elif change in {"scratch-mount-after", "proc-mount-after"}:
            mount = str(Path(tree.stage)) + "/usr" if change == "scratch-mount-after" else "/proc/" + str(os.getpid()) + "/fd"
            rows.append((["9", "0", "0:9", "/", mount], ["tmpfs", "tmpfs", "rw"]))
        elif change == "mount-row-after":
            rows[0][0][0] = "9"
        elif change == "library-mount-after":
            rows.append((["9", "0", "0:7", "/", "/usr/lib/libkmod.so.2.5.1"], ["ext4", "/dev/sda", "rw"]))
        return SimpleNamespace(returncode=int(change == "native-error"),
                               stdout=b"private output sentinel" if change == "native-stdout" else b"",
                               stderr=b"private error sentinel" if change == "native-stderr" else b"")

    for flag, value in (("O_NOFOLLOW", 0x20000), ("O_DIRECTORY", 0x10000), ("O_NONBLOCK", 0x800)):
        monkeypatch.setattr(os, flag, getattr(os, flag, value), raising=False)
    scan = tree.scandir
    monkeypatch.setattr(os, "supports_fd", set() if change == "capability" else {*os.supports_fd, scan})
    for name in ("open", "close", "fstat", "stat", "mkdir", "readlink", "unlink", "rmdir"):
        monkeypatch.setattr(os, name, getattr(tree, name))
    monkeypatch.setattr(os, "scandir", scan)
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(verifier, "_read_installation_tmpfiles", read)
    monkeypatch.setattr(verifier, "_installation_module_snapshot", snapshot)
    monkeypatch.setattr(verifier.subprocess, "run", run)
    recorded = ["/", "/usr"] if change == "recorded-mount" else ["/"]
    def layout():
        """Return the authenticated layout seam, with an independent drift fault."""
        return {"mounts": [{"target": item} for item in recorded],
                "changed": bool(change == "layout-after" and tree.runs)}
    monkeypatch.setattr(verifier, "_verified_installation_layout", layout)
    point = str(verifier.INSTALLATION_MODULE_ROOT) + "/private" if change == "nested-mount" else "/usr"
    rows = [(["2", "0", "0:9", "/", str(verifier.INSTALLATION_MODULE_RUN_ROOT)],
             ["ext4" if change == "runtime-mount" else "tmpfs", "tmpfs", "rw"]),
            (["3", "0", "0:10", "/", "/proc"], ["proc", "proc", "rw"])]
    if change in {"recorded-mount", "unrecorded-mount", "nested-mount"}:
        rows.append((["1", "0", "0:1", "/", point], []))
    if change in {"binary-mount", "config-mount"}:
        point = "/usr/bin/kmod" if change == "binary-mount" else "/etc/depmod.d"
        rows.append((["9", "0", "0:7", "/", point], ["ext4", "/dev/sda", "rw"]))
    if change == "scratch-mount-before":
        rows.append((["9", "0", "0:9", "/", str(Path(tree.stage))], ["tmpfs", "tmpfs", "rw"]))
    monkeypatch.setattr(verifier, "_installation_mount_rows", lambda: rows)
    if change in {"", "empty-config", "recorded-mount", "empty-native-index"}:
        assert verifier.verify_installation_module_indexes() == {"runtime_module_indexes_verified": True}
        assert tree.runs == 1 and tree.snapshots == 2
        assert len(tree.deleted) == 16
        assert Path(tree.stage).name not in tree.lookup("/run").children
    else:
        with pytest.raises(ValueError, match="installation") as error:
            verifier.verify_installation_module_indexes()
        assert "private" not in str(error.value)
        assert tree.deleted == []
        if change in {"scratch-collision", "cleanup-obstruction"}:
            retained = tree.stage + ("/private-retained" if change == "scratch-collision" else "/usr/lib/modules/6.12.113-6.ph5/private-retained")
            assert tree.lookup(retained).kind == "f"
    assert tree.fds == {}
    if change in {"capability", "unrecorded-mount", "nested-mount", "runtime-mount", "ancestor-mode",
                  "ancestor-owner", "alias-target", "alias-owner", "binary", "library", "configuration", "inputs"}:
        assert tree.runs == 0
    assert not any("depmod.d" in path for path in tree.reads)
    captured = capsys.readouterr()
    assert "private" not in captured.out and "private" not in captured.err
