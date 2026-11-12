"""Receipt internal redirect probes for the Photon build-state regression.

The existing PytestGitFixtures owner retains the ordinary Git graph. Redirects
are internal symbolic-link leaves with separate creation receipts; they are
removed through their original no-follow handles before that graph is sealed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Iterator

from scripts.completed_task_cleanup import beneath, require
from scripts.completed_task_files import WindowsFiles, cleanup_lock
from scripts.pytest_git_fixtures import PytestGitFixtures


@contextmanager
def original_root(owner: PytestGitFixtures) -> Iterator[WindowsFiles]:
    """Pin the original root without traversing its intentional redirect probes.

    Args:
        owner: Existing Git-fixture owner with original creation evidence.
    """
    files = WindowsFiles(allow_internal_symlinks=True)
    with files.ancestors(owner.root), files.opened(owner.root, directory=True) as (_, identity, _):
        require(list(identity) == owner.load()["root_identity"], "Original regression fixture root changed.")
        yield files


def create_link(owner: PytestGitFixtures, path: Path, target: Path) -> None:
    """Create and receipt one new internal symbolic link before test use.

    Args:
        owner: Original Git-fixture owner, not a cleanup-time replacement.
        path: New link strictly inside the owned root.
        target: Existing ordinary directory strictly inside the same root.
    """
    path, target = Path(os.path.abspath(path)), Path(os.path.abspath(target))
    require(beneath(path, owner.root) and beneath(target, owner.root), "Redirect probe must stay inside its fixture.")
    with cleanup_lock(owner.permitted, owner.lock_id), original_root(owner) as files:
        records = sorted(owner.receipt.parent.glob(owner.receipt.name + ".redirect-*"))
        require(len(records) < 4 and not owner.receipt.with_name(owner.receipt.name + ".sealed").exists(),
                "Redirect probes require an unsealed fixture and at most four original links.")
        with files.ancestors(path), files.ancestors(target), files.opened(target, directory=True):
            os.symlink(target, path, target_is_directory=True)
            with files.opened(path, directory=True, reparse=True) as (handle, identity, _):
                owner.record(f".redirect-{len(records):04d}", {
                    "binding": owner.binding, "path": str(path), "identity": list(identity),
                    "link_sha256": files.link_data(handle, path, owner.root),
                })


def seal(owner: PytestGitFixtures) -> Path:
    """Retire original redirect leaves, then seal the ordinary original Git graph.

    Args:
        owner: Original owner whose root and Git registrations must remain intact.
    """
    with cleanup_lock(owner.permitted, owner.lock_id), original_root(owner) as files, ExitStack() as stack:
        records = sorted(owner.receipt.parent.glob(owner.receipt.name + ".redirect-*"))
        require(len(records) == 4, "All four original redirect probes must be receipted before sealing.")
        handles = []
        paths = []
        for index, record in enumerate(records):
            require(record.name == owner.receipt.name + f".redirect-{index:04d}", "Redirect journal is incomplete.")
            value = owner.load(f".redirect-{index:04d}")
            path = Path(value["path"])
            require(value["binding"] == owner.binding and beneath(path, owner.root), "Redirect ownership changed.")
            stack.enter_context(files.ancestors(path))
            handle, identity, _ = stack.enter_context(files.opened(path, delete=True, directory=True, reparse=True))
            require(list(identity) == value["identity"] and files.link_data(handle, path, owner.root) == value["link_sha256"],
                    "Original redirect probe changed; preserve the fixture.")
            handles.append(handle)
            paths.append(path)
        # Pin all original links before the first deletion; never traverse targets.
        owner.record(".redirect-release", {"binding": owner.binding, "links": len(handles)})
        for handle in handles:
            files.dispose(handle)
    require(all(not os.path.lexists(path) for path in paths), "Redirect leaf absence is unproven.")
    return owner.seal()


def main() -> int:
    """Run only one creation-bound fixture operation selected by the regression."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("validate", "register", "link", "seal"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--path", type=Path)
    parser.add_argument("--target", type=Path)
    args = parser.parse_args()
    # The owner independently validates configuration and each receipt on use.
    from scripts.completed_task_files import read_bounded_regular

    creation = json.loads(read_bounded_regular(args.receipt, 65536))
    owner = PytestGitFixtures(args.config, args.receipt, creation["binding"])
    require(owner.binding["task_id"] == os.environ.get("CODEX_THREAD_ID"), "Regression belongs to another task.")
    if args.operation == "validate":
        require(args.path is not None and Path(os.path.abspath(args.path)) == owner.root,
                "Original fixture root does not match the regression selectors.")
        with original_root(owner):
            pass
    elif args.operation == "register":
        require(args.path is not None, "Original repository path is required.")
        owner.register(args.path)
    elif args.operation == "link":
        require(args.path is not None and args.target is not None, "Both redirect paths are required.")
        create_link(owner, args.path, args.target)
    else:
        manifest = seal(owner)
        print(json.dumps({"manifest": str(manifest), "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
