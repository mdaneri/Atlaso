#!/usr/bin/env python3
"""Preview or reconcile completed task cleanup using a live JSON-lines controller."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import stat
import subprocess
import sys
import threading
import tomllib
import uuid
from pathlib import Path

from scripts.completed_task_files import (
    FileRefusal,
    WindowsFiles,
    cleanup_lock,
    ensure_durable_directory,
    publish_durable_file,
    read_bounded_regular,
    sync_directory,
)
from scripts.completed_task_process import contained_child
from scripts.completed_task_title import (
    completed_task_title,
    verify_completed_task_title,
)

MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_CHILD_BYTES = 4 * 1024 * 1024
CHILD_TIMEOUT = 90


class Refusal(RuntimeError):
    """A failed gate whose remaining resources must be preserved."""


def require(condition: object, message: str) -> None:
    """Fail closed with a bounded, caller-authored diagnostic.

    Args:
        condition: Gate expression that must be truthy to continue.
        message: Sanitized refusal diagnostic for a failed gate.
    """
    if not condition:
        raise Refusal(message)


def ordinary(path: Path) -> Path:
    """Reject relative paths, aliases, links, and reparse ancestors, including absent retries.

    Args:
        path: Filesystem path examined by this operation.
    """
    require(path.is_absolute(), "Supply an absolute path.")
    require(not any(part in {".", ".."} for part in path.parts), "Path traversal is forbidden.")
    if os.name == "nt":
        require(not str(path).startswith(("\\\\?\\", "\\\\.\\"))
                and not os.path.isreserved(str(path))
                and not any(part.endswith((".", " ")) or re.search(r"~[0-9]", part) for part in path.parts[1:]),
                "Win32-normalized path aliases are forbidden; supply the ordinary long path.")
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "Reparse points and symbolic links block cleanup.")
    return path


def read_handoff(path: Path) -> bytes:
    """Reject special or oversized input before opening and bound the actual read as well.

    Args:
        path: Filesystem path examined by this operation.
    """
    info = ordinary(path).stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 262144,
            "Handoff must be a bounded regular single-link file.")
    return read_bounded_regular(path, 262144)


def beneath(path: Path, root: Path) -> bool:
    """Compare complete canonical path components rather than string prefixes.

    Args:
        path: Filesystem path examined by this operation.
        root: Root directory that bounds the filesystem operation.
    """
    return path != root and path.is_relative_to(root)


def configured_root(config: Path) -> Path:
    """Read the supported desktop setting without inventing a default root.

    Args:
        config: Active Codex configuration path used to resolve the permitted worktree root.
    """
    active_config = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "config.toml"
    require(config == active_config, "Config must be the active CODEX_HOME/config.toml, not a handoff-supplied alternate.")
    desktop = tomllib.loads(read_bounded_regular(ordinary(config), 1024 * 1024).decode("utf-8")).get("desktop", {})
    require(isinstance(desktop, dict), "desktop must be a TOML table; repair the active configuration before retry.")
    value = desktop.get("git-worktree-root")
    require(isinstance(value, str) and value.strip(), "desktop.git-worktree-root is missing; configure it first.")
    root = ordinary(Path(value))
    require(root.is_dir() and root != Path(root.anchor), "Configured worktree root is unavailable or unsafe.")
    return root


class Controller:
    """Require fresh nonce-bound responses from supported tools, never a saved preview."""

    def call(self, operation: str, payload: dict) -> dict:
        """Emit one request and bound the wait for its matching live response.

        Args:
            operation: Named controller operation requested by the cleanup protocol.
            payload: Structured request fields bound to the current cleanup handoff.
        """
        request_id = str(uuid.uuid4())
        print(json.dumps({"kind": "controller_request", "id": request_id,
                          "operation": operation, "payload": payload}), flush=True)
        inbox: queue.Queue[str] = queue.Queue()
        threading.Thread(target=lambda: inbox.put(sys.stdin.readline(262145)), daemon=True).start()
        try:
            line = inbox.get(timeout=120)
        except queue.Empty as exc:
            raise Refusal("Controller response timed out; rerun with a live controller.") from exc
        require(0 < len(line) <= 262144, "Controller response missing or oversized.")
        response = json.loads(line)
        require(isinstance(response, dict), "Controller response must be a JSON object; retry with the live controller.")
        require(response.get("id") == request_id, "Controller response does not match the fresh request.")
        require(response.get("error") is None, "Controller refused the operation; preserve resources and inspect controller evidence.")
        result = response.get("result")
        require(isinstance(result, dict), "Controller must return a structured result.")
        return result


class Cleanup:
    """Own ordered cleanup transitions while keeping external task controls in the controller."""

    def __init__(self, handoff: Path, evidence: Path, config: Path, execute: bool,
                 controller: Controller) -> None:
        """Bind immutable handoff bytes and a durable evidence directory outside the target.

        Args:
            handoff: Path to the immutable task handoff JSON document.
            evidence: Durable evidence directory outside the worktree scheduled for removal.
            config: Active Codex configuration path used to resolve the permitted worktree root.
            execute: Whether to perform eligible transitions rather than return a read-only preview.
            controller: Live bridge providing independently verified task and resource observations.
        """
        self.execute = execute
        self.controller = controller
        raw = read_handoff(handoff)
        self.digest = hashlib.sha256(raw).hexdigest()
        self.handoff = json.loads(raw)
        self.handoff_path = handoff
        require(isinstance(self.handoff, dict) and set(self.handoff) == {
            "schema", "primary_checkout", "worktree", "worktree_identity", "branch", "head", "merge",
            "repository", "pr", "issues", "resources", "task_id", "description", "task_title"},
            "Handoff fields differ from the bounded sanitized schema.")
        self.repo = ordinary(Path(self.handoff["primary_checkout"]))
        self.target = ordinary(Path(self.handoff["worktree"]))
        self.verify_primary_controller()
        self.root = configured_root(config)
        self.config = config
        self.evidence = ordinary(evidence)
        require(beneath(self.target, self.root), "Target is outside the configured worktree root.")
        require(beneath(evidence, self.root) and not evidence.is_relative_to(self.target),
                "Evidence must survive outside the target, beneath the configured root.")
        require(beneath(handoff, self.root) and not handoff.is_relative_to(self.target),
                "Preserve the handoff outside the target, beneath the configured root first.")
        require(self.handoff.get("schema") == 1, "Unsupported handoff schema.")
        self.branch = self.handoff["branch"]
        require(isinstance(self.branch, str), "Branch must be a string containing the exact task-owned ref.")
        self.head = self.handoff["head"]
        self.merge = self.handoff["merge"]
        self.repository = self.handoff["repository"]
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository), "Invalid repository identity.")
        require(all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (self.head, self.merge)), "Full commit SHAs are required.")
        require(self.branch not in {"main", "gh-pages"} and not self.branch.startswith("-"), "Protected branch target.")
        require(not self.branch.endswith("/") and "*" not in self.branch, "An exact branch ref is required.")
        require(type(self.handoff["pr"]) is int and self.handoff["pr"] > 0, "Exact positive PR identity required.")
        require(isinstance(self.handoff["task_id"], str) and 0 < len(self.handoff["task_id"]) <= 512,
                "A bounded exact task identity is required.")
        # Evidence remains byte-bound, but alternate handoff serializations must share exclusion.
        lock_identity = ["github.com", self.repository.lower(), self.handoff["task_id"], self.handoff["pr"]]
        self.lock_digest = hashlib.sha256(json.dumps(lock_identity, separators=(",", ":")).encode("utf-8")).hexdigest()
        require(isinstance(self.handoff["resources"], list) and len(self.handoff["resources"]) <= 100,
                "A bounded validation resource inventory is required, including an explicit empty list.")
        self.gates: list[str] = []
        self.proposed: list[dict] = []
        self.resource_evidence: list[dict] = []
        require(isinstance(self.handoff["task_title"], str) and 0 < len(self.handoff["task_title"]) <= 512,
                "A bounded recorded current task title is required.")
        require(isinstance(self.handoff["description"], str), "Task description must be a string.")
        try:
            self.expected_title = completed_task_title(self.handoff["description"], self.handoff["issues"], [self.handoff["pr"]])
        except ValueError as exc:
            raise Refusal(str(exc)) from exc
        self.restore_gates()

    def restore_gates(self) -> None:
        """Recover a single monotonic journal history before permitting any retry transition."""
        require(not list(self.evidence.glob(f"{self.digest}-*.pending")),
                "An incomplete journal write requires independent evidence reconciliation before retry.")
        records = list(self.evidence.glob(f"{self.digest}-*.json"))
        require(len(records) <= 1000, "Oversized cleanup journal; reconcile evidence before retry.")
        if records:
            # A rename may be visible after its directory fsync failed in the previous process.
            sync_directory(ordinary(self.evidence))
        histories = []
        for path in records:
            ordinary(path)
            record = json.loads(read_bounded_regular(path, MAX_EVIDENCE_BYTES))
            require(isinstance(record, dict) and record.get("handoff_sha256") == self.digest
                    and record.get("task_id") == self.handoff["task_id"]
                    and isinstance(record.get("gates"), list) and all(isinstance(gate, str) for gate in record["gates"])
                    and isinstance(record.get("resource_evidence"), list), "Invalid cleanup journal binding.")
            histories.append(record)
        histories.sort(key=lambda record: len(record["gates"]))
        for record in histories:
            require(record["gates"][:len(self.gates)] == self.gates, "Conflicting cleanup journal histories; reconcile evidence.")
            self.gates = record["gates"]
            self.resource_evidence = record["resource_evidence"]
        for item in self.resource_evidence:
            if isinstance(item, dict) and "evidence_file" in item:
                require(set(item) == {"evidence_file", "sha256"} and isinstance(item["sha256"], str)
                        and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                        and item["evidence_file"] == f"{item['sha256']}.evidence", "Invalid preserved evidence reference.")
                blob = ordinary(self.evidence / item["evidence_file"])
                require(hashlib.sha256(read_bounded_regular(blob, MAX_EVIDENCE_BYTES)).hexdigest() == item["sha256"],
                        "Preserved evidence is missing or changed; reconcile before retry.")

    def verify_push_urls(self) -> None:
        """Validate every effective push destination independently of origin's fetch URL."""
        urls = self.git("remote", "get-url", "--push", "--all", "origin").splitlines()
        require(urls and all(url in {f"https://github.com/{self.repository}.git", f"https://github.com/{self.repository}"}
                            for url in urls),
                "Origin push URLs differ from the exact same-repository destination; preserve all refs.")

    def command(self, args: list[str], *, allowed: tuple[int, ...] = (0,)) -> str:
        """Cap streamed stdout and stderr together; never publish arbitrary child output on failure.

        Args:
            args: Argument array passed directly to the child without shell interpolation.
            allowed: Child exit codes accepted by this operation.
        """
        # Repository/index/config overrides must not redirect either inspection or deletion.
        # Retain only the credential prompt helper; normal on-disk Git configuration still applies.
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith("GIT_") or key.upper() == "GIT_ASKPASS"}
        env.update(GIT_OPTIONAL_LOCKS="0", PYTHONDONTWRITEBYTECODE="1")
        if args[0] == "git":
            # A stale monitor can hide tracked changes from status and worktree remove alike.
            overrides = ["-c", "core.fsmonitor=false", "-c", "core.trustctime=true", "-c", "core.checkStat=default"]
            if os.name != "nt":
                overrides += ["-c", "core.fileMode=true"]
            args = ["git", *overrides, *args[1:]]
        output = bytearray()
        count = 0
        lock = threading.Lock()
        failed = threading.Event()
        try:
            with contained_child(args, self.repo, env) as process:

                def drain(stream, keep: bool) -> None:
                    """Drain bounded chunks concurrently so neither child pipe can deadlock the other.

                    Args:
                        stream: Child output pipe drained under the combined byte limit.
                        keep: Whether this pipe contributes to the returned stdout buffer.
                    """
                    nonlocal count
                    try:
                        with stream:
                            while chunk := stream.read(65536):
                                with lock:
                                    count += len(chunk)
                                    if count > MAX_CHILD_BYTES:
                                        failed.set()
                                        process.kill()
                                        return
                                    if keep:
                                        output.extend(chunk)
                    except OSError:
                        failed.set()

                readers = [threading.Thread(target=drain, args=(stream, keep), daemon=True)
                           for stream, keep in ((process.stdout, True), (process.stderr, False))]
                for reader in readers:
                    reader.start()
                try:
                    process.wait(timeout=CHILD_TIMEOUT)
                    for reader in readers:
                        reader.join(timeout=1)
                    require(not failed.is_set() and not any(reader.is_alive() for reader in readers),
                            "Child output exceeded the bounded capture or could not close; inspect the tool directly before retry.")
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refusal(f"{args[0]} could not complete; verify tool availability and execution policy before retry.") from exc
        require(process.returncode in allowed,
                f"{args[0]} failed with exit {process.returncode}; preserve remaining resources and inspect the tool directly.")
        return output.decode("utf-8").strip()

    def git(self, *args: str) -> str:
        """Read or mutate only this controller's verified repository.

        Args:
            *args: Git subcommand and arguments passed directly to the verified checkout.
        """
        return self.command(["git", *args])

    def api(self, endpoint: str) -> object:
        """Read one GitHub endpoint using existing gh authentication.

        Args:
            endpoint: Repository-relative GitHub API endpoint to read.
        """
        return json.loads(self.command(["gh", "api", "--hostname", "github.com", f"repos/{self.repository}/{endpoint}"]))

    def worktrees(self) -> list[dict[str, str]]:
        """Read Git's authoritative registration inventory without pruning it."""
        blocks = self.git("worktree", "list", "--porcelain", "-z").split("\0\0")
        return [dict(line.split(" ", 1) if " " in line else (line, "")
                     for line in block.split("\0") if line) for block in blocks if block]

    def task(self) -> None:
        """Require the controller to independently reread ownership, holds, activity, and inventory."""
        result = self.controller.call("task.inspect", {"handoff": self.handoff, "sha256": self.digest,
                                                       "config": str(self.config), "configured_root": str(self.root),
                                                       "evidence": str(self.evidence),
                                                       "mode": "execute" if self.execute else "preview"})
        require(result.get("handoff_sha256") == self.digest, "Controller did not bind this handoff.")
        for field in ("identity_verified", "exclusive_ownership_verified", "idle", "unpinned",
                      "holds_clear", "downstream_clear", "inventory_verified", "post_merge_complete",
                      "reviews_complete", "supported_tools_used"):
            require(result.get(field) is True, f"task.inspect.{field} is unproven; obtain fresh supported-tool evidence.")
        require(isinstance(result.get("evidence_refs"), list) and result["evidence_refs"],
                "Controller must identify durable sanitized evidence for its independent checks.")
        runs = result.get("post_merge_runs")
        require(isinstance(runs, list) and 0 < len(runs) <= 100, "Applicable post-merge run identities are required.")
        for identity in runs:
            require(isinstance(identity, dict) and set(identity) == {"id", "run_attempt", "workflow_id", "head_sha", "event"}
                    and all(type(identity[key]) is int and identity[key] > 0 for key in ("id", "run_attempt", "workflow_id")),
                    "Invalid applicable post-merge run identity.")
            run = self.api(f"actions/runs/{identity['id']}")
            require(all(run.get(key) == value for key, value in identity.items())
                    and run.get("repository", {}).get("full_name") == self.repository
                    and run.get("status") == "completed" and run.get("conclusion") == "success",
                    "Applicable post-merge run changed, remains incomplete, or was unsuccessful.")
        if not self.handoff["resources"]:
            require(result.get("inventory_empty_verified") is True,
                    "Explicit validation_resource_inventory_empty verification is required.")
        allowed_titles = {self.handoff["task_title"]}
        if not self.target.exists() and not self.git("for-each-ref", "--format=%(objectname)", f"refs/heads/{self.branch}") \
                and not self.git("ls-remote", "--refs", "origin", f"refs/heads/{self.branch}"):
            allowed_titles.add(self.expected_title)
        require(result.get("observed_title") in allowed_titles,
                "Live task title differs from the recorded handoff title; revalidate task identity.")
        self.resource_evidence.append({"operation": "task.inspect", "evidence_refs": result["evidence_refs"]})

    def verify_primary_controller(self) -> None:
        """Independently classify the checkout before requiring configuration for non-primary cleanup."""
        require(Path.cwd() == self.repo, "Run the command from the primary checkout.")
        inventory = self.worktrees()
        require(inventory and Path(inventory[0]["worktree"]) == self.repo, "Controller is not in Git's primary checkout.")
        common = Path(self.git("rev-parse", "--path-format=absolute", "--git-common-dir"))
        require(common == self.repo / ".git", "Ambiguous primary checkout common directory.")
        require(self.target != self.repo, "Primary checkout deletion is forbidden; use its documented restoration workflow.")

    def eligibility(self) -> None:
        """Independently verify live GitHub identity, issues, current main reachability, and task state."""
        require(hashlib.sha256(read_handoff(self.handoff_path)).hexdigest() == self.digest,
                "Handoff changed during execution; preserve remaining resources and restart verification.")
        ordinary(self.repo)
        ordinary(self.target)
        self.verify_primary_controller()
        require(configured_root(self.config) == self.root, "Configured root changed; restart preview.")
        self.git("check-ref-format", "--branch", self.branch)
        remote = self.git("remote", "get-url", "origin")
        require(remote in {f"https://github.com/{self.repository}.git", f"https://github.com/{self.repository}"},
                "Origin must use the exact same-repository GitHub HTTPS URL; configure HTTPS before retry.")
        self.verify_push_urls()
        pr = self.api(f"pulls/{self.handoff['pr']}")
        require(pr["merged"] is True and pr["merge_commit_sha"] == self.merge and pr["head"]["sha"] == self.head,
                "Merged PR/head/squash identity is unproven.")
        require(pr["base"]["ref"] == "main" and pr["head"]["ref"] == self.branch
                and pr["head"]["repo"] and pr["head"]["repo"]["full_name"] == self.repository,
                "Only an ordinary same-repository main PR is eligible.")
        issues = json.loads(self.command(["gh", "pr", "view", str(self.handoff["pr"]), "--repo", f"github.com/{self.repository}",
                                         "--json", "closingIssuesReferences"]))["closingIssuesReferences"]
        require(all(isinstance(item, dict) and item.get("url") ==
                    f"https://github.com/{self.repository}/issues/{item.get('number')}" for item in issues),
                "Closing issue repository identity differs; reconcile nonlocal issue references before cleanup.")
        require(sorted(item["number"] for item in issues) == sorted(self.handoff["issues"]) and issues,
                "Complete linked issue identity is missing or changed.")
        for item in issues:
            issue = self.api(f"issues/{item['number']}")
            require(issue["state"] == "closed", "A linked issue remains open.")
            require(len({label["name"] for label in issue["labels"]} & {"bug", "enhancement", "documentation"}) == 1,
                    "A linked issue must have exactly one type label.")
        main = self.api("git/ref/heads/main")["object"]["sha"]
        comparison = self.api(f"compare/{self.merge}...{main}")
        require(comparison["status"] in {"ahead", "identical"}, "Squash commit is not reachable from current main.")
        remote_main = self.git("ls-remote", "--refs", "origin", "refs/heads/main").split()
        require(remote_main and remote_main[0] == main,
                "Main changed during verification; retry fresh eligibility.")
        # The live controller identifies the applicable chain; task() verifies exact runs
        # without conflating unrelated manual dispatches that happen to share the merge SHA.
        self.task()
        self.local_state()
        if self.execute:
            self.git("fetch", "--no-prune", "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no",
                     "origin", "refs/heads/main:refs/remotes/origin/main")
            require(self.git("rev-parse", "refs/remotes/origin/main") == main,
                    "Origin main changed during fetch; repeat eligibility before deletion.")
            self.git("merge-base", "--is-ancestor", self.merge, "refs/remotes/origin/main")
            self.task()
        self.verify_resources_absent(completed_only=True)
        self.local_state()

    def local_state(self) -> None:
        """Protect active, dirty, locked, shared, replaced, or ambiguously absent worktrees."""
        self.require_direct_task_ref()
        inventory = self.worktrees()
        targets = [item for item in inventory if Path(item["worktree"]) == self.target]
        owners = [item for item in inventory if item.get("branch") == f"refs/heads/{self.branch}"]
        if self.target.exists():
            require(list((self.target.stat().st_dev, self.target.stat().st_ino)) == self.handoff["worktree_identity"],
                    "Worktree filesystem identity differs from the creation handoff.")
            for parent, directories, files in os.walk(self.target, followlinks=False):
                for name in [*directories, *files]:
                    ordinary(Path(parent) / name)
            require(len(targets) == 1 and owners == targets, "Worktree/local branch registration is not exclusive.")
            require("locked" not in targets[0] and "prunable" not in targets[0], "Locked or prunable worktree must be reconciled first.")
            require(targets[0].get("HEAD") == self.head, "Worktree HEAD differs from recorded PR head.")
            entries = self.git("-C", str(self.target), "ls-files", "-v", "-z").split("\0")
            require(all(not entry or (not entry[0].islower() and entry[0] != "S") for entry in entries),
                    "Index assume-unchanged or skip-worktree flags block cleanup; reconcile tracked content first.")
            require(not self.git("-C", str(self.target), "status", "--porcelain", "--untracked-files=all"),
                    "Dirty or untracked worktree content blocks cleanup.")
            self.verify_tracked_contents()
        else:
            require(not targets and not owners, "Absent path still has Git registration; preserve metadata for diagnosis.")
        local = self.git("for-each-ref", "--format=%(objectname)", f"refs/heads/{self.branch}")
        require(local in {"", self.head}, "Local branch changed; preserve it.")
        remote = self.git("ls-remote", "--refs", "origin", f"refs/heads/{self.branch}")
        require(not remote or remote.split()[0] == self.head, "Remote branch changed; expected-SHA cleanup is refused.")
        if "remote_branch_absent" in self.gates:
            require(not remote, "Remote branch reappeared after its absence gate; preserve it and revalidate ownership.")
        if "local_task_branch_absent" in self.gates:
            require(not local, "Local branch reappeared after its absence gate; preserve it and revalidate ownership.")
        if "worktree_removed" in self.gates:
            require(not self.target.exists() and not targets, "Worktree reappeared after removal; preserve it.")

    def verify_tracked_contents(self) -> None:
        """Hash tracked files independently of Git's cached stat data before trusting cleanliness."""
        entries = self.git("-C", str(self.target), "ls-files", "--stage", "-z").split("\0")
        require(len(entries) <= 50001, "Tracked inventory exceeds the bounded cleanup limit.")
        for entry in filter(None, entries):
            metadata, name = entry.split("\t", 1)
            mode, expected, stage = metadata.split()
            require(stage == "0" and mode in {"100644", "100755"}, "Unsupported tracked entry; reconcile before cleanup.")
            ordinary(self.target / name)
            attributes = self.git("-C", str(self.target), "check-attr", "-z", "filter", "--", name).split("\0")
            require(len(attributes) == 4 and attributes[2] in {"unspecified", "unset"},
                    "Custom content filters require independent reconciliation before cleanup.")
            actual = self.git("-C", str(self.target), "hash-object", f"--path={name}", "--", name)
            require(actual == expected, "Tracked content differs from the index; preserve the worktree.")

    def require_direct_task_ref(self) -> None:
        """Reject even dangling symbolic branches before accepting absence or deleting a ref."""
        symbolic = self.command(["git", "symbolic-ref", "--quiet", f"refs/heads/{self.branch}"], allowed=(0, 1))
        require(not symbolic, "Symbolic task ref blocks cleanup; preserve its target and reconcile branch ownership.")

    def validate_resource_identity(self, resource: dict) -> None:
        """Require repository/PR binding, an exact locator, and durable original manifest bytes.

        Args:
            resource: Inventory entry containing ownership and resource identity evidence.
        """
        required = {"id", "kind", "task_id", "source_commit", "repository", "pr", "ownership_manifest"}
        require(isinstance(resource, dict) and required <= set(resource), "Resource identity fields are incomplete.")
        require(resource["repository"] == self.repository and resource["pr"] == self.handoff["pr"],
                "Resource repository/PR identity differs from this handoff.")
        require(any(isinstance(resource.get(key), str) and resource[key].strip() for key in ("path", "provider_id")),
                "Resource requires an exact path or provider identity.")
        manifest = resource["ownership_manifest"]
        require(isinstance(manifest, dict) and set(manifest) == {"path", "sha256"}
                and isinstance(manifest["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"]),
                "Resource original ownership manifest identity is incomplete.")
        path = ordinary(Path(manifest["path"]))
        require(beneath(path, self.root), "Ownership manifest must be beneath the configured durable root.")
        require(not path.is_relative_to(self.target), "Preserve the original ownership manifest outside the worktree.")
        for candidate in self.handoff["resources"]:
            if isinstance(candidate, dict) and candidate.get("path"):
                require(not path.is_relative_to(ordinary(Path(candidate["path"]))),
                        "Ownership manifest lies inside a resource removal root.")
        require(hashlib.sha256(read_bounded_regular(path, 262144)).hexdigest() == manifest["sha256"],
                "Original resource ownership manifest changed or is unproven.")
        if resource["kind"] == "generated_tree":
            require(resource.get("path") and isinstance(resource.get("root_identity"), list)
                    and len(resource["root_identity"]) == 3, "Generated root creation identity is incomplete.")
        else:
            require(isinstance(resource.get("cleanup_tool"), str) and resource["cleanup_tool"].strip(),
                    "Specialized resource requires its exact supported owning cleanup tool.")

    def verify_resources_absent(self, *, completed_only: bool = False) -> None:
        """Revisit the entire inventory so earlier resources cannot silently reappear.

        Args:
            completed_only: Restrict absence checks to resources whose release gate is already recorded.
        """
        for resource in self.handoff["resources"]:
            if completed_only and "validation_resources_released" not in self.gates \
                    and f"resource_released:{resource['id']}" not in self.gates:
                continue
            self.validate_resource_identity(resource)
            result = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
            require(result.get("absent") is True and result.get("ownership_verified") is True
                    and result.get("inactive") is True and result.get("retained") is False
                    and result.get("evidence_preserved") is True,
                    "Aggregate resource absence readback failed; preserve remaining resources and retry inspection.")
            if resource.get("path"):
                require(not ordinary(Path(resource["path"])).exists(), "An inventoried resource path reappeared.")

    def removal_scopes(self, resource: dict, result: dict) -> list[str]:
        """Protect checkouts and durable evidence from broader owning-tool removal directories.

        Args:
            resource: Inventory entry containing ownership and resource identity evidence.
            result: Fresh controller observation containing the declared removal scopes.
        """
        scopes = result.get("removal_scopes")
        require(isinstance(scopes, list) and len(scopes) <= 100 and all(isinstance(value, str) for value in scopes),
                "Owning tool must report every exact filesystem removal scope.")
        require(scopes or not resource.get("path"), "A filesystem resource requires a removal scope.")
        protected = [self.repo, self.target, self.evidence, self.handoff_path, self.config]
        protected.extend(Path(item["ownership_manifest"]["path"]) for item in self.handoff["resources"])
        protected.extend(Path(item["path"]) for item in self.handoff["resources"]
                         if item["id"] != resource["id"] and item.get("path"))
        for value in scopes:
            scope = ordinary(Path(value))
            require(beneath(scope, self.root), "Removal scope must be beneath the configured root.")
            require(not any(ordinary(path).is_relative_to(scope) for path in protected),
                    "Removal scope contains a checkout, another resource, or preserved evidence; use a narrower owning-tool scope.")
        return scopes

    def record(self, gate: str) -> None:
        """Durably preserve completed gates before the next transition; no evidence writes in preview.

        Args:
            gate: Exact transition identifier to persist or exercise in recovery.
        """
        if gate in self.gates:
            return
        prospective = [*self.gates, gate]
        if self.execute:
            ordinary(self.evidence)
            ensure_durable_directory(self.evidence)
            # Large snapshots and controller references remain separate from the small
            # cumulative gate journal, so every record we publish remains recoverable.
            references = []
            for item in self.resource_evidence:
                if set(item) == {"evidence_file", "sha256"}:
                    references.append(item)
                    continue
                payload = json.dumps(item).encode("utf-8")
                require(len(payload) <= MAX_EVIDENCE_BYTES, "Evidence payload exceeds the recoverable limit; preserve resources.")
                digest = hashlib.sha256(payload).hexdigest()
                blob = self.evidence / f"{digest}.evidence"
                if blob.exists():
                    ordinary(blob)
                    require(read_bounded_regular(blob, MAX_EVIDENCE_BYTES) == payload, "Evidence payload identity changed.")
                else:
                    staged_blob = self.evidence / f"{self.digest}-{uuid.uuid4()}-evidence.pending"
                    with staged_blob.open("xb") as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    publish_durable_file(staged_blob, blob)
                references.append({"evidence_file": blob.name, "sha256": digest})
            self.resource_evidence = references
            payload = json.dumps({"handoff_sha256": self.digest, "task_id": self.handoff["task_id"],
                                  "gates": prospective, "resource_evidence": references}).encode("utf-8")
            require(len(payload) <= MAX_EVIDENCE_BYTES, "Journal exceeds the recoverable limit; preserve resources.")
            destination = self.evidence / f"{self.digest}-{uuid.uuid4()}.json"
            pending = destination.with_suffix(".pending")
            with pending.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            publish_durable_file(pending, destination)
        self.gates = prospective

    def inventory_scopes(self) -> dict[str, list[str]]:
        """Inspect the complete scope inventory before any owning tool can consume another resource."""
        scopes: dict[str, list[str]] = {}
        for resource in self.handoff["resources"]:
            result = ({"removal_scopes": [resource["path"]]} if resource["kind"] == "generated_tree" else
                      self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest}))
            current = self.removal_scopes(resource, result)
            require(not any(Path(left).is_relative_to(Path(right)) or Path(right).is_relative_to(Path(left))
                            for previous in scopes.values() for left in previous for right in current),
                    "Resource removal scopes intersect; reconcile ownership before releasing any resource.")
            scopes[resource["id"]] = current
        return scopes

    def verify_directory_release(self) -> None:
        """Reject filesystem directories Git cannot report, including empty locks and artifacts."""
        if not self.target.exists():
            return
        tracked = self.git("-C", str(self.target), "ls-files", "-z").split("\0")
        source_files = {Path(entry) for entry in tracked if entry}
        source_directories = {parent for entry in tracked if entry for parent in Path(entry).parents}
        for parent, directories, files in os.walk(self.target, followlinks=False):
            for name in files:
                path = ordinary(Path(parent) / name)
                require(path.relative_to(self.target) in source_files or path == self.target / ".git",
                        "Unreleased file remains outside tracked source; reconcile its inventory and owning-tool release.")
            for name in directories:
                path = ordinary(Path(parent) / name)
                require(path.relative_to(self.target) in source_directories,
                        "Unreleased directory remains outside tracked source; reconcile its inventory and owning-tool release.")

    def resources(self) -> None:
        """Delegate specialized resources to their owning tools and demand independent absence readback."""
        identities: set[str] = set()
        for resource in self.handoff["resources"]:
            self.validate_resource_identity(resource)
            require(isinstance(resource, dict) and set(resource) <= {
                "id", "kind", "task_id", "source_commit", "path", "root_identity", "provider_id",
                "ownership_manifest", "cleanup_tool", "repository", "pr"}, "Resource fields differ from the bounded sanitized schema.")
            if "path" in resource:
                resource_path = ordinary(Path(resource["path"]))
                require(not self.evidence.is_relative_to(resource_path)
                        and not self.handoff_path.is_relative_to(resource_path),
                        "Durable evidence or handoff lies inside a resource removal root.")
            require(resource.get("kind") in {"generated_tree", "vm", "lifecycle", "artifact", "reservation",
                                              "credential_bridge", "process", "configuration"},
                    "Unsupported resource kind; obtain an existing owning cleanup tool.")
            identity = resource["id"]
            require(isinstance(identity, str) and identity and identity not in identities, "Resource identity missing or duplicated.")
            identities.add(identity)
            require(resource["task_id"] == self.handoff["task_id"]
                    and re.fullmatch(r"[0-9a-f]{40}", resource["source_commit"]),
                    "Resource ownership/source identity differs from this task.")
            ancestry_gate = f"resource_ancestry_verified:{identity}"
            if f"resource_released:{identity}" in self.gates:
                require(ancestry_gate in self.gates, "Released resource lacks durable ancestry evidence; reconcile before retry.")
            else:
                self.git("merge-base", "--is-ancestor", resource["source_commit"], self.head)
        inventory_scopes = self.inventory_scopes()
        if self.execute:
            for resource in self.handoff["resources"]:
                self.record(f"resource_ancestry_verified:{resource['id']}")
        self.verify_resources_absent(completed_only=True)
        if "validation_resources_released" in self.gates:
            return
        for resource in self.handoff["resources"]:
            identity = resource["id"]
            if f"resource_released:{identity}" in self.gates:
                continue
            result = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
            require(result.get("ownership_verified") is True and result.get("inactive") is True
                    and result.get("retained") is False and result.get("supported_cleanup") is True,
                    "Resource ownership, inactivity, retention, or owning cleanup capability blocks release.")
            require(result.get("evidence_preserved") is True, "Preserve resource evidence outside every removal root first.")
            require(type(result.get("absent")) is bool, "Resource absence must be independently observed.")
            if resource["kind"] != "generated_tree":
                require(self.removal_scopes(resource, result) == inventory_scopes[identity],
                        "Resource scopes changed after inventory preflight; reconcile before release.")
            self.proposed.append({"resource": identity, "action": "release through verified owning tool"})
            generated = resource.get("kind") == "generated_tree"
            if generated:
                path = ordinary(Path(resource["path"]))
                require(beneath(path, self.target), "Generated output must be a strict descendant of this task worktree.")
                require(not {".git", ".atlaso-local"} & {part.casefold() for part in path.relative_to(self.target).parts},
                        "Git metadata and credential/recovery roots require their owning tools.")
                require(not (path / ".git").exists(), "Nested repositories are not generated output trees.")
                if path.exists():
                    require(path.is_dir(), "Generated-tree target must be an ordinary directory.")
                    relative = path.relative_to(self.target).as_posix()
                    require(not self.git("-C", str(self.target), "ls-files", "--", relative),
                            "Generated output contains tracked source; preserve it.")
                    files = WindowsFiles()
                    snapshot = files.snapshot(path)
                    require(not any(".git" in {part.casefold() for part in Path(entry).parts} for entry in snapshot),
                            "Nested repositories are not generated output trees.")
                    require(not any(".atlaso-local" in {part.casefold() for part in Path(entry).parts} for entry in snapshot),
                            "Nested credential/recovery roots require their owning cleanup workflow.")
                    children: dict[Path, set[str]] = {}
                    for entry in snapshot:
                        relative_entry = Path(entry)
                        children.setdefault(relative_entry.parent, set()).add(relative_entry.name.casefold())
                    require(not any({"head", "objects", "refs"} <= names or {"head", "objects", "packed-refs"} <= names
                                    for names in children.values()),
                            "Bare repositories are not generated output trees; use their owning cleanup workflow.")
                    require(snapshot["."]["identity"] == resource["root_identity"],
                            "Generated root differs from its inventoried creation identity.")
                    self.proposed[-1] = {"resource": identity, "path": str(path), "entries": snapshot,
                                         "action": "remove exact generated tree through checked handles"}
                    if self.execute:
                        self.eligibility()
                        self.validate_resource_identity(resource)
                        require(self.inventory_scopes() == inventory_scopes, "Inventory scopes changed before release.")
                        inspected = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
                        require(all(inspected.get(key) is True for key in
                                    ("ownership_verified", "inactive", "supported_cleanup", "evidence_preserved"))
                                and inspected.get("retained") is False and inspected.get("absent") is False,
                                "Generated resource release eligibility changed; preserve the tree.")
                        self.resource_evidence.append(self.proposed[-1])
                        self.record(f"resource_release_prepared:{identity}")
                        files.remove(path, snapshot)
                if self.execute:
                    require(not path.exists(), "Generated tree remains; resource release incomplete.")
                    result = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
            if self.execute and result.get("absent") is not True:
                require(not generated, "Controller could not independently verify generated-tree absence.")
                self.eligibility()
                self.validate_resource_identity(resource)
                inspected = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
                scopes = self.removal_scopes(resource, inspected)
                require(scopes == inventory_scopes[identity] and self.inventory_scopes() == inventory_scopes,
                        "Inventory scopes changed before release.")
                inspected = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
                require(self.removal_scopes(resource, inspected) == scopes, "Resource scopes changed before release.")
                require(all(inspected.get(key) is True for key in
                            ("ownership_verified", "inactive", "supported_cleanup", "evidence_preserved"))
                        and inspected.get("retained") is False and inspected.get("absent") is False,
                        "Resource release eligibility changed.")
                self.record(f"resource_release_prepared:{identity}")
                released = self.controller.call("resource.release", {"resource": resource, "handoff_sha256": self.digest,
                                                                      "removal_scopes": scopes})
                require(released.get("success") is True, "Owning tool failed or refused resource release; preserve remaining resources.")
                result = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
            if self.execute:
                require(result.get("absent") is True and result.get("ownership_verified") is True,
                        "Resource absence lacks independent readback; branch/worktree cleanup blocked.")
                self.record(f"resource_released:{identity}")
        if self.execute:
            self.verify_resources_absent()
            self.verify_directory_release()
            if self.target.exists():
                require(not self.git("-C", str(self.target), "ls-files", "--others", "--ignored", "--exclude-standard"),
                        "Unreleased ignored files remain; resource inventory/release is incomplete.")
            self.record("validation_resources_released")

    def run(self) -> dict:
        """Hold exclusive task ownership and refresh journals before executing any transition."""
        if not self.execute:
            return self.reconcile()
        with cleanup_lock(self.root, self.lock_digest):
            self.gates = []
            self.resource_evidence = []
            self.restore_gates()
            return self.reconcile()

    def reconcile(self) -> dict:
        """Reconcile ordered transitions from live evidence, including interrupted and title-only retries."""
        self.eligibility()
        if self.execute:
            self.record("cleanup_prepared")
        self.resources()
        self.proposed += [{"remote_ref": self.branch, "expected_sha": self.head},
                          {"worktree": str(self.target), "local_ref": self.branch}]
        expected = self.expected_title
        self.proposed.append({"task_id": self.handoff["task_id"], "title": expected})
        if not self.execute:
            return {"status": "preview", "proposed": self.proposed, "gates": [], "handoff_sha256": self.digest}
        self.eligibility()
        self.verify_directory_release()
        if self.git("ls-remote", "--refs", "origin", f"refs/heads/{self.branch}"):
            self.verify_push_urls()
            self.record("remote_branch_removal_prepared")
            self.git("push", "origin", f"--force-with-lease=refs/heads/{self.branch}:{self.head}",
                     f":refs/heads/{self.branch}")
        require(not self.git("ls-remote", "--refs", "origin", f"refs/heads/{self.branch}"), "Remote ref absence verification failed.")
        self.record("remote_branch_absent")
        self.eligibility()
        if self.target.exists():
            self.verify_directory_release()
            # Git's non-forced removal protects tracked/untracked edits; the controller
            # must independently account for all ignored files before this transition.
            ignored = self.git("-C", str(self.target), "ls-files", "--others", "--ignored", "--exclude-standard")
            require(not ignored, "Ignored validation/configuration files remain; release them through their owning tools first.")
            self.record("worktree_removal_prepared")
            self.git("worktree", "remove", str(self.target))
        require(not self.target.exists() and not any(Path(item["worktree"]) == self.target for item in self.worktrees()),
                "Worktree path or registration remains; retry only after independent reconciliation.")
        self.task()
        require(not any(item.get("branch") == f"refs/heads/{self.branch}" for item in self.worktrees()),
                "Local branch is referenced by a worktree; preserve it.")
        local = self.git("for-each-ref", "--format=%(objectname)", f"refs/heads/{self.branch}")
        require(local in {"", self.head}, "Local branch changed after worktree removal.")
        self.require_direct_task_ref()
        if local:
            self.record("local_branch_removal_prepared")
            self.git("update-ref", "--no-deref", "-d", f"refs/heads/{self.branch}", self.head)
        self.require_direct_task_ref()
        require(not self.git("for-each-ref", "--format=%(objectname)", f"refs/heads/{self.branch}"),
                "Local task ref still exists; resume local-ref removal only.")
        self.record("local_task_branch_absent")
        self.record("worktree_removed")
        self.eligibility()
        result = self.controller.call("task.title", {"task_id": self.handoff["task_id"], "expected_title": expected,
                                                     "handoff_sha256": self.digest})
        if result.get("capability") == "unavailable":
            require(result.get("capability_evidence"), "Unavailable title controls require explicit capability evidence.")
            self.resource_evidence.append({"operation": "task.title", "disposition": "capability_unavailable",
                                           "capability_evidence": result["capability_evidence"]})
            self.record("task_title_done:not_applicable")
        else:
            require(result.get("persisted_readback") is True, "Rename acknowledgement is not persisted title readback.")
            try:
                verify_completed_task_title(expected, result.get("observed_title", ""))
            except ValueError as exc:
                raise Refusal(str(exc)) from exc
            self.record("task_title_readback_verified")
        self.eligibility()
        self.record("task_title_done")
        return {"status": "complete", "gates": self.gates, "handoff_sha256": self.digest}


def main() -> int:
    """Expose a JSON-lines protocol with structured refusals and no guard bypass."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    cleanup = None
    try:
        cleanup = Cleanup(args.handoff, args.evidence, args.config, args.execute, Controller())
        result = cleanup.run()
    except (Refusal, FileRefusal, ValueError, KeyError, TypeError, OSError) as exc:
        result = {"status": "refused", "gates": cleanup.gates if cleanup else [],
                  "proposed": cleanup.proposed if cleanup else [],
                  "retry_condition": str(exc) if isinstance(exc, (Refusal, FileRefusal)) else
                  "Invalid or inaccessible evidence; verify schema, ordinary paths, and tool permissions.",
                  "remaining_resources_preserved": True}
        print(json.dumps({"kind": "result", **result}), flush=True)
        return 1
    print(json.dumps({"kind": "result", **result}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
