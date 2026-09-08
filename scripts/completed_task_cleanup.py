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

from scripts.completed_task_files import FileRefusal, WindowsFiles
from scripts.completed_task_title import (
    completed_task_title,
    verify_completed_task_title,
)


class Refusal(RuntimeError):
    """A failed gate whose remaining resources must be preserved."""


def require(condition: object, message: str) -> None:
    """Fail closed with a bounded, caller-authored diagnostic."""
    if not condition:
        raise Refusal(message)


def ordinary(path: Path) -> Path:
    """Reject relative paths, aliases, links, and reparse ancestors, including absent retries."""
    require(path.is_absolute(), "Supply an absolute path.")
    require(not any(part in {".", ".."} for part in path.parts), "Path traversal is forbidden.")
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "Reparse points and symbolic links block cleanup.")
    return path


def beneath(path: Path, root: Path) -> bool:
    """Compare complete canonical path components rather than string prefixes."""
    return path != root and path.is_relative_to(root)


def configured_root(config: Path) -> Path:
    """Read the supported desktop setting without inventing a default root."""
    active_config = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "config.toml"
    require(config == active_config, "Config must be the active CODEX_HOME/config.toml, not a handoff-supplied alternate.")
    with ordinary(config).open("rb") as stream:
        value = tomllib.load(stream).get("desktop", {}).get("git-worktree-root")
    require(isinstance(value, str) and value.strip(), "desktop.git-worktree-root is missing; configure it first.")
    root = ordinary(Path(value))
    require(root.is_dir() and root != Path(root.anchor), "Configured worktree root is unavailable or unsafe.")
    return root


class Controller:
    """Require fresh nonce-bound responses from supported tools, never a saved preview."""

    def call(self, operation: str, payload: dict) -> dict:
        """Emit one request and bound the wait for its matching live response."""
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
        """Bind immutable handoff bytes and a durable evidence directory outside the target."""
        self.execute = execute
        self.controller = controller
        raw = ordinary(handoff).read_bytes()
        require(len(raw) <= 262144, "Handoff exceeds the bounded evidence limit.")
        self.digest = hashlib.sha256(raw).hexdigest()
        self.handoff = json.loads(raw)
        self.handoff_path = handoff
        require(isinstance(self.handoff, dict) and set(self.handoff) == {
            "schema", "primary_checkout", "worktree", "worktree_identity", "branch", "head", "merge",
            "repository", "pr", "issues", "resources", "task_id", "description", "task_title"},
            "Handoff fields differ from the bounded sanitized schema.")
        self.root = configured_root(config)
        self.config = config
        self.repo = ordinary(Path(self.handoff["primary_checkout"]))
        self.target = ordinary(Path(self.handoff["worktree"]))
        self.evidence = ordinary(evidence)
        require(beneath(self.target, self.root), "Target is outside the configured worktree root.")
        require(beneath(evidence, self.root) and not evidence.is_relative_to(self.target),
                "Evidence must survive outside the target, beneath the configured root.")
        require(not handoff.is_relative_to(self.target), "Preserve the handoff outside the target first.")
        require(self.target != self.repo, "Primary checkout deletion is forbidden; use its documented restoration workflow.")
        require(Path.cwd() == self.repo, "Run the command from the primary checkout.")
        require(self.handoff.get("schema") == 1, "Unsupported handoff schema.")
        self.branch = self.handoff["branch"]
        self.head = self.handoff["head"]
        self.merge = self.handoff["merge"]
        self.repository = self.handoff["repository"]
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository), "Invalid repository identity.")
        require(all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (self.head, self.merge)), "Full commit SHAs are required.")
        require(self.branch not in {"main", "gh-pages"} and not self.branch.startswith("-"), "Protected branch target.")
        require(not self.branch.endswith("/") and "*" not in self.branch, "An exact branch ref is required.")
        require(type(self.handoff["pr"]) is int and self.handoff["pr"] > 0, "Exact positive PR identity required.")
        require(isinstance(self.handoff["resources"], list) and len(self.handoff["resources"]) <= 100,
                "A bounded validation resource inventory is required, including an explicit empty list.")
        self.gates: list[str] = []
        self.proposed: list[dict] = []
        self.resource_evidence: list[dict] = []
        require(isinstance(self.handoff["task_title"], str) and 0 < len(self.handoff["task_title"]) <= 512,
                "A bounded recorded current task title is required.")

    def command(self, args: list[str], *, allowed: tuple[int, ...] = (0,)) -> str:
        """Run argument arrays with bounded time; never publish arbitrary child output on failure."""
        env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "PYTHONDONTWRITEBYTECODE": "1"}
        try:
            result = subprocess.run(args, cwd=self.repo, env=env, capture_output=True,
                                    text=True, encoding="utf-8", timeout=90, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refusal(f"{args[0]} could not complete; verify tool availability and execution policy before retry.") from exc
        require(result.returncode in allowed,
                f"{args[0]} failed with exit {result.returncode}; preserve remaining resources and inspect the tool directly.")
        return result.stdout.strip()

    def git(self, *args: str) -> str:
        """Read or mutate only this controller's verified repository."""
        return self.command(["git", *args])

    def api(self, endpoint: str) -> object:
        """Read one GitHub endpoint using existing gh authentication."""
        return json.loads(self.command(["gh", "api", f"repos/{self.repository}/{endpoint}"]))

    def worktrees(self) -> list[dict[str, str]]:
        """Read Git's authoritative registration inventory without pruning it."""
        blocks = self.git("worktree", "list", "--porcelain").split("\n\n")
        return [dict(line.split(" ", 1) if " " in line else (line, "")
                     for line in block.splitlines()) for block in blocks if block]

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
        if not self.handoff["resources"]:
            require(result.get("inventory_empty_verified") is True,
                    "Explicit validation_resource_inventory_empty verification is required.")
        allowed_titles = {self.handoff["task_title"]}
        if not self.target.exists() and not self.git("for-each-ref", "--format=%(objectname)", f"refs/heads/{self.branch}") \
                and not self.git("ls-remote", "--refs", "origin", f"refs/heads/{self.branch}"):
            allowed_titles.add(completed_task_title(self.handoff["description"], self.handoff["issues"], [self.handoff["pr"]]))
        require(result.get("observed_title") in allowed_titles,
                "Live task title differs from the recorded handoff title; revalidate task identity.")
        self.resource_evidence.append({"operation": "task.inspect", "evidence_refs": result["evidence_refs"]})

    def eligibility(self) -> None:
        """Independently verify live GitHub identity, issues, current main reachability, and task state."""
        require(hashlib.sha256(ordinary(self.handoff_path).read_bytes()).hexdigest() == self.digest,
                "Handoff changed during execution; preserve remaining resources and restart verification.")
        require(configured_root(self.config) == self.root, "Configured root changed; restart preview.")
        ordinary(self.repo)
        ordinary(self.target)
        inventory = self.worktrees()
        require(inventory and Path(inventory[0]["worktree"]) == self.repo, "Controller is not in Git's primary checkout.")
        common = Path(self.git("rev-parse", "--path-format=absolute", "--git-common-dir"))
        require(common == self.repo / ".git", "Ambiguous primary checkout common directory.")
        self.git("check-ref-format", "--branch", self.branch)
        remote = self.git("remote", "get-url", "origin")
        require(remote in {f"https://github.com/{self.repository}.git", f"https://github.com/{self.repository}",
                           f"git@github.com:{self.repository}.git"}, "Origin differs from the exact same-repository GitHub identity.")
        pr = self.api(f"pulls/{self.handoff['pr']}")
        require(pr["merged"] is True and pr["merge_commit_sha"] == self.merge and pr["head"]["sha"] == self.head,
                "Merged PR/head/squash identity is unproven.")
        require(pr["base"]["ref"] == "main" and pr["head"]["ref"] == self.branch
                and pr["head"]["repo"] and pr["head"]["repo"]["full_name"] == self.repository,
                "Only an ordinary same-repository main PR is eligible.")
        issues = json.loads(self.command(["gh", "pr", "view", str(self.handoff["pr"]), "--repo", self.repository,
                                         "--json", "closingIssuesReferences"]))["closingIssuesReferences"]
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
        require(self.git("ls-remote", "--refs", "origin", "refs/heads/main").split()[0] == main,
                "Main changed during verification; retry fresh eligibility.")
        # Controller also checks chained workflows and downstream activity. This direct read
        # catches incomplete/failed exact-merge runs without treating an empty list as success.
        runs = self.api(f"actions/runs?head_sha={self.merge}&per_page=100")
        require(0 < runs["total_count"] <= 100, "Missing or oversized post-merge workflow evidence.")
        require(all(run["status"] == "completed" and run["conclusion"] in {"success", "skipped"}
                    for run in runs["workflow_runs"]), "Post-merge workflows remain incomplete or unsuccessful.")
        self.task()
        self.local_state()
        if self.execute:
            self.git("fetch", "--no-prune", "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no",
                     "origin", "refs/heads/main:refs/remotes/origin/main")
            require(self.git("rev-parse", "refs/remotes/origin/main") == main,
                    "Origin main changed during fetch; repeat eligibility before deletion.")
            self.git("merge-base", "--is-ancestor", self.merge, "refs/remotes/origin/main")
            self.task()
        if "validation_resources_released" in self.gates:
            self.verify_resources_absent()
        self.local_state()

    def local_state(self) -> None:
        """Protect active, dirty, locked, shared, replaced, or ambiguously absent worktrees."""
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
            require(not self.git("-C", str(self.target), "status", "--porcelain", "--untracked-files=all"),
                    "Dirty or untracked worktree content blocks cleanup.")
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

    def validate_resource_identity(self, resource: dict) -> None:
        """Require repository/PR binding, an exact locator, and durable original manifest bytes."""
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
        require(not path.is_relative_to(self.target), "Preserve the original ownership manifest outside the worktree.")
        for candidate in self.handoff["resources"]:
            if isinstance(candidate, dict) and candidate.get("path"):
                require(not path.is_relative_to(ordinary(Path(candidate["path"]))),
                        "Ownership manifest lies inside a resource removal root.")
        require(path.stat().st_size <= 262144, "Ownership manifest exceeds the bounded evidence limit.")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == manifest["sha256"],
                "Original resource ownership manifest changed or is unproven.")
        if resource["kind"] == "generated_tree":
            require(resource.get("path") and isinstance(resource.get("root_identity"), list)
                    and len(resource["root_identity"]) == 3, "Generated root creation identity is incomplete.")
        else:
            require(isinstance(resource.get("cleanup_tool"), str) and resource["cleanup_tool"].strip(),
                    "Specialized resource requires its exact supported owning cleanup tool.")

    def verify_resources_absent(self) -> None:
        """Revisit the entire inventory so earlier resources cannot silently reappear."""
        for resource in self.handoff["resources"]:
            self.validate_resource_identity(resource)
            result = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
            require(result.get("absent") is True and result.get("ownership_verified") is True
                    and result.get("inactive") is True and result.get("retained") is False,
                    "Aggregate resource absence readback failed; preserve remaining resources and retry inspection.")
            if resource.get("path"):
                require(not ordinary(Path(resource["path"])).exists(), "An inventoried resource path reappeared.")

    def record(self, gate: str) -> None:
        """Durably preserve completed gates before the next transition; no evidence writes in preview."""
        self.gates.append(gate)
        if self.execute:
            ordinary(self.evidence)
            self.evidence.mkdir(parents=True, exist_ok=True)
            destination = self.evidence / f"{self.digest}-{uuid.uuid4()}.json"
            with destination.open("x", encoding="utf-8") as stream:
                json.dump({"handoff_sha256": self.digest, "task_id": self.handoff["task_id"],
                           "gates": self.gates, "resource_evidence": self.resource_evidence}, stream)
                stream.flush()
                os.fsync(stream.fileno())

    def resources(self) -> None:
        """Delegate specialized resources to their owning tools and demand independent absence readback."""
        identities: set[str] = set()
        for resource in self.handoff["resources"]:
            self.validate_resource_identity(resource)
        for resource in self.handoff["resources"]:
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
            self.git("merge-base", "--is-ancestor", resource["source_commit"], self.head)
            result = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
            require(result.get("ownership_verified") is True and result.get("inactive") is True
                    and result.get("retained") is False and result.get("supported_cleanup") is True,
                    "Resource ownership, inactivity, retention, or owning cleanup capability blocks release.")
            require(result.get("evidence_preserved") is True, "Preserve resource evidence outside every removal root first.")
            require(type(result.get("absent")) is bool, "Resource absence must be independently observed.")
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
                    require(snapshot["."]["identity"] == resource["root_identity"],
                            "Generated root differs from its inventoried creation identity.")
                    self.proposed[-1] = {"resource": identity, "path": str(path), "entries": snapshot,
                                         "action": "remove exact generated tree through checked handles"}
                    if self.execute:
                        self.eligibility()
                        self.validate_resource_identity(resource)
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
                released = self.controller.call("resource.release", {"resource": resource, "handoff_sha256": self.digest})
                require(released.get("success") is True, "Owning tool failed or refused resource release; preserve remaining resources.")
                result = self.controller.call("resource.inspect", {"resource": resource, "handoff_sha256": self.digest})
            if self.execute:
                require(result.get("absent") is True and result.get("ownership_verified") is True,
                        "Resource absence lacks independent readback; branch/worktree cleanup blocked.")
                self.record(f"resource_released:{identity}")
        if self.execute:
            self.verify_resources_absent()
            if self.target.exists():
                require(not self.git("-C", str(self.target), "ls-files", "--others", "--ignored", "--exclude-standard"),
                        "Unreleased ignored files remain; resource inventory/release is incomplete.")
            self.record("validation_resources_released")

    def run(self) -> dict:
        """Reconcile ordered transitions from live evidence, including interrupted and title-only retries."""
        self.eligibility()
        if self.execute:
            self.record("cleanup_prepared")
        self.resources()
        self.proposed += [{"remote_ref": self.branch, "expected_sha": self.head},
                          {"worktree": str(self.target), "local_ref": self.branch}]
        try:
            expected = completed_task_title(self.handoff["description"], self.handoff["issues"], [self.handoff["pr"]])
        except ValueError as exc:
            raise Refusal(str(exc)) from exc
        self.proposed.append({"task_id": self.handoff["task_id"], "title": expected})
        if not self.execute:
            return {"status": "preview", "proposed": self.proposed, "gates": [], "handoff_sha256": self.digest}
        self.eligibility()
        if self.git("ls-remote", "--refs", "origin", f"refs/heads/{self.branch}"):
            self.git("push", "origin", f"--force-with-lease=refs/heads/{self.branch}:{self.head}",
                     f":refs/heads/{self.branch}")
        require(not self.git("ls-remote", "--refs", "origin", f"refs/heads/{self.branch}"), "Remote ref absence verification failed.")
        self.record("remote_branch_absent")
        self.eligibility()
        if self.target.exists():
            # Git's non-forced removal protects tracked/untracked edits; the controller
            # must independently account for all ignored files before this transition.
            ignored = self.git("-C", str(self.target), "ls-files", "--others", "--ignored", "--exclude-standard")
            require(not ignored, "Ignored validation/configuration files remain; release them through their owning tools first.")
            self.git("worktree", "remove", str(self.target))
        require(not self.target.exists() and not any(Path(item["worktree"]) == self.target for item in self.worktrees()),
                "Worktree path or registration remains; retry only after independent reconciliation.")
        self.task()
        require(not any(item.get("branch") == f"refs/heads/{self.branch}" for item in self.worktrees()),
                "Local branch is referenced by a worktree; preserve it.")
        local = self.git("for-each-ref", "--format=%(objectname)", f"refs/heads/{self.branch}")
        require(local in {"", self.head}, "Local branch changed after worktree removal.")
        if local:
            self.git("update-ref", "-d", f"refs/heads/{self.branch}", self.head)
        require(not self.git("for-each-ref", "--format=%(objectname)", f"refs/heads/{self.branch}"),
                "Local task ref still exists; resume local-ref removal only.")
        self.record("local_task_branch_absent")
        self.record("worktree_removed")
        self.eligibility()
        result = self.controller.call("task.title", {"task_id": self.handoff["task_id"], "expected_title": expected,
                                                     "handoff_sha256": self.digest})
        if result.get("capability") == "unavailable":
            require(result.get("capability_evidence"), "Unavailable title controls require explicit capability evidence.")
            self.record("task_title_done:not_applicable")
        else:
            require(result.get("persisted_readback") is True, "Rename acknowledgement is not persisted title readback.")
            try:
                verify_completed_task_title(expected, result.get("observed_title", ""))
            except ValueError as exc:
                raise Refusal(str(exc)) from exc
            self.record("task_title_readback_verified")
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
