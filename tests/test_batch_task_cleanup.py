"""Exercise atomic lifecycle handling for multi-PR Codex tasks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.completed_task_cleanup as cleanup_module
from scripts.completed_task_cleanup import BatchCleanup, Refusal
from scripts.completed_task_title import completed_task_title


class BatchController:
    """Provide independent batch inventory and title readback for orchestration tests."""

    def __init__(self) -> None:
        """Initialize controller state used to inject an incomplete peer inventory."""
        self.calls: list[tuple[str, dict]] = []
        self.pending_pr: int | None = None
        self.title_capability_unavailable = False
        self.observed_title: str | None = None

    def call(self, operation: str, payload: dict) -> dict:
        """Return a batch-bound inventory or persisted title readback.

        Args:
            operation: Supported controller operation requested by the cleanup flow.
            payload: Exact request body bound to the batch or title transition.
        """
        self.calls.append((operation, payload))
        if operation == "task.inspect":
            binding = payload["batch"]
            is_pending = any(member["pr"] == self.pending_pr for member in binding["members"])
            return {
                "handoff_sha256": payload["sha256"],
                "batch_sha256": binding["batch_sha256"],
                "batch_identity_verified": True,
                "batch_membership_complete": not is_pending,
                "evidence_refs": ["fixture-independent-batch-inventory"],
                "identity_verified": True,
                "exclusive_ownership_verified": True,
                "idle": True,
                "unpinned": True,
                "holds_clear": True,
                "downstream_clear": True,
                "inventory_verified": True,
                "post_merge_complete": True,
                "reviews_complete": True,
                "supported_tools_used": True,
                "post_merge_runs": [{"id": 1, "run_attempt": 1, "workflow_id": 2,
                                     "head_sha": "b" * 40, "event": "push"}],
            }
        assert operation == "task.title"
        if self.title_capability_unavailable:
            return {"capability": "unavailable", "capability_evidence": "No supported mutable task-title control."}
        return {"persisted_readback": True,
                "observed_title": self.observed_title or payload["expected_title"]}


class FakeMember:
    """Model the existing Cleanup member contract without Git or external resources."""

    states: dict[str, dict] = {}

    def __init__(self, handoff: Path, evidence: Path, config: Path, execute: bool,
                 controller: BatchController) -> None:
        """Bind a member handoff and recover idempotent fixture progress.

        Args:
            handoff: Schema-1 handoff path referenced by the batch manifest.
            evidence: Per-member journal root selected by BatchCleanup.
            config: Active Codex configuration path.
            execute: Whether transitions may be simulated as mutations.
            controller: Shared fixture controller.
        """
        raw = handoff.read_bytes()
        self.digest = hashlib.sha256(raw).hexdigest()
        self.handoff = json.loads(raw)
        expected_fields = {"schema", "primary_checkout", "worktree", "worktree_identity", "branch", "head",
                           "merge", "repository", "pr", "issues", "resources", "task_id", "description",
                           "task_title"}
        if set(self.handoff) != expected_fields or self.handoff["schema"] != 1:
            raise Refusal("Invalid child handoff schema.")
        self.handoff_path = handoff
        self.evidence = evidence
        self.config = config
        self.execute = execute
        self.controller = controller
        self.repo = Path(self.handoff["primary_checkout"])
        self.target = Path(self.handoff["worktree"])
        if not self.target.is_dir() or self.handoff["worktree_identity"] != [
            self.target.stat().st_dev, self.target.stat().st_ino,
        ]:
            raise Refusal("Child worktree identity changed.")
        self.root = config.parent / "worktrees"
        self.repository = self.handoff["repository"]
        self.branch = self.handoff["branch"]
        self.lock_digest = hashlib.sha256(str(self.handoff["pr"]).encode("utf-8")).hexdigest()
        self.expected_title = ""
        self.batch_binding: dict = {}
        self.batch_coordinator: BatchCleanup | None = None
        self.gates: list[str] = []
        self.proposed: list[dict] = []
        self.resource_evidence: list[dict] = []
        self.state = self.states.setdefault(self.digest, {"mutations": 0, "gates": [], "fail_reconcile": False,
                                                            "pending": False, "change_batch": False, "scopes": []})
        self.gates = list(self.state["gates"])
        self.evidence_path = evidence

    def eligibility(self) -> None:
        """Require a complete independently reported batch inventory for this member."""
        if self.state["pending"]:
            raise Refusal("Peer member is pending review.")
        if self.batch_coordinator is not None:
            self.batch_coordinator.preflight()
            result = self.batch_coordinator.controller.call("task.inspect", {
                "handoff": self.handoff, "sha256": self.digest, "batch": self.batch_binding,
            })
            if result.get("batch_sha256") != self.batch_binding["batch_sha256"] \
                    or result.get("batch_identity_verified") is not True \
                    or result.get("batch_membership_complete") is not True:
                raise Refusal("Complete independently verified batch membership is required.")

    def validate_resource_identity(self, resource: dict) -> None:
        """Accept an empty resource fixture while retaining the production call boundary.

        Args:
            resource: Child validation resource whose identity the coordinator rechecks.
        """
        assert resource

    def inventory_scopes(self) -> dict[str, list[str]]:
        """Return no extra fixture scopes for members with empty resource inventories."""
        return {"generated_tree": list(self.state["scopes"])}

    def resources(self) -> None:
        """Collect a read-only resource proposal for this empty-resource member."""
        self.proposed.extend([])

    def restore_gates(self) -> None:
        """Restore idempotent member gates from fixture state."""
        self.gates = list(self.state["gates"])

    def record(self, gate: str) -> None:
        """Persist one monotonic fixture gate.

        Args:
            gate: Gate name recorded by the cleanup coordinator.
        """
        if gate not in self.gates:
            self.gates.append(gate)
        self.state["gates"] = list(self.gates)

    def reconcile(self) -> dict:
        """Simulate one member transition, with optional failure or manifest-race injection."""
        self.eligibility()
        if self.state["fail_reconcile"]:
            raise Refusal("Injected member release failure.")
        if self.execute and "member_complete" not in self.gates:
            self.state["mutations"] += 1
            for gate in ("validation_resources_released", "remote_branch_absent", "local_task_branch_absent",
                         "worktree_removed", "member_complete"):
                self.record(gate)
            if self.state["change_batch"] and self.batch_coordinator is not None:
                with self.batch_coordinator.handoff_path.open("ab") as stream:
                    stream.write(b" ")
                self.state["change_batch"] = False
        return {"status": "member_complete", "gates": self.gates, "handoff_sha256": self.digest}


@pytest.fixture(autouse=True)
def clear_fake_member_state() -> None:
    """Isolate persistent fake journal state between tests."""
    FakeMember.states.clear()


def _fixture_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, count: int = 2,
                   execute: bool = False, pr_numbers: tuple[int, ...] | None = None,
                   target_names: tuple[str, ...] | None = None) -> tuple[Path, Path, Path, dict, list[Path]]:
    """Write a schema-2 batch and matching schema-1 member handoffs under pytest's root.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and module substitutions.
        count: Number of member handoffs to create.
        execute: Whether the resulting batch will simulate guarded execution.
        pr_numbers: Optional PR identities for duplicate-member validation cases.
        target_names: Optional worktree paths for overlap validation cases.
    """
    FakeMember.states.clear()
    worktree_root = tmp_path / "worktrees"
    worktree_root.mkdir()
    primary = worktree_root / "primary"
    primary.mkdir()
    home = tmp_path / "codex"
    home.mkdir()
    config = home / "config.toml"
    config.write_text("[desktop]\ngit-worktree-root = " + json.dumps(str(worktree_root)), encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(home))
    monkeypatch.setattr(cleanup_module, "Cleanup", FakeMember)

    prs = pr_numbers or tuple(200 + index for index in range(count))
    targets = target_names or tuple(f"task-{index}" for index in range(count))
    title = "Repair batch · Issues #100, #101 · PRs #200, #201"
    members: list[Path] = []
    references: list[dict[str, str]] = []
    for index in range(count):
        target = worktree_root / targets[index]
        target.mkdir(parents=True, exist_ok=True)
        handoff = {
            "schema": 1,
            "primary_checkout": str(primary),
            "worktree": str(target),
            "worktree_identity": [target.stat().st_dev, target.stat().st_ino],
            "branch": f"enhancement/967-member-{index}",
            "head": chr(ord("a") + index) * 40,
            "merge": chr(ord("c") + index) * 40,
            "repository": "example/Atlaso",
            "pr": prs[index],
            "issues": [100 + index],
            "resources": [],
            "task_id": "batch-task",
            "description": "Repair batch",
            "task_title": title,
        }
        path = worktree_root / f"member-{index}.json"
        raw = json.dumps(handoff, sort_keys=True).encode("utf-8")
        path.write_bytes(raw)
        members.append(path)
        references.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()})
    document = {"schema": 2, "task_id": "batch-task", "task_title": title,
                "description": "Repair batch", "handoffs": references}
    batch = worktree_root / "batch.json"
    batch.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    evidence = worktree_root / "evidence"
    return batch, evidence, config, document, members


def _make_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, controller: BatchController,
                *, execute: bool = False, **kwargs: object) -> BatchCleanup:
    """Build a coordinator around generated fixture handoffs.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped fixture substitutions for environment and Cleanup.
        controller: Fake supported-tool bridge.
        execute: Whether to simulate guarded state transitions.
        **kwargs: Additional fixture shape controls passed to `_fixture_batch`.
    """
    batch, evidence, config, _document, _members = _fixture_batch(
        tmp_path, monkeypatch, execute=execute, **kwargs,
    )
    return BatchCleanup(batch, evidence, config, execute, controller)


@pytest.mark.parametrize("invalid", ["schema", "extra-key", "child-digest"])
def test_batch_constructor_rejects_invalid_schema_and_child_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str,
) -> None:
    """Refuse schema drift and raw child digest changes before member execution.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and module substitutions.
        invalid: Manifest or child binding defect to inject.
    """
    controller = BatchController()
    batch, evidence, config, document, members = _fixture_batch(tmp_path, monkeypatch)
    if invalid == "schema":
        document["schema"] = 1
        batch.write_text(json.dumps(document), encoding="utf-8")
    elif invalid == "extra-key":
        document["unexpected"] = True
        batch.write_text(json.dumps(document), encoding="utf-8")
    else:
        document["handoffs"][0]["sha256"] = "0" * 64
        batch.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(Refusal):
        BatchCleanup(batch, evidence, config, True, controller)


@pytest.mark.parametrize("defect", ["duplicate-pr", "overlap", "identity"])
def test_batch_constructor_rejects_duplicate_overlapping_or_mismatched_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str,
) -> None:
    """Refuse duplicate PRs, overlapping worktrees, and child task identity drift.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and module substitutions.
        defect: Member consistency defect to inject.
    """
    controller = BatchController()
    targets = ("task", "task/nested") if defect == "overlap" else None
    prs = (201, 201) if defect == "duplicate-pr" else None
    batch, evidence, config, document, members = _fixture_batch(
        tmp_path, monkeypatch, pr_numbers=prs, target_names=targets,
    )
    if defect == "identity":
        handoff = json.loads(members[1].read_text(encoding="utf-8"))
        handoff["description"] = "Different task"
        raw = json.dumps(handoff, sort_keys=True).encode("utf-8")
        members[1].write_bytes(raw)
        document["handoffs"][1]["sha256"] = hashlib.sha256(raw).hexdigest()
        batch.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    with pytest.raises(Refusal):
        BatchCleanup(batch, evidence, config, True, controller)


def test_batch_preview_preflights_all_members_without_requesting_title(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preview the aggregate title and inventory without member or title mutations.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and Cleanup substitution.
    """
    controller = BatchController()
    batch = _make_batch(tmp_path, monkeypatch, controller)
    result = batch.run()
    assert result["status"] == "preview"
    assert len(batch.members) == 2
    assert sum(operation == "task.inspect" for operation, _payload in controller.calls) >= 2
    assert not any(operation == "task.title" for operation, _payload in controller.calls)
    assert all(member.state["mutations"] == 0 for member in batch.members)
    assert batch.proposed[-1]["title"] == completed_task_title("Repair batch", [100, 101], [200, 201])


def test_incomplete_peer_inventory_blocks_before_first_member_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a pending peer during full preflight before any member transition.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and Cleanup substitution.
    """
    controller = BatchController()
    controller.pending_pr = 201
    batch = _make_batch(tmp_path, monkeypatch, controller, execute=True)
    with pytest.raises(Refusal):
        batch.run()
    assert all(member.state["mutations"] == 0 for member in batch.members)
    assert not any(operation == "task.title" for operation, _payload in controller.calls)

def test_overlapping_specialized_scope_into_peer_blocks_batch_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a generated scope that enters another member worktree before cleanup starts.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and Cleanup substitution.
    """
    controller = BatchController()
    batch = _make_batch(tmp_path, monkeypatch, controller)
    batch.members[0].state["scopes"] = [str(batch.members[1].target / "generated-output")]
    with pytest.raises(Refusal, match="overlap or contain protected peer state"):
        batch.run()
    assert all(member.state["mutations"] == 0 for member in batch.members)
    assert not any(operation == "task.title" for operation, _payload in controller.calls)


def test_two_members_complete_with_one_title_transition_and_read_only_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Complete two members, then revalidate without replaying member mutations or renaming twice.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and Cleanup substitution.
    """
    controller = BatchController()
    batch = _make_batch(tmp_path, monkeypatch, controller, execute=True)
    first = batch.run()
    assert first["status"] == "complete"
    assert [member.state["mutations"] for member in batch.members] == [1, 1]
    initial_title_calls = [payload for operation, payload in controller.calls if operation == "task.title"]
    assert len(initial_title_calls) == 1
    assert initial_title_calls[0]["verify_only"] is False
    assert all("task_title_done" not in member.gates for member in batch.members)
    assert "batch_task_title_done" in batch.anchor.gates

    retry = BatchCleanup(batch.handoff_path, batch.evidence, batch.anchor.config, True, controller)
    assert retry.run()["status"] == "complete"
    assert [member.state["mutations"] for member in retry.members] == [1, 1]
    title_calls = [payload for operation, payload in controller.calls if operation == "task.title"]
    assert len(title_calls) == 2
    assert title_calls[1]["verify_only"] is True


def test_unavailable_title_capability_is_preserved_across_idempotent_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep title capability evidence and avoid replaying completed member mutations on retry.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and Cleanup substitution.
    """
    controller = BatchController()
    controller.title_capability_unavailable = True
    batch = _make_batch(tmp_path, monkeypatch, controller, execute=True)
    assert batch.run()["status"] == "complete"
    assert "batch_title_done:not_applicable" in batch.anchor.gates
    assert "batch_task_title_done" in batch.anchor.gates

    retry = BatchCleanup(batch.handoff_path, batch.evidence, batch.anchor.config, True, controller)
    assert retry.run()["status"] == "complete"
    assert [member.state["mutations"] for member in retry.members] == [1, 1]
    assert "batch_title_done:not_applicable" in retry.anchor.gates
    assert "batch_task_title_done" in retry.anchor.gates


def test_member_failure_blocks_aggregate_title_and_retry_does_not_repeat_completed_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain member one progress after peer failure and retry without duplicate mutations.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and Cleanup substitution.
    """
    controller = BatchController()
    batch = _make_batch(tmp_path, monkeypatch, controller, execute=True)
    batch.members[1].state["fail_reconcile"] = True
    with pytest.raises(Refusal, match="Injected member release failure"):
        batch.run()
    assert batch.members[0].state["mutations"] == 1
    assert batch.members[1].state["mutations"] == 0
    assert not any(operation == "task.title" for operation, _payload in controller.calls)

    batch.members[1].state["fail_reconcile"] = False
    retried = BatchCleanup(batch.handoff_path, batch.evidence, batch.anchor.config, True, controller)
    assert retried.run()["status"] == "complete"
    assert [member.state["mutations"] for member in retried.members] == [1, 1]
    title_calls = [payload for operation, payload in controller.calls if operation == "task.title"]
    assert len(title_calls) == 1
    assert title_calls[0]["batch"]["batch_sha256"] == retried.digest


def test_changed_batch_manifest_during_member_transition_blocks_later_member_and_title(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recheck the batch digest between member transitions and refuse a changed manifest.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment and Cleanup substitution.
    """
    controller = BatchController()
    batch = _make_batch(tmp_path, monkeypatch, controller, execute=True)
    batch.members[0].state["change_batch"] = True
    with pytest.raises(Refusal, match="Batch manifest changed"):
        batch.run()
    assert batch.members[0].state["mutations"] == 1
    assert batch.members[1].state["mutations"] == 0
    assert not any(operation == "task.title" for operation, _payload in controller.calls)


def test_cli_preserves_member_gates_on_title_readback_refusal_and_retries_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    """Report title verification as an actionable refusal and retry the same completed batch safely.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment, module, and CLI argument substitutions.
        capsys: Pytest capture fixture for the structured cleanup result.
    """
    import sys

    controller = BatchController()
    controller.observed_title = "Stale and truncated title"
    batch_path, evidence, config, _document, _children = _fixture_batch(tmp_path, monkeypatch, execute=True)
    monkeypatch.setattr(cleanup_module, "Controller", lambda: controller)
    monkeypatch.setattr(sys, "argv", ["cleanup", "--handoff", str(batch_path), "--evidence", str(evidence),
                                     "--config", str(config), "--execute"])

    assert cleanup_module.main() == 1
    refused = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert refused["status"] == "refused"
    assert refused["retry_condition"] == (
        "Persisted title differs from the expected title; task_title_done remains blocked."
    )
    assert "pr:200:worktree_removed" in refused["gates"]
    assert "pr:201:worktree_removed" in refused["gates"]
    assert not any("batch_title_readback_verified" in gate or "batch_task_title_done" in gate
                   for gate in refused["gates"])
    assert [state["mutations"] for state in FakeMember.states.values()] == [1, 1]

    controller.observed_title = None
    assert cleanup_module.main() == 0
    completed = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert completed["status"] == "complete"
    assert "pr:200:batch_title_readback_verified" in completed["gates"]
    assert "pr:200:batch_task_title_done" in completed["gates"]
    assert [state["mutations"] for state in FakeMember.states.values()] == [1, 1]


def test_cli_surfaces_aggregate_title_budget_refusal_before_any_member_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    """Expose the aggregate identifier-budget limit before mutation while each member title still fits.

    Args:
        tmp_path: Pytest-owned disposable fixture root.
        monkeypatch: Scoped environment, module, and CLI argument substitutions.
        capsys: Pytest capture fixture for the structured cleanup result.
    """
    import sys

    prs = (2_000_000_000, 2_000_000_001, 2_000_000_002)
    for index, pr in enumerate(prs):
        assert completed_task_title("Repair batch", [100 + index], [pr])

    controller = BatchController()
    batch_path, evidence, config, _document, children = _fixture_batch(
        tmp_path, monkeypatch, count=3, execute=True, pr_numbers=prs,
    )
    monkeypatch.setattr(cleanup_module, "Controller", lambda: controller)
    monkeypatch.setattr(sys, "argv", ["cleanup", "--handoff", str(batch_path), "--evidence", str(evidence),
                                     "--config", str(config), "--execute"])

    assert cleanup_module.main() == 1
    refused = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert refused["status"] == "refused"
    assert refused["gates"] == []
    assert refused["retry_condition"] == (
        "All issue/PR identifiers and Done exceed the title budget; maintainer direction is required."
    )
    assert batch_path.is_file() and all(child.is_file() for child in children)
    assert len(FakeMember.states) == len(prs)
    assert all(state["mutations"] == 0 for state in FakeMember.states.values())
    assert controller.calls == []


class TaskProbeController:
    """Supply controlled responses to the real single-member task and title methods."""

    def __init__(self, result: dict) -> None:
        """Keep the independent task-inspection response and record requested operations.

        Args:
            result: Task-inspection result to return to the real Cleanup.task method.
        """
        self.result = result
        self.calls: list[tuple[str, dict]] = []

    def call(self, operation: str, payload: dict) -> dict:
        """Return the prepared inventory or exact persisted-title readback.

        Args:
            operation: Supported controller operation requested by Cleanup.
            payload: Request body that is recorded for assertions.
        """
        self.calls.append((operation, payload))
        if operation == "task.inspect":
            return dict(self.result)
        assert operation == "task.title"
        return {"persisted_readback": True, "observed_title": payload["expected_title"]}


def _real_task_probe(tmp_path: Path, result: dict) -> cleanup_module.Cleanup:
    """Construct a minimal real Cleanup instance for task-inspection contract coverage.

    Args:
        tmp_path: Pytest-owned path used only as a nonexistent target identity.
        result: Independent task-inspection result returned by the controller stub.
    """
    member = object.__new__(cleanup_module.Cleanup)
    member.handoff = {
        "task_id": "batch-task",
        "task_title": "Repair batch · Issues #100, #101 · PRs #200, #201",
        "resources": [],
        "merge": "c" * 40,
    }
    member.digest = "d" * 64
    member.batch_binding = {"batch_sha256": "e" * 64, "members": []}
    member.controller = TaskProbeController(result)
    member.config = tmp_path / "config.toml"
    member.root = tmp_path
    member.evidence = tmp_path / "evidence"
    member.execute = True
    member.repository = "example/Atlaso"
    member.branch = "enhancement/967-member"
    member.target = tmp_path / "absent-worktree"
    member.expected_title = "Issues #100, #101 · PRs #200, #201 · Repair batch · Done"
    member.resource_evidence = []
    member.git = lambda *_arguments: ""
    member.api = lambda _endpoint: {
        "id": 1, "run_attempt": 1, "workflow_id": 2, "head_sha": member.handoff["merge"],
        "event": "push", "repository": {"full_name": member.repository},
        "status": "completed", "conclusion": "success",
    }
    return member


def _eligible_task_inspection() -> dict:
    """Return the complete independent task response required by the real Cleanup.task method."""
    return {
        "handoff_sha256": "d" * 64,
        "batch_sha256": "e" * 64,
        "batch_identity_verified": True,
        "batch_membership_complete": True,
        "identity_verified": True,
        "exclusive_ownership_verified": True,
        "idle": True,
        "unpinned": True,
        "holds_clear": True,
        "downstream_clear": True,
        "inventory_verified": True,
        "post_merge_complete": True,
        "reviews_complete": True,
        "supported_tools_used": True,
        "inventory_empty_verified": True,
        "evidence_refs": ["fixture-independent-batch-inventory"],
        "observed_title": "Issues #100, #101 · PRs #200, #201 · Repair batch · Done",
        "post_merge_runs": [{"id": 1, "run_attempt": 1, "workflow_id": 2,
                             "head_sha": "c" * 40, "event": "push"}],
    }


@pytest.mark.parametrize("field,value", [
    ("batch_sha256", "f" * 64),
    ("batch_identity_verified", False),
    ("batch_membership_complete", False),
])
def test_real_cleanup_task_requires_complete_matching_batch_attestation(
    tmp_path: Path, field: str, value: object,
) -> None:
    """Require the actual Cleanup.task method to reject missing batch attestations.

    Args:
        tmp_path: Pytest-owned path used as an absent worktree target.
        field: Batch attestation field to invalidate.
        value: Mismatched or false value returned by the controller.
    """
    result = _eligible_task_inspection()
    result[field] = value
    member = _real_task_probe(tmp_path, result)
    with pytest.raises(Refusal, match="batch membership"):
        member.task()


def test_real_cleanup_task_accepts_matching_complete_batch_attestation(tmp_path: Path) -> None:
    """Accept actual task.inspect results only when every batch identity field matches.

    Args:
        tmp_path: Pytest-owned path used as an absent worktree target.
    """
    member = _real_task_probe(tmp_path, _eligible_task_inspection())
    member.task()
    assert member.resource_evidence[0]["operation"] == "task.inspect"


def test_real_cleanup_task_allows_original_title_after_unavailable_batch_title_control(tmp_path: Path) -> None:
    """Allow the recorded title when batch completion is explicitly not applicable.

    Args:
        tmp_path: Pytest-owned path used as an absent worktree target.
    """
    result = _eligible_task_inspection()
    result["observed_title"] = "Original recorded title"
    member = _real_task_probe(tmp_path, result)
    member.handoff["task_title"] = "Original recorded title"
    anchor = type("Anchor", (), {"gates": ["batch_title_done:not_applicable", "batch_task_title_done"]})()
    member.batch_coordinator = type("Batch", (), {"anchor": anchor})()
    member.task()


def test_real_cleanup_task_rejects_original_title_after_batch_title_readback(tmp_path: Path) -> None:
    """Reject the old title after a batch title readback was already verified.

    Args:
        tmp_path: Pytest-owned path used as an absent worktree target.
    """
    result = _eligible_task_inspection()
    result["observed_title"] = "Original recorded title"
    member = _real_task_probe(tmp_path, result)
    member.handoff["task_title"] = "Original recorded title"
    anchor = type("Anchor", (), {"gates": ["batch_title_readback_verified", "batch_task_title_done"]})()
    member.batch_coordinator = type("Batch", (), {"anchor": anchor})()
    with pytest.raises(Refusal, match="Live task title differs"):
        member.task()


@pytest.mark.parametrize("is_batch,expected_status", [(True, "member_complete"), (False, "complete")])
def test_real_cleanup_reconcile_defers_title_only_for_batch_members(
    tmp_path: Path, is_batch: bool, expected_status: str,
) -> None:
    """Keep the real reconcile path title-free for batch members and ordinary for one PR.

    Args:
        tmp_path: Pytest-owned path used as a nonexistent worktree.
        is_batch: Whether the cleanup member has a batch coordinator binding.
        expected_status: Expected member or ordinary cleanup status.
    """
    member = object.__new__(cleanup_module.Cleanup)
    member.execute = True
    member.handoff = {"task_id": "batch-task", "task_title": "Repair batch", "resources": []}
    member.digest = "d" * 64
    member.branch = "enhancement/967-member"
    member.head = "a" * 40
    member.expected_title = "Issues #100 · PR #200 · Repair batch · Done"
    member.target = tmp_path / "absent-worktree"
    member.gates = []
    member.proposed = []
    member.resource_evidence = []
    member.controller = TaskProbeController(_eligible_task_inspection())
    member.eligibility = lambda: None
    member.resources = lambda: None
    member.verify_directory_release = lambda: None
    member.task = lambda: None
    member.worktrees = lambda: []
    member.require_direct_task_ref = lambda: None
    member.record = lambda gate: member.gates.append(gate)
    member.git = lambda *_arguments: ""
    if is_batch:
        member.batch_coordinator = SimpleNamespace(preflight=lambda: None)

    result = member.reconcile()
    assert result["status"] == expected_status
    title_calls = [operation for operation, _payload in member.controller.calls if operation == "task.title"]
    assert title_calls == ([] if is_batch else ["task.title"])
