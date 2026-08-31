#!/usr/bin/env python3
"""Repository-wide syntax and content checks for Atlaso.

The checker is intentionally lightweight so it can run as a pre-commit hook on
changed files and as a full-repo smoke test before pushing a branch.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from urllib.parse import unquote

import yaml

ROOT = Path(__file__).resolve().parents[1]

SKIP_PARTS = {
    ".git",
    ".build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site",
    "test-results",
}

SKIP_PREFIXES = (
    Path("atlaso/app/static/vendor"),
    Path("third_party"),
    Path("VCFDT"),
    Path("vcfDownloadTool"),
)

TEXT_SUFFIXES = {
    ".conf",
    ".css",
    ".hcl",
    ".htm",
    ".html",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".svg",
    ".service",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]+\]\(([^)]+)\)")
TABULATOR_CONSTRUCTOR_RE = re.compile(
    r"\bnew\s+(?:(?:window|globalThis|global)\.)?Tabulator\s*\("
)
HTML_FORM_RE = re.compile(
    r"<form\b(?P<attributes>[^>]*)>(?P<body>.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)
UI_PATTERN_FOUNDATION = Path("atlaso/app/static/ui-patterns.js")
LEGACY_TABULATOR_MARKER = "atlaso-legacy-tabulator: #117"
WIZARD_REQUIRED_MARKERS = (
    "data-atlaso-wizard-step",
    "data-atlaso-wizard-nav",
    "data-atlaso-wizard-error",
    "data-atlaso-wizard-back",
    "data-atlaso-wizard-next",
    "data-atlaso-wizard-cancel",
    "data-atlaso-wizard-submit",
)
FORBIDDEN_PAGE_WIZARD_CONTROLLER_MARKERS = (
    'querySelectorAll("[data-atlaso-wizard-step]")',
    "querySelectorAll('[data-atlaso-wizard-step]')",
    'querySelectorAll("[data-atlaso-wizard-nav]")',
    "querySelectorAll('[data-atlaso-wizard-nav]')",
    "dataset.atlasoWizardStep",
    "dataset.atlasoWizardNav",
)

SPARK_WORKER_AGENT_PATH = Path(".codex/agents/spark-worker.toml")
SPARK_WORKER_REQUIRED_VALUES = {
    "name": "spark_worker",
    "model": "gpt-5.3-codex-spark",
    "model_reasoning_effort": "medium",
}
SPARK_WORKER_ALLOWED_KEYS = frozenset(
    (*SPARK_WORKER_REQUIRED_VALUES, "description", "developer_instructions")
)
SPARK_WORKER_OVERRIDE_MESSAGES = {
    "approval_policy": "Spark worker must inherit the parent approval policy",
    "sandbox_mode": "Spark worker must inherit the parent sandbox mode",
    "tools": "Spark worker must inherit the parent tools",
}
SPARK_WORKER_REQUIRED_INSTRUCTION_MARKERS = (
    "Mandatory Agent Startup Gate",
    "Mandatory UI Design Guide Gate",
    "Do not make architecture decisions.",
    "Do not broaden the assigned scope.",
    "Do not handle security-sensitive work",
    "cross-component integration decisions",
    "final verification",
    "Do not spawn or delegate to other agents.",
    "Do not commit, push",
    "change GitHub state.",
    "Run focused tests",
    "Ruff",
    "mypy",
    "Return a concise summary",
)

PROTECTED_PUBLICATION_WORKFLOWS = (
    Path(".github/workflows/inventory-linux-release.yml"),
    Path(".github/workflows/promote-release.yml"),
    Path(".github/workflows/release.yml"),
    Path(".github/workflows/virtualization-prerelease.yml"),
    Path(".github/workflows/virtualization-stable.yml"),
    Path(".github/workflows/virtualization-windows-candidate.yml"),
    Path(".github/workflows/wheel.yml"),
)

SCHEDULED_PR_MONITORING_SHARED_MARKERS = (
    "current-task heartbeat",
    "four minutes",
    "persistent GitHub polling loops",
    "seen comment and review IDs",
    "delivery-complete merge-ready",
    "final bounded readback",
    "delete the exact current-task heartbeat",
    "linked-issue closure",
    "current `origin/main` reachability",
    "applicable post-merge workflow verification",
    "unmerged closed",
    "delivery-complete",
    "never delete unrelated",
    "already absent",
    "terminal evidence",
    "resumable holds",
    "`wait for approval` remains resumable",
    "ambiguous ownership",
    "exact retry condition",
    "never merely paused",
)

DEFAULT_MERGE_AUTHORITY_SHARED_MARKERS = (
    "current user's or maintainer's instructions",
    "later explicit",
    "delegated prompts",
    "task handoffs",
    "heartbeat prompts",
    "preserve that provenance",
    "stale memory",
    "historical policy",
    "agent-authored",
    "invented",
    "guarded merge",
    "second merge instruction",
    "remains disabled",
)

REQUIRED_POLICY_MARKERS = {
    Path("AGENTS.md"): (
        "## Mandatory Agent Startup Gate",
        "## Codex Task Title Traceability",
        "### Supported title controls",
        "Short description · Issue #<issue> · PR #<pr>",
        "### Unsupported title controls",
        "### Schema-constrained reporting",
        "## Sol and Spark Delegation",
        "`spark_worker`",
        "`gpt-5.3-codex-spark`",
        "never substitutes another model",
        "## Mandatory UI Design Guide Gate",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "docs/contribute/ui-design-guide.md",
        "first progress update",
        "delegating agent",
        "direct-edit Tabulator",
        "custom/other",
        "explicit maintainer approval",
        "private vulnerability remediation",
        "advisory-side maintainer review",
        "test suite locally when required",
        "### Focused local validation and pull-request follow-through",
        "Python test suite locally",
        "ready for review",
        "@codex review",
        "exact head",
        "reviewThreads",
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comments",
        "inline review comments",
        "review submissions",
        "### Unrelated issue discoveries",
        "### Default merge authorization",
        "default merge authority",
        "explicit merge hold",
        "strict up-to-date required checks",
        "no merge queue is required",
        "--match-head-commit <head-sha>",
        "### Extended merge descriptions",
        "## Completed Task Cleanup",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        "`non_task_owned_remote_branch_preserved`",
        "`non_task_owned_checkout_preserved`",
        '" · Done"',
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
    ),
    Path("CONTRIBUTING.md"): (
        "## Automated contributors and coding agents",
        "## User-interface contributions",
        "Mandatory Agent Startup Gate",
        "Mandatory UI Design Guide Gate",
        "docs/contribute/ui-design-guide.md",
        "custom/other",
        "delegated agent",
        "### Automated pull-request follow-through",
        "Python test suite locally",
        "ready for review",
        "@codex review",
        "exact head",
        "review threads",
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comments",
        "inline review comments",
        "review submissions",
        "### Unrelated issue discoveries",
        "### Default merge authorization",
        "default merge authority",
        "explicit merge hold",
        "strict up-to-date required checks",
        "no required merge queue",
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
        "private vulnerability remediation",
        "advisory-side maintainer review",
        "complete Python test suite locally",
        "### Completed task cleanup",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        "`non_task_owned_remote_branch_preserved`",
        "`non_task_owned_checkout_preserved`",
        '" · Done"',
    ),
    Path(".github/copilot-instructions.md"): (
        "Mandatory Agent Startup Gate",
        "Mandatory UI Design Guide Gate",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "docs/contribute/ui-design-guide.md",
        "custom/other",
        "linked GitHub issue",
        "complete Python test suite belongs to GitHub CI",
        "ready for review",
        "@codex review",
        "exact head",
        "review threads",
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comments",
        "inline review comments",
        "review submissions",
        "Default merge authorization",
        "default merge authority",
        "explicit merge hold",
        "strict up-to-date required checks",
        "when a merge queue is required",
        "evidence-backed unrelated problem",
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
        "private vulnerability remediation",
        "advisory-side maintainer review",
        "complete Python test suite locally",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        "`non_task_owned_remote_branch_preserved`",
        "`non_task_owned_checkout_preserved`",
        '" · Done"',
    ),
    Path("SECURITY.md"): (
        "## Privately fixing a validated vulnerability",
        "draft repository security advisory",
        "temporary private fork",
        "current default branch",
        "workspace repositories",
        "`UNSTABLE`",
        "`gh pr merge`",
        "Merge pull request(s)",
        "only one pull request may target `main`",
        "Publishing the advisory is a separate explicit action",
        "Explicit maintainer authorization",
        "coordinated disclosure",
        "advisory-side maintainer review",
        "complete Python test suite locally",
    ),
    Path("docs/contribute/agent-policies.md"): (
        "# Detailed agent policies",
        "## Mandatory Agent Startup Gate",
        "## Sol and Spark Delegation",
        "`spark_worker`",
        "`gpt-5.3-codex-spark`",
        "Do not silently",
        "## Repository Delivery Workflow",
        "private vulnerability remediation",
        "temporary private fork",
        "`gh pr merge`",
        "Publishing is a separate explicit action",
        "explicit maintainer authorization",
        "Advisory-side maintainer review",
        "complete Python test suite locally",
        "### Focused local validation and pull-request follow-through",
        "Python test suite locally",
        "ready for review",
        "@codex review",
        "exact head",
        "reviewThreads",
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comments",
        "inline review comments",
        "review submissions",
        "outside that scope is discovered",
        "### Default merge authorization",
        "default merge authority",
        "explicit merge hold",
        "strict up-to-date required checks",
        "no required merge queue",
        "### Completed task cleanup",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        "`non_task_owned_remote_branch_preserved`",
        "`non_task_owned_checkout_preserved`",
        '" · Done"',
    ),
    Path(".github/pull_request_template.md"): (
        "Closes #",
        "Mandatory Agent Startup Gate",
        "For an ordinary pull request, focused local tests/checks passed",
        "complete Python test suite",
        "ready for review",
        "each post-opening pushed commit received one `@codex review` request",
        "request as the exact",
        "authoritative review threads",
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comment",
        "inline review comment",
        "review submission",
        "Default merge authorization",
        "default merge authority",
        "explicit merge hold",
        "strict up-to-date required checks",
        "no merge queue is required",
        "Evidence-backed issues discovered outside",
        "docs/contribute/ui-design-guide.md",
        "custom/other",
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
        "private vulnerability-remediation pull request",
        "advisory-side maintainer review",
        "complete Python test suite ran locally",
        "`cleanup-ready`",
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
        "`non_task_owned_remote_branch_preserved`",
        "`non_task_owned_checkout_preserved`",
        '" · Done"',
    ),
    Path("docs/contribute/ui-design-guide.md"): (
        "# Atlaso UI Design Guide",
        "Tabulator is the only data-grid implementation",
        "Physical Interfaces",
        "ESX Storage",
        "Tasks",
        "Audit Events",
        "Automation Schedules",
        "Reviewed semantic-table exemptions",
        "Custom/other",
        "explicit maintainer approval",
        "AtlasoUiPatterns.createGrid",
        "AtlasoUiPatterns.createWizard",
    ),
    Path("docs/reference/full-technical-reference.md"): (
        "default merge authority",
        "explicit merge hold",
        "strict up-to-date required checks",
        "when a merge queue is required",
        "`non_task_owned_remote_branch_preserved`",
        "`non_task_owned_checkout_preserved`",
        "worktree removal remote branch gate is either verified absent or recorded not applicable",
        "primary checkout remote branch gate is either verified absent or recorded not applicable",
    ),
}

SCHEDULED_PR_MONITORING_SECTION_ANCHORS = {
    Path("AGENTS.md"): "### Focused local validation and pull-request follow-through",
    Path("CONTRIBUTING.md"): "### Automated pull-request follow-through",
    Path(".github/copilot-instructions.md"): (
        "- keep the task active with exactly one current-task heartbeat"
    ),
    Path(".github/pull_request_template.md"): (
        "- [ ] For an ordinary pull request, exactly one current-task heartbeat"
    ),
    Path("docs/contribute/agent-policies.md"): (
        "### Focused local validation and pull-request follow-through"
    ),
}

SCHEDULED_PR_MONITORING_SECTION_END_ANCHORS = {
    Path(".github/copilot-instructions.md"): (
        "- apply the **Default merge authorization** policy"
    ),
    Path(".github/pull_request_template.md"): (
        "- [ ] For an ordinary same-repository pull request within the active "
        "task's scope, the Default merge authorization"
    ),
}

SCHEDULED_PR_MONITORING_SECTION_MARKERS = {
    Path("AGENTS.md"): (
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comments",
        "inline review comments",
        "review submissions",
    ),
    Path("CONTRIBUTING.md"): (
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comments",
        "inline review comments",
        "review submissions",
    ),
    Path(".github/copilot-instructions.md"): (
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comments",
        "inline review comments",
        "review submissions",
    ),
    Path(".github/pull_request_template.md"): (
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comment",
        "inline review comment",
        "review submission",
    ),
    Path("docs/contribute/agent-policies.md"): (
        *SCHEDULED_PR_MONITORING_SHARED_MARKERS,
        "top-level pull-request comments",
        "inline review comments",
        "review submissions",
    ),
}

DEFAULT_MERGE_AUTHORITY_SECTION_ANCHORS = {
    Path("AGENTS.md"): "### Default merge authorization",
    Path("CONTRIBUTING.md"): "### Default merge authorization",
    Path(".github/copilot-instructions.md"): (
        "- apply the **Default merge authorization** policy"
    ),
    Path(".github/pull_request_template.md"): (
        "- [ ] For an ordinary same-repository pull request within the active "
        "task's scope, the Default merge authorization"
    ),
    Path("docs/contribute/agent-policies.md"): "### Default merge authorization",
}

DEFAULT_MERGE_AUTHORITY_SECTION_MARKERS = {
    path: DEFAULT_MERGE_AUTHORITY_SHARED_MARKERS
    for path in DEFAULT_MERGE_AUTHORITY_SECTION_ANCHORS
}

MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH = Path(
    "tests/fixtures/merge_authority_transfer.json"
)
EXPLICIT_MERGE_HOLD_PATTERNS = {
    "do not merge": (
        "do not merge",
        "don't merge",
        "don’t merge",
        "never merge",
        "hold off on merging",
        "hold off on the merge",
        "defer merging",
        "defer the merge",
        "delay merging",
        "delay the merge",
        "postpone merging",
        "postpone the merge",
        "pause before merging",
        "refrain from merging",
        "refrain from the merge",
        "wait before merging",
    ),
    "leave open": (
        "leave open",
        "leave the pull request open",
        "leave this pull request open",
        "leave the pr open",
        "leave this pr open",
        "keep the pull request open",
        "keep this pull request open",
        "keep the pr open",
        "keep this pr open",
        "keep the pull request unmerged",
        "keep this pull request unmerged",
        "keep the pr unmerged",
        "keep this pr unmerged",
    ),
    "pr only": (
        "pull request only",
        "pr only",
        "only open the pull request",
        "only open this pull request",
        "only open a pull request",
        "only open a pr",
        "only open an pr",
        "only create the pull request",
        "only create this pull request",
        "only create a pull request",
        "only create a pr",
        "only create an pr",
        "only submit the pull request",
        "only submit this pull request",
        "only submit a pull request",
        "only submit a pr",
        "only submit an pr",
        "only prepare the pull request",
        "only prepare this pull request",
        "only prepare a pull request",
        "only prepare a pr",
        "only prepare an pr",
    ),
    "wait for approval": (
        "wait for approval",
        "wait for my approval",
        "wait for your approval",
        "await approval",
        "await my approval",
        "await your approval",
        "wait for maintainer approval",
        "wait for the maintainer's approval",
        "wait for the maintainer’s approval",
        "wait for owner approval",
        "wait until approved",
        "wait until i approve",
        "wait until we approve",
        "wait for me to approve",
        "wait for us to approve",
        "after approval",
        "after my approval",
        "after our approval",
        "after your approval",
        "after maintainer approval",
        "once approved",
        "when approved",
        "with approval",
        "with maintainer approval",
        "subject to approval",
        "subject to maintainer approval",
        "pending approval",
        "pending maintainer approval",
        "unless approved",
        "until i approve",
        "until we approve",
        "for me to approve",
        "for us to approve",
        "merge only after i approve",
        "merge only after we approve",
        "merge only if i approve",
        "merge only if we approve",
        "merge only after maintainer approves",
        "merge only after the maintainer approves",
        "merge only if maintainer approves",
        "merge only if the maintainer approves",
        "merge only after owner approves",
        "merge only after the owner approves",
        "merge only if owner approves",
        "merge only if the owner approves",
        "merge only with my approval",
        "merge only with our approval",
    ),
}
MERGE_HOLD_WITHDRAWAL_MARKERS = (
    "withdrawn",
    "lifted",
    "removed",
    "cancelled",
    "canceled",
    "withdraw the",
    "remove the",
    "remove ",
    "lift the",
    "lift ",
    "cancel the",
    "cancel ",
    "no longer applies",
    "no longer need to",
    "rescinded",
    "revoked",
    "may merge now",
    "do not leave open",
    "don't leave open",
    "don’t leave open",
    "do not leave this pr open",
    "do not leave the pr open",
    "do not leave this pull request open",
    "do not leave the pull request open",
    "don't leave this pr open",
    "don't leave the pr open",
    "don't leave this pull request open",
    "don't leave the pull request open",
    "don’t leave this pr open",
    "don’t leave the pr open",
    "don’t leave this pull request open",
    "don’t leave the pull request open",
    "do not wait for approval",
    "don't wait for approval",
    "don’t wait for approval",
    "not pull request only",
    "not pr only",
)
MERGE_HOLD_WITHDRAWAL_NEGATIONS = re.compile(
    r"(?:(?:must|should|may|might|will|would|could|can)\s+not|not|never|"
    r"cannot|can't|can’t|isn't|isn’t|wasn't|wasn’t)"
    r"(?:\s+(?:be|been))?\s*$"
)
MERGE_HOLD_WITHDRAWAL_NONCURRENT_PREFIX = re.compile(
    r"(?:\bunless\b|\bif\b|\bonce\b|\bwhen\b|\bafter\b|\bbefore\b|"
    r"\b(?:will|would|may|might|could|shall)\s+(?:be\s+)?)"
)
MERGE_HOLD_WITHDRAWAL_NONCURRENT_SUFFIX = re.compile(
    r"^\s*(?:tomorrow|later|eventually|(?:only\s+)?"
    r"(?:after|when|once|if|unless)\b)"
)
AUTO_MERGE_ONLY_PATTERN = re.compile(
    r"\b(?:do not|don't|don’t)\s+(?:"
    r"merge(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?\s+automatically|"
    r"merge(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?\s+"
    r"(?:via|using|with)\s+(?:github\s+)?auto[- ]merge|"
    r"automatically\s+merge(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?"
    r")\b"
)
MERGE_HOLD_MODAL_PROHIBITION = re.compile(
    r"\b(?:(?:you\s+)?(?:(?:must|may|can|should)\s+not|cannot|can't|can’t)"
    r"\s+merge|"
    r"you\s+(?:(?:are\s+not|aren't|aren’t|isn't|isn’t)\s+"
    r"(?:allowed|authorized)\s+to\s+merge|are\s+forbidden\s+from\s+merging)|"
    r"you\s+do\s+not\s+have\s+(?:permission|authorization)\s+"
    r"to\s+merge)\b"
)
DEFAULT_MERGE_AUTHORITY_NEGATIONS = re.compile(
    r"(?:(?:do not|don't|don’t|never|must not|should not|cannot|can't|can’t|not)"
    r"(?:\s+\w+){0,6}|(?:lacks?|has no|have no|without)(?:\s+\w+){0,4}|"
    r"(?:there\s+is|there's|there’s)\s+no\s+"
    r"(?:authority|authorization|permission)\s+to|"
    r"(?:skip|avoid|omit|decline|refrain(?:\s+from)?|"
    r"hold off(?:\s+on)?|defer|delay|postpone|pause)"
    r"(?:\s+\w+){0,3})\s*$"
)
DEFAULT_MERGE_AUTHORITY_TRAILING_NEGATIONS = re.compile(
    r"^\s*(?:[\u0022\u0027\u0060\u2019\u201d]\s*)?"
    r"(?:[,;]\s*)?(?:(?:but|and)\s+)?"
    r"(?:(?:does|do|is|are|must|should|can|may|will|would)\s+"
    r"(?:not|never)|doesn't|doesn’t|isn't|isn’t|aren't|aren’t|"
    r"cannot|can't|can’t|won't|won’t|wouldn't|wouldn’t|"
    r"(?:is|are|remains?|be)\s+(?:forbidden|disallowed|prohibited))\b"
)
DEFAULT_MERGE_AUTHORITY_SECOND_INSTRUCTION_CONDITIONS = re.compile(
    r"(?:only\s+)?(?:after|once|when|until)\b.{0,80}"
    r"\b(?:second|another|separate|additional)\b.{0,30}\bmerge instruction\b"
)
DEFAULT_MERGE_AUTHORITY_CONDITIONAL_APPROVAL = re.compile(
    r"(?:only\s+)?(?:if|when|once|after|with|unless|pending|subject to)\b"
    r"[^.!?]{0,60}\b(?:approv\w*|permission|authorization)\b"
)
DEFAULT_MERGE_AUTHORITY_CONDITIONAL_REQUEST = re.compile(
    r"\b(?:if|when|once|after)\s+(?:(?:(?:the|a)\s+)?"
    r"(?:user|maintainer|owner)\s+(?:asks?|requests?|instructs?|tells?)|"
    r"(?:asked|requested|instructed|told))\b"
)
DEFAULT_MERGE_AUTHORITY_DECISION_ONLY = re.compile(r"\bwhether\s+to\b")
DEFAULT_MERGE_AUTHORITY_PERMISSION_QUESTION = re.compile(
    r"\b(?:(?:do|would)\s+you\s+(?:want|like)\s+(?:me|us)\s+to|"
    r"should\s+(?:i|we)|(?:can|could|may)\s+(?:i|we)|"
    r"do\s+(?:i|we)\s+have\s+(?:authority|authorization|permission)\s+to|"
    r"(?:am|are|is)\s+(?:i|we)\s+(?:authorized|permitted|allowed)\s+to)\b"
)
DEFAULT_MERGE_AUTHORITY_PROMPT_MARKERS = (
    "preserve default merge authority",
    "use the repository's default merge authority",
    "apply default merge authority",
    "exercise default merge authority",
    "guarded squash merge",
    "guarded-squash-merge",
    "carry the task through guarded merge",
    "complete the guarded merge",
    "without waiting for a second merge instruction",
)
DEFAULT_MERGE_AUTHORITY_SOURCE_EXCLUSIONS = re.compile(
    r"(?:review(?:-only|[^.!?]{0,60}\bonly\b)|"
    r"only\s+review\b[^;.!?]*|"
    r"report findings only|"
    r"\bplan(?:ning)?\s+(?:an?\s+)?(?:fix|patch|implementation|change|"
    r"update|solution)\b|"
    r"(?:do not|don't|don’t|must not|without)\s+"
    r"(?:\w+\s+){0,3}(?:implement|fix|patch|resolve|solve|deliver|"
    r"(?:updat|chang|modif|edit|mak)\w*\s+(?:any\s+)?"
    r"(?:changes?|code|implementation|issue|task))|"
    r"(?:do not|don't|don’t|must not|without)\s+"
    r"(?:\w+\s+){0,3}(?:address|apply)\s+(?:review\s+)?feedback\s+"
    r"(?:on|for)\s+(?:an?\s+)?(?:existing\s+)?(?:ordinary\s+)?"
    r"(?:pull request|pr)|"
    r"(?:diagnos(?:e|tic)|investigat(?:e|ion)|analy(?:ze|sis)|assess|inspect)"
    r"[^.!?]{0,80}\b(?:without|no)\b[^.!?]{0,40}"
    r"\b(?:implement|chang|modif|edit|mak)|"
    r"(?:please\s+)?(?:investigate|analyze|assess|diagnose|inspect|evaluate)\s+"
    r"(?:how|what|whether)\b[^.!?]{0,80}\b"
    r"(?:implement|fix|patch|resolve|solve|change|modify|edit)\b|"
    r"(?:open(?:ing)?|create|submit|prepare|deliver|leave|keep)\s+"
    r"(?:(?:an?|the|this)\s+)?draft (?:pull request|pr)|"
    r"(?:open(?:ing)?|create|submit|prepare|deliver|leave|keep)\s+"
    r"(?:(?:an?|the|this)\s+)?(?:pull request|pr)"
    r"[^.!?]{0,20}\bas (?:an? )?draft\b|"
    r"(?:leave|keep|remain)\s+(?:(?:this|the)\s+)?(?:pull request|pr)\s+"
    r"(?:in|as)\s+(?:an?\s+)?draft\b)"
)
DEFAULT_MERGE_AUTHORITY_WORKFLOW_EXCLUSIONS = re.compile(
    r"(?:perform|follow|conduct|undertake|use)\s+(?:the\s+)?"
    r"private (?:vulnerability|advisory|remediation)\b|"
    r"(?:fix|patch|resolve|remediate|address)\s+"
    r"(?:(?:this|the|an?)\s+)?(?:security\s+)?vulnerabilit(?:y|ies)\b|"
    r"(?:fix|patch|resolve|change|modify|edit|work on)\s+"
    r"(?:(?:an?|the|this|existing)\s+)?draft (?:pull request|pr)\b|"
    r"(?:implement|fix|patch|resolve|solve|deliver|change|modify|edit|work on)"
    r"\b[^.!?]{0,60}\b(?:external fork|"
    r"(?:from|in|on|inside|within)\s+"
    r"(?:(?:an?|the|this|my|your|our|their)\s+)?(?:external\s+)?fork|"
    r"(?:on|in|against) (?:(?:an?|the|this|existing) )?"
    r"draft (?:pull request|pr)\b|"
    r"private (?:vulnerability|advisory|remediation))\b"
)
DEFAULT_MERGE_AUTHORITY_WORKFLOW_RECLASSIFICATION = re.compile(
    r"(?:^|[;.!?]\s*)(?:this|the\s+(?:work|task|implementation))\s+is\s+"
    r"(?:now\s+)?private (?:vulnerability|advisory|remediation)\b|"
    r"(?:^|[;.!?]\s*)(?:the|this)\s+(?:pull request|pr)\s+is\s+"
    r"(?:now\s+)?(?:an?\s+)?draft\b|"
    r"(?:^|[;.!?]\s*)move\s+(?:the\s+)?(?:work|task|implementation)\s+"
    r"to\s+(?:an?\s+)?(?:external\s+)?fork\b|"
    r"(?:^|[;.!?]\s*)(?:convert|mark|move)\s+"
    r"(?:(?:the|this)\s+)?(?:pull request|pr)\s+(?:to|as)\s+"
    r"(?:an?\s+)?draft\b|"
    r"(?:^|[;.!?]\s*)make\s+(?:(?:the|this)\s+)?"
    r"(?:(?:pull request|pr)\s+)?(?:an?\s+)?draft\s*(?:pull request|pr)?\b"
)
DEFAULT_MERGE_AUTHORITY_DIRECT_REVIEW = re.compile(
    r"(?:review|inspect|check|test|summarize|describe|explain|report|"
    r"verif(?:y|ication)|validat(?:e|ion)|"
    r"analy(?:ze|sis)|assess|audit|evaluat(?:e|ion))(?:\s+of)?\s+"
    r"(?:(?:the|this|that|an?|my|our|your|their|his|her|its)\s+)?"
    r"(?:(?:proposed|existing|current|updated|submitted)\s+)?"
    r"(?:implementation|changes?|code|patch|fix(?:es)?|pull request|pr|commit|"
    r"it|them)\b"
    r"(?:\s+(?:#\d+|[0-9a-f]{7,40}))?"
    r"(?:\s+and\s+(?:report|summarize|describe)\b[^;.!?]*)?"
)
DEFAULT_MERGE_AUTHORITY_INTERROGATIVE_REVIEW = re.compile(
    r"(?:^|[;.!?]\s*)(?:can|could|would|will)\s+you\s+"
    r"(?:explain|describe|assess|evaluate|tell)\b[^?]*\?|"
    r"(?:^|[;.!?]\s*)(?:is|are|was|were|does|do|did)\s+"
    r"(?:(?:the|this|that|an?)\s+)?"
    r"(?:implementation|fix|patch|changes?|code|pull request|pr)\b[^?]*\?|"
    r"(?:^|[;.!?]\s*)how\s+(?:do|should|can|could|would)\s+"
    r"(?:i|we|you)\s+(?:implement|fix|patch|resolve|solve)\b[^?]*\?|"
    r"(?:^|[;.!?]\s*)what\s+(?:is|are)\s+(?:needed|required)\s+to\s+"
    r"(?:implement|fix|patch|resolve|solve)\b[^?]*\?"
)
DEFAULT_MERGE_AUTHORITY_REPORTED_DISCUSSION = re.compile(
    r"\b(?:(?:i|we|they|the\s+(?:user|maintainer|owner|team))\s+"
    r"(?:discussed|considered|contemplated|explored|talked\s+about)|"
    r"(?:i|we|they)\s+had\s+(?:a\s+)?discussion\s+about)\b"
    r"[^.!?]{0,80}\b(?:implement|fix|patch|resolve|solve|change|modify|edit)\b"
)
DEFAULT_MERGE_AUTHORITY_SUPERSEDING_REVIEW_PREFIX = re.compile(
    r"(?:^|[;.!?]\s*)(?:instead,?|switch to|move to|change to)\s*$"
)
DEFAULT_MERGE_AUTHORITY_SUPERSEDING_REVIEW_MARKER = re.compile(r"\binstead\b")
DEFAULT_MERGE_AUTHORITY_STOP_WORK = re.compile(
    r"(?:^|[;.!?]\s*|,\s*(?:but|and)\s+|\s+but\s+)(?:please\s+)?(?:"
    r"(?:stop|cancel|cease|end)\s+"
    r"(?:(?:all|further|this|the)\s+)?(?:work(?:ing)?|implementation|task)|"
    r"(?:cancel|end)\s+(?:this|that|the)\s+request)\b"
    r"(?![^;.!?]*\b(?:if|unless|when|once|after|before)\b)[^;.!?]*"
)
DEFAULT_MERGE_AUTHORITY_POST_STOP_SUMMARY = re.compile(
    r"(?:^|[;.!?]\s*)(?:please\s+)?(?:"
    r"(?:stop|cancel|cease|end)\s+"
    r"(?:(?:all|further|this|the)\s+)?(?:work(?:ing)?|implementation|task)|"
    r"(?:cancel|end)\s+(?:this|that|the)\s+request)\b"
    r"[^.!?]*[.!?]\s*(?:summarize|describe|explain|report|document)\b[^.!?]*"
)
DEFAULT_MERGE_AUTHORITY_POST_STOP_STATUS = re.compile(
    r"(?:^|[;.!?]\s*)(?:please\s+)?(?:"
    r"(?:stop|cancel|cease|end)\s+"
    r"(?:(?:all|further|this|the)\s+)?(?:work(?:ing)?|implementation|task)|"
    r"(?:cancel|end)\s+(?:this|that|the)\s+request)\b"
    r"[^.!?]*[.!?]\s*(?:(?:the|this|that)\s+)?"
    r"(?:implementation|work|task|change|patch|fix)\s+"
    r"(?:is|isn't|isn’t|is not|remains?|was|wasn't|wasn’t|was not)\b[^.!?]*"
)
DEFAULT_MERGE_AUTHORITY_NEGATED_MUTATION = re.compile(
    r"(?:^|[;.!?]\s*|,\s*(?:but|and)\s+|\s+but\s+)"
    r"(?:please\s+)?(?:do not|don't|don’t|must not)\s+"
    r"(?!leave\s+(?:(?:this|the)\s+)?(?:pull request|pr)\s+open\b)"
    r"(?:\w+\s+){0,3}(?:implement|fix|patch|resolve|solve|deliver|open|submit|"
    r"prepare|update|change|modify|edit|add|remove|create|build|refactor|repair|"
    r"commit|push)"
    r"\b[^;.!?]*"
)
DEFAULT_MERGE_AUTHORITY_SOURCE_MARKERS = re.compile(
    r"\b(?:implement|fix|patch|resolve|solve|deliver|refactor|repair)\b|"
    r"\bcomplete\s+(?:the\s+)?implementation\b|"
    r"\b(?:update|change|modify|edit|add|remove|create|build|"
    r"prepare|open|submit|revert|roll back)\s+"
    r"(?:(?:the|this|that|an?|new|existing)\s+)?"
    r"(?:code|changes?|implementation|documentation|docs?|tests?|files?|repository|repo|"
    r"scripts?|modules?|packages?|workflows?|polic(?:y|ies)|checkers?|fixtures?|"
    r"features?|behavio(?:u)?r|support|pages?|guides?|configuration|config|"
    r"api|ui|issue(?:s)?(?:\s+#\d+)?|pull request|pr)\b|"
    r"\bwork on (?:an? )?(?:existing )?(?:ordinary )?(?:pull request|pr)\b|"
    r"\b(?:address|resolve|apply|implement)\s+(?:review\s+)?feedback\s+"
    r"(?:on|for)\s+(?:an?\s+)?(?:existing\s+)?(?:ordinary\s+)?"
    r"(?:pull request|pr)\b|"
    r"pull[- ]request delivery|guarded[- ]squash merge|"
    r"task-owned pull request|ordinary same-repository"
)
DEFAULT_MERGE_AUTHORITY_COORDINATED_NO_WORK = re.compile(
    r"\b(?:do not|don't|don’t|must not|without)\s+"
    r"(?:\w+\s+){0,3}"
    r"(?:implement|fix|patch|resolve|solve|deliver|update|change|modify|edit|make|"
    r"add|remove|create|build|refactor)"
    r"(?:\s*(?:,\s*(?:(?:and|or)\s+)?|\s+(?:and|or)\s+)"
    r"(?:implement|fix|patch|resolve|solve|deliver|update|change|modify|edit|make|"
    r"add|remove|create|build|refactor)){1,}"
)
MERGE_AUTHORITY_INSTRUCTION_BOUNDARY = re.compile(
    r"(?:[;,.!?]+|\s+(?:but|and)\s+)"
)
MERGE_AUTHORITY_COARSE_BOUNDARY = re.compile(r"(?:[;,.!?]+|\s+but\s+)")
MERGE_HOLD_DISCUSSION_CONTEXT = re.compile(
    r"\b(?:explain(?:ed|ing)?|document(?:ed|ing)?|discuss(?:ed|ing)?|"
    r"describe(?:d|s|ing)?|mention(?:ed|ing)?|refer(?:red|ring)?|"
    r"test(?:ed|ing)?|plan(?:ned|ning)?|consider(?:ed|ing|ation)?|"
    r"contemplat(?:e|ed|ing|ion)|ask(?:ed|ing)?|"
    r"determin(?:e|ed|ing|ation)|decid(?:e|ed|ing))\b"
)
MERGE_HOLD_DIRECT_REQUEST_CONTEXT = re.compile(
    r"\b(?:i|we)\s+(?:ask|request)\s+that\s+(?:you\s+)?$"
)
MERGE_HOLD_DIRECT_DECISION_CONTEXT = re.compile(
    r"\b(?:(?:i|we)\s+decid(?:e|ed)|(?:my|our)\s+decision\s+is)\s*:\s*$"
)
MERGE_HOLD_CONDITIONAL_CLAUSE_COMMA = re.compile(
    r"(\b(?:if|when|once|after|unless)\b[^.!?]{0,80}),\s*"
    r"(?=(?:do not|don't|don’t|never|leave|keep|pull request|pr|only|"
    r"wait|await|hold off|defer|delay|postpone|pause|refrain)\b)"
)
MERGE_HOLD_CONDITIONAL_CONTEXT = re.compile(
    r"\b(?:if|when|once|after|unless)\b[^.!?]{0,100}$"
)
MERGE_HOLD_COMPLETED_ACTION_CONTEXT = re.compile(
    r"\bafter\s+(?:i|we|(?:the\s+)?(?:user|maintainer|owner))\s+"
    r"(?:(?:reviewed|checked|examined|inspected|confirmed|decided|evaluated|"
    r"assessed|read|saw|received|completed|finished)\b[^.!?]{0,80})$"
)
DEFAULT_MERGE_AUTHORITY_ACTION_BOUNDARY = re.compile(
    r"(?:[;,.!?]+|\s+(?:and|then|but)\s+)"
)
MERGE_HOLD_OTHER_TASK_SUFFIX = re.compile(
    r"^\s+(?:(?:for|on)\s+)?(?:(?:the|an?)\s+)?"
    r"(?:unrelated|other|another)\s+"
    r"(?:pull request|pr)\b"
)
MERGE_HOLD_OTHER_TASK_PREFIX = re.compile(
    r"(?:unrelated|other|another)\s+(?:pull request|pr)(?:\s*#\d+)?"
    r"(?:\s+[^.!?]{0,20})?\s*$"
)
MERGE_HOLD_OTHER_TASK_REFERENCE = re.compile(
    r"(?:unrelated|other|another)\s+(?:pull request|pr)\b"
)
MERGE_HOLD_ACTIVE_TASK_TARGET = re.compile(
    r"(?:(?:this|the)\s+)?(?:pull request|pr|branch|change|commit)\b"
)
MERGE_HOLD_OTHER_TASK_TRAILING_CLAUSE = re.compile(
    r"\s+(?:and|or|but)\s+(?:(?:for|on)\s+)?(?:(?:the|an?)\s+)?"
    r"(?:unrelated|other|another)\s+(?:pull request|pr)\b[^;.!?]*$"
)
MERGE_HOLD_NUMBERED_PR_REFERENCE = re.compile(
    r"\b(?:pull[- ]request|pr)\s*#(\d+)\b"
)
MERGE_HOLD_NUMBERED_ISSUE_REFERENCE = re.compile(r"\bissue\s*#(\d+)\b")
MERGE_HOLD_REPORTED_PERMISSION_CONTEXT = re.compile(
    r"\b(?:previous|prior|earlier|former|historical|stale)\b"
    r"[^.!?]{0,80}\b(?:claimed|said|reported|stated|suggested|wrote|asserted)\b"
)
MERGE_HOLD_INTERROGATIVE_PERMISSION_CONTEXT = re.compile(
    r"(?:\b(?:who|what|why|when|where|how)\b[^.!?]{0,80}"
    r"\b(?:said|says?|told|claimed|asked)\b|"
    r"\b(?:did|does|do|would|could|has|have|is|are|was|were)\b"
    r"[^.!?]{0,80}\b(?:said|say|tell|claim|authorize|permit)\b)"
)
MERGE_HOLD_NEGATED_PERMISSION_REPORT_CONTEXT = re.compile(
    r"(?:\b(?:no\s+one|nobody)\s+"
    r"(?:said|claimed|reported|stated|suggested|wrote|asserted)\b|"
    r"\b(?:i|we|(?:the\s+)?(?:user|maintainer|owner))\s+"
    r"(?:cannot|can't|can’t|did\s+not|didn't|didn’t|never)\s+"
    r"(?:say|claim|report|state|suggest|write|assert)\b)"
)
MERGE_HOLD_NONAUTHORITATIVE_SOURCE_CONTEXT = re.compile(
    r"(?:\baccording\s+to\s+(?:(?:the|a)\s+)?"
    r"(?:task\s+handoff|handoff|task[- ]note|policy|stale\s+memory|memory|"
    r"heartbeat|delegated\s+prompt)\b|"
    r"\b(?:task\s+handoff|handoff|task[- ]note|policy|stale\s+memory|memory|"
    r"heartbeat|delegated\s+prompt)\s+(?:said|says|reported|states?|claims?)\b)"
)
MERGE_AUTHORITY_TASK_CLAUSE_BOUNDARY = re.compile(r"[;.?!]+")
MERGE_AUTHORITY_COORDINATED_CLAUSE_BOUNDARY = re.compile(
    r",\s+(?:but|and)\s+|\s+but\s+"
)
MERGE_HOLD_STANDALONE_PERMISSION = re.compile(
    r"\b(?:(?P<imperative>merge now|(?:please\s+)?merge\s+"
    r"(?:(?:this|the)\s+)?(?:pull request|pr)(?:\s+now)?)|"
    r"you\s+(?:may|can)\s+merge"
    r"(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?(?:\s+now)?|"
    r"i\s+authorize\s+you\s+to\s+merge"
    r"(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?|"
    r"you\s+have\s+(?:permission|authorization)\s+to\s+merge"
    r"(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?|"
    r"go ahead and merge|"
    r"proceed (?:with the merge|with merging|to merge)(?: now)?)\b"
)
MERGE_HOLD_APPROVAL_CONDITION = re.compile(
    r"\b(?:merge(?: only)?|only merge)"
    r"(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?\s+"
    r"(?:after|when|if|once|until|unless|before)\s+"
    r"(?:(?:i|we|(?:the\s+)?maintainer|"
    r"(?:the\s+)?(?:[a-z][a-z0-9_-]*\s+)?owner)\s+approves?|approved)\b"
)
MERGE_HOLD_APPROVAL_CONDITION_FIRST = re.compile(
    r"\b(?:(?:only\s+)?(?:with\s+(?:(?:my|our|your)\s+approval|"
    r"(?:(?:the\s+)?(?:user|maintainer|owner)(?:'s|’s)?)\s+approval)|"
    r"after\s+(?:i|we|(?:the\s+)?(?:user|maintainer|owner))\s+approves?)\s+"
    r"(?:may|can|should)\s+(?:you|i|we)\s+merge"
    r"(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?|"
    r"approval\s+is\s+(?:required|needed)\s+before\s+(?:you|i|we)\s+merge"
    r"(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?)\b"
)
MERGE_HOLD_APPROVAL_BOUNDED_DISPOSITION = re.compile(
    r"\b(?:(?:do not|don't|don’t|never)\s+merge"
    r"(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?|"
    r"(?:leave|keep)\s+(?:(?:this|the)\s+)?(?:pull request|pr)\s+open|"
    r"(?:pull request|pr)\s+only|"
    r"only\s+(?:open|create|submit|prepare)\s+"
    r"(?:(?:an?|the|this)\s+)?(?:pull request|pr))\b"
    r"[^.!?]{0,60}\b(?:after|when|if|once|until|unless|before|prior\s+to)\s+"
    r"(?:(?:i|we|(?:the\s+)?maintainer|"
    r"(?:the\s+)?(?:[a-z][a-z0-9_-]*\s+)?owner)\s+approves?|approved|"
    r"(?:(?:the\s+)?(?:user|maintainer|"
    r"(?:[a-z][a-z0-9_-]*\s+)?owner)(?:'s|’s)?\s+)?approval)\b"
)
MERGE_HOLD_APPROVAL_BEFORE_MERGING = re.compile(
    r"\b(?:wait (?:for|until)\s+(?:(?:the\s+)?"
    r"(?:user|maintainer|(?:[a-z][a-z0-9_-]*\s+)?owner)\s+to\s+approve|"
    r"(?:(?:the\s+)?(?:user|maintainer|(?:[a-z][a-z0-9_-]*\s+)?owner)"
    r"(?:'s|’s)?\s+)?approval)|"
    r"(?:(?:you|i|we)\s+)?(?:get|obtain|require|need)\s+(?:(?:the\s+)?"
    r"(?:user|maintainer|(?:[a-z][a-z0-9_-]*\s+)?owner)"
    r"(?:'s|’s)?\s+|(?:my|our|your)\s+)?approval)\b"
    r"[^.!?]{0,40}\bbefore merging\b"
)
MERGE_HOLD_WITHOUT_APPROVAL = re.compile(
    r"\b(?:do not|don't|don’t|must not)\s+merge"
    r"(?:\s+(?:(?:this|the)\s+)?(?:pull request|pr))?\s+without\s+"
    r"(?:(?:my|our|your|the|maintainer|owner|code owner)\s+)?approval\b"
)
MERGE_HOLD_NON_PR_OBJECT = re.compile(
    r"^\s+(?!(?:(?:this|the)\s+)?(?:pull request|pr)\b|it\b|"
    r"(?:(?:this|the)\s+)?(?:branch|change|commit)\b|"
    r"(?:hold|instruction|directive)s?\b|until\b|before\b|after\b|unless\b|"
    r"because\b|while\b|when\b|yet\b|now\b|automatically\b|"
    r"into\s+(?:(?:the\s+)?(?:main|master|default|target|base)\s+branch|"
    r"main|master)\b|"
    r"(?:to|for)\s+(?:merge|merging)\b|"
    r"for\s+issue(?:\s+#\d+)?\b|"
    r"from\s+(?:(?:the)\s+)?(?:maintainer|owner|me|us|you)\b|"
    r"for\s+(?:now|the moment|approval|maintainer approval)\b)\w+"
)
MERGE_HOLD_NONMERGE_APPROVAL_QUALIFIER = re.compile(
    r"^\s+(?:before|after|until|when|if|once)\s+"
    r"(?!(?:(?:we|you|i|they)\s+)?(?:merge|merging)\b)"
    r"(?!(?:(?:the|this)\s+)?(?:pull request|pr)\b)\w+"
)
MERGE_HOLD_WITHDRAWAL_BEFORE_HOLD = re.compile(
    r"\s*(?:(?:the|previous|current|explicit|earlier)\s+){0,3}"
)
MERGE_HOLD_WITHDRAWAL_AFTER_HOLD = re.compile(
    r"\s*(?:(?:hold|instruction|directive)s?\s*)?"
    r"(?:(?:is|are|was|were|has been|have been)\s*)?"
    r"(?:(?:hereby|explicitly|now|formally)\s*)?"
)

ORDERED_TERMINAL_CLEANUP_MARKERS = {
    path: (
        "`remote_branch_absent`",
        "`worktree_removed`",
        "`task_title_done`",
    )
    for path in (
        Path("AGENTS.md"),
        Path("CONTRIBUTING.md"),
        Path(".github/copilot-instructions.md"),
        Path(".github/pull_request_template.md"),
        Path("docs/contribute/agent-policies.md"),
    )
}

TERMINAL_CLEANUP_SECTION_ANCHORS = {
    Path("AGENTS.md"): "## Completed Task Cleanup",
    Path("CONTRIBUTING.md"): "### Completed task cleanup",
    Path(".github/copilot-instructions.md"): (
        "- after an authorized merge and all remaining activity,"
    ),
    Path(".github/pull_request_template.md"): (
        "- [ ] After any authorized merge and remaining post-merge activity,"
    ),
    Path("docs/contribute/agent-policies.md"): "### Completed task cleanup",
}

PRIVATE_REMEDIATION_CLEANUP_MARKER = "`advisory_cleanup_ready`"
PRIVATE_REMEDIATION_REMOTE_MARKER = "`advisory_remote_branch_absent`"
PRIMARY_CHECKOUT_RESTORED_MARKER = "`primary_checkout_restored`"
PRIMARY_CHECKOUT_RESUME_MARKER = "`primary_checkout_resume`"
LOCAL_TASK_BRANCH_ABSENT_MARKER = "`local_task_branch_absent`"
REMOTE_BRANCH_LEASE_MARKER = "`--force-with-lease=refs/heads/BRANCH:HEAD_SHA`"
WORKTREE_REMOVAL_RESUME_MARKER = "`worktree_removal_resume`"
WORKTREE_REMOVAL_REMOTE_GATE_MARKER = (
    "worktree removal remote branch gate is either verified absent "
    "or recorded not applicable"
)
PRIMARY_CHECKOUT_REMOTE_GATE_MARKER = (
    "primary checkout remote branch gate is either verified absent "
    "or recorded not applicable"
)
TITLE_CONTROL_UNAVAILABLE_MARKER = "`task_title_done` as verified not applicable"
NON_TASK_OWNED_REMOTE_BRANCH_PRESERVED_MARKER = (
    "`non_task_owned_remote_branch_preserved`"
)
NON_TASK_OWNED_CHECKOUT_PRESERVED_MARKER = "`non_task_owned_checkout_preserved`"
TERMINAL_CLEANUP_SECTION_MARKERS = {
    path: (
        "`cleanup-ready`",
        *ordered_markers,
        '" · Done"',
        PRIMARY_CHECKOUT_RESTORED_MARKER,
        PRIMARY_CHECKOUT_RESUME_MARKER,
        LOCAL_TASK_BRANCH_ABSENT_MARKER,
        REMOTE_BRANCH_LEASE_MARKER,
        WORKTREE_REMOVAL_RESUME_MARKER,
        WORKTREE_REMOVAL_REMOTE_GATE_MARKER,
        PRIMARY_CHECKOUT_REMOTE_GATE_MARKER,
        TITLE_CONTROL_UNAVAILABLE_MARKER,
        NON_TASK_OWNED_REMOTE_BRANCH_PRESERVED_MARKER,
        NON_TASK_OWNED_CHECKOUT_PRESERVED_MARKER,
        PRIVATE_REMEDIATION_CLEANUP_MARKER,
        PRIVATE_REMEDIATION_REMOTE_MARKER,
    )
    for path, ordered_markers in ORDERED_TERMINAL_CLEANUP_MARKERS.items()
}

TERMINAL_CLEANUP_ORDER_ANCHOR = "Terminal order:"
TERMINAL_CLEANUP_ORDER_LINES = tuple(
    f"{position}. {marker}"
    for position, marker in enumerate(
        next(iter(ORDERED_TERMINAL_CLEANUP_MARKERS.values())), start=1
    )
)


@dataclass(frozen=True)
class Finding:
    """Represent finding.

    Attributes:
        path: Path maintained by this finding.
        message: Message maintained by this finding.
        line: Line maintained by this finding.
    """

    path: Path
    message: str
    line: int | None = None

    def render(self) -> str:
        """Render operation.

        Returns:
            The render result.
        """
        display = self.path.relative_to(ROOT) if self.path.is_absolute() else self.path
        if self.line is None:
            return f"{display}: {self.message}"
        return f"{display}:{self.line}: {self.message}"


def explicit_merge_holds(text: str) -> tuple[str, ...]:
    """Return canonical explicit merge holds present in user-authored text.

    Args:
        text: Current user or maintainer instruction text to inspect.
    """
    normalized = " ".join(text.casefold().split())
    normalized = normalized.replace("pull-request", "pull request")
    normalized = MERGE_HOLD_MODAL_PROHIBITION.sub("do not merge", normalized)
    normalized = AUTO_MERGE_ONLY_PATTERN.sub(
        "keep github auto-merge disabled", normalized
    )
    return tuple(
        hold
        for hold, patterns in EXPLICIT_MERGE_HOLD_PATTERNS.items()
        if any(pattern in normalized for pattern in patterns)
    )


def _is_hold_discussion(segment: str, offset: int) -> bool:
    """Return whether a hold phrase is only a discussed policy term.

    Args:
        segment: Current instruction segment containing the hold phrase.
        offset: Character offset where the hold phrase begins.
    """
    prefix = segment[max(0, offset - 100) : offset]
    if (
        MERGE_HOLD_DIRECT_REQUEST_CONTEXT.search(prefix) is not None
        or MERGE_HOLD_DIRECT_DECISION_CONTEXT.search(prefix) is not None
        or MERGE_HOLD_COMPLETED_ACTION_CONTEXT.search(prefix) is not None
    ):
        return False
    return (
        MERGE_HOLD_DISCUSSION_CONTEXT.search(prefix) is not None
        or MERGE_HOLD_CONDITIONAL_CONTEXT.search(prefix) is not None
    )


def _task_clause_prefix(text: str, offset: int) -> str:
    """Return all text before an offset in the current sentence-level clause.

    Args:
        text: Normalized instruction text being classified.
        offset: Character offset whose preceding clause context is requested.
    """
    clause_start = 0
    for boundary in MERGE_AUTHORITY_TASK_CLAUSE_BOUNDARY.finditer(text, 0, offset):
        clause_start = boundary.end()
    return text[clause_start:offset]


def _hold_targets_other_task(
    segment: str,
    offset: int,
    pattern: str,
    *,
    active_pull_request: int | None = None,
    active_issue: int | None = None,
) -> bool:
    """Return whether a hold phrase explicitly targets a different task.

    Args:
        segment: Current instruction segment containing the hold phrase.
        offset: Character offset where the hold phrase begins.
        pattern: Exact hold phrase matched in the segment.
        active_pull_request: Pull request owned by the active task, when known.
        active_issue: Issue owned by the active task, when known.
    """
    prefix = segment[max(0, offset - 80) : offset]
    suffix = segment[offset + len(pattern) : offset + len(pattern) + 80]
    if active_pull_request is not None:
        # A following PR number is the permission or hold's direct object. When
        # absent, the nearest preceding number identifies a leading task scope.
        direct_reference = MERGE_HOLD_NUMBERED_PR_REFERENCE.search(
            segment[offset : offset + len(pattern) + 80]
        )
        if direct_reference is not None:
            return int(direct_reference.group(1)) != active_pull_request
        prefix_references = tuple(MERGE_HOLD_NUMBERED_PR_REFERENCE.finditer(prefix))
        if prefix_references:
            return int(prefix_references[-1].group(1)) != active_pull_request
    if active_issue is not None:
        direct_reference = MERGE_HOLD_NUMBERED_ISSUE_REFERENCE.search(
            segment[offset : offset + len(pattern) + 80]
        )
        if direct_reference is not None:
            return int(direct_reference.group(1)) != active_issue
        prefix_references = tuple(MERGE_HOLD_NUMBERED_ISSUE_REFERENCE.finditer(prefix))
        if prefix_references:
            return int(prefix_references[-1].group(1)) != active_issue
    return (
        MERGE_HOLD_OTHER_TASK_PREFIX.search(prefix) is not None
        or MERGE_HOLD_OTHER_TASK_SUFFIX.search(suffix) is not None
    )


def _hold_targets_non_pr_object(
    hold: str, segment: str, offset: int, pattern: str
) -> bool:
    """Return whether hold wording governs an application object, not PR delivery.

    Args:
        hold: Canonical merge-hold name being classified.
        segment: Current instruction segment containing the hold phrase.
        offset: Character offset where the hold phrase begins.
        pattern: Exact hold phrase matched in the segment.
    """
    hold_end = offset + len(pattern)
    for marker in MERGE_HOLD_WITHDRAWAL_MARKERS:
        marker_offset = segment.find(marker)
        while marker_offset >= 0:
            marker_end = marker_offset + len(marker)
            if marker_end <= offset and (
                MERGE_HOLD_WITHDRAWAL_BEFORE_HOLD.fullmatch(
                    segment[marker_end:offset]
                )
                is not None
            ):
                return False
            if hold_end <= marker_offset and (
                MERGE_HOLD_WITHDRAWAL_AFTER_HOLD.fullmatch(
                    segment[hold_end:marker_offset]
                )
                is not None
            ):
                return False
            marker_offset = segment.find(marker, marker_offset + 1)
    suffix = segment[offset + len(pattern) : offset + len(pattern) + 80]
    return (
        MERGE_HOLD_NON_PR_OBJECT.search(suffix) is not None
        or (
            hold == "wait for approval"
            and MERGE_HOLD_NONMERGE_APPROVAL_QUALIFIER.search(suffix) is not None
        )
    )


def _is_approval_scoped_disposition(
    hold: str, segment: str, offset: int, pattern: str
) -> bool:
    """Return whether a permanent disposition belongs to an approval condition.

    Args:
        hold: Canonical merge-hold name being classified.
        segment: Current instruction segment containing the hold phrase.
        offset: Character offset where the hold phrase begins.
        pattern: Exact hold phrase matched in the segment.
    """
    if hold not in {"do not merge", "leave open", "pr only"}:
        return False
    hold_end = offset + len(pattern)
    approval_matches = (
        tuple(MERGE_HOLD_APPROVAL_CONDITION.finditer(segment))
        + tuple(MERGE_HOLD_APPROVAL_BEFORE_MERGING.finditer(segment))
        + tuple(MERGE_HOLD_WITHOUT_APPROVAL.finditer(segment))
        + tuple(MERGE_HOLD_APPROVAL_BOUNDED_DISPOSITION.finditer(segment))
    )
    return any(match.start() < hold_end and offset < match.end() for match in approval_matches)


def merge_hold_directions(
    text: str,
    *,
    active_holds: tuple[str, ...] = (),
    active_pull_request: int | None = None,
    active_issue: int | None = None,
) -> dict[str, str | None]:
    """Classify each mentioned hold as an addition or explicit withdrawal.

    Args:
        text: One current user or maintainer instruction to classify.
        active_holds: Holds active before this instruction is evaluated.
        active_pull_request: Pull request owned by the active task, when known.
        active_issue: Issue owned by the active task, when known.
    """
    normalized = " ".join(text.casefold().split())
    normalized = normalized.replace("pull-request", "pull request")
    normalized = MERGE_HOLD_MODAL_PROHIBITION.sub("do not merge", normalized)
    normalized = AUTO_MERGE_ONLY_PATTERN.sub(
        "keep github auto-merge disabled", normalized
    )
    normalized = MERGE_HOLD_CONDITIONAL_CLAUSE_COMMA.sub(r"\1 ", normalized)
    task_clauses: list[str] = []
    for sentence in MERGE_AUTHORITY_TASK_CLAUSE_BOUNDARY.split(normalized):
        for clause in MERGE_AUTHORITY_COORDINATED_CLAUSE_BOUNDARY.split(sentence):
            clause = MERGE_HOLD_OTHER_TASK_TRAILING_CLAUSE.sub("", clause).strip()
            other_task_reference = MERGE_HOLD_OTHER_TASK_REFERENCE.search(clause)
            has_active_target_before_reference = (
                other_task_reference is not None
                and MERGE_HOLD_ACTIVE_TASK_TARGET.search(
                    clause[: other_task_reference.start()]
                )
                is not None
            )
            if clause and (
                other_task_reference is None or has_active_target_before_reference
            ):
                task_clauses.append(clause)
    normalized = "; ".join(task_clauses)
    if not normalized:
        return {}
    conditional_named_withdrawals: set[str] = set()
    for clause in MERGE_AUTHORITY_TASK_CLAUSE_BOUNDARY.split(normalized):
        for marker in MERGE_HOLD_WITHDRAWAL_MARKERS:
            marker_offset = clause.find(marker)
            while marker_offset >= 0:
                context_start = 0
                context_end = len(clause)
                for boundary in MERGE_AUTHORITY_COORDINATED_CLAUSE_BOUNDARY.finditer(
                    clause
                ):
                    if boundary.end() <= marker_offset:
                        context_start = boundary.end()
                    elif marker_offset < boundary.start():
                        context_end = boundary.start()
                        break
                withdrawal_context = clause[context_start:context_end]
                if MERGE_HOLD_WITHDRAWAL_NONCURRENT_PREFIX.search(
                    withdrawal_context
                ):
                    marker_end = marker_offset + len(marker)
                    for hold, patterns in EXPLICIT_MERGE_HOLD_PATTERNS.items():
                        for pattern in patterns:
                            hold_offset = clause.find(pattern)
                            if hold_offset < 0:
                                continue
                            if hold_offset < marker_offset or (
                                marker_end <= hold_offset
                                and MERGE_HOLD_WITHDRAWAL_BEFORE_HOLD.fullmatch(
                                    clause[marker_end:hold_offset]
                                )
                                is not None
                            ):
                                conditional_named_withdrawals.add(hold)
                                break
                marker_offset = clause.find(marker, marker_offset + 1)
    shared_withdrawals: set[str] = set()
    coarse_segments = (
        segment.strip()
        for segment in MERGE_AUTHORITY_COARSE_BOUNDARY.split(normalized)
        if segment.strip()
    )
    for coarse_segment in coarse_segments:
        for marker in MERGE_HOLD_WITHDRAWAL_MARKERS:
            marker_offset = coarse_segment.find(marker)
            while marker_offset >= 0:
                prefix = coarse_segment[max(0, marker_offset - 24) : marker_offset]
                suffix = coarse_segment[
                    marker_offset + len(marker) : marker_offset + len(marker) + 40
                ]
                if (
                    MERGE_HOLD_WITHDRAWAL_NEGATIONS.search(prefix) is None
                    and MERGE_HOLD_WITHDRAWAL_NONCURRENT_PREFIX.search(prefix) is None
                    and MERGE_HOLD_WITHDRAWAL_NONCURRENT_SUFFIX.search(suffix) is None
                ):
                    mentioned_holds = {
                        hold
                        for hold, patterns in EXPLICIT_MERGE_HOLD_PATTERNS.items()
                        if any(
                            0 <= (hold_offset := coarse_segment.find(pattern))
                            < marker_offset
                            and not _hold_targets_other_task(
                                coarse_segment,
                                hold_offset,
                                pattern,
                                active_pull_request=active_pull_request,
                                active_issue=active_issue,
                            )
                            for pattern in patterns
                        )
                    }
                    if len(mentioned_holds) > 1:
                        shared_withdrawals.update(mentioned_holds)
                marker_offset = coarse_segment.find(marker, marker_offset + 1)
    # Coordinating conjunctions begin a new instruction segment so a withdrawal
    # attached to one named hold cannot reverse a different hold later in the
    # same sentence.
    segments = tuple(
        segment.strip()
        for segment in MERGE_AUTHORITY_INSTRUCTION_BOUNDARY.split(normalized)
        if segment.strip()
    )
    directions: dict[str, str | None] = {}
    for hold, patterns in EXPLICIT_MERGE_HOLD_PATTERNS.items():
        hold_directions: set[str] = set()
        for segment in segments:
            has_directive_occurrence = False
            for pattern in patterns:
                pattern_offset = segment.find(pattern)
                while pattern_offset >= 0:
                    if not _is_hold_discussion(
                        segment, pattern_offset
                    ) and not _hold_targets_other_task(
                        segment,
                        pattern_offset,
                        pattern,
                        active_pull_request=active_pull_request,
                        active_issue=active_issue,
                    ) and not _hold_targets_non_pr_object(
                        hold, segment, pattern_offset, pattern
                    ) and not _is_approval_scoped_disposition(
                        hold, segment, pattern_offset, pattern
                    ):
                        has_directive_occurrence = True
                        break
                    pattern_offset = segment.find(pattern, pattern_offset + 1)
                if has_directive_occurrence:
                    break
            if not has_directive_occurrence:
                continue
            withdrawn = False
            for marker in MERGE_HOLD_WITHDRAWAL_MARKERS:
                marker_offset = segment.find(marker)
                while marker_offset >= 0:
                    prefix = segment[max(0, marker_offset - 24) : marker_offset]
                    suffix = segment[
                        marker_offset + len(marker) : marker_offset + len(marker) + 40
                    ]
                    marker_end = marker_offset + len(marker)
                    targets_hold = False
                    for pattern in patterns:
                        hold_offset = segment.find(pattern)
                        while hold_offset >= 0:
                            hold_end = hold_offset + len(pattern)
                            if marker_offset < hold_end and hold_offset < marker_end:
                                targets_hold = True
                            elif marker_end <= hold_offset:
                                bridge = segment[marker_end:hold_offset]
                                targets_hold = (
                                    MERGE_HOLD_WITHDRAWAL_BEFORE_HOLD.fullmatch(
                                        bridge
                                    )
                                    is not None
                                )
                            else:
                                bridge = segment[hold_end:marker_offset]
                                targets_hold = (
                                    MERGE_HOLD_WITHDRAWAL_AFTER_HOLD.fullmatch(bridge)
                                    is not None
                                )
                            if targets_hold:
                                break
                            hold_offset = segment.find(pattern, hold_offset + 1)
                        if targets_hold:
                            break
                    if (
                        targets_hold
                        and MERGE_HOLD_WITHDRAWAL_NEGATIONS.search(prefix) is None
                        and MERGE_HOLD_WITHDRAWAL_NONCURRENT_PREFIX.search(prefix)
                        is None
                        and MERGE_HOLD_WITHDRAWAL_NONCURRENT_SUFFIX.search(suffix)
                        is None
                    ):
                        withdrawn = True
                        break
                    marker_offset = segment.find(marker, marker_offset + 1)
                if withdrawn:
                    break
            hold_directions.add("remove" if withdrawn else "add")
        if hold_directions:
            directions[hold] = (
                hold_directions.pop() if len(hold_directions) == 1 else None
            )
    for condition_match in MERGE_HOLD_APPROVAL_CONDITION.finditer(normalized):
        condition = condition_match.group(0)
        if not _is_hold_discussion(
            normalized, condition_match.start()
        ) and not _hold_targets_other_task(
            normalized,
            condition_match.start(),
            condition,
            active_pull_request=active_pull_request,
            active_issue=active_issue,
        ):
            directions["wait for approval"] = "add"
    for condition_match in MERGE_HOLD_APPROVAL_CONDITION_FIRST.finditer(normalized):
        condition = condition_match.group(0)
        if not _is_hold_discussion(
            normalized, condition_match.start()
        ) and not _hold_targets_other_task(
            normalized,
            condition_match.start(),
            condition,
            active_pull_request=active_pull_request,
            active_issue=active_issue,
        ):
            directions["wait for approval"] = "add"
    for condition_match in MERGE_HOLD_APPROVAL_BOUNDED_DISPOSITION.finditer(
        normalized
    ):
        condition = condition_match.group(0)
        if not _is_hold_discussion(
            normalized, condition_match.start()
        ) and not _hold_targets_other_task(
            normalized,
            condition_match.start(),
            condition,
            active_pull_request=active_pull_request,
            active_issue=active_issue,
        ):
            directions["wait for approval"] = "add"
    for condition_match in MERGE_HOLD_APPROVAL_BEFORE_MERGING.finditer(normalized):
        condition = condition_match.group(0)
        if not _is_hold_discussion(
            normalized, condition_match.start()
        ) and not _hold_targets_other_task(
            normalized,
            condition_match.start(),
            condition,
            active_pull_request=active_pull_request,
            active_issue=active_issue,
        ):
            directions["wait for approval"] = "add"
    for condition_match in MERGE_HOLD_WITHOUT_APPROVAL.finditer(normalized):
        condition = condition_match.group(0)
        if not _is_hold_discussion(
            normalized, condition_match.start()
        ) and not _hold_targets_other_task(
            normalized,
            condition_match.start(),
            condition,
            active_pull_request=active_pull_request,
            active_issue=active_issue,
        ):
            directions["wait for approval"] = "add"
    for permission_match in MERGE_HOLD_STANDALONE_PERMISSION.finditer(normalized):
        permission_offset = permission_match.start()
        permission = permission_match.group(0)
        prefix = _task_clause_prefix(normalized, permission_offset)
        suffix = normalized[
            permission_match.end() : permission_match.end() + 40
        ]
        if (
            MERGE_HOLD_WITHDRAWAL_NEGATIONS.search(prefix) is None
            and
            MERGE_HOLD_WITHDRAWAL_NONCURRENT_PREFIX.search(prefix) is None
            and MERGE_HOLD_WITHDRAWAL_NONCURRENT_SUFFIX.search(suffix) is None
            and MERGE_HOLD_REPORTED_PERMISSION_CONTEXT.search(prefix) is None
            and MERGE_HOLD_INTERROGATIVE_PERMISSION_CONTEXT.search(prefix) is None
            and MERGE_HOLD_NEGATED_PERMISSION_REPORT_CONTEXT.search(prefix) is None
            and MERGE_HOLD_NONAUTHORITATIVE_SOURCE_CONTEXT.search(prefix) is None
            and MERGE_HOLD_NONAUTHORITATIVE_SOURCE_CONTEXT.search(suffix) is None
            and (
                permission_match.group("imperative") is None
                or not prefix.strip()
            )
            and not _hold_targets_non_pr_object(
                "", normalized, permission_offset, permission
            )
            and not _hold_targets_other_task(
                normalized,
                permission_offset,
                permission,
                active_pull_request=active_pull_request,
                active_issue=active_issue,
            )
        ):
            for hold in active_holds:
                directions[hold] = "remove"
            break
    for hold in shared_withdrawals:
        directions[hold] = "remove"
    for hold in conditional_named_withdrawals:
        directions[hold] = "add"
    return directions


def has_affirmative_default_merge_authority(text: str) -> bool:
    """Return whether generated text affirmatively continues through merge.

    Args:
        text: Generated delegation, handoff, or heartbeat prompt to classify.
    """
    normalized = " ".join(text.casefold().split())
    for marker in DEFAULT_MERGE_AUTHORITY_PROMPT_MARKERS:
        offset = normalized.find(marker)
        while offset >= 0:
            prefix = normalized[max(0, offset - 80) : offset]
            suffix = normalized[offset + len(marker) : offset + len(marker) + 80]
            context = normalized[
                max(0, offset - 100) : offset + len(marker) + 100
            ]
            action_prefix = DEFAULT_MERGE_AUTHORITY_ACTION_BOUNDARY.split(prefix)[-1]
            if (
                DEFAULT_MERGE_AUTHORITY_NEGATIONS.search(prefix) is None
                and DEFAULT_MERGE_AUTHORITY_TRAILING_NEGATIONS.search(suffix) is None
                and MERGE_HOLD_DISCUSSION_CONTEXT.search(action_prefix) is None
                and DEFAULT_MERGE_AUTHORITY_SECOND_INSTRUCTION_CONDITIONS.search(
                    context
                )
                is None
                and DEFAULT_MERGE_AUTHORITY_CONDITIONAL_APPROVAL.search(context)
                is None
                and DEFAULT_MERGE_AUTHORITY_CONDITIONAL_REQUEST.search(context)
                is None
                and DEFAULT_MERGE_AUTHORITY_DECISION_ONLY.search(context) is None
                and DEFAULT_MERGE_AUTHORITY_PERMISSION_QUESTION.search(context)
                is None
                and MERGE_HOLD_REPORTED_PERMISSION_CONTEXT.search(context) is None
                and MERGE_HOLD_NONAUTHORITATIVE_SOURCE_CONTEXT.search(context)
                is None
            ):
                return True
            offset = normalized.find(marker, offset + 1)
    return False


def source_has_default_merge_authority(instructions: tuple[str, ...]) -> bool:
    """Derive whether current source instructions describe eligible implementation.

    Args:
        instructions: Ordered user or maintainer instructions from one fixture.
    """
    eligible = False
    for instruction in instructions:
        normalized = " ".join(instruction.casefold().split())
        exclusion_matches = tuple(
            DEFAULT_MERGE_AUTHORITY_SOURCE_EXCLUSIONS.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_INTERROGATIVE_REVIEW.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_REPORTED_DISCUSSION.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_COORDINATED_NO_WORK.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_STOP_WORK.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_POST_STOP_SUMMARY.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_POST_STOP_STATUS.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_NEGATED_MUTATION.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_WORKFLOW_EXCLUSIONS.finditer(normalized)
        ) + tuple(
            DEFAULT_MERGE_AUTHORITY_WORKFLOW_RECLASSIFICATION.finditer(normalized)
        )
        source_markers = tuple(
            DEFAULT_MERGE_AUTHORITY_SOURCE_MARKERS.finditer(normalized)
        )
        affirmative_source_markers = tuple(
            marker
            for marker in source_markers
            if not any(
                exclusion.start() <= marker.start() < exclusion.end()
                for exclusion in exclusion_matches
            )
        )
        direct_review_matches = tuple(
            match
            for match in DEFAULT_MERGE_AUTHORITY_DIRECT_REVIEW.finditer(normalized)
            if (
                DEFAULT_MERGE_AUTHORITY_SUPERSEDING_REVIEW_PREFIX.search(
                    normalized[: match.start()]
                )
                is not None
                or DEFAULT_MERGE_AUTHORITY_SUPERSEDING_REVIEW_MARKER.search(
                    normalized[match.end() : match.end() + 24]
                )
                is not None
                or not any(
                    marker.start() < match.start()
                    for marker in affirmative_source_markers
                )
            )
        )
        exclusion_matches += direct_review_matches
        events = [
            (match.start(), 0, False)
            for match in exclusion_matches
        ]
        events.extend(
            (match.start(), 1, True)
            for match in source_markers
            if not any(
                exclusion.start() <= match.start() < exclusion.end()
                for exclusion in exclusion_matches
            )
        )
        for _, _, event_eligibility in sorted(events):
            eligible = event_eligibility
    return eligible


def check_merge_authority_transfer_fixtures(root: Path) -> list[Finding]:
    """Verify delegation and heartbeat fixtures preserve merge authority.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    path = root / MERGE_AUTHORITY_TRANSFER_FIXTURE_PATH
    text, error = read_text(path)
    if error is not None or text is None:
        return [
            Finding(path, "merge authority transfer fixtures are missing or unreadable")
        ]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return [
            Finding(path, f"merge authority transfer fixtures are invalid JSON: {exc}")
        ]
    cases = payload.get("cases") if isinstance(payload, dict) else None
    if not isinstance(cases, list) or not cases:
        return [
            Finding(
                path, "merge authority transfer fixtures require a non-empty cases list"
            )
        ]

    findings: list[Finding] = []
    seen_names: set[str] = set()
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            findings.append(
                Finding(path, f"merge authority fixture {index} must be an object")
            )
            continue
        name = case.get("name")
        instructions = case.get("instructions")
        generated = case.get("generated")
        expected_holds = case.get("expected_holds")
        default_merge_authority = case.get("default_merge_authority")
        active_pull_request = case.get("active_pull_request")
        active_issue = case.get("active_issue")
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(instructions, list)
            or not instructions
            or not isinstance(generated, str)
            or not isinstance(expected_holds, list)
            or any(not isinstance(item, str) for item in expected_holds)
            or not isinstance(default_merge_authority, bool)
            or (
                active_pull_request is not None
                and (
                    not isinstance(active_pull_request, int)
                    or isinstance(active_pull_request, bool)
                    or active_pull_request <= 0
                )
            )
            or (
                active_issue is not None
                and (
                    not isinstance(active_issue, int)
                    or isinstance(active_issue, bool)
                    or active_issue <= 0
                )
            )
        ):
            findings.append(
                Finding(path, f"merge authority fixture {index} has invalid fields")
            )
            continue
        if name in seen_names:
            findings.append(
                Finding(path, f"merge authority fixture name is duplicated: {name}")
            )
            continue
        seen_names.add(name)
        expected = tuple(dict.fromkeys(item.casefold() for item in expected_holds))
        source_holds: list[str] = []
        source_instruction_texts: list[str] = []
        instruction_error = False
        for instruction_index, instruction in enumerate(instructions, start=1):
            if not isinstance(instruction, dict):
                findings.append(
                    Finding(
                        path,
                        f"merge authority fixture {name} instruction "
                        f"{instruction_index} must be an object",
                    )
                )
                instruction_error = True
                continue
            instruction_text = instruction.get("text")
            add_holds = instruction.get("add_holds", [])
            remove_holds = instruction.get("remove_holds", [])
            if (
                not isinstance(instruction_text, str)
                or not isinstance(add_holds, list)
                or any(not isinstance(item, str) for item in add_holds)
                or not isinstance(remove_holds, list)
                or any(not isinstance(item, str) for item in remove_holds)
            ):
                findings.append(
                    Finding(
                        path,
                        f"merge authority fixture {name} instruction "
                        f"{instruction_index} has invalid fields",
                    )
                )
                instruction_error = True
                continue
            source_instruction_texts.append(instruction_text)
            additions = tuple(dict.fromkeys(item.casefold() for item in add_holds))
            removals = tuple(dict.fromkeys(item.casefold() for item in remove_holds))
            directions = merge_hold_directions(
                instruction_text,
                active_holds=tuple(source_holds),
                active_pull_request=active_pull_request,
                active_issue=active_issue,
            )
            derived_additions = {
                hold for hold, direction in directions.items() if direction == "add"
            }
            derived_removals = {
                hold for hold, direction in directions.items() if direction == "remove"
            }
            if (
                any(
                    hold not in EXPLICIT_MERGE_HOLD_PATTERNS
                    for hold in (*additions, *removals)
                )
                or set(additions) & set(removals)
                or any(direction is None for direction in directions.values())
                or set(additions) != derived_additions
                or set(removals) != derived_removals
            ):
                findings.append(
                    Finding(
                        path,
                        f"merge authority fixture {name} instruction "
                        f"{instruction_index} hold operations do not match its text",
                    )
                )
                instruction_error = True
                continue
            source_holds = [hold for hold in source_holds if hold not in removals]
            source_holds.extend(
                hold for hold in additions if hold not in source_holds
            )
        if instruction_error:
            continue
        derived_default_merge_authority = source_has_default_merge_authority(
            tuple(source_instruction_texts)
        )
        if default_merge_authority != derived_default_merge_authority:
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} declared default authority "
                    "does not match its source instructions",
                )
            )
            continue
        source_holds_tuple = tuple(source_holds)
        generated_directions = merge_hold_directions(
            generated,
            active_holds=source_holds_tuple,
            active_pull_request=active_pull_request,
            active_issue=active_issue,
        )
        ambiguous_generated = tuple(
            hold
            for hold, direction in generated_directions.items()
            if direction is None
        )
        if ambiguous_generated:
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} has ambiguous generated hold "
                    f"direction: {', '.join(ambiguous_generated)}",
                )
            )
        generated_holds = tuple(
            hold
            for hold, direction in generated_directions.items()
            if direction == "add"
        )
        generated_removals = tuple(
            hold
            for hold, direction in generated_directions.items()
            if direction == "remove"
        )
        if source_holds_tuple != expected:
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} expected holds do not match the source instructions",
                )
            )
        invented = tuple(
            hold for hold in generated_holds if hold not in source_holds_tuple
        )
        if invented:
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} invents a hold: {', '.join(invented)}",
                )
            )
        nonexistent_removals = tuple(
            hold for hold in generated_removals if hold not in source_holds_tuple
        )
        if nonexistent_removals:
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} withdraws a nonexistent "
                    f"source hold: {', '.join(nonexistent_removals)}",
                )
            )
        omitted = tuple(
            hold for hold in source_holds_tuple if hold not in generated_holds
        )
        if omitted:
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} drops an explicit hold: {', '.join(omitted)}",
                )
            )
        if expected and has_affirmative_default_merge_authority(generated):
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} asserts merge authority while "
                    "an explicit hold is active",
                )
            )
        if (
            default_merge_authority
            and not expected
            and not invented
            and not omitted
            and not nonexistent_removals
            and not has_affirmative_default_merge_authority(generated)
        ):
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} omits affirmative default authority",
                )
            )
        if (
            not default_merge_authority
            and has_affirmative_default_merge_authority(generated)
        ):
            findings.append(
                Finding(
                    path,
                    f"merge authority fixture {name} asserts default authority "
                    "for an ineligible task",
                )
            )
    return findings


def relative_path(path: Path) -> Path:
    """Return relative path.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    try:
        return path.resolve().relative_to(ROOT)
    except ValueError:
        return path


def should_skip(path: Path) -> bool:
    """Return whether skip.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    rel = relative_path(path)
    if any(part in SKIP_PARTS or part.startswith(".venv") for part in rel.parts):
        return True
    return any(rel == prefix or rel.is_relative_to(prefix) for prefix in SKIP_PREFIXES)


def is_checkable(path: Path) -> bool:
    """Return whether checkable.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    rel = relative_path(path)
    return (
        len(rel.parts) >= 4
        and rel.parts[0] == "image"
        and rel.parent.name == "sudoers.d"
    )


def collect_files(paths: list[str]) -> list[Path]:
    """Return collect files.

    Args:
        paths: Paths consumed by collect files.
    """
    if paths:
        candidates: list[Path] = []
        for raw in paths:
            path = Path(raw)
            if not path.is_absolute():
                path = ROOT / path
            if path.is_dir():
                candidates.extend(path.rglob("*"))
            elif path.exists():
                candidates.append(path)
    else:
        candidates = list(ROOT.rglob("*"))

    files = []
    for path in candidates:
        if path.is_file() and not should_skip(path) and is_checkable(path):
            files.append(path.resolve())
    return sorted(set(files), key=lambda item: str(relative_path(item)))


def read_text(path: Path) -> tuple[str | None, Finding | None]:
    """Return text.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, Finding(path, f"cannot read file: {exc}")
    if b"\x00" in data:
        return None, Finding(path, "contains NUL bytes")
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return None, Finding(path, f"must be UTF-8 text: {exc}")


def line_for_offset(text: str, offset: int) -> int:
    """Return line for offset.

    Args:
        text: Text content consumed by the operation.
        offset: Offset consumed by line for offset.
    """
    return text.count("\n", 0, offset) + 1


def check_common_text(path: Path, text: str) -> list[Finding]:
    """Check common text.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check common text result.
    """
    findings: list[Finding] = []
    for index, line in enumerate(text.splitlines(), start=1):
        if line.startswith("<<<<<<< ") or line == "=======" or line.startswith(">>>>>>> "):
            findings.append(Finding(path, "contains unresolved merge conflict marker", index))
    return findings


def check_python(path: Path, text: str) -> list[Finding]:
    """Check python.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check python result.
    """
    try:
        ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return [Finding(path, exc.msg, exc.lineno)]
    return []


def check_json(path: Path, text: str) -> list[Finding]:
    """Check json.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check json result.
    """
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return [Finding(path, exc.msg, exc.lineno)]
    return []


def check_toml(path: Path, text: str) -> list[Finding]:
    """Check toml.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check toml result.
    """
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [Finding(path, str(exc))]
    return []


def check_jinja(path: Path, text: str) -> list[Finding]:
    """Check jinja.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check jinja result.
    """
    try:
        from jinja2 import Environment
        from jinja2.exceptions import TemplateSyntaxError
    except ImportError:
        return [Finding(path, "Jinja2 is required for template checks; run pip install -e .[dev]")]

    env = Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"])
    try:
        env.parse(text)
    except TemplateSyntaxError as exc:
        return [Finding(path, exc.message, exc.lineno)]
    return []


def strip_css_noise(text: str) -> str:
    """Return strip css noise.

    Args:
        text: Text content consumed by the operation.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    return text


def check_css(path: Path, text: str) -> list[Finding]:
    """Check css.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check css result.
    """
    findings: list[Finding] = []
    stack: list[tuple[str, int]] = []
    pairs = {"{": "}", "(": ")", "[": "]"}
    closing = {value: key for key, value in pairs.items()}
    for index, char in enumerate(strip_css_noise(text)):
        if char in pairs:
            stack.append((char, line_for_offset(text, index)))
        elif char in closing:
            if not stack or stack[-1][0] != closing[char]:
                findings.append(Finding(path, f"unexpected '{char}'", line_for_offset(text, index)))
                continue
            stack.pop()
    for char, line in stack:
        findings.append(Finding(path, f"unclosed '{char}'", line))
    return findings


def check_javascript(path: Path) -> list[Finding]:
    """Check javascript.

    Args:
        path: Filesystem or URL path to read, validate, or update.

    Returns:
        The check javascript result.
    """
    node = shutil.which("node")
    if node is None:
        return [Finding(path, "Node.js is required for JavaScript syntax checks")]
    result = subprocess.run(
        [node, "--check", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return []
    detail = (result.stderr or result.stdout).strip().splitlines()
    message = detail[-1] if detail else "node --check failed"
    return [Finding(path, message)]


def markdown_link_target_exists(path: Path, target: str) -> bool:
    """Return markdown link target exists.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        target: Resource targeted by the operation.
    """
    target = target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    target = unquote(target)
    if not target or target.startswith(("#", "/", "http://", "https://", "mailto:")):
        return True
    file_part = target.split("#", 1)[0]
    if not file_part:
        return True
    return (path.parent / file_part).exists()


def check_markdown(path: Path, text: str) -> list[Finding]:
    """Check markdown.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check markdown result.
    """
    findings: list[Finding] = []
    in_fence = False
    fence_line: int | None = None
    for index, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            fence_line = index if in_fence else None
            continue
        if in_fence:
            continue
        for match in MARKDOWN_LINK_RE.finditer(line):
            target = match.group(1)
            if not markdown_link_target_exists(path, target):
                findings.append(Finding(path, f"local Markdown link target not found: {target}", index))
    if in_fence:
        findings.append(Finding(path, "unclosed fenced code block", fence_line))
    return findings


def check_file(path: Path) -> list[Finding]:
    """Check file.

    Args:
        path: Filesystem or URL path to read, validate, or update.

    Returns:
        The check file result.
    """
    text, error = read_text(path)
    if error is not None:
        return [error]
    assert text is not None

    suffix = path.suffix.lower()
    findings = check_common_text(path, text)
    if suffix == ".py":
        findings.extend(check_python(path, text))
    elif suffix == ".json":
        findings.extend(check_json(path, text))
    elif suffix == ".toml":
        findings.extend(check_toml(path, text))
    elif suffix in {".html", ".htm"}:
        findings.extend(check_jinja(path, text))
    elif suffix == ".css":
        findings.extend(check_css(path, text))
    elif suffix == ".js":
        findings.extend(check_javascript(path))
    elif suffix == ".md":
        findings.extend(check_markdown(path, text))
    elif suffix == ".svg":
        findings.extend(check_xmlish_svg(path, text))
    return findings


def extract_required_policy_section(
    text: str,
    section_anchor: str,
    *,
    section_end_anchor: str | None = None,
) -> tuple[int, str | None]:
    """Return the count and operative content for one policy section.

    Args:
        text: Complete Markdown policy source.
        section_anchor: Exact heading or leading list-item text that starts the section.
        section_end_anchor: Optional next sibling marker that bounds a list section.
    """
    operative_text = strip_markdown_nonoperative_content(text)
    source_lines = text.splitlines()
    raw_html_block_lines = markdown_raw_html_block_lines(text)
    section_anchor_lines = tuple(
        index
        for index, line in enumerate(operative_text.splitlines())
        if (
            line == section_anchor
            if section_anchor.startswith("#")
            else line.startswith(section_anchor)
        )
        and index < len(source_lines)
        and (
            source_lines[index] == section_anchor
            if section_anchor.startswith("#")
            else source_lines[index].startswith(section_anchor)
        )
        and index not in raw_html_block_lines
    )
    if len(section_anchor_lines) != 1:
        return len(section_anchor_lines), None
    if section_end_anchor is not None:
        section_start_line = section_anchor_lines[0]
        section_end_lines = tuple(
            index
            for index, line in enumerate(operative_text.splitlines())
            if index > section_start_line
            and line.startswith(section_end_anchor)
            and index < len(source_lines)
            and source_lines[index].startswith(section_end_anchor)
            and index not in raw_html_block_lines
        )
        if len(section_end_lines) != 1:
            return 1, ""
        bounded_source = "\n".join(
            source_lines[section_start_line : section_end_lines[0]]
        )
        return 1, strip_markdown_nonoperative_content(bounded_source)
    if section_anchor.startswith("#"):
        section = extract_markdown_policy_section(
            operative_text,
            section_anchor,
            start_line=section_anchor_lines[0],
        )
    else:
        structural_section = extract_markdown_policy_section(
            text,
            section_anchor,
            start_line=section_anchor_lines[0],
        )
        section = (
            strip_markdown_nonoperative_content(structural_section)
            if structural_section is not None
            else None
        )
    return 1, section


def check_agent_policy_gate(root: Path) -> list[Finding]:
    """Require agent policy entry points and their non-negotiable markers.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    findings: list[Finding] = []
    for relative_path, markers in REQUIRED_POLICY_MARKERS.items():
        path = root / relative_path
        text, error = read_text(path)
        if error is not None:
            findings.append(Finding(path, "required agent policy entry point is missing or unreadable"))
            continue
        assert text is not None
        missing_required_markers = tuple(marker for marker in markers if marker not in text)
        for marker in missing_required_markers:
            findings.append(
                Finding(path, f"required agent policy marker is missing: {marker}")
            )
        monitoring_markers = SCHEDULED_PR_MONITORING_SECTION_MARKERS.get(
            relative_path, ()
        )
        monitoring_anchor = SCHEDULED_PR_MONITORING_SECTION_ANCHORS.get(
            relative_path
        )
        monitoring_end_anchor = SCHEDULED_PR_MONITORING_SECTION_END_ANCHORS.get(
            relative_path
        )
        monitoring_section: str | None = None
        monitoring_boundary_missing = False
        if monitoring_anchor is not None:
            monitoring_boundary_missing = any(
                marker in monitoring_anchor
                or (
                    monitoring_end_anchor is not None
                    and marker in monitoring_end_anchor
                )
                for marker in missing_required_markers
            )
            monitoring_anchor_count, monitoring_section = (
                extract_required_policy_section(
                    text,
                    monitoring_anchor,
                    section_end_anchor=monitoring_end_anchor,
                )
            )
            if monitoring_anchor_count == 0 and not monitoring_boundary_missing:
                findings.append(
                    Finding(
                        path,
                        "pull-request monitoring section is missing: "
                        + monitoring_anchor,
                    )
                )
            elif monitoring_anchor_count > 1 and not monitoring_boundary_missing:
                findings.append(
                    Finding(
                        path,
                        "pull-request monitoring section must appear exactly once: "
                        + monitoring_anchor,
                    )
                )
        if (
            monitoring_markers
            and monitoring_section is not None
            and not monitoring_boundary_missing
        ):
            missing_monitoring_markers = tuple(
                marker
                for marker in monitoring_markers
                if marker not in monitoring_section
            )
            for marker in missing_monitoring_markers:
                if marker not in missing_required_markers:
                    findings.append(
                        Finding(
                            path,
                            "pull-request monitoring section marker is missing: "
                            + marker,
                        )
                    )
        authority_markers = DEFAULT_MERGE_AUTHORITY_SECTION_MARKERS.get(
            relative_path, ()
        )
        authority_anchor = DEFAULT_MERGE_AUTHORITY_SECTION_ANCHORS.get(relative_path)
        if authority_anchor is not None:
            authority_boundary_missing = any(
                marker in authority_anchor for marker in missing_required_markers
            )
            authority_anchor_count, authority_section = extract_required_policy_section(
                text,
                authority_anchor,
            )
            if authority_anchor_count == 0 and not authority_boundary_missing:
                findings.append(
                    Finding(
                        path,
                        "default merge authority section is missing: "
                        + authority_anchor,
                    )
                )
            elif authority_anchor_count > 1 and not authority_boundary_missing:
                findings.append(
                    Finding(
                        path,
                        "default merge authority section must appear exactly once: "
                        + authority_anchor,
                    )
                )
            elif authority_section is not None and not authority_boundary_missing:
                for marker in authority_markers:
                    if marker not in authority_section:
                        findings.append(
                            Finding(
                                path,
                                "default merge authority section marker is missing: "
                                + marker,
                            )
                        )
        ordered_markers = ORDERED_TERMINAL_CLEANUP_MARKERS.get(relative_path)
        section_markers = TERMINAL_CLEANUP_SECTION_MARKERS.get(relative_path, ())
        section_anchor = TERMINAL_CLEANUP_SECTION_ANCHORS.get(relative_path)
        operative_text = strip_markdown_nonoperative_content(text)
        source_lines = text.splitlines()
        raw_html_block_lines = markdown_raw_html_block_lines(text)
        section_anchor_lines = (
            tuple(
                index
                for index, line in enumerate(operative_text.splitlines())
                if (
                    line == section_anchor
                        if section_anchor.startswith("#")
                        else line.startswith(section_anchor)
                    )
                    and index < len(source_lines)
                    and (
                        source_lines[index] == section_anchor
                        if section_anchor.startswith("#")
                        else source_lines[index].startswith(section_anchor)
                    )
                    and index not in raw_html_block_lines
                )
            if section_anchor is not None
            else ()
        )
        section_anchor_count = len(section_anchor_lines)
        cleanup_section: str | None = None
        if section_anchor is not None and section_anchor_count == 1:
            if section_anchor.startswith("#"):
                cleanup_section = extract_markdown_policy_section(
                    operative_text,
                    section_anchor,
                    start_line=section_anchor_lines[0],
                )
            else:
                structural_section = extract_markdown_policy_section(
                    text,
                    section_anchor,
                    start_line=section_anchor_lines[0],
                )
                cleanup_section = (
                    strip_markdown_nonoperative_content(structural_section)
                    if structural_section is not None
                    else None
                )
        if section_anchor is not None and section_anchor_count == 0:
            findings.append(
                Finding(
                    path,
                    f"completed-task cleanup section is missing: {section_anchor}",
                )
            )
        elif section_anchor is not None and section_anchor_count > 1:
            findings.append(
                Finding(
                    path,
                    "completed-task cleanup section must appear exactly once: "
                    + section_anchor,
                )
            )
        if section_markers and cleanup_section is not None:
            missing_section_markers = tuple(
                marker for marker in section_markers if marker not in cleanup_section
            )
            for marker in missing_section_markers:
                if marker not in missing_required_markers:
                    findings.append(
                        Finding(
                            path,
                            f"completed-task cleanup section marker is missing: {marker}",
                        )
                    )
        if ordered_markers is not None and cleanup_section is not None:
            order_lines = extract_terminal_cleanup_order(cleanup_section)
            if order_lines != TERMINAL_CLEANUP_ORDER_LINES:
                findings.append(
                    Finding(
                        path,
                        "completed-task cleanup markers must remain ordered: "
                        + " -> ".join(ordered_markers),
                    )
                )
    return findings


def check_spark_worker_agent(root: Path) -> list[Finding]:
    """Require Atlaso's project-scoped Spark worker contract.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    path = root / SPARK_WORKER_AGENT_PATH
    text, error = read_text(path)
    if error is not None:
        return [Finding(path, "required Spark worker agent is missing or unreadable")]
    assert text is not None

    try:
        config = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [Finding(path, f"invalid Spark worker TOML: {exc}")]

    findings: list[Finding] = []
    for key, expected in SPARK_WORKER_REQUIRED_VALUES.items():
        if config.get(key) != expected:
            findings.append(
                Finding(path, f"Spark worker {key} must equal {expected!r}")
            )

    description = config.get("description")
    if not isinstance(description, str) or not description.strip():
        findings.append(Finding(path, "Spark worker description must be non-empty"))

    instructions = config.get("developer_instructions")
    if not isinstance(instructions, str) or not instructions.strip():
        findings.append(
            Finding(path, "Spark worker developer_instructions must be non-empty")
        )
    else:
        for marker in SPARK_WORKER_REQUIRED_INSTRUCTION_MARKERS:
            if marker not in instructions:
                findings.append(
                    Finding(
                        path,
                        "required Spark worker instruction marker is missing: "
                        + marker,
                    )
                )

    for key in sorted(config.keys() - SPARK_WORKER_ALLOWED_KEYS):
        message = SPARK_WORKER_OVERRIDE_MESSAGES.get(
            key,
            f"Spark worker contains unsupported top-level key: {key}",
        )
        findings.append(Finding(path, message))
    return findings


def strip_markdown_fenced_code(text: str) -> str:
    """Replace fenced Markdown content with blank lines.

    Args:
        text: Markdown source whose operative prose must be inspected.
    """
    visible_lines: list[str] = []
    fence_character: str | None = None
    fence_length = 0
    list_content_indents: list[int] = []
    paragraph_open = False
    for line in text.splitlines(keepends=True):
        list_content_indent = update_markdown_list_content_indent(
            line,
            list_content_indents,
            paragraph_open=paragraph_open,
        )
        block_line = (
            line[list_content_indent:]
            if list_content_indent is not None
            and line.startswith(" " * list_content_indent)
            else line
        )
        relative_indent = len(block_line) - len(block_line.lstrip(" "))
        candidate = block_line[relative_indent:]
        fence_match = (
            re.match(r"(`{3,}|~{3,})", candidate)
            if relative_indent <= 3
            else None
        )
        if (
            fence_match is not None
            and fence_match.group(1).startswith("`")
            and "`" in candidate[fence_match.end() :]
        ):
            fence_match = None
        if fence_character is None and fence_match is not None:
            fence = fence_match.group(1)
            fence_character = fence[0]
            fence_length = len(fence)
            paragraph_open = False
            visible_lines.append("\n" if line.endswith("\n") else "")
            continue
        if fence_character is not None:
            closing_match = (
                re.fullmatch(
                    rf"{re.escape(fence_character)}{{{fence_length},}}"
                    r"[ \t]*(?:\r?\n)?",
                    candidate,
                )
                if relative_indent <= 3
                else None
            )
            if closing_match is not None:
                fence_character = None
                fence_length = 0
            visible_lines.append("\n" if line.endswith("\n") else "")
            continue
        visible_lines.append(line)
        paragraph_open = bool(block_line.strip()) and not (
            starts_markdown_block_construct(block_line)
            or re.match(r"(?: {4}|\t)", block_line) is not None
        )
    return "".join(visible_lines)


def update_markdown_list_content_indent(
    line: str,
    content_indents: list[int],
    *,
    paragraph_open: bool,
) -> int | None:
    """Update nested list indentation and return the active content indent.

    Args:
        line: Current Markdown source line.
        content_indents: Mutable stack of active absolute content indents.
        paragraph_open: Whether the preceding line ended in paragraph content.
    """
    leading_spaces = len(line) - len(line.lstrip(" "))
    list_match = re.match(
        r"(?P<indent> *)(?P<marker>[*+-]|\d{1,9}[.)])(?P<spacing>[ \t]+)",
        line,
    )
    marker_can_interrupt = (
        list_match is not None
        and (
            not paragraph_open
            or list_match.group("marker") in {"*", "+", "-", "1.", "1)"}
        )
    )
    list_can_start = (
        list_match is not None
        and marker_can_interrupt
        and (
            leading_spaces <= 3
            if not content_indents
            else leading_spaces <= content_indents[-1] + 3
        )
    )
    if list_can_start:
        while content_indents and content_indents[-1] > leading_spaces:
            content_indents.pop()
        container_indent = content_indents[-1] if content_indents else None
        spacing_width = len(list_match.group("spacing"))
        padding_width = spacing_width if spacing_width <= 4 else 1
        content_indent = (
            leading_spaces + len(list_match.group("marker")) + padding_width
        )
        if not content_indents or content_indents[-1] != content_indent:
            content_indents.append(content_indent)
        return container_indent
    elif line.strip():
        while content_indents and content_indents[-1] > leading_spaces:
            content_indents.pop()
    return content_indents[-1] if content_indents else None


MARKDOWN_CODE_SPAN_PROTECTION = str.maketrans(
    {
        "!": "\ue000",
        "<": "\ue001",
        ">": "\ue002",
        "[": "\ue003",
        "]": "\ue004",
        "(": "\ue005",
        ")": "\ue006",
    }
)
MARKDOWN_CODE_SPAN_RESTORATION = str.maketrans(
    {replacement: source for source, replacement in MARKDOWN_CODE_SPAN_PROTECTION.items()}
)


def protect_markdown_code_spans(text: str) -> str:
    """Protect rendered code-span content from later Markdown tokenizers.

    Args:
        text: Fence-normalized Markdown source.
    """
    protected_parts: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != "`":
            protected_parts.append(text[index])
            index += 1
            continue
        run_end = index + 1
        while run_end < len(text) and text[run_end] == "`":
            run_end += 1
        delimiter = text[index:run_end]
        cursor = run_end
        closing_start: int | None = None
        while cursor < len(text):
            candidate = text.find(delimiter, cursor)
            if candidate < 0:
                break
            before_is_backtick = candidate > 0 and text[candidate - 1] == "`"
            closing_end = candidate + len(delimiter)
            after_is_backtick = (
                closing_end < len(text) and text[closing_end] == "`"
            )
            if not before_is_backtick and not after_is_backtick:
                closing_start = candidate
                break
            cursor = closing_end
        if closing_start is None:
            protected_parts.append(delimiter)
            index = run_end
            continue
        protected_parts.append(delimiter)
        protected_parts.append(
            text[run_end:closing_start].translate(MARKDOWN_CODE_SPAN_PROTECTION)
        )
        protected_parts.append(delimiter)
        index = closing_start + len(delimiter)
    return "".join(protected_parts)


def strip_markdown_html_comments(text: str) -> str:
    """Blank HTML comments and raw-text blocks with token-aware precedence.

    Args:
        text: Fence-normalized Markdown source.
    """
    visible_parts: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("<!--", index):
            comment_end = text.find("-->", index + 4)
            end = len(text) if comment_end < 0 else comment_end + 3
            visible_parts.append(re.sub(r"[^\r\n]", "", text[index:end]))
            index = end
            continue
        if text[index] == "<" and re.match(
            r"/?[A-Za-z]",
            text[index + 1 : index + 3],
        ) is not None:
            tag_match = re.match(
                r"<(?P<closing>/)?(?P<tag>[A-Za-z][A-Za-z0-9-]*)",
                text[index:],
            )
            cursor = index + 1
            quote: str | None = None
            while cursor < len(text):
                character = text[cursor]
                if quote is not None:
                    if character == quote:
                        quote = None
                elif character in {'"', "'"}:
                    quote = character
                elif character == ">":
                    cursor += 1
                    tag_text = text[index:cursor]
                    tag_name = (
                        tag_match.group("tag").casefold()
                        if tag_match is not None
                        else ""
                    )
                    if (
                        tag_match is not None
                        and tag_match.group("closing") is None
                        and tag_name in {"pre", "script", "style", "textarea"}
                        and re.search(r"/[ \t\r\n]*>$", tag_text) is None
                    ):
                        closing_match = re.search(
                            rf"</{re.escape(tag_name)}[ \t\r\n]*>",
                            text[cursor:],
                            flags=re.IGNORECASE,
                        )
                        raw_end = (
                            len(text)
                            if closing_match is None
                            else cursor + closing_match.end()
                        )
                        visible_parts.append(
                            re.sub(r"[^\r\n]", "", text[index:raw_end])
                        )
                        index = raw_end
                    else:
                        visible_parts.append(tag_text)
                        index = cursor
                    break
                cursor += 1
            else:
                visible_parts.append(text[index])
                index += 1
            continue
        visible_parts.append(text[index])
        index += 1
    return "".join(visible_parts)


def normalize_reference_label(label: str) -> str:
    """Return a case-folded, whitespace-normalized reference label.

    Args:
        label: Reference label content without the surrounding brackets.
    """
    unescaped = re.sub(r"\\([!\"#$%&'()*+,./:;<=>?@\[\\\]^_`{|}~-])", r"\1", label)
    return re.sub(r"\s+", " ", unescaped).strip().casefold()


def inline_link_target_is_valid(target: str) -> bool:
    """Return whether parenthesized inline-link metadata is valid.

    Args:
        target: Text inside the link's outer parentheses.
    """
    index = 0
    while index < len(target) and target[index].isspace():
        index += 1
    if index == len(target):
        return True
    if target[index] == "<":
        index += 1
        while index < len(target):
            if target[index] == "\\" and index + 1 < len(target):
                index += 2
                continue
            if target[index] == ">":
                index += 1
                break
            if target[index] in "<>\r\n":
                return False
            index += 1
        else:
            return False
    else:
        destination_start = index
        depth = 0
        while index < len(target):
            character = target[index]
            if character == "\\" and index + 1 < len(target):
                index += 2
                continue
            if character.isspace() or ord(character) < 0x20:
                break
            if character in "<>" or (character == ")" and depth == 0):
                return False
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            index += 1
        if index == destination_start or depth != 0:
            return False
    tail = target[index:]
    if not tail.strip():
        return True
    if not tail[0].isspace():
        return False
    title = tail.strip()
    if title[0] in {'"', "'"}:
        closing = title[0]
    elif title[0] == "(":
        closing = ")"
    else:
        return False
    cursor = 1
    while cursor < len(title):
        if title[cursor] == "\\" and cursor + 1 < len(title):
            cursor += 2
            continue
        if title[cursor] == closing:
            return not title[cursor + 1 :].strip()
        if closing == ")" and title[cursor] == "(":
            return False
        cursor += 1
    return False


def strip_markdown_inline_link_metadata(
    text: str,
    reference_labels: frozenset[str] = frozenset(),
) -> str:
    """Preserve rendered labels while removing inline link/image metadata.

    Args:
        text: Markdown source whose inline links and images must be normalized.
        reference_labels: Valid definition labels available to full-reference links.
    """
    visible_parts: list[str] = []
    index = 0
    while index < len(text):
        is_image = text.startswith("![", index)
        label_open = index + 1 if is_image else index
        if label_open >= len(text) or text[label_open] != "[":
            visible_parts.append(text[index])
            index += 1
            continue
        cursor = label_open + 1
        label_depth = 1
        while cursor < len(text) and label_depth:
            if text[cursor] == "\\" and cursor + 1 < len(text):
                cursor += 2
                continue
            if text[cursor] == "[":
                label_depth += 1
            elif text[cursor] == "]":
                label_depth -= 1
            cursor += 1
        label_close = cursor - 1
        if not label_depth and cursor < len(text) and text[cursor] == "[":
            reference_cursor = cursor + 1
            while reference_cursor < len(text):
                if (
                    text[reference_cursor] == "\\"
                    and reference_cursor + 1 < len(text)
                ):
                    reference_cursor += 2
                    continue
                if text[reference_cursor] == "]":
                    reference_cursor += 1
                    reference_label = text[cursor + 1 : reference_cursor - 1]
                    if not reference_label:
                        reference_label = text[label_open + 1 : label_close]
                    if normalize_reference_label(reference_label) not in reference_labels:
                        visible_parts.append(text[index:reference_cursor])
                        index = reference_cursor
                        break
                    visible_parts.append(
                        strip_markdown_inline_link_metadata(
                            text[label_open:cursor],
                            reference_labels,
                        )
                    )
                    visible_parts.append(
                        "".join(
                            character
                            for character in text[cursor:reference_cursor]
                            if character in "\r\n"
                        )
                    )
                    index = reference_cursor
                    break
                reference_cursor += 1
            if index == reference_cursor:
                continue
        if label_depth or cursor >= len(text) or text[cursor] != "(":
            visible_parts.append(text[index])
            index += 1
            continue
        target_open = cursor
        cursor += 1
        target_depth = 1
        quote_character: str | None = None
        in_angle_destination = False
        while cursor < len(text) and target_depth:
            character = text[cursor]
            if character == "\\" and cursor + 1 < len(text):
                cursor += 2
                continue
            if quote_character is not None:
                if character == quote_character:
                    quote_character = None
                cursor += 1
                continue
            if in_angle_destination:
                if character == ">":
                    in_angle_destination = False
                cursor += 1
                continue
            if character == "<":
                in_angle_destination = True
            elif character in {'"', "'"} and (
                cursor == target_open + 1 or text[cursor - 1].isspace()
            ):
                quote_character = character
            elif character == "(":
                target_depth += 1
            elif character == ")":
                target_depth -= 1
            cursor += 1
        if target_depth:
            visible_parts.append(text[index])
            index += 1
            continue
        if not inline_link_target_is_valid(text[target_open + 1 : cursor - 1]):
            visible_parts.append(text[index:cursor])
            index = cursor
            continue
        visible_parts.append(
            strip_markdown_inline_link_metadata(
                text[label_open : label_close + 1],
                reference_labels,
            )
        )
        visible_parts.append(
            "".join(
                character
                for character in text[label_close + 1 : cursor]
                if character in "\r\n"
            )
        )
        index = cursor
    return "".join(visible_parts)


def strip_markdown_blank_terminated_inert_html_blocks(text: str) -> str:
    """Blank inert raw HTML blocks whose boundary is the next blank line.

    Args:
        text: Markdown source whose inert raw HTML blocks must be normalized.
    """
    block_tags = "code|head|iframe|noscript|template|title|xmp"
    block_start = re.compile(
        rf" {{0,3}}</?(?P<tag>{block_tags})(?=(?:\s|/?>|$))",
        flags=re.IGNORECASE,
    )
    visible_lines: list[str] = []
    in_raw_block = False
    for line in text.splitlines(keepends=True):
        if in_raw_block:
            if not line.strip():
                in_raw_block = False
                visible_lines.append(line)
            else:
                visible_lines.append("\n" if line.endswith("\n") else "")
            continue
        if start_match := block_start.match(line):
            same_line_close = re.search(
                rf"</{re.escape(start_match.group('tag'))}[ \t\r\n]*>",
                line[start_match.end() :],
                flags=re.IGNORECASE,
            )
            if same_line_close is not None:
                visible_lines.append(line)
                continue
            in_raw_block = True
            visible_lines.append("\n" if line.endswith("\n") else "")
        else:
            visible_lines.append(line)
    return "".join(visible_lines)


def has_hidden_html_attribute(attributes: str) -> bool:
    """Return whether an HTML start tag carries the ``hidden`` attribute.

    Args:
        attributes: Raw attribute text from an HTML start tag.
    """
    return re.search(
        r'''(?:^|[ \t\r\n\f])hidden(?:[ \t\r\n\f]*=[ \t\r\n\f]*'''
        r'''(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?(?=[ \t\r\n\f/]|$)''',
        attributes,
        flags=re.IGNORECASE,
    ) is not None


def has_css_hidden_style(attributes: str) -> bool:
    """Return whether inline CSS removes an element from rendering.

    Args:
        attributes: Raw attribute text from an HTML start tag.
    """
    for style_match in re.finditer(
        r'''(?:^|[ \t\r\n\f])style[ \t\r\n\f]*=[ \t\r\n\f]*'''
        r'''(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|'''
        r'''(?P<bare>[^\s"'=<>`]+))''',
        attributes,
        flags=re.IGNORECASE,
    ):
        style = next(
            value
            for value in (
                style_match.group("double"),
                style_match.group("single"),
                style_match.group("bare"),
            )
            if value is not None
        )
        style = unescape(style)
        style = re.sub(r"/\*.*?\*/", "", style, flags=re.DOTALL)
        computed: dict[str, tuple[str, bool]] = {}
        for declaration in split_css_declarations(style):
            raw_property, separator, raw_value = declaration.partition(":")
            if not separator:
                continue
            property_name = decode_css_escapes(raw_property).strip().casefold()
            if property_name not in {
                "content-visibility",
                "display",
                "opacity",
                "visibility",
            }:
                continue
            value = decode_css_escapes(raw_value).strip()
            important_match = re.search(
                r"\s*!\s*important\s*$",
                value,
                flags=re.IGNORECASE,
            )
            important = important_match is not None
            if important_match is not None:
                value = value[: important_match.start()].strip()
            if not css_property_value_is_valid(property_name, value):
                continue
            previous = computed.get(property_name)
            if previous is not None and previous[1] and not important:
                continue
            computed[property_name] = (value, important)
        hidden_values = {
            "display": r"none",
            "visibility": r"(?:hidden|collapse)",
            "content-visibility": r"hidden",
        }
        if any(
            property_name in computed
            and re.fullmatch(
                pattern,
                computed[property_name][0],
                flags=re.IGNORECASE,
            )
            is not None
            for property_name, pattern in hidden_values.items()
        ) or (
            "opacity" in computed
            and css_opacity_is_hidden(computed["opacity"][0])
        ):
            return True
    return False


def split_css_declarations(style: str) -> list[str]:
    """Split an inline style without treating quoted or functional semicolons as separators.

    Args:
        style: Comment-free inline CSS source.
    """
    declarations: list[str] = []
    start = 0
    cursor = 0
    quote: str | None = None
    parenthesis_depth = 0
    while cursor < len(style):
        character = style[cursor]
        if character == "\\" and cursor + 1 < len(style):
            cursor += 2
            continue
        if quote is not None:
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "(":
            parenthesis_depth += 1
        elif character == ")" and parenthesis_depth:
            parenthesis_depth -= 1
        elif character == ";" and parenthesis_depth == 0:
            declarations.append(style[start:cursor])
            start = cursor + 1
        cursor += 1
    declarations.append(style[start:])
    return declarations


def css_property_value_is_valid(property_name: str, value: str) -> bool:
    """Return whether a tracked CSS property has a syntactically usable value.

    Args:
        property_name: Normalized CSS property name.
        value: Decoded CSS value without a trailing important annotation.
    """
    normalized = " ".join(value.casefold().split())
    global_values = {"inherit", "initial", "revert", "revert-layer", "unset"}
    if normalized in global_values or re.fullmatch(
        r"(?:var|env)\(.+\)",
        normalized,
        flags=re.DOTALL,
    ):
        return True
    if property_name == "visibility":
        return normalized in {"collapse", "hidden", "visible"}
    if property_name == "content-visibility":
        return normalized in {"auto", "hidden", "visible"}
    if property_name == "opacity":
        return (
            re.fullmatch(
                r"[-+]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:e[-+]?\d+)?%?",
                normalized,
                flags=re.IGNORECASE,
            )
            is not None
            or re.fullmatch(
                r"(?:calc|min|max|clamp)\(.+\)",
                normalized,
                flags=re.DOTALL,
            )
            is not None
        )
    if property_name != "display":
        return False
    legacy_display_values = {
        "contents",
        "inline-block",
        "inline-flex",
        "inline-grid",
        "inline-list-item",
        "inline-table",
        "list-item",
        "none",
        "ruby-base",
        "ruby-base-container",
        "ruby-text",
        "ruby-text-container",
        "table-caption",
        "table-cell",
        "table-column",
        "table-column-group",
        "table-footer-group",
        "table-header-group",
        "table-row",
        "table-row-group",
    }
    if normalized in legacy_display_values:
        return True
    tokens = normalized.split()
    outer_values = {"block", "inline", "run-in"}
    inner_values = {"flex", "flow", "flow-root", "grid", "ruby", "table"}
    if len(tokens) == 1:
        return tokens[0] in outer_values | inner_values
    if len(tokens) == 2:
        token_set = set(tokens)
        return (
            len(token_set & outer_values) == 1
            and len(token_set & inner_values) == 1
        ) or (
            "list-item" in token_set
            and bool(token_set & (outer_values | {"flow", "flow-root"}))
        )
    if len(tokens) == 3:
        token_set = set(tokens)
        return (
            "list-item" in token_set
            and len(token_set & outer_values) == 1
            and len(token_set & {"flow", "flow-root"}) == 1
        )
    return False


def css_opacity_is_hidden(value: str) -> bool:
    """Return whether a literal opacity value computes or clamps to zero.

    Args:
        value: Validated decoded opacity value.
    """
    numeric_match = re.fullmatch(
        r"(?P<number>[-+]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:e[-+]?\d+)?)%?",
        value,
        flags=re.IGNORECASE,
    )
    if numeric_match is not None:
        return float(numeric_match.group("number")) <= 0
    return re.fullmatch(
        r"(?:var|env|calc|min|max|clamp)\(.+\)",
        value,
        flags=re.IGNORECASE | re.DOTALL,
    ) is not None


def decode_css_escapes(value: str) -> str:
    """Decode CSS escapes before declaration matching.

    Args:
        value: Raw CSS declaration text.
    """
    def replace_hex_escape(match: re.Match[str]) -> str:
        """Decode one bounded CSS hexadecimal escape.

        Args:
            match: Regex match containing the hexadecimal CSS code point.
        """
        codepoint = int(match.group("hex"), 16)
        if codepoint == 0 or codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            return "\ufffd"
        return chr(codepoint)

    decoded = re.sub(
        r"\\(?P<hex>[0-9A-Fa-f]{1,6})(?:[ \t\r\n\f])?",
        replace_hex_escape,
        value,
    )
    decoded = re.sub(r"\\(?:\r\n|[\r\n\f])", "", decoded)
    return re.sub(r"\\([^\r\n\f])", r"\1", decoded)


def starts_markdown_html_block(line: str) -> bool:
    """Return whether a visible block HTML tag interrupts a Markdown quote.

    Args:
        line: Structural Markdown source line.
    """
    block_elements = (
        "address|article|aside|base|basefont|blockquote|body|caption|center|"
        "col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|"
        "figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|"
        "legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|"
        "p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|"
        "tr|track|ul"
    )
    return re.match(
        rf" {{0,3}}</?(?:{block_elements})(?=(?:[ \t\r\n/>]|$))",
        line,
        flags=re.IGNORECASE,
    ) is not None


def starts_valid_markdown_fence(line: str) -> bool:
    """Return whether a line is a valid fenced-code opener.

    Args:
        line: Structural Markdown source line.
    """
    relative_indent = len(line) - len(line.lstrip(" "))
    if relative_indent > 3:
        return False
    candidate = line[relative_indent:]
    fence_match = re.match(r"(`{3,}|~{3,})", candidate)
    if fence_match is None:
        return False
    fence = fence_match.group(1)
    return not (
        fence.startswith("`") and "`" in candidate[fence_match.end() :]
    )


def starts_markdown_block_construct(line: str) -> bool:
    """Return whether a line starts a non-paragraph Markdown block.

    Args:
        line: Structural Markdown source line.
    """
    return any(
        pattern.match(line) is not None
        for pattern in (
            re.compile(r" {0,3}>"),
            re.compile(r" {0,3}(?:[*+-]|\d{1,9}[.)])(?:[ \t]+|$)"),
            re.compile(r" {0,3}(?:#{1,6})(?:[ \t]+|$)"),
            re.compile(
                r" {0,3}(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|"
                r"(?:-[ \t]*){3,})$"
            ),
        )
    ) or starts_valid_markdown_fence(line) or starts_markdown_html_block(line)


def markdown_raw_html_block_lines(text: str) -> set[int]:
    """Return source lines inside blank-line-terminated raw HTML blocks.

    Args:
        text: Structural Markdown source.
    """
    block_lines: set[int] = set()
    in_raw_block = False
    for index, line in enumerate(text.splitlines(keepends=True)):
        if in_raw_block:
            if not line.strip():
                in_raw_block = False
            else:
                block_lines.add(index)
            continue
        if starts_markdown_html_block(line):
            in_raw_block = True
            block_lines.add(index)
    return block_lines


def strip_markdown_hidden_html_containers(text: str) -> str:
    """Blank balanced non-rendered HTML containers while preserving lines.

    Args:
        text: Markdown source whose hidden raw HTML containers must be normalized.
    """
    inert_elements = {"head", "iframe", "noscript", "template", "title", "xmp"}
    void_elements = {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
    tag_pattern = re.compile(
        r'''<(?P<closing>/)?(?P<tag>[A-Za-z][A-Za-z0-9-]*)\b'''
        r'''(?P<attributes>(?:[^<>"']|"[^"]*"|'[^']*')*?)'''
        r'''(?P<self_closing>/)?[ \t\r\n]*>''',
        flags=re.IGNORECASE,
    )
    visible_parts: list[str] = []
    output_cursor = 0
    search_cursor = 0
    while opening_match := tag_pattern.search(text, search_cursor):
        tag_name = opening_match.group("tag").casefold()
        if (
            opening_match.group("closing") is not None
            or opening_match.group("self_closing") is not None
            or tag_name in void_elements
            or (
                tag_name not in inert_elements
                and not has_hidden_html_attribute(
                    opening_match.group("attributes")
                )
                and not has_css_hidden_style(
                    opening_match.group("attributes")
                )
            )
        ):
            search_cursor = opening_match.end()
            continue
        depth = 1
        nested_cursor = opening_match.end()
        closing_end: int | None = None
        while candidate := tag_pattern.search(text, nested_cursor):
            nested_cursor = candidate.end()
            if candidate.group("tag").casefold() != tag_name:
                continue
            if candidate.group("closing") is not None:
                depth -= 1
                if depth == 0:
                    closing_end = candidate.end()
                    break
            elif candidate.group("self_closing") is None:
                depth += 1
        if closing_end is None:
            visible_parts.append(text[output_cursor : opening_match.start()])
            visible_parts.append(
                re.sub(r"[^\r\n]", "", text[opening_match.start() :])
            )
            output_cursor = len(text)
            search_cursor = len(text)
            break
        visible_parts.append(text[output_cursor : opening_match.start()])
        visible_parts.append(
            re.sub(r"[^\r\n]", "", text[opening_match.start() : closing_end])
        )
        output_cursor = closing_end
        search_cursor = closing_end
    visible_parts.append(text[output_cursor:])
    return "".join(visible_parts)


def scan_reference_definition_label(text: str) -> tuple[int | None, bool]:
    """Scan an escape-aware, optionally multiline reference label.

    Args:
        text: Candidate Markdown reference-definition text.

    Returns:
        The index after a complete label and colon, plus whether an incomplete
        candidate may continue on the next line.
    """
    index = 0
    while index < min(3, len(text)) and text[index] == " ":
        index += 1
    if index >= len(text) or text[index] != "[":
        return None, False
    index += 1
    label_start = index
    line_endings = 0
    while index < len(text):
        if index - label_start > 999:
            return None, False
        if text[index] == "\\" and index + 1 < len(text):
            index += 2
            continue
        if text[index] in "\r\n":
            if text[index] == "\r" and index + 1 < len(text) and text[index + 1] == "\n":
                index += 1
            line_endings += 1
            if line_endings > 1:
                return None, False
        elif text[index] == "[":
            return None, False
        elif text[index] == "]":
            if index + 1 < len(text) and text[index + 1] == ":":
                label = text[label_start:index]
                return (
                    (index + 2, False)
                    if any(not character.isspace() for character in label)
                    else (None, False)
                )
            return None, False
        index += 1
    return None, True


def normalized_reference_definition_label(text: str, end: int) -> str:
    """Return the normalized label from a scanned definition prefix.

    Args:
        text: Reference-definition source containing the label.
        end: Index immediately after the label's trailing colon.
    """
    label_start = text.find("[", 0, end)
    return normalize_reference_label(text[label_start + 1 : end - 2])


def reference_destination_prefix_end(text: str) -> int | None:
    """Return the end of a balanced reference destination prefix.

    Args:
        text: Candidate continuation line for a reference definition.
    """
    index = 0
    while index < min(3, len(text)) and text[index] == " ":
        index += 1
    if index >= len(text):
        return None
    if text[index] == "<":
        index += 1
        while index < len(text):
            if text[index] == "\\" and index + 1 < len(text):
                index += 2
                continue
            if text[index] == ">":
                return index + 1
            if text[index] in "<>\r\n":
                return None
            index += 1
        return None
    destination_start = index
    parenthesis_depth = 0
    while index < len(text):
        character = text[index]
        if character == "\\" and index + 1 < len(text):
            index += 2
            continue
        if character.isspace() or ord(character) < 0x20:
            break
        if character == "(":
            parenthesis_depth += 1
        elif character == ")":
            if parenthesis_depth == 0:
                return None
            parenthesis_depth -= 1
        index += 1
    if index == destination_start or parenthesis_depth != 0:
        return None
    return index


def unclosed_reference_title_delimiter(text: str) -> str | None:
    """Return the expected close for a reference title opened on this line.

    Args:
        text: Reference-definition text after its label and colon.
    """
    opening_match = re.match(r'''[ \t]+(?P<opening>["'(])''', text)
    if opening_match is not None:
        opening = opening_match.group("opening")
        closing = ")" if opening == "(" else opening
        cursor = opening_match.end()
        while cursor < len(text):
            if text[cursor] == "\\" and cursor + 1 < len(text):
                cursor += 2
                continue
            if text[cursor] == closing:
                break
            cursor += 1
        else:
            return closing
    return None


def closes_reference_title(line: str, delimiter: str) -> bool:
    """Return whether a continuation line validly closes a reference title.

    Args:
        line: Candidate continuation line.
        delimiter: Expected quote or parenthesis closing delimiter.
    """
    cursor = 0
    while cursor < len(line):
        if line[cursor] == "\\" and cursor + 1 < len(line):
            cursor += 2
            continue
        if line[cursor] == delimiter:
            return re.fullmatch(r"[ \t]*(?:\r?\n)?", line[cursor + 1 :]) is not None
        cursor += 1
    return False


def complete_reference_title(text: str, *, require_separator: bool) -> bool:
    """Return whether text contains one complete escape-aware reference title.

    Args:
        text: Candidate title text, including its optional indentation.
        require_separator: Whether at least one space or tab must precede the title.
    """
    candidate = text.removesuffix("\n").removesuffix("\r")
    if "\r" in candidate or "\n" in candidate:
        return False
    cursor = 0
    while cursor < len(candidate) and candidate[cursor] in " \t":
        cursor += 1
    if require_separator:
        if cursor == 0:
            return False
    elif "\t" in candidate[:cursor] or cursor > 3:
        return False
    if cursor >= len(candidate) or candidate[cursor] not in {'"', "'", "("}:
        return False
    opening = candidate[cursor]
    closing = ")" if opening == "(" else opening
    cursor += 1
    while cursor < len(candidate):
        character = candidate[cursor]
        if character == "\\" and cursor + 1 < len(candidate):
            cursor += 2
            continue
        if opening == "(" and character == "(":
            return False
        if character == closing:
            return candidate[cursor + 1 :].strip(" \t") == ""
        cursor += 1
    return False


def strip_markdown_nonoperative_content(text: str) -> str:
    """Replace non-rendered Markdown content with blank lines.

    Args:
        text: Markdown source whose operative prose must be inspected.
    """
    without_fenced_code = strip_markdown_fenced_code(text)
    with_protected_code_spans = protect_markdown_code_spans(without_fenced_code)
    without_comments = strip_markdown_html_comments(with_protected_code_spans)
    without_raw_directives = without_comments
    for directive_pattern in (
        r"<\?.*?(?:\?>|$)",
        r"<!\[CDATA\[.*?(?:\]\]>|$)",
        r"<![A-Z].*?(?:>|$)",
    ):
        without_raw_directives = re.sub(
            directive_pattern,
            lambda match: re.sub(r"[^\r\n]", "", match.group(0)),
            without_raw_directives,
            flags=re.DOTALL,
        )
    without_raw_html_blocks = without_raw_directives
    for tag_name in ("script", "style", "pre", "textarea"):
        without_raw_html_blocks = re.sub(
            rf'''<{tag_name}\b(?:[^<>"']|"[^"]*"|'[^']*')*>.*?(?:</{tag_name}[ \t\r\n]*>|$)''',
            lambda match: re.sub(r"[^\r\n]", "", match.group(0)),
            without_raw_html_blocks,
            flags=re.DOTALL | re.IGNORECASE,
        )
    without_raw_html_blocks = strip_markdown_blank_terminated_inert_html_blocks(
        without_raw_html_blocks
    )
    without_raw_html_blocks = strip_markdown_hidden_html_containers(
        without_raw_html_blocks,
    )
    html_block_interrupt_lines = {
        index
        for index, line in enumerate(
            without_raw_html_blocks.splitlines(keepends=True)
        )
        if starts_markdown_html_block(line)
    }
    without_html_tags = re.sub(
        r'''</?[A-Za-z][A-Za-z0-9-]*(?:[^<>"']|"[^"]*"|'[^']*')*>''',
        lambda match: re.sub(r"[^\r\n]", "", match.group(0)),
        without_raw_html_blocks,
    )
    without_quotes_lines: list[str] = []
    in_block_quote = False
    interrupting_block_patterns = (
        re.compile(r" {0,3}#{1,6}(?:[ \t]+|$)"),
        re.compile(r" {0,3}(?:[*+-]|1[.)])[ \t]+(?=\S)"),
        re.compile(
            r" {0,3}(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|"
            r"(?:-[ \t]*){3,})(?:\r?\n)?$"
        ),
    )
    for line_index, line in enumerate(
        without_html_tags.splitlines(keepends=True)
    ):
        if re.match(r" {0,3}>[ \t]?", line) is not None:
            quoted_content = line
            while quote_match := re.match(r" {0,3}>[ \t]?", quoted_content):
                quoted_content = quoted_content[quote_match.end() :]
            in_block_quote = bool(quoted_content.strip()) and not (
                quoted_content.startswith("    ")
                or starts_markdown_block_construct(quoted_content)
            )
            without_quotes_lines.append("\n" if line.endswith("\n") else "")
        elif in_block_quote and line.strip():
            starts_interrupting_block = any(
                pattern.match(line) is not None
                for pattern in interrupting_block_patterns
            ) or (
                starts_valid_markdown_fence(line)
                or line_index in html_block_interrupt_lines
            )
            if starts_interrupting_block:
                in_block_quote = False
                without_quotes_lines.append(line)
            else:
                without_quotes_lines.append("\n" if line.endswith("\n") else "")
        else:
            if not line.strip():
                in_block_quote = False
            without_quotes_lines.append(line)
    without_quotes = "".join(without_quotes_lines)
    visible_lines: list[str] = []
    link_reference_destination_pending = False
    pending_reference_line_index: int | None = None
    pending_reference_line: str | None = None
    link_reference_title_pending = False
    open_reference_title_delimiter: str | None = None
    open_reference_title_lines: list[tuple[int, str]] = []
    pending_reference_label_text = ""
    pending_reference_label_lines: list[tuple[int, str]] = []
    pending_reference_normalized_label: str | None = None
    open_reference_normalized_label: str | None = None
    valid_reference_labels: set[str] = set()
    list_content_indents: list[int] = []
    paragraph_open = False
    for line in without_quotes.splitlines(keepends=True):
        list_content_indent = update_markdown_list_content_indent(
            line,
            list_content_indents,
            paragraph_open=paragraph_open,
        )
        block_line = (
            line[list_content_indent:]
            if list_content_indent is not None
            and line.startswith(" " * list_content_indent)
            else line
        )
        if not block_line.strip():
            paragraph_open = False
        reference_label_end: int | None = None
        reference_normalized_label: str | None = None
        completed_reference_label_lines: list[tuple[int, str]] = []
        if pending_reference_label_lines:
            combined_label = pending_reference_label_text + block_line
            combined_label_end, label_may_continue = scan_reference_definition_label(
                combined_label
            )
            if combined_label_end is not None:
                reference_label_end = combined_label_end - len(
                    pending_reference_label_text
                )
                completed_reference_label_lines = pending_reference_label_lines
                reference_normalized_label = normalized_reference_definition_label(
                    combined_label,
                    combined_label_end,
                )
                pending_reference_label_text = ""
                pending_reference_label_lines = []
            elif label_may_continue and line.strip():
                pending_reference_label_text = combined_label
                pending_reference_label_lines.append((len(visible_lines), line))
                visible_lines.append("\n" if line.endswith("\n") else "")
                continue
            else:
                for line_index, original_line in pending_reference_label_lines:
                    visible_lines[line_index] = original_line
                pending_reference_label_text = ""
                pending_reference_label_lines = []
        if open_reference_title_delimiter is not None:
            if line.strip():
                open_reference_title_lines.append((len(visible_lines), line))
                visible_lines.append("\n" if line.endswith("\n") else "")
                if closes_reference_title(
                    block_line,
                    open_reference_title_delimiter,
                ):
                    if open_reference_normalized_label is not None:
                        valid_reference_labels.add(open_reference_normalized_label)
                    open_reference_title_delimiter = None
                    open_reference_title_lines = []
                    open_reference_normalized_label = None
                continue
            for line_index, original_line in open_reference_title_lines:
                visible_lines[line_index] = original_line
            open_reference_title_delimiter = None
            open_reference_title_lines = []
            open_reference_normalized_label = None
        if reference_label_end is None and not paragraph_open:
            reference_label_end, label_may_continue = scan_reference_definition_label(
                block_line
            )
            if reference_label_end is None and label_may_continue:
                pending_reference_label_text = block_line
                pending_reference_label_lines = [(len(visible_lines), line)]
                visible_lines.append("\n" if line.endswith("\n") else "")
                continue
            if reference_label_end is not None:
                reference_normalized_label = normalized_reference_definition_label(
                    block_line,
                    reference_label_end,
                )
        inline_open_title_delimiter: str | None = None
        inline_title_is_complete = False
        if reference_label_end is not None:
            inline_reference_tail = block_line[reference_label_end:]
            if inline_reference_tail.strip():
                inline_destination_end = reference_destination_prefix_end(
                    inline_reference_tail
                )
                inline_destination_tail = (
                    inline_reference_tail[inline_destination_end:]
                    if inline_destination_end is not None
                    else ""
                )
                inline_open_title_delimiter = (
                    unclosed_reference_title_delimiter(inline_destination_tail)
                    if inline_destination_end is not None
                    else None
                )
                inline_title_is_complete = complete_reference_title(
                    inline_destination_tail,
                    require_separator=True,
                )
                inline_destination_is_valid = (
                    re.fullmatch(
                        r"[ \t]*(?:\r?\n)?",
                        inline_destination_tail,
                    )
                    is not None
                    or inline_title_is_complete
                )
                if (
                    not inline_destination_is_valid
                    and inline_open_title_delimiter is None
                ):
                    for (
                        line_index,
                        original_line,
                    ) in completed_reference_label_lines:
                        visible_lines[line_index] = original_line
                    reference_label_end = None
                    reference_normalized_label = None
        continued_destination_prefix_end = (
            reference_destination_prefix_end(block_line)
            if link_reference_destination_pending
            else None
        )
        continued_destination_tail = (
            block_line[continued_destination_prefix_end:]
            if continued_destination_prefix_end is not None
            else ""
        )
        continued_open_title_delimiter = (
            unclosed_reference_title_delimiter(
                continued_destination_tail
            )
            if continued_destination_prefix_end is not None
            else None
        )
        continued_title_is_complete = complete_reference_title(
            continued_destination_tail,
            require_separator=True,
        )
        continued_destination_is_valid = (
            continued_destination_prefix_end is not None
            and (
                re.fullmatch(
                    r"[ \t]*(?:\r?\n)?",
                    continued_destination_tail,
                )
                is not None
                or continued_title_is_complete
            )
        )
        continued_title_is_valid = (
            complete_reference_title(
                block_line,
                require_separator=False,
            )
            if link_reference_title_pending
            else False
        )
        if (
            continued_destination_is_valid
            or continued_open_title_delimiter is not None
        ):
            completed_reference_label = pending_reference_normalized_label
            link_reference_destination_pending = False
            pending_reference_line_index = None
            pending_reference_line = None
            pending_reference_normalized_label = None
            visible_lines.append("\n" if line.endswith("\n") else "")
            if continued_open_title_delimiter is not None:
                link_reference_title_pending = False
                open_reference_title_delimiter = continued_open_title_delimiter
                open_reference_title_lines = [(len(visible_lines) - 1, line)]
                open_reference_normalized_label = completed_reference_label
            else:
                if completed_reference_label is not None:
                    valid_reference_labels.add(completed_reference_label)
                link_reference_title_pending = not continued_title_is_complete
        else:
            if link_reference_destination_pending:
                assert pending_reference_line_index is not None
                assert pending_reference_line is not None
                visible_lines[pending_reference_line_index] = pending_reference_line
                link_reference_destination_pending = False
                pending_reference_line_index = None
                pending_reference_line = None
                pending_reference_normalized_label = None
            if reference_label_end is not None:
                assert reference_normalized_label is not None
                reference_tail = block_line[reference_label_end:]
                destination_is_pending = not reference_tail.strip()
                link_reference_destination_pending = destination_is_pending
                pending_reference_line_index = (
                    len(visible_lines) if destination_is_pending else None
                )
                pending_reference_line = line if destination_is_pending else None
                pending_reference_normalized_label = (
                    reference_normalized_label if destination_is_pending else None
                )
                link_reference_title_pending = (
                    not destination_is_pending and not inline_title_is_complete
                )
                visible_lines.append("\n" if line.endswith("\n") else "")
                open_reference_title_delimiter = inline_open_title_delimiter
                if open_reference_title_delimiter is not None:
                    link_reference_title_pending = False
                    open_reference_normalized_label = reference_normalized_label
                elif not destination_is_pending:
                    valid_reference_labels.add(reference_normalized_label)
                open_reference_title_lines = (
                    [(len(visible_lines) - 1, line)]
                    if open_reference_title_delimiter is not None
                    else []
                )
                paragraph_open = False
            elif continued_title_is_valid:
                link_reference_title_pending = False
                visible_lines.append("\n" if line.endswith("\n") else "")
                paragraph_open = False
            elif re.match(r"(?: {4}|\t)", block_line) is not None:
                link_reference_title_pending = False
                visible_lines.append("\n" if line.endswith("\n") else "")
                paragraph_open = False
            else:
                link_reference_title_pending = False
                visible_lines.append(line)
                paragraph_open = bool(block_line.strip()) and not (
                    starts_markdown_block_construct(block_line)
                )
    if link_reference_destination_pending:
        assert pending_reference_line_index is not None
        assert pending_reference_line is not None
        visible_lines[pending_reference_line_index] = pending_reference_line
    if open_reference_title_delimiter is not None:
        for line_index, original_line in open_reference_title_lines:
            visible_lines[line_index] = original_line
    for line_index, original_line in pending_reference_label_lines:
        visible_lines[line_index] = original_line
    without_indented_code = "".join(visible_lines)
    without_link_metadata = strip_markdown_inline_link_metadata(
        without_indented_code,
        frozenset(valid_reference_labels),
    )
    normalized = strip_markdown_fenced_code(without_link_metadata)
    return normalized.translate(MARKDOWN_CODE_SPAN_RESTORATION)


def extract_terminal_cleanup_order(cleanup_section: str) -> tuple[str, ...] | None:
    """Return the three numbered transitions following the terminal-order anchor.

    Args:
        cleanup_section: Canonical cleanup heading section or top-level list item.
    """
    lines = cleanup_section.splitlines()
    anchors = tuple(
        index
        for index, line in enumerate(lines)
        if line.strip() == TERMINAL_CLEANUP_ORDER_ANCHOR
    )
    if len(anchors) != 1:
        return None
    transition_lines = tuple(
        line.rstrip("\r\n")
        for line in lines[anchors[0] + 1 :]
        if line.strip()
    )
    expected_count = len(TERMINAL_CLEANUP_ORDER_LINES)
    order_lines: list[str] = []
    top_level_indent: int | None = None
    top_level_content_indent: int | None = None
    for candidate in transition_lines:
        candidate_match = re.fullmatch(r"( *)(\d+[.)])(\s+).+", candidate)
        if top_level_indent is None:
            if candidate_match is None:
                return (candidate.strip(),)
            top_level_indent = len(candidate_match.group(1))
            top_level_content_indent = (
                top_level_indent
                + len(candidate_match.group(2))
                + len(candidate_match.group(3))
            )
            order_lines.append(candidate.strip())
            continue
        if candidate_match is not None:
            candidate_indent = len(candidate_match.group(1))
            if candidate_indent < top_level_indent:
                break
            if (
                top_level_content_indent is not None
                and candidate_indent < top_level_content_indent
            ):
                order_lines.append(candidate.strip())
                if len(order_lines) > expected_count:
                    break
            continue
        candidate_indent = len(candidate) - len(candidate.lstrip(" "))
        if candidate_indent <= top_level_indent:
            break
    return tuple(order_lines)


def extract_markdown_policy_section(
    text: str,
    anchor: str,
    *,
    start_line: int | None = None,
) -> str | None:
    """Return the canonical heading section or top-level list item at ``anchor``.

    Args:
        text: Markdown policy entry point.
        anchor: Exact heading or top-level list-item prefix for the cleanup policy.
        start_line: Prevalidated structural anchor line, when normalization was separate.
    """
    lines = text.splitlines(keepends=True)
    if start_line is None:
        starts = tuple(
            index
            for index, line in enumerate(lines)
            if (
                line.rstrip("\r\n") == anchor
                if anchor.startswith("#")
                else line.startswith(anchor)
            )
        )
    elif 0 <= start_line < len(lines) and (
        lines[start_line].rstrip("\r\n") == anchor
        if anchor.startswith("#")
        else lines[start_line].startswith(anchor)
    ):
        starts = (start_line,)
    else:
        starts = ()
    if len(starts) != 1:
        return None
    start = starts[0]

    if anchor.startswith("#"):
        heading_level = len(anchor) - len(anchor.lstrip("#"))
        for end in range(start + 1, len(lines)):
            heading_match = re.match(
                r" {0,3}(#{1,6})(?:[ \t]+|(?=\r?\n?$))",
                lines[end],
            )
            if heading_match is not None and len(heading_match.group(1)) <= heading_level:
                return "".join(lines[start:end])
            title_line = lines[end].rstrip("\r\n")
            title_indent = len(title_line) - len(title_line.lstrip(" "))
            title_starts_block = starts_markdown_block_construct(title_line)
            setext_match = (
                re.fullmatch(r" {0,3}(=+|-+)[ \t]*(?:\r?\n)?", lines[end + 1])
                if end + 1 < len(lines)
                and title_line.strip()
                and title_indent <= 3
                and not title_starts_block
                else None
            )
            if setext_match is not None:
                next_level = 1 if setext_match.group(1).startswith("=") else 2
                if next_level <= heading_level:
                    paragraph_start = end
                    while paragraph_start > start + 1:
                        previous_line = lines[paragraph_start - 1].rstrip("\r\n")
                        previous_indent = len(previous_line) - len(
                            previous_line.lstrip(" ")
                        )
                        if (
                            not previous_line.strip()
                            or previous_indent > 3
                            or starts_markdown_block_construct(previous_line)
                        ):
                            break
                        paragraph_start -= 1
                    return "".join(lines[start:paragraph_start])
    else:
        for end in range(start + 1, len(lines)):
            if lines[end].strip() and not lines[end].startswith(("  ", "\t")):
                return "".join(lines[start:end])
    return "".join(lines[start:])


def check_ui_pattern_foundation(root: Path) -> list[Finding]:
    """Require new grids and every wizard to use the shared browser foundation.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    findings: list[Finding] = []
    foundation_path = root / UI_PATTERN_FOUNDATION
    foundation_text, foundation_error = read_text(foundation_path)
    if foundation_error is not None:
        return [Finding(foundation_path, "shared UI-pattern foundation is missing or unreadable")]
    assert foundation_text is not None
    for marker in ("AtlasoUiPatterns", "createGrid", "createWizard"):
        if marker not in foundation_text:
            findings.append(Finding(foundation_path, f"shared UI-pattern API marker is missing: {marker}"))

    static_root = root / "atlaso" / "app" / "static"
    for path in static_root.rglob("*.js") if static_root.exists() else []:
        relative = path.relative_to(root)
        if relative.is_relative_to(Path("atlaso/app/static/vendor")):
            continue
        text, error = read_text(path)
        if error is not None:
            findings.append(error)
            continue
        assert text is not None
        constructors = list(TABULATOR_CONSTRUCTOR_RE.finditer(text))
        if relative == UI_PATTERN_FOUNDATION:
            if len(constructors) != 1:
                findings.append(
                    Finding(path, "shared UI-pattern foundation must contain exactly one Tabulator constructor")
                )
        else:
            for match in constructors:
                findings.append(
                    Finding(
                        path,
                        "raw Tabulator construction is forbidden; use AtlasoUiPatterns.createGrid",
                        line_for_offset(text, match.start()),
                    )
                )
            if LEGACY_TABULATOR_MARKER in text:
                findings.append(
                    Finding(path, "the completed #117 legacy Tabulator marker is forbidden")
                )
        if relative != UI_PATTERN_FOUNDATION:
            for marker in FORBIDDEN_PAGE_WIZARD_CONTROLLER_MARKERS:
                offset = text.find(marker)
                if offset >= 0:
                    findings.append(
                        Finding(
                            path,
                            "page-specific wizard step control is forbidden; use AtlasoUiPatterns.createWizard",
                            line_for_offset(text, offset),
                        )
                    )

    template_root = root / "atlaso" / "app" / "templates"
    for path in template_root.rglob("*.html") if template_root.exists() else []:
        text, error = read_text(path)
        if error is not None:
            findings.append(error)
            continue
        assert text is not None
        for match in TABULATOR_CONSTRUCTOR_RE.finditer(text):
            findings.append(
                Finding(
                    path,
                    "raw Tabulator construction is forbidden; use AtlasoUiPatterns.createGrid",
                    line_for_offset(text, match.start()),
                )
            )
        for match in HTML_FORM_RE.finditer(text):
            attributes = match.group("attributes")
            body = match.group("body")
            if "wizard" not in attributes.lower():
                continue
            if "data-atlaso-wizard" not in attributes:
                findings.append(
                    Finding(
                        path,
                        "wizard form must declare data-atlaso-wizard",
                        line_for_offset(text, match.start()),
                    )
                )
                continue
            form_text = attributes + body
            for marker in WIZARD_REQUIRED_MARKERS:
                if marker not in form_text:
                    findings.append(
                        Finding(
                            path,
                            f"wizard form is missing shared foundation marker: {marker}",
                            line_for_offset(text, match.start()),
                        )
                    )
    return findings


def check_xmlish_svg(path: Path, text: str) -> list[Finding]:
    """Check xmlish svg.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The check xmlish svg result.
    """
    import xml.etree.ElementTree as ET

    try:
        ET.fromstring(text)
    except ET.ParseError as exc:
        return [Finding(path, str(exc))]
    return []


def check_virtualization_legacy(root: Path) -> list[Finding]:
    """Reject retired Hyper-V development and standalone QCOW2 release surfaces.

    Args:
        root: Repository root to inspect.
    """

    findings: list[Finding] = []
    forbidden_paths = (
        Path("image/hyperv"),
        Path("scripts/windows/hyperv"),
        Path("docs/hyperv-lifecycle-testing.md"),
        Path("docs/reference/hyperv-lifecycle-testing.md"),
        Path("hyperv-admin-check.txt"),
        Path("hyperv-prereq-check.txt"),
    )
    for relative in forbidden_paths:
        if (root / relative).exists():
            findings.append(Finding(root / relative, "retired Hyper-V development or lifecycle path remains"))

    stale_markers = (
        "image/hyperv/",
        "image\\hyperv\\",
        "scripts/windows/hyperv/",
        "scripts\\windows\\hyperv\\",
        "hyperv-lifecycle-testing.md",
        "retired_hyperv_",
    )
    for relative_root in (Path("docs"), Path("tests"), Path(".github")):
        directory = root / relative_root
        for path in directory.rglob("*") if directory.exists() else ():
            if not path.is_file() or path.is_symlink():
                continue
            text, error = read_text(path)
            if error is not None or text is None:
                continue
            for marker in stale_markers:
                offset = text.find(marker)
                if offset >= 0:
                    findings.append(
                        Finding(path, f"retired virtualization reference remains: {marker}", line_for_offset(text, offset))
                    )

    workflow_directory = root / ".github"
    workflow_markers = (
        "Test-AtlasoHyperVSecureString.ps1",
        "Test-CreateHypervSwitches.ps1",
        "test_hyperv_cleanup.py",
        "test_tiny_client_preparation.py",
    )
    for path in workflow_directory.rglob("*") if workflow_directory.exists() else ():
        if not path.is_file() or path.is_symlink():
            continue
        text, error = read_text(path)
        if error is not None or text is None:
            continue
        for marker in workflow_markers:
            offset = text.find(marker)
            if offset >= 0:
                findings.append(
                    Finding(path, f"retired virtualization test command remains: {marker}", line_for_offset(text, offset))
                )

    exporter_roots = (
        root / "scripts/windows/virtualization",
        root / "docs/reference/virtualization-artifacts.md",
    )
    standalone_markers = ("photon-os.qcow2", "atlaso-system.qcow2", "-Target Kvm", "-Target Proxmox")
    for candidate in exporter_roots:
        paths = candidate.rglob("*") if candidate.is_dir() else (candidate,)
        for path in paths:
            if not path.is_file() or path.is_symlink():
                continue
            text, error = read_text(path)
            if error is not None or text is None:
                continue
            for marker in standalone_markers:
                offset = text.find(marker)
                if offset >= 0:
                    findings.append(
                        Finding(path, f"standalone QCOW2 release marker remains: {marker}", line_for_offset(text, offset))
                    )
    exporter_directory = root / "scripts/windows/virtualization"
    for path in (
        sorted(exporter_directory.glob("*.ps1")) + sorted(exporter_directory.glob("*.psm1"))
        if exporter_directory.exists()
        else []
    ):
        text, error = read_text(path)
        if error is not None or text is None:
            continue
        for marker in ("AllowedTargetNames", "'Kvm', 'Proxmox'", "'qcow2'"):
            offset = text.find(marker)
            if offset >= 0:
                findings.append(
                    Finding(path, f"standalone multi-target exporter marker remains: {marker}", line_for_offset(text, offset))
                )
    return findings


def check_protected_workflow_caches(root: Path) -> list[Finding]:
    """Reject writable setup-python caches without effective Actions write scope.

    Args:
        root: Repository root containing protected publication workflows.

    Returns:
        Findings for cache-enabled setup-python steps that cannot save a cache.
    """

    findings: list[Finding] = []
    for relative_path in PROTECTED_PUBLICATION_WORKFLOWS:
        path = root / relative_path
        text, error = read_text(path)
        if error is not None or text is None:
            findings.append(Finding(path, "protected publication workflow is missing or unreadable"))
            continue
        try:
            workflow = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            findings.append(Finding(path, f"protected publication workflow YAML is invalid: {exc}"))
            continue
        if not isinstance(workflow, dict):
            findings.append(Finding(path, "protected publication workflow must be a YAML mapping"))
            continue
        workflow_permissions = workflow.get("permissions")
        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            findings.append(Finding(path, "protected publication workflow jobs must be a mapping"))
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            permissions = job.get("permissions", workflow_permissions)
            actions_permission: object = None
            if permissions == "write-all":
                actions_permission = "write"
            elif permissions == "read-all":
                actions_permission = "read"
            elif isinstance(permissions, dict):
                actions_permission = permissions.get("actions")
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                inputs = step.get("with", {})
                if not isinstance(uses, str) or not uses.startswith("actions/setup-python@"):
                    continue
                if not isinstance(inputs, dict) or "cache" not in inputs:
                    continue
                cache_value = inputs.get("cache")
                if cache_value is None or (isinstance(cache_value, str) and not cache_value.strip()):
                    continue
                if actions_permission != "write":
                    findings.append(
                        Finding(
                            path,
                            f"protected job {str(job_id)!r} enables setup-python cache without actions: write",
                        )
                    )
    return findings


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Command-line arguments to parse, or ``None`` to use the process arguments.


    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser(description="Run Atlaso repository checks.")
    parser.add_argument("paths", nargs="*", help="Optional files or directories to check.")
    args = parser.parse_args(argv)

    files = collect_files(args.paths)
    findings: list[Finding] = []
    for path in files:
        findings.extend(check_file(path))
    findings.extend(check_agent_policy_gate(ROOT))
    findings.extend(check_merge_authority_transfer_fixtures(ROOT))
    findings.extend(check_spark_worker_agent(ROOT))
    findings.extend(check_ui_pattern_foundation(ROOT))
    findings.extend(check_virtualization_legacy(ROOT))
    findings.extend(check_protected_workflow_caches(ROOT))

    if findings:
        print(f"Repository checks failed with {len(findings)} issue(s):", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding.render()}", file=sys.stderr)
        return 1

    print(f"Repository checks passed for {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
