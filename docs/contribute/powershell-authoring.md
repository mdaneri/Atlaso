---
title: PowerShell authoring
description: Comment-based help, credential types, and pinned analyzer requirements.
audience:
  - contributor
  - maintainer
status: current
---

# PowerShell authoring

Every new or changed `.ps1` or `.psm1` file must use comment-based help at file/module scope and before every function,
including nested helpers. Provide a concise `.SYNOPSIS` and one `.PARAMETER` entry for every declared parameter. Keep
exactly one canonical help block for each script, module, or function; adjacent generated and purpose-specific help
blocks are invalid. Add ordinary comments where they preserve non-obvious intent, safety ordering, trust boundaries, or
platform-specific reasoning; comments should explain why the code is structured that way rather than restating the command.

Run `pwsh -NoProfile -File scripts/check_powershell_help.ps1 -BaseRoot <base-checkout>` before committing PowerShell
changes. CI compares the candidate with the exact pull-request base, so untouched legacy files remain valid until their
next edit and every edited PowerShell file adopts the complete standard at once.

Install the exact repository analyzer with
`Install-PSResource PSScriptAnalyzer -Version 1.25.0 -TrustRepository`, then run
`pwsh -NoProfile -File scripts/check_powershell_analysis.ps1`. The pinned profile analyzes every tracked `.ps1`,
`.psm1`, and `.psd1` file. Credential parameters must use `SecureString` or `PSCredential`, must not declare default
values, and must not rely on broad `PSAvoidUsingPlainTextForPassword` suppressions. CI and pre-commit run the same
checker so the local and pull-request requirements remain identical.

Run the isolated Photon build-state regression on Windows with
`pwsh -NoProfile -File tests/powershell/Test-PhotonBuildStateRoot.ps1 -RepositoryRoot (Resolve-Path .).Path`.
It extracts wrapper functions through the PowerShell AST without running the image build. Keep required helper
imports synchronized with the functions under test, and reject missing or duplicate definitions during setup.

Run fixtures that depend on Windows filesystem identity, DPAPI, or Workstation host APIs on Windows. Gate those
Python cases on the operating system as well as PowerShell availability. The Windows Packer validation job runs the
native Workstation cleanup, hostname, Photon build, and credential fixtures with synthetic inputs.

For task-owned local validation, first create an empty root with the existing
[`PytestGitFixtures` owner](completed-task-cleanup.md#disposable-pytest-git-fixtures), preserving its original receipt
outside every removal root. Pass that root and its original native identity as `-FixtureRoot` and
`-OriginalFixtureIdentity`, together with `-FixtureOwnerReceipt`, `-FixturePythonPath` (Python 3.14), and
`-FixtureConfigPath` (the active supported Codex configuration). The regression immediately registers its synthetic
Git repository and receipts each internal redirect before use. Owned mode retains the graph instead of recursively
deleting it. After the test process is terminal, run `scripts.photon_build_state_test_fixtures seal` with the same
`--config` and `--receipt`: it retires only the four original redirect leaves, then seals the graph through its
existing Git owner. Preserve the manifest and digest for normal completed-task cleanup. A failed creation, changed
link, missing receipt or incomplete seal requires retention; never reconstruct ownership from the surviving tree.

When a Python test extracts a production PowerShell block, load its real helper dependencies and supply the valid
public inputs that the full script normally initializes. For example, the Windows ownership fixtures load
`Atlaso.WorkstationFirstBoot.ps1` and bind the VM name before running parent preflight and restored-root admission.
Run `python -m pytest tests/test_vmware_test_vm_ownership.py` on Windows to check those synthetic fixtures. Keep their
ownership, refusal, and publication assertions intact; setup must let each test reach the behavior it names.
