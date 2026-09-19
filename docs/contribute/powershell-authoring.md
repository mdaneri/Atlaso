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
