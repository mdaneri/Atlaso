---
title: Python static analysis
description: Run and extend Atlaso's enforced Ruff and scoped mypy baselines.
audience:
  - contributor
  - maintainer
status: current
---

# Python static analysis

Atlaso enforces a high-signal Python lint baseline across the application, scripts, and tests, plus a strict typed
ratchet for selected shared service modules. The baseline runs in the existing **Repository checks** status, so a new
violation blocks a pull request instead of creating a separate advisory result.

## Set up the analyzers

Use Python 3.14 and install the development dependencies and hash-locked analyzers from the repository root:

```powershell
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pip install --require-hashes -r requirements-static-analysis.lock
```

`requirements-static-analysis.in` pins Ruff and mypy exactly. Its generated lock constrains their transitive
dependencies and enforces the same seven-day package-age policy as every other Python lock. Analyzer dependency changes
must use the wrapper described in [Dependency management](dependency-management.md).

## Run the baseline

Run the same entry point used by pre-commit and CI:

```powershell
python scripts/check_python_static_analysis.py
```

For focused diagnostics, run the analyzers directly:

```powershell
python -m ruff check atlaso scripts tests
python -m mypy
```

Ruff checks pycodestyle syntax/error rules, Pyflakes, flake8-bugbear, blind exceptions, and import ordering. Generated
or vendored Python under `VCFDT`, `vcfDownloadTool`, and `third_party` is excluded. Ruff rule `B008` is excluded because
FastAPI dependency declarations intentionally call factories such as `Depends` and `Form` in function defaults.

Mypy runs in strict mode against the explicit `files` list in `pyproject.toml`. That list is the typed-analysis ratchet:
new shared mutation or service modules should be made strict-clean and added to the list; existing entries must not be
removed or weakened to accommodate unrelated debt. Imported type information remains available, but silent import
following prevents diagnostics from unlisted transitive modules from expanding the ratchet implicitly.

## Repository syntax and content checks

Run `python scripts/check_repo.py` for the repository's lightweight syntax and content checks. Default discovery
excludes the root `.atlaso-local/` task-state directory before descending into it, so downloaded vendor metadata and
deliberately malformed validation fixtures do not fail source validation. Existing vendor, environment, and build
directory exclusions are also pruned before traversal. Other checkable sources, including untracked files, remain
eligible; this is a fixed exclusion policy rather than a general Git-ignore filter and also works in source archives.

Explicit file or directory arguments retain their existing behavior. For example,
`python scripts/check_repo.py .atlaso-local/example/fixture.json` deliberately validates that fixture, and an explicit
`.atlaso-local/example` directory or `.` includes its checkable descendants. Existing exclusions such as
`node_modules` still apply. Keep repository source files outside the reserved root `.atlaso-local/` directory.

## Justify suppressions

Prefer correcting the code. When an analyzer cannot model an intentional boundary, keep the exception on the narrowest
line and include both the exact rule code and a reviewable rationale:

```python
handler.runtime_flag = True  # type: ignore[attr-defined]  # The adapter adds this runtime-only marker.
from local_tool import run  # noqa: E402 - the script adds its checked-in module path first.
```

Bare `# noqa`, code-free `# type: ignore`, and suppressions without a rationale fail
`scripts/check_python_static_analysis.py`. Do not add file-wide ignores or reduce the configured rule families to make
a change pass.
