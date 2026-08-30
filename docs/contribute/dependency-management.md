---
title: Dependency management
description: Regenerate Atlaso Python locks while enforcing package maturity, integrity, and appliance compatibility.
audience:
  - contributor
  - maintainer
status: current
---

# Dependency management

Atlaso accepts a Python distribution into a generated lock only after it has been published for at least seven full
days. The rule applies to direct dependencies, transitive dependencies, bootstrap tools, documentation tools, release
tools, and security updates. It reduces the chance that an approved package mirror is missing a newly published
artifact and gives maintainers time to observe upstream regressions or compromised releases.

Dependabot applies the same seven-day cooldown to pip version updates. The resolver cutoff remains authoritative because
Dependabot cooldowns do not cover every transitive selection and do not delay security-update pull requests.

## Regenerate locks

Use Python 3.14 with pip 26.0 or newer and pip-tools 7.6.0. From the repository root, run:

```powershell
python scripts/compile_requirements.py
```

The wrapper regenerates:

- `requirements-appliance-bootstrap.lock`;
- `requirements-appliance.lock`;
- `requirements-docs.lock`;
- `requirements-static-analysis.lock`;
- `requirements-release-tools.lock`;
- `requirements-onepassword-deploy.lock`; and
- `requirements-virtualization-smoke.lock`.

Every resolver invocation includes `--uploaded-prior-to=P7D` and `--generate-hashes`. Locks that need pip's unsafe
bootstrap tools retain `--allow-unsafe`, and the wrapper refreshes the declaration fingerprint embedded in
`requirements-appliance.lock`. Pass `--upgrade` only when the intended change should move every eligible package to the
newest version that satisfies the seven-day cutoff.

The wrapper resolves against the PEP 691/700 JSON API at `https://pypi.org/simple` by default and verifies that the
index returns upload times before compiling. It ignores pip configuration and environment variables that could add an
unverified index or find-links source. An approved alternative can be supplied with `--index-url`, but it must use HTTPS,
must not embed credentials, and must provide complete upload-time metadata or compilation stops before any lock changes.

Do not edit generated pins, hashes, generation-command headers, or the appliance fingerprint manually. Do not remove or
shorten the upload-time cutoff to obtain a newer dependency, including for a security update. If no eligible version
satisfies the input declarations, change the input constraint through a reviewed dependency update or wait until the
required release reaches seven full days.

Protected appliance, promotion, Inventory Linux, and virtualization publication jobs intentionally run without a
writable Actions cache scope. Their `actions/setup-python` steps therefore do not enable the built-in pip cache, because
that option always registers a post-job cache save. This cache-free setup does not relax dependency integrity: every
release-tool and appliance dependency installation continues to consume the checked-in hash-locked requirements files.
Ordinary CI jobs may continue to use dependency caching under their separate execution permissions.

## Validate the result

Run:

```powershell
python scripts/check_dependency_policy.py
python scripts/check_appliance_lock.py
python scripts/check_photon_compatibility.py
python scripts/check_repo.py
git diff --check
```

`check_dependency_policy.py` verifies the Dependabot cooldown, Python 3.14 lock headers, seven-day resolver cutoff,
expected input manifests, exact pins, and SHA-256 hashes across all generated locks. It also rejects workflow
`--requirement` or `-r` paths that do not resolve to a tracked lock in both the generation and minimum-age policy
inventories. That workflow check follows ordered checkout destinations, each job's active workspace-root checkout, and
step or job-default working directories, rejecting external repositories and untrusted Atlaso revisions instead of
validating a same-named lock from the review checkout. Dynamic or escaping working directories fail closed.
The small allowlist of dynamic root revisions is limited to the canonical workflows whose admission jobs already prove
the supplied commit is the successful `main` release target. The appliance check separately verifies direct dependency
coverage, bootstrap equality, and the
declaration fingerprint.
