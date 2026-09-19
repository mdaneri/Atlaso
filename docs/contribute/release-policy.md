---
title: Release and publication policy
description: Conditional trusted CI, Pages, signing, and publication requirements.
audience:
  - contributor
  - maintainer
status: current
---

# Release and publication policy

Read before changing release, trusted CI, signing, promotion, or Pages workflows, or performing publication.

Trusted version refresh dispatches CI from protected `main` with the exact PR number, base SHA, and head SHA. Candidate
validation jobs remain read-only. Only separate no-checkout jobs may publish the canonical `Version policy`, `Repository
checks`, and `Python tests` commit statuses after revalidating the open same-repository PR and exact head/base. Preserve
the bot-only publication gate, visible run links, diagnostic names for bot-triggered `pull_request` jobs, and the active
ruleset contexts. Keep trusted dispatch and diagnostic pull-request runs in separate concurrency groups so diagnostic
work cannot cancel the trusted publisher. Never dispatch a candidate workflow revision with status-write permission.

Every workflow job that mutates `gh-pages` must use the shared `atlaso-github-pages` concurrency group with `queue: max`
and `cancel-in-progress: false`. Keep long prerequisite builds outside that job-level lock; acquire it before reading the
current Pages branch and retain it through the guarded publication push. Do not weaken existing signature, immutable
tag/release, monotonic-channel, or byte-idempotency checks when narrowing the lock scope.
Every Pages writer must also fail closed unless the shipped default `stable` manifest and signature exist in its final
tree. Appliance release and promotion workflows must re-fetch the published signed pointer and immutable release
manifest, verify the named trust key, and confirm CPython 3.14 compatibility after publication.

The trusted version workflow may update an internal pull request with `GITHUB_TOKEN`. GitHub can place the duplicate
`pull_request` workflow run created by that update behind an approval gate, so those diagnostic jobs use non-required
names. Automated branch updates request version refresh through a typed repository dispatch, which always uses the
workflow revision on protected `main`; there is no privileged manual-dispatch entry point.

The protected workflow then dispatches CI from `main` with the exact pull-request number, base SHA, and head SHA. Its
candidate validation jobs retain read-only permissions. Separate jobs that never check out candidate code revalidate
the open same-repository pull request and publish pending, success, failure, or error commit statuses named `Version
policy`, `Repository checks`, and `Python tests`, each linked to the trusted run. Those visible statuses are the
canonical contexts required by the `main` ruleset; a manual CI dispatch cannot publish them. Trusted dispatches and
diagnostic pull-request runs use separate concurrency groups, so a delayed diagnostic run cannot cancel trusted status
publication.

GitHub Pages writers serialize only their final mutation jobs through the shared `atlaso-github-pages` group. The group
uses `queue: max` with `cancel-in-progress: false`, preserving multiple pending documentation, appliance release,
Inventory Linux release, and promotion writers while keeping long prerequisite builds outside the Pages lock.

## Release lifecycle contributions

Every successful same-repository `main` push CI run automatically starts **Publish Python wheel**. That separate
GitHub-hosted workflow has read-only repository permissions and publishes only the immutable Actions artifact
`atlaso-wheel-vX.Y.Z-<full-sha>` for 90 days. The artifact contains exactly one versioned Atlaso wheel and a canonical
identity document binding its source CI run ID and attempt, publisher run ID and attempt, version, commit, size, and
SHA-256 digest. Downstream consumption revalidates those exact attempts. It has no signing
material, GitHub Release/tag or Pages write authority, protected environment, self-hosted runner, or virtualization
access. Repeated artifacts for one version/commit must contain identical wheel bytes or the software consumer fails.
When identical retries coexist, the consumer stages each publisher-run artifact separately, validates its recorded
attempt, and preserves the earliest retained publisher run-and-attempt identity so an automatic retry cannot change the
inputs of an already published signed bundle.

Each successful automatic-main wheel handoff starts the separately protected **Publish appliance release** workflow.
The workflow requires the retained matching artifact, validates its GitHub run identities and
embedded build metadata, fails closed on collisions, and records that identity inside the signed appliance bundle. It
does not rebuild or substitute the application wheel. It retains the exact CPython 3.14 wheelhouse, signing,
immutable-tag/Release, Pages serialization, automatic `development` advancement, and live-verification gates. Manual
dispatch with the exact full SHA of a successful `main` push CI run remains available for idempotent recovery. After
the 90-day retention window, manually dispatch **Replay Python wheel** from `main` with the exact commit plus its
successful source CI run ID
and attempt. That admission workflow revalidates the evidence and current-`main` reachability without checking out or
executing the target, then emits only a one-day canonical replay request. Its completed `workflow_run` causes the
read-only **Publish Python wheel** workflow to revalidate the request and publish the replacement handoff. Replay does
not implicitly advance an older release; use the exact-SHA software-release dispatch for recovery. If the immutable
software Release already exists, that workflow verifies and reuses its signed
assets only after the replay wheel matches the bundled wheel byte for byte, preserving the original signed provenance
for channel recovery. Never rebuild or rename a wheel locally.

OVA and Hyper-V images use the separate manual lifecycle documented in the
[virtualization artifact guide](../reference/virtualization-artifacts.md). A maintainer workstation creates and
smokes `virtualization-vX.Y.Z-rc.N`; protected hosted jobs sign it, and the exact bytes may become
`virtualization-vX.Y.Z` only after isolated Proxmox and KVM smoke. Never attach virtualization assets to `vX.Y.Z`,
advance an appliance-update channel from a virtualization workflow, or give signing material or write-capable tokens
to a self-hosted runner.
