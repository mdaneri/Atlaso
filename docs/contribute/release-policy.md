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

The complete Python CI job has a two-hour deadline covering locked dependency setup, the full suite, and runner cleanup.
Local Python validation remains focused; the canonical CI check must complete successfully.

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
immutable-tag/Release, Pages serialization, and live-verification gates. Starting with `v0.9.506`, each software
release automatically stages its signed installation ISO and software bundle in one hidden GitHub Release draft.
The hosted acceptance job reconstructs the signed draft's exact ISO, installs it in a disconnected UEFI VM and
checks the installed version, source, services, media-free boot and unselected disk. The protected publisher admits
the receipt from that workflow attempt, revalidates the signed draft and publishes it as a GitHub prerelease before
advancing `development`. A separate maintainer dispatch requires exact-ISO representative physical acceptance to
promote to `stable` and mark the same GitHub release stable. See the
[ISO release procedure](../reference/installation-iso.md#stage-and-publish-a-standard-release). Manual
dispatch with the exact full SHA of a successful `main` push CI run remains available for idempotent recovery. After
the 90-day retention window, manually dispatch **Replay Python wheel** from `main` with the exact commit plus its
successful source CI run ID
and attempt. That admission workflow revalidates the evidence and current-`main` reachability without checking out or
executing the target, then emits only a one-day canonical replay request. Its completed `workflow_run` causes the
read-only **Publish Python wheel** workflow to revalidate the request and publish the replacement handoff. Replay does
not implicitly advance an older release; use the exact-SHA software-release dispatch for recovery. When a draft or
public release already exists, the workflow verifies and reuses its signed assets only after the replay wheel matches
the bundled wheel byte for byte, preserving the original signed provenance for channel recovery.

The protected appliance release workflow consumes an approved Photon snapshot from its private, digest-pinned
installation capture archive. The archive binds retained Photon 5.0 repository metadata, including the exact
`repomd.xml` and primary package metadata, to the original native capture receipt and complete RPM inventory. A
release job validates metadata and referenced package identities against captured bytes, verifies Photon signatures,
tests the full offline RPM transaction, and independently checks reviewed runtime inputs, PowerCLI content, the pinned
boot ISO, and output capacity. This snapshot boundary keeps routine changes to the live Photon updates
repository from invalidating staging or changing the package bytes selected for a release.

The capture compatibility fingerprint covers declarative installer requirements, including package selection, pinned
boot ISO identity, Photon signing keys, PowerCLI lock, guest-tools source, and reviewed runtime RPM identities. Changes
to unrelated provisioning code do not by themselves require a new RPM capture. All release-source and output checks
remain bound to the exact release commit. A snapshot remains valid for 30 days after its original capture. New Photon
publications prompt separate drift review and do not block otherwise compatible routine software releases. A changed
installer requirement, expired snapshot, or withdrawal for an applicable security advisory or signing-trust issue
blocks new staging until a fresh reviewed capture is admitted and both protected digest pins are rotated together.
Snapshot-aware production staging requires the new archive format. Earlier workflow revisions and the standalone
prerelease path retain live upstream-metadata admission.

Release notice generation identifies each wheel from its top-level `.dist-info/METADATA` file. Nested metadata for
vendored distributions, such as Packaging bundled inside setuptools, cannot establish the wheel's identity even when
the vendored version also appears in the release lock. Missing or ambiguous top-level locked metadata, missing locked
packages, and missing license or source information still stop publication.

### Version transition

The first new release in this lifecycle is `1.0.0`. Land the trusted version policy with the ordinary next patch,
then use `python scripts/version.py bump --version 1.0.0` in the next PR. The protected release workflow skips automatic
staging for the intermediate `0.9.x` patch. The existing signed `v0.9.516` draft is eligible for recovery at its original
commit and version. Subsequent PRs use the ordinary synchronized patch rule.

OVA and Hyper-V images use the separate manual lifecycle documented in the
[virtualization artifact guide](../reference/virtualization-artifacts.md). A maintainer workstation creates and
smokes `virtualization-vX.Y.Z-rc.N`; protected hosted jobs sign it, and the exact bytes may become
`virtualization-vX.Y.Z` only after isolated Proxmox and KVM smoke. Never attach virtualization assets to `vX.Y.Z`,
advance an appliance-update channel from a virtualization workflow, or give signing material or write-capable tokens
to a self-hosted runner.
