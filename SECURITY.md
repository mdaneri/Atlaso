# Security Policy

## Supported versions

Security fixes are provided for the latest published Atlaso release and the current `main` branch while a fix is being
prepared.

## Atlaso data classification

Atlaso treats IP addresses, MAC addresses, hostnames, and account names as non-sensitive operational identifiers when
they appear by themselves.

Passwords, tokens, authenticated URLs, boot capabilities, session material, private keys, password hashes, credential
verifiers, and other
secret-bearing data are sensitive. Content-integrity hashes of non-secret material and one-way change-detection hashes
of encrypted-at-rest ciphertext are not sensitive by themselves. An operational identifier becomes sensitive when it
is embedded in or paired with authentication or cryptographic material.

This classification does not make authenticated or access-restricted data public, bypass authorization, or override an
operator's site or organization handling requirements. Review the complete context before sharing logs, audits,
screenshots, or diagnostics. When the context is uncertain, keep the material private and use the vulnerability
reporting process below.

## Reporting a vulnerability

Please do not report security vulnerabilities in public GitHub issues, discussions, pull requests, or chat channels.

Use the repository's **Security** tab and select **Report a vulnerability**, or open a
[private vulnerability report](https://github.com/mdaneri/Atlaso/security/advisories/new), to submit a private GitHub
Security Advisory. Include the affected version, reproduction steps, impact, and any proof of concept. We will
acknowledge a valid report within seven days and coordinate disclosure after a fix or mitigation is available.

Use ordinary bug reports only for non-sensitive defects.

## Privately fixing a validated vulnerability

Use a draft repository security advisory as the private tracking and discussion record for a validated sensitive
vulnerability. Do not create a public issue for the finding. GitHub requires the draft advisory before maintainers can
[start a temporary private fork][github-private-fork].

Create the fix branch from the project's current default branch, push it only to the temporary private fork, and open
the private pull request in that fork. Reference the advisory on private surfaces in place of the ordinary public issue
and `Closes #<issue>` relationship. GitHub treats temporary private forks as workspace repositories: ordinary Issues
cannot be enabled, and pull-request labels or comments may be unavailable or forbidden. Keep tracking and discussion in
the advisory when the workspace repository cannot host them.

GitHub integrations, including CI, cannot access temporary private forks, and status checks do not run. Complete every
validation required by the ordinary contribution workflow locally and record the results privately before review. An
otherwise mergeable private pull request may show `UNSTABLE` solely because checks are absent; that state does not
replace the required local evidence or maintainer review.

For this private workflow, advisory-side maintainer review and the recorded local validation replace every ordinary
integration-dependent follow-through requirement. Do not request or wait for Codex review, `@codex review` comments,
exact-head CI or status checks, or unavailable pull-request labels, comments, and review threads. Use the advisory and
any available private pull-request surfaces for review and discussion, and do not claim that unavailable integrations
ran.

When the change affects Python or the ordinary workflow otherwise requires it, run the complete Python test suite locally
and record the result privately. This is the security-specific exception to the ordinary automated-contributor rule that
reserves the complete suite for GitHub CI. If the complete required suite cannot run locally, the private patch is not
ready for advisory merge; obtain maintainer direction instead of waiving or claiming the missing evidence.

Temporary-fork pull requests are merged together only through the corresponding advisory workflow; they are not merged
individually. Do not use the ordinary pull-request merge button or `gh pr merge`. An advisory administrator must open
the parent repository's **Security > Advisories** page, select the draft advisory, scroll to **This advisory is ready to
be merged**, and choose **Merge pull request(s)**. GitHub merges every open pull request in that advisory's temporary
private fork together, and only one pull request may target `main`.

An advisory merge applies the patch to the public repository's `main` branch even while the advisory remains a draft.
Publishing the advisory is a separate explicit action. Merge only when the coordinated release and disclosure are
authorized. Do not publish, close, merge, or otherwise change advisory state. Explicit maintainer authorization is
required for any of those actions. GitHub does not enforce the target branch's protection rules in this workflow, so
maintainer review and the recorded local validation are mandatory before an authorized advisory merge.

The human-maintainer break-glass authority cannot be delegated to automation and does not replace or broaden this
private workflow. Automated contributors, coding agents, delegated agents, workflows, and other automation must never
use or request a ruleset or administrative bypass. Advisory state changes and advisory merges remain subject to the
explicit private authorization, review, and validation requirements above.

When one patch resolves multiple private findings, keep every cross-reference on private surfaces and choose one
advisory's temporary private fork as the patch workspace. After coordinated disclosure, create sanitized public
tracking or release documentation only when a maintainer explicitly approves it.

[github-private-fork]: https://docs.github.com/en/code-security/tutorials/fix-reported-vulnerabilities/collaborate-in-a-fork
