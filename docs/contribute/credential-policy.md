---
title: Agent credential policy
description: Conditional secret custody and worktree credential reuse requirements.
audience:
  - contributor
  - maintainer
status: current
---

# Agent credential policy

Read before obtaining, storing, copying, or using credentials. The
[security policy](https://github.com/mdaneri/Atlaso/blob/main/SECURITY.md) owns classification and private reporting.

Use the installed 1Password plugin and the exact `Atlaso` Environment for every user password and every newly created
user or key secret, including passwords, tokens, API keys, and private keys. Authenticate through the plugin, verify
the named Environment, and store secrets as concealed variables. If either is unavailable, stop for maintainer direction.
Never fall back to chat, plaintext repository files, local `.env`, shell arguments, logs, screenshots, or documentation.

For supported Windows subprocess use, bind the exact Environment by its opaque ID through the supported 1Password SDK
inside a bounded child; never return plaintext to agent-visible output. Service-account tokens may be stored only as
current-user DPAPI ciphertext in the Git-ignored checkout-local path, with current-user-and-SYSTEM access, and decrypted
only inside a bounded child. Preserve timeout, whole-tree termination, sensitive staging cleanup, and recovery gates.
`DEFAULT_ROOT_PASSWORD` and `DEFAULT_ADMIN_PASSWORD` supply their corresponding deployment identities only through
that supported path. Explicit supported authentication selections remain authoritative.

Before same-host, same-user worktree reuse, read and follow the full
[credential reuse procedure](../reference/vmware-workstation-lifecycle-testing.md#reuse-primary-checkout-configuration-in-a-task-worktree).
Discover the primary checkout from Git's common directory and worktree inventory. Copy only missing validated selector
and DPAPI-token files without replacement, retaining ciphertext, ownership/ACL, ordinary-single-link identity,
containment, and non-reparse-point checks. Never copy the remaining `.atlaso-local` tree or repair conflicting existing
configuration automatically. Validate through the existing bounded credential helpers before use.

An ordinary task without credential operations need not prepare credential copies. Deployment, image building,
signing, and VM use additionally load their exact lifecycle procedures before any credential-consuming mutation.
