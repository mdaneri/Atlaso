# Atlaso Agent Notes

## Mandatory Agent Startup Gate

Read this file and [CONTRIBUTING.md](CONTRIBUTING.md) before planning or mutation.
Load each applicable route below before planning or performing its operation; other links are conditional.

First progress update: confirm policies read, classify work as `bug`, `enhancement`, `documentation`, or security-sensitive,
and link the issue. Private remediation: confirm private tracking without advisory identifiers or findings.
Read-only discovery may precede this update.

Record repository, worktree, policy revision, and loaded routes. Re-evaluate routes on repository, worktree, directory,
policy, or scope changes; read changed or newly applicable instructions. Reuse unchanged policy already read in this task.
If policy is missing, conflicting, or unclear, stop the affected operation for maintainer direction.

## Always applicable boundaries

- Scope changes to the linked task; preserve unrelated work. Never commit directly to `main`.
- Implementation requires a dedicated clean task worktree and task-owned branch beneath the exact supported Codex
  `git-worktree-root`. Resolve it independently; never guess or implement in the primary checkout. Keep task-owned
  temporary files, caches, builds, logs, and evidence beneath that root or another explicit maintainer-configured
  permitted root. Preserve out-of-root or ambiguous state and stop before mutation.
- Before worktree or disposable validation-root creation, load cleanup's ownership section. Record original identities
  and task/repository/source bindings durably outside removal roots before use; verify containment and supported cleanup.
  Missing creation provenance blocks implementation/validation: report the prerequisite, never retrofit later snapshots.
- Protect secrets: never expose credentials, authenticated URLs, private keys, or secret-bearing data in tool output,
  logs, ordinary files, screenshots, or public reports. Before credential operations load the credentials route;
  suspected sensitive vulnerabilities require the security route before any public issue or finding.
- Run focused local tests and applicable repository/documentation/static checks. Canonical CI owns ordinary full
  Python-suite coverage; private remediation defines its own local-validation exception.
- Enforce [appliance time-source safety](docs/services/ntp.md).
- Follow CONTRIBUTING for issue/type, documentation, synchronized next patch, and ready-PR requirements. Read the PR
  workflow before delivery, including default merge authority and explicit holds. Automation must never use or request
  a ruleset or administrative bypass. Auto-merge requires explicit selection.
- Before destructive actions, signing/publication, or external infrastructure mutation, load the exact procedure and
  prove authority and ownership. Preserve its fail-closed gates. Policy grants no authority; unavailable
  capabilities never justify substitutes.
- Certificate handoff needs proven address control before mutation; see the
  [VMware procedure](docs/reference/vmware-workstation-lifecycle-testing.md).

## Conditional policy routes

Select routes by operation AND affected behavior, not filenames alone; load all affected routes and relevant subsystem
sections. Resolve unknown applicability before mutation rather than treating it as an exemption.

| Route | Trigger before planning or action | Canonical source |
| --- | --- | --- |
| implementation | Implementation preparation, worktree selection, titles, delegation, unrelated discoveries | [Agent workflow](docs/contribute/agent-workflow.md) |
| review | Reviewing a diff/PR, opening, following, or merging a PR | [PR workflow](docs/contribute/pr-workflow.md) |
| security | Sensitive material, suspected vulnerability, private remediation | [Security policy](SECURITY.md) |
| credentials | Obtaining, storing, copying, or using passwords, tokens, keys, or 1Password configuration | [Credential policy](docs/contribute/credential-policy.md) |
| ui | Templates, authored CSS/JS, controls, layouts, grids, dialogs, wizards, visible UI copy | [UI guide](docs/contribute/ui-design-guide.md) |
| api | API operations, route ownership, compatibility | [API authoring](docs/contribute/api-authoring.md), [router architecture](docs/contribute/router-architecture.md) |
| python | Python source or tests | [Static analysis](docs/contribute/python-static-analysis.md) |
| powershell | PowerShell source or modules | [PowerShell authoring](docs/contribute/powershell-authoring.md) |
| documentation | Docs, screenshots, media, branding | [Documentation authoring](docs/contribute/documentation-authoring.md) |
| dependencies | Dependency updates or generated locks, including Dependabot | [Dependency management](docs/contribute/dependency-management.md) |
| release | Changes to release/version tooling, trusted CI, signing, publication, promotion, GitHub Pages; routine synchronized version bumps follow CONTRIBUTING only | [Release policy](docs/contribute/release-policy.md) |
| subsystem | Appliance, networking, services, authentication, storage, host-mutation behavior | [Subsystem sections](docs/contribute/agent-policies.md) |
| infrastructure | Image builds, builder reservations, VMware validation, deployment, infrastructure mutation | [VMs / `-CleanupOnly`](docs/reference/vmware-workstation-lifecycle-testing.md), [subsystem contracts](docs/contribute/agent-policies.md) |
| cleanup | Creating task worktrees or disposable validation resources (ownership section), resource release, destructive cleanup, completed-task handoff | [Cleanup policy](docs/contribute/completed-task-cleanup.md) |
| community | Community participation | [Code of conduct](CODE_OF_CONDUCT.md) |

[Routing](docs/operate/networking.md); [DHCP](docs/services/dhcp.md): native limits/report-only checks.

[Reverse proxies](docs/services/reverse-proxies.md): Apply, ownership, trust, native acceptance.

For tty1, load subsystem applied-address observation and atomic Settings capture.

## Review and delegation

For every PR review, including file assignments, load the review route. Complete analysis and verification
before one consolidated review. Never repeatedly review an unchanged head without
material new evidence; relevant commits still require re-review under that contract.

A delegating agent lists startup gate, exact worktree/state roots, owned files, routes, result, and focused checks;
verify compliance and diff before use.
Delegation never expands permissions. The implementation route owns the Luna contract and unavailable-worker fallback.

UI work requires the **Mandatory UI Design Guide Gate**: classify the interaction, name the reused Atlaso reference,
and obtain explicit maintainer approval for `custom/other` before implementation.

[Logs](docs/operate/logs.md#important-event-coverage); [progressive policy](docs/contribute/progressive-policy.md).

See [VCF SSH/su](docs/services/vcf-helper.md) and [KMIP trust](docs/services/vsphere-key-providers.md).
[VCF import coverage/URI rotation](docs/services/vaults.md#vcf-helper-import).
