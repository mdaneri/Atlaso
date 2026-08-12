---
title: Appliance UI compliance matrix
description: Record the reviewed interaction, fallback, permission, responsive, and accessibility contract for every Atlaso HTML surface.
audience:
  - contributor
  - maintainer
status: current
---

# Appliance UI compliance matrix

This is the durable completion record for the browser-wide compliance program in
[GitHub issue #115](https://github.com/mdaneri/Atlaso/issues/115). It inventories every route that deliberately renders
HTML from `atlaso/app/ui.py` or `atlaso/app/web_terminal.py`, plus the shared shells, dialogs, and responsive variants
used by those routes. API, download, redirect-only, and static-asset routes are outside this matrix because they do not
render an Atlaso browser surface.

Issue #287 introduced an explicitly maintainer-approved `custom/other` information-architecture change while preserving
the established dashboard, chart, terminal, login, and public-directory interactions. Management surfaces now belong to
`/ui/management`; app-owned public surfaces belong to `/ui/public`; `/` is only the interface-aware dispatcher.

## Canonical browser-route inventory

The route-inventory test fails when an app-owned human route is added outside its declared plane or when a protocol
exemption changes without review. The management routes rendered by the current templates are:

```text
/ui/management
/ui/management/appliance-update
/ui/management/audit-log
/ui/management/authentication
/ui/management/automation
/ui/management/backup-restore
/ui/management/ca/requests
/ui/management/certificate-authority
/ui/management/dashboard
/ui/management/dhcp
/ui/management/dns
/ui/management/esx-storage
/ui/management/firewall
/ui/management/vsphere-key-providers
/ui/management/ldap
/ui/management/login
/ui/management/logs
/ui/management/monitor
/ui/management/network-boot
/ui/management/ntp
/ui/management/openid-connect
/ui/management/physical-interfaces
/ui/management/routes-wan
/ui/management/services
/ui/management/services/{service}/logs
/ui/management/settings
/ui/management/tasks
/ui/management/terminal
/ui/management/terminal/remote
/ui/management/users
/ui/management/vaults
/ui/management/vcf-backups
/ui/management/vcf-helper
/ui/management/vcf-offline-depot
/ui/management/vcf-offline-depot/tasks/{job_id}/log
/ui/management/vcf-private-registry
/ui/management/vcf-trust
/ui/management/vlan-interfaces
/ui/management/{page}
```

The public routes rendered through `public_portal_base.html` are:

```text
/ui/public
/ui/public/ca
/ui/public/ca/login
/ui/public/ca/requests
/ui/public/login
/ui/public/terminal
```

For compactness, the detailed rows below retain their recognizable child slugs. Management child slugs are relative to
`/ui/management`, public child slugs are relative to `/ui/public`, and `/PROD/` remains an explicitly exempt protocol
and browser contract at its existing root path. Retired root-level browser paths are temporary compatibility entries,
not canonical route owners.

## Result and evidence key

Each result records desktop (**D**, 1600×1000), narrow (**N**, 900×1200), keyboard-only operation (**K**), launcher
focus restoration (**F**), browser zoom through 200% (**Z**), and validation failure/recovery (**V**). `N/A` means the
surface has no editor or validation step. A **Pass** result means the applicable checks passed; it does not claim that a
read-only or unavailable surface has a mutation workflow.

- **E1 — inventory:** `tests/test_ui_compliance.py` extracts every HTML route, page template, and dialog identifier and
  requires this document to retain it.
- **E2 — foundations:** shared-grid/wizard tests and `scripts/check_repo.py` enforce `createGrid(...)`,
  `createWizard(...)`, keyboard row actions, server fallbacks, and the raw-Tabulator boundary.
- **E3 — server behavior:** focused route tests cover authentication, roles, CSRF, validation recovery, destructive
  endpoints, desired state, and the global appliance-apply boundary.
- **E4 — rendered fallback:** the page response or a paired `*-fallback` element keeps initial data and empty/error
  language readable without JavaScript. Dynamic task progress that can exist only after a scripted submission is marked
  N/A.
- **E5 — responsive evidence:** the checked-in screenshot manifest and generated interface gallery cover the canonical
  management and public surfaces at desktop and narrow sizes. #120 changed no visual layout, so no screenshot became
  inaccurate.
- **E6 — dialog audit:** every shared wizard has an accessible name and live step description; the shared confirmation
  and About dialogs restore launcher focus, and wizard validation retains data and focuses the invalid control.
- **E7 — deployed audit:** the #120 pull request records the exact-head VMware version and host-facing `/openapi.json`
  proof, plus page-by-page overflow, keyboard, zoom, JavaScript-disabled, permission, and representative recovery checks.
- **E8 — repository gates:** JavaScript, full pytest, compileall, repository, Photon, docs, Markdown, strict site,
  version-policy, and whitespace checks run on the final pull-request head.

## Management and operations routes

| Route and surface | Approved interaction and shared foundation | Server-rendered or no-JavaScript behavior | Permission, confirmation, and apply boundary | Result | Evidence |
| --- | --- | --- | --- | --- | --- |
| `/dashboard` — operations command center | Established read-only Dashboard; Tasks/Audit navigation and shared application shell | Initial dashboard snapshot, setup state, attention items, recent activity, and stale/error language are rendered in HTML | Authenticated read; links enter existing permission-checked workflows; no dashboard mutation or service-specific apply | Pass D/N/K/F/Z; V N/A | E1–E5, E7–E8 |
| `/monitor` — health metrics, charts, interfaces, and devices | Established Monitor charts plus read-only Tabulator using the Tasks reference | Initial metrics and truthful interface/device fallback tables; charts degrade to readable metrics and status | Authenticated read-only; no destructive action or apply boundary | Pass D/N/K/F/Z; V N/A | E1–E8 |
| `/appliance-update` — streams, repositories, modules, tasks | Wizard-backed Tabulator plus non-grid settings; ESX Storage, Automation, and DNS references | Repository/module details, validation, source data, and shared Tasks fallback remain readable | Admin write controls; shared confirmation for deletion; maintenance task boundary remains separate from global apply | Pass D/N/K/F/Z/V | E1–E8 |
| `/automation` — schedules, executions, managed scripts | Wizard-backed and read-only Tabulator; Automation Schedules reference | Truthful schedules, executions, and managed-scripts fallback tables added by #120 | Admin writes, shared discard/destructive confirmation, durable worker/task boundary; no direct host mutation | Pass D/N/K/F/Z/V | E1–E8 |
| `/routes-wan` — static routes, routing permissions, NAT, policies | Wizard-backed Tabulator; ESX Storage reference | Four paired fallback tables and rendered validation/config preview | Role-gated reviewed add/edit, direct Enabled state, shared confirmations; generated permissions read-only; enforcement only through global `wan` apply | Pass D/N/K/F/Z/V | E1–E8 |
| `/firewall` — operator and managed rules, source groups | Wizard-backed and direct-edit Tabulator plus non-grid settings; DNS/ESX Storage references | Rule and managed-rule fallbacks, source-group settings, validation, and preview | Role-gated edits; shared remove confirmation; global `firewall` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/physical-interfaces` — observed and desired interfaces | Direct-edit Tabulator; Physical Interfaces reference | Paired interface fallback with observed and desired values, including access management UI exposure | Role-gated desired-state edits; management-path lockout validation; confirmation for guarded state changes; global `network` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/vlan-interfaces` — VLAN desired state | Wizard-backed Tabulator using `vlan-interface-dialog`; ESX Storage reference; approved wizard-only persisted-state exception | Paired VLAN fallback, access management UI exposure, and validation rail | Role-gated reviewed desired-state edits; management-path and dependent-state validation; confirmed deletion; global `network` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/dns` — service settings, zones, records, previews | Direct-edit Tabulator and non-grid settings; DNS reference | Zone/record fallbacks and reviewed reverse-zone semantic summaries; settings and validation render in HTML | Role-gated autosave, CSRF, explicit fallback labels, shared delete confirmation; global `dnsmasq` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/dhcp` — settings, IP zones, options, reservations, leases | Wizard-backed, direct-edit, and read-only Tabulator; DNS/ESX Storage references | Four paired fallbacks plus reviewed generated PXE option summary | Role-gated desired-state writes, shared confirmations, validation recovery; global `dnsmasq` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/certificate-authority` — CA settings, profiles, certificates | Wizard-backed Tabulator and non-grid settings; ESX Storage/DNS references | Certificate/profile fallbacks, settings, validation, and redacted preview | Role-gated writes, CSRF, shared revoke/delete confirmation; global `ca` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/ldap` — organizations, users, groups, VCF setup | Wizard-backed and direct-edit Tabulator plus non-grid settings; DNS zones and ESX Storage references | Organization/settings content and paired user/group fallbacks | Admin writes, secret-safe one-time dialogs, confirmation and recovery; global `ldap` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/ui/management/vsphere-key-providers` — providers, trusted vCenters, certificates, health | Wizard-backed and read-only Tabulator plus non-grid settings; ESX Storage/Tasks/Audit Events/DNS references | Four tool fallbacks, validation, nullable lifecycle counts, and redacted preview | Admin writes; shared destructive confirmation; public-certificate-only trust, exact fingerprint mapping, and global `kms` apply boundaries preserved | Pass D/N/K/F/Z/V | E1–E8 |
| `/ntp` — settings, upstreams, source health | Wizard-backed Tabulator and non-grid settings; ESX Storage/DNS references | Upstream fallback, settings, validation, and config preview | Role-gated desired-state writes; NTS remains disabled; global `ntpd` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/vcf-helper` — FQDN and remote VCF workflows | Established VCF Helper workflows and shared wizards; VCF credential-wizard reference | Server-rendered forms, reviewed FQDN semantic summary, and recoverable errors | Admin permission, TLS fingerprint before credentials, shared confirmation; DNS edits remain global-apply desired state | Pass D/N/K/F/Z/V | E1–E8 |
| `/vcf-trust` — certificate-trust handoff | Shared VCF credential wizard on the VCF Helper surface | Server-rendered VCF Helper state and recoverable validation errors | Admin, request-local credentials, explicit TLS confirmation, auditable task boundary | Pass D/N/K/F/Z/V | E1–E8 |
| `/vcf-offline-depot` — settings, VCFDT, profiles, tasks | Wizard-backed Tabulator and non-grid settings; ESX Storage/DNS references | Profile fallback, settings summaries, validation, Tasks fallback, and task status | Admin writes; reset confirmation; credential/identity rules and global-apply/task boundaries preserved | Pass D/N/K/F/Z/V | E1–E8 |
| `/vcf-offline-depot/tasks/{job_id}/log` — task log | Established read-only task/log detail | Bounded, redacted log and error state render in HTML | Authenticated read; no mutation | Pass D/N/K/F/Z; V N/A | E1, E3–E5, E7–E8 |
| `/vcf-private-registry` — settings and bundles | Wizard-backed Tabulator and non-grid settings; ESX Storage/DNS references | Bundle fallback, settings, validation, and redacted previews | Admin desired-state writes; shared deletion confirmation; global registry apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/vcf-backups` — SFTP settings and validation | Non-grid settings; DNS reference | Complete settings, validation, and redacted config preview render in HTML | Admin autosave with CSRF; selected-user dependency; global `vcf_backups` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/esx-storage` — volumes and NFS datastores | Wizard-backed Tabulator; ESX Storage reference | Paired volume/share fallback tables and rendered validation/instructions | Admin writes; format authorization and removal confirmation; global `esx_storage` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/authentication` — provider, clients, keys, mappings, tokens | Wizard-backed, direct-edit, and read-only Tabulator; ESX Storage/Physical Interfaces/Tasks references | Five paired fallbacks and complete provider settings | Admin writes, CSRF, one-time secret display, shared delete confirmation; no host apply side effect | Pass D/N/K/F/Z/V | E1–E8 |
| `/openid-connect` — canonical OIDC entry | Same authenticated surface and contract as `/authentication` | Same server response and paired fallbacks | Same role, secret, validation, and confirmation boundaries | Pass D/N/K/F/Z/V | E1–E8 |
| `/users` — local users and password policy | Wizard-backed Tabulator and non-grid settings; ESX Storage/DNS references | User fallback, policy settings, and password-not-staged states | Admin writes; password values never render; confirmation and global `local_users` apply preserved | Pass D/N/K/F/Z/V | E1–E8 |
| `/services` — service state | Direct-edit Tabulator; Physical Interfaces reference | Paired service fallback and truthful unavailable states | Permission-gated desired-state enablement; enforcement remains global apply | Pass D/N/K/F/Z/V | E1–E8 |
| `/services/{service}/logs` — legacy service-log entry | Redirected/normalized Services or Logs surface using their existing read-only contracts | Server-rendered target surface or explicit unavailable response | Authenticated read; helper allowlist remains server-owned | Pass D/N/K/F/Z; V N/A | E1, E3–E5, E7–E8 |
| `/logs` — fixed log sources | Established read-only Logs tabs | Initial bounded, redacted log text and unavailable source states | Authenticated read; helper allowlist and redaction enforced server-side | Pass D/N/K/F/Z; V N/A | E1, E3–E5, E7–E8 |
| `/tasks` — task collection and details | Read-only Tabulator; Tasks reference | Paired task fallback with server filtering/pagination; detail/log dialogs are enhancements | Authenticated read; cancellation remains permission/CSRF checked and confirmed where destructive | Pass D/N/K/F/Z/V | E1–E8 |
| `/audit-log` — audit events | Read-only Tabulator; Audit Events reference | Paired audit fallback remains visible until grid readiness or on error | Admin read; no mutation | Pass D/N/K/F/Z; V N/A | E1–E8 |
| `/network-boot` — environments, discovered hosts, ESXi references, media | Direct-edit, wizard-backed, and read-only Tabulator; Network Boot/ESX Storage references | Paired fallbacks for every collection plus semantic inventory reports and no-script editors | Permission-gated actions, CSRF, confirmations, audited immediate actions; global `esxi_pxe` apply boundary preserved | Pass D/N/K/F/Z/V | E1–E8 |
| `/backup-restore` — archives, restore, factory reset | Established non-grid settings/task workflow; DNS/shared confirmation references | Forms, status, and reviewed archive-scope semantic summary render in HTML | Admin, CSRF, passphrase handling, and destructive confirmation; task/global-apply boundaries preserved | Pass D/N/K/F/Z/V | E1–E8 |
| `/settings` — appliance settings | Non-grid settings; DNS reference | Complete settings, validation, and config preview render in HTML | Admin autosave/CSRF; guarded changes and global `appliance_settings` apply only | Pass D/N/K/F/Z/V | E1–E8 |
| `/vaults` — password vaults and entries | Wizard-backed Tabulator; ESX Storage reference | Paired entry fallbacks and empty states; secrets remain masked/not emitted | Admin, CSRF, audited bounded reveal, shared confirmations; no host apply | Pass D/N/K/F/Z/V | E1–E8 |
| `/terminal` — management or public terminal and unavailable state | Established terminal surface and shared management/public shell | Authenticated unavailable-state page renders when disabled; protocol data is not substituted for browser navigation | Explicit local-user Web SSH authorization, HTTPS/applied-state checks, no credential in browser state | Pass D/N/K/F/Z/V | E1, E3–E8 |
| `/terminal/remote` — vault-backed remote launch | Established remote-terminal workflow and fingerprint confirmation | Server-rendered target/credential selector and recoverable unavailable/error state | Admin, exact host-key confirmation, one-use launch, no password/authenticated URI exposure | Pass D/N/K/F/Z/V | E1, E3–E8 |
| `/{page}` — known unavailable/placeholder pages | Established authenticated unavailable-state shell | Title and unavailable copy render entirely in HTML | Authentication required; no mutation | Pass D/N/K/F/Z; V N/A | E1, E3–E5, E7–E8 |

## Public, login, and interface-scoped routes

| Route and surface | Approved interaction and shared foundation | Server-rendered or no-JavaScript behavior | Permission, confirmation, and interface boundary | Result | Evidence |
| --- | --- | --- | --- | --- | --- |
| `/` — management redirect or public service directory | Established management/public front door and public shell | Public cards, empty-directory state, and footer render in HTML; management listeners redirect through normal login/dashboard flow | Binding and service visibility are server-owned; no public mutation | Pass D/N/K/F/Z; V N/A | E1, E3–E5, E7–E8 |
| `/login` — management login and invalid-credential recovery | Established management login shell | Form, CSRF value, return path, and invalid-credential error render in HTML | Unauthenticated entry; safe return path and server authentication | Pass D/N/K/F/Z/V | E1, E3–E5, E7–E8 |
| `/ca` — public CA trust portal | Established public CA portal and public shell | Trust material, fingerprints, downloads, empty/disabled state, and footer render in HTML | Interface-scoped unauthenticated read; no custody/private-key exposure | Pass D/N/K/F/Z; V N/A | E1, E3–E8 |
| `/ca/login` — public certificate-request login | Established public login shell | Form and invalid-credential recovery render in HTML | Interface-scoped authentication, CSRF, safe return target | Pass D/N/K/F/Z/V | E1, E3–E5, E7–E8 |
| `/ca/requests` — management request list | Read-only Tabulator; Tasks reference | Paired request fallback with safe columns and revoke form | Authenticated permission/CSRF; shared revoke confirmation; global CA apply boundary | Pass D/N/K/F/Z/V | E1–E8 |
| `/requests` — public request list and submission | Read-only Tabulator plus non-grid request form; Tasks/DNS references | Paired request fallback and complete submission form remain usable/readable | Interface-scoped authentication, authorization, CSRF, revoke confirmation, validation recovery | Pass D/N/K/F/Z/V | E1–E8 |
| `/PROD/login` — depot login | Established public login shell | Form and invalid-credential recovery render in HTML | Interface-scoped authentication/Basic-auth compatibility, CSRF, safe depot return path | Pass D/N/K/F/Z/V | E1, E3–E5, E7–E8 |
| `/PROD/` and `/PROD/{depot_path:path}` — depot directory browser | Read-only Tabulator; Tasks reference | Paired directory fallback, exact native links, parent navigation, empty and traversal-error states | Interface/auth mode enforced server-side; files/directories retain exact safe URLs | Pass D/N/K/F/Z; V N/A | E1–E8 |

## Dialog and shared-surface inventory

The shared `base.html`, `public_portal_base.html`, `partials/resource_wizard.html`, `partials/task_grid.html`, and
`partials/task_modals.html` contracts are part of every applicable row above. The following stable dialog identifiers
are explicitly inventoried so route/template changes cannot silently escape the matrix:

- Shared shell: `about-modal`, `confirm-modal`, `preview-modal`, `ntp-source-health-modal`,
  `appliance-apply-modal`, `task-detail-modal`, and `task-log-modal`.
- Authentication and users: `oidc-client-dialog`, `oidc-key-dialog`, `api-token-dialog`, `user-account-dialog`, and
  `user-password-modal`.
- Automation and maintenance: `automation-schedule-modal`, `automation-script-create-dialog`,
  `automation-script-modal`, `automation-script-run-modal`, `automation-script-diff-modal`,
  `appliance-update-source-dialog`, and `managed-package-dialog`.
- Networking and services: `dns-domain-dialog`, `dhcp-scope-dialog`, `dhcp-option-dialog`,
  `dhcp-lease-reservation-modal`, `dhcp-lease-pxe-modal`, `firewall-rule-dialog`,
  `firewall-rename-group-modal`, and `ntp-source-dialog`.
- Identity, CA, and vSphere Key Providers: `ca-csr-dialog`, `ca-profile-dialog`, `ca-certificate-dialog`,
  `ldap-organization-dialog`, `ldap-user-dialog`, `ldap-group-dialog`, `ldap-bind-secret-modal`,
  `ldap-password-modal`, `ldap-group-members-modal`, `ldap-generate-modal`, `vsphere-provider-dialog`,
  `vsphere-vcenter-dialog`, and `vsphere-certificate-dialog`.
- Network Boot and storage: `network-boot-host-dialog`, `network-boot-upload-dialog`,
  `network-boot-promote-dialog`, `esxi-iso-upload-dialog`, `esxi-custom-variable-wizard-dialog`,
  `esxi-boot-authorization-dialog`, `kickstart-wizard-dialog`, `esx-storage-volume-modal`, and
  `esx-storage-share-modal`.
- Routing and WAN: `routes-wan-route-dialog`, `routes-wan-routing-dialog`, `routes-wan-nat-dialog`, and
  `routes-wan-policy-dialog`.
- VCF workflows: `vcf-fqdn-modal`, `vcf-ldap-modal`, `vcf-trust-modal`, `vcf-sddc-deploy-modal`, `vcf-target-depot-modal`,
  `vcf-vault-import-modal`, `vcf-depot-profile-dialog`, `vcf-depot-tool-package-dialog`,
  `vcf-depot-configuration-dialog`, `vcf-depot-tool-reset-modal`, and `vcf-registry-bundle-dialog`.
- Vaults and Monitor: `vault-create-modal`, `vault-entry-modal`, and `monitor-chart-modal`.

Every wizard identifier above uses `createWizard(...)`, `data-atlaso-wizard-*`, an accessible name and description,
first-invalid-control recovery, focus containment, and launcher-focus restoration. Shared confirmation restores its
action launcher, or the enclosing account-menu launcher when the action closes that menu, after confirm, cancel, or
Escape. Other established dialogs keep native dialog focus containment and their
route-specific close/return behavior. Desktop, narrow, and 200% zoom checks require dialog content to scroll without
moving essential title/action context outside the viewport.

## Template and semantic-summary coverage

Page templates covered by the route rows are `appliance_update.html`, `audit.html`, `authentication.html`,
`automation.html`, `backup_restore.html`, `ca_public.html`, `ca_request_login.html`, `ca_request_portal.html`,
`ca_requests.html`, `certificate_authority.html`, `dashboard.html`, `depot_browser.html`, `dhcp.html`, `dns.html`,
`esx_storage.html`, `esxi_pxe.html`, `firewall.html`, `kms.html`, `ldap.html`, `login.html`, `logs.html`, `monitor.html`,
`ntp.html`, `physical_interfaces.html`, `placeholder.html`, `public_service_home.html`, `public_terminal.html`,
`remote_terminal.html`, `routes_wan.html`, `services.html`, `settings.html`, `tasks.html`, `terminal.html`, `users.html`,
`vaults.html`, `vcf_backups.html`, `vcf_helper.html`, `vcf_offline_depot.html`,
`vcf_offline_depot_task_log.html`, `vcf_private_registry.html`, and `vlan_interfaces.html`.

Shared-only templates are `base.html`, `public_portal_base.html`, `partials/appliance_apply_status.html`,
`partials/brand_mark.html`, `partials/config_preview_action.html`, `partials/resource_wizard.html`,
`partials/task_grid.html`, `partials/task_modals.html`, `partials/terminal_panel.html`, `partials/vcf_ldap_modal.html`,
`partials/vcf_sddc_deploy_modal.html`, `partials/vcf_target_depot_modal.html`, `partials/vcf_trust_modal.html`,
`partials/vcf_vault_credential_picker.html`, and `partials/vcf_vault_import_modal.html`.

The only non-fallback native tables are the reviewed #115 semantic summaries: backup archive scope, generated DHCP PXE
options, generated DNS reverse zones, and the VCF Helper FQDN review. Tooltip/membership and compact key/value,
manifest, configuration, or result summaries remain semantic markup only while they do not gain resource-collection
behavior. Any future sortable, filterable, selectable, navigable, editable, or actionable collection must use the
shared Tabulator foundation or receive explicit maintainer approval through a separately labeled issue.

## Completion rule

The matrix is complete only while E1–E8 pass on the same pull-request head. A future failure must be remediated in the
same change or tracked by a separately labeled issue linked to #115; a new `custom/other` interaction also requires
explicit maintainer approval before implementation.
