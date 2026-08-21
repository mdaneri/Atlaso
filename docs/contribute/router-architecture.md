---
title: Router architecture
description: Preserve Atlaso UI and API contracts while moving route ownership into deterministic domain modules.
audience:
  - contributor
  - maintainer
status: current
---

# Router architecture

Atlaso is moving its monolithic UI and API v1 route implementations into product-domain modules in staged work under
issue #317. The application-facing modules `atlaso/app/ui.py` and `atlaso/app/api/v1.py` remain stable compatibility and
aggregation facades throughout that migration. Phase 1 established the registries and contract baselines. Phase 2
extracted physical-interface and VLAN transport ownership without changing their external contracts. Phase 3 places
physical-interface desired-state mutation, dependent reconciliation, and audit persistence behind one typed domain
service shared by both extracted transports. Phase 4 extracts Routes/WAN and Firewall transport ownership while
preserving the established UI, API v1, desired-state, and global Appliance Apply contracts. Phase 5 extracts DNS/DHCP
transport ownership while retaining dnsmasq behavior and every cross-domain integration. Phase 6 extracts the four
Appliance Apply management transports while keeping submission, execution, recovery, unit construction, status
projection, logging, and audit behavior in the stable UI facade. Phase 7 extracts bounded identity-management UI and
API v1 transports while keeping OIDC protocol endpoints, managed LDAP transports, and identity-domain behavior in
their established owners. Phase 8 extracts Managed LDAP UI and API v1 transports while retaining LDAP services,
helpers, models, renderers, Appliance Apply execution, settings-archive core behavior, and OIDC protocol ownership in
their established modules. Phase 9 extracts Network Boot and ESXi PXE management transports plus the remaining ESXi
PXE API v1 transports while leaving the dedicated Network Boot API and protocol/media router unchanged. Phase 10
extracts the VCF workflow management transports and their three API v1 status operations while preserving their
separated effective positions and the Automation-owned contextual schedule transport. Phase 11 extracts Automation
and operational management transports plus the contiguous operational API v1 block without changing route order,
behavior, or cross-domain service ownership. Phase 12 extracts Appliance Settings and Backup Restore management
transports plus the two API v1 Settings operations while retaining settings-archive, recovery, factory-reset,
credential-custody, and global Appliance Apply behavior in their established owners. Phase 13 extracts the Dashboard
and Monitor management transports plus their two API v1 operations while retaining dashboard projections, monitoring
sampling and service behavior, templates, browser assets, and every operator-visible interaction in their established
owners. Phase 14 extracts the seven Vault management transports while retaining Vault services, encryption, CLI,
templates, browser assets, remote-terminal tickets, Kickstart dependencies, and cross-domain integrations in their
established owners. Phase 15 extracts appliance power and Appliance Update management transports into two ordered
contributions while retaining updater services, helpers, workers, durable tasks, signed-release activation, rollback,
recovery, adapters, templates, browser assets, screenshots, and operator guidance in their established owners.

## Ownership and responsibilities

- `atlaso/app/main.py` owns application construction, middleware, mounts, and the top-level order in which stable facade
  and protocol routers are included. It must include each facade router exactly once.
- `atlaso/app/ui.py` remains the compatibility facade for existing UI helpers and the management, public, front-door,
  and protocol routers. It imports extracted UI domain routers, registers them, and preserves their established
  effective order.
- `atlaso/app/api/v1.py` remains the compatibility facade for the versioned management API. It imports and registers
  extracted API v1 domain routers without changing their external contract.
- `atlaso/app/routers/ui/<domain>.py` owns UI transport concerns for one product domain. These modules may depend on
  services, schemas, models, security dependencies, and shared router infrastructure, but never on `atlaso.app.ui` or
  the API facade.
- `atlaso/app/routers/api_v1/<domain>.py` owns API v1 transport concerns for one product domain. These modules may not
  import either monolithic facade.
- `atlaso/app/services/` owns framework-independent domain behavior. Services may not import application construction,
  router packages, or UI/API facades.

Existing dedicated protocol modules, such as Network Boot, OIDC, and Web Terminal, retain their current ownership until
an explicitly scoped phase changes it. A URL prefix does not replace listener, authentication, authorization, session,
CSRF, or protocol enforcement.

## Registry contract

The UI and API v1 facades register ordered router contributions through `DomainRouterRegistry`. Each registry rejects:

- an invalid or duplicate domain name;
- a router object registered more than once;
- a duplicate `(plane, path, method)` identity; and
- a parameterized, mounted, or catch-all handler placed before a peer that it would shadow; and
- a stale or unused compatibility-shadow declaration.

Callable identity does not make two route records equivalent because FastAPI may bind the same parameter from different
request locations or apply different dependencies and response configuration. The existing depot path fallback
intentionally intercepts its fixed `/PROD/` compatibility alias, so the UI facade declares that exact path-and-method
relationship through `allow_compatible_route_shadow(...)`. The declaration validates that both records exist exactly
once and use the same endpoint, and registry plus application-inventory validation fail if it becomes unused. Do not
infer or add another exception merely because routes share a name or callable. Facades call `validate_domains(...)`
with the complete expected domain order so an omitted, unexpected, or reordered domain fails during import rather than
silently dropping routes.

Registry modules are dependency-neutral: they do not import facades or product-domain routers. A facade imports the
domain modules, registers their contributions in the established order, and remains the only application-facing
aggregation boundary. Do not use import-time registration from a domain module to reach back into a facade.

When extraction occurs inside an existing monolithic route sequence, the facade registers a before-domain segment,
the domain router, and an after-domain segment. It then aggregates those registered routers into the single stable
facade object imported by `main.py`. This keeps application construction unchanged while making ownership and ordering
explicit and testable.

## Extracted physical-interface and VLAN ownership

Physical-interface and VLAN management handlers live in
`atlaso/app/routers/ui/physical_vlans.py`; their API v1 handlers live in
`atlaso/app/routers/api_v1/physical_vlans.py`. The API domain also owns the existing physical-interface inventory
refresh operation. Both modules receive the facade-owned compatibility helpers they need during router construction,
so neither imports a monolithic facade and existing helper exports remain stable.

The independently runnable transport coverage lives in
`tests/routers/ui/test_physical_vlans.py` and `tests/routers/api_v1/test_physical_vlans.py`. Shared registry tests assert
the exact before/domain/after order and endpoint module ownership. Import-boundary checks require both facades to
assemble these domain modules while continuing to reject domain-to-facade imports.

`atlaso/app/services/physical_interfaces.py` owns the typed partial-mutation, audit-input, and committed-result contract
used by both transports. It stages the interface row, every reconciled dependent row, and the transport-compatible audit
event before one commit. `atlaso/app/services/interface_updates.py` retains the detailed reconciliation algorithm as a
documented low-level compatibility seam for VLAN and other callers that already own a wider transaction; it does not
replace the physical-interface domain-service boundary.

This service consolidation does not change templates, browser assets, visible copy, API operations, route inventory,
normalized OpenAPI, or the global Appliance Apply boundary. The service writes desired state only; host mutation still
belongs exclusively to Appliance Apply.

## Extracted Routes/WAN and Firewall ownership

Routes, routing permissions, WAN policies, and NAT transports live in
`atlaso/app/routers/ui/routes_wan.py` and `atlaso/app/routers/api_v1/routes_wan.py`. Firewall transports live separately
in `atlaso/app/routers/ui/firewall.py` and `atlaso/app/routers/api_v1/firewall.py`. The stable facades continue to export
the established endpoint and helper names while supplying facade-owned compatibility helpers to each router builder.
Neither domain router imports a monolithic facade.

At the Phase 4 boundary, the UI registry ended with `physical_vlans` and `facade_after_physical_vlans`, while the API
v1 registry placed `facade_between_routes_wan_firewall` between `routes_wan` and `firewall`. Phase 5 extends those
historical tuples with the DNS/DHCP ownership and current effective sequences documented below. Complete
expected-domain tuples make an omitted or reordered contribution fail during facade import.

Independently runnable transport coverage lives in:

- `tests/routers/ui/test_routes_wan.py`;
- `tests/routers/ui/test_firewall.py`;
- `tests/routers/api_v1/test_routes_wan.py`; and
- `tests/routers/api_v1/test_firewall.py`.

Service rendering, helper, lifecycle, and global Appliance Apply tests retain their existing ownership. This extraction
does not change templates, browser assets, visible copy, API operations, normalized OpenAPI, route inventory, audit
actions, or host-mutation boundaries.

## Extracted DNS/DHCP ownership

DNS and DHCP management transports live in `atlaso/app/routers/ui/dns_dhcp.py`; their API v1 transports live in
`atlaso/app/routers/api_v1/dns_dhcp.py`. The stable facades continue to export the established endpoint and helper
names while supplying facade-owned compatibility helpers to each router builder. Neither domain router imports a
monolithic facade.

The UI registry preserves the effective sequence through `physical_vlans`, `dns_dhcp`, and
`facade_after_dns_dhcp`. The API v1 registry preserves `routes_wan`, the helper-only
`facade_between_routes_wan_dns_dhcp` segment, `dns_dhcp`, and `firewall`. Independently runnable
transport coverage lives in `tests/routers/ui/test_dns_dhcp.py` and
`tests/routers/api_v1/test_dns_dhcp.py`.

Rendering and low-level validation remain in `atlaso/app/services/dnsmasq.py` with their existing
`tests/test_dns_dhcp.py` coverage. Appliance Apply, VCF, Network Boot/PXE, firewall generation, interface
reconciliation, and other cross-domain lifecycle tests retain their existing owners. This extraction does not change
templates, browser assets, visible copy, API operations, normalized OpenAPI, route inventory, audits, desired state, or
the global Appliance Apply boundary.

## Extracted Appliance Apply ownership

The established Appliance Apply management transports live in
`atlaso/app/routers/ui/appliance_apply.py`: the direct-page redirect, review projection, lightweight status projection,
and submission endpoint. The stable `atlaso/app/ui.py` facade continues to export the four endpoint names and owns the
status, context, unit construction, active-job, submission, execution, logging, recovery, audit, identity/CSRF, and
background-task helpers supplied through the typed router builder. The UI registry places `appliance_apply` immediately
after `facade_between_automation_routes_wan` and before `routes_wan`, preserving the established effective route order.

Independently runnable transport coverage lives in `tests/routers/ui/test_appliance_apply.py`. Browser polling remains
covered by `tests/javascript/appliance-apply-polling.test.js`; execution, recovery, subsystem sequencing, helper
rendering, and cross-domain behavior retain their existing test owners. This extraction changes no route, response,
listener dependency, permission, CSRF/session behavior, desired-state boundary, route inventory, or normalized OpenAPI
contract.

## Extracted identity-management ownership

Authentication and OpenID Connect administration, UI API-token administration, Local Users management and status,
and the legacy LDAP-users redirect live in `atlaso/app/routers/ui/identity.py`. Current-identity and API-token lifecycle
operations live in `atlaso/app/routers/api_v1/identity.py`. The stable facades continue to export the established
endpoint and compatibility-helper names while supplying the UI module with facade-owned rendering, CSRF, authorization,
desired-state status, service-binding, DNS/CA reconciliation, and Local Users helpers. Neither domain router imports a
monolithic facade.

The UI registry places `identity` after `facade_between_dns_dhcp_identity` and before `facade_after_identity`, preserving
the established position between ESX Storage and Services. The API v1 registry places `identity` after
`facade_before_identity` and before `facade_between_identity_physical_vlans`, preserving the established position after
API login and before Dashboard. `/api/v1/auth/login` remains in the facade, OIDC protocol endpoints under `/identity`
retain their dedicated ownership, and managed LDAP transports remain unextracted.

Independently runnable transport coverage lives in `tests/routers/ui/test_identity.py` and
`tests/routers/api_v1/test_identity.py`. OIDC protocol and service behavior retain their existing test owners. This
extraction changes no template, browser asset, visible copy, route, route name, operation ID, authorization scope,
session or CSRF behavior, secret-once or redaction behavior, redirect, response schema, route inventory, or normalized
OpenAPI contract.

## Extracted Managed LDAP ownership

Managed LDAP management transports live in `atlaso/app/routers/ui/managed_ldap.py`; their API v1 transports live in
`atlaso/app/routers/api_v1/managed_ldap.py`. The stable facades continue to export the established endpoint and helper
names while supplying facade-owned rendering, CSRF, authorization, service-binding, DNS/CA reconciliation, VCF Helper,
Appliance Apply status, and runtime-service helpers through typed router builders. Neither domain router imports a
monolithic facade.

The UI registry places `managed_ldap` between `facade_between_dns_dhcp_managed_ldap` and
`facade_between_managed_ldap_vcf_workflows`, preserving its established position after Certificate Authority and
before VCF workflows. The API v1 registry places `managed_ldap` after `network_boot` and before
`facade_after_managed_ldap`, preserving its established position after ESXi PXE and before vSphere Key Providers.

Independently runnable transport coverage lives in `tests/routers/ui/test_managed_ldap.py` and
`tests/routers/api_v1/test_managed_ldap.py`. LDAP protocol, models, credentials, helper actions, renderers, DNS and CA
reconciliation, OIDC identity-source behavior, VCF integration, staged recovery custody, settings-archive core
behavior, and global Appliance Apply execution retain their existing owners and tests. This extraction changes no
template, browser asset, visible copy, route, route name, operation ID, authorization scope, session or CSRF behavior,
schema, redirect, download, status code, route inventory, normalized OpenAPI output, desired state, or host-mutation
boundary.

## Extracted Network Boot and ESXi PXE ownership

Network Boot and ESXi PXE management transports under `/ui/management/network-boot` and
`/ui/management/esxi-pxe` live in `atlaso/app/routers/ui/network_boot.py`. The remaining `/api/v1/esxi-pxe` transports
live in `atlaso/app/routers/api_v1/network_boot.py`. The stable facades continue to export every established endpoint
and helper name while supplying facade-owned rendering, identity, CSRF, task, desired-state, and compatibility helpers
through the typed UI router builder. Neither extracted router imports a monolithic facade.

The UI registry places `network_boot` between `facade_between_identity_network_boot` and `settings_backup`, preserving
its established position after Web Terminal and before Backup Restore. The API
v1 registry places `network_boot` between `facade_between_vcf_private_registry_network_boot` and `managed_ldap`,
preserving its established position after VCF Private Registry and before Managed LDAP.

The separate `atlaso/app/api/network_boot.py` owner of `/api/v1/network-boot` and the protocol/media routes remains
unchanged. Network Boot and ESXi PXE services, helpers, models, renderers, cross-domain DHCP/DNS integration, task and
media behavior, desired/applied-state handling, and global Appliance Apply ownership also retain their established
modules.

Independently runnable facade-transport coverage lives in `tests/routers/ui/test_network_boot.py` and
`tests/routers/api_v1/test_network_boot.py`. Protocol, service, media, and lifecycle coverage remains in
`tests/test_network_boot.py` and its existing specialized owners. This behavior-neutral extraction changes no
template, browser asset, visible copy, interaction class, route, route name, operation ID, authorization scope, session
or CSRF behavior, upload or download contract, redirect, status code, schema, audit action, route inventory, normalized
OpenAPI output, desired state, or host-mutation boundary.

## Extracted VCF workflow ownership

The legacy HTTPS Repository bridge and the VCF Helper, Trust, Offline Depot, Private Registry, and Backups management
transports live in `atlaso/app/routers/ui/vcf_workflows.py`. Their services, helpers, models, workers, lifecycle and task
execution, download admission, Appliance Apply units, templates, and browser assets retain their established owners.
The stable UI facade continues to export every established endpoint and helper name and supplies only the bounded
compatibility dependencies needed by the extracted router.

The UI registry places `vcf_workflows` between `facade_between_managed_ldap_vcf_workflows` and
`facade_between_vcf_workflows_identity`. The following facade segment retains ESX Storage and the other transports that
precede the extracted Identity router. The contextual
`/ui/management/vcf-offline-depot/profiles/{profile_id}/schedules` transport remains in its earlier Automation-owned
route block; extraction into the VCF workflow router would change both ownership and effective order.

The three API v1 status transports live together in `atlaso/app/routers/api_v1/vcf_workflows.py`, but the module returns
three ordered router contributions so their effective positions do not collapse. `vcf_workflows_backups` remains
immediately after `settings`; the facade segment through ESX Storage remains before
`vcf_workflows_offline_depot`; the compatibility `/api/v1/repository/status` alias remains in
`facade_between_offline_depot_private_registry`; and `vcf_workflows_private_registry` remains before
`facade_between_vcf_private_registry_network_boot` and Network Boot. The stable API v1 facade continues to export all
three operation callables and owns the shared Offline Depot status projection used by its repository alias.

Independently runnable facade-transport coverage lives in `tests/routers/ui/test_vcf_workflows.py` and
`tests/routers/api_v1/test_vcf_workflows.py`. Service, worker, lifecycle, task, download, protocol, and browser-JavaScript
coverage remains with the established VCF and Automation test owners. This behavior-neutral extraction changes no
template, CSS, JavaScript, control, layout, visible copy, interaction class, route, route name, operation ID,
authorization scope, session or CSRF behavior, upload or download contract, redirect, status code, response schema,
audit action, secret or redaction contract, route inventory, normalized OpenAPI output, desired state, or global
Appliance Apply boundary.

## Extracted Automation and operations ownership

Automation management transports live in `atlaso/app/routers/ui/automation.py`. This owner includes the Automation
page, schedule create/edit/run/toggle/delete transports, managed-script and script-revision
create/edit/delete/toggle/run transports, and the contextual
`/ui/management/vcf-offline-depot/profiles/{profile_id}/schedules` transport. The contextual path remains Automation
owned because it creates an Automation schedule for one VCF Offline Depot profile; VCF profile configuration,
download admission, execution, and lifecycle remain in their established VCF owners.

Operational management transports live in `atlaso/app/routers/ui/operations.py`: Services list/actions/logs, Logs
page/data, Tasks page/list/status/log/cancel, and Audit Log. The UI registry preserves Automation's earlier position
between `facade_before_automation` and `facade_between_automation_routes_wan`. Operations remains later between
`facade_between_identity_operations` and `facade_between_identity_network_boot`, after Identity and before Network
Boot. The stable UI facade continues to export all established endpoints and compatibility helpers.

The contiguous service, log, audit-event, and job API v1 transports live in
`atlaso/app/routers/api_v1/operations.py`. The API registry places `operations` between
`facade_between_firewall_operations` and `settings`, retaining the original position
after Dashboard/Monitor and the intervening networking domains, and before Settings and later VCF Backups status.
Every path, method, name, operation ID, tag, scope, status, response schema, audit, cancellation, and redaction
contract remains unchanged.

Independently runnable facade-transport coverage lives in `tests/routers/ui/test_automation.py`,
`tests/routers/ui/test_operations.py`, and `tests/routers/api_v1/test_operations.py`. Scheduler, service, worker,
task-execution, lifecycle, protocol, and browser-JavaScript behavior retain their established test owners. This
behavior-neutral extraction changes no template, CSS, JavaScript, control, layout, visible copy, interaction class,
route inventory, normalized OpenAPI output, desired state, service-control boundary, or global Appliance Apply
behavior.

## Extracted Appliance Settings and Backup Restore ownership

Appliance Settings and Backup Restore management transports live in
`atlaso/app/routers/ui/settings_backup.py`. This owner includes the Backup Restore page, settings-archive export and
restore submissions, factory-reset submission, Appliance Settings page and desired-state update, VMware CEIP policy
update, and operational-logging settings update. Settings-archive services, preflight and transaction behavior,
rollback, staged Managed LDAP recovery custody, factory-reset reseeding, runtime logging configuration, templates, and
browser assets retain their established owners. The stable UI facade continues to export every endpoint and helper
name while supplying the extracted router with bounded compatibility dependencies.

The UI registry places `settings_backup` after `network_boot` and before `facade_after_settings_backup`. That final
facade segment retains the management placeholder catch-all, so every fixed Settings and Backup Restore route remains
at its original effective position and before the fallback.

The two Settings API v1 operations live in `atlaso/app/routers/api_v1/settings.py`. The API registry places `settings`
immediately after `operations` and before `vcf_workflows_backups`, preserving the established position between the
operational API block and VCF Backups status. The stable API facade continues to export both operation callables and
the appliance-settings response and desired-state compatibility helpers.

Independently runnable facade-transport coverage lives in
`tests/routers/ui/test_settings_backup.py` and `tests/routers/api_v1/test_settings.py`. Settings-archive, restore,
factory-reset, Managed LDAP recovery, credential-custody, lifecycle, and global Appliance Apply behavior retain their
established test owners. This behavior-neutral extraction changes no template, CSS, JavaScript, visible copy, control,
layout, interaction class, route, route name, operation ID, tag, authorization scope, session or CSRF behavior, upload
or download contract, redirect, status code, response schema, audit action, caching or redaction contract, route
inventory, normalized OpenAPI output, desired state, or host-mutation boundary.

## Extracted Dashboard and Monitor ownership

Dashboard and Monitor management transports live in
`atlaso/app/routers/ui/dashboard_monitor.py`. This owner includes the Dashboard page and private data response, Monitor
page and data response, and management server-time response. Dashboard projection helpers remain in the stable UI
facade, and monitoring collection, sampling, persistence, and payload construction remain in
`atlaso/app/services/monitoring.py`. Templates, authored CSS, browser JavaScript, screenshots, refresh cadence, and
operator guidance retain their established owners.

The UI registry places `dashboard_monitor` between `appliance_maintenance_power` and
`appliance_maintenance_update`, preserving the original effective position after appliance power and before Appliance
Update, Automation, and every later management domain. The stable UI facade continues to export all five endpoint
callables plus the dashboard, monitoring-access, formatting, and projection compatibility helpers.

The bearer-authenticated Dashboard and Monitor API v1 operations live in
`atlaso/app/routers/api_v1/dashboard_monitor.py`. The API registry places `dashboard_monitor` immediately after
`identity` and before `physical_vlans`, preserving the established position after API login and identity operations and
before the physical-interface, VLAN, networking, operational, Settings, VCF, Network Boot, and Managed LDAP blocks.
The stable API v1 facade continues to export both operation callables and the monitoring payload compatibility helper.

Independently runnable facade-transport coverage lives in
`tests/routers/ui/test_dashboard_monitor.py` and
`tests/routers/api_v1/test_dashboard_monitor.py`. Dashboard projection, monitoring service and sampling, lifecycle,
browser-JavaScript, template, and cross-domain behavior retain their established test owners. Monitor detail
collections remain read-only Tabulator surfaces that reuse Tasks and Audit Events operational-grid behavior. Dashboard
command-center cards and Monitor chart/status panels remain their existing reviewed custom read-only surfaces. This
behavior-neutral extraction changes no template, CSS, JavaScript, visible copy, control, layout, chart, grid, tab,
refresh cadence, interaction class, route, route name, operation ID, tag, authorization scope, session, caching,
redirect, status code, response schema, monitoring sample, task or apply projection, redaction, audit, route inventory,
or normalized OpenAPI contract.

## Extracted Vault ownership

The seven Vault management transports live in `atlaso/app/routers/ui/vaults.py`: the Vault page, Vault creation, entry
creation, entry editing, explicit timed reveal, entry deletion, and Vault deletion. The dedicated Vault service, CLI,
template and browser JavaScript, encryption and secret custody, VCF Helper integration, managed-script scope, remote
URI and one-use Web Terminal ticket behavior, and Network Boot/Kickstart dependency handling retain their established
owners.

The UI registry places `vaults` between `facade_before_vaults` and
`facade_between_vaults_appliance_maintenance`. The first facade segment retains front-door, protocol, public, and
earlier management routes through the Web Terminal WebSocket. The following facade segment begins with management home
and login and continues through the account actions that precede appliance power. This preserves Vault's exact original
position after Web Terminal and before management home without collapsing the later appliance-maintenance and
Dashboard/Monitor contributions.

The stable `atlaso/app/ui.py` facade continues to export `vaults_page`, `create_vault_from_ui`,
`create_vault_entry_from_ui`, `edit_vault_entry_from_ui`, `reveal_vault_entry_from_ui`,
`delete_vault_entry_from_ui`, and `delete_vault_from_ui`. It also retains the `vaults_context` and
`_vaults_render_error` compatibility helpers supplied to the extracted router. The domain router does not import the
UI facade or another monolithic facade.

Independently runnable transport coverage lives in `tests/routers/ui/test_vaults.py`. Vault service, encryption, CLI,
browser-JavaScript, remote-URI and one-use-ticket, Kickstart dependency, settings-archive, worker, and VCF Helper
integration coverage remains in `tests/test_vaults.py` and its established specialized owners. This behavior-neutral
extraction changes no template, CSS, JavaScript, visible copy, control, layout, accessibility, responsive behavior,
interaction class, route, route name, listener eligibility, authorization scope, session or CSRF behavior, redirect,
status code, rendering or cache contract, audit action, encryption, masking, timed reveal, delete-dependency behavior,
route inventory, or normalized OpenAPI output.

## Extracted appliance-maintenance ownership

The authenticated appliance power transport and the eleven Appliance Update transports live in
`atlaso/app/routers/ui/appliance_maintenance.py`. The module returns two explicit ordered routers:
`appliance_maintenance_power` remains immediately before Dashboard and Monitor, while
`appliance_maintenance_update` remains immediately after them and before Automation. The facade contribution preceding
power is named `facade_between_vaults_appliance_maintenance`, preserving every earlier front-door, protocol, public,
authentication, account, and management route at its established position.

The stable `atlaso/app/ui.py` facade continues to export `appliance_power_action`, `appliance_update_page`,
`update_appliance_update_settings`, `update_appliance_update_source`, `create_appliance_update_source`,
`delete_appliance_update_source`, `create_managed_update_package`, `update_managed_update_package`,
`delete_managed_update_package`, `sync_appliance_update_sources`, `check_appliance_update`, and
`run_appliance_update`. It also retains the `_managed_package_from_form` and `submit_appliance_update` helpers and
supplies late-bound compatibility dependencies so existing facade monkeypatch seams continue to work. The extracted
domain module does not import the UI facade or another monolithic facade.

Independently runnable transport coverage lives in
`tests/routers/ui/test_appliance_maintenance.py`. Appliance Update services, helper actions, worker execution, durable
task behavior, signed-release activation, rollback and recovery, system adapters, lifecycle coverage, templates,
browser JavaScript, screenshots, and operator guidance retain their established owners. This preservation-only
extraction changes no template, CSS, JavaScript, visible copy, control, layout, accessibility, responsive behavior,
interaction class, route, route name, listener, authorization, admin permission, session or CSRF behavior, redirect,
status code, response, rendering, caching, task, audit, adapter, helper, update-manifest, credential-custody,
release-signature, activation, rollback, recovery, redaction, route inventory, normalized OpenAPI output, or global
Appliance Apply boundary.

## Extracted certificate-trust ownership

Certificate Authority and vSphere Key Provider management transports live in
`atlaso/app/routers/ui/certificate_trust.py`. The module contributes two ordered
management routers around Managed LDAP: Certificate Authority remains after the
DNS/DHCP facade segment and before Managed LDAP, while vSphere Key Providers
remain after Managed LDAP and before the facade segment that owns NTP, ESX
Storage, and later VCF workflows. The existing public CA and certificate-request
routes retain the shared public and protocol router positions supplied by the
stable UI facade.

The vSphere Key Provider API v1 operations and the Certificate Authority status
compatibility operation live in
`atlaso/app/routers/api_v1/certificate_trust.py`. The API registry places this
domain immediately after Managed LDAP and before the remaining Backup Restore
compatibility operation. The stable `atlaso/app/ui.py` and
`atlaso/app/api/v1.py` facades continue to export every established endpoint and
helper name while supplying facade-owned rendering, listener, CSRF, desired-state,
DNS, certificate, and Appliance Apply helpers as bounded dependencies.

Independently runnable transport coverage lives in
`tests/routers/ui/test_certificate_trust.py` and
`tests/routers/api_v1/test_certificate_trust.py`. CA and KMIP service, lifecycle,
protocol, settings-archive, rendering, credential-custody, worker, and global
Appliance Apply behavior retain their established test owners. Certificate
Authority singleton settings remain `non-grid settings` using the DNS settings
and validation-rail reference. Certificate profiles, request intake, providers,
trusted vCenters, and certificate lifecycle retain their existing
`wizard-backed Tabulator` interactions using ESX Storage. Management and public
request collections and operational inspection retain their existing
`read-only Tabulator` behavior using Tasks and Audit Events.

This behavior-neutral extraction changes no template, CSS, JavaScript, visible
copy, control, layout, interaction class, route, route name, operation ID, tag,
authorization scope, session or CSRF behavior, redirect, status, response schema,
audit action, public-certificate or redaction contract, certificate/private-key
custody, managed-certificate ownership, vCenter trust, provider identity, route
inventory, normalized OpenAPI output, desired state, KMIP protocol, or global
Appliance Apply boundary.

## Route and OpenAPI compatibility

`tests/contracts/route_inventory.json` records every effective application route in order, including browser,
protocol, WebSocket, mount, and API routes. Its stable fields are plane, path, methods, route name, explicit operation
ID, schema visibility, and route kind. It makes omissions, duplicates, and unintended order changes reviewable.

`tests/contracts/openapi_v1.json` records the complete generated OpenAPI document after removing only `info.version`,
which is generated from the installed Atlaso version. An extraction must not normalize or ignore any other field.

Preserve all established paths, methods, names, operation IDs, tags, scopes, authorization dependencies, session and
CSRF behavior, status codes, redirects, media types, response models, aliases, audit behavior, and effective route
ordering. Keep non-`/api/v1` browser and protocol routes out of OpenAPI. Regenerate a baseline only when the linked issue
explicitly approves the corresponding external contract or order change; an ordinary extraction must leave both files
unchanged.

## Domain implementation and test placement

Put new or extracted code and tests together by product domain:

```text
atlaso/app/routers/ui/<domain>.py
atlaso/app/routers/api_v1/<domain>.py
atlaso/app/services/<domain>.py
tests/routers/ui/test_<domain>.py
tests/routers/api_v1/test_<domain>.py
tests/services/test_<domain>.py
```

Use only the files that match the domain's actual transports. Keep service tests focused on domain invariants and keep
transport tests focused on authorization, validation, response, redirect, session, CSRF, media-type, and audit
behavior. The shared registry, import-boundary, route-inventory, and OpenAPI tests stay under `tests/routers/`.

For physical interfaces, `tests/services/test_physical_interfaces.py` owns rollback, dependent-binding, child-VLAN,
DHCP/reservation/DNS, inactive-legacy-field, and audit-atomicity behavior. The extracted UI and API test modules retain
their distinct response and audit-action contracts and representative parity coverage.

Every new or changed `/api/v1` operation must also follow the [API authoring standard](api-authoring.md). Any later
change to templates, authored CSS, browser JavaScript, controls, layouts, grids, wizards, or visible copy must first
complete the [UI Design Guide](ui-design-guide.md) gate.

## Staged extraction workflow

For each independently reviewable phase under issue #317:

1. Start from current protected `main` and identify the phase's closing issue.
2. Characterize the domain's current UI, API, service, and test ownership before moving code.
3. Move transport code without behavioral refactoring, keeping the stable facades as aggregators.
4. Register the domain in its established order and update the facade's complete expected-domain tuple.
5. Move or add domain tests without weakening shared route, OpenAPI, or import-boundary enforcement.
6. Run the focused domain tests and the full compatibility validation before delivery.

Use these focused foundation checks while developing:

```powershell
python -m pytest -q tests/routers
python -m pytest -q tests/routers/ui/test_physical_vlans.py tests/routers/api_v1/test_physical_vlans.py
python -m pytest -q tests/routers/ui/test_routes_wan.py tests/routers/api_v1/test_routes_wan.py
python -m pytest -q tests/routers/ui/test_firewall.py tests/routers/api_v1/test_firewall.py
python -m pytest -q tests/routers/ui/test_dns_dhcp.py tests/routers/api_v1/test_dns_dhcp.py tests/test_dns_dhcp.py
python -m pytest -q tests/routers/ui/test_identity.py tests/routers/api_v1/test_identity.py
python -m pytest -q tests/routers/ui/test_managed_ldap.py tests/routers/api_v1/test_managed_ldap.py
python -m pytest -q tests/routers/ui/test_network_boot.py tests/routers/api_v1/test_network_boot.py tests/test_network_boot.py
python -m pytest -q tests/routers/ui/test_vcf_workflows.py tests/routers/api_v1/test_vcf_workflows.py
python -m pytest -q tests/routers/ui/test_automation.py tests/routers/ui/test_operations.py tests/routers/api_v1/test_operations.py
python -m pytest -q tests/routers/ui/test_dashboard_monitor.py tests/routers/api_v1/test_dashboard_monitor.py
python -m pytest -q tests/routers/ui/test_vaults.py tests/test_vaults.py
python -m pytest -q tests/routers/ui/test_appliance_maintenance.py tests/test_appliance_update.py
python -m pytest -q tests/test_openapi_contract.py tests/test_ui_route_namespaces.py tests/test_ui_compliance.py
python scripts/generate_router_contract_baselines.py --check
python scripts/check_python_static_analysis.py
```

Then run the repository's required documentation, version, and diff checks; canonical CI owns the complete Python
suite. Later phases remain incomplete until their own linked issue, documentation, validation, review, and merge gates
are satisfied.
