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
preserving the established UI, API v1, desired-state, and global Appliance Apply contracts.

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

The UI registry preserves the effective sequence `facade_before_routes_wan`, `routes_wan`, `firewall`,
`physical_vlans`, and `facade_after_physical_vlans`. The API v1 registry preserves
`facade_before_physical_vlans`, `physical_vlans`, `routes_wan`, `facade_between_routes_wan_firewall`, `firewall`, and
`facade_after_firewall`. These complete expected-domain tuples make an omitted or reordered contribution fail during
facade import.

Independently runnable transport coverage lives in:

- `tests/routers/ui/test_routes_wan.py`;
- `tests/routers/ui/test_firewall.py`;
- `tests/routers/api_v1/test_routes_wan.py`; and
- `tests/routers/api_v1/test_firewall.py`.

Service rendering, helper, lifecycle, and global Appliance Apply tests retain their existing ownership. This extraction
does not change templates, browser assets, visible copy, API operations, normalized OpenAPI, route inventory, audit
actions, or host-mutation boundaries.

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
python -m pytest -q tests/test_openapi_contract.py tests/test_ui_route_namespaces.py tests/test_ui_compliance.py
python scripts/generate_router_contract_baselines.py --check
python scripts/check_python_static_analysis.py
```

Then run the repository's required documentation, version, and diff checks; canonical CI owns the complete Python
suite. Later phases remain incomplete until their own linked issue, documentation, validation, review, and merge gates
are satisfied.
