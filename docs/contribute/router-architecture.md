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
aggregation facades throughout that migration. Phase 1 establishes registries and contract baselines only; it does not
claim that any product-domain route has already moved.

## Ownership and responsibilities

- `atlaso/app/main.py` owns application construction, middleware, mounts, and the top-level order in which stable facade
  and protocol routers are included. It must include each facade router exactly once.
- `atlaso/app/ui.py` remains the compatibility facade for existing UI helpers and the management, public, front-door,
  and protocol routers. During later phases it imports extracted UI domain routers, registers them, and preserves their
  established effective order.
- `atlaso/app/api/v1.py` remains the compatibility facade for the versioned management API. During later phases it
  imports and registers extracted API v1 domain routers without changing their external contract.
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
- a parameterized or catch-all handler placed before a fixed peer that it would shadow.

Several path patterns may intentionally reach the same endpoint, as the fixed depot root and its path fallback do. That
same-handler alias is not a shadowing conflict, but its exact application order remains characterized by the checked-in
route inventory. Facades call `validate_domains(...)` with the complete expected domain order so an omitted,
unexpected, or reordered domain fails during import rather than silently dropping routes.

Registry modules are dependency-neutral: they do not import facades or product-domain routers. A facade imports the
domain modules, registers their contributions in the established order, and remains the only application-facing
aggregation boundary. Do not use import-time registration from a domain module to reach back into a facade.

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
python -m pytest -q tests/test_openapi_contract.py tests/test_ui_route_namespaces.py tests/test_ui_compliance.py
python scripts/generate_router_contract_baselines.py --check
python scripts/check_python_static_analysis.py
```

Then run the repository's required full Python, documentation, version, and diff checks. Later phases remain incomplete
until their own linked issue, documentation, validation, review, and merge gates are satisfied.
