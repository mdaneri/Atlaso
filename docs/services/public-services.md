---
title: Public Services
description: Understand Atlaso browser namespaces, listener scoping, protocol routes, and legacy bookmark compatibility.
audience:
  - operator
  - maintainer
status: current
---

# Public Services

Atlaso separates its authenticated management browser plane from human-facing public service pages. Use
`/ui/management` on the management listener and `/ui/public` on an eligible non-management listener. The root `/` is an
interface-aware dispatcher: it redirects to the plane authorized for the requested host and returns not found when the
host is entitled to neither.

## Browser route contract

| Plane | Canonical root | Publication boundary |
| --- | --- | --- |
| Management | `/ui/management` | Last-applied management-role or flagged access-management binding, paired with observed addresses |
| Public | `/ui/public` | Non-management host/interface with applied Public Services state |
| Dispatcher | `/` | Uses the requested host/interface binding; it does not own a page |

Management child pages, browser-only JSON, forms, downloads, polling endpoints, dialogs, and actions remain under the
management root. App-owned public pages use the public root, including `/ui/public/ca`,
`/ui/public/ca/requests`, and `/ui/public/terminal`. Public pages continue to use the compact Public Services shell and
list only services eligible on the called host/interface.

The prefixes organize browser presentation; they do not replace authentication, authorization, CSRF, session, listener,
Nginx, or Firewall enforcement. A request for `/ui/management/login` on a public-only listener returns not found and does
not reveal the management shell or login behavior. A management listener likewise does not publish `/ui/public`.
Pending desired Network edits do not change this dispatch boundary. The previously applied management binding remains
authoritative until the protected management handoff commits; a newly flagged access listener stays public-only until
then, and a pending role conversion does not expose `/ui/public` on the active management origin.

## Stable machine and protocol routes

The following contracts stay outside `/ui`:

- `/api/v1/...`, `/openapi.json`, `/api/docs`, and `/api/redoc`;
- `/static/...`, `/favicon.ico`, and management-only browser metadata assets;
- OIDC discovery, authorization, token, UserInfo, JWKS, and callback routes under `/identity/...`;
- CA bundle and certificate downloads under `/ca/downloads/...` and
  `/certificate-authority/.../downloads/...`;
- `/pxe/...` and boot artifacts;
- VCF Offline Depot `/PROD/` browsing, authentication, and artifacts; and
- service-owned registry endpoints and canonical registry URLs.

Human pages link to these unchanged paths when they need protocol data. Public Nginx listeners expose only the canonical
public plane, applicable compatibility paths, required static assets, and the selected service protocols. The management
plane, OpenAPI, and unrelated protocols remain unavailable there.

## Legacy bookmark window

Retired root-level browser URLs are compatibility paths for the current release line. Eligible `GET` and `HEAD`
requests receive a same-host temporary redirect to the canonical plane. The eligibility check happens before the
redirect, so a public listener cannot use a legacy management bookmark to discover management routing.

Legacy `POST`, `PATCH`, and `DELETE` requests are bridged internally to the canonical handler and are never replayed by
a `307` or `308` redirect. The canonical handler still owns authentication, role, CSRF, validation, and listener checks.
Operators should update bookmarks and automation now; compatibility routes may be removed in a future major or minor
release after a separately documented deprecation decision. Machine and protocol routes listed above are not part of
this removal window.

## Browser caching

The web manifest starts at `/ui/management/dashboard` and declares scope `/ui/management/`. Its service worker is
registered only from management pages, uses the same narrow scope, and serves an offline fallback only for management
navigation. It does not intercept API, OIDC, CA download, PXE, depot, registry, or other protocol traffic. Public UI
caching is intentionally disabled. On the first management page load after upgrading from the former root-scoped PWA,
Atlaso unregisters the legacy `/` service-worker registration before installing the management-scoped registration.
An updated worker becomes active only after every required offline-shell asset is fetched successfully and written to
its versioned cache. If any required fetch or cache write fails, the installation fails and the previous complete
worker and cache remain authoritative. After a successful installation, activation retires only older
`atlaso-management-pwa-v*` caches and preserves unrelated caches on the same origin.

## Verify an applied appliance

1. Confirm readiness through the management listener at `/openapi.json`.
2. Request `/` on the management address and verify a redirect to `/ui/management`.
3. Request `/` on each selected non-management address and verify a redirect to `/ui/public`.
4. Verify `/ui/public` shows only the services applied to that address, including the minimal empty state where none
   match.
5. Request `/ui/management/login` on a public-only listener and verify `404 Not Found` without management HTML.
6. Request `/ui/public` on the management listener and verify `404 Not Found`.
7. Exercise sign-in, sign-out, a deep link, refresh, keyboard navigation, and a validation-error recovery on desktop and
   narrow viewports.
8. Verify a representative API, OIDC, CA download, PXE, depot, and registry path remains at its documented URL.

If a public page is missing, inspect the desired listener selection and the **Public Services** and **Firewall** units in
the global Appliance Apply review. Validate the staged Nginx configuration before applying it. Do not broaden a listener
with a catch-all proxy as a recovery shortcut.
