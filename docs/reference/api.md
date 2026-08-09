---
title: API reference
description: Discover Atlaso REST operations and schemas through the generated OpenAPI interface.
audience:
  - contributor
  - maintainer
status: current
---

# API reference

Open `/api/docs` on an Atlaso appliance for the interactive Swagger interface or `/api/redoc` for ReDoc. The
machine-readable schema is available at `/openapi.json` and is also the canonical application-readiness endpoint. Only
the supported `/api/v1` REST contract appears in these interfaces.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Swagger API reference page in the clean-appliance desktop viewport.](../assets/screenshots/swagger-clean-desktop.webp)

*Figure: Swagger API reference in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

For token creation, safe command examples, scopes, errors, request IDs, locking, and mutation boundaries, start with
[Use the Atlaso API](../operate/api.md). This page remains the generated-contract reference.

## Use the interface

1. Select an operation and inspect its parameters, request schema, responses, and required authorization.
2. Authenticate with an appropriately scoped API token when the operation requires it.
3. Use example or RFC 1918 values in documentation and test evidence.
4. Verify the response status and schema; do not infer success from network reachability alone.

Never paste production tokens, passwords, private keys, or authenticated URLs into screenshots or public issues.

## Identify the appliance version

Send an unauthenticated `GET` request to `/api/v1/version` through the management front door to identify the installed
Atlaso build. The response contains the installed `version`, its `base_version`, the full source `git_commit`, and the
UTC `built_at` timestamp. Source checkouts and development wheels return an empty string when commit or build-time
metadata is unavailable. These values come only from package metadata embedded during the build; the request does not
inspect a runtime Git checkout.

This operation intentionally omits host-platform diagnostics and does not make management API routes available through
additional Public Services listeners.

## Compatibility

Treat the published OpenAPI schema as a compatibility surface. Additive fields should preserve existing consumers, and
behavior changes require synchronized operator documentation, tests, and media ownership. For broader implementation
details, see the [full technical reference](full-technical-reference.md).

OIDC `/identity`, Network Boot `/pxe`, Web Terminal, and browser routes are intentionally absent from Swagger. Their
runtime protocols remain supported and are documented in the corresponding service and operator guides.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### API reference

![Atlaso Swagger API reference page in the clean-appliance responsive viewport.](../assets/screenshots/swagger-clean-responsive.webp)

*Figure: Swagger API reference in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
