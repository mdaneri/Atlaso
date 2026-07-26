---
title: API reference
description: Discover Atlaso REST operations and schemas through the generated OpenAPI interface.
audience:
  - contributor
  - maintainer
status: current
---

# API reference

Open `/api/docs` on an Atlaso appliance for the interactive Swagger interface. The machine-readable schema is available
at `/openapi.json` and is also the canonical application-readiness endpoint.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Swagger API reference page in the clean-appliance desktop viewport.](../assets/screenshots/swagger-clean-desktop.webp)

*Figure: Swagger API reference in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Use the interface

1. Select an operation and inspect its parameters, request schema, responses, and required authorization.
2. Authenticate with an appropriately scoped API token when the operation requires it.
3. Use example or RFC 1918 values in documentation and test evidence.
4. Verify the response status and schema; do not infer success from network reachability alone.

Never paste production tokens, passwords, private keys, or authenticated URLs into screenshots or public issues.

## Compatibility

Treat the published OpenAPI schema as a compatibility surface. Additive fields should preserve existing consumers, and
behavior changes require synchronized operator documentation, tests, and media ownership. For broader implementation
details, see the [full technical reference](full-technical-reference.md).

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### API reference

![Atlaso Swagger API reference page in the clean-appliance responsive viewport.](../assets/screenshots/swagger-clean-responsive.webp)

*Figure: Swagger API reference in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
