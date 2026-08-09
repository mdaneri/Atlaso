---
title: API authoring standard
description: Required OpenAPI metadata, compatibility, tests, and topic documentation for Atlaso API changes.
audience:
  - contributor
  - maintainer
status: current
---

# API authoring standard

Every supported OpenAPI operation belongs under `/api/v1` and must be fully documented in the same change that adds or
changes it. Browser pages and non-versioned service protocols remain operational with `include_in_schema=False`; their
canonical service guides document those routes.

The legacy DNS, DHCP, and firewall direct-apply routes are the only reviewed `/api/v1` exclusions. They remain hidden
compatibility surfaces because they predate the global Appliance Apply boundary. Do not add another exclusion instead
of documenting a new API or use those routes as a pattern for host mutation.

## Operation requirements

Every new or changed `/api/v1` operation must provide, beside the route declaration:

- a stable, unique `operation_id`, one declared tag, a concise summary, and a non-placeholder detailed description;
- the required Atlaso scope or explicit unauthenticated posture;
- whether the call acts immediately, saves desired state, queues a job, or requires global Appliance Apply;
- the meaning of each successful response and important failure behavior, including locking or safety boundaries;
- explicit request and response models that preserve compatibility unless the linked issue approves a versioned break;
- semantic descriptions for every path, query, header, form, and file parameter; and
- documented response statuses, with validation failures using Atlaso `ProblemDetails` instead of FastAPI's generic
  validation schema.

Do not add a blanket schema postprocessor that invents fallback text. Documentation lives with the route and model so a
reviewer can evaluate behavior and contract together.

## Schema-property requirements

Describe every recursively exposed request and response property with Pydantic `Field(description=...)` metadata.
Document formats, units, allowed-value meaning, nullability, one-time-secret behavior, and safety boundaries when they
apply. A property name repeated in several models may need different descriptions when its semantics differ.

Examples must use placeholders, documentation ranges, or RFC 1918 lab data. Never embed passwords, tokens,
authenticated URLs, private keys, or other secret-bearing values. Secrets returned once must say so explicitly.

## Compatibility and topic documentation

Preserve existing paths, operation IDs, authentication, accepted request shapes, and response shapes. Call out additive
fields and lifecycle changes in the closest operator or service guide. Update the [API operator guide](../operate/api.md)
when authentication, shared errors, apply semantics, compatibility expectations, or client guidance changes.

OIDC under `/identity`, public Network Boot under `/pxe`, Web Terminal routes, and UI pages are service protocols or
browser surfaces rather than the generated `/api/v1` contract. Keep their protocol details in their canonical guides
and explicitly exclude their routers from the schema without changing runtime routing.

## Enforcement

Run the focused contract check before delivery:

```bash
pytest -q tests/test_openapi_contract.py
```

The check discovers all `/api/v1` operations automatically. It rejects non-versioned documented paths, duplicate or
missing operation IDs, missing tags or descriptions, undocumented parameters or recursively exposed schema properties,
generic success responses, incorrect validation responses, and missing tag or bearer-scheme metadata. Also run the
affected authorization and service tests, repository checks, Markdown lint, strict documentation build, full test suite
when warranted, and `git diff --check`.
