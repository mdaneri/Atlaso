---
title: Diagnostic collector authoring
description: Extend observational diagnostic evidence without introducing raw-data or credential fallbacks.
audience:
  - contributor
  - maintainer
status: current
---

# Diagnostic collector authoring

The shared collector in `atlaso/diagnostics.py` must remain importable using only the standard library and the package
version. The UI domain router and task service are adapters; the recovery CLI must never import application database
startup, web dependencies, system mutation helpers, or credential providers.

## Reviewed source allowlist

| Source | Included projection | Excluded content |
| --- | --- | --- |
| Package/runtime and bounded proc counters | Version, commit, hostname, clocks, boot ID, resource numbers | Environment, command lines, memory dumps |
| `systemctl show` on fixed units | Enumerated state/result, restart and exit counters, service username | ExecStart, environment, arbitrary status text |
| Appliance SQLite in read-only mode | Schema metadata, selected interface fields, bounded task identity/status/times, PXE enablement | Database copies, secret settings, task results, error strings |
| `ip` JSON, numeric `ss`, `resolvectl dns` | Interface/address/route fields, numeric sockets, DNS addresses | Process details, free-form output |
| Filter-table save commands | Standard policies, numeric address/port matches, known verdicts | Comments, extension arguments and nonstandard chains |
| Managed nginx configuration | Listener address/TLS, server hostname, recognized WebSocket headers | Arbitrary directives, paths, credentials, raw config |
| Active release link and fixed update records | Release identity, finalizer, restart receipt, recovery and worker startup states | Update credentials, arbitrary messages |
| Selected systemd journals | Timestamp, priority, hostname and fixed failure categories | Raw messages, bodies, session material and unknown fields |

The worker invokes only the helper's allowlisted `diagnostics source` operation for journals, firewall tables and
protected update records. The helper runs the installed standard-library collector in isolated Python mode with a
fixed environment, deadline and bounded projection. No request-provided source path or command is accepted.

## Extension rules

1. Add a fixed source and a typed, bounded projection. Web requests must never supply source paths, shell arguments or
   executable names. Use existing per-command/overall limits and cancellation checks; do not create a new shell runner.
2. Validate data types and semantic values before serialization. Unknown or malformed source data must be omitted with
   a fixed reason. Regex-scrubbing an arbitrary file or exception is not an acceptable fallback.
3. Pass hostnames and usernames through the one capture-local `Projection`; retain literal IP/MAC addresses. Never
   persist mapping tables, raw output, excluded values, hashes of excluded secrets, or arbitrary collector stderr.
4. Record source provenance, collector start/end, meaningful outcome, and omissions. Keep desired/applied/observed data
   distinct. Do not imply a multi-stage snapshot is atomic or missing evidence proves health.
5. Seed synthetic passwords, tokens, URLs, private keys, personal/customer contents and malformed data into both success
   and failure paths. Inspect every archive member and temporary-output behavior. Test size/time limits, cancellation,
   unavailable tools/database/services, restrictive paths, and retained partial evidence.
6. Review this source allowlist and the manifest schema explicitly in the PR. Add source coverage and operator guidance
   in the same change. No collector may perform Apply, restart, login, repair or automatic transmission.

The browser transports stay under `/ui/management/backup-restore/diagnostics`, outside OpenAPI. They require current
administrator identity, management-listener eligibility and CSRF on mutations. The service binds archives to diagnostic
job UUIDs and checks expiry again at download. No new `/api/v1` contract is introduced.

The Maintenance page retains its `/ui/management/backup-restore` compatibility route.
LDAP, Backup, Reset and Diagnostics reuse the shared tabs. Diagnostics is a wizard-backed Tabulator collection,
referencing ESX Storage and Automation Schedules;
progress and inspectable results reuse the Tasks interaction. Existing recovery and reset action boundaries remain intact.
