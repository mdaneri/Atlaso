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
| Appliance SQLite in read-only mode | Schema metadata, selected interface fields, bounded task identity/status/times, PXE enablement, validated task checkpoint important events | Database copies, secret settings, task results, error strings, task-log chunks |
| `ip` JSON, numeric `ss`, `resolvectl dns` | Interface/address/route fields, numeric sockets, DNS addresses | Process details, free-form output |
| Native `nft -j -nn list table inet atlaso` | Chain policies, numeric address/port matches, known verdicts | Comments, unsupported expressions and other tables |
| Managed nginx configuration | Listener address/TLS, server hostname, recognized WebSocket headers | Arbitrary directives, paths, credentials, raw config |
| Active release link and fixed update records | Release identity, finalizer, restart receipt, recovery and worker startup states | Update credentials, arbitrary messages |
| Selected systemd journals | Timestamp, priority, hostname and fixed failure categories | Raw messages, bodies, session material and unknown fields |

Task important events are projected from `task_log_checkpoints.state_json` only. The collector revalidates schema 1,
timezone-aware timestamps, severity, reviewed component IDs for Apply units, update streams, VCF workflow stages and
task-level events, plus stage, outcome, reason code and bounded return code.
Unknown keys and invalid events are discarded; only the fixed explanation for a validated reason code is added.
The bundle includes at most 64 events per task and reports the producer's omitted count plus invalid or over-limit
events. A checkpoint without the typed field, an absent checkpoint table, or malformed checkpoint JSON is marked
`evidence_unavailable`; an empty typed event list means the checkpoint is available and contains no retained events.
Legacy task result/error columns and task-log chunks remain excluded. Important-event retention in the support bundle
does not depend on the runtime verbosity setting.

Journal evidence carries an explicit `availability` outcome. `available`, `no_entries`, `source_missing`,
`permission_denied`, `timed_out`, `malformed_data`, `truncated`, `helper_incompatible`, `command_missing`, and
`unavailable` remain distinct in the evidence and manifest. Empty journals never imply a healthy service. The helper
protocol still accepts only the fixed `diagnostics source` names and bounded time window; the collector validates its
evidence envelope and event fields. Direct `journalctl` stderr is drained into a 64 KiB memory bound and used only to
classify a fixed permission-denied signal; its text is never exported. The privileged helper continues to suppress
stderr, and the collector never falls back to helper stderr or arbitrary command output. A nonzero helper result with
no typed response remains `unavailable` because the constrained helper intentionally suppresses stderr.

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
