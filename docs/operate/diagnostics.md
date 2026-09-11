---
title: Diagnostic support bundles
description: Collect bounded private support evidence from Maintenance or the recovery CLI.
audience:
  - operator
  - maintainer
status: current
---

# Diagnostic support bundles

Administrators can create a support archive under **Operations > Maintenance > Diagnostics**.
The archive is observational: collection does not Apply, restart, repair, authenticate to external services, or upload
anything. A diagnostic bundle is not a settings backup or a promise of source authenticity.

## Create and inspect a bundle

1. Use the bottom **Create diagnostic bundle** row to open the shared four-step wizard.
2. In **Incident**, keep **Last 30 minutes** or select a custom window of at most seven days. Custom times use the
   displayed browser timezone. An optional task/correlation UUID narrows task history; existing short and full-length
   `job_` IDs and scheduled `job_schedule_` IDs work too. Selecting an ID includes matching task history even when
   no optional evidence scopes are selected. Task history preserves skipped, no-op, and partial-failure outcomes as
   well as ordinary lifecycle states.
   Runtime observations describe capture time, not historical state, and system logs are not filtered by that ID.
3. In **Contents**, select additional Network, Web Terminal, Appliance Update, or Network Boot / PXE evidence.
   Basic version, clock, resource pressure, service status, and database availability are always included.
   **Include detailed log evidence** is unchecked by default. When selected, it includes bounded journal timestamps,
   severity, hostnames, and recognized failure categories. Free-form messages and unknown fields are omitted.
4. In **Privacy**, optionally enable **Anonymize hostnames and usernames**. It is off by default.
5. In **Review**, check the time range, selected evidence, privacy choice and retention, then choose **Create bundle**.
   The request becomes a normal background task. You can leave the page and return while collection runs.
6. Open the bundle to inspect collector outcomes and omissions. **Ready with omissions** remains downloadable.
   Use **Download bundle** to save it locally; sharing is always your own separate action.

The page uses the established Atlaso grid and wizard controls, including keyboard row opening and context-menu actions.
Use **Collect again** to reopen the previous selections for review; it does not silently expand collection scope.
The row context menu offers cancellation while pending/running and confirmed deletion after collection stops.
When JavaScript is unavailable, the page retains a read-only collection; use the CLI for recovery collection.

## Privacy and contents

With anonymization enabled, repeated hostnames become `hostname0001`, `hostname0002`, and so on; usernames become
`user0001`, `user0002`, and so on. The mapping is consistent across the archive and exists only in collector memory.
Each capture starts a new mapping. No original-value mapping or pseudonymization key is written to the archive.
IP and MAC addresses remain unchanged. Replacing hostnames may make literal DNS-name comparison less useful.

Passwords, tokens, authorization headers, cookies, private keys, credential stores, password hashes, terminal contents,
customer payloads, raw databases, environments, process command lines, arbitrary files and arbitrary log messages are
excluded regardless of the anonymization selection. Source exceptions and stderr are never included verbatim.
Sanitization does not guarantee anonymity: these are access-restricted operational records, not public posting material.

The ZIP contains `summary.txt`, `manifest.json`, and structured JSON evidence under `evidence/`. No bundled script needs
to run. The manifest records schema and collector versions, selections, UTC capture times, source provenance, per-item
status, byte counts, and SHA-256 hashes of included evidence. Hashes establish file integrity, not source authenticity.

Collector statuses distinguish success, unavailable, permission denied, truncation, timeout and malformed-source failure.
Missing values remain null or unavailable rather than healthy or zero. Configuration change comparison covers the selected
desired/applied database interface fields only; other runtime changes can occur during this non-atomic capture.
Browser handshake status and close codes cannot be captured from the appliance; collect those separately if needed.

Network evidence preserves desired, last-applied and observed state separately. Nginx evidence projects only known listener
and WebSocket headers from the managed file; it is not a full nginx configuration export. Firewall evidence includes
numeric matches and standard chain policies, with omitted extensions called out. Numeric listener endpoints retain
IPv6 interface zones; invalid endpoint rows are counted as omitted. Logs include classified events rather
than arbitrary text. An unfamiliar failure may therefore require a separate, carefully scoped investigation.

## Recovery CLI

Use an authorized local console or SSH account with read access to the required sources. An administrator may invoke the
installed CLI using the existing operating-system privilege policy. Collection does not depend on a running web server,
worker, writable database, application initialization, credential retrieval, or external connectivity. On Photon, use
the installed absolute path below; the application virtual environment is not on a normal console or SSH shell PATH.

```sh
/opt/atlaso/.venv/bin/atlaso-diagnostics --output /root/support/incident.zip --scope terminal --anonymize
/opt/atlaso/.venv/bin/atlaso-diagnostics --output /root/support/network.zip --scope network --detailed-logs --log-lines 500
```

Prepare an existing private output directory first. The destination must be an absolute new filename; existing files,
symlinks/reparse paths and hard-linked source files are rejected. Output is created mode `0600` on Photon.
The appliance database source is `/var/lib/atlaso/atlaso.db` opened read-only; an absent or busy database is reported as
unavailable. The collector never creates a missing database. Use `--since` and `--until` with timezone-qualified ISO
timestamps for a custom window. `--scope` may be repeated; all options have the same meaning as in the wizard.

Exit code **0** means a completed collection, **2** means a downloadable partial collection, and **1** means failure.
Read the manifest even after code 0: known omissions such as browser-only evidence still apply.
CLI output is under the operator's custody and is not registered for the managed Web UI retention policy.

On Photon, the worker uses fixed privileged helper reads for journals, firewall tables and protected update records.
Missing tools or denied helper access are recorded as omissions; collection never falls back to unrestricted commands.

## Limits and retention

Only administrators may create, inspect, download, cancel or delete Web UI bundles. All administrators can inspect the
managed bundle collection; current permissions are checked for each action, including downloads after permission changes.
Downloads are authenticated, non-cacheable responses, never public/static URLs. Safe audits record creation, download,
cancellation, deletion and expiry without bundle contents or identity mappings.

The managed spool defaults to `/var/lib/atlaso/diagnostics`, mode `0700`, and may be configured by the operator with
`ATLASO_DIAGNOSTICS_SPOOL_PATH`. It must have an existing trusted parent and restrictive ownership/permissions.
One collection runs or waits at a time, with at most 32 requests per 24 hours. Limits are five seconds per command,
60 seconds per capture, 256 KiB per source, 8 MiB of evidence, and 1–2,000 selected journal events per source.
Collection requires at least 16 MiB of free spool space and uses bounded memory before private publication.

Web bundles expire 24 hours after their request time and immediately become unavailable to download. The worker removes
expired terminal artifacts during bounded reconciliation; if the worker is stopped, physical removal resumes when it
returns. Pending or running jobs remain cancellable after the retention deadline so an unavailable worker cannot
leave the collection slot blocked. Cancelling a queued bundle records its finish time and completed progress in Tasks.
Expired downloads also attempt cleanup. An item-specific cleanup failure retains that protected artifact for retry and
storage attention; cleanup continues for the other expired bundles.
Complete factory reset clears the dedicated diagnostic spool before replacing its job records. A spool with an unsafe
path, owner, or permissions or an unrecognized entry blocks reset cleanup so the existing retention records remain
available for recovery. Appliance reset validates ownership against the `atlaso` service account even though reset
itself runs as root. Console reset recovery reads the spool selection from `/etc/atlaso/atlaso.env`, overriding any
console-shell value so custom-spool archives are included in cleanup.
Development-mode reset uses the same cleanup while holding its database writer lock. Finish or cancel any queued or
running diagnostic collection first; development reset does not stop appliance services to quiesce collectors.
Manual deletion affects only the appliance copy. Neither expiry nor deletion promises forensic erasure or removes copies
the operator downloaded or shared. For storage failures, check free space and private-directory permissions, then retry.

See [Backup and restore](backup-restore.md) for LDAP, settings archive and reset actions in the other Maintenance tabs,
and [Diagnostic collector authoring](../contribute/diagnostic-collectors.md) for the source allowlist and extension contract.
