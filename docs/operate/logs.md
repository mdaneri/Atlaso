---
title: Operational logs
description: Filter and review sanitized Atlaso runtime logs without changing appliance state.
audience:
  - operator
  - maintainer
status: current
---

# Operational logs

Open **Logs** for read-only application and appliance diagnostics. Use the page to narrow an incident by time, severity,
source, and message before moving to a service-specific verification step.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Logs page in the clean-appliance desktop viewport.](../assets/screenshots/logs-clean-desktop.webp)

*Figure: Logs in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Investigate a problem

The selected source updates automatically every five seconds. **From beginning** opens its oldest retained entries;
**Next page** and **Previous page** move through the complete retained history in bounded pages. The page size limits
each response, not the total history you can inspect. Numbered file rotations, including compressed archives, are
included. Journal history remains subject to the appliance's journal retention policy.

**Follow live** advances to new output. Scrolling up or selecting text preserves your reading position and shows when
new output is available. Empty sources remain selectable and populate when their first entries arrive. A connection
failure preserves the displayed page and retries with a bounded delay; the freshness indicator identifies stale output.
Closing a viewer, switching sources or hiding the browser suspends its requests. Retention changes are reported rather
than silently continuing a position in a different file.

Task Log dialogs and standalone download logs use the same controls. Completed tasks receive a final trailing read
before automatic refresh stops. Only retained output is available: entries removed by retention or never captured by
the producing command cannot be recovered by the viewer. Downloaded log files are snapshots taken at download time.

1. Set a narrow time window around the observed failure.
2. Filter by severity and the affected Atlaso component.
3. Correlate task identifiers with [Tasks](tasks.md) and operator actions with the [Audit log](audit-log.md).
4. Record the smallest sanitized excerpt that explains the failure.

The UI intentionally avoids presenting credentials and secret-bearing command lines. If a log entry appears to contain
sensitive data, do not publish it; follow the private process in the repository security policy.

IP addresses, MAC addresses, hostnames, and account names are not sensitive by themselves in Atlaso. Passwords, tokens,
authenticated URLs, session material, private keys, password hashes, credential verifiers, and other secret-bearing
data remain sensitive. Content-integrity hashes of non-secret material and one-way change-detection hashes of
encrypted-at-rest ciphertext do not. Review the complete excerpt before sharing it because authentication or
cryptographic context can make an otherwise ordinary identifier sensitive. This classification does not make
authenticated logs public or override site handling policy.

## Next steps

Logs are evidence, not an enforcement surface. Correct desired state in the owning service page and submit it through
[Appliance Apply](appliance-apply.md). For local recovery when the web UI is unavailable, use the
[local appliance console](appliance-console.md).

Physical file entries larger than 64 KiB are represented by an explicit omission marker. The reader advances through
them in bounded pages so later entries remain reachable; omitted entry contents are not exposed.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Logs

![Atlaso Logs page in the clean-appliance responsive viewport.](../assets/screenshots/logs-clean-responsive.webp)

*Figure: Logs in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
