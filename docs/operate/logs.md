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

The selected source updates automatically every five seconds. **Lines per page** selects 100, 200, or 500 lines
for the live tail and history pages; it never limits the total retained history. The browser remembers this selection.
Unavailable source tabs are disabled,
and a source that becomes unavailable yields to another available tab. Lightweight metadata checks re-enable tabs
when their log files appear, without loading inactive log contents. These checks pause when the page is hidden.
**From beginning** opens its oldest retained entries;
**Next page** and **Previous page** move through the complete retained history in bounded pages. From the live tail,
**Previous page** opens the preceding group directly, including within a multiline journal record. The page size limits
each response, not the total history you can inspect. Previous is unavailable at the oldest retained journal page.
File, task, and journal pages include JSON escaping and response metadata in their byte limit.
File pages retain complete-line boundaries; task and multiline journal cursors retain character-safe continuation.
Numbered file rotations, including compressed archives, are
included and keep nginx sources available even when their current file is absent. Journal history remains subject
to the appliance's journal retention policy. Classified DNS/DHCP/TFTP history also bounds raw scan windows; a window
with no matching rows can still advance to the next retained window while preserving redaction state.

**Follow live** resumes new output with one click, including after scrolling up. Scrolling up or selecting text preserves
your reading position and shows when
new output is available. Empty sources remain selectable and populate when their first entries arrive. A connection
failure preserves the displayed page and retries with a bounded delay; the freshness indicator identifies stale output.
Closing a viewer, switching sources or hiding the browser suspends its requests. Retention changes are reported rather
than silently continuing a position in a different file.

Task Log dialogs and standalone download logs use the same controls. Completed tasks receive a final trailing read
before automatic refresh stops, including while browsing older pages and for `no-op` and `partial-failure` outcomes.
Manual history navigation remains available afterward. Only retained output is available:
entries removed by retention or never captured by
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

DNS, DHCP, and TFTP are classified before each journal page is limited, so a quiet protocol's recent history remains
visible even after many newer entries from another protocol. Redaction state is preserved across those skipped records.

## Next steps

Logs are evidence, not an enforcement surface. Correct desired state in the owning service page and submit it through
[Appliance Apply](appliance-apply.md). For local recovery when the web UI is unavailable, use the
[local appliance console](appliance-console.md).

Physical file entries larger than 64 KiB are represented by an explicit omission marker. The reader advances through
them in bounded pages so later entries remain reachable; omitted entry contents are not exposed. Private-key markers
inside discarded fragments still update redaction state for following lines and pages.

Live viewers open at the newest retained group. **From beginning** reads earlier history, and **Follow live**
returns to recent output. Tail reads preserve private-key redaction across older entries. Multiple private-key
markers on one line are processed in text order, including when a line closes one block and opens another. If a
retained archive cannot be scanned within the read deadline, use **From beginning** to read it in pages. Journal
records larger than 1 MiB use an explicit omission marker and preserve continuation to newer entries. Backward
navigation also advances across oversized entries, including an unfinished final entry. Multiline journal messages
are paged within the record so each response remains within 500 displayed lines and 1 MiB, including timestamps.
Replacing a file behind an unchanged opening banner invalidates its previous position and reopens retained history.

Standalone VCFDT task-log pages and their live JSON responses disable HTTP caching so refreshes read current output.

Direct service-log pages include a bounded, redacted snapshot before JavaScript starts. If scripting is unavailable,
reload the page to refresh that snapshot. Development mode explains that no host journal was read; an empty or
unavailable source displays its current condition. Full history navigation and live updates require JavaScript.

Local uncompressed log files retain bounded redaction checkpoints in memory. Large initial scans may show a
preparation notice; refreshes resume saved progress instead of restarting. File identity and content fingerprints
validate each reused checkpoint. Any size or modification-time change discards cached state, including apparent
appends, because growth alone cannot prove that earlier bytes were preserved. Process restarts or cache eviction
can require preparation again. Completed task logs keep refreshing while preparation is pending.

While selection or scrolling holds a displayed page, its navigation controls retain the displayed positions.
New lines become navigable only after their page is displayed. Private-key labels may include digits and punctuation.
Service-log HTML snapshots and JSON refreshes both disable caching and vary on the representation header.

Local compressed-history preparation retains at most 32 bounded decompressor checkpoints in process memory.
Each step reads at most 16 KiB of compressed input and expands at most 64 KiB. Later requests resume immutable
archives, including concatenated gzip members, while a newer file grows. Archive identity, size, or modification-time
changes invalidate that progress. This does not change the privileged helper's compressed-file reader.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Logs

![Atlaso Logs page in the clean-appliance responsive viewport.](../assets/screenshots/logs-clean-responsive.webp)

*Figure: Logs in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
