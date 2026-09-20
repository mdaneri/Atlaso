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

This interface capture uses synthetic test data for visual orientation.

![Atlaso Logs desktop layout showing retained-history navigation with synthetic data.](../assets/screenshots/logs-clean-desktop.webp)

*Figure: Logs history controls in the desktop layout with synthetic test data.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Captured application and HTTP history

Supported provisioning and development deployment prepare producer-owned history for App, KMS, and HTTP logs.
App and KMS capture sanitized records in their existing processes. HTTP capture seals the previous Nginx files,
requests the supported reopen operation, and verifies that every Nginx process has released the old files before
importing them. The collector runs every five seconds; new HTTP entries appear after a successful collection.
Accepted history pages keep their original boundaries while newer records arrive.

The initial migration stops the affected producers, preserves the complete retained legacy inventory, verifies its
hashes, and imports it before selecting the new store. App capture uses the existing web and worker processes;
no logging wrapper replaces the worker. Oversized physical entries show an omission notice while their private-key
redaction state continues into subsequent entries. App history retains an 8 MiB window measured in original input
bytes. KMS and HTTP history currently preserve all captured records and sealed raw generations; administrators
must account for their disk growth. Raw migration copies remain protected and are not displayed by the viewer.

A conflicting HTTP rotation configuration prevents activation rather than risking an incomplete import.
A capture failure preserves its durable recovery state. Successfully prepared sanitized records can be recovered
without replaying raw secrets; an interruption before sanitization requires operator investigation and leaves capture
unavailable. Do not delete a selected store or its pending state to resume logging. Existing displayed pages remain
available in the browser when a request fails.

Signed-release migration runs only after the release has committed and before maintenance mode is cleared.
A failure at this stage requires forward recovery, not rollback of the selected history. For first adoption from a
release with the older helper, install the verified new helper through the supported deployment procedure before
starting the signed update: an already-running older helper cannot execute the newly installed completion hook.

## Investigate a problem

The selected source updates automatically every five seconds. **Lines per page** selects 100, 200, or 500 lines
for the live tail and history pages; it never limits the total retained history. The browser remembers this selection.
Unavailable source tabs are disabled,
and a source that becomes unavailable yields to another available tab. Lightweight metadata checks re-enable tabs
when their selected history store or legacy log files become available, without loading inactive log contents.
These checks pause when the page is hidden.
**From beginning** opens its oldest retained entries;
**Next page** and **Previous page** move through the complete retained history in bounded pages. From the live tail,
**Previous page** opens the preceding group directly, including within a multiline journal record. The page size limits
each response, not the total history you can inspect. History controls pause until the requested page arrives,
so repeated activation cannot skip or duplicate pages. Previous remains available while older journal records exist
at every supported page size, and becomes unavailable at the oldest retained journal page. Preparation retries keep
the displayed snapshot or accepted page visible. When the initially selected source recovers from an unavailable state,
its live viewer starts automatically.
File, task, and journal pages include JSON escaping and response metadata in their byte limit.
Private-key headers split between journal records retain redaction state across pages, including filtered views
and oversized-record omissions. Tail and Previous navigation prepare older context in bounded, resumable scans;
the displayed output stays visible while preparation continues.
Sparse DHCP and TFTP tails continue through older bounded journal windows until matching records are found or
retained history is exhausted, even when thousands of unrelated service records follow the latest match.
Writes to newer files do not interrupt a page from an unchanged archive; the reader still verifies the selected
file and older files that determine its redaction state.
If journal retention removes an open cursor, the viewer reopens the oldest available entries and reports the reset.
Permission and other journal errors preserve the current page for a later retry.
Development-mode service refreshes retain the explanation that no host journal is read.
Task history keeps unfinished private-key content concealed until a complete closing marker with the same key label arrives;
unrelated PEM endings, including another private-key type, do not end that redaction state.
File, journal, and task readers retain bounded label fingerprints across fragments. Interleaved opening markers
keep subsequent output concealed when a single matching context cannot be established.
Task capture shares the active private-key label across changed result fields, new log lines, errors, and audit
details. It preserves bounded partial markers within each source when another source interrupts a split header,
and conceals intervening output until the context is complete. Unchanged result fields are recognized by keyed
fingerprints and are not replayed into that state on later log updates. When result fields or their order change,
the current result snapshot is also replayed for redaction, so changing a later footer cannot erase an unchanged
opening marker's protection. Snapshot and incremental concealment are combined before persistence.
Values hidden by a secret field name still advance this state before they are discarded.
Progress and audit-only updates reuse the committed task-result checkpoint without rehashing unchanged log output.
Streaming task producers use `append_task_log_lines` with new lines only (up to 500 lines or 64 KiB per call).
The append shares the producer transaction and redaction state; it does not read or hash earlier cumulative output.
The producer commits or rolls back its task changes and output together. Legacy `result.log_lines` snapshots
remain supported, but changing them requires validating the old prefix; they are unsuitable for repeated streaming updates.
Startup backfill selects only tasks without history checkpoints and rechecks eligibility under the task lock,
so ordinary web and worker restarts do not reprocess retained task output.
File pages retain complete-line boundaries; task and multiline journal cursors retain character-safe continuation.
Numbered file rotations, including compressed archives, are
included and keep nginx sources available even when their current file is absent. Journal history remains subject
to the appliance's journal retention policy. Classified DNS/DHCP/TFTP history also bounds raw scan windows; a window
with no matching rows can still advance to the next retained window while preserving redaction state.
If the initial classified tail has no retained matches, it keeps the original newest cursor and its redaction
context, so a new matching event can appear on the next refresh without replaying the older journal.

**Follow live** resumes new output with one click, including after scrolling up. Scrolling up or selecting text preserves
your reading position and shows when
new output is available. Empty sources remain selectable and populate when their first entries arrive. A connection
failure preserves the displayed page and retries with a bounded delay. After a failed navigation, **From beginning**
and **Follow live** let you abandon the failing position; the freshness indicator identifies stale output.
Closing a viewer, switching sources or hiding the browser suspends its requests. Without JavaScript, the initial
redacted view remains available as a completed snapshot. Retention changes are reported rather
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
inside discarded fragments still update redaction state for following lines and pages. Long marker labels retain
their parser state across read chunks, page boundaries, and retained file rotations using a fixed-size fingerprint
and a bounded partial label block. Opening and closing headers split between files still govern redaction of
subsequent entries.

Live viewers open at the newest retained group. **From beginning** reads earlier history, and **Follow live**
returns to recent output. Tail reads preserve private-key redaction across older entries. Multiple private-key
markers on one line are processed in text order, including when a line closes one block and opens another. If a
retained Atlaso App, KMS, HTTP Access, or HTTP Errors archive needs several read windows, preparation resumes
automatically until the selected
page is ready. Tail discovery and page reads share that prepared archive window. Fixed nginx files use bounded,
version-checked helper reads so preparation survives separate helper invocations. Journal
records larger than 1 MiB use an explicit omission marker and preserve continuation to newer entries.
When an omitted record needs an earlier opening-label context, the reader streams that immutable record again
under the original request deadline; it retains only bounded parser metadata. Backward
navigation also advances across oversized entries, including an unfinished final entry. Multiline journal messages
are paged within the record so each response remains within 500 displayed lines and 1 MiB, including timestamps.
Replacing a file behind an unchanged opening banner invalidates its previous position and reopens retained history.
Slow prefix verification resumes across refreshes while the file version remains unchanged. A further write invalidates
that verification progress so an interior rewrite cannot reuse an earlier redaction decision. Source versions are
checked again after page preparation; a concurrent rewrite discards the candidate page and retries. Reused cursors
also revalidate their redaction state when the retained source version changes.

Standalone VCFDT task-log pages and their live JSON responses disable HTTP caching so refreshes read current output.

Direct service-log pages include a bounded, redacted snapshot before JavaScript starts. If scripting is unavailable,
reload the page to refresh that snapshot. Development mode explains that no host journal was read; an empty or
unavailable source displays its current condition. Full history navigation and live updates require JavaScript.

Local uncompressed log files retain bounded redaction checkpoints in memory. Large initial scans may show a
preparation notice; refreshes resume saved progress instead of restarting. File identity and content fingerprints
validate each reused checkpoint. After size or modification-time changes, the reader hashes every previously
scanned byte before resuming. Matching prefixes preserve progress across appends; interior rewrites invalidate it
even when sampled boundaries are unchanged. Verification remains subject to the request deadline. Process restarts
or cache eviction can require preparation again. Completed task logs keep refreshing while preparation is pending.

While selection or scrolling holds a displayed page, its navigation controls retain the displayed positions.
New lines become navigable only after their page is displayed. Private-key labels may include digits and punctuation.
Service-log HTML snapshots and JSON refreshes both disable caching and vary on the representation header.

Local compressed-history preparation retains at most 32 bounded decompressor checkpoints in process memory.
Each step reads at most 16 KiB of compressed input and expands at most 64 KiB. Later requests resume immutable
archives, including concatenated gzip members, while a newer file grows. Archive identity, size, or modification-time
changes invalidate that progress. A growing plain file after those archives uses full-prefix authentication to
retain its own progress, including after older checkpoints leave the bounded cache. This does not change the
privileged helper's compressed-file reader.

Live pages and initial snapshots share the same sensitive configuration-key vocabulary, including dotted key names.

Task history also retains Network cleanup retry diagnostics in the same transaction as the task result update.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Logs

![Atlaso Logs responsive layout showing retained-history navigation with synthetic data.](../assets/screenshots/logs-clean-responsive.webp)

*Figure: Logs history controls in the responsive layout with synthetic test data.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
