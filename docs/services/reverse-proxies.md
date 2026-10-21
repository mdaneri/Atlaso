---
title: Reverse Proxies
description: Configure path-based public reverse proxies through the global appliance change workflow.
audience:
  - operator
status: roadmap
---

# Reverse Proxies

This page describes the planned operator workflow for issue #723. The feature remains roadmap work until native appliance
acceptance is complete; this guide does not claim that the described behavior is available on a released appliance.

The API saves complete desired state at `/api/v1/traffic-publishing/reverse-proxies`; create and replace include the
complete ordered route collection. Reads require `read:firewall`; mutations require `write:firewall`. `GET
/api/v1/traffic-publishing/reverse-proxies/health` compares saved intent with the helper's applied snapshot and reports
cached per-route observations. It does not probe the upstream on a browser or API request; missing, stale, or mismatched
evidence remains unavailable or pending.
Public directory cards use a 15-second cache of validated applied intent, including failed observations, with only one
helper refresh admitted at a time. Cached evidence still expires at its original observation age; applied baseline
changes and Apply completion invalidate it. CA and depot admission checks do not load proxy cards or invoke this observer.

## Before you begin

Choose an eligible addressed access or route interface, or enabled VLAN, for each listener. Management-role interfaces
and trunk physical interfaces are not public reverse-proxy listeners. Confirm that the upstream host and port are
reachable from the appliance and that its name resolves to the intended upstream. Use HTTPS when the upstream supports
it; HTTP sends the application traffic without TLS protection between Atlaso and the upstream.
Literal upstreams must not match any desired or observed appliance address, including every preferred automatic
IPv6 address retained during prefix renumbering.

The permission-gated Add action remains available in both empty and populated fallback collections when the grid
cannot load; it opens the same review wizard as the normal grid.

Reverse proxies preserve the application’s own authentication. Atlaso forwards the selected paths and manages the
forwarded host, client address, protocol, and WebSocket upgrade headers. The editor does not accept arbitrary headers,
authentication bypasses, or raw nginx directives.

The appliance accepts at most 256 proxies, 256 total path routes, and 256 selected listener/route combinations.
A route selected on four listener addresses counts as four combinations. Disabled proxies retain these capacity
reservations so enabling saved state cannot exceed the generated publication bound.
The generated nginx configuration sizes its server-name hash for accepted 253-character names on shared sockets.
Protected management handoffs retain those canonical hash settings once alongside old and new proxy listeners.
Firewall validation and legacy API Firewall Apply retain the same exact-address proxy and redirect admissions.

Exclusive Atlaso services cannot take an address and port used by an enabled proxy, even on another interface.
Service settings saves reject this conflict
before changing desired state; move or disable the proxy first. Matching HTTP or HTTPS virtual hosts can share nginx
sockets only when every virtual host selects the same interface scope for that address and port. HTTP and HTTPS cannot
occupy the same address and port even across different interfaces. Management front doors, including enabled
Management UI exposure on access interfaces and VLANs, participate in the same scope comparison. A proxy cannot share
a management address and port through a different interface selection, even when duplicate-address checks are disabled.
Every observed management IPv4 address participates, including secondary addresses on static or DHCP interfaces.
Management HTTPS certificate IP SANs, appliance DNS records and applied DNS source tracking include the same addresses;
withdrawn observations are retired without removing operator-owned records.
Runtime address observations remain excluded from portable settings archives. Restore preflight checks the target
appliance's observed management and Web Terminal socket scopes before replacing desired state, including newly
selected terminal interfaces. Conflicting enabled proxies are rejected; disabled intent remains inactive.
Web Terminal HTTPS selections include secondary observed IPv4 and preferred automatic IPv6 addresses.
CA browser HTTP/HTTPS, and Depot, Registry and Network Boot directory HTTP ingress
participate too, including directory port 80 when the service uses a custom protocol port. Appliance Settings saves and
archive preflight reject conflicting terminal selections before changing settings, proxies or audit records.
API settings writers return **409 Conflict** for this case.
Service hostname edits also preserve saved proxy names and upstream targets, including disabled proxy intent.
NFS share create and retarget operations validate generated storage aliases under the same writer lock.
Interface-named NFS aliases remain reserved while their interface is down, missing or unaddressed.
Conflicting API and UI saves return 409 without changing the share, DNS records or audit history.
Disable HTTPS proxies before disabling their CA. Conflicting service or CA changes are rejected without saving them.

Interface edits also reject changes that remove an enabled proxy's exact interface and address binding.
VLAN create, edit and enable operations also recheck service and management socket scopes before saving, including
Management UI exposure introduced on a duplicate address. Rejected changes preserve the prior VLAN and proxy state.
Physical-interface and VLAN writers also reject assigning an enabled proxy's literal upstream address to the appliance,
even when the changed interface is unrelated to the proxy's listeners. Disable or move that upstream first.
Disable or move the proxy before changing its address, renaming or deleting its VLAN, or making its parent unavailable.
Rejected edits preserve the interface, proxy, and owned DNS records together.
Interface edits also validate the final rebased service listeners before committing; disabling duplicate-address checks
does not permit a native service to take an enabled proxy's socket.
PXE HTTP and a proxy can use the same port on distinct addresses. Sharing an exact socket still requires compatible
HTTP publication and the same interface ownership; HTTPS cannot take the PXE HTTP socket.
DHCP reservation create and edit reject proxy-owned DNS names, including short names expanded by their scope.
Network Boot host reservation and DNS synchronization uses the same saved-name guard under the shared writer lock,
including when a proxy record has not yet been published because its authoritative zone is disabled or unserved.
Enabled managed-DNS proxies reserve their names even while authoritative DNS is disabled or cannot serve their zone.
Ordinary DNS create, edit, hosts import, and zone import enforce the same reservation before changing any rows.
The reservation and generated DNS changes remain atomic; ownership conflicts return **409 Conflict**.
Legacy DNS, DHCP and Firewall Apply endpoints return **409 Conflict** while proxy publication is pending. Use global
Appliance Apply so the proxy listener and its DNS records publish together. Management DNS provenance includes every
observed IPv6 address, so address changes retire secondary AAAA records and their generated PTR records together.
When an applied native service owns a
replacement proxy's socket, review its shutdown with the proxy changes; the service stops before nginx activates.
Registry handoffs account for every applied listener address, including non-first addresses in a multi-address binding.
For an enabled service moving to another socket, keep the replacement proxy disabled, apply the service move first,
then enable and apply the proxy. Disabled intent can be saved or edited while its primary or redirect socket is
occupied; enabling it rechecks service, port-forward, and peer proxy socket ownership before saving. This preserves certificate setup and listener release ordering.
When a native service takes a disabled or moved proxy's still-applied socket, review Public Services with that service.
The protected publication releases nginx's old listener before the service starts. A served hostname also cannot claim
a peer route's upstream hostname, including disabled peer intent, because that would redirect the peer's backend DNS.
Host inventory refresh disables proxies tied to renamed or missing NICs and their child VLANs in the same transaction.
Saved exact listener tuples remain unchanged for explicit review; inventory refresh never silently rebinds a proxy.
Review the warning, select the current listener tuples, and re-enable the proxy before applying publication.

## Create a reverse proxy

If the grid cannot initialize, the fallback table keeps **Edit** and **Delete** available to writers. **Delete**
uses the same confirmation and desired-state removal flow as the grid menu; runtime retirement requires global
Appliance Apply.

Open **Traffic Publishing**, select **Reverse Proxies**, and choose **Add reverse proxy**. The wizard has six steps:
If the grid cannot load, the empty fallback table retains **Add reverse proxy** for permitted writers.
The health fallback also shows the latest bounded observations after **Refresh health**.
The collection count follows saved create and delete results. Validation shows **review warnings** when warnings
remain without errors, including before browser scripts run; review these warnings before global Appliance Apply.

1. **Identity**: enter a unique **Name** and **Hostname**. Add a **Description** to record the application's purpose.
   Atlaso reserves its own service hostnames, generated interface/address targets, retained app-owned DNS aliases,
   and the explicit or default authoritative DNS primary hostname, including while authoritative DNS is disabled.
   Selected service targets remain reserved while
   their bindings are unavailable. These names cannot be used as upstream targets either. Identity rejects invalid
   fully qualified hostnames and IP literals before Next.
2. **Listener**: select one or more exact **Listener addresses**, then choose the **Listener scheme** and **Listener
   port**. A shared nginx address and port can serve only one protocol. HTTPS uses an Atlaso CA-managed certificate for
   the hostname; its private key is not shown in the editor. Enable the CA before saving an enabled HTTPS proxy.
   Disabled HTTPS intent can be saved while the CA is disabled.
   Optionally enable **Redirect HTTP to HTTPS** and choose the **Redirect listener port**. The redirect applies only to
   the selected listener addresses and port. The Listener step requires different HTTPS and HTTP redirect ports.
3. **Routes**: add up to 64 path routes; the wizard rejects extra routes before Review. Set an absolute **Path prefix**,
   upstream HTTP or HTTPS **Upstream
   scheme**, **Upstream host or IP**, and **Upstream port**. Choose whether to **Preserve prefix** or **Strip prefix**.
   Routes rejects invalid upstream DNS names or IP literals before Review; enter the port in its separate field.
   Upstream literals must be ordinary unicast addresses, excluding loopback, link-local, multicast, unspecified,
   reserved and IPv4-mapped IPv6 addresses. Legacy shortened, octal and hexadecimal numeric spellings are rejected
   on Identity and Routes and during desired-state save or archive restore; use canonical IP literals for upstreams.
   Route prefixes must not overlap one another or reserved Atlaso and machine paths. The 1024-character limit counts
   Unicode code points, including one character per astral symbol. Strip prefixes without a trailing slash also
   require their escaped rewrite parameter to fit within 4000 UTF-8 bytes; shorten the prefix if that limit is exceeded.
   Atlaso reserves protocol roots, including favicon, certificate downloads, OAuth/OpenID/OIDC, and the `/PROD` prefix;
   catch-all application routes reject requests for these namespaces before forwarding them upstream.
   The Routes step rejects encoded
   paths, repeated slashes, dot segments, whitespace, backslashes, and configuration delimiters before Review.
   For HTTPS upstreams, choose
   **HTTPS upstream trust**:
   - **Trusted CA validation** uses the system's trusted certificate authorities.
   - **Exact SHA-256 fingerprint** pins the upstream leaf certificate on each TLS connection. Enter the expected
     certificate digest in **SHA-256 fingerprint**.
   - **Insecure certificate verification** disables certificate verification. Atlaso marks this choice with a warning
     in validation, configuration previews, and operational status. Use it only when you accept the risk of an
     unverified upstream identity.

   The defaults are 5 seconds for **Connection timeout**, 60 seconds each for **Read timeout** and **Send timeout**,
   and 16 MiB for **Maximum request body**. The timeouts accept 1–30 seconds for connection and 1–300 seconds for read
   and send; request bodies accept 1 byte–1 GiB. Adjust them for the application's expected connection and transfer
   behavior.
   WebSocket traffic uses the same path mapping and managed upgrade headers.
4. **Publication**: enable **Publish in Public Services** to show a service card on matching public listener views.
   Cards follow the applied proxy snapshot. Pending edits, failed Apply, and rollback retain the previous links;
   successful Apply updates or retires them. Cards are hidden when bounded applied-runtime evidence is unavailable.
   Cards require the selected interface and address together. If several interfaces share the called address, Atlaso
   hides proxy cards because the directory cannot determine which interface received the request.
   This setting is independent of direct access: hiding the card does not disable the configured proxy. **Manage
   authoritative DNS** is a separate opt-in. When enabled and Atlaso authoritative DNS can serve the hostname, Atlaso
   reconciles its A and AAAA records to the selected listener addresses. Otherwise, create those records in your
   external DNS service. Existing operator DNS records for the same name, including a different letter case or final
   dot, prevent managed publication; resolve the conflict without deleting unrelated records. Ordinary DNS create,
   edit, and bulk import operations also reject these alternate spellings of proxy-owned names.
5. **State**: **Proxy enabled** defaults off. Turn it on to include the proxy in validated desired state.
6. **Review**: check the identity, listener, path routes, publication, and desired state, including any TLS warnings.
   Choose **Save reverse proxy** to save the desired state.

Saving or deleting updates the collection and validation preview from the returned response. If the completed result
cannot be displayed, refresh the page before saving again.

Saving changes desired state only. Review the changed units in **Review appliance changes**, select the applicable
units, and submit **Submit appliance changes**. Appliance Apply validates and publishes the proxy together with its
listener, certificate, firewall, DNS, and Public Services changes. The route becomes active only after the complete
apply succeeds.

## Verify runtime behavior

The transport worker publishes cached route health after each batch, pausing 30 seconds between full cycles, with at most
64 probes running at once. At the 256-route limit, four batches with ten-second probe deadlines and the pause have a
70-second budget, leaving margin for scheduling and publication within the freshness window. Every route retains its
own observation time; samples older than 90 seconds are unavailable even when another batch has just published.
Temporary health-cache write failures retain the last atomic publication and do not stop sampling. The worker retries
on the next bounded batch or cycle; retained observations still expire normally until publication recovers.
Each probe sends `HEAD` to the configured public hostname and route path and
keeps no response body. Fingerprint trust checks
the SHA-256 digest of the leaf certificate on the connected upstream TLS session before forwarding data. Insecure TLS
verification is always reported as degraded, even when an HTTP status is returned. These observations are operational
signals, not proof that an application's complete workflow works.

Stripping `/app` or `/app/` from `/app/value` sends `/value` upstream with the original query arguments.
A request matching the complete strip prefix maps to `/`; the mapping adds no extra leading slash.

An applied ESXi PXE HTTP listener is a socket owner too. Review its shutdown with Public Services before an HTTPS proxy
takes that socket. Move an enabled PXE listener in a separate Apply while the replacement proxy stays disabled.
If PXE takes an applied proxy socket, review Public Services with PXE so the old proxy listener retires first.

After a successful appliance apply, test the configured hostname, scheme, port, and path from an authorized client on
each selected listener. Confirm both path-prefix behaviors as configured, the upstream application's normal sign-in and
authorization behavior, and a WebSocket connection when the application uses one. For an HTTP-to-HTTPS redirect,
confirm that the selected HTTP listener redirects to the configured HTTPS hostname and port. Check **Reverse Proxy
Health** after choosing **Refresh health**; it reads the latest cached status and reports the last successful probe,
failure class, HTTP status, TLS status, applied/pending state, and any warning without returning response bodies.
Refreshing the page does not trigger another upstream probe.

If validation fails, correct the listed desired-state error before applying again. If publication or readiness fails,
review the appliance-apply task and its recovery result. Do not edit generated nginx files or bypass the global apply
workflow.

Settings archives retain proxy and ordered route desired state. They do not carry active transport generations, cached
health observations, or proxy-owned CA certificate rows and their private keys. Preserve the appliance secrets key with
recovery material; global CA and Public Services Apply regenerate the proxy certificate from restored desired state.
Long proxy hostnames remain complete in the managed certificate's DNS SAN and nginx server name. When the hostname
exceeds the certificate subject common-name limit, Atlaso uses a bounded display name for that subject field.
Apply comparison retains a digest of the complete proxy intent, including disabled names and descriptions, while
configuration previews keep sensitive text redacted. This comparison also selects the protected handoff when an
edit is hidden by preview redaction. The digest covers only the canonical proxy snapshot, outside shared credential previews.
A restore changes desired state only and still requires global Appliance Apply. Preflight renders the complete proxy
collection, including disabled intent, and rejects publication metadata above the ordinary save size limit before
replacing any saved rows.
Restore also checks the flushed publication with its database-assigned proxy and route IDs before committing.
If those IDs make the configuration exceed the size limit, the whole restore rolls back and retains staged recovery data.
Archives with an enabled HTTPS proxy require an enabled CA; restore rejects this inconsistent relationship before
replacing saved state. Disabled HTTPS intent and enabled HTTP proxies remain portable without an enabled CA.
Preflight also reserves service names that factory-default identity migration will create under the restored appliance
domain, including ESXi PXE, before replacing any saved rows. The database-bound preflight also reserves service aliases
from the target appliance’s observed automatic addresses on the restored interfaces. Rejection preserves saved state
and audit records. Automatic listener rebasing checks the same ownership under the Network Objects writer lock before
publishing aliases; a conflict preserves cached listeners and DNS while retaining the new observation for diagnosis.
Startup defers that refresh with a warning; the Apply preview remains available with validation errors until the proxy
conflict is repaired.
Native interface inventory also checks management and Web Terminal browser ingress against each enabled proxy's
exact saved interface scope before committing observations. A duplicate secondary address that broadens that scope
rejects and rolls back the inventory transaction. Remove the duplicate address or move the proxy before retrying;
no proxy is silently rebound. Ordinary service inspection checks alias ownership without requiring an enabled CA,
while service mutation continues to enforce HTTPS CA dependencies.
Operator-chosen service names remain unchanged.

<!-- ATLASO-REVERSE-PROXY-ACCEPTANCE-PENDING -->
## Native appliance acceptance pending

The operator workflow remains **roadmap** until a native appliance run verifies listener and path isolation, HTTP
redirect behavior, managed HTTPS certificates, every-connection fingerprint enforcement, visible insecure-mode
warnings, normal application authentication, WebSocket traffic, coordinated Firewall/DNS/Public Services publication,
rollback, and state after reboot. Remove this section and change the page status to `current` only after that evidence
has been recorded.

Create, edit and archive restore check actual database-assigned proxy and route identities against their separate
helper limits before committing, including disabled proxies. An exhausted retained sequence rejects the entire
operation without replacing desired state or audit records; restore also retains recovery payloads.

Insecure upstream routes remain degraded and retain their TLS policy warning. Connectivity, timeout and HTTP failures
remain visible in health details instead of being replaced by that policy warning.
