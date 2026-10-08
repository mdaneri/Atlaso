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

## Before you begin

Choose an eligible addressed access or route interface, or enabled VLAN, for each listener. Management-role interfaces
and trunk physical interfaces are not public reverse-proxy listeners. Confirm that the upstream host and port are
reachable from the appliance and that its name resolves to the intended upstream. Use HTTPS when the upstream supports
it; HTTP sends the application traffic without TLS protection between Atlaso and the upstream.

The permission-gated Add action remains available in both empty and populated fallback collections when the grid
cannot load; it opens the same review wizard as the normal grid.

Reverse proxies preserve the application’s own authentication. Atlaso forwards the selected paths and manages the
forwarded host, client address, protocol, and WebSocket upgrade headers. The editor does not accept arbitrary headers,
authentication bypasses, or raw nginx directives.

The appliance accepts at most 256 proxies, 256 total path routes, and 256 selected listener/route combinations.
A route selected on four listener addresses counts as four combinations. Disabled proxies retain these capacity
reservations so enabling saved state cannot exceed the generated publication bound.

Exclusive Atlaso services cannot take a socket used by an enabled proxy. Service settings saves reject this conflict
before changing desired state; move or disable the proxy first. Matching HTTP or HTTPS virtual hosts can share nginx
sockets, but HTTP and HTTPS cannot occupy the same socket. API settings writers return **409 Conflict** for this case.
Service hostname edits also preserve saved proxy names and upstream targets, including disabled proxy intent.
Disable HTTPS proxies before disabling their CA. Conflicting service or CA changes are rejected without saving them.

Interface edits also reject changes that remove an enabled proxy's exact interface and address binding.
Disable or move the proxy before changing its address, renaming or deleting its VLAN, or making its parent unavailable.
Rejected edits preserve the interface, proxy, and owned DNS records together.
Host inventory refresh disables proxies tied to renamed or missing NICs and their child VLANs in the same transaction.
Saved exact listener tuples remain unchanged for explicit review; inventory refresh never silently rebinds a proxy.
Review the warning, select the current listener tuples, and re-enable the proxy before applying publication.

## Create a reverse proxy

Open **Traffic Publishing**, select **Reverse Proxies**, and choose **Add reverse proxy**. The wizard has six steps:
If the grid cannot load, the empty fallback table retains **Add reverse proxy** for permitted writers.
The health fallback also shows the latest bounded observations after **Refresh health**.

1. **Identity**: enter a unique **Name** and **Hostname**. Add a **Description** to record the application's purpose.
   Atlaso reserves its own service hostnames, including the explicit or default authoritative DNS primary hostname.
   These names cannot be used as upstream targets either. Identity rejects invalid fully qualified hostnames before Next.
2. **Listener**: select one or more exact **Listener addresses**, then choose the **Listener scheme** and **Listener
   port**. A shared nginx address and port can serve only one protocol. HTTPS uses an Atlaso CA-managed certificate for
   the hostname; its private key is not shown in the editor. Enable the CA before saving an enabled HTTPS proxy.
   Disabled HTTPS intent can be saved while the CA is disabled.
   Optionally enable **Redirect HTTP to HTTPS** and choose the **Redirect listener port**. The redirect applies only to
   the selected listener addresses and port.
3. **Routes**: add one or more path routes. Set an absolute **Path prefix**, upstream HTTP or HTTPS **Upstream
   scheme**, **Upstream host or IP**, and **Upstream port**. Choose whether to **Preserve prefix** or **Strip prefix**.
   Routes rejects invalid upstream DNS names or IP literals before Review; enter the port in its separate field.
   Route prefixes must not overlap one another or reserved Atlaso and machine paths.
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
   This setting is independent of direct access: hiding the card does not disable the configured proxy. **Manage
   authoritative DNS** is a separate opt-in. When enabled and Atlaso authoritative DNS can serve the hostname, Atlaso
   reconciles its A and AAAA records to the selected listener addresses. Otherwise, create those records in your
   external DNS service. Existing operator DNS records for the same name, including a different letter case or final
   dot, prevent managed publication; resolve the conflict without deleting unrelated records. Ordinary DNS create,
   edit, and bulk import operations also reject these alternate spellings of proxy-owned names.
5. **State**: **Proxy enabled** defaults off. Turn it on to include the proxy in validated desired state.
6. **Review**: check the identity, listener, path routes, publication, and desired state, including any TLS warnings.
   Choose **Save reverse proxy** to save the desired state.

Saving changes desired state only. Review the changed units in **Review appliance changes**, select the applicable
units, and submit **Submit appliance changes**. Appliance Apply validates and publishes the proxy together with its
listener, certificate, firewall, DNS, and Public Services changes. The route becomes active only after the complete
apply succeeds.

## Verify runtime behavior

The transport worker publishes cached route health after each batch, pausing 30 seconds between full cycles, with at most
eight probes running at once. Every route retains its own observation time; samples older than 90 seconds are unavailable
even when another batch has just published. Each probe sends `HEAD` to the configured public hostname and route path and
keeps no response body. Fingerprint trust checks
the SHA-256 digest of the leaf certificate on the connected upstream TLS session before forwarding data. Insecure TLS
verification is always reported as degraded, even when an HTTP status is returned. These observations are operational
signals, not proof that an application's complete workflow works.

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
A restore changes desired state only and still requires global Appliance Apply.
Archives with an enabled HTTPS proxy require an enabled CA; restore rejects this inconsistent relationship before
replacing saved state. Disabled HTTPS intent and enabled HTTP proxies remain portable without an enabled CA.
Preflight also reserves service names that factory-default identity migration will create under the restored appliance
domain, including ESXi PXE, before replacing any saved rows. Operator-chosen service names remain unchanged.

<!-- ATLASO-REVERSE-PROXY-ACCEPTANCE-PENDING -->
## Native appliance acceptance pending

The operator workflow remains **roadmap** until a native appliance run verifies listener and path isolation, HTTP
redirect behavior, managed HTTPS certificates, every-connection fingerprint enforcement, visible insecure-mode
warnings, normal application authentication, WebSocket traffic, coordinated Firewall/DNS/Public Services publication,
rollback, and state after reboot. Remove this section and change the page status to `current` only after that evidence
has been recorded.
