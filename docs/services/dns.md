---
title: DNS
description: Configure Atlaso DNS desired state, authoritative zones, records, and validation.
audience:
  - operator
status: current
---

# DNS

Atlaso manages DNS desired state through dnsmasq. Editing settings, zones, or records changes the control-plane database
and the global DNS/DHCP preview; it does not mutate the appliance until an operator submits the `DNS/DHCP (dnsmasq)`
unit through Appliance Apply.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso DNS page in the clean-appliance desktop viewport.](../assets/screenshots/dns-clean-desktop.webp)

*Figure: DNS in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

Select **+ Domain** to create a forward domain through the guided identity, enablement, and review steps. Each domain
identity includes a full-width multiline description. The selected domain tab presents that description as its heading
and keeps the DNS suffix in the supporting line. Each domain places its direct enablement switch at the right of the
**Records**, **Import Hosts**, and **Import Zone File** tab row. Disabling a domain retains the domain and all scoped
records in Atlaso's
database while excluding that zone from rendered dnsmasq desired state; at least one domain must remain enabled.

## Local and authoritative modes

With **Authoritative** off, each managed domain renders as `local=/domain/`. Atlaso answers known local records and
forwards other queries to the configured upstream or conditional forwarders. Existing newline-delimited `domain` API
values remain supported.

When the management interface uses DHCP and no upstream is saved explicitly, Atlaso uses the non-loopback DNS servers
from that interface's active systemd-networkd lease. This lease fallback remains authoritative after the appliance
resolver has been redirected to local dnsmasq and `resolvectl` therefore reports only `127.0.0.1`; applying DNS must not
regenerate dnsmasq without the DHCP-provided forwarders.

With **Authoritative** on, every managed forward domain renders as `auth-zone=domain`. dnsmasq has service-level
authoritative settings, so all managed zones share one primary nameserver, SOA administrator, TTL, refresh, retry,
expiry, and serial. v1 does not configure secondary nameservers, AXFR, or a separate DNS server. Generated reverse zones
remain normal dnsmasq PTR behavior rather than authoritative reverse zones.

The authoritative renderer emits:

- `auth-server` for the configured primary nameserver and every selected DNS interface;
- one `auth-zone` per managed forward domain;
- shared `auth-soa` and `auth-ttl` values;
- A/AAAA `host-record` glue mapping the primary nameserver to every selected DNS listen address.

The primary nameserver must belong to a managed domain. Its glue identity is generated and cannot conflict with operator
CNAME or A/AAAA data. SOA expiry must be greater than refresh and retry, and all timer values must be positive 32-bit
seconds.

dnsmasq treats interfaces named by `auth-server` as authoritative-only destinations. Those selected DNS listeners return
complete authoritative SOA, NS, glue, positive-record, and negative-SOA responses, but intentionally return `REFUSED`
for unrelated recursive queries and non-authoritative reverse zones. The same dnsmasq process retains ordinary local/PTR
and upstream-recursive service on listeners not named by `auth-server`, including appliance loopback. This service-level
boundary is why v1 cannot provide authority and recursion on the same address and port.

## Generated zone records and serial

Each forward-zone summary and zone-file export shows the generated apex SOA and NS records plus nameserver glue. The
summary uses compact typography so the structural values remain subordinate to the editable records collection. These
records are structural and read-only; they are not available in the ordinary record-type selector or stored as duplicate
DNS record rows.

Atlaso owns one shared monotonic SOA serial. Zone creation/deletion, record create/update/delete/import,
generated-record changes, and authoritative settings or listen-target changes advance it. The serial is exposed
read-only in the UI and public DNS settings response and is included in backup/restore and desired-state comparisons.

## Factory service identities

Factory-derived service names use the domain portion of the canonical appliance FQDN. For example, an appliance FQDN
of `atlaso.lab.internal` produces `ca.lab.internal`, `kms.lab.internal`, `ldap.lab.internal`, `ntp.lab.internal`,
`oidc.lab.internal`, `nfs.lab.internal`, `esxi-pxe.lab.internal`, `registry.lab.internal`, and
`depot.lab.internal`. Fresh seed, OVF first boot, factory reset, settings restore, and later appliance-domain changes
all use this rule.

When the appliance domain changes, Atlaso migrates only a packaged default or the exact factory name under the
immediately previous appliance domain. A different service hostname is treated as operator-owned and remains unchanged.
Atlaso renames or removes only DNS rows carrying that service's exact app-owned marker, including generated IPv4 and
IPv6 targets. If the destination name already has an operator-owned record of the same type, Atlaso preserves the
operator record and removes the stale app-owned alias instead of overwriting it. The affected service and DNS desired
state remain pending until submitted through Appliance Apply.

## Zone-file import and export

Zone-file export includes `$ORIGIN`, `$TTL`, generated SOA/NS/glue, and all enabled operator records. Import supports A,
AAAA, CNAME, TXT, SRV, MX, CAA, and PTR records. Matching SOA, NS, and glue are accepted and ignored rather than
persisted. Conflicting structural metadata is rejected with guidance to change Authoritative DNS settings. Import
remains scoped to the selected managed domain.

## Apply and verification

Review the DNS validation card and rendered config, then submit only the global DNS/DHCP unit when that is the intended
changed unit. The helper stages and validates `/var/lib/atlaso/apply/dnsmasq/atlaso.conf`, installs
`/etc/atlaso/dnsmasq.d/atlaso.conf`, and reloads or restarts `dnsmasq.service`.

On an applied appliance, verify the installed directives and query behavior:

```sh
sudo grep -E '^(auth-zone|auth-server|auth-soa|auth-ttl|host-record=ns)' /etc/atlaso/dnsmasq.d/atlaso.conf
systemctl is-active dnsmasq
dig @192.168.50.1 atlaso.internal SOA
dig @192.168.50.1 atlaso.internal NS
dig @192.168.50.1 ns1.atlaso.internal A
dig @192.168.50.1 app.atlaso.internal A
dig @192.168.50.1 missing.atlaso.internal A
dig @127.0.0.1 -x 192.168.50.20
dig @127.0.0.1 example.com A
```

The missing managed name should return authoritative NXDOMAIN with SOA authority. The loopback queries verify that
existing PTR behavior and configured upstream recursion remain available on a non-authoritative listener. Replace
addresses and names with the appliance's selected listener and managed data. To provide recursion on an external
address, leave Authoritative off for that listener or select a separate DNS interface that is not part of the
authoritative interface set.

### DHCP upstream preservation

Explicit DNS upstreams always take precedence. When the management interface uses DHCP and upstreams are empty, Atlaso
uses that interface's observed DHCP resolvers as dnsmasq forwarders. Local DNS intentionally changes
`resolvectl dns <management-interface>` to loopback; after that transition Atlaso recovers the original resolvers from
the exact systemd-networkd lease identified by the management interface's ifindex. Loopback, duplicate, malformed,
unscoped IPv6 link-local, and other-interface lease values are excluded. Link-local lease values cannot be used safely
because the lease does not retain the interface scope required to reach them.

Every later global appliance apply, including an apply caused by enabling or disabling Web Terminal, reuses the same
effective forwarders. If DHCP fallback is required and the management lease has no usable resolver, DNS/DHCP validation
fails before dnsmasq is changed. Restore or renew the management DHCP lease, or configure explicit upstreams, then
review and resubmit the DNS/DHCP unit. After apply, confirm both an Atlaso-managed name and an external name resolve with
`getent hosts` or direct `dig @127.0.0.1` queries.

## Transport ownership

The management DNS transports and their API v1 counterparts are owned by the dedicated `dns_dhcp` domain routers.
The stable UI and API facade modules continue to aggregate and export those handlers. This internal ownership split
does not change any path, method, permission, response, desired-state behavior, dnsmasq rendering, or the global
Appliance Apply boundary described above.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### DNS

![Atlaso DNS page after the desired dnsmasq configuration was applied successfully.](../assets/screenshots/dns-applied-desktop.webp)

*Figure: DNS desired state after a successful dnsmasq apply.*

![Atlaso DNS page in the clean-appliance responsive viewport.](../assets/screenshots/dns-clean-responsive.webp)

*Figure: DNS in the verified clean-appliance responsive state.*

### Dns: Managed Domain

![Atlaso DNS managed domain showing Records, Import Hosts, and Import Zone File tabs with Domain enabled on the right and compact generated authoritative records above.](../assets/screenshots/dns-domain-tools-desktop.webp)

*Figure: DNS domain tools with the Enabled switch beside the tabs and compact generated authoritative records.*

![Atlaso DNS managed domain in a narrow viewport with Domain enabled aligned to the right of the tool tabs.](../assets/screenshots/dns-domain-tools-narrow.webp)

*Figure: DNS domain tools in the verified narrow viewport.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
