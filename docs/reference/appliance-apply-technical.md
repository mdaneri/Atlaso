---
title: Appliance Apply technical reference
description: Complete apply-unit ownership, staging, helper, locking, baseline, and interface contracts.
audience:
  - operator
  - contributor
  - maintainer
status: current
---

# Appliance Apply technical reference

This page preserves the complete implementation and subsystem reference formerly embedded in the operator workflow.
Use [Apply appliance changes](../operate/appliance-apply.md) for the review, submission, verification, and recovery task.

## Reference map

| Group | Use it for |
| --- | --- |
| [Workflow and execution model](#workflow-and-execution-model) | Global ownership, routes, locking, and unit boundaries. |
| [Appliance and network units](#appliance-and-network-units) | Users, interface inventory, network, routing, and DNS/DHCP. |
| [Infrastructure and security units](#infrastructure-and-security-units) | PXE, storage, firewall, backups, certificates, and KMS. |
| [Appliance settings and operations](#appliance-settings-and-operations) | NTPsec, settings, logs, power, tasks, and depot behavior. |
| [State, results, and interface contracts](#state-results-and-interface-contracts) | Baselines, diffs, task results, recovery, and UI expectations. |

## Workflow and execution model

### Workflow architecture

Service pages edit desired state. They autosave routine settings and grids, show local validation, expose rendered
config previews through compact preview actions, and link to the global apply review. They should not own
service-specific apply buttons or service-specific apply submit routes.

`Appliance Apply` is the global review and submit workflow, presented through a shared modal rather than a standalone
page. The bottom-left review card and page-level review actions open the modal, which lists changed apply units, checks
valid changed units by default, and lets an operator unselect any unit that should remain pending. A direct GET to
`/ui/management/appliance-apply` redirects to `/ui/management/dashboard#appliance-apply-review`, where the same modal
opens automatically. The `/ui/management/appliance-apply` POST, `/ui/management/appliance-apply/review`, and
`/ui/management/appliance-apply/status` routes remain the browser-only backend workflow used by the modal. Their
transport ownership lives in `atlaso/app/routers/ui/appliance_apply.py`; the stable `atlaso/app/ui.py` facade retains
the unit, projection, submission, execution, recovery, logging, and audit helpers injected into that router.

The status route is deliberately a lightweight desired-state projection: it compares current snapshots with stored
baselines without running apply-time reconciliation or privileged observation helpers. Full review, validation, and
submission still reconcile current host observations and therefore retain fail-closed DHCP DNS fallback behavior.
The browser permits only one status request at a time, polls active work every two seconds, exponentially backs idle
polling from ten to sixty seconds, suspends polling while hidden, and refreshes immediately after successful desired-
state mutations, visibility return, and Apply completion. Once a master task is observed, the browser retains its ID
until `/ui/management/tasks/<id>/status` returns a valid terminal task. A transient status or terminal-follow-up failure
keeps the global lock visible, shows a retry warning in the open monitor, and retries at the two-second active cadence.
Successful reconciliation clears that warning and converges the modal, sidebar badge, pending count, and lock from the
authoritative status and task responses. Terminal task state is sticky so an older in-flight `pending` or `running`
response cannot replace a newer `succeeded`, `failed`, or `cancelled` result. If another session starts a new Apply
between polls, the browser reconciles the retained task and runs its terminal completion refresh before accepting the
new active task. Directly observed terminal responses, including cancellation races, run the same completion refresh.

Submitting transforms the review modal into a live master/child task grid. One `appliance-apply` master owns one child
execution record per selected component. Every signed-in session sees the blocking grid while the master is pending or
running. Atlaso rejects other UI and API mutations with HTTP `423 Locked`; read-only pages, authentication/session
actions, task inspection, and safe master cancellation remain available. Submitted units disappear from the sidebar
pending count immediately, while unselected changes remain pending.

Each selected unit runs its helper steps in order and stops at the first failed step. For example, if a unit's
`validate` helper fails, Atlaso records that command output in the job and does not run the unit's `apply`, reload,
sync, or relocation steps.

On Photon appliances, real mutating helper actions run through `atlaso-helper` and then re-enter via a transient
`systemd-run` service when `ATLASO_HELPER_USE_SYSTEMD_RUN=1` is set. The web control plane remains inside the
`atlaso.service` sandbox, while the reviewed root helper writes approved `/etc` files from outside that service's
read-only mount namespace.

### Apply units

Current apply units are:

- Local Users
- Network
- Appliance Settings
- Routes & WAN Simulation
- Firewall
- DNS/DHCP (dnsmasq)
- ESXi PXE
- Certificate Authority
- vSphere Key Providers (internal `kms` unit)
- Managed LDAP
- NTPsec
- VCF Backups
- VCF Offline Depot
- VCF Private Registry
- Public Services

DNS and DHCP are one unit because they share the rendered dnsmasq config and reload boundary.

Appliance Settings owns appliance identity, OS hostname, resolver mode, resolver servers, management UI HTTPS
preference, passwordless web-terminal preference, and root SSH login preference. NTPsec owns appliance time service
behavior. The app-owned appliance DNS record is derived from that identity, but DNS/DHCP still owns the rendered dnsmasq
record and service reload boundary.

The web terminal is disabled globally by default. Enabling it requires management HTTPS and always includes the
management interface; administrators may also select addressed access/route physical interfaces or enabled VLANs.
Appliance Settings creates a dedicated Ed25519 OpenSSH user CA under `/etc/atlaso/ssh`, installs `TrustedUserCAKeys`
through `/etc/ssh/sshd_config.d/atlaso-web-terminal.conf`, and keeps the CA private key root-readable. Public Services
renders terminal-only HTTPS listeners for selected non-management addresses, adds a `Web Terminal` directory tile only
on those selected addresses, and Firewall opens TCP/443 on those interfaces. Individual local users require the explicit
Web SSH permission, an enabled account, an interactive shell, and an applied Photon password. The management terminal
uses the Operations shell; selected non-management listeners use the Public Services shell and local Photon
authentication. The page connects automatically and retains one bounded shell per authorized user across reloads for up
to the reconnect timeout. Opening it in another browser requires confirmation before the same live shell and buffered
output move to the new browser. `Ctrl-D` and `exit` intentionally terminate the shell; copy/download remain available
for the retained transcript and reconnect creates a new shell. Apply changed `appliance_settings`, `public_services`,
and `firewall` units together when terminal bindings change. See
[Web terminal](../operate/web-terminal.md) for the full behavior and troubleshooting notes.

Browser sessions use a 30-second one-use ticket and an ephemeral key. The constrained helper signs a user certificate
valid for 60 seconds and restricted to SSH connections originating from `127.0.0.1`; port, agent, and X11 forwarding
plus user RC execution are disabled. Atlaso pins the installed Ed25519 SSH host key and connects only to local TCP/22.
One session per authorized user and four sessions appliance-wide are allowed, with a 15-minute idle timeout and one-hour
maximum lifetime. SSH authentication is passwordless for the matching interactive Photon OS account, while `sudo`
continues to enforce that account's password policy.

## Appliance and network units

### Local Users apply

The real Local Users apply path stages JSON at `/var/lib/atlaso/apply/local-users/atlaso-users.json`. The `local_users`
unit synchronizes Atlaso local users to Photon OS users through `atlaso-helper local-users validate|apply`. Enabled
Atlaso users are created under `/var/lib/atlaso/users/<username>` with the per-user desired shell, defaulting to
`/sbin/nologin`; disabled and removed managed users are removed from Photon OS with `userdel -r`. Photon image
provisioning creates the bootstrap admin OS account before first apply. When VCF Backup desired state is off, Atlaso
keeps the default `vcf-backup` user disabled so Local Users apply removes that OS account.

Atlaso users can hold multiple UI/API roles. The Users page edits roles through a multi-select grid cell, stores the
normalized set in `roles_json`, keeps `role` as the primary compatibility value, and evaluates permissions as the union
of all selected role scopes. This changes Atlaso authorization only; Photon OS account sync still writes one OS account,
home directory, shell, password/update state, and unlock state per local user.

Passwords are available for OS sync only when an administrator creates or resets a local user password. Atlaso does not
store local user password hashes or encrypted pending OS passwords in the database; the pending value is held only in
process memory until a real global apply sends it to `chpasswd` over stdin and then clears it. A real apply keeps the
pending password when the account is disabled because the helper does not create or update that Photon account; the
password is consumed only after the account is enabled and applied. If the service restarts before apply, the operator
must set/reset the password again. Dry-run apply records command intent but keeps the in-memory pending password staged.
Unlock requests are staged as desired state and applied later with `passwd -u` plus
`faillock --user <name> --reset`. Password policy edits are also desired state; Local Users apply writes a
Atlaso-managed block in `/etc/security/pwquality.conf` and ensures `/etc/pam.d/system-password` runs `pam_pwquality.so`
before `pam_unix.so`. Rendered previews, diffs, job results, logs, and audit details must show only counts and status
such as `password staged` or `password not staged; reset to sync`.

For a real apply, the control plane writes the helper input with mode `0600` immediately before validation. A
`finally` boundary removes it after validation or apply returns or raises, and the helper independently removes an
allowlisted apply input on every terminal apply path. Startup first uses the constrained `staging prepare` helper action
to repair apply-directory ownership, then removes stale fixed inputs and their tightly matched atomic temporary files.
Read-only OS status uses a unique `.atlaso-users.status-*.json` file without password values and deletes it after the
request, so it cannot replace the fixed apply payload.

### Physical interface inventory

Refreshing Physical Interfaces is inventory only. Appliance startup refreshes observed Linux NIC facts automatically,
and operators can also run the same refresh manually from the page. Both paths update Atlaso's observed model, but
neither runs the network adapter nor applies desired state to the host. Reconciliation matches observed NICs by MAC
address before Linux interface name, so Hyper-V/Linux `ethN` renumbering after a removed adapter does not transfer
desired state to a different NIC. Removed host NICs are made inert, dependent VLANs are disabled, service listener
interfaces and listener addresses are pruned or disabled when no listener remains, and the cleanup is written to the
Atlaso app log and audit events.

Physical and VLAN interfaces share the canonical `management`, `access`, `route`, and `unused` role set. New UI, API,
desired-state, and helper inputs reject any other value. A one-time startup reconciliation maps the retired `services`
and `storage` values to `access`, changes no other interface fields, records an audit event when rows change, and marks
the migration complete. Settings archives export canonical values and apply the same bounded compatibility mapping on
restore; unrelated role strings fail closed.

The management physical interface may define optional static IPv4 and IPv6 gateways. IPv4 must be on-link. IPv6 may be
on-link or link-local (`fe80::/10`); neither gateway may equal its interface address. Network apply writes each
configured management default to both the main table and management policy table `100`; non-management physical
interfaces and VLANs cannot set these fields. IPv4 DHCP and IPv6 Disabled or Automatic clear the corresponding static
gateway. Lab route gateways remain owned by Routes & WAN Simulation in table `200`, allowing management and lab traffic
to use different exits.

A physical management role exposes `/ui/management` inherently. Addressed access-mode physical interfaces and enabled
access VLANs may additionally persist `access_management_ui_enabled=true`. This does not change their routing domain or
service-binding eligibility. Desired-state and helper validation allow zero or one dedicated management physical
interface, but require at least one effective management UI listener. Without a dedicated role, no management DHCP,
default gateway, resolver-lease recovery, or table `100` ownership is synthesized; flagged access listeners retain lab
routing. The preferred appliance identity is a flagged `eth0`, then the first stable flagged physical interface, then a
flagged VLAN. The app-owned appliance FQDN records and `appliance:https` certificate SANs cover all effective management
UI addresses.

### Network apply

The real network apply path is Photon `systemd-networkd` backed. The `network` apply unit stages Atlaso's rendered
network config at `/var/lib/atlaso/apply/network/atlaso-network.conf`, validates management, physical, VLAN, CIDR, and
gateway intent, installs Atlaso-owned `.network` and `.netdev` files under `/etc/systemd/network/`, reloads networkd,
and reconfigures non-management links. Disabled management IPv6 renders `IPv6AcceptRA=no` with no static IPv6 address or
route. Automatic renders `IPv6AcceptRA=yes` with IPv6 link-local addressing. Static renders `IPv6AcceptRA=no`, the
configured address, IPv6 link-local addressing, and the optional default route in both the main and management policy
  tables. The helper does not blindly reconfigure a dedicated management link during this first pass. Dedicated
  management source networks use the Atlaso management route table, while access and route networks use the
lab route table. When a VLAN was present in successful Atlaso network apply history and is no longer desired, the staged
config includes an explicit removal target and the helper deletes that VLAN link after verifying it is a VLAN device.

Any change to the effective management address, gateway, dedicated-management role, or flagged access-management
listener converts five apply units into one `management-handoff` helper transaction whenever an operator submits any
one of them: Certificate Authority, Network, Firewall, Appliance Settings, and Public Services. This forced dependency
closure prevents a partial Firewall, certificate, listener, or resolver apply from publishing candidate-derived state
before candidate networking exists. The helper validates all staged inputs before mutation, snapshots
the Atlaso-owned networkd, nftables, nginx, certificate, and related runtime files under a root-only state directory,
syncs every backup file and the backup directory before publishing the rollback marker,
and merges global runtime addresses from every previous management interface with the configured addresses before it
installs temporary higher-priority networkd holdovers for the previous management links. It then applies the
candidate network and a transitional firewall that admits both previous and candidate management addresses. If the
public protocol or same-protocol HTTP port changes, address-specific nginx blocks retain the old address, port, and
HTTP/HTTPS behavior beside the candidate listener until candidate readiness succeeds. Previous HTTPS blocks always use
separate snapshotted certificate and key files, including when the protocol remains HTTPS while the candidate
certificate rotates.
Within Appliance Settings, this transaction applies the management resolver interface, Atlaso loopback drop-in, and
management nginx front door. The helper writes the selected static/local resolver directives into the candidate
generated effective-listener networkd file or reverts that link to DHCP-provided DNS, then applies the matching per-link
runtime state. After final Network retirement regenerates the managed networkd files, the helper repeats that persistent
and runtime resolver apply before reconfiguring the links. This persistence applies equally to
`00-atlaso-mgmt.network` and flagged-access physical/VLAN files.
The resolver interface follows the effective listener precedence: dedicated management first, then a flagged access
physical interface, then a flagged access VLAN.
If another Appliance Settings field differs from its baseline, that unit remains pending after a successful handoff so
the full hostname, resolver, SSH, Web Terminal trust, and telemetry apply remains pending. A staged resolver-mode or
server change is used for candidate safety but is not baseline-committed by the handoff when another unrelated setting
also differs. Rollback restores the snapshotted networkd resolver directives, reverts the candidate link's transient
resolver override, and reconfigures the restored links before checking the previous listener.

Readiness is fail-closed and bounded. Every host-facing probe includes the previous or candidate configured public port.
The helper first requires Atlaso's loopback `/openapi.json` upstream to succeed;
only then may it validate and reload nginx. It requires consecutive successful direct candidate-listener probes and
host-facing probes for every configured candidate address. Each dynamic listener row must acquire an address for every
requested DHCP or SLAAC family within the shared bounded discovery window; readiness cannot succeed on another row or
family when one is missing. When the candidate disables nftables, the transitional ruleset keeps the previous filtering
policy and adds only the candidate management admission rules. When enabling filtering from an open state, the
transitional ruleset remains open. The enabled or disabled candidate ruleset applies only after readiness while the old
path retires. A second
readiness pass protects retirement. Any validation, mutation, service, probe, or retirement failure restores every
captured file, reloads networkd and nftables, reconfigures previous links, reloads nginx, and restarts Atlaso when the
captured state requires it. Rollback explicitly reconfigures every pre-existing candidate link and removes a
candidate-only VLAN after restoring its files. A previously absent firewall state is restored by disabling/stopping the
candidate `atlaso-firewall.service`, deleting its snapshotted-as-absent unit and config, reloading systemd, and running
`nft flush ruleset`. The helper leaves a durable transaction marker until Atlaso commits the
bundled task state and baselines and sends an idempotent acknowledgement. A fixed transient systemd unit serializes
apply with startup recovery, which stops and verifies any surviving helper before rollback. Startup rolls back when
interruption precedes that database boundary and completes the acknowledgement only when a separate durable task field
proves the database already committed the candidate. A retained helper marker without that proof selects recovery, so
an incomplete pre-commit rollback is retried. Adapter timeouts and other indeterminate apply returns invoke that same
fixed-unit stop and rollback before the task becomes terminal. Empty or malformed systemd unit-state evidence fails
closed before rollback. Exceptions
reconcile the same boundary immediately, and an unproven acknowledgement keeps the global Apply lock held. Results
expose only a bounded failing-layer identifier and
non-secret error text; Appliance Apply writes that evidence to every bundled component and updates none of their
baselines unless the transaction commits. The committed baselines come from the exact snapshots hash-checked and staged
at task start; desired-state edits saved during the helper's bounded readiness interval remain pending.

### Routes and WAN apply

The real Routes & WAN Simulation apply path stages config at `/var/lib/atlaso/apply/wan/atlaso-wan.conf`. The `wan` unit
owns static lab route desired state, routing permissions, IPv4 outbound masquerade NAT rules, and interface/VLAN-level
WAN simulation through `tc/netem`; it does not represent an interface role. Atlaso has no `wan` interface role. The
static management IPv4 gateway is installed as the main-table default so appliance-originated traffic can select a route
before a source address exists, and is also installed in management table 100 for management source-policy routing.
Static routes may target IPv4-only, IPv6-only, or dual-stack non-management access physical interfaces and enabled
VLANs; IPv6 routes render through `ip -6 route`. Lab routes are installed in Atlaso table 200 so their gateways do not
compete with the management default. NAT v1 is explicit IPv4 masquerade only: no destination NAT, port forwarding, IPv6
NAT, or automatic broad NAT is created from interface roles. Operators edit NAT rules on
`/ui/management/routes-wan`, choose a
non-management access physical interface or enabled VLAN with an IPv4 CIDR as the outbound interface, and review the
rendered nftables table and command intent on the global apply page. Route-specific WAN impairment is planned but not
exposed in v1; the design notes live in `docs/routing-wan-roadmap.md`.

The `/ui/management/routes-wan` browser surface labels path entries **Static Routes** and forwarding authorization **Routing
Permissions**. Static Routes, explicit Routing Permissions, NAT Rules, and WAN Policies retain Tabulator browse grids
but use the shared `resource_wizard(...)` structure and `createWizard(...)` behavior for reviewed add/edit flows.
Wizard submission and direct Enabled changes update desired state only;
they never invoke this helper or apply unit directly. Generated route-role permissions remain read-only.

Through `atlaso-helper wan validate|apply`, the helper validates staged routes, routing rules, NAT rules, WAN targets,
and netem policy values. Apply installs `/etc/atlaso/nftables.d/atlaso-nat.nft`, enables `net.ipv4.ip_forward=1` only
when enabled lab routing or NAT requires forwarding, applies source policy rules with `ip rule`, applies the NAT table
with `nft`, applies static routes with `ip route replace ... table 200`, and applies or clears `tc qdisc` netem state on
route targets with assigned policies. Removed route deletion is staged only when a route existed in the selected unit's
last-applied baseline and is absent from current desired state. Management is never a route, NAT, or routing-permission
target, and the Firewall unit generates explicit management-to-lab and lab-to-management forward drops.

### DNS/DHCP apply

The real DNS/DHCP apply path is dnsmasq-backed. The `dnsmasq` apply unit stages Atlaso's rendered dnsmasq config at
`/var/lib/atlaso/apply/dnsmasq/atlaso.conf`, validates it with `dnsmasq --test`, installs
`/etc/atlaso/dnsmasq.d/atlaso.conf`, enables `dnsmasq`, and reloads or restarts the service through `atlaso-helper`. DNS
and DHCP remain one global apply unit because they share one dnsmasq config and service reload boundary. The Services
page keeps separate DNS and DHCP rows for desired-state visibility, while their runtime state is read from the shared
`dnsmasq.service`.

#### Authoritative DNS

Authoritative DNS remains inside that same unit. When enabled, the renderer emits one `auth-zone=<domain>` for each
managed forward domain, one `auth-server=<primary-nameserver>,<selected-interface>...`, shared
`auth-soa=<serial>,<administrator>,<refresh>,<retry>,<expiry>`, and `auth-ttl=<seconds>`. Generated `host-record` lines
provide A/AAAA glue for every selected DNS listen address. dnsmasq makes interfaces named by `auth-server`
authoritative-only: those listeners provide complete authoritative positive and negative answers but refuse unrelated
recursion and non-authoritative reverse zones. The same process continues PTR and upstream-recursive service on
non-authoritative listeners such as loopback. Validate the installed state with
`sudo grep -E '^(auth-zone|auth-server|auth-soa|auth-ttl|host-record=ns)' /etc/atlaso/dnsmasq.d/atlaso.conf`,
`systemctl is-active dnsmasq`, authoritative queries such as `dig @<selected-listener> <zone> SOA`,
`dig @<selected-listener> <zone> NS`, `dig @<selected-listener> <nameserver> A`, and
`dig @<selected-listener> missing.<zone> A`, then recursive-path queries such as `dig @127.0.0.1 -x <record-address>`
and `dig @127.0.0.1 example.com A`. The missing-name result should be authoritative NXDOMAIN with the generated SOA in
authority.

#### DNS security and logging

DNSSEC validation, rebind protection, and query logging are desired-state dnsmasq settings. DNSSEC renders `dnssec` plus
a Atlaso-managed trust-anchor include under `/var/lib/atlaso/apply/dnsmasq/`; the helper verifies installed dnsmasq
DNSSEC support and copies package-provided trust anchors before running `dnsmasq --test`. Rebind protection renders
`stop-dns-rebind` and explicit `rebind-domain-ok` exemptions. Query logging renders `log-queries=extra` only when
enabled and should be treated as temporary troubleshooting because it can expose client query names.

#### Service endpoint records

Service-owned endpoint DNS uses a canonical alias plus generated target records. When a service such as KMS, ESXi PXE,
VCF Offline Depot, or VCF Private Registry selects one or more listen interfaces, Atlaso creates direct A/AAAA records
for each selected listener target and makes the main service name, such as `depot.atlaso.internal`, a CNAME to the first
selected target. This alias is created even for a single selected interface. Appliance Settings controls generated
target names globally: the default `ip` mode creates names such as `depot-192-168-87-12.atlaso.internal`, while
`interface` mode preserves the older style such as `depot-eth2.atlaso.internal`. Operators can use the canonical name by
default and use the generated target names for networks that cannot reach the first selected listener. Atlaso does not
create a multi-A default for the canonical service name because clients may resolve an unreachable address. If the first
selected interface is removed, interface order changes, or the target naming mode changes, the CNAME target moves to the
next first valid selected target and stale app-owned generated records are removed.

#### Operator records and resolver fallback

Operator-managed DNS records support A, AAAA, CNAME, TXT, SRV, MX, CAA, and explicit PTR records. A and AAAA records
still generate matching dnsmasq PTR answers through `host-record`; explicit PTR rows are for custom reverse names that
do not map directly to an address record.

When Appliance Settings resolver mode is still DHCP and DNS upstreams are empty, the DNS/DHCP desired-state preview uses
the management interface's observed DHCP DNS servers as fallback forwarders. Atlaso first reads
`resolvectl dns <management-interface>`; if local DNS has replaced that link state with loopback, the constrained helper
resolves the same interface's ifindex and reads only `/run/systemd/netif/leases/<ifindex>`. Both sources reject loopback,
duplicates, malformed addresses, and values from another interface. Explicit upstreams retain precedence. The renderer
marks DHCP-required configs, and both control-plane and helper validation reject a config with no usable unconditional
forwarder before dnsmasq is changed. Converting the management interface from DHCP to static preserves the observed
lease addresses and copies DHCP-provided DNS servers into Appliance Settings external DNS and into DNS service upstreams
when those settings were relying on DHCP fallback.

#### DHCP addressing and leases

DHCP IP zones can be IPv4 or IPv6. IPv4 zones bind only to valid IPv4 service targets, and IPv6 zones bind only to valid
IPv6 service targets: access physical interfaces or enabled VLAN interfaces must have the matching CIDR family. Trunk
physical interfaces, missing interfaces, and addressless interfaces are rejected before apply. Each zone stores one
comma-separated range expression. IPv4 expressions should use full addresses for ranges and single leases, for example
`192.168.87.100-192.168.87.200, 192.168.87.30`; Atlaso also accepts compact range ends such as `192.168.87.100-200` in a
`/24` or `192.168.87.100-87.200` in a `/16` and expands them in canonical output. IPv6 expressions use full IPv6
addresses for the same range and single-lease pattern, for example `fd00:50::100-fd00:50::200, fd00:50::30`. The
rendered dnsmasq config owns DHCPv4 ranges, DHCPv6 ranges with router advertisements, options, reservations, and the
lease file at `/var/lib/atlaso/dnsmasq/dhcp.leases`; live lease readback goes through the allowlisted
`atlaso-helper dnsmasq leases --real` path.

## Infrastructure and security units

### ESXi PXE apply

The ESXi PXE apply unit owns generated installer boot artifacts. Operators manage Kickstarts in a wizard-backed
Tabulator collection and edit database source through the built-in Monaco Editor; filesystem copies are derived
artifacts, not desired state. Saving a Kickstart updates the database source hash and marks `esxi_pxe` changed, but does
not write `/var/lib/atlaso/pxe/http/esxi/ks/<id>.cfg`.
Applied host boot files contain no reusable Kickstart location. An
MAC-selected menu request creates a distinct unpredictable pending claim and
shows its one-time code only on that boot console. An authenticated `write:pxe`
administrator enters the code before Atlaso creates one attempt-specific boot
file with a cryptographically random, ten-minute, single-use capability. Atlaso
stores only claim, code, and capability verifiers and binds retrieval to every
render-affecting field of the exact applied Host Reference, full Kickstart
content hash, listener, and generated attempt before rendering
`{{variable}}` markers. A MAC address is an operational selector, not
authentication, and invalid, expired, consumed, or mismatched capabilities fail
with the same not-found response.

Kickstart vault scope is derived only from exact
`{{vault.<vaultname>.<key>.<username|password|uri1..uri9>}}` source markers. Save and validation reject malformed,
missing, renamed, inaccessible, or unsupported references. Boot-time rendering revalidates the references and resolves
only the exact requested values. Vault values never enter editor completion metadata, page state, previews, diffs,
jobs, logs, or audits.

#### Installer images

The ESXi PXE page also discovers installer ISOs under `/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST`, the VCFDT ESX
host component folder, and creates that folder when needed. The Installer ISOs tab lists images found there, marks
user-uploaded images separately from VCFDT-discovered images with dates, allows uploading additional `.iso` files, and
allows deleting either source. Deleting an ISO clears host/default PXE references to that image; generated runtime files
are reconciled on the next global `esxi_pxe` apply.

#### Host profiles

Host references are edited in a Tabulator grid. Each host can select a database Kickstart and installer ISO. Its
Host Reference wizard lists every Custom Variables definition with the read-only default and an editable host override;
only explicit overrides are stored in the host variables JSON. Built-in variables include host identity and selected
DHCP scope values such as
`{{dhcp.gateway}}`, `{{dhcp.dns_servers}}`, and `{{dhcp.ntp_servers}}`, and the PXE HTTP base URL; custom values are
referenced as `{{custom.<name>}}`. The Custom Variables collection defines the available names and optional non-secret
defaults; an unassigned host row uses its matching default. The grid also has a default profile for
undefined MAC addresses; when enabled with an
installer ISO, Atlaso generates the top-level default `boot.cfg`, HTTP `boot.cfg`, and `pxelinux.cfg/default` artifacts
from that profile instead of falling back to the first host reference. The default profile cannot use a Kickstart
because dynamic Kickstart rendering requires a defined host MAC.

#### Boot services and apply

The ESXi PXE boot service selects one or more IPv4 DHCP IP zones instead of a freeform interface/IP pair. Atlaso derives
the PXE interfaces, TFTP server addresses, DNS records, firewall bind targets, and generated dnsmasq scope tags from
those zones; the DHCP page shows those generated PXE lines separately from operator-managed DHCP options. Native UEFI
HTTP boot URLs are generated per selected IPv4 zone from that zone's appliance address and always return the staged
`snponly.efi` first stage. Both BIOS and UEFI iPXE requests then load `/pxe/boot.ipxe`, where Atlaso safely resolves the
exact host assignment or inventory default. DHCP never returns an ESXi loader directly.

Fresh desired state keeps both ESXi PXE and Native UEFI HTTP disabled. Native UEFI HTTP is dormant whenever ESXi PXE is
disabled, including for compatible restored state that still carries the older enabled flag with a blank URL. When
ESXi PXE is enabled, Native UEFI HTTP requires either a saved absolute HTTP(S) URL or an effective URL derived from a
selected IPv4 DHCP zone; the shared validation blocks Appliance Apply before helper execution when neither is available.

Host PXE definitions can optionally include an IP address. Blank IPs keep normal DHCP behavior. A concrete host IP
creates or updates an ESXi-managed DHCP reservation and matching DNS A/AAAA record, and the IP must fall inside one of
the selected ESXi PXE DHCP zones. The default undefined-MAC profile remains DHCP-only and never creates a reservation.

The real apply path stages schema-v2 `/var/lib/atlaso/apply/esxi-pxe/atlaso-esxi-pxe.json`. Through
`atlaso-helper esxi-pxe validate|apply`, the helper validates the manifest, writes enabled Kickstarts to the PXE HTTP
root, validates selected installer ISO paths remain under the ESX_HOST folder, extracts selected installers to
`/var/lib/atlaso/pxe/http/esxi/images/<image-key>/`, stages the iPXE first-stage boot files `undionly.kpxe` and
`snponly.efi` to both TFTP and HTTP, stages `pxelinux.0` and `mboot.c32`, writes an HTTP `boot.ipxe` entrypoint even when
no host profiles
exist, and generates host-specific `boot.cfg` plus PXELINUX configs. For ESXi UEFI, the helper uses the selected ISO's
`EFI/BOOT/BOOTX64.EFI` as `mboot.efi` and places it beside the matching host `boot.cfg`; when `crypto64.efi` is present,
it is copied into the same host boot directory. The helper searches Photon package paths plus
`/var/lib/atlaso/pxe/bootloaders` for `undionly.kpxe`, `snponly.efi`, and `pxelinux.0`; Photon image provisioning stages
Atlaso's bundled iPXE `undionly.kpxe` and `snponly.efi` artifacts there because the appliance package stream may not
ship those filenames. The helper also installs an nginx listener on the configured PXE HTTP port that redirects
`/pxe/esxi` to `/pxe/esxi/`, returns a compact status response at `/pxe/esxi/`, proxies dynamic `/pxe/esxi/ks/` and
`boot.ipxe` requests to Atlaso, and serves the remaining `/pxe/esxi/` boot/image artifacts statically. Atlaso redacts
Kickstart secrets and secret-looking host variables from previews, diffs, job output, logs, and audit events. Drift
detection compares the generated filesystem copy to the database source hash and never imports filesystem changes
without an explicit admin action.

ESXi PXE boot settings also affect DNS/DHCP and Firewall desired state. Apply the changed DNS/DHCP, ESXi PXE, and
Firewall units together when the DHCP IP zone, HTTP port, or boot files change so dnsmasq returns zone-scoped
guide-aligned first-stage and second-stage boot files and the appliance exposes UDP/69 plus the PXE HTTP port on the
selected bind targets.

### ESX Storage apply

The `esx_storage` unit stages `/var/lib/atlaso/apply/esx-storage/atlaso-esx-storage.json` and is the only path that may
initialize approved blank disks, mount ESX Storage volumes, create bind exports, or change `rpcbind.service` and
`nfs-server.service`. IPv4 and IPv6 are equivalent: every enabled family is validated against the selected
interface/VLAN, its own VMkernel allowlist, generated A/AAAA target, ESX command, and family-specific firewall rule.

Blank whole-disk initialization requires the global review modal to show the stable `/dev/disk/by-id` path plus model,
serial, WWN, and size and accept the exact `FORMAT <volume-name>` confirmation. The server binds that authorization to
the appliance-apply job ID, manifest SHA256, and stable identity. The helper validates the complete manifest,
re-inventories the disk immediately before `mkfs.ext4`, mounts by UUID, and never performs destructive rollback.
Settings backups and apply baselines exclude format authorization.

NFS 3 and 4.1 run over TCP with NFS 2/4.0 disabled and mountd fixed to TCP/20048. Exports use AUTH_SYS with
`rw,sync,no_subtree_check,no_root_squash` and per-family client CIDRs. NFS 3 firewall rules open TCP/111, TCP/20048, and
TCP/2049; NFS 4.1 rules open TCP/2049. Endpoint changes reconcile app-owned DNS records and make ESX Storage, DNS/DHCP,
and Firewall pending together. See [ESX Storage over NFS](../services/esx-storage.md).

### Firewall apply

Managed LDAP contributes Firewall-owned TCP/636 rules on every selected LDAP listener interface. Plaintext TCP/389 is
never generated.

The Firewall apply unit derives Atlaso-managed service allow rules from enabled service listener desired state.
Management, DNS, DHCP, KMS, NTPsec, VCF Backup, VCF Offline Depot, and VCF Private Registry listeners appear in the
managed service rules grid on the Firewall page, while custom firewall rules remain editable in the main grid. Managed
DNS and service listener rules default to the built-in `Any` group. Operators can create, rename, remove, and assign
firewall groups containing `any`, CIDRs, addresses, or other groups when rule sources or destinations need narrower
access than the default. DHCP bootstrap rules are the exception: they remain interface-bound input rules without group
filtering because clients and relay paths may arrive before a client address is assigned. IPv4 DHCP zones open UDP/67;
IPv6 DHCP zones open UDP/547; NTPsec opens UDP/123 on selected bind targets and TCP/4460 when NTPsec NTS server mode is
enabled. If a DHCP zone or service listener moves from a physical interface to a VLAN such as `eth2.50`, the firewall
preview and apply diff should move the generated rule to that same interface. Apply the changed Firewall unit with the
service unit that changed when the global apply page shows both as pending.

The `public_services` unit stages `/var/lib/atlaso/apply/public-services/atlaso-public-services.conf` and installs
`/etc/atlaso/nginx/sites.d/public-services.conf`. It renders HTTP server blocks only for non-management interface IPs
where ESXi PXE is enabled, redirects `/pxe/esxi` to `/pxe/esxi/`, proxies dynamic PXE requests to Atlaso, and serves
remaining `/pxe/esxi/` boot artifacts from the narrow PXE HTTP alias. It also renders hostname-specific HTTPS/SNI server
blocks for the CA portal using the CA-managed `ca_portal:https` certificate, so `ca.atlaso.internal` and other HTTPS
service names can share an IP without sharing a leaf certificate. It must not expose VCF Offline Depot, management,
broad depot roots, or `/registry` proxy locations over HTTP. The app-owned public service directory at `/` defaults
service cards to hostnames, offers a Name/IP toggle stored in the `atlaso_public_address_mode` cookie, and builds card
URLs from each service's configured scheme and port. VCF Offline Depot and registry access use their service-owned HTTPS
front doors. Firewall apply owns the generated HTTP/HTTPS allow rules, while management nginx remains separate on
management-role IPs and redirects management HTTP/80 to HTTPS/443.

OIDC adds a hostname-specific HTTPS server block on only its selected access or routed addresses and configured port.
That block uses the CA-managed `oidc:https` certificate, proxies only `/identity/`, forwards the exact listener address
to Atlaso for ingress enforcement, and returns 404 for unrelated management or application paths.

### VCF Backups apply

The real VCF Backups apply path is OpenSSH-backed. The `vcf_backups` unit stages Atlaso's rendered `Match User` drop-in
at `/var/lib/atlaso/apply/vcf-backups/atlaso-vcf-backups-sshd.conf`, validates that it is Atlaso-rendered and scoped to
the selected backup user, verifies the selected OS account exists, installs
`/etc/ssh/sshd_config.d/atlaso-vcf-backups.conf`, prepares the fixed chroot storage mount and `/backups` upload
directory, validates `sshd`, and restarts `sshd` through `atlaso-helper`. The selected backup user should be
synchronized through the Local Users apply unit before VCF Backups is applied. Firewall apply owns the selected
interface and port allow rule.

### Certificate Authority apply

The real Certificate Authority apply path stages JSON at `/var/lib/atlaso/apply/ca/atlaso-ca.json`. Fresh appliances
enable the integrated CA at first boot, generate root material, issue the managed `appliance:https` certificate, and
write the initial management HTTPS files before nginx exposes the console. When enabled, Atlaso generates and stores the
local root CA and issued leaf private keys encrypted in the database with `ATLASO_SECRETS_KEY`, auto-ensures
certificates for Atlaso HTTPS, the CA portal, Managed LDAP, KMS/KMIP, VCF Offline Depot, and VCF Private Registry, and
renders a redacted apply preview. Through `atlaso-helper ca validate|apply`, the helper validates the staged JSON,
rejects certificate/key mismatches when OpenSSL can check them, writes `root-ca.pem`, `root.crt`, `ca-bundle.pem`, and
service certificate/key/chain files under `/etc/atlaso`, and keeps private keys out of job output. Rewriting the managed
LDAPS key preserves `root:ldap` ownership and mode `0640` so a later CA-only apply cannot prevent `slapd.service` from
reading its key after restart. The same boundary gives the KMIP server key `root:atlaso-kmip` ownership and mode `0640`
without granting the daemon access to other service keys. Root CA material is not regenerated by ordinary CA identity
edits after it exists; root
replacement is an explicit rotation workflow so service certificates and client trust can be redeployed deliberately.

CA custody and managed certificate deployment remain valid with no CA listen interface. Listen interfaces control only
public portal DNS, firewall, and nginx publication; an empty selection leaves those public-service entries absent while
the CA helper can still write root and managed service material.

The secret-bearing CA staging file uses mode `0600` only for the helper execution window. The control plane removes it
after validation or apply succeeds, fails, or raises; the helper performs the same deletion after validating the
allowlisted path, and startup removes an input left by interruption.

Settings backups include encrypted CA private-key material. Restoring usable CA custody requires the same
`ATLASO_SECRETS_KEY`; otherwise operators should reissue the CA/certificates.

### vSphere Key Provider apply

The real internal `kms` apply unit uses Atlaso's appliance-native, experimental `atlaso-kmip` daemon. The
`/ui/management/vsphere-key-providers` page derives IPv4 and IPv6 listen addresses from selected access interfaces or
enabled VLANs, creates app-owned DNS records for the shared endpoint, and requires an enabled healthy CA and issued `kms:server`
identity before activation. Provider and trusted-vCenter changes remain database desired state until this global apply.

The unit stages `/var/lib/atlaso/apply/kms/server.json` and the public-only
`/var/lib/atlaso/apply/kms/client-trust.pem`. Through `atlaso-helper kms validate|apply`, the helper confines both fixed
paths, rejects symbolic links and private-key material, validates exact schema, derived listener, CA-managed server
identity, immutable UUID namespaces, globally unique exact SHA-256 fingerprints, store paths, and resource limits, then
installs `/etc/atlaso/kmip/server.json` and `/etc/atlaso/kmip/client-trust.pem`. The installed trust bundle is mode
`0640`, owned by root and `atlaso-kmip`, and contains the internal CA public root plus imported public leaf certificates.
The daemon binds the shared endpoint port on every exact derived address recorded in the validated configuration.

The daemon runs as the non-login `atlaso-kmip` account with a hardened systemd sandbox. Its SQLite store and KEK
envelope live under `/var/lib/atlaso/kmip` with service-only permissions; the KEK is protected by
`ATLASO_SECRETS_KEY`. The helper uses `systemd-creds` to persist only a machine-encrypted credential; systemd exposes
the decrypted value only in the daemon's private runtime credential directory. TLS requires version 1.2 or newer,
allows partial-chain verification for explicitly imported public leaves, and still requires an exact fingerprint to map
to one provider. `atlaso-helper kms status` authenticates store metadata and returns only service/store health and
per-provider lifecycle counts. Disabling the service preserves the operational store. Firewall apply owns TCP/5696
access to selected interfaces. The bounded protocol contract is documented in
[vSphere Key Provider protocol contract](vsphere-key-provider-protocol.md).

## Appliance settings and operations

### NTPsec apply

The real NTPsec apply path is Photon `ntpd.service` backed. The **NTP / NTS** page owns enabled state, service hostname,
upstream NTP sources, per-source NTS client selection, optional NTS server certificate/key paths, hardening directives,
bind targets, derived listen addresses, UDP/123, and client allow sources. Fresh NTPsec desired state uses NTS-capable
upstream rows for `time.cloudflare.com` and `nts.netnod.se` with NTS enabled and descriptions populated. This is a clean
desired-state replacement: the retired Chrony table and old Appliance Settings time fields are not imported, restored,
or migrated. Separately, `ntp_nts_restoration_v1` runs once for appliances affected by the NTS removal: it re-enables
and normalizes only those two canonical default rows, records a value-free system audit, leaves custom rows unchanged,
and keeps NTS server mode disabled.

The `ntpd` unit stages `/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf`. Through `atlaso-helper ntpd validate|apply`, the
helper confines the staged file to that directory, requires Photon `ntpsec` and NTPsec binary identity without starting
another daemon, validates upstream identities, explicit listen addresses, restrictive client access, and NTS
certificate/key/cookie paths, then atomically installs `/etc/ntp.conf`. Per-source NTS renders
`server <hostname> iburst nts`; server mode renders `nts enable`, the CA-managed certificate chain, the private-key
path, and persistent `/var/lib/ntp/nts-keys` cookie storage. The read-only status action runs bounded `ntpq -pn`,
`ntpq -c rv`, and `ntpq -c ntsinfo`; logs read only `ntpd.service`. When enabled, apply grants the NTS key `root:ntp`
mode `0640`, stops/disables competing time daemons, and enables/restarts `ntpd.service`. When disabled, it
stops/disables `ntpd.service`. Firewall apply owns UDP/123 access and, when enabled, TCP/4460 NTS-KE access to the
selected interfaces. When NTS server mode is off, NTP apply removes its managed certificate/key and cookie directory
even when authenticated NTS client source lines remain configured.

When an operator selects NTP/NTS server changes, submission always adds the CA unit, including when its desired-state
baseline appears current. The global unit order executes CA first so the helper materializes or repairs the NTS chain
and private key before `ntpd` validation checks those paths. Adding CA through this NTS dependency also preserves the
managed LDAP closure: any changed CA, DNS/DHCP, Firewall, and Managed LDAP units are submitted together when managed
LDAP desired state is active.

The read-only `atlaso-helper ntpd capabilities` action requires Photon’s `ntpsec` package and verifies the `ntpd` binary
identifies itself as NTPsec without starting a daemon. If those checks fail, Atlaso disables the NTS server switch and
per-upstream NTS editors, marks NTS cells unavailable, and rejects attempts to persist or apply NTS state. The normal
NTP service, source health, UDP/123 listener, and non-NTS upstreams continue to work once the required package is
present.

### Appliance Settings apply

The `appliance_settings` unit owns the centralized VMware Customer Experience Improvement Program (CEIP) preference. It
defaults to disabled and is new desired state: Atlaso does not migrate or infer it from the retired VCF Download
Tool-specific choice. During real apply, the helper applies and verifies the choice for installed VCF PowerCLI at
`AllUsers` scope and writes the matching `ENABLE` or `DISABLE` VCF Download Tool telemetry flag when that runtime
exists. Explicit PowerCLI `User` and `Session` overrides remain outside Atlaso ownership, and missing optional VMware
products are reported as skipped.

The real Appliance Settings apply path stages JSON at `/var/lib/atlaso/apply/appliance-settings/atlaso-settings.json`.
The `appliance_settings` unit records the appliance FQDN, resolver mode, resolver servers, local DNS desired-state flag,
management interface/IP, management UI HTTPS preference, root SSH login preference, derived nginx public ports `80` and
`443`, and the uvicorn loopback upstream. Through `atlaso-helper appliance-settings validate|apply`, the helper sets the
OS hostname to the appliance FQDN, local DNS mode configures the management resolver to `127.0.0.1` with `Domains=~.`,
and external DNS mode configures the management resolver to the selected external DNS servers and removes the local
catch-all domain. The helper always installs `/etc/nginx/conf.d/atlaso.conf` plus
`/etc/atlaso/nginx/sites.d/management.conf`, writes a loopback-only `atlaso.service` override, reloads nginx/systemd,
and schedules a short delayed restart of `atlaso.service` so the apply job can be recorded before uvicorn moves behind
nginx. It also writes `/etc/ssh/sshd_config.d/atlaso-root-login.conf`, validates `sshd`, and restarts `sshd`; root SSH
is disabled by default and enabled only when the Appliance Settings switch is applied. When management UI HTTPS is
enabled, the helper requires the CA-managed `appliance:https` cert/key files, redirects public HTTP/80 to HTTPS/443, and
reverse-proxies HTTPS traffic to uvicorn on `127.0.0.1:8000`. Appliance FQDN or management IP changes automatically
refresh the managed appliance leaf certificate before apply. When management UI HTTPS is disabled, including after
factory reset plus apply, nginx serves public HTTP/80 as a plain reverse proxy to uvicorn on `127.0.0.1:8000` and does
not expose a management HTTPS listener.

### Operational logs and appliance power

The Logs page uses fixed read-only tabs for Atlaso App, KMS, LDAP / LDAPS, NTPsec, Nginx, HTTP Access, HTTP Errors, DNS,
DHCP, and TFTP. DNS, DHCP, and TFTP are classified from one allowlisted `dnsmasq.service` journal read; lines emitted by
`dnsmasq-dhcp` and `dnsmasq-tftp` go to their matching tabs, while base `dnsmasq` and service lifecycle messages stay
under DNS. The LDAP / LDAPS tab reads only the fixed `slapd.service` journal through `atlaso-helper ldap logs`. The HTTP
tabs expose the standard nginx access and error files for management and other nginx-hosted services through fixed
`atlaso-helper nginx access-logs` and `error-logs` actions; callers cannot supply arbitrary paths. The page
auto-refreshes every five seconds, shows the update time in one compact status pill, and supports selectable 100, 200,
and 500 line tails. Client-side log highlighting distinguishes timestamps, severity levels, components, identifiers,
addresses, and redaction markers and is reapplied after refresh. The panel is constrained to the viewport so its header
and tabs remain visible; vertical scrolling belongs to the terminal output. Long lines wrap within that terminal
scroller so no log source expands the page or creates a horizontal scrollbar. Each source path or systemd unit is
exposed through the tab tooltip; unavailable sources have disabled tabs, while an all-unavailable page still exposes the
first source's explanation. LDAP, NTPsec, Nginx, and dnsmasq journal reads use fixed allowlisted helper actions; the
server redacts sensitive-looking content before returning it. The retired VCFDT tab is not part of the fixed source set.

#### Audit events

Audit Events has its own Operations navigation entry and a read-only Tabulator grid with column filters and local
pagination. The UI derives page size from the visible holder height and compact row pitch, recalculating it on grid
resize rather than using a fixed row count or page-size selector. This avoids an internal scrollbar, long details remain
available through cell tooltips, and a responsive minimum height preserves useful grid space while the parent page
remains fixed. It is intentionally separate from stream-oriented log sources.

#### Appliance power

The authenticated account menu exposes About and username-aware sign out to every signed-in operator. Administrators
also receive Reboot and Shutdown. Both power actions require the shared confirmation modal and create a durable
`appliance-reboot` or `appliance-shutdown` task before invoking `atlaso-helper appliance-power <action> --real`. The
helper uses a transient `systemd-run --on-active=5` unit so the task result and audit event can be committed before
`systemctl reboot` or `systemctl poweroff` runs. If delayed scheduling is unavailable, the helper fails closed instead
of executing the power action immediately. These actions are runtime maintenance and do not create or apply
desired-state units.

#### Task inspection

The Tasks page uses backend-owned filtering and pagination. Status and state are fixed lists; Task / Component offers
recorded task/component choices plus a custom fragment. Redacted result payloads remain wrapped, syntax-highlighted JSON
audit previews. Console output removes helper execution-envelope JSON, shows only process stdout/stderr, and colors
stderr red. The task-log dialog uses nearly the full available viewport. Result, console, and log previews remain
constrained to the viewport, include overlaid copy/open controls without blank header rows, and are read-only renderings
rather than text form controls.

### VCF Offline Depot apply

VCF Offline Depot no longer owns a separate telemetry switch. Command previews, manual and scheduled download
preparation, and `atlaso-helper vcf-offline-depot apply-ceip` always consume the centralized Appliance Settings
preference and write an exact `ENABLE` or `DISABLE` flag before VCFDT runs.

#### Authentication

Authentication behavior: `/PROD/login` accepts the bootstrap administrator for compatibility and the selected enabled
depot user through the stdin-only `atlaso-helper local-users authenticate <username>` Photon password check. HTML
navigation redirects to the form; non-browser requests receive a standard `401` Basic challenge, so ordinary
`curl -u vcf-depot:<password>` and `wget --user=vcf-depot --password=<password>` flows work. Apply both changed
`vcf_offline_depot` and `public_services` units when this nginx behavior changes because either front door may own the
shared service-IP listener. Local Users apply refreshes an existing managed depot `htpasswd` entry from the current
Photon hash and writes a locked, non-matching entry if that account is missing or locked. No second application password
hash is stored. Public Services validation blocks publishing the authenticated depot while its selected local user is
disabled. When an authenticated VCF Offline Depot or Public Services unit is selected and its HTTP user has unapplied
Local Users state, appliance apply automatically places Local Users before that publishing unit so the Photon account
and derived `htpasswd` state exist first. Unrelated Local Users changes do not alter a publishing-only submission.
After successful browser authentication, Atlaso reconstructs the return location beneath the server-owned `/PROD`
prefix. A valid nested depot path and query are preserved; an unsupported or malformed destination returns to
`/PROD/`.

#### Tool staging, downloads, and HTTPS service

The real VCF Offline Depot apply path stages nginx config at
`/var/lib/atlaso/apply/vcf-offline-depot/atlaso-vcf-offline-depot.conf`. The preview and staged config use the
CA-managed `vcf_offline_depot:https` certificate/key file paths, expose only `settings.depot_store_path/PROD/` at the
HTTPS `/PROD/` path, and enable range-friendly static-file behavior for large depot artifacts. Non-`/PROD` paths on the
depot hostname return 404 so the depot site does not capture Atlaso management UI, CA, or request portal browsing on
shared appliances; CA portal routes are served by the public-services SNI site using the separate `ca_portal:https`
certificate. By default, `/PROD/` accepts either a Atlaso browser session through nginx `auth_request` or HTTPS Basic
Authentication backed by the selected local user's applied Photon password hash. Command-line clients that wait for a
401 challenge, including GNU Wget, should send credentials preemptively (for example, with `--auth-no-challenge`)
because unauthenticated browser requests redirect to `/PROD/login`. Operators may explicitly enable unauthenticated
access for an isolated open mirror. VCF Offline Depot bind validation excludes management-role interfaces; existing
desired state that still references a management interface remains visible but invalid until moved to a non-management
service interface. Uploading a VCFDT archive is desired-state only: it validates/stores the package and clears generated
metadata, but it does not extract, create runtime folders, invoke `vcf-download-tool`, or generate a software depot ID.
Global apply `stage-tool` extracts the uploaded archive under `/opt/atlaso/vcf-download-tool/extracted`, writes a stable
`/opt/atlaso/vcf-download-tool/vcf-download-tool` wrapper for helper-owned apply work, records the tool version from
`--version`, and applies `application-prodv2.properties` to both the helper extraction tree and
`/var/lib/atlaso/vcfDownloadTool/active-tool/conf/`. Atlaso preserves the current software depot ID during ordinary
settings and download-profile applies. It runs `vcf-download-tool configuration generate --software-depot-id` only
when no ID has been recorded or the operator explicitly confirms **Refresh software depot ID**. The helper then runs
`vcf-download-tool configuration get --software-depot-id` and records only the unambiguous persisted readback value;
it does not trust the first UUID printed during first-run initialization. A generation failure leaves the previous ID
recorded. Successful generation followed by failed or ambiguous readback clears the displayed ID because VCFDT may
already have replaced its runtime identity. The refresh icon submits explicit refresh intent through the same global
`/ui/management/appliance-apply` workflow for `vcf_offline_depot`; it is not a service-specific helper call.
Download tokens and activation codes use the combined VCFDT configuration wizard's state-aware credential selector and
conditional upload-or-paste step; storage keys remain separate for compatibility.
Metadata and binaries profiles use whichever credential was staged most recently: the runtime download-token file used
by `--depot-download-token-file` or the runtime activation-code file used by
`--depot-download-activation-code-file`. Existing state with indistinguishable credential timestamps retains the
download-token fallback. ESX profiles always use the activation-code file. The VCFDT
preview is generated as a bash script with `/var/lib/atlaso/vcfDownloadTool/active-tool` runtime token and
activation-code file paths, telemetry flag setup, `conf/esxUserConfig.json` for disabled ESX platforms, and command
intent for install, upgrade, upgrade-only, patch-only, Day-N component, metadata, and ESX downloads. Operators can
manually start one profile from the Download Profiles grid; the Start button is disabled until that profile has a token
or activation-code file, but missing profile credentials do not block applying the depot service or disabling it. Start
creates a durable `vcf-depot-download` task, writes runtime token or activation-code files under the VCFDT working tree,
runs VCFDT as the Atlaso service user, and keeps credential bodies out of task output. Enabled profiles can also be
scheduled under Operations → Automation. The application properties editor saves desired-state text and syncs the
Monaco Editor value before submit; global apply writes the runtime `application-prodv2.properties` used by the active tool.
Manual profile starts and Automation starts use the same atomic `vcf-depot-download` admission function. A partial
unique jobs index permits only one pending or running task for each profile; distinct profiles queue in creation-time/job
ID FIFO order. A second partial index permits exactly one running VCFDT operation. The Software Depot ID and
`vcf_offline_depot` Appliance Apply paths acquire the same admission gate and reject admission until all queued/running
downloads drain; their pending/running state rejects new downloads. Scheduled same-profile and exclusive-operation
collisions become terminal skipped jobs with the active job ID; one-time schedules disable and recurring schedules
advance without replay. The worker performs claim-time validation before runtime preparation, preserves unclaimed
pending jobs across restart, and records terminal success or failure audits. Schedule JSON remains the compatibility
shape `{"profile_id": <integer>}` and never stores credentials or generated commands.
Through
`atlaso-helper vcf-offline-depot validate|stage-tool|apply-properties|generate-software-depot-id|sync-intent|apply-https`,
the helper validates the staged site, rejects broad depot-root exposure and duplicate hostname/listener combinations,
prepares `/mnt/atlaso-vcf-offline-depot/PROD` as web-readable static content, regenerates the managed htpasswd file from
the selected local user's active Photon password hash, installs or removes
`/etc/atlaso/nginx/sites.d/vcf-offline-depot.conf`, validates with `nginx -t`, and reloads nginx. Disabling the depot
removes the nginx site and managed htpasswd file; depot files remain intact.

#### Listener validation

Generated nginx listeners use `address:port` for IPv4 and `[address]:port` for IPv6 across the dedicated depot site and
shared Public Services front door. The privileged helper rejects unbracketed IPv6 listen endpoints before installing
configuration or invoking `nginx -t`.

## State, results, and interface contracts

### Baselines and diffs

After each successfully applied component, Atlaso stores that unit's last-applied baseline in the existing `settings`
table. The baseline includes the normalized snapshot hash, compact summary, rendered config preview, config path, and
apply timestamp. This per-component commit means an earlier success remains current when a later child fails or the
remaining children are skipped.

On fresh Photon appliance startup, Atlaso records the factory desired-state baseline automatically when there is no
existing baseline, no appliance-apply job, and no non-auth operator audit event. This startup baseline is comparison
metadata only: it does not submit an apply job, run helper commands, or mutate host services. It also records the
provisioned bootstrap admin OS account as synced because image provisioning already created that Photon account and set
its password.

When desired state changes later, the global apply page compares the current rendered config preview to the last-applied
preview and shows a unified config diff when available. On first apply, no baseline exists yet, so the page shows the
current preview instead. If an appliance already has operator activity but its Network baseline is absent, Network
apply fails closed before helper execution because Atlaso cannot prove which management path must remain reachable.
Restore a known-good settings archive containing the apply baselines or complete maintainer-guided local-console
recovery before retrying Network apply.

Rendered previews and job results must redact sensitive-looking values such as passwords, tokens, credentials, private
keys, robot accounts, activation codes, encrypted CA private material, and uploaded secret contents.

Local Users, Certificate Authority, and Managed LDAP are the secret-bearing apply inputs with an explicit transient
file lifecycle. Each fixed input is mode `0600` and exists only from staging through its helper execution window.
Control-plane `finally` cleanup covers validation and apply success or failure, the helper deletes after every
allowlisted apply path for defense in depth, and startup removes stale inputs before database recovery. These files are
never used as previews, baselines, task payloads, log fields, audit details, or test output.

### Job result

Submitting first commits one pending `appliance-apply` master and its ordered component children, then returns HTTP
`202` to the modal while adapter execution continues as background work. The children progress through `pending`,
`running`, `succeeded`, `failed`, or `skipped`. Components execute sequentially; the first failed child stops the task
and skips the remainder. A safe cancellation request allows every command in the running component to finish, skips
the remaining components, and releases the global mutation lock only after the master becomes terminal.

Only one appliance apply master may be pending or running at a time, preventing overlapping helper commands from sharing
staging paths. If Atlaso restarts during an apply, startup fails the running child, skips pending children, fails the
master, and releases the lock. The submitted desired-state snapshot hash is checked again before execution, and the task
fails closed with a resubmit message if a selected unit changes while it is queued. The master and children record:

- selected apply units;
- skipped changed units;
- validation errors and warnings;
- compact summaries;
- rendered config previews and diffs;
- adapter commands and dry-run status;
- per-component status, timing, progress, result, and error.

In development, adapter commands are dry-run records. They capture command intent without changing host services.

Atlaso also writes a compact operational breadcrumb for each appliance apply submission to `/var/log/atlaso/atlaso.log`,
including the job id, selected units, skipped changed units, dry-run/live status, per-unit result, and adapter command
return codes. Audit events are mirrored to the same app log with sensitive-looking values redacted. Operators can adjust
local log verbosity and optional external syslog forwarding from Settings.

### UI expectations

Service right rails should show:

- `Pending Appliance Changes`, with status and an action that opens the shared review modal;
- `Validation`, with errors, warnings, and compact rendered config preview actions.

The top pending banner is page-scoped: show it only when the current page's apply unit has changed. The sidebar review
card remains global, shows only unsubmitted pending units, and disappears when no changes require review. Active
submitted work is represented by the blocking master/child grid instead of a second pending banner or sidebar count.

Validation side rails should not render full config blocks inline. Keep the path/name visible in a compact preview
action row and open the shared preview modal for the full rendered text. The hidden source element in that row should
retain the existing `data-...-preview` selector so autosave refreshes continue to replace the latest preview content.
Appliance Apply keeps component diffs collapsed until the operator opens the relevant row.

Editable Tabulator grids should keep new-record placeholder rows visually incomplete until the required identity field
is filled. Only the required first field should be visible and editable at first; generated defaults and secondary cells
should stay blank and locked so operators do not mistake a placeholder for a saved complete row.

The global submit button should be labeled `Submit appliance changes`. Avoid reintroducing labels such as
`Create appliance apply task`, `DNS Apply`, `DHCP Apply`, `SFTP Apply`, or other service-scoped apply actions.
