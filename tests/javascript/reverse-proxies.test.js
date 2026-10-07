const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");

const reverseProxies = require("../../atlaso/app/static/reverse-proxies.js");

test("path prefixes overlap when one can capture the other", () => {
  assert.equal(reverseProxies.pathsOverlap("/app", "/app/admin"), true);
  assert.equal(reverseProxies.pathsOverlap("/app/", "/api/"), false);
  assert.equal(reverseProxies.pathsOverlap("", "/app"), false);
});

test("health projection contains bounded status fields without response payloads", () => {
  const row = reverseProxies.routeHealthRow({
    proxy_id: 21,
    route_id: 34,
    proxy_name: "Inventory",
    path_prefix: "/inventory/",
    status: "degraded",
    last_success: "2026-10-06T18:00:00Z",
    failure_class: "upstream_http",
    http_status: 504,
    tls_status: "not applicable",
    applied: true,
    pending: false,
    warning: "The upstream did not respond within the configured timeout.",
    response_body: "secret application data",
    detail: "raw response details",
  });

  assert.equal(row.failure_class, "upstream_http");
  assert.equal(row.proxy_id, 21);
  assert.equal(row.route_id, 34);
  assert.equal(typeof row.proxy_id, "number");
  assert.equal(row.http_status, "504");
  assert.equal(Object.hasOwn(row, "response_body"), false);
  assert.equal(Object.hasOwn(row, "detail"), false);
});

test("health display maps worker states without losing apply, TLS, or warning details", () => {
  const pending = reverseProxies.healthDisplayRow({
    proxy_id: 21,
    route_id: 35,
    status: "pending",
    failure_class: "desired_state_pending",
    tls_status: "not_probed",
    pending: true,
    applied: false,
  });
  assert.equal(pending.status, "Pending");
  assert.equal(pending.failure_class, "Desired state pending");
  assert.equal(pending.http_tls, "TLS Not probed");
  assert.equal(pending.apply_state, "Pending apply");

  const insecure = reverseProxies.healthDisplayRow({
    proxy_id: 21,
    route_id: 36,
    status: "degraded",
    failure_class: "insecure_verification",
    tls_status: "insecure",
    http_status: 502,
    pending: false,
    applied: true,
    warning: "Upstream certificate verification is disabled; this route remains degraded.",
  });
  assert.equal(insecure.status, "Degraded");
  assert.equal(insecure.failure_class, "Insecure verification");
  assert.equal(insecure.http_tls, "HTTP 502 · TLS Insecure");
  assert.equal(insecure.apply_state, "Applied");
  assert.match(insecure.warning, /verification is disabled/);

  const healthy = reverseProxies.healthDisplayRow({
    status: "healthy",
    tls_status: "trusted_ca",
    pending: false,
    applied: true,
  });
  assert.equal(healthy.status, "Healthy");
  assert.equal(healthy.failure_class, "—");
  assert.equal(healthy.http_tls, "TLS Trusted CA");
  assert.equal(healthy.apply_state, "Applied");

  const unavailable = reverseProxies.healthDisplayRow({
    status: "unavailable",
    failure_class: "runtime_observer_unavailable",
    tls_status: "not_probed",
    pending: true,
    applied: false,
  });
  assert.equal(unavailable.status, "Unavailable");
  assert.equal(unavailable.failure_class, "Runtime observation unavailable");
  assert.equal(unavailable.apply_state, "Pending apply");

  const disabled = reverseProxies.healthDisplayRow({
    status: "disabled",
    applied: true,
    pending: false,
  });
  assert.equal(disabled.status, "Disabled");
  assert.equal(disabled.apply_state, "Applied");
});

test("inline save serializes only the complete desired-state model", () => {
  const payload = reverseProxies.serializeProxy({
    id: 21,
    name: "Inventory",
    description: "Internal inventory app",
    hostname: "inventory.example.test",
    scheme: "https",
    port: 8443,
    redirect_http: true,
    redirect_port: 8080,
    enabled: false,
    public_listing: false,
    managed_dns: true,
    listeners: [{ interface: "eth2", address: "192.0.2.10", label: "read-only projection" }],
    routes: [{
      id: 34,
      path_prefix: "/inventory/",
      upstream_scheme: "https",
      upstream_host: "192.0.2.30",
      upstream_port: 9443,
      path_behavior: "strip",
      trust_mode: "fingerprint",
      fingerprint: "ab".repeat(32),
      insecure_acknowledged: true,
      health_status: "healthy",
      last_probe_detail: "read-only projection",
    }],
    connect_timeout: 7,
    read_timeout: 45,
    send_timeout: 55,
    body_limit: 8388608,
    health_status: "healthy",
    pending: false,
  }, true);

  assert.equal(payload.id, 21);
  assert.equal(payload.enabled, true);
  assert.deepEqual(payload.listeners, [{ interface: "eth2", address: "192.0.2.10" }]);
  assert.deepEqual(payload.routes[0], {
    id: 34,
    path_prefix: "/inventory/",
    upstream_scheme: "https",
    upstream_host: "192.0.2.30",
    upstream_port: 9443,
    path_behavior: "strip",
    trust_mode: "fingerprint",
    fingerprint: "ab".repeat(32),
    insecure_acknowledged: false,
  });
  assert.equal(Object.hasOwn(payload, "health_status"), false);
  assert.equal(Object.hasOwn(payload.routes[0], "last_probe_detail"), false);
});

test("visible row keeps all strict desired-state fields and drops projection extras", () => {
  const row = reverseProxies.visibleProxyRow({
    id: 91,
    name: "Portal",
    description: "Internal operator portal",
    hostname: "portal.example.test",
    scheme: "https",
    port: 443,
    enabled: true,
    public_listing: false,
    managed_dns: false,
    listeners: [{ interface: "eth1", address: "192.0.2.10", label: "display-only" }],
    routes: [{
      id: 92,
      path_prefix: "/portal/",
      upstream_scheme: "https",
      upstream_host: "192.0.2.20",
      upstream_port: 9443,
      trust_mode: "insecure",
      insecure_acknowledged: true,
      path_behavior: "preserve",
      probe_detail: "display-only",
    }],
    connect_timeout: 13,
    read_timeout: 120,
    send_timeout: 121,
    body_limit: 8388608,
    pending: true,
    health_status: "degraded",
  });

  assert.equal(row.id, 91);
  assert.equal(row.description, "Internal operator portal");
  assert.equal(row.connect_timeout, 13);
  assert.equal(row.read_timeout, 120);
  assert.equal(row.send_timeout, 121);
  assert.equal(row.body_limit, 8388608);
  assert.deepEqual(row.listeners, [{ interface: "eth1", address: "192.0.2.10" }]);
  assert.equal(row.routes[0].id, 92);
  assert.equal(row.routes[0].insecure_acknowledged, true);
  assert.equal(Object.hasOwn(row.routes[0], "probe_detail"), false);
  assert.equal(Object.hasOwn(row, "pending"), false);
  assert.equal(Object.hasOwn(row, "health_status"), false);
});

test("new desired state defaults disabled and keeps the bounded body limit", () => {
  const payload = reverseProxies.serializeProxy({ name: "New" });
  assert.equal(payload.enabled, false);
  assert.equal(payload.body_limit, 16777216);
});

test("display escaping protects operator-controlled text", () => {
  assert.equal(reverseProxies.escapeHtml(`<script title="x">'&</script>`), "&lt;script title=&quot;x&quot;&gt;&#39;&amp;&lt;/script&gt;");
});

test("management service worker precaches the reverse-proxy page asset", () => {
  const worker = fs.readFileSync("atlaso/app/static/service-worker.js", "utf8");
  assert.match(worker, /const ATLASO_CACHE = `\$\{ATLASO_CACHE_PREFIX\}353`;/);
  assert.match(worker, /"\/static\/reverse-proxies\.js\?v=issue-723-1"/);
});
