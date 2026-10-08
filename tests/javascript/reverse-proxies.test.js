const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const test = require("node:test");

const reverseProxies = require("../../atlaso/app/static/reverse-proxies.js");

test("path prefixes overlap when one can capture the other", () => {
  assert.equal(reverseProxies.pathsOverlap("/app", "/app/admin"), true);
  assert.equal(reverseProxies.pathsOverlap("/app/", "/api/"), false);
  assert.equal(reverseProxies.pathsOverlap("", "/app"), false);
});

test("route steps reject ambiguous paths before review", () => {
  for (const path of ["/app%2Fadmin", "/app//admin", "/app/../admin", "/./app", "/app\\admin", "/a b", "/a\t", "/a\u0085b", "/a?b", "/a#b", "/a;b", "/a{b", "/a}b", "/a$b", '/a"b', "/a'b", "/a\x00", "/a\x7f", "app", "", "/" + "a".repeat(1024)]) {
    assert.equal(reverseProxies.validPathPrefix(path), false, path);
  }
  for (const path of ["/", "/app/", "/app/admin", "/a-b_c.json", "/" + "a".repeat(1023)]) {
    assert.equal(reverseProxies.validPathPrefix(path), true, path);
  }
});

test("route steps reject every reserved component without rejecting neighboring application names", () => {
  const reserved = ["ui", "api", "openapi.json", "identity", "ca", "pxe", "prod", "registry", "v2", "static",
    "manifest.webmanifest", "service-worker.js", "terminal", "requests", "depot"];
  for (const name of reserved) {
    for (const path of [`/${name}`, `/${name}/app`, `/${name.toUpperCase()}/`]) {
      assert.equal(reverseProxies.validPathPrefix(path), false, path);
    }
    assert.equal(reverseProxies.validPathPrefix(`/${name}-app/`), true, name);
  }
  assert.equal(reverseProxies.validPathPrefix("/ſtatic/app"), false);
  assert.equal(reverseProxies.validPathPrefix("/"), true);
  assert.equal(reverseProxies.validPathPrefix("/app/api/"), true);
});

test("fallback add action opens the existing new-proxy wizard", () => {
  const source = fs.readFileSync("atlaso/app/static/reverse-proxies.js", "utf8");
  const start = source.lastIndexOf('    fallback?.addEventListener("click",');
  const end = source.indexOf("\n\n    try {", start);
  class Element { closest(selector) { return selector === "[data-reverse-proxy-add]" ? this : null; } }
  let handler; const opened = [];
  const context = vm.createContext({ Element, fallback: { addEventListener: (_type, callback) => { handler = callback; } },
    edit: (...args) => opened.push(args), items: [] });
  vm.runInContext(source.slice(start, end), context);
  const launcher = new Element();
  handler({target: launcher});
  assert.equal(opened.length, 1);
  assert.equal(opened[0][0], null);
  assert.equal(opened[0][1], launcher);
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

test("health refresh keeps the visible fallback when shared grid creation has no table", async () => {
  const source = fs.readFileSync("atlaso/app/static/reverse-proxies.js", "utf8");
  const hook = "  const api = Object.freeze({";
  assert.equal(source.split(hook).length, 2, "expected one private API assembly point");
  const instrumented = source.replace(hook, "  globalThis.__initializeHealthForTest = initializeHealth;\n" + hook);
  const fallbackClasses = new Set(["hidden"]);
  const gridClasses = new Set();
  class Node {
    constructor(tag) { this.tagName = tag; this.children = []; this.textContent = ""; }
    appendChild(child) { this.children.push(child); }
    replaceChildren(...children) { this.children = children; }
    set innerHTML(_value) { throw new Error("health values must use text nodes"); }
  }
  const body = new Node("tbody");
  const fallback = { classList: classListFor(fallbackClasses), tBodies: [body] };
  let observations = [{ proxy_name: "<img src=x>", path_prefix: "/inventory/", status: "degraded",
    last_success: "2026-10-08T02:00:00Z", failure_class: "upstream_http", http_status: 502,
    tls_status: "trusted_ca", applied: true, pending: true, warning: "<script>warning</script>" }];
  const element = {
    dataset: { fallbackId: "health-fallback", healthUrl: "/health" },
    classList: classListFor(gridClasses),
  };
  const message = { textContent: "" };
  const sandbox = {
    AbortController,
    AtlasoUiPatterns: { createGrid: () => ({ table: null }) },
    document: {
      readyState: "loading",
      createElement: (tag) => new Node(tag),
      addEventListener() {},
      getElementById: () => fallback,
      querySelector: (selector) => selector === "[data-reverse-proxy-health-message]" ? message : null,
    },
    fetch: async () => ({ ok: true, json: async () => ({ items: observations }) }),
    window: { setTimeout: () => 1, clearTimeout() {} },
  };
  vm.runInNewContext(instrumented, sandbox, { filename: "reverse-proxies.js" });

  const errors = [];
  const health = sandbox.__initializeHealthForTest(element, (error) => errors.push(error));
  await health.refresh();

  assert.equal(health.table, null);
  assert.equal(gridClasses.has("hidden"), true);
  assert.equal(fallbackClasses.has("hidden"), false);
  assert.equal(element.dataset.atlasoGridState, "fallback");
  assert.match(message.textContent, /Showing the fallback view/);
  assert.deepEqual(errors, []);
  assert.equal(body.children.length, 1);
  assert.deepEqual(body.children[0].children.map((cell) => cell.textContent), [
    "<img src=x>", "/inventory/", "Degraded", "2026-10-08T02:00:00Z", "Upstream HTTP error",
    "HTTP 502 · TLS Trusted CA", "Applied with pending changes", "<script>warning</script>",
  ]);
  observations = [{ proxy_name: "New", path_prefix: "/new/", status: "healthy", applied: true }];
  await health.refresh();
  assert.equal(body.children.length, 1);
  assert.equal(body.children[0].children[0].textContent, "New");
  assert.equal(body.children[0].children[2].textContent, "Healthy");
  observations = [];
  await health.refresh();
  assert.equal(body.children.length, 1);
  assert.equal(body.children[0].children[0].colSpan, 8);
  assert.equal(body.children[0].children[0].textContent, "No route health observations are available.");
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

test("wizard payload normalizes every fingerprint separator accepted by validation", () => {
  const source = fs.readFileSync("atlaso/app/static/reverse-proxies.js", "utf8");
  const helperStart = source.indexOf("  function normalizeFingerprint(value) {");
  const helperEnd = source.indexOf("\n  }", helperStart) + "\n  }".length;
  const collectStart = source.indexOf("    function collectPayload() {");
  const validateStart = source.indexOf("    function validateStep({ step }) {", collectStart);
  assert.ok(helperStart >= 0 && helperEnd > helperStart && collectStart >= 0 && validateStart > collectStart);
  const helperSource = source.slice(helperStart, helperEnd);
  const collectSource = source.slice(collectStart, validateStart);
  const expected = "ab".repeat(32);
  const variants = [
    expected.match(/.{2}/g).join(":"),
    expected.match(/.{2}/g).join("-"),
    `${expected.slice(0, 18)} ${expected.slice(18, 42)}\t${expected.slice(42)}`,
  ];

  for (const fingerprint of variants) {
    const harness = `
      const DEFAULTS = { connect_timeout: 5, read_timeout: 60, send_timeout: 60, body_limit: 16777216 };
      ${helperSource}
      const routeFields = {
        route_id: { value: "" }, path_prefix: { value: "/" },
        upstream_scheme: { value: "https" }, upstream_host: { value: "upstream.example.test" },
        upstream_port: { value: "443" }, path_behavior: { value: "preserve" },
        trust_mode: { value: "fingerprint" }, fingerprint: { value: ${JSON.stringify(fingerprint)} },
      };
      function routeField(_route, name) { return routeFields[name]; }
      function routeNodes() { return [{}]; }
      const listenerSelect = null;
      const values = {
        name: { value: "Inventory" }, description: { value: "" }, hostname: { value: "inventory.example.test" },
        scheme: { value: "https" }, port: { value: "443" }, redirect_port: { value: "0" },
        redirect_http: { checked: false }, enabled: { checked: false }, public_listing: { checked: true },
        managed_dns: { checked: false }, connect_timeout: { value: "5" }, read_timeout: { value: "60" },
        send_timeout: { value: "60" }, body_limit: { value: "16777216" }, id: { value: "" },
      };
      const form = { querySelector(selector) {
        if (selector === "[data-reverse-proxy-insecure-ack]") return { checked: false };
        const match = selector.match(/^\\[name="([^"]+)"\\]$/);
        return match ? values[match[1]] || null : null;
      } };
      ${collectSource}
      collectPayload();
    `;
    const payload = vm.runInNewContext(harness, { HTMLSelectElement: class HTMLSelectElement {} });
    assert.equal(payload.hostname, "inventory.example.test");
    assert.equal(payload.routes[0].fingerprint, expected);
  }
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
  assert.match(worker, /const ATLASO_CACHE = `\$\{ATLASO_CACHE_PREFIX\}358`;/);
  assert.match(worker, /"\/static\/reverse-proxies\.js\?v=issue-723-6"/);
});

function classListFor(classes) {
  return {
    add: (name) => classes.add(name),
    remove: (name) => classes.delete(name),
  };
}

test("fallback refresh replaces nonempty rows, removes stale actions, and escapes text", () => {
  const source = fs.readFileSync("atlaso/app/static/reverse-proxies.js", "utf8");
  const start = source.indexOf("    function setCollectionRows(");
  const end = source.indexOf("    function setValidation(", start);
  class HTMLElement {
    constructor(tag = "table") { this.tag = tag; this.children = []; this.dataset = {}; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
  }
  const body = new HTMLElement("tbody");
  const fallback = new HTMLElement();
  fallback.tBodies = [body];
  const context = vm.createContext({ HTMLElement, document: {
    getElementById: () => fallback,
    createElement: (tag) => new HTMLElement(tag),
    createTextNode: (text) => ({ textContent: text }),
  }, visibleProxyRow: reverseProxies.visibleProxyRow });
  vm.runInContext(`const MAX_ITEMS = 256; let items = []; const table = null;
    let canWrite = true; const element = {dataset: {fallbackId: "fallback"}};
    ${source.slice(start, end)}`, context);
  const refresh = (rows) => {
    context.nextRows = rows;
    vm.runInContext("setCollectionRows(nextRows)", context);
  };
  refresh([{ id: 10, name: "Old", hostname: "old.example.test", listeners: [], routes: [] }]);
  refresh([{ id: 11, name: "<img src=x>", hostname: "new.example.test", scheme: "https", port: 443,
    listeners: [{interface: "eth1", address: "192.0.2.10"}], routes: [{path_prefix: "/new/"}], enabled: true }]);
  assert.equal(body.children.length, 1);
  assert.equal(body.children[0].children[0].children[0].textContent, "<img src=x>");
  assert.equal(body.children[0].children[6].children[0].textContent, "Enabled");
  assert.equal(body.children[0].children[7].children[0].dataset.reverseProxyEdit, "11");
  vm.runInContext("canWrite = false", context);
  refresh([{id: 12, name: "Read", listeners: [], routes: []}]);
  assert.equal(body.children[0].children[7].children[0].textContent, "Read only");
  assert.deepEqual(body.children[0].children[7].children[0].dataset, {});
  refresh([]);
  assert.equal(body.children.length, 1);
  assert.equal(body.children[0].children[0].textContent, "No reverse proxies are configured.");
  assert.equal(body.children[0].children[0].colSpan, 8);
  vm.runInContext("canWrite = true", context);
  refresh([]);
  const add = body.children[0].children[0].children[1];
  assert.equal(add.textContent, "Add reverse proxy");
  assert.equal(add.type, "button");
  assert.equal(add.dataset.reverseProxyAdd, "");
});
