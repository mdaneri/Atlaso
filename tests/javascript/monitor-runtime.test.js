const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const runtimeSource = fs.readFileSync("atlaso/app/static/monitor-runtime.js", "utf8");
const context = vm.createContext({
  Date,
  URLSearchParams,
  document: { addEventListener() {} },
  window: { addEventListener() {} },
});
vm.runInContext(runtimeSource, context);
const runtime = context.window.MonitorRuntime;

test("monitor runtime labels its owned routing tables", () => {
  assert.equal(runtime.tableLabel(100), "Management (100)");
  assert.equal(runtime.tableLabel("200"), "Lab (200)");
  assert.equal(runtime.tableLabel(254), "Main (254)");
});

test("monitor runtime formats activation duration", () => {
  assert.equal(runtime.formatDuration(0), "0m");
  assert.equal(runtime.formatDuration(3665), "1h 1m");
  assert.equal(runtime.formatDuration(90061), "1d 1h");
  assert.equal(runtime.formatDuration(null), "Unavailable");
});

test("monitor runtime labels observed clock sources", () => {
  assert.equal(runtime.clockSourceLabel("ntp_client"), "NTP client");
  assert.equal(runtime.clockSourceLabel("vmware_tools"), "VMware Tools");
  assert.equal(runtime.clockSourceLabel(null), "Unavailable");
});

test("runtime status reports partial and unavailable observations", () => {
  assert.equal(runtime.monitorRuntimeStatusText({ routes: "ok", rules: "ok" }), "Runtime data is current.");
  assert.equal(runtime.monitorRuntimeStatusText({ routes: "partial" }), "Some runtime data is partial or unavailable (routes).");
  assert.equal(runtime.monitorRuntimeStatusText({ routes: "unavailable" }), "Runtime data is unavailable.");
});

test("runtime load coordinator suppresses overlapping refresh requests", async () => {
  let resolveRequest;
  let requestCount = 0;
  let renderCount = 0;
  const coordinator = runtime.createMonitorRuntimeLoadCoordinator({
    request() {
      requestCount += 1;
      return new Promise((resolve) => { resolveRequest = resolve; });
    },
    onData() { renderCount += 1; },
  });

  const first = coordinator.refresh();
  const second = coordinator.refresh();
  assert.equal(requestCount, 0);
  await Promise.resolve();
  assert.equal(requestCount, 1);
  resolveRequest({ captured_at: "2026-11-18T12:00:00Z" });
  assert.deepEqual(await second, { captured_at: "2026-11-18T12:00:00Z" });
  assert.equal(await first, await second);
  assert.equal(renderCount, 1);
});


function renderComparisonDetails(sections) {
  const document = context.document;
  const changedDetails = [];
  const elements = new Map();
  const root = {
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, { append() {}, replaceChildren() {} });
      return elements.get(selector);
    },
  };
  document.createElement = (tag) => ({
    append(...children) {
      if (tag === "ul") changedDetails.push(...children.map((child) => child.textContent));
    },
  });
  runtime.renderMonitorUpdateComparison(root, { phases: {}, sections });
  return changedDetails;
}

test("update comparison details show the before and after MTU and carrier", () => {
  const comparison = {
    eth1: { interface: "eth1", carrier: true, mtu: 1500, addresses: [] },
    eth2: { interface: "eth2", carrier: true, mtu: 1500, addresses: [] },
  };
  const changedDetails = renderComparisonDetails({
    interfaces: {
      state: "ok",
      changed: [
        { before: comparison.eth1, after: { ...comparison.eth1, mtu: 9000 } },
        { before: comparison.eth2, after: { ...comparison.eth2, carrier: false } },
      ],
    },
  });
  assert.match(changedDetails[0], /MTU 1500.*→.*MTU 9000/);
  assert.match(changedDetails[1], /Carrier up.*→.*Carrier down/);
});

test("route comparisons show changes to each projected path attribute", () => {
  const before = {
    family: 6, table: 200, destination: "default", type: "unicast", protocol: "static",
    preferred_source: "2001:db8::1", source_prefix: "2001:db8:1::/64", nexthop_id: 10,
    nexthops: [{ gateway: "fe80::1", interface: "eth1", weight: 1 }, { gateway: "fe80::2", interface: "eth2", weight: 1 }],
  };
  const details = renderComparisonDetails({
    routes: {
      state: "ok",
      changed: [
        { before, after: { ...before, preferred_source: "2001:db8::2" } },
        { before, after: { ...before, source_prefix: "2001:db8:2::/64" } },
        { before, after: { ...before, protocol: "ra" } },
        { before, after: { ...before, nexthop_id: 11 } },
        { before, after: { ...before, nexthops: [before.nexthops[0], { ...before.nexthops[1], weight: 2 }] } },
      ],
    },
  });
  assert.match(details[0], /Preferred source 2001:db8::1.*→.*Preferred source 2001:db8::2/);
  assert.match(details[1], /Source prefix 2001:db8:1::\/64.*→.*Source prefix 2001:db8:2::\/64/);
  assert.match(details[2], /Protocol static.*→.*Protocol ra/);
  assert.match(details[3], /Next-hop ID 10.*→.*Next-hop ID 11/);
  assert.match(details[4], /fe80::2 on eth2 \(weight 1\).*→.*fe80::2 on eth2 \(weight 2\)/);
});

test("policy rule comparisons show changes to egress and individual selectors", () => {
  const before = {
    family: 4, priority: 100, action: "lookup", table: 200, egress: "eth1",
    selectors: "fwmark 0x1, suppress_prefixlen 0",
  };
  const details = renderComparisonDetails({
    rules: {
      state: "ok",
      changed: [
        { before, after: { ...before, egress: "eth2" } },
        { before, after: { ...before, selectors: "fwmark 0x2, suppress_prefixlen 0" } },
        { before, after: { ...before, selectors: "fwmark 0x1, suppress_prefixlen 24" } },
      ],
    },
  });
  assert.match(details[0], /Egress eth1.*→.*Egress eth2/);
  assert.match(details[1], /fwmark 0x1.*→.*fwmark 0x2/);
  assert.match(details[2], /suppress_prefixlen 0.*→.*suppress_prefixlen 24/);
});

test("an unavailable clock observation clears previously observed health", () => {
  const fields = new Map(["source", "sync", "pending"].map((field) => [`[data-monitor-clock-${field}]`, {}]));
  const panel = { querySelector: (selector) => fields.get(selector) };
  const values = () => Array.from(fields.values(), (field) => field.textContent);
  runtime.renderClockSummary(panel, { source: "ntp_client", synchronization: "synchronized", pending: false });
  assert.deepEqual(values(), ["NTP client", "Synchronized", "No transition pending"]);
  runtime.renderClockSummary(panel, undefined);
  assert.deepEqual(values(), ["Unavailable", "Unavailable", "Unavailable"]);
});
