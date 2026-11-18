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
