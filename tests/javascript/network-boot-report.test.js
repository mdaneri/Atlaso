const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function loadFunction(name, nextName, context = {}) {
  const functionSource = source
    .split(`function ${name}`, 2)[1]
    .split(`function ${nextName}`, 1)[0];
  return vm.runInNewContext(`(function ${name}${functionSource})`, context);
}

const networkBootReportValue = loadFunction(
  "networkBootReportValue",
  "networkBootAddressListOptions",
);
const networkBootAddressListOptions = loadFunction(
  "networkBootAddressListOptions",
  "appendNetworkBootReportFacts",
);
const esxiHostVariableRows = loadFunction(
  "esxiHostVariableRows",
  "esxiHostVariableDefinitionRows",
  { JSON, Object, Array, String },
);
const esxiHostVariableDefinitionRows = loadFunction(
  "esxiHostVariableDefinitionRows",
  "parseEsxiHostVariableRows",
  { Array, Boolean, Map, String, esxiHostVariableRows },
);
const parseEsxiHostVariableRows = loadFunction(
  "parseEsxiHostVariableRows",
  "initializeEsxiHostReferenceWizard",
  { Object, String },
);
const esxiHostMacKey = loadFunction(
  "esxiHostMacKey",
  "isValidEsxiHostMac",
  { String },
);
const isValidEsxiHostMac = loadFunction(
  "isValidEsxiHostMac",
  "normalizeEsxiHostMac",
  { Number, esxiHostMacKey },
);
const normalizeEsxiHostMac = loadFunction(
  "normalizeEsxiHostMac",
  "esxiDiscoveredHostLabel",
  { String, esxiHostMacKey, isValidEsxiHostMac },
);
const esxiDiscoveredHostLabel = loadFunction(
  "esxiDiscoveredHostLabel",
  "esxiDiscoveredHostIsRegistered",
);
const esxiDiscoveredHostIsRegistered = loadFunction(
  "esxiDiscoveredHostIsRegistered",
  "esxiSuggestedHostname",
  { Boolean, esxiHostMacKey },
);
const networkBootChangedRowValues = loadFunction(
  "networkBootChangedRowValues",
  "reconcileNetworkBootDiscoveredHosts",
  { Array, JSON, Object },
);
const reconcileNetworkBootDiscoveredHosts = loadFunction(
  "reconcileNetworkBootDiscoveredHosts",
  "initializeNetworkBootDiscoveredHostRefresh",
  { Map, Object, String, networkBootChangedRowValues },
);

test("Network Boot report distinguishes empty v2 addresses from missing legacy data", () => {
  assert.equal(
    networkBootReportValue([], networkBootAddressListOptions(false)),
    "None",
  );
  assert.equal(
    networkBootReportValue([], networkBootAddressListOptions(true)),
    "Not reported",
  );
  assert.equal(
    networkBootReportValue(undefined, networkBootAddressListOptions(false)),
    "Not reported",
  );
  assert.equal(
    networkBootReportValue(["192.0.2.10", "2001:db8::10"], networkBootAddressListOptions(false)),
    "192.0.2.10, 2001:db8::10",
  );
});

test("Network Boot report applies schema-aware address options to both address surfaces", () => {
  assert.match(
    source,
    /\["Assigned addresses", report\.assigned_addresses, networkBootAddressListOptions\(legacyReport\)\]/,
  );
  assert.match(
    source,
    /\["Addresses", "addresses", networkBootAddressListOptions\(legacyReport\)\]/,
  );
});

test("ESXi Host Reference accepts only concrete unicast MAC addresses", () => {
  assert.equal(isValidEsxiHostMac("00:50:56:aa:bb:cc"), true);
  assert.equal(isValidEsxiHostMac("0050.56aa.bbcc"), true);
  assert.equal(isValidEsxiHostMac("01:50:56:aa:bb:cc"), false);
  assert.equal(isValidEsxiHostMac("00:00:00:00:00:00"), false);
  assert.equal(isValidEsxiHostMac("prefix-00:50:56:aa:bb:cc"), false);
  assert.equal(normalizeEsxiHostMac("0050.56AA.BBCC"), "00:50:56:aa:bb:cc");
});

test("ESXi discovered host labels show only the reported boot MAC", () => {
  assert.equal(
    esxiDiscoveredHostLabel({
      id: 7,
      product_name: "VMware20,1",
      boot_mac: "00:0c:29:be:e2:b6",
      macs: ["00:0c:29:be:e2:c0", "00:0c:29:be:e2:b6"],
    }),
    "VMware20,1 · 00:0c:29:be:e2:b6",
  );
});

test("ESXi discovered host selection skips registered hosts", () => {
  const usedMacs = new Set(["005056aabbcc"]);
  assert.equal(esxiDiscoveredHostIsRegistered({ boot_mac: "00:50:56:aa:bb:cc" }, usedMacs), true);
  assert.equal(esxiDiscoveredHostIsRegistered({ boot_mac: "00:50:56:aa:bb:dd", assigned_to_esxi: true }, usedMacs), true);
  assert.equal(esxiDiscoveredHostIsRegistered({ boot_mac: "00:50:56:aa:bb:dd", esxi_host_id: 9 }, usedMacs), true);
  assert.equal(esxiDiscoveredHostIsRegistered({ boot_mac: "00:50:56:aa:bb:dd", esxi_assignments: [{ id: 9 }] }, usedMacs), true);
  assert.equal(esxiDiscoveredHostIsRegistered({ boot_mac: "00:50:56:aa:bb:dd" }, usedMacs), false);
});

test("Network Boot discovered hosts refresh while visible and immediately on visibility return", async () => {
  class HTMLElement {}
  const status = new HTMLElement();
  status.dataset = {};
  status.hidden = true;
  status.textContent = "";
  const listeners = new Map();
  const scheduled = [];
  const document = {
    visibilityState: "visible",
    addEventListener: (name, callback) => listeners.set(name, callback),
    removeEventListener: (name, callback) => {
      if (listeners.get(name) === callback) listeners.delete(name);
    },
  };
  const window = {
    clearTimeout: () => {},
    setTimeout: (callback, milliseconds) => {
      scheduled.push({ callback, milliseconds });
      return scheduled.length;
    },
  };
  const initializeRefresh = loadFunction(
    "initializeNetworkBootDiscoveredHostRefresh",
    "networkBootEnvironmentHasLatestInstalled",
    { document, window, HTMLElement, Error, reconcileNetworkBootDiscoveredHosts },
  );
  const additions = [];
  const hostsTable = {
    getRows: () => [],
    addRow: async (row) => additions.push(row),
  };
  const requests = [];
  const request = async (url) => {
    requests.push(url);
    return [{ id: requests.length }];
  };

  const controller = initializeRefresh(hostsTable, status, {
    request,
    refreshMilliseconds: 5000,
  });

  assert.equal(scheduled[0].milliseconds, 5000);
  await scheduled[0].callback();
  assert.deepEqual(requests, ["/api/v1/network-boot/hosts"]);
  assert.deepEqual(additions, [{ id: 1 }]);
  assert.equal(status.hidden, true);

  document.visibilityState = "hidden";
  await listeners.get("visibilitychange")();
  assert.equal(requests.length, 1);
  document.visibilityState = "visible";
  await listeners.get("visibilitychange")();
  assert.equal(requests.length, 2);
  assert.deepEqual(additions.at(-1), { id: 2 });

  controller.stop();
  assert.equal(listeners.has("visibilitychange"), false);
});

test("Network Boot discovered-host refresh changes rows in place", async () => {
  const updates = [];
  const deletions = [];
  const additions = [];
  const rows = [
    {
      getData: () => ({ id: 1, macs: ["00:50:56:aa:bb:cc"], last_seen_at: "old" }),
      update: async (values) => updates.push(values),
      delete: async () => deletions.push(1),
    },
    {
      getData: () => ({ id: 2, last_seen_at: "removed" }),
      update: async (values) => updates.push(values),
      delete: async () => deletions.push(2),
    },
  ];
  await reconcileNetworkBootDiscoveredHosts({
    getRows: () => rows,
    addRow: async (row) => additions.push(row),
  }, [
    { id: 1, macs: ["00:50:56:aa:bb:cc"], last_seen_at: "new" },
    { id: 3, last_seen_at: "added" },
  ]);

  assert.deepEqual(updates, [{ last_seen_at: "new" }]);
  assert.deepEqual(deletions, [2]);
  assert.deepEqual(additions, [{ id: 3, last_seen_at: "added" }]);
});

test("Network Boot discovered-host refresh preserves the last list after failure", async () => {
  class HTMLElement {}
  const status = new HTMLElement();
  status.dataset = {};
  status.hidden = true;
  status.textContent = "";
  const document = {
    visibilityState: "visible",
    addEventListener: () => {},
    removeEventListener: () => {},
  };
  const window = {
    clearTimeout: () => {},
    setTimeout: () => 1,
  };
  const initializeRefresh = loadFunction(
    "initializeNetworkBootDiscoveredHostRefresh",
    "networkBootEnvironmentHasLatestInstalled",
    { document, window, HTMLElement, Error, reconcileNetworkBootDiscoveredHosts },
  );
  let additionCount = 0;
  const controller = initializeRefresh(
    { getRows: () => [], addRow: async () => { additionCount += 1; } },
    status,
    { request: async () => { throw new Error("temporary failure"); } },
  );

  await controller.refresh();

  assert.equal(additionCount, 0);
  assert.equal(status.hidden, false);
  assert.match(status.textContent, /temporary failure/);
  assert.match(status.textContent, /last received host list/);
});

test("Network Boot disables latest download when that version is installed", () => {
  const hasLatestInstalled = loadFunction(
    "networkBootEnvironmentHasLatestInstalled",
    "networkBootRemovableMedia",
    { Array, Boolean, String },
  );

  assert.equal(hasLatestInstalled({
    available_version: "8.10",
    installed_versions: [{ version: "8.10" }],
  }), true);
  assert.equal(hasLatestInstalled({
    available_version: "8.10",
    installed_versions: [{ version: "8.9" }],
  }), false);
  assert.equal(hasLatestInstalled({
    available_version: "",
    installed_versions: [{ version: "8.10" }],
  }), false);
});

test("Network Boot allows disabled desired media removal but protects active media", () => {
  const removableMedia = loadFunction(
    "networkBootRemovableMedia",
    "initializeNetworkBootPage",
    { Array, Boolean, String },
  );
  const installedVersions = [{ version: "8.10" }];

  assert.equal(removableMedia({
    enabled: false,
    desired_version: "8.10",
    active_version: "",
    installed_versions: installedVersions,
  }).version, "8.10");
  assert.equal(removableMedia({
    enabled: true,
    desired_version: "8.10",
    active_version: "",
    installed_versions: installedVersions,
  }), null);
  assert.equal(removableMedia({
    enabled: false,
    desired_version: "8.10",
    active_version: "8.10",
    installed_versions: installedVersions,
  }), null);
});

test("ESXi host variables round-trip through key/value rows", () => {
  const rows = esxiHostVariableRows('{"rack":"r1","custom.cluster":2}');
  const parsed = parseEsxiHostVariableRows(rows);

  assert.equal(parsed.valid, true);
  assert.equal(JSON.stringify(parsed.variables), '{"cluster":"2","rack":"r1"}');
});

test("ESXi host variable definitions show defaults and persist overrides only", () => {
  const rows = esxiHostVariableDefinitionRows([
    { name: "cluster", description: "Cluster name", default_value: "domain-c8" },
    { name: "rack", description: "Rack name", default_value: "" },
  ], '{"rack":"r1"}');
  const parsed = parseEsxiHostVariableRows(rows);

  assert.deepEqual(JSON.parse(JSON.stringify(rows)), [
    {
      id: "variable-cluster",
      name: "cluster",
      description: "Cluster name",
      default_value: "domain-c8",
      value: "",
      has_override: false,
      definition_missing: false,
    },
    {
      id: "variable-rack",
      name: "rack",
      description: "Rack name",
      default_value: "",
      value: "r1",
      has_override: true,
      definition_missing: false,
    },
  ]);
  assert.equal(JSON.stringify(parsed.variables), '{"rack":"r1"}');
});

test("ESXi host variable definitions preserve unavailable overrides", () => {
  const rows = esxiHostVariableDefinitionRows([], '{"legacy":"kept"}');
  const parsed = parseEsxiHostVariableRows(rows);

  assert.equal(rows[0].definition_missing, true);
  assert.equal(rows[0].has_override, true);
  assert.equal(JSON.stringify(parsed.variables), '{"legacy":"kept"}');
});

test("ESXi host variable rows reject duplicates and built-in namespaces", () => {
  const duplicate = parseEsxiHostVariableRows([
    { name: "rack", value: "r1" },
    { name: "rack", value: "r2" },
  ]);
  const builtIn = parseEsxiHostVariableRows([{ name: "host.hostname", value: "override" }]);

  assert.equal(duplicate.valid, false);
  assert.match(duplicate.message, /duplicated/);
  assert.equal(builtIn.valid, false);
  assert.match(builtIn.message, /cannot override built-in variables/);
});
