const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const asyncStart = appSource.indexOf(`async function ${name}(`);
  const ordinaryStart = appSource.indexOf(`function ${name}(`);
  const start = asyncStart >= 0 ? asyncStart : ordinaryStart;
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf("{", start);
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

function conversionScenario(overrides = {}, confirmed = true) {
  const data = {
    name: "eth0",
    role: "management",
    ipv4_method: "dhcp",
    host_ip_cidr: "192.168.167.219/24",
    host_ipv4_gateway: "192.168.167.2",
    host_ipv6_cidr: "",
    ip_cidr: "",
    gateway: "",
    ipv6_cidr: "",
    ipv6_gateway: "",
    ipv6_enabled: false,
    ...overrides,
  };
  let confirmationOptions = null;
  let saved = false;
  const row = {
    getData: () => data,
    async update(values) { Object.assign(data, values); },
  };
  const context = vm.createContext({
    requestConfirmation: async (options) => { confirmationOptions = options; return confirmed; },
    savePhysicalInterfaceRow: async () => { saved = true; },
    showNetworkMessage() {},
  });
  vm.runInContext(
    `${functionSource("isValidIpv4Address")}
     ${functionSource("isValidCidr")}
     ${functionSource("ipv4GatewayIsOnLink")}
     ${functionSource("convertManagementDhcpInterfaceToStatic")}
     globalThis.run = convertManagementDhcpInterfaceToStatic;`,
    context,
  );
  return context.run(row, "csrf").then(() => ({ data, confirmationOptions, saved }));
}

test("DHCP conversion reviews and preserves the observed on-link gateway", async () => {
  const result = await conversionScenario();
  assert.equal(result.saved, true);
  assert.equal(result.data.ipv4_method, "static");
  assert.equal(result.data.ip_cidr, "192.168.167.219/24");
  assert.equal(result.data.gateway, "192.168.167.2");
  assert.match(result.confirmationOptions.detail, /IPv4 address: 192\.168\.167\.219/);
  assert.match(result.confirmationOptions.detail, /IPv4 prefix: \/24/);
  assert.match(result.confirmationOptions.detail, /IPv4 gateway: 192\.168\.167\.2/);
});

test("DHCP conversion makes an absent or off-link gateway an explicit routed-connectivity warning", async () => {
  const result = await conversionScenario({ host_ipv4_gateway: "192.168.168.2" });
  assert.equal(result.saved, true);
  assert.equal(result.data.gateway, "");
  assert.match(result.confirmationOptions.message, /off-subnet routed connectivity/);
  assert.match(result.confirmationOptions.detail, /gateway: none/);
});

test("cancelling DHCP conversion preserves the DHCP row", async () => {
  const result = await conversionScenario({}, false);
  assert.equal(result.saved, false);
  assert.equal(result.data.ipv4_method, "dhcp");
  assert.equal(result.data.gateway, "");
});

test("clearing a configured gateway requires the routed-connectivity warning", async () => {
  let options = null;
  const context = vm.createContext({
    requestConfirmation: async (value) => { options = value; return false; },
  });
  vm.runInContext(
    `${functionSource("confirmManagementGatewayClear")}
     globalThis.run = confirmManagementGatewayClear;`,
    context,
  );
  const accepted = await context.run({ name: "eth0", ip_cidr: "192.168.167.219/24" }, "192.168.167.2", "");
  assert.equal(accepted, false);
  assert.match(options.message, /off-subnet HTTPS, DNS, repositories, and updates/);
  assert.match(options.detail, /IPv4 gateway: none/);
});

test("management-to-access conversion reviews both default-route migrations", async () => {
  let options = null;
  const context = vm.createContext({
    requestConfirmation: async (value) => { options = value; return true; },
  });
  vm.runInContext(
    `${functionSource("confirmManagementToAccessRouteMigration")}
     globalThis.run = confirmManagementToAccessRouteMigration;`,
    context,
  );

  const accepted = await context.run({
    name: "eth0",
    gateway: "192.168.167.2",
    ipv6_gateway: "fe80::1",
  });

  assert.equal(accepted, true);
  assert.match(options.message, /atomically stage their routing intent/);
  assert.match(options.detail, /IPv4 default route: 192\.168\.167\.2 via eth0/);
  assert.match(options.detail, /IPv6 default route: fe80::1 via eth0/);
  assert.match(options.detail, /Management UI: retained on flagged access interface eth0/);
});

test("management-to-access conversion warns when no gateway can be migrated", async () => {
  let options = null;
  const context = vm.createContext({
    requestConfirmation: async (value) => { options = value; return false; },
  });
  vm.runInContext(
    `${functionSource("confirmManagementToAccessRouteMigration")}
     globalThis.run = confirmManagementToAccessRouteMigration;`,
    context,
  );

  const accepted = await context.run({ name: "eth0", gateway: "", ipv6_gateway: "" });

  assert.equal(accepted, false);
  assert.match(options.message, /no default route will be invented/i);
  assert.match(options.detail, /IPv4 default route: not staged - no prior gateway/);
  assert.match(options.detail, /IPv6 default route: not staged - no prior gateway/);
});


test("address evidence keeps failed attempts distinct from restored addresses and escapes text", () => {
  const context = vm.createContext({
    escapeHtml: (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"),
  });
  vm.runInContext(`${functionSource("networkAddressStatusHtml")} globalThis.render = networkAddressStatusHtml;`, context);
  const rendered = context.render({ state: "conflict", detail: "Rejected 192.0.2.20 <script> <SCRIPT>", active_addresses: ["192.0.2.10"], last_conflict: { detected_at: "2026-09-12T00:00:00Z", mac: "" } });
  assert.match(rendered, /IP conflict/);
  assert.match(rendered, /Active: 192.0.2.10/);
  assert.match(rendered, /Detected: 2026-09-12/);
  assert.ok(rendered.includes("Rejected 192.0.2.20 &lt;script&gt; &lt;SCRIPT&gt;"));
  assert.equal(rendered.includes("MAC:"), false);
  assert.match(context.render({}), /Unable to check/);
});

test("address status refresh never replaces a desired edit in progress", async () => {
  class Element {}
  const element = new Element();
  const desired = { id: 1, ip_cidr: "192.0.2.30/24", check_duplicate_ip_addresses: false };
  const updates = [];
  element.atlasoTabulator = { getRow: () => ({ update: async (value) => { updates.push(value); Object.assign(desired, value); } }) };
  const context = vm.createContext({
    HTMLElement: Element, URL,
    document: { querySelector: () => element, getElementById: () => null, visibilityState: "visible", addEventListener() {} },
    window: { location: { href: "https://atlaso.test/physical-interfaces" }, clearTimeout() {}, setTimeout() {} },
    fetch: async () => ({ ok: true, json: async () => ({ rows: [{ id: 1, ip_cidr: "192.0.2.10/24", check_duplicate_ip_addresses: true, address_status: { state: "checking" } }] }) }),
  });
  vm.runInContext(`${functionSource("initializeNetworkAddressStatusRefresh")} initializeNetworkAddressStatusRefresh();`, context);
  await new Promise(setImmediate);
  assert.equal(updates.length, 1);
  assert.deepEqual(Object.keys(updates[0]), ["address_status"]);
  assert.equal(desired.ip_cidr, "192.0.2.30/24");
  assert.equal(desired.check_duplicate_ip_addresses, false);
});
