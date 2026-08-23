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
