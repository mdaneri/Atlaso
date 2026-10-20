const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf("{", appSource.indexOf(")", start));
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (!depth) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

class FakeElement {
  constructor(textContent = "") { this.textContent = textContent; }
}

class FakeTable {
  constructor(rows) { this.rows = rows; }
  getData() { return this.rows; }
  getRows() {
    return this.rows.map((data) => ({
      getData: () => data,
      getCell: (field) => this.cells?.get(`${data.id}:${field}`),
      reformat: () => this.cells?.get(`${data.id}:provider_id`)?.reformat(),
    }));
  }
  getRow(id) {
    const data = this.rows.find((item) => String(item.id) === String(id));
    return data ? {
      update: async (changes) => Object.assign(data, changes),
      getData: () => data,
      getCell: (field) => this.cells?.get(`${data.id}:${field}`),
      reformat: () => this.cells?.get(`${data.id}:provider_id`)?.reformat(),
    } : null;
  }
}

test("vSphere badges count saved rows and exclude synthetic add rows", () => {
  const badges = {
    '[data-vsphere-count="providers"]': new FakeElement("9 providers"),
    '[data-vsphere-count="vcenters"]': new FakeElement("9 vCenters"),
  };
  const context = vm.createContext({
    HTMLElement: FakeElement,
    document: { querySelector: (selector) => badges[selector] },
  });
  vm.runInContext(`${functionSource("updateVsphereGridCounts")}; globalThis.update = updateVsphereGridCounts;`, context);
  context.update(new FakeTable([{ id: "p1" }, { id: "add", is_new: true }]), new FakeTable([
    { id: "v1" }, { id: "v2" }, { id: "add", is_new: true },
  ]));
  assert.equal(badges['[data-vsphere-count="providers"]'].textContent, "1 providers");
  assert.equal(badges['[data-vsphere-count="vcenters"]'].textContent, "2 vCenters");
});

test("provider rename reformats only its trusted-vCenter provider cells in place", () => {
  const providers = [{ id: "p1", name: "Renamed provider" }, { id: "p2", name: "Other provider" }];
  const visible = new Map();
  const rows = [{ id: "v1", provider_id: "p1" }, { id: "v2", provider_id: "p2" }, { id: "add", provider_id: "", is_new: true }];
  const table = new FakeTable(rows);
  table.cells = new Map(rows.map((row) => [
    `${row.id}:provider_id`,
    { reformat: () => visible.set(row.id, providers.find((provider) => provider.id === row.provider_id)?.name || "") },
  ]));
  const context = vm.createContext({});
  vm.runInContext(`${functionSource("reformatVsphereProviderCells")}; globalThis.reformat = reformatVsphereProviderCells;`, context);
  visible.set("v1", "Old provider");
  visible.set("v2", "Other provider");

  context.reformat(table, "p1");

  assert.equal(visible.get("v1"), "Renamed provider");
  assert.equal(visible.get("v2"), "Other provider");
  assert.equal(visible.has("add"), false);
});

test("trusted-vCenter deletion recomputes the provider trust count from remaining rows", async () => {
  const providerTable = new FakeTable([{ id: "p1", trusted_vcenter_count: 2 }]);
  const vcenterTable = new FakeTable([{ id: "v2", provider_id: "p1" }, { id: "add", provider_id: "p1", is_new: true }]);
  const context = vm.createContext({});
  vm.runInContext(`globalThis.update = async ${functionSource("updateVsphereProviderTrustCount")};`, context);
  await context.update(providerTable, vcenterTable, "p1");
  assert.equal(providerTable.getRow("p1").getData().trusted_vcenter_count, 1);
});
