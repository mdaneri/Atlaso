const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
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

class FakeElement {
  constructor({ top = 200, width = 900, hidden = false } = {}) {
    this.top = top;
    this.width = width;
    this.hidden = hidden;
  }

  closest() {
    return this.hidden ? {} : null;
  }

  getBoundingClientRect() {
    return { top: this.top, width: this.width };
  }
}

const context = vm.createContext({ HTMLElement: FakeElement, Math, window: {} });
vm.runInContext(`${functionSource("dnsRecordsGridHeight")}; globalThis.heightFor = dnsRecordsGridHeight;`, context);

test("DNS record grids use the remaining desktop viewport with a practical minimum", () => {
  assert.equal(context.heightFor(new FakeElement({ top: 180 }), 1440, 1000), 796);
  assert.equal(context.heightFor(new FakeElement({ top: 520 }), 1440, 700), 300);
  assert.equal(context.heightFor(new FakeElement({ top: 260 }), 1200, 900), 616);
});

test("DNS record grids keep compact CSS sizing for narrow or hidden layouts", () => {
  assert.equal(context.heightFor(new FakeElement(), 1100, 900), null);
  assert.equal(context.heightFor(new FakeElement({ hidden: true }), 1440, 900), null);
  assert.equal(context.heightFor(new FakeElement({ width: 0 }), 1440, 900), null);
});

test("DNS grid initialization keeps shared Tabulator behavior and responsive redraws", () => {
  const source = functionSource("initializeDnsRecordsTableElement");
  assert.match(source, /window\.AtlasoUiPatterns\.createGrid/);
  assert.match(source, /height: "100%"/);
  assert.match(source, /redrawDnsRecordTables\(tableElement\)/);
  assert.match(source, /new ResizeObserver/);
  assert.match(source, /window\.addEventListener\("resize", scheduleResize\)/);
  assert.match(source, /dnsAddRowHintFormatter\(cell, "\+ Add record here"\)/);
  assert.match(functionSource("redrawDnsRecordTables"), /root\.matches\("\.dns-records-table"\)/);
});
