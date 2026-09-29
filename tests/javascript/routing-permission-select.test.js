const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf(") {", start) + 2;
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

class TestOption {
  constructor(text, value) {
    this.text = text;
    this.value = value;
    this.dataset = {};
  }

  remove() {
    this.owner.options = this.owner.options.filter((option) => option !== this);
    if (this.owner.value === this.value) this.owner.value = "";
  }
}

class TestSelect {
  constructor(values) {
    this.options = values.map((value) => new TestOption(value, value));
    this.options.forEach((option) => { option.owner = this; });
    this.value = "";
  }

  querySelectorAll(selector) {
    assert.equal(selector, "[data-unavailable]");
    return this.options.filter((option) => option.dataset.unavailable === "true");
  }

  add(option) {
    option.owner = this;
    this.options.push(option);
  }

  set value(value) {
    this.selectedValue = this.options.some((option) => option.value === value) ? value : "";
  }

  get value() {
    return this.selectedValue;
  }
}

const context = vm.createContext({ HTMLSelectElement: TestSelect, Option: TestOption });
vm.runInContext(
  `${functionSource("restoreRoutingInterfaceSelection")}; globalThis.restore = restoreRoutingInterfaceSelection;`,
  context,
);

test("disabled routing edits retain unavailable source and destination selections", () => {
  for (const endpoint of ["source", "destination"]) {
    const select = new TestSelect(["current-a", "current-b"]);
    context.restore(select, `removed-${endpoint}`, false);
    assert.equal(select.value, `removed-${endpoint}`);
    assert.equal(select.options.at(-1).text, `removed-${endpoint} (unavailable; disabled permission only)`);
    assert.equal(select.options.at(-1).dataset.unavailable, "true");
  }
});

test("active edits do not preserve a missing endpoint as an unavailable option", () => {
  const select = new TestSelect(["current-a", "current-b"]);
  context.restore(select, "removed-interface", true);
  assert.equal(select.value, "");
  assert.deepEqual(select.options.map((option) => option.value), ["current-a", "current-b"]);
});

test("opening a new rule removes unavailable options left by a disabled edit", () => {
  const select = new TestSelect(["current-a", "current-b"]);
  context.restore(select, "removed-interface", false);
  context.restore(select, "current-a", true);
  assert.equal(select.value, "current-a");
  assert.deepEqual(select.options.map((option) => option.value), ["current-a", "current-b"]);
});

test("routing wizard restores both saved endpoints according to the saved enabled state", () => {
  const initializer = functionSource("initializeRoutesWanWizards");
  assert.match(initializer, /restoreRoutingInterfaceSelection\(source,[\s\S]*?enabled\)/);
  assert.match(initializer, /restoreRoutingInterfaceSelection\(destination,[\s\S]*?enabled\)/);
});
