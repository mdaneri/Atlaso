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

class ClassList {
  constructor() {
    this.values = new Set();
  }

  toggle(value, force) {
    if (force) this.values.add(value);
    else this.values.delete(value);
  }

  contains(value) {
    return this.values.has(value);
  }
}

class FakeElement {
  constructor() {
    this.attributes = new Map();
    this.classList = new ClassList();
    this.dataset = {};
    this.hidden = false;
  }

  getAttribute(name) {
    return this.attributes.get(name) || null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }
}

class FakeButton extends FakeElement {
  addEventListener(name, callback) {
    this[`on${name}`] = callback;
  }

  click() {
    this.onclick();
  }
}

class FakeGroup extends FakeElement {
  constructor(key, active = false) {
    super();
    this.dataset.navGroupKey = key;
    this.toggle = new FakeButton();
    this.links = new FakeElement();
    this.active = active;
  }

  querySelector(selector) {
    if (selector === "[data-primary-nav-toggle]") return this.toggle;
    if (selector === "[data-primary-nav-links]") return this.links;
    if (selector === '.nav-link[aria-current="page"]') return this.active ? new FakeElement() : null;
    return null;
  }
}

class FakeStorage {
  constructor(value = null) {
    this.value = value;
    this.writes = [];
  }

  getItem() {
    return this.value;
  }

  setItem(_key, value) {
    this.value = value;
    this.writes.push(JSON.parse(value));
  }
}

function navigationContext(groups, storage) {
  const context = vm.createContext({
    Array,
    HTMLButtonElement: FakeButton,
    HTMLElement: FakeElement,
    JSON,
    Object,
    document: { querySelectorAll: () => groups },
    window: { localStorage: storage },
  });
  vm.runInContext(
    'const PRIMARY_NAVIGATION_STORAGE_KEY = "atlaso:primary-navigation:v1";\n' +
      `${functionSource("primaryNavigationStorage")}\n` +
      `${functionSource("readPrimaryNavigationState")}\n` +
      `${functionSource("writePrimaryNavigationState")}\n` +
      `${functionSource("setPrimaryNavigationGroupExpanded")}\n` +
      `${functionSource("initializePrimaryNavigation")}\n` +
      "globalThis.initializePrimaryNavigation = initializePrimaryNavigation;",
    context,
  );
  return context;
}

test("primary navigation starts expanded and toggles only the selected group", () => {
  const overview = new FakeGroup("overview");
  const operations = new FakeGroup("operations");
  const storage = new FakeStorage();
  const context = navigationContext([overview, operations], storage);

  context.initializePrimaryNavigation(context.document);

  assert.equal(overview.toggle.getAttribute("aria-expanded"), "true");
  assert.equal(overview.links.hidden, false);
  assert.equal(operations.toggle.getAttribute("aria-expanded"), "true");
  overview.toggle.click();
  assert.equal(overview.toggle.getAttribute("aria-expanded"), "false");
  assert.equal(overview.links.hidden, true);
  assert.equal(overview.classList.contains("collapsed"), true);
  assert.equal(operations.toggle.getAttribute("aria-expanded"), "true");
  assert.deepEqual(storage.writes.at(-1), { version: 1, groups: { overview: false } });
});

test("primary navigation restores inactive choices and forces the active group open", () => {
  const overview = new FakeGroup("overview");
  const operations = new FakeGroup("operations", true);
  const storage = new FakeStorage(JSON.stringify({ version: 1, groups: { overview: false, operations: false } }));
  const context = navigationContext([overview, operations], storage);

  context.initializePrimaryNavigation(context.document);

  assert.equal(overview.links.hidden, true);
  assert.equal(operations.links.hidden, false);
  assert.equal(operations.toggle.getAttribute("aria-expanded"), "true");
  assert.equal(storage.writes.length, 0, "active-page override must not replace the saved user choice");
});

test("primary navigation ignores obsolete values and survives unavailable storage", () => {
  const group = new FakeGroup("overview");
  const malformedStorage = new FakeStorage(JSON.stringify({ version: 2, groups: { overview: false } }));
  navigationContext([group], malformedStorage).initializePrimaryNavigation();
  assert.equal(group.links.hidden, false);

  const unavailable = {};
  Object.defineProperty(unavailable, "localStorage", {
    get() {
      throw new Error("storage disabled");
    },
  });
  const secondGroup = new FakeGroup("overview");
  const context = navigationContext([secondGroup], null);
  context.window = unavailable;
  assert.doesNotThrow(() => context.initializePrimaryNavigation());
  assert.equal(secondGroup.links.hidden, false);
  assert.doesNotThrow(() => secondGroup.toggle.click());
  assert.equal(secondGroup.links.hidden, true);
});

test("primary navigation DOM-ready registration does not pass the event as the root", () => {
  assert.match(
    appSource,
    /document\.addEventListener\("DOMContentLoaded", \(\) => initializePrimaryNavigation\(\)\);/,
  );
});
