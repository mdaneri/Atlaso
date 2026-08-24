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

  toggleAttribute(name, force) {
    if (force) this.attributes.set(name, "");
    else this.attributes.delete(name);
    if (name === "hidden") this.hidden = force;
  }

  querySelector() {
    return null;
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

class FakeBulkButton extends FakeButton {
  constructor() {
    super();
    this.dataset.primaryNavBulkAction = "collapse";
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

class FakeDocument {
  constructor(groups, bulkControl = new FakeBulkButton()) {
    this.groups = groups;
    this.bulkControl = bulkControl;
  }

  querySelectorAll(selector) {
    return selector === "[data-primary-nav-group]" ? this.groups : [];
  }

  querySelector(selector) {
    return selector === "[data-primary-nav-bulk-toggle]" ? this.bulkControl : null;
  }
}

function navigationContext(groups, storage, { bulkControl = new FakeBulkButton() } = {}) {
  const document = new FakeDocument(groups, bulkControl);
  const context = vm.createContext({
    Array,
    HTMLButtonElement: FakeButton,
    HTMLElement: FakeElement,
    JSON,
    Object,
    document,
    window: { localStorage: storage },
  });
  vm.runInContext(
    'const PRIMARY_NAVIGATION_STORAGE_KEY = "atlaso:primary-navigation:v1";\n' +
      `${functionSource("primaryNavigationStorage")}\n` +
      `${functionSource("readPrimaryNavigationState")}\n` +
      `${functionSource("writePrimaryNavigationState")}\n` +
      `${functionSource("setPrimaryNavigationGroupExpanded")}\n` +
      `${functionSource("primaryNavigationGroupIsExpanded")}\n` +
      `${functionSource("updatePrimaryNavigationBulkControl")}\n` +
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
  assert.equal(context.document.bulkControl.dataset.primaryNavBulkAction, "collapse");
});

test("primary navigation persists a toggle across separate document initializations", () => {
  const storage = new FakeStorage();
  const firstOverview = new FakeGroup("overview");
  const firstContext = navigationContext([firstOverview], storage);
  firstContext.initializePrimaryNavigation(firstContext.document);
  firstOverview.toggle.click();

  const reloadedOverview = new FakeGroup("overview");
  const reloadedContext = navigationContext([reloadedOverview], storage);
  reloadedContext.initializePrimaryNavigation(reloadedContext.document);

  assert.equal(reloadedOverview.toggle.getAttribute("aria-expanded"), "false");
  assert.equal(reloadedOverview.links.hidden, true);
  assert.deepEqual(JSON.parse(storage.value), { version: 1, groups: { overview: false } });
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

test("primary navigation bulk control collapses and expands every rendered group", () => {
  const overview = new FakeGroup("overview");
  const operations = new FakeGroup("operations");
  const storage = new FakeStorage();
  const context = navigationContext([overview, operations], storage);
  const control = context.document.bulkControl;

  context.initializePrimaryNavigation(context.document);
  assert.equal(control.dataset.primaryNavBulkAction, "collapse");
  assert.equal(control.getAttribute("aria-label"), "Collapse all navigation groups");
  assert.equal(control.getAttribute("title"), "Collapse all navigation groups");
  assert.equal(control.textContent, "<<");

  control.click();
  assert.equal(overview.links.hidden, true);
  assert.equal(operations.links.hidden, true);
  assert.deepEqual(storage.writes.at(-1), {
    version: 1,
    groups: { overview: false, operations: false },
  });
  assert.equal(control.dataset.primaryNavBulkAction, "expand");
  assert.equal(control.getAttribute("aria-label"), "Expand all navigation groups");
  assert.equal(control.getAttribute("title"), "Expand all navigation groups");
  assert.equal(control.textContent, ">>");

  control.click();
  assert.equal(overview.links.hidden, false);
  assert.equal(operations.links.hidden, false);
  assert.deepEqual(storage.writes.at(-1), {
    version: 1,
    groups: { overview: true, operations: true },
  });
  assert.equal(control.dataset.primaryNavBulkAction, "collapse");
});

test("primary navigation bulk control collapses mixed state and tracks individual toggles", () => {
  const overview = new FakeGroup("overview");
  const operations = new FakeGroup("operations");
  const storage = new FakeStorage(JSON.stringify({ version: 1, groups: { overview: false, operations: true } }));
  const context = navigationContext([overview, operations], storage);
  const control = context.document.bulkControl;

  context.initializePrimaryNavigation(context.document);
  assert.equal(overview.links.hidden, true);
  assert.equal(operations.links.hidden, false);
  assert.equal(control.dataset.primaryNavBulkAction, "collapse");

  control.click();
  assert.equal(overview.links.hidden, true);
  assert.equal(operations.links.hidden, true);
  assert.equal(control.dataset.primaryNavBulkAction, "expand");

  overview.toggle.click();
  assert.equal(overview.links.hidden, false);
  assert.equal(control.dataset.primaryNavBulkAction, "collapse");
});

test("primary navigation bulk preference survives active-group overrides", () => {
  const storage = new FakeStorage();
  const activeOverview = new FakeGroup("overview", true);
  const operations = new FakeGroup("operations");
  const firstContext = navigationContext([activeOverview, operations], storage);
  firstContext.initializePrimaryNavigation(firstContext.document);
  firstContext.document.bulkControl.click();
  assert.deepEqual(JSON.parse(storage.value), {
    version: 1,
    groups: { overview: false, operations: false },
  });

  const reloadedOverview = new FakeGroup("overview", true);
  const reloadedOperations = new FakeGroup("operations");
  const reloadedContext = navigationContext([reloadedOverview, reloadedOperations], storage);
  reloadedContext.initializePrimaryNavigation(reloadedContext.document);
  assert.equal(reloadedOverview.links.hidden, false);
  assert.equal(reloadedOperations.links.hidden, true);
  assert.equal(reloadedContext.document.bulkControl.dataset.primaryNavBulkAction, "collapse");
  assert.deepEqual(JSON.parse(storage.value), {
    version: 1,
    groups: { overview: false, operations: false },
  });

  const laterOverview = new FakeGroup("overview");
  const laterOperations = new FakeGroup("operations", true);
  const laterContext = navigationContext([laterOverview, laterOperations], storage);
  laterContext.initializePrimaryNavigation(laterContext.document);
  assert.equal(laterOverview.links.hidden, true);
  assert.equal(laterOperations.links.hidden, false);
});

test("primary navigation honors an active group without an authorized active link", () => {
  const identityTrust = new FakeGroup("identity-trust");
  identityTrust.classList.toggle("active", true);
  const storage = new FakeStorage(JSON.stringify({ version: 1, groups: { "identity-trust": false } }));
  const context = navigationContext([identityTrust], storage);

  context.initializePrimaryNavigation(context.document);

  assert.equal(identityTrust.links.hidden, false);
  assert.equal(identityTrust.toggle.getAttribute("aria-expanded"), "true");
  assert.equal(storage.writes.length, 0, "server-active override must not replace the saved user choice");
});

test("primary navigation prunes saved groups hidden by current permissions", () => {
  const overview = new FakeGroup("overview");
  const storage = new FakeStorage(
    JSON.stringify({ version: 1, groups: { overview: false, "core-services": false } }),
  );
  const context = navigationContext([overview], storage);

  context.initializePrimaryNavigation(context.document);

  assert.equal(overview.links.hidden, true);
  assert.deepEqual(storage.writes, [{ version: 1, groups: { overview: false } }]);
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

test("primary navigation remains usable when storage writes fail", () => {
  const storage = new FakeStorage();
  storage.setItem = () => {
    throw new Error("storage full");
  };
  const group = new FakeGroup("overview");
  const context = navigationContext([group], storage);

  assert.doesNotThrow(() => context.initializePrimaryNavigation(context.document));
  assert.doesNotThrow(() => group.toggle.click());
  assert.equal(group.links.hidden, true);
  assert.equal(context.document.bulkControl.dataset.primaryNavBulkAction, "expand");
  assert.doesNotThrow(() => context.document.bulkControl.click());
  assert.equal(group.links.hidden, false);
});

test("primary navigation DOM-ready registration does not pass the event as the root", () => {
  assert.match(
    appSource,
    /document\.addEventListener\("DOMContentLoaded", \(\) => initializePrimaryNavigation\(\)\);/,
  );
});
