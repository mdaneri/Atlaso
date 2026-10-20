const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const parametersStart = appSource.indexOf("(", start);
  let parameterDepth = 0;
  let bodyStart = -1;
  for (let index = parametersStart; index < appSource.length; index += 1) {
    if (appSource[index] === "(") parameterDepth += 1;
    if (appSource[index] === ")") {
      parameterDepth -= 1;
      if (parameterDepth === 0) {
        bodyStart = appSource.indexOf("{", index);
        break;
      }
    }
  }
  assert.notEqual(bodyStart, -1, `${name} must have a function body`);
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

const context = vm.createContext({});
test("LDAP grids resize to the viewport and clear desktop sizing when hidden or narrow", () => {
  class Element {
    constructor(top) {
      this.top = top;
      this.width = 900;
      this.hidden = false;
      this.isConnected = true;
      this.style = { height: "" };
    }
    closest() { return this.hidden ? {} : null; }
    getBoundingClientRect() { return { top: this.top, width: this.width }; }
    get offsetParent() { return this.hidden ? null : {}; }
    querySelector() { return {}; }
  }
  class Document {}
  const users = new Element(200);
  const groups = new Element(200);
  groups.hidden = true;
  const document = new Document();
  document.querySelectorAll = () => [users, groups];
  document.querySelector = () => ({ getBoundingClientRect: () => ({ height: 30 }) });
  const tables = new WeakMap([[users, { redraw() {} }], [groups, { redraw() {} }]]);
  const window = { innerWidth: 1440, innerHeight: 1000, requestAnimationFrame: (callback) => callback() };
  const state = vm.createContext({ HTMLElement: Element, Document, document, window, atlasoLdapDirectoryTables: tables });
  vm.runInContext(["dnsRecordsGridHeight", "resizeDnsRecordsTableElement", "redrawLdapDirectoryTables"].map(functionSource).join("\n"), state);
  state.redrawLdapDirectoryTables();
  assert.equal(users.style.height, "746px");
  assert.equal(groups.style.height, "");
  users.hidden = true;
  groups.hidden = false;
  state.redrawLdapDirectoryTables();
  assert.equal(users.style.height, "");
  assert.equal(groups.style.height, "746px");
  window.innerWidth = 900;
  state.redrawLdapDirectoryTables();
  assert.equal(groups.style.height, "");
  window.innerWidth = 1440;
  groups.width = 0;
  state.redrawLdapDirectoryTables();
  assert.equal(groups.style.height, "");
});

test("LDAP creation enables users and groups while editing preserves disabled state", () => {
  const state = vm.createContext({ CSS: { escape: (value) => value } });
  vm.runInContext(
    `${functionSource("newLdapUserRow")}\n${functionSource("newLdapGroupRow")}\n${functionSource("populateAtlasoWizardForm")}`,
    state,
  );
  for (const factory of [state.newLdapUserRow, state.newLdapGroupRow]) {
    const control = { name: "enabled", type: "checkbox", checked: false };
    const elements = [control];
    elements.namedItem = () => null;
    const form = { elements, querySelectorAll: () => [control] };
    const defaults = factory("2");
    state.populateAtlasoWizardForm(form, {}, { defaults });
    assert.equal(control.checked, true);
    state.populateAtlasoWizardForm(form, { id: 4, enabled: false }, { defaults });
    assert.equal(control.checked, false);
    state.populateAtlasoWizardForm(form, {}, { defaults });
    assert.equal(control.checked, true);
  }
});

vm.runInContext(
  `${functionSource("createLdapOrganizationLoadCoordinator")}\n` +
    `${functionSource("shouldSuppressLdapOrganizationHistory")}\n` +
    `${functionSource("ldapOrganizationIdForHistory")}\n` +
    "globalThis.createLdapOrganizationLoadCoordinator = createLdapOrganizationLoadCoordinator;\n" +
    "globalThis.shouldSuppressLdapOrganizationHistory = shouldSuppressLdapOrganizationHistory;\n" +
    "globalThis.ldapOrganizationIdForHistory = ldapOrganizationIdForHistory;",
  context,
);

function deferredLoadHarness() {
  const pending = [];
  const requested = [];
  const rendered = [];
  const errors = [];
  const busy = [];
  const coordinator = context.createLdapOrganizationLoadCoordinator({
    request: (selection) => {
      requested.push(selection.organizationId);
      return new Promise((resolve, reject) => pending.push({ selection, resolve, reject }));
    },
    onData: (payload, selection) => rendered.push({ payload, selection }),
    onError: (error, selection) => errors.push({ message: error.message, selection }),
    onBusyChange: (value, selection) => busy.push({ value, selection }),
  });
  return { busy, coordinator, errors, pending, rendered, requested };
}

test("rapid LDAP selections render only the latest response", async () => {
  const state = deferredLoadHarness();
  const first = state.coordinator.load({ organizationId: "organization-b", options: {} });
  const latest = state.coordinator.load({ organizationId: "organization-c", options: {} });

  assert.deepEqual(state.requested, ["organization-b", "organization-c"]);
  state.pending[0].resolve("content-b");
  assert.equal(await first, false);
  assert.deepEqual(state.rendered, []);

  state.pending[1].resolve("content-c");
  assert.equal(await latest, true);
  assert.equal(state.rendered.length, 1);
  assert.equal(state.rendered[0].payload, "content-c");
  assert.equal(state.rendered[0].selection.organizationId, "organization-c");
  assert.equal(state.coordinator.isLoading(), false);
  assert.equal(state.busy.at(-1).value, false);
});

test("an older response finishing last cannot replace the latest LDAP selection", async () => {
  const state = deferredLoadHarness();
  const first = state.coordinator.load({ organizationId: "organization-b", options: {} });
  const latest = state.coordinator.load({ organizationId: "organization-c", options: {} });

  state.pending[1].resolve("content-c");
  assert.equal(await latest, true);
  state.pending[0].resolve("content-b");
  assert.equal(await first, false);
  assert.deepEqual(state.rendered.map(({ payload }) => payload), ["content-c"]);
  assert.equal(state.busy.at(-1).selection.organizationId, "organization-c");
});

test("stale LDAP failures cannot trigger fallback navigation", async () => {
  const state = deferredLoadHarness();
  const first = state.coordinator.load({ organizationId: "organization-b", options: {} });
  const latest = state.coordinator.load({ organizationId: "organization-c", options: { history: false } });

  state.pending[0].reject(new Error("obsolete response failed"));
  assert.equal(await first, false);
  assert.deepEqual(state.errors, []);

  state.pending[1].resolve("content-c");
  assert.equal(await latest, true);
  assert.equal(state.rendered[0].selection.options.history, false);
});

test("the latest LDAP failure retains full-navigation fallback", async () => {
  const state = deferredLoadHarness();
  const load = state.coordinator.load({ organizationId: "organization-c", options: {} });

  state.pending[0].reject(new Error("latest response failed"));
  assert.equal(await load, false);
  assert.deepEqual(state.errors.map(({ message }) => message), ["latest response failed"]);
  assert.equal(state.coordinator.isLoading(), false);
});

test("an LDAP selection suppresses history only when it matches the current URL", () => {
  assert.equal(context.shouldSuppressLdapOrganizationHistory("organization-b", "organization-b"), true);
  assert.equal(context.shouldSuppressLdapOrganizationHistory("organization-b", "organization-a"), false);
});

test("queryless LDAP history resolves to the server-default organization", () => {
  assert.equal(context.ldapOrganizationIdForHistory("", "organization-a"), "organization-a");
  assert.equal(context.ldapOrganizationIdForHistory("organization-b", "organization-a"), "organization-b");
  const querylessDefault = context.ldapOrganizationIdForHistory("", "organization-a");
  assert.equal(context.shouldSuppressLdapOrganizationHistory("organization-a", querylessDefault), true);
});

test("a pending popstate target suppresses duplicate history", () => {
  assert.equal(context.shouldSuppressLdapOrganizationHistory("organization-c", "organization-c"), true);
});

test("queryless LDAP history supersedes a pending organization selection", async () => {
  const state = deferredLoadHarness();
  const pendingSelection = state.coordinator.load({ organizationId: "organization-c", options: {} });
  const querylessHistory = state.coordinator.load({ organizationId: "organization-a", options: { history: false } });

  state.pending[0].resolve("content-c");
  assert.equal(await pendingSelection, false);
  assert.deepEqual(state.rendered, []);

  state.pending[1].resolve("content-a");
  assert.equal(await querylessHistory, true);
  assert.equal(state.rendered[0].selection.organizationId, "organization-a");
  assert.equal(state.rendered[0].selection.options.history, false);
});

test("organization swaps replace the rotation target and bind the imported launcher", () => {
  const nodes = new Map();
  let onData;
  const openedActions = [];
  class Element {
    constructor(id) { this.id = id; this.dataset = {}; this.events = {}; }
    replaceWith(next) { nodes.set(this.id, next); }
    addEventListener(name, callback) { this.events[name] = callback; }
    setAttribute() {}
    removeAttribute() {}
  }
  class Dialog extends Element {}
  class Form extends Element {}
  class Anchor extends Element {}
  function organization(id) {
    const panel = new Element("ldap-organization-current");
    panel.launcher = new Element("rotation-launcher");
    const dialog = new Dialog("ldap-bind-rotation-dialog");
    dialog.form = new Form("rotation-form");
    dialog.form.action = `/ui/management/ldap/organizations/${id}/bind-credential/rotate`;
    return { panel, dialog };
  }
  const link = new Anchor("organization-link");
  link.dataset.ldapOrganizationId = "1";
  link.href = "https://atlaso.invalid/ui/management/ldap?organization_id=1";
  link.classList = { toggle() {} };
  const tabs = new Element("tabs");
  tabs.querySelector = () => link;
  tabs.querySelectorAll = () => [link];
  const initial = organization("1");
  nodes.set(initial.panel.id, initial.panel);
  nodes.set(initial.dialog.id, initial.dialog);
  const document = {
    querySelector: (selector) => selector === "[data-ldap-organization-tabs]" ? tabs : nodes.get("ldap-bind-rotation-dialog").form,
    querySelectorAll: () => [nodes.get("ldap-organization-current").launcher],
    getElementById: (id) => nodes.get(id),
    importNode: (node) => node,
  };
  const browser = {
    location: { href: link.href, pathname: "/ui/management/ldap" },
    localStorage: { getItem: () => null, setItem() {} },
    history: { pushState() {}, replaceState() {} },
    addEventListener() {},
    AtlasoUiPatterns: { createWizard: ({ form }) => ({ open: () => openedActions.push(form.action) }) },
  };
  const sandbox = vm.createContext({
    document, window: browser, URL,
    HTMLElement: Element, HTMLDialogElement: Dialog, HTMLFormElement: Form, HTMLAnchorElement: Anchor,
    LDAP_ORGANIZATION_SELECTION_KEY: "selection",
    initializeLdapSettingsStatus() {}, initializeTabs() {}, initializeLdapDirectoryTables() {},
    initializeLdapPasswordModal() {}, initializeConfirmationModals() {},
    initializeLdapBindCredentialFields() {}, restoreLdapBindWizardError() {},
    managementUiPath: (path) => `/ui/management${path}`,
    createLdapOrganizationLoadCoordinator: (config) => { onData = config.onData; return {}; },
  });
  vm.runInContext(functionSource("initializeLdapBindRotationWizard") + "\n" + functionSource("initializeLdapPageState"), sandbox);
  sandbox.initializeLdapPageState();
  for (const id of ["2", "3"]) {
    const next = organization(id);
    const nextDocument = { getElementById: (key) => key === next.panel.id ? next.panel : key === next.dialog.id ? next.dialog : null };
    onData(nextDocument, { link, options: { history: false }, organizationId: id });
    assert.equal(nodes.get("ldap-bind-rotation-dialog"), next.dialog);
    next.panel.launcher.events.click();
    assert.equal(openedActions.at(-1), `/ui/management/ldap/organizations/${id}/bind-credential/rotate`);
  }
});
