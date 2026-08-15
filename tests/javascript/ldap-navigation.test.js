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

test("an active LDAP tab suppresses history only when it matches the current URL", () => {
  assert.equal(context.shouldSuppressLdapOrganizationHistory("organization-b", true, "organization-b"), true);
  assert.equal(context.shouldSuppressLdapOrganizationHistory("organization-b", true, "organization-a"), false);
  assert.equal(context.shouldSuppressLdapOrganizationHistory("organization-b", false, "organization-b"), false);
});

test("queryless LDAP history resolves to the server-default organization", () => {
  assert.equal(context.ldapOrganizationIdForHistory("", "organization-a"), "organization-a");
  assert.equal(context.ldapOrganizationIdForHistory("organization-b", "organization-a"), "organization-b");
  const querylessDefault = context.ldapOrganizationIdForHistory("", "organization-a");
  assert.equal(context.shouldSuppressLdapOrganizationHistory("organization-a", true, querylessDefault), true);
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
