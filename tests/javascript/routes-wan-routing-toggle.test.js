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

const initialRows = () => [
  { id: 9, generated: false, enabled: true, effective_action: "explicit deny", apply_state: "applied" },
  { id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "explicit deny", apply_state: "applied" },
  { id: "__new__", generated: false, is_new: true },
];

function createGrid() {
  const rows = new Map(initialRows().map((row) => [String(row.id), { ...row }]));
  const contextState = { filter: "deny", selectedIds: ["generated:access-a-to-b-ipv4"], scrollTop: 216 };
  const table = {
    rows,
    contextState,
    updates: [],
    getRows(kind) {
      assert.equal(kind, "all");
      return [...this.rows.values()].map((data) => ({ getData: () => data }));
    },
    async updateData(updates) {
      this.updates.push(updates);
      for (const update of updates) {
        const current = this.rows.get(String(update.id));
        this.rows.set(String(update.id), { ...current, ...update });
      }
    },
  };
  return table;
}

function projectionDocument(explicitRows, generatedRows) {
  const routingTable = {
    dataset: {
      rules: JSON.stringify(explicitRows),
      generatedRules: JSON.stringify(generatedRows),
      targetOptions: JSON.stringify([{ name: "eth2", label: "Access 2" }]),
    },
  };
  return { getElementById: (id) => id === "routes-wan-routing-table" ? routingTable : null };
}

function projectionContext(document) {
  const ctx = vm.createContext({
    DOMParser: class {
      parseFromString() { return document; }
    },
    fetch: async (_url, options) => {
      assert.equal(options.credentials, "same-origin");
      assert.equal(options.headers.Accept, "text/html");
      return { ok: true, text: async () => "<html>updated Routes and WAN page</html>" };
    },
    window: { location: { href: "/ui/management/routes-wan#routes-wan-routing-panel" } },
  });
  vm.runInContext(
    `async ${functionSource("refreshRoutesWanRoutingProjection")}; globalThis.refresh = refreshRoutesWanRoutingProjection;`,
    ctx,
  );
  return ctx;
}

test("routing Enabled refreshes explicit and generated projections in the same grid", async () => {
  const tableElement = { dataset: {} };
  const table = createGrid();
  const disabledDocument = projectionDocument(
    [{ id: 9, generated: false, enabled: false, effective_action: "suspended", apply_state: "pending" }],
    [{ id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "automatic deny", apply_state: "pending" }],
  );
  await projectionContext(disabledDocument).refresh(tableElement, table);

  assert.equal(table.rows.get("9").enabled, false);
  assert.equal(table.rows.get("9").effective_action, "suspended");
  assert.equal(table.rows.get("9").apply_state, "pending");
  assert.equal(table.rows.get("generated:access-a-to-b-ipv4").effective_action, "automatic deny");
  assert.equal(table.rows.get("generated:access-a-to-b-ipv4").apply_state, "pending");

  const enabledDocument = projectionDocument(
    [{ id: 9, generated: false, enabled: true, effective_action: "explicit deny", apply_state: "applied" }],
    [{ id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "explicit deny", apply_state: "applied" }],
  );
  await projectionContext(enabledDocument).refresh(tableElement, table);
  assert.equal(table.rows.get("9").effective_action, "explicit deny");
  assert.equal(table.rows.get("9").apply_state, "applied");
  assert.equal(table.rows.get("generated:access-a-to-b-ipv4").effective_action, "explicit deny");
  assert.equal(table.rows.get("generated:access-a-to-b-ipv4").apply_state, "applied");
  assert.equal(table.updates.length, 2);
  assert.deepEqual(table.contextState, { filter: "deny", selectedIds: ["generated:access-a-to-b-ipv4"], scrollTop: 216 });
  assert.equal(table.rows.get("__new__").is_new, true);
  assert.equal(JSON.parse(tableElement.dataset.rules)[0].enabled, true);
});

test("invalid routing projection is rejected before the current grid is changed", async () => {
  const table = createGrid();
  const before = table.rows.get("9");
  const ctx = projectionContext(projectionDocument(
    [{ id: 9, generated: false, enabled: false, apply_state: "pending" }],
    [{ id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "automatic deny", apply_state: "pending" }],
  ));
  await assert.rejects(ctx.refresh({ dataset: {} }, table), /projection .* invalid/i);
  assert.equal(table.updates.length, 0);
  assert.equal(table.rows.get("9"), before);
});

function saveContext({ postError = null } = {}) {
  const messages = [];
  let restores = 0;
  let sideStackRefreshes = 0;
  const ctx = vm.createContext({
    clearCaMessage() {},
    managementUiPath: (path) => path,
    postWanAction: async () => { if (postError) throw postError; },
    refreshNetworkSideStack: async () => { sideStackRefreshes += 1; },
    showTransientGridStatus() {},
    showWanMessage: (_id, message) => messages.push(message),
  });
  vm.runInContext(
    `async ${functionSource("saveWanEnabledState")}; globalThis.save = saveWanEnabledState;`,
    ctx,
  );
  const cell = {
    getRow: () => ({ getData: () => ({ id: 9, enabled: false }) }),
    restoreOldValue: () => { restores += 1; },
  };
  return {
    ctx,
    cell,
    messages,
    restores: () => restores,
    sideStackRefreshes: () => sideStackRefreshes,
  };
}

test("a failed Enabled save restores the edited cell", async () => {
  const state = saveContext({ postError: new Error("server rejected permission") });
  await state.ctx.save(state.cell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    afterSave: async () => assert.fail("failed saves must not refresh projections"),
  });
  assert.equal(state.restores(), 1);
  assert.equal(state.messages[0], "Save failed");
  assert.equal(state.sideStackRefreshes(), 0);
});

test("a successful save keeps the new Enabled value when projection refresh fails", async () => {
  const state = saveContext();
  await state.ctx.save(state.cell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    afterSave: async () => { throw new Error("projection response unavailable"); },
  });
  assert.equal(state.restores(), 0);
  assert.match(state.messages[0], /saved, but its displayed effective state could not be refreshed/i);
  assert.equal(state.sideStackRefreshes(), 0);
});

test("routing Enabled uses the authoritative projection refresh while other resource toggles remain shared", () => {
  const routing = functionSource("initializeRoutesWanRoutingTable");
  assert.ok(routing.includes("afterSave: async () => {"));
  assert.ok(routing.includes("refreshRoutesWanRoutingProjection(tableElement, table)"));
  assert.ok(routing.includes("table = window.AtlasoUiPatterns.createGrid"));
  const initializer = functionSource("initializeRoutesWanNatTable");
  assert.ok(initializer.includes('saveWanEnabledState(cell, csrf, "/traffic-publishing/nat-rules"'));
});
