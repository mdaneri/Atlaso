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

function projectionDocument(explicitRows, generatedRows, targetOptions = [{ name: "eth2", label: "Access 2" }]) {
  const routingTable = {
    dataset: {
      rules: JSON.stringify(explicitRows),
      generatedRules: JSON.stringify(generatedRows),
      targetOptions: JSON.stringify(targetOptions),
    },
  };
  return { getElementById: (id) => id === "routes-wan-routing-table" ? routingTable : null };
}

function projectionContext(documentOrFetch) {
  const ctx = vm.createContext({
    DOMParser: class {
      parseFromString(value) { return value; }
    },
    fetch: async (_url, options) => {
      assert.equal(options.credentials, "same-origin");
      assert.equal(options.headers.Accept, "text/html");
      if (typeof documentOrFetch === "function") return documentOrFetch();
      return { ok: true, text: async () => documentOrFetch };
    },
    window: { location: { href: "/ui/management/routes-wan#routes-wan-routing-panel" } },
  });
  vm.runInContext(
    `async ${functionSource("refreshRoutesWanRoutingProjection")}; globalThis.refresh = refreshRoutesWanRoutingProjection;`,
    ctx,
  );
  return ctx;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function responseFor(document) {
  return { ok: true, text: async () => document };
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

test("a late obsolete response cannot replace a newer routing projection or targets", async () => {
  const olderResponse = deferred();
  const newerResponse = deferred();
  const responses = [olderResponse, newerResponse];
  const ctx = projectionContext(() => responses.shift().promise);
  const tableElement = { dataset: { rules: "old", generatedRules: "old", targetOptions: "old" } };
  const table = createGrid();
  let generation = 1;
  const oldRefresh = ctx.refresh(tableElement, table, () => generation === 1);
  generation = 2;
  const newRefresh = ctx.refresh(tableElement, table, () => generation === 2);
  newerResponse.resolve(responseFor(projectionDocument(
    [{ id: 9, generated: false, enabled: true, effective_action: "new permission", apply_state: "pending" }],
    [{ id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "new generated", apply_state: "pending" }],
    [{ name: "eth3", label: "Access 3" }],
  )));
  const newTargets = await newRefresh;
  olderResponse.resolve(responseFor(projectionDocument(
    [{ id: 9, generated: false, enabled: false, effective_action: "stale permission", apply_state: "applied" }],
    [{ id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "stale generated", apply_state: "applied" }],
    [{ name: "eth1", label: "Stale Access" }],
  )));

  assert.equal(await oldRefresh, false);
  assert.equal(table.updates.length, 1);
  assert.equal(table.rows.get("9").effective_action, "new permission");
  assert.equal(table.rows.get("generated:access-a-to-b-ipv4").effective_action, "new generated");
  assert.equal(JSON.parse(tableElement.dataset.rules)[0].effective_action, "new permission");
  assert.equal(JSON.parse(tableElement.dataset.generatedRules)[0].effective_action, "new generated");
  assert.deepEqual(JSON.parse(JSON.stringify(newTargets)), [{ name: "eth3", label: "Access 3" }]);
  assert.deepEqual(JSON.parse(tableElement.dataset.targetOptions), JSON.parse(JSON.stringify(newTargets)));
});

test("a newer edit queues behind an in-flight grid update and remains the final projection", async () => {
  const olderUpdate = deferred();
  const oldDocument = projectionDocument(
    [{ id: 9, generated: false, enabled: false, effective_action: "older", apply_state: "pending" }],
    [{ id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "older generated", apply_state: "pending" }],
    [{ name: "eth1", label: "Older target" }],
  );
  const newDocument = projectionDocument(
    [{ id: 9, generated: false, enabled: true, effective_action: "newest", apply_state: "pending" }],
    [{ id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "newest generated", apply_state: "pending" }],
    [{ name: "eth3", label: "Newest target" }],
  );
  const ctx = projectionContext(() => Promise.resolve(responseFor(oldDocument)));
  const tableElement = { dataset: {} };
  const table = createGrid();
  const realUpdateData = table.updateData.bind(table);
  let updateCalls = 0;
  table.updateData = async (updates) => {
    updateCalls += 1;
    if (updateCalls === 1) await olderUpdate.promise;
    await realUpdateData(updates);
  };
  let generation = 1;
  let updateQueue = Promise.resolve();
  const enqueue = (update) => {
    const queued = updateQueue.then(update);
    updateQueue = queued.catch(() => {});
    return queued;
  };
  const oldRefresh = ctx.refresh(tableElement, table, () => generation === 1, enqueue);
  while (updateCalls === 0) await new Promise((resolve) => setImmediate(resolve));
  generation = 2;
  const newCtx = projectionContext(newDocument);
  const newRefresh = newCtx.refresh(tableElement, table, () => generation === 2, enqueue);
  await Promise.resolve();
  assert.equal(updateCalls, 1);
  olderUpdate.resolve();
  assert.equal(await oldRefresh, false);
  assert.deepEqual(JSON.parse(JSON.stringify(await newRefresh)), [{ name: "eth3", label: "Newest target" }]);
  assert.equal(table.rows.get("9").effective_action, "newest");
  assert.equal(table.rows.get("generated:access-a-to-b-ipv4").effective_action, "newest generated");
  assert.equal(JSON.parse(tableElement.dataset.targetOptions)[0].name, "eth3");
});

function saveContext({ postError = null, ErrorConstructor = null } = {}) {
  const messages = [];
  let restores = 0;
  let sideStackRefreshes = 0;
  const globals = {
    clearCaMessage() {},
    managementUiPath: (path) => path,
    postWanAction: async () => { if (postError) throw postError; },
    refreshNetworkSideStack: async () => { sideStackRefreshes += 1; },
    showTransientGridStatus() {},
    showWanMessage: (_id, message) => messages.push(message),
  };
  if (ErrorConstructor) globals.Error = ErrorConstructor;
  const ctx = vm.createContext(globals);
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

test("a failed-save projection refresh keeps the save error and adds reload guidance", async () => {
  const state = saveContext({ postError: new Error("permission was rejected"), ErrorConstructor: Error });
  await state.ctx.save(state.cell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    afterSave: async () => assert.fail("failed saves must not run the success callback"),
    afterFailure: async () => { throw new Error("projection response unavailable"); },
  });
  assert.equal(state.restores(), 1);
  assert.match(state.messages.at(-1), /permission was rejected.*current routing state could not be fully refreshed.*reload the page/i);
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

test("an older save completion cannot restore or refresh over a newer edit", async () => {
  const olderSave = deferred();
  const newerSave = deferred();
  const calls = [];
  let generation = 1;
  const status = [];
  const ctx = vm.createContext({
    clearCaMessage() {},
    managementUiPath: (path) => path,
    postWanAction: (_url, data) => data.enabled ? newerSave.promise : olderSave.promise,
    refreshNetworkSideStack: async () => {},
    showTransientGridStatus: (message) => status.push(message),
    showWanMessage: (_id, message) => calls.push(message),
  });
  vm.runInContext(
    `async ${functionSource("saveWanEnabledState")}; globalThis.save = saveWanEnabledState;`,
    ctx,
  );
  let restores = 0;
  let oldAfterSave = 0;
  let newAfterSave = 0;
  const cell = (enabled) => ({
    getRow: () => ({ getData: () => ({ id: 9, enabled }) }),
    restoreOldValue: () => { restores += 1; },
  });
  const oldEdit = ctx.save(cell(false), "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    isCurrent: () => generation === 1,
    afterSave: async () => { oldAfterSave += 1; },
  });
  generation = 2;
  const newEdit = ctx.save(cell(true), "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    isCurrent: () => generation === 2,
    afterSave: async () => { newAfterSave += 1; },
  });
  newerSave.resolve();
  await newEdit;
  olderSave.resolve();
  await oldEdit;

  assert.equal(restores, 0);
  assert.equal(oldAfterSave, 0);
  assert.equal(newAfterSave, 1);
  assert.equal(status.length, 1);
  assert.deepEqual(calls, []);
});

function routingInitializerContext({ rows, generatedRows = [], postWanAction, projection = null, refreshSideStack = async () => {}, ErrorConstructor = null }) {
  const messages = [];
  let sideStackRefreshes = 0;
  const HTMLElementStub = class HTMLElement {};
  const tableElement = new class extends HTMLElementStub {
    constructor() {
      super();
      this.dataset = {
        canWrite: "true",
        csrf: "csrf",
        rules: JSON.stringify(rows),
        generatedRules: JSON.stringify(generatedRows),
        targetOptions: JSON.stringify([{ name: "eth1", label: "Access 1" }]),
      };
    }
  }();
  let gridOptions;
  const table = {
    rows: new Map(),
    getRows(kind) {
      assert.equal(kind, "all");
      return [...this.rows.values()].map((data) => ({ getData: () => data }));
    },
    async updateData(updates) {
      for (const update of updates) {
        const current = this.rows.get(String(update.id));
        this.rows.set(String(update.id), { ...current, ...update });
      }
    },
  };
  const globals = {
    DOMParser: class { parseFromString(value) { return value; } },
    HTMLElement: HTMLElementStub,
    Tabulator: function Tabulator() {},
    clearCaMessage() {},
    document: { getElementById: (id) => id === "routes-wan-routing-table" ? tableElement : null },
    escapeHtml: (value) => String(value ?? ""),
    fetch: async () => ({ ok: true, text: async () => projection
      ? projection()
      : projectionDocument(
        rows.map((row) => ({ ...row, effective_action: row.enabled ? "explicit allow" : "suspended", apply_state: "pending" })),
        generatedRows,
      ) }),
    managementUiPath: (path) => path,
    postWanAction,
    refreshNetworkSideStack: async () => {
      sideStackRefreshes += 1;
      return refreshSideStack();
    },
    showTransientGridStatus() {},
    showWanMessage: (id, message) => messages.push({ id, message }),
    window: {
      location: { href: "/ui/management/routes-wan#routes-wan-routing-panel" },
      AtlasoUiPatterns: {
        createGrid: ({ options }) => {
          gridOptions = options;
          table.rows = new Map(options.data.map((row) => [String(row.id), { ...row }]));
          return { table };
        },
      },
    },
  };
  if (ErrorConstructor) globals.Error = ErrorConstructor;
  const ctx = vm.createContext(globals);
  vm.runInContext(
    `async ${functionSource("saveWanEnabledState")}\nasync ${functionSource("refreshRoutesWanRoutingProjection")}\n${functionSource("initializeRoutesWanRoutingTable")}\nglobalThis.initialize = initializeRoutesWanRoutingTable;`,
    ctx,
  );
  ctx.initialize();
  const enabledColumn = gridOptions.columns.find((column) => column.field === "enabled");
  const edit = (id) => {
    const row = table.rows.get(String(id));
    return {
      row,
      cell: {
        getRow: () => ({
          getData: () => row,
          update: async (updates) => Object.assign(row, updates),
        }),
        restoreOldValue: () => assert.fail("routing rollback should use confirmed state"),
      },
      submit: () => enabledColumn.cellEdited({
        getRow: () => ({
          getData: () => row,
          update: async (updates) => Object.assign(row, updates),
        }),
      }),
    };
  };
  return { table, tableElement, edit, gridOptions, messages, sideStackRefreshes: () => sideStackRefreshes };
}

const twoRoutingRows = () => [
  { id: 9, generated: false, enabled: true, effective_action: "explicit allow", apply_state: "applied" },
  { id: 10, generated: false, enabled: true, effective_action: "explicit allow", apply_state: "applied" },
];

test("initializer serializes same-row POST snapshots so the final server and grid values match", async () => {
  const requests = [];
  const serverRows = twoRoutingRows();
  const state = routingInitializerContext({
    rows: serverRows,
    postWanAction: (_url, data) => {
      const request = { data: { ...data }, deferred: deferred() };
      requests.push(request);
      return request.deferred.promise.then(() => {
        serverRows.find((row) => String(row.id) === String(data.id)).enabled = data.enabled;
      });
    },
  });
  const first = state.edit(9);
  first.row.enabled = false;
  const firstEdit = first.submit();
  first.row.enabled = true;
  const second = state.edit(9);
  const secondEdit = second.submit();

  while (requests.length < 1) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(requests.length, 1);
  assert.equal(requests[0].data.enabled, false);
  requests[0].deferred.resolve();
  while (requests.length < 2) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(requests[1].data.enabled, true);
  requests[1].deferred.resolve();
  await Promise.all([firstEdit, secondEdit]);

  assert.equal(serverRows.find((row) => row.id === 9).enabled, true);
  assert.equal(state.table.rows.get("9").enabled, true);
});

test("a failed earlier row save restores that row while a newer different row saves", async () => {
  const requests = [];
  const serverRows = twoRoutingRows();
  const state = routingInitializerContext({
    rows: serverRows,
    postWanAction: (_url, data) => {
      const request = { data: { ...data }, deferred: deferred() };
      requests.push(request);
      return request.deferred.promise.then(() => {
        serverRows.find((row) => String(row.id) === String(data.id)).enabled = data.enabled;
      });
    },
  });
  const first = state.edit(9);
  first.row.enabled = false;
  const firstEdit = first.submit();
  const second = state.edit(10);
  second.row.enabled = false;
  const secondEdit = second.submit();

  while (requests.length < 1) await new Promise((resolve) => setImmediate(resolve));
  requests[0].deferred.reject(new Error("row 9 rejected"));
  await firstEdit;
  assert.equal(first.row.enabled, true);
  assert.equal(state.sideStackRefreshes(), 0);
  while (requests.length < 2) await new Promise((resolve) => setImmediate(resolve));
  requests[1].deferred.resolve();
  await secondEdit;

  assert.equal(serverRows.find((row) => row.id === 9).enabled, true);
  assert.equal(serverRows.find((row) => row.id === 10).enabled, false);
  assert.equal(state.table.rows.get("9").enabled, true);
  assert.equal(state.table.rows.get("10").enabled, false);
});

test("two failed same-row edits restore the last confirmed Enabled value", async () => {
  const requests = [];
  const serverRows = twoRoutingRows();
  const state = routingInitializerContext({
    rows: serverRows,
    postWanAction: () => {
      const request = deferred();
      requests.push(request);
      return request.promise;
    },
  });
  const first = state.edit(9);
  first.row.enabled = false;
  const firstEdit = first.submit();
  first.row.enabled = true;
  const secondEdit = first.submit();
  while (requests.length < 1) await new Promise((resolve) => setImmediate(resolve));
  requests[0].reject(new Error("first save failed"));
  await firstEdit;
  while (requests.length < 2) await new Promise((resolve) => setImmediate(resolve));
  requests[1].reject(new Error("second save failed"));
  await secondEdit;
  assert.equal(first.row.enabled, true);
  assert.equal(serverRows[0].enabled, true);
});

test("a latest failed edit refreshes the authoritative projection after an earlier save commits", async (t) => {
  for (const scenario of [
    { name: "same row", newerId: 9, newerValue: true, expectedSecond: true },
    { name: "different row", newerId: 10, newerValue: false, expectedSecond: true },
  ]) {
    await t.test(scenario.name, async () => {
      const requests = [];
      const serverRows = twoRoutingRows().map((row) => ({ ...row, source_interface: "eth2", source_networks: [] }));
      let railSnapshot = null;
      const generatedRow = {
        id: "generated:access-a-to-b-ipv4",
        generated: true,
        effective_action: "automatic allow",
        apply_state: "applied",
      };
      const projection = () => {
        const anyDisabled = serverRows.some((row) => !row.enabled);
        return projectionDocument(
          serverRows.map((row) => ({
            ...row,
            effective_action: row.enabled ? "explicit allow" : "suspended",
            apply_state: row.enabled ? "applied" : "pending",
          })),
          [{
            ...generatedRow,
            effective_action: anyDisabled ? "automatic deny" : "automatic allow",
            apply_state: anyDisabled ? "pending" : "applied",
          }],
          [{ name: "eth2", label: "Updated access target" }],
        );
      };
      const state = routingInitializerContext({
        rows: serverRows,
        generatedRows: [generatedRow],
        projection,
        refreshSideStack: async () => {
          const anyDisabled = serverRows.some((row) => !row.enabled);
          railSnapshot = {
            validation: anyDisabled ? "review required" : "valid",
            preview: serverRows.map((row) => `${row.id}:${row.enabled ? "enabled" : "disabled"}`),
          };
        },
        postWanAction: (_url, data) => {
          const request = { data: { ...data }, deferred: deferred() };
          requests.push(request);
          return request.deferred.promise.then(() => {
            const saved = serverRows.find((row) => String(row.id) === String(data.id));
            saved.enabled = data.enabled;
          });
        },
      });
      const first = state.edit(9);
      first.row.enabled = false;
      const firstEdit = first.submit();
      const second = state.edit(scenario.newerId);
      second.row.enabled = scenario.newerValue;
      const secondEdit = second.submit();

      while (requests.length < 1) await new Promise((resolve) => setImmediate(resolve));
      requests[0].deferred.resolve();
      while (requests.length < 2) await new Promise((resolve) => setImmediate(resolve));
      requests[1].deferred.reject(new Error("newer save failed"));
      await Promise.all([firstEdit, secondEdit]);

      assert.equal(serverRows.find((row) => row.id === 9).enabled, false);
      assert.equal(serverRows.find((row) => row.id === 10).enabled, scenario.expectedSecond);
      assert.deepEqual(railSnapshot, {
        validation: "review required",
        preview: serverRows.map((row) => `${row.id}:${row.enabled ? "enabled" : "disabled"}`),
      });
      assert.equal(state.sideStackRefreshes(), 1);
      for (const row of serverRows) {
        const displayed = state.table.rows.get(String(row.id));
        assert.equal(displayed.enabled, row.enabled);
        assert.equal(displayed.effective_action, row.enabled ? "explicit allow" : "suspended");
        assert.equal(displayed.apply_state, row.enabled ? "applied" : "pending");
      }
      const displayedGenerated = state.table.rows.get(generatedRow.id);
      assert.equal(displayedGenerated.effective_action, "automatic deny");
      assert.equal(displayedGenerated.apply_state, "pending");
      assert.equal(JSON.parse(state.tableElement.dataset.rules).find((row) => row.id === 9).enabled, false);
      assert.equal(JSON.parse(state.tableElement.dataset.generatedRules)[0].effective_action, "automatic deny");
      assert.deepEqual(JSON.parse(state.tableElement.dataset.targetOptions), [{ name: "eth2", label: "Updated access target" }]);
      const sourceColumn = state.gridOptions.columns.find((column) => column.field === "source_networks");
      const sourceRow = state.table.rows.get("9");
      assert.match(sourceColumn.formatter({
        getValue: () => sourceRow.source_networks,
        getRow: () => ({ getData: () => sourceRow }),
      }), /Updated access target/);
      assert.match(state.messages.at(-1).message, /The routing permission could not be saved\./);
    });
  }
});

test("a failed save keeps its error and reload guidance when the recovery rail refresh fails", async () => {
  const request = deferred();
  const state = routingInitializerContext({
    rows: twoRoutingRows(),
    ErrorConstructor: Error,
    postWanAction: () => request.promise,
    refreshSideStack: async () => { throw new Error("network status unavailable"); },
  });
  const edit = state.edit(9);
  edit.row.enabled = false;
  const pendingEdit = edit.submit();
  request.reject(new Error("permission was rejected"));
  await pendingEdit;

  assert.equal(edit.row.enabled, true);
  assert.equal(state.sideStackRefreshes(), 1);
  assert.match(state.messages.at(-1).message, /permission was rejected.*current routing state could not be fully refreshed.*reload the page/i);
});

test("routing Enabled uses the authoritative projection refresh while other resource toggles remain shared", () => {
  const routing = functionSource("initializeRoutesWanRoutingTable");
  assert.ok(routing.includes("afterFailure: refreshAfterFailure"));
  assert.ok(routing.includes("const generation = ++routingEditGeneration"));
  assert.ok(routing.includes("if (refreshedTargets && isCurrent())"));
  assert.ok(routing.includes("refreshRoutesWanRoutingProjection("));
  assert.ok(routing.includes("table = window.AtlasoUiPatterns.createGrid"));
  const initializer = functionSource("initializeRoutesWanNatTable");
  assert.ok(initializer.includes('saveWanEnabledState(cell, csrf, "/traffic-publishing/nat-rules"'));
});
