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

async function waitForCondition(predicate, message, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function withTimeout(promise, message, timeoutMs = 1000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function responseFor(document) {
  return { ok: true, text: async () => document };
}

function sideStackContext({ currentPresent = true, refreshedPresent = true, response = { ok: true, text: async () => "updated side stack" }, initialize = () => {} } = {}) {
  const HTMLElementStub = class HTMLElement {};
  const currentSideStack = currentPresent ? new HTMLElementStub() : null;
  const nextSideStack = refreshedPresent ? new HTMLElementStub() : null;
  let attachedSideStack = currentSideStack;
  const calls = { fetch: 0, replacements: [], initialized: [], highlighted: [] };
  if (currentSideStack) currentSideStack.replaceWith = (replacement) => {
    calls.replacements.push(replacement);
    if (attachedSideStack === currentSideStack) attachedSideStack = replacement;
  };
  const ctx = vm.createContext({
    DOMParser: class { parseFromString() { return { querySelector: () => nextSideStack }; } },
    HTMLElement: HTMLElementStub,
    document: { querySelector: () => attachedSideStack },
    fetch: async () => { calls.fetch += 1; return response; },
    highlightConfigPreviews: (sideStack) => calls.highlighted.push(sideStack),
    initializeRefreshedSideStack: (sideStack) => {
      calls.initialized.push(sideStack);
      initialize(sideStack);
    },
    clearNetworkSideStackRefreshWarnings() {},
    window: { location: { href: "/ui/management/routes-wan" } },
  });
  vm.runInContext(`let networkSideStackRefreshGeneration = 0; let networkSideStackRefreshRequest = null; async ${functionSource("refreshNetworkSideStack")}; globalThis.refresh = refreshNetworkSideStack;`, ctx);
  return { ctx, calls, currentSideStack, nextSideStack, attachedSideStack: () => attachedSideStack };
}

function concurrentSideStackContext() {
  const HTMLElementStub = class HTMLElement {
    constructor(name) {
      this.name = name;
      this.textContent = "";
      this.classes = new Set();
      this.classList = {
        add: (...names) => names.forEach((value) => this.classes.add(value)),
        remove: (...names) => names.forEach((value) => this.classes.delete(value)),
        toggle: (value, enabled) => {
          if (enabled) this.classes.add(value);
          else this.classes.delete(value);
          return this.classes.has(value);
        },
      };
    }
  };
  const calls = { fetch: 0, replacements: [], initialized: [], highlighted: [] };
  const saves = { firewall: 0 };
  const initialSideStack = new HTMLElementStub("initial");
  const oldSideStack = new HTMLElementStub("old response");
  const newSideStack = new HTMLElementStub("new response");
  const sideStacksByResponse = new Map([[
    "older response",
    oldSideStack,
  ], [
    "newer response",
    newSideStack,
  ]]);
  let attachedSideStack = initialSideStack;
  const messages = [];
  const alertElements = new Map();
  let firewallPostFailure = null;
  const alertElement = (id) => {
    if (!alertElements.has(id)) {
      const element = new HTMLElementStub(id);
      element.id = id;
      alertElements.set(id, element);
    }
    return alertElements.get(id);
  };
  const attachable = [initialSideStack, oldSideStack, newSideStack];
  const statuses = [];
  attachable.forEach((sideStack) => {
    sideStack.replaceWith = (replacement) => {
      if (attachedSideStack !== sideStack) return;
      calls.replacements.push(replacement);
      attachedSideStack = replacement;
    };
  });
  const responses = [];
  const ctx = vm.createContext({
    DOMParser: class { parseFromString(html) { return { querySelector: () => sideStacksByResponse.get(html) || null }; } },
    HTMLElement: HTMLElementStub,
    document: {
      querySelector: (selector) => selector === "aside.side-stack" ? attachedSideStack : null,
      getElementById: alertElement,
    },
    fetch: async () => { calls.fetch += 1; return responses.shift(); },
    highlightConfigPreviews: (sideStack) => calls.highlighted.push(sideStack),
    initializeRefreshedSideStack: (sideStack) => calls.initialized.push(sideStack),
    clearCaMessage: (id) => { alertElement(id).textContent = ""; },
    managementUiPath: (path) => path,
    postWanAction: async () => {},
    postFirewallRuleAction: async () => {
      saves.firewall += 1;
      if (firewallPostFailure) throw firewallPostFailure;
    },
    showTransientGridStatus: (status) => statuses.push(status),
    showWanMessage: (id, message) => {
      messages.push({ id, message });
      alertElement(id).textContent = message;
    },
    showCaMessage: (id, message) => {
      messages.push({ id, message });
      const element = alertElement(id);
      element.textContent = message;
      element.classList.toggle("error", true);
      element.classList.remove("hidden");
    },
    window: { location: { href: "/ui/management/routes-wan" } },
  });
  vm.runInContext(`let networkSideStackRefreshGeneration = 0; let networkSideStackRefreshRequest = null; let networkSideStackRefreshWarnings = new Map(); ${functionSource("networkSideStackRefreshWarningText")}; ${functionSource("networkSideStackRefreshFailureMessage")}; ${functionSource("rememberNetworkSideStackRefreshWarning")}; ${functionSource("showNetworkSideStackRefreshWarning")}; ${functionSource("clearNetworkSideStackRefreshWarnings")}; async ${functionSource("refreshNetworkSideStack")}; async ${functionSource("saveWanEnabledState")}; async ${functionSource("autoSaveFirewallRule")}; globalThis.refresh = refreshNetworkSideStack; globalThis.save = saveWanEnabledState; globalThis.saveFirewall = autoSaveFirewallRule;`, ctx);
  return {
    ctx,
    calls,
    saves,
    statuses,
    messages,
    alertElements,
    responses,
    oldSideStack,
    newSideStack,
    attachedSideStack: () => attachedSideStack,
    setAttachedSideStack: (sideStack) => { attachedSideStack = sideStack; },
    setFirewallPostFailure: (error) => { firewallPostFailure = error; },
  };
}

test("side-stack refresh reports non-success HTTP responses and missing current or refreshed asides", async (t) => {
  await t.test("non-2xx", async () => {
    const state = sideStackContext({ response: { ok: false } });
    assert.equal(await state.ctx.refresh(), false);
    assert.equal(state.calls.replacements.length, 0);
  });
  await t.test("missing current aside", async () => {
    const state = sideStackContext({ currentPresent: false });
    assert.equal(await state.ctx.refresh(), false);
    assert.equal(state.calls.fetch, 0);
  });
  await t.test("missing refreshed aside", async () => {
    const state = sideStackContext({ refreshedPresent: false });
    assert.equal(await state.ctx.refresh(), false);
    assert.equal(state.calls.replacements.length, 0);
  });
  await t.test("response-body exception", async () => {
    const state = sideStackContext({ response: { ok: true, text: async () => { throw new Error("body read failed"); } } });
    assert.equal(await state.ctx.refresh(), false);
  });
  await t.test("side-stack initialization exception", async () => {
    const state = sideStackContext({ initialize: () => { throw new Error("initialization failed"); } });
    assert.equal(await state.ctx.refresh(), false);
  });
});

test("side-stack refresh replaces and initializes the refreshed aside", async () => {
  const state = sideStackContext();
  assert.equal(await state.ctx.refresh(), true);
  assert.deepEqual(state.calls.replacements, [state.nextSideStack]);
  assert.deepEqual(state.calls.initialized, [state.nextSideStack]);
  assert.deepEqual(state.calls.highlighted, [state.nextSideStack]);
});

test("an invalidated side-stack refresh resolves as superseded without waiting for a successor", async () => {
  const responseText = deferred();
  let readingText = false;
  const state = sideStackContext({ response: { ok: true, text: () => {
    readingText = true;
    return responseText.promise;
  } } });
  let current = true;
  const refresh = state.ctx.refresh(() => current);
  while (!readingText) await new Promise((resolve) => setImmediate(resolve));
  current = false;
  responseText.resolve("obsolete side stack");
  assert.equal(await withTimeout(refresh, "superseded refresh remained pending"), "superseded");
  assert.equal(state.calls.replacements.length, 0);
});

test("legacy save callers stay neutral when their adopted Routing refresh is invalidated", async (t) => {
  for (const finalRail of ["success", "failure"]) {
    await t.test(`newest rail ${finalRail}`, async () => {
      const legacyText = deferred();
      const routingText = deferred();
      const latestText = deferred();
      let legacyTextStarted = false;
      let routingTextStarted = false;
      let latestTextStarted = false;
      const state = concurrentSideStackContext();
      state.responses.push(
        { ok: true, text: () => { legacyTextStarted = true; return legacyText.promise; } },
        { ok: true, text: () => { routingTextStarted = true; return routingText.promise; } },
        finalRail === "success"
          ? { ok: true, text: () => { latestTextStarted = true; return latestText.promise; } }
          : { ok: false },
      );
      const firewallCell = { getRow: () => ({ getData: () => ({ id: 77, enabled: false }) }) };
      const legacySave = state.ctx.saveFirewall(firewallCell, "csrf");
      await waitForCondition(() => legacyTextStarted, "legacy side-panel refresh did not start");

      let routingEditCurrent = true;
      const routingCell = { getRow: () => ({ getData: () => ({ id: 9, enabled: false }) }) };
      const routingSave = state.ctx.save(routingCell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
        isCurrent: () => routingEditCurrent,
        afterSave: async () => {},
      });
      await waitForCondition(() => routingTextStarted, "guarded Routing refresh did not start");
      routingEditCurrent = false;
      routingText.resolve("obsolete Routing response");
      await withTimeout(Promise.all([legacySave, routingSave]), "invalidated callers remained pending");
      assert.deepEqual(state.messages, []);
      assert.deepEqual(state.statuses, []);
      assert.deepEqual(state.calls.replacements, []);

      const latestSave = state.ctx.save(routingCell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
        afterSave: async () => {},
      });
      if (finalRail === "success") {
        await waitForCondition(() => latestTextStarted, "latest Routing refresh did not start");
      }

      if (finalRail === "success") latestText.resolve("newer response");
      await latestSave;
      legacyText.resolve("obsolete legacy response");
      await Promise.resolve();

      assert.equal(state.saves.firewall, 1);
      assert.deepEqual(state.messages, finalRail === "success" ? [] : [
        {
          id: "routing-error",
          message: "The routing permission and its displayed state were saved, but the network status panel could not be refreshed. Reload the page to see the latest state.",
        },
      ]);
      assert.deepEqual(state.statuses, finalRail === "success" ? ["Saved"] : []);
      assert.deepEqual(state.calls.replacements, finalRail === "success" ? [state.newSideStack] : []);
    });
  }
});

test("overlapping side-stack refreshes replace the attached rail in either completion order", async (t) => {
  for (const order of ["newer first", "older first"]) {
    await t.test(order, async () => {
      const oldText = deferred();
      const newText = deferred();
      let oldTextStarted = false;
      let newTextStarted = false;
      const state = concurrentSideStackContext();
      state.responses.push(
        { ok: true, text: () => { oldTextStarted = true; return oldText.promise; } },
        { ok: true, text: () => { newTextStarted = true; return newText.promise; } },
      );
      const oldRefresh = state.ctx.refresh();
      await waitForCondition(() => oldTextStarted, "older side-panel response text did not start");
      const newRefresh = state.ctx.refresh();
      await waitForCondition(() => newTextStarted, "newer side-panel response text did not start");
      if (order === "newer first") {
        newText.resolve("newer response");
        assert.equal(await newRefresh, true);
        oldText.resolve("older response");
        assert.equal(await oldRefresh, true);
      } else {
        oldText.resolve("older response");
        const supersededOldRefresh = assert.doesNotReject(oldRefresh);
        newText.resolve("newer response");
        assert.equal(await newRefresh, true);
        await supersededOldRefresh;
      }
      assert.equal(state.attachedSideStack(), state.newSideStack);
      assert.deepEqual(state.calls.replacements, [state.newSideStack]);
      assert.deepEqual(state.calls.initialized, [state.newSideStack]);
      assert.deepEqual(state.calls.highlighted, [state.newSideStack]);
    });
  }
});

test("superseded side-stack callers observe the newest HTTP failure", async () => {
  const oldText = deferred();
  let oldTextStarted = false;
  const state = concurrentSideStackContext();
  state.responses.push(
    { ok: true, text: () => { oldTextStarted = true; return oldText.promise; } },
    { ok: false },
  );
  const oldRefresh = state.ctx.refresh();
  await waitForCondition(() => oldTextStarted, "older side-panel response text did not start");
  const newestRefresh = state.ctx.refresh();

  assert.equal(await newestRefresh, false);
  assert.equal(await oldRefresh, false);
  oldText.resolve("obsolete response");
  await Promise.resolve();
  assert.equal(state.attachedSideStack().name, "initial");
  assert.deepEqual(state.calls.replacements, []);
});

test("superseded side-stack text failures defer to the latest success", async () => {
  const oldText = deferred();
  const newText = deferred();
  let oldTextStarted = false;
  let newTextStarted = false;
  const state = concurrentSideStackContext();
  state.responses.push(
    { ok: true, text: () => { oldTextStarted = true; return oldText.promise; } },
    { ok: true, text: () => { newTextStarted = true; return newText.promise; } },
  );
  const oldRefresh = state.ctx.refresh();
  await waitForCondition(() => oldTextStarted, "older side-panel response text did not start");
  const newestRefresh = state.ctx.refresh();
  await waitForCondition(() => newTextStarted, "newer side-panel response text did not start");

  newText.resolve("newer response");
  assert.equal(await newestRefresh, true);
  oldText.reject(new Error("obsolete response text failed"));
  assert.equal(await oldRefresh, true);
  assert.equal(state.attachedSideStack(), state.newSideStack);
  assert.deepEqual(state.calls.replacements, [state.newSideStack]);
});

test("multiple side-stack supersessions follow the final refresh result", async () => {
  const firstText = deferred();
  const secondText = deferred();
  const finalText = deferred();
  const textStarted = [false, false, false];
  const state = concurrentSideStackContext();
  state.responses.push(
    { ok: true, text: () => { textStarted[0] = true; return firstText.promise; } },
    { ok: true, text: () => { textStarted[1] = true; return secondText.promise; } },
    { ok: true, text: () => { textStarted[2] = true; return finalText.promise; } },
  );
  const firstRefresh = state.ctx.refresh();
  await waitForCondition(() => textStarted[0], "first side-panel response text did not start");
  const secondRefresh = state.ctx.refresh();
  await waitForCondition(() => textStarted[1], "second side-panel response text did not start");
  const finalRefresh = state.ctx.refresh();
  await waitForCondition(() => textStarted[2], "final side-panel response text did not start");

  finalText.resolve("newer response");
  assert.equal(await finalRefresh, true);
  assert.equal(await firstRefresh, true);
  assert.equal(await secondRefresh, true);
  firstText.resolve("older response");
  secondText.resolve("older response");
  assert.equal(state.attachedSideStack(), state.newSideStack);
  assert.deepEqual(state.calls.replacements, [state.newSideStack]);
});

test("a Routing save does not warn when a newer shared side-panel refresh succeeds", async () => {
  const routingText = deferred();
  const staticText = deferred();
  let routingTextStarted = false;
  let staticTextStarted = false;
  const state = concurrentSideStackContext();
  state.responses.push(
    { ok: true, text: () => { routingTextStarted = true; return routingText.promise; } },
    { ok: true, text: () => { staticTextStarted = true; return staticText.promise; } },
  );
  const cell = { getRow: () => ({ getData: () => ({ id: 9, enabled: false }) }) };
  const routingSave = state.ctx.save(cell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    afterSave: async () => {},
  });
  await waitForCondition(() => routingTextStarted, "Routing side-panel response text did not start");
  const staticRefresh = state.ctx.refresh();
  await waitForCondition(() => staticTextStarted, "newer side-panel response text did not start");
  staticText.resolve("newer response");

  assert.equal(await staticRefresh, true);
  await routingSave;
  assert.deepEqual(state.messages, []);
  routingText.resolve("older response");
  assert.equal(state.attachedSideStack(), state.newSideStack);
});

test("a Routing save still warns when the newest shared side-panel refresh fails", async () => {
  const routingText = deferred();
  let routingTextStarted = false;
  const state = concurrentSideStackContext();
  state.responses.push(
    { ok: true, text: () => { routingTextStarted = true; return routingText.promise; } },
    { ok: false },
  );
  const cell = { getRow: () => ({ getData: () => ({ id: 9, enabled: false }) }) };
  const routingSave = state.ctx.save(cell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    afterSave: async () => {},
  });
  await waitForCondition(() => routingTextStarted, "Routing side-panel response text did not start");
  const staticRefresh = state.ctx.refresh();

  assert.equal(await staticRefresh, false);
  await routingSave;
  assert.match(state.messages.at(-1).message, /network status panel could not be refreshed.*reload the page/i);
  routingText.resolve("older response");
  assert.equal(state.calls.replacements.length, 0);
});

test("superseded callers receive false when the newest side-panel refresh throws", async () => {
  const olderText = deferred();
  const newestText = deferred();
  let olderTextStarted = false;
  let newestTextStarted = false;
  const state = concurrentSideStackContext();
  state.responses.push(
    { ok: true, text: () => { olderTextStarted = true; return olderText.promise; } },
    { ok: true, text: () => { newestTextStarted = true; return newestText.promise; } },
  );
  const oldRefresh = state.ctx.refresh();
  await waitForCondition(() => olderTextStarted, "older side-panel response text did not start");
  const newestRefresh = state.ctx.refresh();
  await waitForCondition(() => newestTextStarted, "newest side-panel response text did not start");
  newestText.reject(new Error("newest side-panel response failed"));

  assert.equal(await newestRefresh, false);
  assert.equal(await oldRefresh, false);
  olderText.resolve("older response");
});

test("a committed legacy firewall save reports its own refresh failure without rollback or success status", async () => {
  const fetchFailure = deferred();
  const state = concurrentSideStackContext();
  state.responses.push(fetchFailure.promise);
  let restores = 0;
  const cell = {
    getRow: () => ({ getData: () => ({ id: 77, enabled: false }) }),
    restoreOldValue: () => { restores += 1; },
  };
  const save = state.ctx.saveFirewall(cell, "csrf");
  await waitForCondition(() => state.calls.fetch === 1, "firewall side-panel refresh did not start");
  fetchFailure.reject(new Error("side-panel fetch failed"));
  await save;

  assert.equal(state.saves.firewall, 1);
  assert.equal(restores, 0);
  assert.deepEqual(state.statuses, []);
  assert.equal(state.messages.length, 1);
  assert.equal(state.messages[0].id, "firewall-rule-error");
  assert.match(state.messages[0].message, /change was saved.*could not be refreshed.*reload the page/i);
});

test("a committed legacy firewall save reports a superseding refresh failure without rollback or success status", async () => {
  const olderText = deferred();
  let olderTextStarted = false;
  const state = concurrentSideStackContext();
  state.responses.push(
    { ok: true, text: () => { olderTextStarted = true; return olderText.promise; } },
    { ok: true, text: async () => { throw new Error("newer side-panel body failed"); } },
  );
  let restores = 0;
  const cell = {
    getRow: () => ({ getData: () => ({ id: 77, enabled: false }) }),
    restoreOldValue: () => { restores += 1; },
  };
  const save = state.ctx.saveFirewall(cell, "csrf");
  await waitForCondition(() => olderTextStarted, "firewall side-panel response text did not start");
  assert.equal(await state.ctx.refresh(), false);
  await save;
  olderText.resolve("older response");

  assert.equal(state.saves.firewall, 1);
  assert.equal(restores, 0);
  assert.deepEqual(state.statuses, []);
  assert.equal(state.messages.length, 1);
  assert.equal(state.messages[0].id, "firewall-rule-error");
  assert.match(state.messages[0].message, /change was saved.*could not be refreshed.*reload the page/i);
});

test("a later successful Routing refresh clears only a settled side-panel warning", async () => {
  const state = concurrentSideStackContext();
  state.responses.push(
    { ok: false },
    { ok: true, text: async () => "newer response" },
  );
  const firewallCell = {
    getRow: () => ({ getData: () => ({ id: 77, enabled: false }) }),
    restoreOldValue() { assert.fail("a committed save must not roll back"); },
  };
  await state.ctx.saveFirewall(firewallCell, "csrf");

  const warning = "The change was saved, but the network status panel could not be refreshed. Reload the page to see the latest state.";
  const firewallAlert = state.alertElements.get("firewall-rule-error");
  assert.equal(firewallAlert.textContent, warning);

  const routingCell = { getRow: () => ({ getData: () => ({ id: 9, enabled: false }) }) };
  await state.ctx.save(routingCell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    afterSave: async () => {},
  });

  assert.equal(state.attachedSideStack(), state.newSideStack);
  assert.equal(firewallAlert.textContent, "");
  assert.equal(firewallAlert.classes.has("hidden"), true);
  assert.equal(state.messages.length, 1);
  assert.deepEqual(state.statuses, ["Saved"]);
});

test("a successful side-panel refresh preserves a genuine save error", async () => {
  const state = concurrentSideStackContext();
  const firewallCell = {
    getRow: () => ({ getData: () => ({ id: 77, enabled: false }) }),
    restoreOldValue() {},
  };
  state.responses.push({ ok: false }, { ok: true, text: async () => "newer response" });
  await state.ctx.saveFirewall(firewallCell, "csrf");
  const refreshWarning = "The change was saved, but the network status panel could not be refreshed. Reload the page to see the latest state.";
  const firewallAlert = state.alertElements.get("firewall-rule-error");
  assert.equal(firewallAlert.textContent, refreshWarning);

  state.setFirewallPostFailure(new Error("The firewall rule could not be saved."));
  await state.ctx.saveFirewall(firewallCell, "csrf");
  assert.match(firewallAlert.textContent, /firewall rule could not be saved/i);

  const routingCell = { getRow: () => ({ getData: () => ({ id: 9, enabled: false }) }) };
  await state.ctx.save(routingCell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    afterSave: async () => {},
  });

  assert.match(firewallAlert.textContent, /firewall rule could not be saved/i);
  assert.deepEqual(state.calls.replacements, [state.newSideStack]);
});

test("refresh warning cleanup handles the actual dismissible error toast", () => {
  class ElementStub {
    constructor(tagName) {
      this.tagName = tagName;
      this.id = "";
      this.attributes = {};
      this.children = [];
      this._textContent = "";
      this.classes = new Set();
      this.listeners = new Map();
      this.classList = {
        add: (...names) => names.forEach((name) => this.classes.add(name)),
        remove: (...names) => names.forEach((name) => this.classes.delete(name)),
        toggle: (name, enabled) => {
          if (enabled) this.classes.add(name);
          else this.classes.delete(name);
          return this.classes.has(name);
        },
      };
    }
    get textContent() {
      return this._textContent + this.children.map((child) => child.textContent).join("");
    }
    set textContent(value) {
      this._textContent = String(value);
      this.children = [];
    }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener(name, callback) { this.listeners.set(name, callback); }
    querySelector(selector) { return selector === "span" ? this.children.find((child) => child.tagName === "span") || null : null; }
    replaceChildren(...children) {
      this._textContent = "";
      this.children = children;
    }
  }
  let toast = null;
  const ctx = vm.createContext({
    document: {
      getElementById: (id) => id === "grid-status-toast" ? toast : null,
      createElement: (tagName) => new ElementStub(tagName),
      body: { appendChild: (element) => { toast = element; } },
    },
    window: { clearTimeout, setTimeout },
  });
  vm.runInContext(`let networkSideStackRefreshWarnings = new Map(); ${functionSource("networkSideStackRefreshWarningText")}; ${functionSource("rememberNetworkSideStackRefreshWarning")}; ${functionSource("clearNetworkSideStackRefreshWarnings")}; ${functionSource("showTransientGridStatus")};`, ctx);
  const warning = "The change was saved, but the network status panel could not be refreshed. Reload the page to see the latest state.";

  ctx.showTransientGridStatus(warning, { error: true });
  ctx.rememberNetworkSideStackRefreshWarning(toast, warning);
  assert.equal(toast.attributes.role, "alert");
  assert.equal(toast.attributes["aria-live"], "assertive");
  assert.equal(toast.children[0].textContent, warning);
  assert.equal(toast.children[1].textContent, "Dismiss");
  toast.children[1].listeners.get("click")();
  assert.equal(toast.classes.has("visible"), false);
  ctx.clearNetworkSideStackRefreshWarnings();
  assert.deepEqual(toast.children, []);
  assert.equal(toast.classes.has("error"), false);

  ctx.showTransientGridStatus(warning, { error: true });
  ctx.rememberNetworkSideStackRefreshWarning(toast, warning);
  ctx.showTransientGridStatus("A separate save failed.", { error: true });
  ctx.clearNetworkSideStackRefreshWarnings();
  assert.equal(toast.children[0].textContent, "A separate save failed.");
  assert.equal(toast.classes.has("visible"), true);
  assert.equal(toast.classes.has("error"), true);
});

test("the shared wizard skips optional side-panel refreshes on rail-less pages", async () => {
  class HTMLElementStub {
    constructor() { this.classList = { add() {}, remove() {} }; }
    setAttribute() {}
  }
  class HTMLFormElementStub extends HTMLElementStub {
    constructor() {
      super();
      this.elements = { namedItem: (name) => name === "enabled" ? enabledControl : null };
    }
  }
  class HTMLDialogElementStub extends HTMLElementStub {}
  class HTMLInputElementStub extends HTMLElementStub {}
  class FormDataStub {
    constructor() { this.values = new Map(); }
    set(name, value) { this.values.set(name, value); }
    get(name) { return this.values.get(name) ?? null; }
  }
  const enabledControl = new HTMLInputElementStub();
  const tableElement = Object.assign(new HTMLElementStub(), {
    dataset: { csrf: "csrf", fallbackId: "resource-fallback" },
    addEventListener() {},
  });
  const dialog = new HTMLDialogElementStub();
  const form = new HTMLFormElementStub();
  const status = new HTMLElementStub();
  const rowData = { id: 12, enabled: false };
  let rowDeleted = false;
  const row = {
    getData: () => rowData,
    async update(resource) { Object.assign(rowData, resource); },
    async delete() { rowDeleted = true; },
  };
  const addedRows = [];
  const statuses = [];
  let refreshes = 0;
  let savedCallbacks = 0;
  let deletedCallbacks = 0;
  let clickHandler;
  let gridOptions;
  let wizardOptions;
  const button = { setAttribute() {}, addEventListener: (_event, handler) => { clickHandler = handler; } };
  const table = {
    getRow: () => row,
    async addRow(resource) { addedRows.push(resource); return row; },
  };
  const ctx = vm.createContext({
    HTMLElement: HTMLElementStub,
    HTMLFormElement: HTMLFormElementStub,
    HTMLDialogElement: HTMLDialogElementStub,
    HTMLInputElement: HTMLInputElementStub,
    HTMLButtonElement: class HTMLButtonElement extends HTMLElementStub {},
    FormData: FormDataStub,
    document: {
      getElementById: (id) => id === "resource-table" ? tableElement : dialog,
      querySelector: (selector) => selector === "#resource-form" ? form : selector === "#resource-error" ? status : null,
      querySelectorAll: () => [],
      createElement: () => button,
    },
    window: { AtlasoUiPatterns: {
      createGrid: ({ options, rowActions }) => { gridOptions = options; table.rowActions = rowActions; return { table }; },
      createWizard: (options) => { wizardOptions = options; return {}; },
    } },
    populateAtlasoWizardForm: () => {},
    atlasoBooleanFormatter: (cell) => String(cell.getValue()),
    atlasoGridWizardRequest: async (_url, body, options = {}) => {
      if (options.expectJson === false) return {};
      return body.get("record_id")
        ? { item: { id: 12, enabled: true } }
        : { item: { id: 13, enabled: true } };
    },
    requestConfirmation: async () => true,
    refreshNetworkSideStack: async () => { refreshes += 1; return false; },
    networkSideStackRefreshFailureMessage: () => "The change was saved, but the network status panel could not be refreshed. Reload the page to see the latest state.",
    rememberNetworkSideStackRefreshWarning() {},
    showTransientGridStatus: (message) => statuses.push(message),
  });
  vm.runInContext(`function initializeAtlasoResourceWizard(config) { ${functionSource("initializeAtlasoResourceWizard").slice("function initializeAtlasoResourceWizard(config) {".length, -1)} }; globalThis.initialize = initializeAtlasoResourceWizard;`, ctx);
  ctx.initialize({
    elementId: "resource-table",
    formSelector: "#resource-form",
    dialogId: "resource-dialog",
    actionErrorSelector: "#resource-error",
    resourceName: "item",
    editUrl: (id) => `/items/${id}`,
    createUrl: "/items",
    deleteResource: true,
    deleteUrl: (id) => `/items/${id}`,
    deleteConfirmation: () => ({ title: "Delete item?" }),
    onSaved: () => { savedCallbacks += 1; },
    onDeleted: () => { deletedCallbacks += 1; },
    rows: [rowData],
    newRow: { id: "__new__", is_new: true },
    options: { columns: [{ field: "enabled" }] },
  });

  const cell = {
    getValue: () => rowData.enabled,
    getRow: () => row,
    setValue: (value) => { rowData.enabled = value; },
  };
  gridOptions.columns[0].formatter(cell);
  clickHandler({ stopPropagation() {} });
  await waitForCondition(() => statuses.length === 1, "rail-less inline save did not complete");
  assert.equal((await wizardOptions.onSubmit()).valid, true);
  await table.rowActions.find((action) => action.label === "Delete").action({}, row);

  assert.equal(refreshes, 0);
  assert.deepEqual(statuses, ["Enabled", "Created", "Deleted"]);
  assert.equal(savedCallbacks, 2);
  assert.equal(deletedCallbacks, 1);
  assert.equal(addedRows.length, 1);
  assert.equal(rowDeleted, true);
});

test("the shared wizard Enabled callback reports side-panel failure after a committed save", async () => {
  class HTMLElementStub {
    constructor() {
      this.classList = { add() {}, remove() {} };
    }
    setAttribute() {}
  }
  class HTMLFormElementStub extends HTMLElementStub {
    constructor() {
      super();
      this.elements = { namedItem: (name) => name === "enabled" ? enabledControl : null };
    }
  }
  class HTMLDialogElementStub extends HTMLElementStub {}
  class HTMLInputElementStub extends HTMLElementStub {}
  const tableElement = Object.assign(new HTMLElementStub(), {
    dataset: { csrf: "csrf", fallbackId: "resource-fallback" },
    addEventListener() {},
  });
  let attachedSideStack = new HTMLElementStub();
  const dialog = new HTMLDialogElementStub();
  const enabledControl = new HTMLInputElementStub();
  const form = new HTMLFormElementStub();
  const status = new HTMLElementStub();
  let clickHandler;
  const button = {
    setAttribute() {},
    addEventListener: (_name, handler) => { clickHandler = handler; },
  };
  const rowData = { id: 12, enabled: false };
  const row = {
    getData: () => rowData,
    async update(resource) { Object.assign(rowData, resource); },
  };
  let gridOptions;
  let writes = 0;
  let refreshes = 0;
  const statuses = [];
  const ctx = vm.createContext({
    HTMLElement: HTMLElementStub,
    HTMLFormElement: HTMLFormElementStub,
    HTMLDialogElement: HTMLDialogElementStub,
    HTMLInputElement: HTMLInputElementStub,
    HTMLButtonElement: class HTMLButtonElement extends HTMLElementStub {},
    FormData: class { constructor() {} },
    document: {
      getElementById: (id) => id === "resource-table" ? tableElement : dialog,
      querySelector: (selector) => selector === "#resource-form" ? form : selector === "#resource-error" ? status : selector === "aside.side-stack" ? attachedSideStack : null,
      querySelectorAll: () => [],
      createElement: () => button,
    },
    window: { AtlasoUiPatterns: {
      createGrid: ({ options }) => { gridOptions = options; return { table: { getRow: () => row } }; },
      createWizard: () => ({}),
    } },
    populateAtlasoWizardForm: () => {},
    atlasoBooleanFormatter: (cell) => String(cell.getValue()),
    atlasoGridWizardRequest: async () => { writes += 1; return { item: { id: 12, enabled: true } }; },
    refreshNetworkSideStack: async () => { refreshes += 1; return attachedSideStack !== null; },
    networkSideStackRefreshFailureMessage: () => "The change was saved, but the network status panel could not be refreshed. Reload the page to see the latest state.",
    rememberNetworkSideStackRefreshWarning() {},
    showTransientGridStatus: (message) => statuses.push(message),
  });
  vm.runInContext(`function initializeAtlasoResourceWizard(config) { ${functionSource("initializeAtlasoResourceWizard").slice("function initializeAtlasoResourceWizard(config) {".length, -1)} }; globalThis.initialize = initializeAtlasoResourceWizard;`, ctx);
  ctx.initialize({
    elementId: "resource-table",
    formSelector: "#resource-form",
    dialogId: "resource-dialog",
    actionErrorSelector: "#resource-error",
    resourceName: "item",
    editUrl: (id) => `/items/${id}`,
    rows: [rowData],
    newRow: { id: "__new__", is_new: true },
    options: { columns: [{ field: "enabled" }] },
  });
  attachedSideStack = null;

  const cell = {
    getValue: () => rowData.enabled,
    getRow: () => row,
    setValue: (value) => { rowData.enabled = value; },
  };
  gridOptions.columns[0].formatter(cell);
  clickHandler({ stopPropagation() {} });
  await waitForCondition(() => status.textContent, "shared wizard did not report the side-panel failure");

  assert.equal(writes, 1);
  assert.equal(refreshes, 1);
  assert.equal(rowData.enabled, true);
  assert.match(status.textContent, /change was saved.*could not be refreshed.*reload the page/i);
  assert.deepEqual(statuses, []);
});

test("a side-stack response cannot report success if its originally attached aside was detached", async () => {
  const responseText = deferred();
  const state = concurrentSideStackContext();
  state.responses.push({ ok: true, text: () => responseText.promise });
  const refresh = state.ctx.refresh();
  state.setAttachedSideStack(null);
  responseText.resolve("older response");
  assert.equal(await refresh, false);
  assert.equal(state.calls.replacements.length, 0);
  assert.equal(state.calls.initialized.length, 0);
});

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

function saveContext({ postError = null, ErrorConstructor = null, sideStackResult = true } = {}) {
  const messages = [];
  const statuses = [];
  const alertElements = new Map();
  const alertElement = (id) => {
    if (!alertElements.has(id)) {
      alertElements.set(id, { id, textContent: "", classList: { add() {}, remove() {} } });
    }
    return alertElements.get(id);
  };
  let restores = 0;
  let sideStackRefreshes = 0;
  const globals = {
    clearCaMessage() {},
    document: { getElementById: alertElement },
    managementUiPath: (path) => path,
    postWanAction: async () => { if (postError) throw postError; },
    refreshNetworkSideStack: async () => { sideStackRefreshes += 1; return sideStackResult; },
    showTransientGridStatus: (message) => statuses.push(message),
    showWanMessage: (_id, message) => messages.push(message),
    showCaMessage: (id, message) => {
      messages.push(message);
      alertElement(id).textContent = message;
    },
  };
  if (ErrorConstructor) globals.Error = ErrorConstructor;
  const ctx = vm.createContext(globals);
  vm.runInContext(
    `let networkSideStackRefreshWarnings = new Map(); ${functionSource("networkSideStackRefreshWarningText")}\n${functionSource("rememberNetworkSideStackRefreshWarning")}\n${functionSource("showNetworkSideStackRefreshWarning")}\n${functionSource("networkSideStackRefreshFailureMessage")}\nasync ${functionSource("saveWanEnabledState")}; globalThis.save = saveWanEnabledState;`,
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
    statuses,
    alertElements,
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

test("Routing warns and gives reload guidance when the successful-save side rail returns false", async () => {
  const state = saveContext({ sideStackResult: false });
  await state.ctx.save(state.cell, "csrf", "/routes-wan/routing-rules", "routing-error", "Save failed", {
    afterSave: async () => {},
  });
  assert.equal(state.restores(), 0);
  assert.match(state.messages.at(-1), /routing permission and its displayed state were saved.*network status panel could not be refreshed.*reload the page/i);
  assert.equal(state.sideStackRefreshes(), 1);
  assert.deepEqual(state.statuses, []);
});

test("a non-Routing save reports side-rail refresh failure without rollback or success status", async () => {
  const state = saveContext({ sideStackResult: false });
  await state.ctx.save(state.cell, "csrf", "/traffic-publishing/nat-rules", "nat-error", "Save failed");

  assert.equal(state.restores(), 0);
  assert.equal(state.sideStackRefreshes(), 1);
  assert.match(state.messages[0], /change was saved.*network status panel could not be refreshed.*reload the page/i);
  assert.deepEqual(state.statuses, []);
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
    refreshNetworkSideStack: async () => true,
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

function routingInitializerContext({ rows, generatedRows = [], postWanAction, projection = null, refreshSideStack = async () => true, ErrorConstructor = null, duringUpdate = null }) {
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
      if (duringUpdate) await duringUpdate(updates, this);
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
      const result = await refreshSideStack();
      return result === undefined ? true : result;
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

test("initializer refreshes Source and Destination target labels before grid rows are formatted", async () => {
  const rows = twoRoutingRows().map((row) => ({
    ...row,
    source_interface: "eth2",
    source_networks: [],
    destination_interface: "eth3",
    destination_networks: [],
  }));
  let state;
  let formattedDuringUpdate;
  state = routingInitializerContext({
    rows,
    projection: () => projectionDocument(
      rows.map((row) => ({ ...row, effective_action: "explicit allow", apply_state: "applied" })),
      [],
      [
        { name: "eth2", label: "Refreshed source access" },
        { name: "eth3", label: "Refreshed destination access" },
      ],
    ),
    duringUpdate: (_updates, table) => {
      const row = table.rows.get("9");
      const format = (field) => {
        const column = state.gridOptions.columns.find((candidate) => candidate.field === field);
        return column.formatter({
          getValue: () => row[field],
          getRow: () => ({ getData: () => row }),
        });
      };
      formattedDuringUpdate = {
        source: format("source_networks"),
        destination: format("destination_networks"),
      };
    },
    postWanAction: async () => {},
  });

  const edit = state.edit(9);
  edit.row.enabled = false;
  await edit.submit();

  assert.deepEqual(formattedDuringUpdate, {
    source: "Refreshed source access",
    destination: "Refreshed destination access",
  });
  assert.deepEqual(JSON.parse(state.tableElement.dataset.targetOptions), [
    { name: "eth2", label: "Refreshed source access" },
    { name: "eth3", label: "Refreshed destination access" },
  ]);
});

test("a failed grid projection restores the previous target labels", async () => {
  const rows = twoRoutingRows().map((row) => ({ ...row, source_interface: "eth2", source_networks: [] }));
  const state = routingInitializerContext({
    rows,
    projection: () => projectionDocument(
      rows.map((row) => ({ ...row, effective_action: "explicit allow", apply_state: "applied" })),
      [],
      [{ name: "eth2", label: "Unapplied refreshed target" }],
    ),
    duringUpdate: () => { throw new Error("grid update failed"); },
    postWanAction: async () => {},
  });
  const edit = state.edit(9);
  edit.row.enabled = false;
  await edit.submit();

  const sourceColumn = state.gridOptions.columns.find((column) => column.field === "source_networks");
  const row = state.table.rows.get("9");
  assert.equal(sourceColumn.formatter({
    getValue: () => row.source_networks,
    getRow: () => ({ getData: () => row }),
  }), "eth2");
  assert.deepEqual(JSON.parse(state.tableElement.dataset.targetOptions), [{ name: "eth1", label: "Access 1" }]);
  assert.equal(row.effective_action, "explicit allow");
});

test("an applied projection updates the confirmed value used by a later failed save", async () => {
  const rows = twoRoutingRows();
  let projectionRequests = 0;
  let saveRequests = 0;
  const state = routingInitializerContext({
    rows,
    ErrorConstructor: Error,
    projection: () => {
      projectionRequests += 1;
      if (projectionRequests > 1) throw new Error("recovery projection unavailable");
      return projectionDocument(
        [
          { ...rows[0], enabled: false, effective_action: "suspended", apply_state: "pending" },
          { ...rows[1], enabled: false, effective_action: "suspended", apply_state: "pending" },
        ],
        [],
      );
    },
    postWanAction: async () => {
      saveRequests += 1;
      if (saveRequests === 2) throw new Error("save rejected");
    },
  });

  const triggerProjection = state.edit(10);
  triggerProjection.row.enabled = false;
  await triggerProjection.submit();
  assert.equal(state.table.rows.get("9").enabled, false);

  const failedExternalValueEdit = state.edit(9);
  failedExternalValueEdit.row.enabled = true;
  await failedExternalValueEdit.submit();

  assert.equal(state.table.rows.get("9").enabled, false);
  assert.match(state.messages.at(-1).message, /save rejected/);
});

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

test("a stalled obsolete projection does not block a newer Routing POST or replace its projection", async () => {
  const requests = [];
  const serverRows = twoRoutingRows().map((row) => ({ ...row, source_interface: "eth2", source_networks: [] }));
  const oldProjection = deferred();
  const generatedRow = { id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "automatic allow", apply_state: "applied" };
  let projectionRequests = 0;
  const state = routingInitializerContext({
    rows: serverRows,
    generatedRows: [generatedRow],
    projection: () => {
      projectionRequests += 1;
      if (projectionRequests === 1) return oldProjection.promise;
      if (projectionRequests > 2) throw new Error("recovery projection unavailable");
      return projectionDocument(
        serverRows.map((row) => ({
          ...row,
          effective_action: row.enabled ? "explicit allow" : "suspended",
          apply_state: row.enabled ? "applied" : "pending",
        })),
        [{ ...generatedRow }],
        [{ name: "eth2", label: "Latest access target" }],
      );
    },
    postWanAction: (_url, data) => {
      const request = { data: { ...data }, deferred: deferred() };
      requests.push(request);
      return request.deferred.promise.then(() => {
        serverRows.find((row) => String(row.id) === String(data.id)).enabled = data.enabled;
      });
    },
  });
  const oldEdit = state.edit(9);
  oldEdit.row.enabled = false;
  const oldSave = oldEdit.submit();

  await waitForCondition(() => requests.length === 1, "first Routing POST did not start");
  requests[0].deferred.resolve();
  await waitForCondition(() => projectionRequests === 1, "first projection GET did not start");

  const latestEdit = state.edit(9);
  latestEdit.row.enabled = true;
  const latestSave = latestEdit.submit();
  await waitForCondition(() => requests.length === 2, "newer Routing POST was blocked by the stalled projection GET");
  assert.equal(requests[1].data.enabled, true);
  requests[1].deferred.resolve();
  await latestSave;

  oldProjection.resolve(projectionDocument(
    serverRows.map((row) => ({ ...row, enabled: false, effective_action: "suspended", apply_state: "pending" })),
    [{ id: "generated:access-a-to-b-ipv4", generated: true, effective_action: "automatic deny", apply_state: "pending" }],
    [{ name: "eth2", label: "Obsolete access target" }],
  ));
  await oldSave;

  assert.equal(serverRows[0].enabled, true);
  assert.equal(state.table.rows.get("9").enabled, true);
  assert.equal(state.table.rows.get("9").effective_action, "explicit allow");
  assert.equal(state.table.rows.get("9").apply_state, "applied");
  assert.equal(state.table.rows.get("generated:access-a-to-b-ipv4").effective_action, "automatic allow");
  assert.deepEqual(JSON.parse(state.tableElement.dataset.rules).find((row) => row.id === 9).enabled, true);
  assert.equal(JSON.parse(state.tableElement.dataset.generatedRules)[0].effective_action, "automatic allow");
  assert.deepEqual(JSON.parse(state.tableElement.dataset.targetOptions), [{ name: "eth2", label: "Latest access target" }]);
  const sourceColumn = state.gridOptions.columns.find((column) => column.field === "source_networks");
  const row = state.table.rows.get("9");
  assert.match(sourceColumn.formatter({
    getValue: () => row.source_networks,
    getRow: () => ({ getData: () => row }),
  }), /Latest access target/);

  const failedEdit = state.edit(9);
  failedEdit.row.enabled = false;
  const failedSave = failedEdit.submit();
  await waitForCondition(() => requests.length === 3, "rollback-check Routing POST did not start");
  requests[2].deferred.reject(new Error("save rejected"));
  await failedSave;
  assert.equal(state.table.rows.get("9").enabled, true);
});

test("a stalled obsolete side-panel refresh does not block a newer Routing POST or final rail refresh", async () => {
  const requests = [];
  const serverRows = twoRoutingRows();
  const railRequests = [];
  let railSnapshot = null;
  const state = routingInitializerContext({
    rows: serverRows,
    refreshSideStack: () => {
      const refresh = deferred();
      railRequests.push(refresh);
      return refresh.promise.then(() => {
        railSnapshot = serverRows.map((row) => `${row.id}:${row.enabled ? "enabled" : "disabled"}`);
      });
    },
    postWanAction: (_url, data) => {
      const request = { data: { ...data }, deferred: deferred() };
      requests.push(request);
      return request.deferred.promise.then(() => {
        serverRows.find((row) => String(row.id) === String(data.id)).enabled = data.enabled;
      });
    },
  });
  const oldEdit = state.edit(9);
  oldEdit.row.enabled = false;
  const oldSave = oldEdit.submit();
  await waitForCondition(() => requests.length === 1, "first Routing POST did not start");
  requests[0].deferred.resolve();
  await waitForCondition(() => railRequests.length === 1, "first side-panel refresh did not start");

  const latestEdit = state.edit(9);
  latestEdit.row.enabled = true;
  const latestSave = latestEdit.submit();
  await waitForCondition(() => requests.length === 2, "newer Routing POST was blocked by the stalled side-panel refresh");
  assert.equal(requests[1].data.enabled, true);
  requests[1].deferred.resolve();
  await waitForCondition(() => railRequests.length === 2, "newer side-panel refresh did not start");
  railRequests[1].resolve(true);
  await latestSave;
  assert.deepEqual(railSnapshot, ["9:enabled", "10:enabled"]);

  railRequests[0].resolve(true);
  await oldSave;
  assert.equal(serverRows[0].enabled, true);
  assert.equal(state.table.rows.get("9").enabled, true);
  assert.equal(state.table.rows.get("9").effective_action, "explicit allow");
  assert.equal(state.sideStackRefreshes(), 2);
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

test("a failed save keeps its error and reload guidance when the recovery rail reports false", async () => {
  const request = deferred();
  const state = routingInitializerContext({
    rows: twoRoutingRows(),
    ErrorConstructor: Error,
    postWanAction: () => request.promise,
    refreshSideStack: async () => false,
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
  assert.ok(routing.includes("previousTargetValues = targetValues"));
  assert.ok(routing.includes("targetValues = Object.fromEntries(targetOptions.map"));
  assert.ok(routing.includes("refreshRoutesWanRoutingProjection("));
  assert.ok(routing.includes("table = window.AtlasoUiPatterns.createGrid"));
  const initializer = functionSource("initializeRoutesWanNatTable");
  assert.ok(initializer.includes('saveWanEnabledState(cell, csrf, "/traffic-publishing/nat-rules"'));
});
