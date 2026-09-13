const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../../atlaso/app/static/app.js"), "utf8");
const action = source.slice(source.indexOf("async function cancelTask("), source.indexOf("function initializeTasksPage("));

for (const allowed of [true, false]) {
  test(`task cancellation uses backend capability ${allowed} and preserves the returned lifecycle`, async () => {
    class Element { constructor() { this.dataset = { csrf: "synthetic" }; } }
    const current = { id: "task", can_cancel: allowed, cancel_confirmation: "Finish the bounded check and cleanup first." };
    const returned = { id: "task", status: "running", cancel_requested_at: "now", can_cancel: false };
    const confirmations = [];
    const requests = [];
    const renders = [];
    const context = vm.createContext({
      HTMLElement: Element, document: { querySelector: () => new Element() }, URLSearchParams,
      atlasoTaskDetail: null, taskById: () => current, managementUiPath: (value) => value,
      requestConfirmation: async (value) => { confirmations.push(value); return true; },
      fetch: async (url, options) => { requests.push({ url, options }); return { ok: true, json: async () => ({ task: returned }) }; },
      refreshTasksPage: async () => {}, renderTaskDetail: (task) => renders.push(task),
    });
    vm.runInContext(action, context);
    await context.cancelTask("task");
    assert.equal(requests.length, allowed ? 1 : 0);
    assert.equal(confirmations.length, allowed ? 1 : 0);
    if (allowed) {
      assert.equal(confirmations[0].message, current.cancel_confirmation);
      assert.equal(renders[0].status, "running");
      assert.equal(renders[0].cancel_requested_at, "now");
    }
  });
}


const diagnosticsSource = fs.readFileSync(path.join(__dirname, "../../atlaso/app/static/diagnostics.js"), "utf8");
const diagnosticsCancel = diagnosticsSource.slice(diagnosticsSource.indexOf("async function cancel(data)"), diagnosticsSource.indexOf("async function remove(data)"));
for (const [outcome, expected] of [
  ["cancelled", /cancelled before execution/],
  ["succeeded", /completed before cancellation/],
  ["ready", /completed before cancellation/],
  ["ready_with_omissions", /completed with omissions/],
  ["failed", /failed before cancellation/],
  ["expired", /has expired/],
  ["deleted", /already deleted/],
  ["running", /not confirmed/],
  [undefined, /not confirmed/],
]) {
  test(`diagnostics cancellation reports returned disposition ${outcome}`, async () => {
    const status = {};
    let refreshes = 0;
    const context = vm.createContext({ status, root: "/diagnostics", FormData: class { set() {} },
      form: { elements: { csrf: { value: "synthetic" } } },
      request: async () => ({ status: outcome }), refresh: async () => { refreshes += 1; } });
    vm.runInContext(diagnosticsCancel, context);
    await context.cancel({ id: "bundle", status: "pending" });
    assert.match(status.textContent, expected);
    if (outcome !== "cancelled") assert.doesNotMatch(status.textContent, /cancelled before execution/);
    assert.equal(refreshes, 1);
  });
}


test("off-page task detail cancellation uses the rendered capability and refreshes it", async () => {
  class Element { constructor() { this.dataset = { csrf: "synthetic" }; } }
  class Dialog extends Element { querySelector() { return null; } }
  const page = new Element();
  const modal = new Dialog();
  modal.open = true;
  const requests = [];
  const confirmations = [];
  const selected = { id: "off-page", can_cancel: true, cancel_confirmation: "Finish and clean up." };
  const returned = { ...selected, can_cancel: false, cancel_requested_at: "now", status: "running" };
  const context = vm.createContext({
    HTMLElement: Element, HTMLDialogElement: Dialog, HTMLDetailsElement: Element, HTMLButtonElement: Element,
    document: { querySelector: () => page, getElementById: () => modal }, URLSearchParams,
    atlasoTaskDetail: null, atlasoSelectedTaskId: "", taskById: () => null,
    managementUiPath: (value) => value,
    requestConfirmation: async (value) => { confirmations.push(value); return true; },
    fetch: async (url) => { requests.push(url); return { ok: true, json: async () => ({ task: returned }) }; },
    refreshTasksPage: async () => {},
  });
  const render = source.slice(source.indexOf("function renderTaskDetail("), source.indexOf("function openTaskDetail("));
  vm.runInContext(render + action, context);
  context.renderTaskDetail(selected);
  await context.cancelTask("off-page");
  assert.deepEqual(requests, ["/tasks/off-page/cancel"]);
  assert.equal(confirmations[0].message, selected.cancel_confirmation);
  assert.equal(context.atlasoTaskDetail, returned);
  await context.cancelTask("off-page");
  await context.cancelTask("different-task");
  assert.equal(requests.length, 1);
});


for (const open of [false, true]) {
  for (const allowed of [false, true]) {
    test(`fresh grid capability overrides stale detail: open=${open}, allowed=${allowed}`, async () => {
      class Element { constructor() { this.dataset = {}; } }
      const confirmations = [];
      const current = { id: "task", can_cancel: allowed, cancel_confirmation: "Running changes remain; finish cleanup." };
      const context = vm.createContext({
        HTMLElement: Element, document: { querySelector: () => new Element(), getElementById: () => ({ open }) },
        atlasoTaskDetail: { id: "task", can_cancel: true, cancel_confirmation: "Prevent from starting." },
        taskById: () => current,
        requestConfirmation: async (value) => { confirmations.push(value); return false; },
      });
      vm.runInContext(action, context);
      await context.cancelTask("task");
      assert.equal(confirmations.length, allowed ? 1 : 0);
      if (allowed) assert.equal(confirmations[0].message, current.cancel_confirmation);
      context.taskById = () => null;
      context.document.getElementById = () => ({ open: false });
      await context.cancelTask("task");
      assert.equal(confirmations.length, allowed ? 1 : 0);
    });
  }
}
