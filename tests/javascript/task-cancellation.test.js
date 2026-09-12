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
      taskById: () => current, managementUiPath: (value) => value,
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
