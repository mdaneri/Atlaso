const assert = require("node:assert/strict");
const test = require("node:test");

const { createController, createMonitor } = require("../../atlaso/app/static/appliance-apply-polling.js");

function harness(request) {
  let hidden = false;
  const timers = [];
  const statuses = [];
  const controller = createController({
    request,
    onStatus: async (payload) => statuses.push(payload),
    isHidden: () => hidden,
    setTimer: (callback, delay) => {
      timers.push({ callback, delay, cleared: false });
      return timers.length;
    },
    clearTimer: (id) => {
      if (timers[id - 1]) timers[id - 1].cleared = true;
    },
  });
  return { controller, timers, statuses, setHidden: (value) => { hidden = value; } };
}

function monitorHarness({ requestStatus, requestTask }) {
  let hidden = false;
  const timers = [];
  const tasks = [];
  const errors = [];
  const terminals = [];
  const ui = { modalStatus: "", locked: false, sidebarBadge: "", pendingCount: -1 };
  const monitor = createMonitor({
    requestStatus,
    requestTask,
    onStatus: async (payload) => {
      ui.pendingCount = payload.pending_count;
      ui.sidebarBadge = payload.pending_count ? "pending" : "current";
    },
    onTask: (task) => {
      tasks.push(task);
      ui.modalStatus = task.status;
      ui.locked = ["pending", "running"].includes(task.status);
    },
    onTerminal: async (task) => terminals.push(task.status),
    onError: (error) => errors.push(error.message),
    isHidden: () => hidden,
    setTimer: (callback, delay) => {
      timers.push({ callback, delay, cleared: false });
      return timers.length;
    },
    clearTimer: (id) => {
      if (timers[id - 1]) timers[id - 1].cleared = true;
    },
  });
  return { monitor, timers, tasks, errors, terminals, ui, setHidden: (value) => { hidden = value; } };
}

test("deduplicates an in-flight status request", async () => {
  let resolveRequest;
  let calls = 0;
  const pending = new Promise((resolve) => { resolveRequest = resolve; });
  const state = harness(() => { calls += 1; return pending; });

  const first = state.controller.refresh();
  const second = state.controller.refresh();
  assert.equal(calls, 1);
  assert.strictEqual(first, second);
  resolveRequest({ active_task: null });
  await first;
});

test("queues a forced refresh behind an in-flight request", async () => {
  let resolveRequest;
  const forced = [];
  const pending = new Promise((resolve) => { resolveRequest = resolve; });
  const state = harness((force) => {
    forced.push(force);
    return forced.length === 1 ? pending : Promise.resolve({ active_task: null });
  });

  const first = state.controller.refresh();
  state.controller.refreshImmediately();
  resolveRequest({ active_task: null });
  await first;
  assert.equal(state.timers.at(-1).delay, 0);
  await state.timers.at(-1).callback();
  assert.deepEqual(forced, [false, true]);
});

test("backs off idle polling and keeps active polling prompt", async () => {
  const state = harness(async () => ({ active_task: null }));
  await state.controller.refresh();
  assert.equal(state.timers.at(-1).delay, 10000);
  await state.timers.at(-1).callback();
  assert.equal(state.timers.at(-1).delay, 20000);

  const active = harness(async () => ({ active_task: { id: "job-1" } }));
  await active.controller.refresh();
  assert.equal(active.timers.at(-1).delay, 2000);
});

test("hidden pages suspend polling and refresh immediately when visible", async () => {
  let calls = 0;
  const state = harness(async () => { calls += 1; return { active_task: null }; });
  state.setHidden(true);
  await state.controller.refresh();
  assert.equal(calls, 0);
  assert.equal(state.timers.length, 0);
  state.setHidden(false);
  await state.controller.visibilityChanged();
  assert.equal(calls, 1);
  assert.equal(state.timers.at(-1).delay, 10000);
});

test("mutation refresh resets idle backoff", async () => {
  let calls = 0;
  const forced = [];
  const state = harness(async (force) => { calls += 1; forced.push(force); return { active_task: null }; });
  await state.controller.refresh();
  await state.timers.at(-1).callback();
  assert.equal(state.timers.at(-1).delay, 20000);
  await state.controller.refreshImmediately();
  assert.equal(calls, 3);
  assert.deepEqual(forced, [false, false, true]);
  assert.equal(state.timers.at(-1).delay, 10000);
});

for (const terminalStatus of ["succeeded", "failed", "cancelled"]) {
  test(`reconciles an active task that becomes ${terminalStatus}`, async () => {
    const statusPayloads = [
      { active_task: { id: "job-1", status: "running" }, pending_count: 0 },
      { active_task: null, pending_count: terminalStatus === "succeeded" ? 0 : 1 },
    ];
    const state = monitorHarness({
      requestStatus: async () => statusPayloads.shift(),
      requestTask: async () => ({ id: "job-1", status: terminalStatus }),
    });

    await state.monitor.refresh();
    assert.equal(state.timers.at(-1).delay, 2000);
    await state.timers.at(-1).callback();

    assert.deepEqual(state.tasks.map((task) => task.status), ["running", terminalStatus]);
    assert.deepEqual(state.terminals, [terminalStatus]);
    assert.equal(state.ui.modalStatus, terminalStatus);
    assert.equal(state.ui.locked, false);
    assert.equal(state.ui.pendingCount, terminalStatus === "succeeded" ? 0 : 1);
    assert.equal(state.ui.sidebarBadge, terminalStatus === "succeeded" ? "current" : "pending");
    assert.equal(state.monitor.trackedJobId(), "");
  });
}

test("retries a transient terminal reconciliation failure at the active interval", async () => {
  let statusCalls = 0;
  const state = monitorHarness({
    requestStatus: async () => {
      statusCalls += 1;
      if (statusCalls === 1) throw new Error("temporary status failure");
      return { active_task: null, pending_count: 0 };
    },
    requestTask: async () => ({ id: "job-1", status: "succeeded" }),
  });
  state.monitor.trackJob("job-1");

  await state.monitor.refresh();
  assert.deepEqual(state.errors, ["temporary status failure"]);
  assert.equal(state.timers.at(-1).delay, 2000);
  await state.timers.at(-1).callback();

  assert.equal(statusCalls, 2);
  assert.equal(state.ui.modalStatus, "succeeded");
  assert.equal(state.ui.locked, false);
  assert.equal(state.monitor.trackedJobId(), "");
});

test("keeps tracking when the terminal task-status request fails", async () => {
  let taskCalls = 0;
  const state = monitorHarness({
    requestStatus: async () => ({ active_task: null, pending_count: 0 }),
    requestTask: async () => {
      taskCalls += 1;
      if (taskCalls === 1) throw new Error("temporary task failure");
      return { id: "job-1", status: "failed" };
    },
  });
  state.monitor.trackJob("job-1");

  await state.monitor.refresh();
  assert.equal(state.monitor.trackedJobId(), "job-1");
  assert.equal(state.timers.at(-1).delay, 2000);
  await state.timers.at(-1).callback();

  assert.equal(taskCalls, 2);
  assert.equal(state.ui.modalStatus, "failed");
  assert.equal(state.monitor.trackedJobId(), "");
});

test("does not let an older running response replace a terminal task", async () => {
  let resolveStatus;
  const pendingStatus = new Promise((resolve) => { resolveStatus = resolve; });
  const state = monitorHarness({
    requestStatus: () => pendingStatus,
    requestTask: async () => ({ id: "job-1", status: "succeeded" }),
  });

  const oldPoll = state.monitor.refresh();
  assert.equal(state.monitor.observeTask({ id: "job-1", status: "succeeded" }), true);
  resolveStatus({ active_task: { id: "job-1", status: "running" }, pending_count: 0 });
  await oldPoll;

  assert.deepEqual(state.tasks.map((task) => task.status), ["succeeded"]);
  assert.equal(state.ui.modalStatus, "succeeded");
  assert.equal(state.ui.locked, false);
  assert.equal(state.monitor.trackedJobId(), "");
});
