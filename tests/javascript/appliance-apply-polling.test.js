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

function monitorHarness({ requestStatus, requestTask, now = () => Date.now() }) {
  let hidden = false;
  const timers = [];
  const tasks = [];
  const errors = [];
  const errorStates = [];
  const terminals = [];
  const ui = { modalStatus: "", locked: false, sidebarBadge: "", pendingCount: -1, pollNotice: "", pollTone: "" };
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
    onError: (error, state) => {
      errors.push(error.message);
      errorStates.push(state);
      ui.pollNotice = state.expectedReconnect ? "reconnecting" : "unavailable";
      ui.pollTone = state.expectedReconnect ? "neutral" : "warning";
    },
    onRecovered: () => {
      ui.pollNotice = "";
      ui.pollTone = "";
    },
    now,
    isHidden: () => hidden,
    setTimer: (callback, delay) => {
      timers.push({ callback, delay, cleared: false });
      return timers.length;
    },
    clearTimer: (id) => {
      if (timers[id - 1]) timers[id - 1].cleared = true;
    },
  });
  return { monitor, timers, tasks, errors, errorStates, terminals, ui, setHidden: (value) => { hidden = value; } };
}

function plannedRestartTask(status = "running") {
  return {
    id: "job-1",
    status: "running",
    result: {
      management_status_transition: {
        kind: "planned_service_restart",
        restart_delay_seconds: 3,
        grace_seconds: 15,
      },
    },
    _children: [
      { component_key: "appliance_settings", status },
    ],
  };
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

test("uses a neutral bounded reconnect state for a planned management restart", async () => {
  let now = 1000;
  const confirmedTask = plannedRestartTask("succeeded");
  confirmedTask._children[0].finished_at = new Date(now).toISOString().replace("Z", "+00:00");
  const statusPayloads = [
    { active_task: confirmedTask, pending_count: 0 },
    new Error("front door restarting"),
    { active_task: confirmedTask, pending_count: 0 },
    new Error("later unexpected outage"),
  ];
  const state = monitorHarness({
    requestStatus: async () => {
      const payload = statusPayloads.shift();
      if (payload instanceof Error) throw payload;
      return payload;
    },
    requestTask: async () => confirmedTask,
    now: () => now,
  });

  await state.monitor.refresh();
  now = 2000;
  await state.timers.at(-1).callback();

  assert.equal(state.errorStates[0].expectedReconnect, true);
  assert.equal(state.errorStates[0].reconnectGraceMs, 18000);
  assert.equal(state.ui.pollNotice, "reconnecting");
  assert.equal(state.ui.pollTone, "neutral");
  assert.equal(state.ui.modalStatus, "running");
  assert.equal(state.ui.locked, true);
  assert.equal(state.monitor.trackedJobId(), "job-1");

  now = 5000;
  await state.timers.at(-1).callback();
  assert.equal(state.ui.pollNotice, "");
  assert.equal(state.ui.pollTone, "");
  assert.equal(state.ui.modalStatus, "running");
  assert.equal(state.ui.locked, true);

  now = 6000;
  await state.timers.at(-1).callback();
  assert.equal(state.errorStates[1].expectedReconnect, false);
  assert.equal(state.ui.pollNotice, "unavailable");
  assert.equal(state.ui.pollTone, "warning");
});

test("does not spend confirmed restart grace on a failure while settings are running", async () => {
  let now = 1000;
  const runningTask = plannedRestartTask();
  const confirmedTask = plannedRestartTask("succeeded");
  confirmedTask._children[0].finished_at = new Date(3000).toISOString().replace("Z", "+00:00");
  const statusPayloads = [
    { active_task: runningTask, pending_count: 0 },
    new Error("transient failure before restart scheduling"),
    { active_task: confirmedTask, pending_count: 0 },
    new Error("confirmed scheduled restart"),
  ];
  const state = monitorHarness({
    requestStatus: async () => {
      const payload = statusPayloads.shift();
      if (payload instanceof Error) throw payload;
      return payload;
    },
    requestTask: async () => confirmedTask,
    now: () => now,
  });

  await state.monitor.refresh();
  now = 2000;
  await state.timers.at(-1).callback();
  assert.equal(state.errorStates[0].expectedReconnect, false);
  assert.equal(state.ui.pollTone, "warning");

  now = 3000;
  await state.timers.at(-1).callback();
  now = 5000;
  await state.timers.at(-1).callback();
  assert.equal(state.errorStates[1].expectedReconnect, true);
  assert.equal(state.ui.pollTone, "neutral");
});

test("keeps reconnect grace through the delayed restart after settings success", async () => {
  let now = 1000;
  const afterSettingsTask = plannedRestartTask("succeeded");
  afterSettingsTask._children[0].finished_at = new Date(now).toISOString().replace("Z", "+00:00");
  afterSettingsTask._children.push({ component_key: "firewall", status: "running" });
  const statusPayloads = [
    { active_task: plannedRestartTask(), pending_count: 0 },
    { active_task: afterSettingsTask, pending_count: 0 },
    new Error("scheduled restart"),
    { active_task: afterSettingsTask, pending_count: 0 },
    new Error("later unrelated outage"),
  ];
  const state = monitorHarness({
    requestStatus: async () => {
      const payload = statusPayloads.shift();
      if (payload instanceof Error) throw payload;
      return payload;
    },
    requestTask: async () => afterSettingsTask,
    now: () => now,
  });

  await state.monitor.refresh();
  now = 3000;
  await state.timers.at(-1).callback();
  now = 5000;
  await state.timers.at(-1).callback();

  assert.equal(state.errorStates[0].expectedReconnect, true);
  assert.equal(state.errorStates[0].reconnectGraceMs, 18000);
  assert.equal(state.ui.pollTone, "neutral");

  now = 6000;
  await state.timers.at(-1).callback();
  now = 7000;
  await state.timers.at(-1).callback();

  assert.equal(state.errorStates[1].expectedReconnect, false);
  assert.equal(state.errorStates[1].reconnectGraceMs, 0);
  assert.equal(state.ui.pollNotice, "unavailable");
  assert.equal(state.ui.pollTone, "warning");
  assert.equal(state.ui.modalStatus, "running");
  assert.equal(state.ui.locked, true);
});

test("consumes unused grace after a successful poll beyond the scheduled restart", async () => {
  let now = 1000;
  const afterSettingsTask = plannedRestartTask("succeeded");
  afterSettingsTask._children[0].finished_at = new Date(now).toISOString().replace("Z", "+00:00");
  afterSettingsTask._children.push({ component_key: "firewall", status: "running" });
  const statusPayloads = [
    { active_task: plannedRestartTask(), pending_count: 0 },
    { active_task: afterSettingsTask, pending_count: 0 },
    new Error("later unrelated outage"),
  ];
  const state = monitorHarness({
    requestStatus: async () => {
      const payload = statusPayloads.shift();
      if (payload instanceof Error) throw payload;
      return payload;
    },
    requestTask: async () => afterSettingsTask,
    now: () => now,
  });

  await state.monitor.refresh();
  now = 5000;
  await state.timers.at(-1).callback();
  now = 6000;
  await state.timers.at(-1).callback();

  assert.equal(state.errorStates[0].expectedReconnect, false);
  assert.equal(state.errorStates[0].reconnectGraceMs, 0);
  assert.equal(state.ui.pollTone, "warning");
});

test("escalates a planned reconnect after its grace window", async () => {
  let now = 1000;
  const confirmedTask = plannedRestartTask("succeeded");
  confirmedTask._children[0].finished_at = new Date(now).toISOString().replace("Z", "+00:00");
  const state = monitorHarness({
    requestStatus: async () => {
      if (!state.monitor.trackedJobId()) return { active_task: confirmedTask, pending_count: 0 };
      throw new Error("front door still unavailable");
    },
    requestTask: async () => confirmedTask,
    now: () => now,
  });

  await state.monitor.refresh();
  await state.timers.at(-1).callback();
  assert.equal(state.errorStates[0].expectedReconnect, true);
  assert.equal(state.ui.pollTone, "neutral");

  now += 19000;
  await state.timers.at(-1).callback();
  assert.equal(state.errorStates[1].expectedReconnect, false);
  assert.equal(state.errorStates[1].reconnectElapsedMs, 19000);
  assert.equal(state.ui.pollNotice, "unavailable");
  assert.equal(state.ui.pollTone, "warning");
  assert.equal(state.ui.modalStatus, "running");
  assert.equal(state.ui.locked, true);
});

test("keeps unexpected active-task failures on the warning path", async () => {
  const state = monitorHarness({
    requestStatus: async () => {
      if (!state.monitor.trackedJobId()) {
        return {
          active_task: {
            id: "job-1",
            status: "running",
            result: { selected_units: ["firewall"] },
            _children: [{ component_key: "firewall", status: "running" }],
          },
          pending_count: 0,
        };
      }
      throw new Error("unexpected outage");
    },
    requestTask: async () => null,
  });

  await state.monitor.refresh();
  await state.timers.at(-1).callback();

  assert.equal(state.errorStates[0].expectedReconnect, false);
  assert.equal(state.ui.pollNotice, "unavailable");
  assert.equal(state.ui.pollTone, "warning");
  assert.equal(state.ui.modalStatus, "running");
  assert.equal(state.ui.locked, true);
});

test("keeps terminal reconciliation failures on the warning path during a planned restart task", async () => {
  const statusPayloads = [
    { active_task: plannedRestartTask(), pending_count: 0 },
    { active_task: null, pending_count: 0 },
  ];
  const state = monitorHarness({
    requestStatus: async () => statusPayloads.shift(),
    requestTask: async () => { throw new Error("terminal task unavailable"); },
  });

  await state.monitor.refresh();
  await state.timers.at(-1).callback();

  assert.equal(state.errorStates[0].expectedReconnect, false);
  assert.equal(state.errorStates[0].reconnectGraceMs, 0);
  assert.equal(state.ui.pollNotice, "unavailable");
  assert.equal(state.ui.pollTone, "warning");
  assert.equal(state.monitor.trackedJobId(), "job-1");
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
  assert.equal(await state.monitor.observeTask({ id: "job-1", status: "succeeded" }), true);
  resolveStatus({ active_task: { id: "job-1", status: "running" }, pending_count: 0 });
  await oldPoll;

  assert.deepEqual(state.tasks.map((task) => task.status), ["succeeded"]);
  assert.deepEqual(state.terminals, ["succeeded"]);
  assert.equal(state.ui.modalStatus, "succeeded");
  assert.equal(state.ui.locked, false);
  assert.equal(state.monitor.trackedJobId(), "");
});

test("reconciles the tracked task before accepting a different active task", async () => {
  const statusPayloads = [
    { active_task: { id: "job-1", status: "running" }, pending_count: 0 },
    { active_task: { id: "job-2", status: "running" }, pending_count: 0 },
  ];
  const requestedTaskIds = [];
  const state = monitorHarness({
    requestStatus: async () => statusPayloads.shift(),
    requestTask: async (jobId) => {
      requestedTaskIds.push(jobId);
      return { id: jobId, status: "succeeded" };
    },
  });

  await state.monitor.refresh();
  await state.timers.at(-1).callback();

  assert.deepEqual(requestedTaskIds, ["job-1"]);
  assert.deepEqual(state.tasks.map((task) => `${task.id}:${task.status}`), [
    "job-1:running",
    "job-1:succeeded",
    "job-2:running",
  ]);
  assert.deepEqual(state.terminals, ["succeeded"]);
  assert.equal(state.monitor.trackedJobId(), "job-2");
});

test("does not replace a tracked task when its reconciliation fails", async () => {
  const statusPayloads = [
    { active_task: { id: "job-1", status: "running" }, pending_count: 0 },
    { active_task: { id: "job-2", status: "running" }, pending_count: 0 },
  ];
  const state = monitorHarness({
    requestStatus: async () => statusPayloads.shift(),
    requestTask: async () => { throw new Error("temporary task failure"); },
  });

  await state.monitor.refresh();
  await state.timers.at(-1).callback();

  assert.deepEqual(state.tasks.map((task) => `${task.id}:${task.status}`), ["job-1:running"]);
  assert.deepEqual(state.errors, ["temporary task failure"]);
  assert.equal(state.monitor.trackedJobId(), "job-1");
  assert.equal(state.timers.at(-1).delay, 2000);
});

test("runs terminal reconciliation for a directly observed terminal task", async () => {
  const state = monitorHarness({
    requestStatus: async () => ({ active_task: null, pending_count: 0 }),
    requestTask: async () => null,
  });
  state.monitor.trackJob("job-1");

  assert.equal(await state.monitor.observeTask({ id: "job-1", status: "succeeded" }), true);

  assert.deepEqual(state.tasks.map((task) => task.status), ["succeeded"]);
  assert.deepEqual(state.terminals, ["succeeded"]);
  assert.equal(state.monitor.trackedJobId(), "");
});
