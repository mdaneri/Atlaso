const assert = require("node:assert/strict");
const test = require("node:test");

const { createController } = require("../../atlaso/app/static/appliance-apply-polling.js");

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
