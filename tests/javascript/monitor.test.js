const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf("{", start);
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
  `${functionSource("createMonitorLoadCoordinator")}\n` +
    "globalThis.createMonitorLoadCoordinator = createMonitorLoadCoordinator;",
  context,
);

function deferredRequestHarness() {
  const pending = [];
  const requested = [];
  const rendered = [];
  const errors = [];
  let active = 0;
  let maximumActive = 0;
  const coordinator = context.createMonitorLoadCoordinator({
    initialRange: 6,
    request: (range) => {
      requested.push(range);
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      return new Promise((resolve, reject) => {
        pending.push({
          range,
          resolve: (payload) => {
            active -= 1;
            resolve(payload);
          },
          reject: (error) => {
            active -= 1;
            reject(error);
          },
        });
      });
    },
    onData: (payload, { range }) => rendered.push({ payload, range }),
    onError: (error, { range }) => errors.push({ message: error.message, range }),
  });
  return { coordinator, errors, maximumActive: () => maximumActive, pending, rendered, requested };
}

test("queues a range change behind an active load and suppresses the obsolete response", async () => {
  const state = deferredRequestHarness();
  const initial = state.coordinator.refresh();
  state.coordinator.selectRange(12);

  assert.deepEqual(state.requested, [6]);
  state.pending[0].resolve({ marker: "6h" });
  await initial;
  assert.deepEqual(state.requested, [6, 12]);
  assert.deepEqual(state.rendered, []);

  const latest = state.coordinator.refresh();
  state.pending[1].resolve({ marker: "12h" });
  await latest;
  assert.deepEqual(state.rendered, [{ payload: { marker: "12h" }, range: 12 }]);
});

test("rapid range changes coalesce to the latest selection without overlapping requests", async () => {
  const state = deferredRequestHarness();
  const initial = state.coordinator.refresh();
  state.coordinator.selectRange(12);
  state.coordinator.selectRange(24);
  state.coordinator.selectRange(1);

  state.pending[0].resolve({ marker: "6h" });
  await initial;
  assert.deepEqual(state.requested, [6, 1]);
  assert.equal(state.maximumActive(), 1);

  const latest = state.coordinator.refresh();
  state.pending[1].resolve({ marker: "1h" });
  await latest;
  assert.deepEqual(state.rendered, [{ payload: { marker: "1h" }, range: 1 }]);
  assert.equal(state.maximumActive(), 1);
});

test("an obsolete range failure cannot replace status for the newer selection", async () => {
  const state = deferredRequestHarness();
  const initial = state.coordinator.refresh();
  state.coordinator.selectRange(24);
  state.pending[0].reject(new Error("old range failed"));
  await initial;

  assert.deepEqual(state.errors, []);
  const latest = state.coordinator.refresh();
  state.pending[1].resolve({ marker: "24h" });
  await latest;
  assert.deepEqual(state.rendered, [{ payload: { marker: "24h" }, range: 24 }]);
});
