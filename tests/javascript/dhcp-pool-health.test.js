const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

for (const [canVerify, canSchedule, expectedActions] of [["false", "false", 1], ["true", "false", 2], ["true", "true", 3]]) {
test(`pool evidence refreshes and gates actions (verify=${canVerify}, schedule=${canSchedule})`, async () => {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, {dataset: {}, hidden: false, textContent: ""});
    return elements.get(id);
  };
  const report = {scope_id: 7, name: "Site", interface_name: "eth1.50", job_id: "job_test",
    progress_percent: 0, reason: "Queued", observations: []};
  const panel = get("dhcp-pool-health");
  panel.dataset = {reports: JSON.stringify([report]), selectedPool: "7", canVerify, canSchedule};
  const configs = [];
  const grids = [];
  const visibility = {};
  let timer;
  let requests = 0;
  let next = {...report, progress_percent: 100, reason: "Complete",
    observations: [{ip_address: "192.0.2.100", status: "unexpected_occupancy", unresolved: true}]};
  const document = {hidden: false, documentElement: {dataset: {managementUiRoot: "/ui/management"}},
    getElementById: get, createElement: () => ({textContent: ""}),
    querySelector: () => ({click() {}}), addEventListener: (event, callback) => {visibility[event] = callback;}};
  vm.runInNewContext(fs.readFileSync("atlaso/app/static/dhcp-pool-health.js", "utf8"), {
    document, FormData, MutationObserver: class {observe() {}},
    window: {setInterval(callback) {timer = callback;}, AtlasoUiPatterns: {
      createGrid(config) {
        configs.push(config);
        const grid = {data: config.options.data, events: {}, on(event, callback) {this.events[event] = callback;},
          redraw() {}, replaceData(rows) {this.data = rows; return Promise.resolve();}};
        grids.push(grid);
        return {table: grid};
      },
    }},
    fetch: async (url) => {requests += 1; assert.equal(url, "/ui/management/dhcp/verification");
      return {ok: true, json: async () => [next]};},
  });
  visibility.DOMContentLoaded();
  grids[0].events.tableBuilt();
  configs[1].onReady();
  await new Promise(setImmediate);
  assert.equal(grids[0].data[0].status, "unexpected_occupancy");
  assert.match(get("dhcp-pool-status").textContent, /Complete/);
  assert.equal(get("dhcp-pool-task-link").href, "/ui/management/tasks?job_id=job_test");
  assert.equal(configs[1].rowActions.length, expectedActions);
  assert.equal(configs[1].rowActions.some(action => action.label === "Schedule verification"), canSchedule === "true");
  document.hidden = true;
  const previousRequests = requests;
  await timer();
  assert.equal(requests, previousRequests);
  document.hidden = false;
  next = {...next, observations: [{ip_address: "192.0.2.100", status: "legitimate_use", unresolved: false}]};
  await visibility.visibilitychange();
  assert.equal(grids[0].data[0].status, "legitimate_use");
  assert.equal(grids[0].data[0].unresolved, false);
});

}
