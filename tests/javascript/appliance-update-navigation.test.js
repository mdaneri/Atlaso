const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const navigation = source.slice(source.indexOf("function enterApplianceUpdateStatus("), source.indexOf("async function refreshTasksPage("));
const request = source.slice(source.indexOf("async function requestTasksTableData("), source.indexOf("async function openTaskLog("));

function harness(response) {
  const destinations = [];
  const tasks = [{ id: "job_0123456789ab", status: "running" }];
  const context = vm.createContext({
    URLSearchParams,
    atlasoTasks: tasks,
    atlasoSelectedTaskId: tasks[0].id,
    document: { querySelector: () => ({ dataset: { taskType: "appliance-update" } }) },
    fetch: async () => response,
    managementUiPath: (path) => `/ui/management${path}`,
    window: { location: { replace: (path) => destinations.push(path) } },
  });
  vm.runInContext(`${navigation}\n${request}`, context);
  return { context, destinations, tasks };
}

test("maintenance polling navigates without parsing HTML or losing task rows", async () => {
  const { context, destinations, tasks } = harness({
    status: 503,
    headers: { get: (name) => name === "X-Atlaso-Update-Mode" ? "active" : null },
    json: () => { throw new Error("HTML must not be parsed as JSON"); },
  });
  const result = await context.requestTasksTableData("", {}, { page: 2 });
  assert.deepEqual(destinations, ["/ui/management/appliance-update"]);
  assert.equal(result.data, tasks);
  assert.equal(result.last_page, 2);
});

test("ordinary failures do not trigger a maintenance redirect", async () => {
  const { context, destinations } = harness({
    status: 503,
    ok: false,
    headers: { get: () => null },
    json: async () => ({ detail: "Temporary backend failure" }),
  });
  await assert.rejects(context.requestTasksTableData("", {}, {}), /Temporary backend failure/);
  assert.deepEqual(destinations, []);
});

test("ordinary task responses retain their data and do not navigate", async () => {
  const payload = { data: [{ id: "existing" }], last_page: 1 };
  const { context, destinations } = harness({ status: 200, ok: true, json: async () => payload });
  assert.equal(await context.requestTasksTableData("", {}, {}), payload);
  assert.deepEqual(destinations, []);
});
