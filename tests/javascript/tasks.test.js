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
  `${functionSource("expandedTaskRowIds")}\n${functionSource("restoreExpandedTaskRows")}\n` +
  "globalThis.expandedTaskRowIds = expandedTaskRowIds; globalThis.restoreExpandedTaskRows = restoreExpandedTaskRows;",
  context,
);

test("expandedTaskRowIds retains only expanded task parents", () => {
  const rows = [
    { getTreeChildren: () => [{}], isTreeExpanded: () => true, getData: () => ({ id: "job-expanded" }) },
    { getTreeChildren: () => [{}], isTreeExpanded: () => false, getData: () => ({ id: "job-collapsed" }) },
    { getTreeChildren: () => [], isTreeExpanded: () => true, getData: () => ({ id: "job-leaf" }) },
  ];
  assert.deepEqual(Array.from(context.expandedTaskRowIds({ getRows: () => rows })), ["job-expanded"]);
});

test("restoreExpandedTaskRows reopens surviving parents after refresh", () => {
  const expanded = [];
  const rows = new Map([
    ["job-expanded", { treeExpand: () => expanded.push("job-expanded") }],
  ]);
  context.restoreExpandedTaskRows({ getRow: (id) => rows.get(id) }, ["job-expanded", "job-removed"]);
  assert.deepEqual(expanded, ["job-expanded"]);
});

test("task refresh continues while any VCFDT operation is active", () => {
  assert.match(
    appSource,
    /payload\.active_downloads\.some\(\(task\) => taskStatusActive\(task\.status\)\)/,
  );
  assert.match(appSource, /taskStatusActive\(payload\.active_exclusive_operation\?\.status\)/);
});
