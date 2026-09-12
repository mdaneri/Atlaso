const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const definition = source.split("\n").find((line) => line.includes('title: "Review", field: "restore_review_required"'));
assert.ok(definition);
const column = vm.runInNewContext(`(${definition.trim().replace(/,$/, "")})`);

test("restored listener review remains visible independently of enabled state", () => {
  for (const enabled of [false, true]) {
    const cell = { getValue: () => true, getRow: () => ({ getData: () => ({ enabled }) }) };
    assert.equal(column.formatter(cell), "Review restored listener");
  }
});

test("ordinary rows and the add placeholder do not claim restored-listener review", () => {
  for (const [is_new, review] of [[false, false], [true, true]]) {
    const cell = { getValue: () => review, getRow: () => ({ getData: () => ({ is_new }) }) };
    assert.equal(column.formatter(cell), "");
  }
});
