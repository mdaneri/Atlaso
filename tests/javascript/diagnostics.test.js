const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

test("expired retained bundles allow detail and context-menu deletion", async () => {
  const elements = new Map();
  const element = () => ({
    dataset: { root: "/diagnostics" },
    classList: { toggle() {} },
    addEventListener() {}, querySelectorAll: () => [],
    replaceChildren() {}, append() {}, showModal() {},
  });
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  let config;
  let selected;
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../../atlaso/app/static/diagnostics.js"), "utf8"), {
    document: { getElementById: get, createElement: element, addEventListener() {} },
    window: {
      AtlasoUiPatterns: {
        createWizard: () => ({}),
        createGrid: (options) => { config = options; return { table: {} }; },
      },
      addEventListener() {}, setInterval() {},
    },
    Intl,
    fetch: async () => ({ ok: true, json: async () => selected }),
  });
  const deletion = config.options.rowContextMenu.find((item) => item.label === "Delete bundle");
  for (const status of ["expired", "ready", "failed", "pending", "running", "deleted"]) {
    selected = { id: "bundle", task_id: "bundle", status };
    await config.onOpenRow(selected);
    const blocked = ["pending", "running", "deleted"].includes(status);
    assert.equal(get("diagnostics-remove").hidden, blocked, status);
    assert.equal(deletion.disabled({ getData: () => selected }), blocked, status);
    if (status === "expired") assert.equal(get("diagnostics-download").hidden, true);
  }
  assert.equal(deletion.disabled({ getData: () => ({ is_new: true }) }), true);
});
