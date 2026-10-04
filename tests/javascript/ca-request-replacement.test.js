const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../../atlaso/app/static/app.js"), "utf8");
const replacement = source.slice(source.indexOf("function submitCaRequestReplacement("), source.indexOf("function initializeCaRequestsTable("));
const grid = source.slice(source.indexOf("function initializeCaRequestsTable("), source.indexOf("function depotEntryLinkFormatter("));

for (const confirmed of [false, true]) {
  test(`managed replacement confirmation ${confirmed ? "submits" : "returns focus"}`, async () => {
    const forms = [];
    const confirmations = [];
    let focus = 0;
    const document = {
      body: { append: (form) => forms.push(form) },
      createElement: (tag) => ({ tag, children: [], append(child) { this.children.push(child); }, submit() { this.submitted = true; } }),
    };
    const context = vm.createContext({ document, encodeURIComponent, requestConfirmation: (options) => {
      confirmations.push(options);
      return Promise.resolve(confirmed);
    } });
    vm.runInContext(replacement, context);
    const element = { dataset: { replaceUrlTemplate: "/ui/public/ca/requests/certificates/__id__/replace", csrf: "synthetic-csrf" } };
    const row = { getElement: () => ({ focus: () => { focus += 1; } }) };
    context.submitCaRequestReplacement(element, { id: "7/8", common_name: "<service>", can_replace: true }, row);
    await Promise.resolve();
    assert.equal(confirmations.length, 1);
    assert.match(confirmations[0].message, /retain the revoked serial/);
    assert.match(confirmations[0].message, /global CA apply/);
    assert.equal(confirmations[0].label, "Replace certificate");
    assert.equal(focus, confirmed ? 0 : 1);
    assert.equal(forms.length, confirmed ? 1 : 0);
    if (confirmed) {
      assert.equal(forms[0].method, "post");
      assert.equal(forms[0].action, "/ui/public/ca/requests/certificates/7%2F8/replace");
      assert.equal(forms[0].children[0].name, "csrf");
      assert.equal(forms[0].children[0].value, "synthetic-csrf");
      assert.equal(forms[0].submitted, true);
    }
    context.submitCaRequestReplacement(element, { id: 7, can_replace: false }, row);
    await Promise.resolve();
    assert.equal(confirmations.length, 1);
  });
}

test("replacement uses permission-state row actions in the established read-only grid", () => {
  class HTMLElement {}
  const element = new HTMLElement();
  element.dataset = { fallbackId: "fallback", rows: "[]" };
  let config;
  const context = vm.createContext({ HTMLElement, document: { getElementById: () => element }, window: {
    AtlasoUiPatterns: { createGrid: (value) => { config = value; } },
  }, escapeHtml: (value) => value, caRequestStatusFormatter: () => "", submitCaRequestRevocation: () => {}, submitCaRequestReplacement: () => {} });
  vm.runInContext(grid, context);
  context.initializeCaRequestsTable();
  assert.equal(config.pattern, "read-only");
  assert.equal(config.fallback, "#fallback");
  const action = config.rowActions.find((item) => item.label === "Replace revoked managed certificate");
  assert.equal(action.disabled({ getData: () => ({ can_replace: false }) }), true);
  assert.equal(action.disabled({ getData: () => ({ can_replace: true }) }), false);
});
