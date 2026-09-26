const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const updateSelection = `function updateApplianceApplySelection${source.split("function updateApplianceApplySelection", 2)[1].split("async function openApplianceApplyReview", 1)[0]}`;

test("combined Network and WAN selection surfaces candidate errors and blocks submit", () => {
  class HTMLElement {}
  class HTMLDialogElement extends HTMLElement {}
  class HTMLInputElement extends HTMLElement {}
  class HTMLButtonElement extends HTMLElement {}

  const network = new HTMLInputElement();
  network.checked = true;
  network.value = "network";
  network.dataset = { valid: "true" };
  const wan = new HTMLInputElement();
  wan.checked = true;
  wan.value = "wan";
  wan.disabled = false;
  wan.dataset = { valid: "true" };
  const alert = new HTMLElement();
  alert.hidden = true;
  alert.classList = { toggle: (_name, value) => { alert.hidden = value; } };
  const validity = new HTMLElement();
  validity.classList = { toggle: () => {} };
  const wanRow = new HTMLElement();
  wanRow.dataset = { applyCandidateValid: "false" };
  const networkRow = new HTMLElement();
  networkRow.dataset = {};
  wanRow.querySelector = (selector) => ({
    "[data-appliance-apply-review-checkbox]": wan,
    "[data-apply-candidate-errors]": alert,
    "[data-apply-validity]": validity,
  })[selector] || null;
  wanRow.querySelectorAll = () => [];
  wan.closest = () => wanRow;
  network.closest = () => null;
  const modal = new HTMLDialogElement();
  modal.querySelector = (selector) => ({
    '[data-appliance-apply-review-checkbox][value="network"]': network,
    '[data-apply-unit-id="network"]': networkRow,
    '[data-apply-unit-id="wan"]': wanRow,
  })[selector] || null;
  modal.querySelectorAll = (selector) => selector === "[data-appliance-apply-review-checkbox]:checked"
    ? [network, wan].filter((checkbox) => checkbox.checked) : [];
  const selectionSummary = new HTMLElement();
  const submit = new HTMLButtonElement();
  const context = vm.createContext({
    HTMLDialogElement, HTMLInputElement, HTMLElement, HTMLButtonElement,
    applianceApplyModalElements: () => ({ modal, selectionSummary, submit, connectionWarning: null }),
  });
  vm.runInContext(updateSelection, context);

  context.updateApplianceApplySelection();
  assert.equal(alert.hidden, false);
  assert.equal(validity.textContent, "needs attention");
  assert.match(selectionSummary.textContent, /review Routing & WAN validation/);
  assert.equal(submit.disabled, true);

  network.checked = false;
  context.updateApplianceApplySelection();
  assert.equal(alert.hidden, true);
  assert.equal(validity.textContent, "valid");
  assert.equal(submit.disabled, false);

  wanRow.dataset.applyForcesNetworkSelection = "true";
  context.updateApplianceApplySelection();
  assert.equal(network.checked, true);
  assert.equal(network.disabled, true);
  assert.equal(alert.hidden, false);
  assert.match(selectionSummary.textContent, /review Routing & WAN validation/);
  assert.equal(submit.disabled, true);

  wan.checked = false;
  context.updateApplianceApplySelection();
  assert.equal(network.checked, false);
  assert.equal(network.disabled, false);
  assert.equal(alert.hidden, true);

  networkRow.dataset.applyForcesWanSelection = "true";
  network.checked = true;
  context.updateApplianceApplySelection();
  assert.equal(wan.checked, true);
  assert.equal(wan.disabled, true);
  assert.equal(alert.hidden, false);
  assert.match(selectionSummary.textContent, /review Routing & WAN validation/);
  assert.equal(submit.disabled, true);
  context.updateApplianceApplySelection();
  assert.equal(network.disabled, false);

  network.checked = false;
  context.updateApplianceApplySelection();
  assert.equal(wan.checked, false);
  assert.equal(wan.disabled, false);
  assert.equal(alert.hidden, true);
});
