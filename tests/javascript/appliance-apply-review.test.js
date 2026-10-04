const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const updateSelection = `function updateApplianceApplySelection${source.split("function updateApplianceApplySelection", 2)[1].split("async function openApplianceApplyReview", 1)[0]}`;
const submitForm = `async function submitApplianceApplyForm${source.split("async function submitApplianceApplyForm", 2)[1].split("async function pollGlobalApplianceApply", 1)[0]}`;

function createNetworkDependencyHarness({ networkChecked = true, dependentChecked = false, dependentValid = true,
  wanChecked = false, forcesNetwork = false } = {}) {
  class HTMLElement {}
  class HTMLDialogElement extends HTMLElement {}
  class HTMLInputElement extends HTMLElement {}
  class HTMLButtonElement extends HTMLElement {}

  const network = new HTMLInputElement();
  network.checked = networkChecked;
  network.disabled = false;
  network.value = "network";
  network.dataset = { valid: "true" };
  const dependent = new HTMLInputElement();
  dependent.checked = dependentChecked;
  dependent.disabled = !dependentValid;
  dependent.value = "public_services";
  dependent.dataset = { valid: String(dependentValid), requiresNetworkSelection: "" };
  const wan = new HTMLInputElement();
  wan.checked = wanChecked;
  wan.disabled = false;
  wan.value = "wan";
  wan.dataset = { valid: "true" };
  const networkRow = new HTMLElement();
  networkRow.dataset = { applyForcesWanSelection: "false" };
  networkRow.querySelectorAll = () => [];
  const wanRow = new HTMLElement();
  wanRow.dataset = { applyForcesNetworkSelection: String(forcesNetwork) };
  wanRow.querySelector = (selector) => selector === "[data-appliance-apply-review-checkbox]" ? wan : null;
  wanRow.querySelectorAll = () => [];
  const dependentRow = new HTMLElement();
  dependentRow.dataset = {};
  dependentRow.querySelectorAll = () => [];
  network.closest = () => networkRow;
  wan.closest = () => wanRow;
  dependent.closest = () => dependentRow;

  const modal = new HTMLDialogElement();
  modal.querySelector = (selector) => ({
    '[data-appliance-apply-review-checkbox][value="network"]': network,
    '[data-apply-unit-id="network"]': networkRow,
    '[data-apply-unit-id="wan"]': wanRow,
  })[selector] || null;
  modal.querySelectorAll = (selector) => {
    if (selector === "[data-requires-dns-selection]") return [];
    if (selector === "[data-requires-network-selection]") return [dependent];
    if (selector === "[data-appliance-apply-review-checkbox]:checked") {
      return [network, wan, dependent].filter((checkbox) => checkbox.checked);
    }
    return [];
  };
  const selectionSummary = new HTMLElement();
  const submit = new HTMLButtonElement();
  const context = vm.createContext({
    HTMLDialogElement, HTMLInputElement, HTMLElement, HTMLButtonElement,
    applianceApplyModalElements: () => ({ modal, selectionSummary, submit, connectionWarning: null }),
  });
  vm.runInContext(updateSelection, context);
  return { context, modal, network, dependent, wan, selectionSummary, submit };
}

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

test("Network locks valid dependent units and restores their prior selection", () => {
  const harness = createNetworkDependencyHarness();
  harness.context.updateApplianceApplySelection();
  assert.equal(harness.dependent.checked, true);
  assert.equal(harness.dependent.disabled, true);

  harness.network.checked = false;
  harness.context.updateApplianceApplySelection();
  assert.equal(harness.dependent.checked, false);
  assert.equal(harness.dependent.disabled, false);

  harness.dependent.checked = true;
  harness.network.checked = true;
  harness.context.updateApplianceApplySelection();
  harness.network.checked = false;
  harness.context.updateApplianceApplySelection();
  assert.equal(harness.dependent.checked, true);
  assert.equal(harness.dependent.disabled, false);
});

test("Network selection blocks submission when a required dependent unit is invalid", () => {
  const harness = createNetworkDependencyHarness({ dependentValid: false });
  harness.context.updateApplianceApplySelection();
  assert.equal(harness.dependent.checked, false);
  assert.equal(harness.dependent.disabled, true);
  assert.equal(harness.submit.disabled, true);
  assert.match(harness.selectionSummary.textContent, /dependent component validation/);
});

test("WAN-forced Network selection also locks and then restores its dependencies", () => {
  const harness = createNetworkDependencyHarness({ networkChecked: false, wanChecked: true, forcesNetwork: true });
  harness.context.updateApplianceApplySelection();
  assert.equal(harness.network.checked, true);
  assert.equal(harness.network.disabled, true);
  assert.equal(harness.dependent.checked, true);
  assert.equal(harness.dependent.disabled, true);

  harness.wan.checked = false;
  harness.context.updateApplianceApplySelection();
  assert.equal(harness.network.checked, false);
  assert.equal(harness.network.disabled, false);
  assert.equal(harness.dependent.checked, false);
  assert.equal(harness.dependent.disabled, false);
});

test("checked disabled review units are serialized in the submit FormData", async () => {
  class HTMLElement {}
  class HTMLDialogElement extends HTMLElement {}
  class HTMLInputElement extends HTMLElement {}
  class HTMLButtonElement extends HTMLElement {}
  class HTMLFormElement extends HTMLElement {
    querySelector() { return null; }
  }
  class FormData {
    constructor(form) {
      this.values = form.controls
        .filter((control) => control.name && !control.disabled && (control.type !== "checkbox" || control.checked))
        .map((control) => [control.name, control.value]);
    }

    append(name, value) {
      this.values.push([name, value]);
    }
  }

  const network = new HTMLInputElement();
  Object.assign(network, { name: "selected_units", value: "network", type: "checkbox", checked: true, disabled: true });
  const dependent = new HTMLInputElement();
  Object.assign(dependent, { name: "selected_units", value: "public_services", type: "checkbox", checked: true, disabled: true });
  const modal = new HTMLDialogElement();
  modal.dataset = {};
  modal.querySelectorAll = (selector) => selector === "[data-appliance-apply-review-checkbox]:checked:disabled"
    ? [network, dependent] : [];
  const submit = new HTMLButtonElement();
  const form = new HTMLFormElement();
  form.controls = [network, dependent];
  let submittedBody;
  const context = vm.createContext({
    HTMLDialogElement, HTMLInputElement, HTMLElement, HTMLButtonElement, HTMLFormElement, FormData,
    applianceApplyModalElements: () => ({ modal, submit }),
    managementUiPath: (path) => path,
    fetch: async (_url, options) => {
      submittedBody = options.body;
      return { ok: true, json: async () => ({ job_id: "job" }) };
    },
    applianceApplyPollController: { trackJob() {} },
    refreshApplianceApplySidebar: async () => {},
    setApplianceApplyModalError() {},
  });
  vm.runInContext(`${submitForm}; globalThis.submitReview = submitApplianceApplyForm;`, context);

  await context.submitReview(form);
  assert.deepEqual(submittedBody.values, [
    ["selected_units", "network"],
    ["selected_units", "public_services"],
  ]);
});
