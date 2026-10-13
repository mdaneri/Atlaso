const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const updateSelection = `function updateApplianceApplySelection${source.split("function updateApplianceApplySelection", 2)[1].split("async function openApplianceApplyReview", 1)[0]}`;
const submitForm = `async function submitApplianceApplyForm${source.split("async function submitApplianceApplyForm", 2)[1].split("async function pollGlobalApplianceApply", 1)[0]}`;
const currentPlanRequest = `function isCurrentApplianceApplyPlanRequest${source.split("function isCurrentApplianceApplyPlanRequest", 2)[1].split("function applianceApplySelectedValues", 1)[0]}`;
const selectedPlanValues = `function applianceApplySelectedValues${source.split("function applianceApplySelectedValues", 2)[1].split("function preserveApplianceApplyReviewState", 1)[0]}`;

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
  modal.dataset = {};
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

function createServerPlanHarness(specs) {
  class HTMLElement {}
  class HTMLDialogElement extends HTMLElement {}
  class HTMLInputElement extends HTMLElement {}
  class HTMLButtonElement extends HTMLElement {}

  const checkboxes = specs.map((spec) => {
    const checkbox = new HTMLInputElement();
    Object.assign(checkbox, {
      checked: spec.selected,
      disabled: spec.required || !spec.valid,
      value: spec.id,
      dataset: {
        changed: String(Boolean(spec.changed)),
        requiredDependency: String(Boolean(spec.required)),
        valid: String(Boolean(spec.valid)),
      },
      closest: () => ({ querySelectorAll: () => [] }),
    });
    return checkbox;
  });
  const modal = new HTMLDialogElement();
  modal.dataset = {
    serverPlanAvailable: "true",
    planLoading: "false",
    planError: "",
    requestedUnits: JSON.stringify(specs.filter((spec) => spec.selected && !spec.required).map((spec) => spec.id)),
  };
  modal.querySelectorAll = (selector) => selector === "[data-appliance-apply-review-checkbox]:checked"
    ? checkboxes.filter((checkbox) => checkbox.checked) : [];
  const selectionSummary = new HTMLElement();
  const submit = new HTMLButtonElement();
  const connectionWarning = new HTMLElement();
  connectionWarning.classList = { toggle() {} };
  connectionWarning.replaceChildren = () => {};
  connectionWarning.append = () => {};
  const context = vm.createContext({
    HTMLDialogElement, HTMLInputElement, HTMLElement, HTMLButtonElement,
    applianceApplyModalElements: () => ({ modal, selectionSummary, submit, connectionWarning }),
  });
  vm.runInContext(updateSelection, context);
  return { context, modal, checkboxes, selectionSummary, submit };
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
  modal.dataset = {};
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

test("server plan counts locked changed WAN separately from five unchanged dependencies", () => {
  const harness = createServerPlanHarness([
    { id: "network", selected: true, changed: true, valid: true },
    { id: "wan", selected: true, changed: true, required: true, valid: true },
    ...["ca", "firewall", "appliance_settings", "public_services", "nat"].map((id) => ({
      id, selected: true, changed: false, required: true, valid: true,
    })),
  ]);
  harness.context.updateApplianceApplySelection();

  assert.match(harness.selectionSummary.textContent, /2 changed components \+ 5 required dependencies = 7 components to process/);
  assert.match(harness.selectionSummary.textContent, /1 explicitly selected/);
  assert.equal(harness.submit.disabled, false);
  assert.equal(harness.checkboxes.filter((checkbox) => checkbox.checked).length, 7);

  harness.checkboxes[1].checked = false;
  harness.modal.dataset.requestedUnits = JSON.stringify(["network"]);
  harness.context.updateApplianceApplySelection();
  assert.match(harness.selectionSummary.textContent, /1 changed component \+ 5 required dependencies = 6 components to process/);
  assert.match(harness.selectionSummary.textContent, /1 explicitly selected/);
});

test("server plan leaves required rows checked when invalid and blocks submission", () => {
  const harness = createServerPlanHarness([
    { id: "network", selected: true, changed: true, valid: true },
    { id: "wan", selected: true, changed: true, valid: true },
    { id: "ca", selected: true, changed: false, required: true, valid: false },
  ]);
  harness.modal.dataset.planError = "Certificate Authority needs attention.";
  harness.context.updateApplianceApplySelection();

  assert.equal(harness.checkboxes[2].checked, true);
  assert.equal(harness.checkboxes[2].disabled, true);
  assert.match(harness.selectionSummary.textContent, /Certificate Authority needs attention/);
  assert.equal(harness.submit.disabled, true);
});

test("plan refresh preserves explicit locked roots while excluding implicit dependencies", () => {
  class HTMLElement {}
  class HTMLInputElement extends HTMLElement {}
  const selected = [
    Object.assign(new HTMLInputElement(), { value: "network", dataset: { requiredDependency: "false" } }),
    Object.assign(new HTMLInputElement(), { value: "ca", dataset: { requiredDependency: "true" } }),
    Object.assign(new HTMLInputElement(), { value: "wan", dataset: { requiredDependency: "true" } }),
  ];
  const modal = { dataset: { requestedUnits: JSON.stringify(["network", "wan"]) }, querySelectorAll: () => selected };
  const context = vm.createContext({ HTMLElement, HTMLInputElement });
  vm.runInContext(`${selectedPlanValues}; globalThis.selectedPlanValues = applianceApplySelectedValues;`, context);

  assert.deepEqual(Array.from(context.selectedPlanValues(modal)), ["network", "wan"]);
  selected.push(Object.assign(new HTMLInputElement(), { value: "local_users", dataset: { requiredDependency: "false" } }));
  assert.deepEqual(Array.from(context.selectedPlanValues(modal)), ["network", "wan", "local_users"]);
  selected.pop();
  assert.deepEqual(Array.from(context.selectedPlanValues(modal)), ["network", "wan"]);
  modal.dataset.requestedUnits = JSON.stringify(["network"]);
  assert.deepEqual(Array.from(context.selectedPlanValues(modal)), ["network"]);
});

test("late plan responses are rejected after a newer request starts", () => {
  const context = vm.createContext({});
  vm.runInContext(`let applianceApplyPlanRequest = 2; ${currentPlanRequest}; globalThis.isCurrentPlanRequest = isCurrentApplianceApplyPlanRequest;`, context);

  assert.equal(context.isCurrentPlanRequest(1), false);
  assert.equal(context.isCurrentPlanRequest(2), true);
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

    set(name, value) {
      this.delete(name);
      this.append(name, value);
    }

    delete(name) {
      this.values = this.values.filter(([key]) => key !== name);
    }
  }

  const network = new HTMLInputElement();
  Object.assign(network, { name: "selected_units", value: "network", type: "checkbox", checked: true, disabled: true });
  const dependent = new HTMLInputElement();
  Object.assign(dependent, { name: "selected_units", value: "public_services", type: "checkbox", checked: true, disabled: true });
  const modal = new HTMLDialogElement();
  modal.dataset = {
    serverPlanAvailable: "true",
    planToken: "plan-fingerprint",
    requestedUnits: JSON.stringify(["network", "wan"]),
  };
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
    updateApplianceApplySelection() {},
  });
  vm.runInContext(`${submitForm}; globalThis.submitReview = submitApplianceApplyForm;`, context);

  await context.submitReview(form);
  assert.deepEqual(submittedBody.values, [
    ["reviewed_plan", "plan-fingerprint"],
    ["requested_units", "network"],
    ["requested_units", "wan"],
    ["selected_units", "network"],
    ["selected_units", "public_services"],
  ]);
  submittedBody = null;
  modal.dataset.planLoading = "true";
  assert.equal(await context.submitReview(form), false);
  assert.equal(submittedBody, null);
  modal.dataset.planLoading = "false";
  modal.dataset.planToken = "";
  assert.equal(await context.submitReview(form), false);
  assert.equal(submittedBody, null);
});
const formatIdentitySource = source.slice(source.indexOf("function applianceApplyFormatIdentity"), source.indexOf("function applianceApplyReviewRow"));
const reviewStateSource = source.slice(source.indexOf("function preserveApplianceApplyReviewState"), source.indexOf("async function refreshApplianceApplyPlan"));

test("format confirmation survives only the same reviewed manifest and disk identity", () => {
  class HTMLElement {}
  class HTMLInputElement extends HTMLElement {}
  const context = vm.createContext({ HTMLElement, HTMLInputElement, document: { activeElement: null } });
  vm.runInContext(formatIdentitySource + reviewStateSource, context);
  const unit = { snapshot_hash: "reviewed-storage-manifest" };
  const volume = { id: 17, name: "datastore", stable_device_id: "/dev/disk/by-id/original",
    fingerprint: { serial: "original", wwn: "wwn-original", size_bytes: 1000 } };
  const makeRow = (identity, value = "") => {
    const hidden = Object.assign(new HTMLInputElement(), { disabled: true, value: JSON.stringify({ volume_id: identity.id }) });
    const input = Object.assign(new HTMLInputElement(), { value, dataset: {
      expected: "FORMAT datastore", formatIdentity: context.applianceApplyFormatIdentity(identity.unit || unit, identity),
    }, parentElement: { querySelector: () => hidden } });
    const row = Object.assign(new HTMLElement(), { dataset: { applyUnitId: "esx_storage" }, querySelectorAll: () => [input] });
    return { row, input, hidden };
  };
  const old = makeRow(volume, "FORMAT datastore");
  const saved = context.preserveApplianceApplyReviewState({ querySelectorAll: () => [old.row] });
  const same = makeRow({ ...volume, fingerprint: { size_bytes: 1000, wwn: "wwn-original", serial: "original" } });
  context.restoreApplianceApplyReviewState({ querySelectorAll: () => [same.row] }, saved);
  assert.equal(same.input.value, "FORMAT datastore");
  assert.equal(same.hidden.disabled, false);
  for (const replacement of [
    { ...volume, id: 18 },
    { ...volume, stable_device_id: "/dev/disk/by-id/replacement" },
    { ...volume, fingerprint: { ...volume.fingerprint, serial: "replacement" } },
    { ...volume, unit: { snapshot_hash: "replacement-manifest" } },
    { ...volume, unit: {} },
  ]) {
    const fresh = makeRow(replacement);
    context.restoreApplianceApplyReviewState({ querySelectorAll: () => [fresh.row] }, saved);
    assert.equal(fresh.input.value, "");
    assert.equal(fresh.hidden.disabled, true);
  }
  const missing = makeRow(volume);
  delete missing.input.dataset.formatIdentity;
  context.restoreApplianceApplyReviewState({ querySelectorAll: () => [missing.row] }, saved);
  assert.equal(missing.input.value, "");
  assert.equal(missing.hidden.disabled, true);
});
const refreshPlanSource = source.slice(source.indexOf("async function refreshApplianceApplyPlan"), source.indexOf("function applianceApplyDuration"));

for (const withController of [false, true]) {
  test("plan refresh observes another session's active task without installing review rows: " + withController, async () => {
    class HTMLElement {}
    class HTMLDialogElement extends HTMLElement {}
    class HTMLInputElement extends HTMLElement {}
    class HTMLButtonElement extends HTMLElement {}
    const modal = Object.assign(new HTMLDialogElement(), { dataset: {
      serverPlanAvailable: "true", planToken: "old-plan",
    } });
    const token = Object.assign(new HTMLInputElement(), { value: "old-plan" });
    let installedRows = 0;
    let restored = 0;
    let selectionUpdates = 0;
    const submit = Object.assign(new HTMLButtonElement(), { disabled: false, classList: { add: (value) => { submit.hiddenClass = value; } } });
    const observed = [];
    const task = { id: "other-session-task", status: "running" };
    const elements = {
      modal, submit, reviewForm: { querySelector: () => token },
      reviewList: { replaceChildren: () => { installedRows += 1; } },
    };
    const context = vm.createContext({
      HTMLElement, HTMLDialogElement, HTMLInputElement, HTMLButtonElement, URLSearchParams,
      applianceApplyModalElements: () => elements,
      applianceApplySelectedValues: () => ["network"],
      preserveApplianceApplyReviewState: () => ({ active: null, focused: null }),
      restoreApplianceApplyReviewState: () => { restored += 1; },
      updateApplianceApplySelection: () => { selectionUpdates += 1; },
      managementUiPath: (path) => path,
      applianceApplyPollController: withController ? { observeTask: async (value) => observed.push(value) } : null,
      renderApplianceApplyTask: (value) => observed.push(value),
      fetch: async () => ({ ok: true, json: async () => ({
        active_task: task, plan_token: "obsolete-plan", units: [{ id: "network" }],
      }) }),
    });
    vm.runInContext("let applianceApplyPlanRequest = 0; function isCurrentApplianceApplyPlanRequest(id) { return id === applianceApplyPlanRequest; } " + refreshPlanSource, context);
    await context.refreshApplianceApplyPlan();
    assert.deepEqual(observed, [task]);
    assert.equal(installedRows, 0);
    assert.equal(restored, 0);
    assert.equal(modal.dataset.planToken, undefined);
    assert.equal(token.value, "");
    assert.equal(modal.dataset.planLoading, "false");
    assert.equal(selectionUpdates, 1);
    assert.equal(submit.disabled, true);
    assert.equal(submit.hiddenClass, "hidden");
  });
}
