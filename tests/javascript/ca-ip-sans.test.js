const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const app = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const ipv4ParserStart = app.indexOf("function parseIpv4AddressParts(");
const ipv4ParserEnd = app.indexOf("function parseCompactIpv4RangeEnd(", ipv4ParserStart);
const helperStart = app.indexOf("function parseCaIpSanEntries(");
const helperEnd = app.indexOf("function initializeCaCertificatesTable(", helperStart);
const helpers = `${app.slice(ipv4ParserStart, ipv4ParserEnd)}\n${app.slice(helperStart, helperEnd)}`;
const context = vm.createContext({ URL, String, RegExp });
vm.runInContext(`${helpers}\nglobalThis.caIpSans = { parseCaIpSanEntries, isValidCaIpSan, validateCaIpSanField };`, context);

test("CA IP SAN parser accepts supported separators, blanks, and IPv4/IPv6 literals", () => {
  assert.deepEqual([...context.caIpSans.parseCaIpSanEntries(" 192.0.2.1,\n2001:db8::1 \r\n")], ["192.0.2.1", "2001:db8::1"]);
  for (const address of ["0.0.0.0", "255.255.255.255", "2001:db8::1", "::", "::ffff:192.0.2.1", "fe80::1%eth0", "fe80::1%scope name"]) {
    assert.equal(context.caIpSans.isValidCaIpSan(address), true, address);
  }
  assert.equal(context.caIpSans.validateCaIpSanField(" ,\n "), "", "blank input stays optional");
});

test("CA IP SAN parser rejects malformed entries in mixed IPv4/IPv6 input", () => {
  for (const address of ["192.0.2", "256.0.0.1", "001.2.3.4", "192.0.2.1/24", "example.test", "2001:db8:::1", "2001:db8::gg", "2001:db8::1:10000", "[::1]", "::1]/path", "::1/path", "::ffff:999.0.0.1", "fe80::1%", "1.2.3.4,invalid"]) {
    assert.equal(context.caIpSans.isValidCaIpSan(address), false, address);
  }
  assert.match(context.caIpSans.validateCaIpSanField("192.0.2.1\n2001:db8::bad::1"), /valid IPv4 or IPv6/);
});

function certificateWizardHarness() {
  let configuration;
  class Element {
    constructor() { this.dataset = { profileOptions: "[]", certificates: "[]" }; this.listeners = {}; }
    addEventListener(name, listener) { this.listeners[name] = listener; }
  }
  class Select {}
  const element = new Element();
  const field = new Element();
  field.value = "";
  field.setAttribute = () => {};
  field.removeAttribute = () => {};
  const feedback = new Element();
  feedback.textContent = "";
  const form = { elements: { ip_addresses: field, profile_id: { selectedOptions: [] }, subject_alt_names: { value: "" } }, querySelector: () => feedback };
  const wizard = { clearError() { feedback.textContent = ""; } };
  const testContext = vm.createContext({
    URL, String, RegExp, JSON, Number, HTMLElement: Element, HTMLSelectElement: Select,
    document: { getElementById: () => element, querySelector: () => form },
    initializeAtlasoResourceWizard: (config) => { configuration = config; element.atlasoWizard = wizard; return { table: null }; },
    newCaCertificateRow: () => ({}), managementUiPath: (path) => path,
  });
  const start = app.indexOf("function initializeCaCertificatesTable()");
  const end = app.indexOf("function caRequestStatusFormatter", start);
  vm.runInContext(`${helpers}\n${app.slice(start, end)}\ninitializeCaCertificatesTable();`, testContext);
  return { configuration, field, feedback, form };
}

test("certificate create/edit names and final review both block invalid SANs and clear feedback after correction", () => {
  const { configuration, field, feedback, form } = certificateWizardHarness();
  for (const step of ["names", "review"]) {
    field.value = "192.0.2.1\nnot-an-ip";
    const result = configuration.validateStep({ form: { elements: { ip_addresses: field, profile_id: {}, subject_alt_names: { value: "" } }, querySelector: () => feedback }, step: { id: step } });
    assert.equal(result.valid, false);
    assert.equal(result.field, "ip_addresses");
    assert.equal(result.step, "names");
    assert.match(result.message, /not-an-ip/);
    assert.match(feedback.textContent, /not-an-ip/);
  }
  field.value = "192.0.2.1, 2001:db8::1";
  field.listeners.input();
  assert.equal(feedback.textContent, "");
  configuration.onOpen({ form });
  assert.equal(feedback.textContent, "", "opening create/edit clears stale adjacent feedback");
});

test("CSR intake validates IP SANs before leaving Names and again on review submission", () => {
  let configuration;
  class Element {
    constructor() { this.listeners = {}; this.textContent = ""; }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    setAttribute() {}
    removeAttribute() {}
  }
  class Dialog extends Element {}
  class Form extends Element {
    constructor() {
      super();
      this.ip = new Element();
      this.ip.value = "192.0.2.1\ninvalid";
      this.csr = new Element();
      this.csr.value = "";
      this.elements = { ip_addresses: this.ip, csr_text: this.csr, namedItem: (name) => this.elements[name] };
    }
    querySelector() { return null; }
  }
  class Button extends Element {}
  const dialog = new Dialog();
  const form = new Form();
  const launcher = new Button();
  const feedback = new Element();
  form.querySelector = (selector) => selector === "[data-ca-ip-san-error]" ? feedback : null;
  const testContext = vm.createContext({
    URL, String, RegExp, HTMLElement: Element, HTMLDialogElement: Dialog, HTMLFormElement: Form,
    HTMLButtonElement: Button, HTMLInputElement: class extends Element {}, HTMLTextAreaElement: class extends Element {},
    document: { getElementById: () => dialog, querySelector: (selector) => selector === "[data-ca-csr-form]" ? form : launcher },
    window: { AtlasoUiPatterns: { createWizard: (config) => { configuration = config; return { open() {}, clearError() {} }; } } },
    renderAtlasoWizardReview() {}, validateCaCsrPem: () => "",
  });
  const start = app.indexOf("function initializeCaCsrWizard()");
  const end = app.indexOf("function serviceBindSelection", start);
  vm.runInContext(`${helpers}\n${app.slice(start, end)}\ninitializeCaCsrWizard();`, testContext);

  for (const step of ["names", "review"]) {
    const result = configuration.validateStep({ form, step: { id: step } });
    assert.equal(result.valid, false);
    assert.equal(result.field, "ip_addresses");
    assert.equal(result.step, "names");
    assert.match(feedback.textContent, /invalid/);
  }
  form.ip.value = "2001:db8::1";
  form.ip.listeners.input();
  assert.equal(feedback.textContent, "");
  assert.equal(configuration.validateStep({ form, step: { id: "review" } }).valid, true);
  feedback.textContent = "stale IP error";
  configuration.onOpen();
  assert.equal(feedback.textContent, "", "opening CSR intake clears stale adjacent feedback");
  feedback.textContent = "stale IP error";
  form.listeners.reset();
  assert.equal(feedback.textContent, "", "reset clears adjacent feedback");
});
