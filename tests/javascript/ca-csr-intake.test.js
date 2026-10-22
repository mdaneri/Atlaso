const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const app = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const helperStart = app.indexOf("const CA_CSR_MAX_BYTES =");
const helperEnd = app.indexOf("function serviceBindSelection", helperStart);
const helpers = app.slice(helperStart, helperEnd);
const context = vm.createContext({ TextEncoder, TextDecoder, Error, Number, String, RegExp });
vm.runInContext(`${helpers}\nglobalThis.caCsr = { validateCaCsrPem, readCaCsrFile };`, context);

const validPem = [
  "-----BEGIN CERTIFICATE REQUEST-----",
  "MII=",
  "-----END CERTIFICATE REQUEST-----",
].join("\n");

function file(name, contents, size = Buffer.byteLength(contents), type = "") {
  const bytes = Buffer.from(contents, "utf8");
  return {
    name,
    size,
    type,
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}

test("CSR validation accepts pasted request PEM and rejects non-CSR blocks", () => {
  assert.equal(context.caCsr.validateCaCsrPem(validPem), "");
  assert.equal(context.caCsr.validateCaCsrPem(validPem.replace("BEGIN CERTIFICATE REQUEST", "BEGIN NEW CERTIFICATE REQUEST").replace("END CERTIFICATE REQUEST", "END NEW CERTIFICATE REQUEST")), "");
  assert.match(context.caCsr.validateCaCsrPem("-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----"), /complete PEM certificate signing request/);
  assert.match(context.caCsr.validateCaCsrPem(`${validPem}\nextra`), /no extra content/);
  assert.match(context.caCsr.validateCaCsrPem(validPem.replace("MII=", "M!I=")), /valid base64/);
});

test("CSR file reader accepts bounded .csr/.pem files and rejects unsafe inputs", async () => {
  assert.equal(await context.caCsr.readCaCsrFile(file("request.CSR", validPem)), validPem);
  assert.equal(await context.caCsr.readCaCsrFile(file("request.pem", validPem)), validPem);
  assert.equal(await context.caCsr.readCaCsrFile(file("request.csr", validPem, undefined, "application/pkcs10")), validPem);
  await assert.rejects(context.caCsr.readCaCsrFile(file("request.crt", validPem)), /\.csr or \.pem/);
  await assert.rejects(context.caCsr.readCaCsrFile(file("request.pem", validPem, undefined, "application/x-pkcs12")), /PEM text file or a PKCS#10/);
  await assert.rejects(context.caCsr.readCaCsrFile(file("empty.pem", "")), /larger than zero/);
  await assert.rejects(context.caCsr.readCaCsrFile(file("large.pem", validPem, 64 * 1024 + 1)), /no larger than 64 KiB/);
  await assert.rejects(context.caCsr.readCaCsrFile(file("private.pem", "-----BEGIN PRIVATE KEY-----\nMII=\n-----END PRIVATE KEY-----")), /Private-key/);
  const invalidUtf8 = { name: "request.pem", size: 1, arrayBuffer: async () => Uint8Array.of(0xff).buffer };
  await assert.rejects(context.caCsr.readCaCsrFile(invalidUtf8), /valid UTF-8/);
});

function wizardHarness() {
  let wizardConfig;
  const errors = [];
  const clearCount = { value: 0 };
  class Element extends EventTarget {
    constructor() {
      super();
      this.dataset = {};
      this.value = "";
      this.textContent = "";
      this.files = [];
    }
    focus() {}
    setAttribute() {}
    addEventListener(name, listener, options) {
      this.listeners ||= {};
      this.listeners[name] ||= [];
      this.listeners[name].push(listener);
      super.addEventListener(name, listener, options);
    }
  }
  class Input extends Element {}
  class Textarea extends Element {
    dispatchEvent(event) { return super.dispatchEvent(event); }
  }
  class Button extends Element {}
  class Dialog extends Element {}
  class Form extends Element {
    constructor() {
      super();
      this.csr = new Textarea();
      this.file = new Input();
      this.status = new Element();
      this.elements = { csr_text: this.csr, namedItem: name => name === "csr_text" ? this.csr : null };
    }
    querySelector(selector) {
      if (selector === "[data-ca-csr-file]") return this.file;
      if (selector === "[data-ca-csr-file-status]") return this.status;
      return null;
    }
  }
  const form = new Form();
  const dialog = new Dialog();
  const launcher = new Button();
  const wizard = {
    clearError: () => { clearCount.value += 1; },
    setError: (message) => errors.push(message),
  };
  const context = vm.createContext({
    TextEncoder, TextDecoder, Error, Number, String, RegExp, Event,
    HTMLElement: Element, HTMLDialogElement: Dialog, HTMLFormElement: Form,
    HTMLButtonElement: Button, HTMLInputElement: Input, HTMLTextAreaElement: Textarea,
    document: {
      getElementById: () => dialog,
      querySelector: selector => selector === "[data-ca-csr-form]" ? form : launcher,
    },
    window: {
      AtlasoUiPatterns: {
        createWizard: config => { wizardConfig = config; return wizard; },
      },
    },
    renderAtlasoWizardReview: () => {},
  });
  vm.runInContext(`${helpers}\ninitializeCaCsrWizard();`, context);
  return { form, wizardConfig, errors, clearCount };
}

function deferredFile(name, contents = validPem) {
  let finish;
  const arrayBuffer = new Promise(resolve => { finish = resolve; });
  return {
    file: { name, size: Buffer.byteLength(contents), type: "", arrayBuffer: () => arrayBuffer },
    finish: () => {
      const bytes = Buffer.from(contents, "utf8");
      finish(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
    },
  };
}

test("a newer file selection wins when CSR reads complete out of order", async () => {
  const { form, errors } = wizardHarness();
  const first = deferredFile("first.pem");
  const second = deferredFile("second.csr");
  form.file.files = [first.file];
  const firstRead = form.file.listeners.change[0]();
  form.file.files = [second.file];
  const secondRead = form.file.listeners.change[0]();
  second.finish();
  await secondRead;
  first.finish();
  await firstRead;
  assert.equal(form.csr.value, validPem);
  assert.equal(form.status.textContent, "CSR file loaded into the text field.");
  assert.deepEqual(errors, []);
});

test("paste, file-picker cancel, form reset, and wizard close invalidate pending CSR reads", async () => {
  for (const invalidate of ["paste", "picker-cancel", "reset", "close"]) {
    const { form, wizardConfig, errors } = wizardHarness();
    const pending = deferredFile("request.pem");
    form.file.files = [pending.file];
    const read = form.file.listeners.change[0]();
    if (invalidate === "paste") {
      form.csr.value = "manually pasted CSR";
      form.csr.dispatchEvent(new Event("input"));
    } else if (invalidate === "picker-cancel") {
      form.file.dispatchEvent(new Event("cancel"));
    } else if (invalidate === "reset") {
      form.dispatchEvent(new Event("reset"));
    } else {
      wizardConfig.onClose();
    }
    form.status.textContent = "newer state";
    pending.finish();
    await read;
    assert.notEqual(form.csr.value, validPem, `${invalidate} must not be overwritten`);
    assert.equal(form.status.textContent, "newer state", `${invalidate} status must remain untouched`);
    assert.deepEqual(errors, [], `${invalidate} must not surface a stale error`);
  }
});

test("a stale file-read failure cannot replace current wizard feedback", async () => {
  const { form, wizardConfig, errors } = wizardHarness();
  const invalidPem = deferredFile("request.pem", "-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----");
  form.file.files = [invalidPem.file];
  const read = form.file.listeners.change[0]();
  wizardConfig.onClose();
  form.status.textContent = "current wizard state";
  invalidPem.finish();
  await read;
  assert.equal(form.status.textContent, "current wizard state");
  assert.deepEqual(errors, []);
});
