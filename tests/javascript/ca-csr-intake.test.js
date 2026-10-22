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

const framedPem = [
  "-----BEGIN CERTIFICATE REQUEST-----",
  "MII=",
  "-----END CERTIFICATE REQUEST-----",
].join("\n");
const validCsrPem = [
  "-----BEGIN CERTIFICATE REQUEST-----",
  "MIHWMH4CAQAwHDEaMBgGA1UEAwwRbWltZS5leGFtcGxlLnRlc3QwWTATBgcqhkjO",
  "PQIBBggqhkjOPQMBBwNCAAS8y4tbolyEQk67P4N7AQ44JhwKDoyKy5Ir62zN9P3V",
  "EL2l1EoaVvfxlSXd4gU+wbwkQRZpiCGkyKeyGWquXe26oAAwCgYIKoZIzj0EAwID",
  "SAAwRQIhANMsSqf/8CwoU31O1yL/pwJ5jfANoing0XGkI5gavinvAiAGgKIZ2MI/",
  "ngXttbMyLBCPdrBNphS56rdkhYtKxZSDpA==",
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

test("CSR client framing accepts request PEM syntax and rejects non-CSR blocks", () => {
  assert.equal(context.caCsr.validateCaCsrPem(framedPem), "");
  assert.equal(context.caCsr.validateCaCsrPem(framedPem.replace("BEGIN CERTIFICATE REQUEST", "BEGIN NEW CERTIFICATE REQUEST").replace("END CERTIFICATE REQUEST", "END NEW CERTIFICATE REQUEST")), "");
  assert.match(context.caCsr.validateCaCsrPem("-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----"), /complete PEM certificate signing request/);
  assert.match(context.caCsr.validateCaCsrPem(`${framedPem}\nextra`), /no extra content/);
  assert.match(context.caCsr.validateCaCsrPem(framedPem.replace("MII=", "M!I=")), /valid base64/);
});

test("CSR file reader accepts bounded .csr/.pem text framing and rejects unsafe inputs", async () => {
  assert.equal(await context.caCsr.readCaCsrFile(file("request.CSR", validCsrPem)), validCsrPem);
  assert.equal(await context.caCsr.readCaCsrFile(file("request.pem", validCsrPem, undefined, "application/x-x509-ca-cert")), validCsrPem);
  assert.equal(await context.caCsr.readCaCsrFile(file("request.csr", validCsrPem, undefined, "application/octet-stream")), validCsrPem);
  assert.equal(await context.caCsr.readCaCsrFile(file("request.pem", validCsrPem, undefined, "application/unknown")), validCsrPem);
  await assert.rejects(context.caCsr.readCaCsrFile(file("request.crt", validCsrPem)), /\.csr or \.pem/);
  await assert.rejects(context.caCsr.readCaCsrFile(file("empty.pem", "")), /larger than zero/);
  await assert.rejects(context.caCsr.readCaCsrFile(file("large.pem", framedPem, 64 * 1024 + 1)), /no larger than 64 KiB/);
  await assert.rejects(context.caCsr.readCaCsrFile(file("private.pem", "-----BEGIN PRIVATE KEY-----\nMII=\n-----END PRIVATE KEY-----")), /Private-key/);
  await assert.rejects(context.caCsr.readCaCsrFile(file("private.pem", "-----BEGIN PRIVATE KEY-----\nMII=\n-----END PRIVATE KEY-----", undefined, "application/octet-stream")), /Private-key/);
  const invalidUtf8 = { name: "request.pem", size: 1, arrayBuffer: async () => Uint8Array.of(0xff).buffer };
  await assert.rejects(context.caCsr.readCaCsrFile(invalidUtf8), /valid UTF-8/);
});

test("pasted CSR limits count raw UTF-8 bytes including surrounding whitespace", () => {
  const paddingBytes = 64 * 1024 - Buffer.byteLength(validCsrPem);
  const atLimit = " ".repeat(paddingBytes) + validCsrPem;
  assert.equal(context.caCsr.validateCaCsrPem(atLimit), "");
  assert.match(context.caCsr.validateCaCsrPem(` ${atLimit}`), /no larger than 64 KiB/);
  assert.match(context.caCsr.validateCaCsrPem(`${atLimit}\n`), /no larger than 64 KiB/);
  const unicodePadding = "\u2003".repeat(Math.floor(paddingBytes / 3) + 1);
  assert.match(context.caCsr.validateCaCsrPem(`${validCsrPem}${unicodePadding}`), /no larger than 64 KiB/);
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

function deferredFile(name, contents = framedPem) {
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

test("pending replacement CSR reads block advancing and review submission", async () => {
  const { form, wizardConfig } = wizardHarness();
  form.csr.value = validCsrPem;
  const first = deferredFile("first.pem");
  const replacement = deferredFile("replacement.pem", validCsrPem);
  form.file.files = [first.file];
  const firstRead = form.file.listeners.change[0]();
  form.file.files = [replacement.file];
  const replacementRead = form.file.listeners.change[0]();
  const validate = id => wizardConfig.validateStep({ form, step: { id } });
  for (const id of ["csr", "review"]) {
    assert.equal(validate(id).valid, false);
    assert.match(validate(id).message, /finish loading/);
  }
  assert.equal(form.csr.value, validCsrPem, "retain previous text while loading");
  first.finish();
  await firstRead;
  assert.equal(validate("review").valid, false, "stale completion cannot unlock submission");
  replacement.finish();
  await replacementRead;
  assert.equal(validate("csr").valid, true);
  assert.equal(validate("review").valid, true);
});

test("failed replacement reads preserve the prior CSR and release the pending guard", async () => {
  const { form, wizardConfig, errors } = wizardHarness();
  form.csr.value = validCsrPem;
  const invalid = deferredFile("invalid.pem", "not a CSR");
  form.file.files = [invalid.file];
  const read = form.file.listeners.change[0]();
  assert.equal(wizardConfig.validateStep({ form, step: { id: "review" } }).valid, false);
  invalid.finish();
  await read;
  assert.equal(form.csr.value, validCsrPem);
  assert.equal(wizardConfig.validateStep({ form, step: { id: "csr" } }).valid, true);
  assert.equal(errors.length, 1);
});

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
  assert.equal(form.csr.value, framedPem);
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
    assert.equal(wizardConfig.validateStep({ form, step: { id: "review" } }).valid, true);
    assert.notEqual(form.csr.value, framedPem, `${invalidate} must not be overwritten`);
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
