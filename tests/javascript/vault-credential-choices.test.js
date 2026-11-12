const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const parametersStart = appSource.indexOf("(", start);
  let parameterDepth = 0;
  let bodyStart = -1;
  for (let index = parametersStart; index < appSource.length; index += 1) {
    if (appSource[index] === "(") parameterDepth += 1;
    if (appSource[index] === ")") {
      parameterDepth -= 1;
      if (parameterDepth === 0) {
        bodyStart = appSource.indexOf("{", index);
        break;
      }
    }
  }
  assert.notEqual(bodyStart, -1, `${name} must have a function body`);
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

const context = vm.createContext({ URL });
vm.runInContext(`${functionSource("vaultCredentialChoices")}; globalThis.choices = vaultCredentialChoices;`, context);

function choices(entries, options) {
  return context.choices(entries, options);
}

test("ranks explicit service and preferred protocols and keeps labels as text", () => {
  const entries = [
    { id: 1, key: "ops", service_type: "vcf_operations", service_type_label: "Operations", display_name: "Ops account", username: "operator", uris: ["https://ops.example", "http://ops.example"] },
    { id: 2, key: "vc", service_type: "vcenter", service_type_label: "vCenter", display_name: "VC account", username: "administrator", uris: ["http://vc.example", "https://vc.example"] },
    { id: 3, key: "unknown", uris: ["https://other.example"] },
  ];
  const result = choices(entries, {
    preferredServices: ["vcenter", "vcf_operations"],
    preferredProtocols: ["https", "http"],
  });

  assert.deepEqual(Array.from(result, ({ entry, uri }) => [entry.id, uri]), [
    [1, "https://ops.example"], [2, "https://vc.example"],
    [1, "http://ops.example"], [2, "http://vc.example"], [3, "https://other.example"],
  ]);
  assert.equal(result[0].matched, true);
  assert.equal(result[1].matched, true);
  assert.equal(result[2].matched, true);
  assert.equal(result[3].matched, true);
  assert.equal(result[4].matched, false);
  assert.match(result[0].label, /^Recommended · Operations · HTTPS · Ops account · operator — https:\/\/ops\.example$/);
  assert.match(result[4].label, /^Unknown · HTTPS · unknown — https:\/\/other\.example$/);
});

test("unmatched services and protocols remain eligible without recommendation", () => {
  const entry = { id: "stable-17", key: "legacy-key", service_type: "installer", service_type_label: "Installer", uris: ["http://installer.example"] };
  const [choice] = choices([entry], { preferredServices: ["vcenter"], preferredProtocols: ["https"] });

  assert.equal(choice.entry, entry);
  assert.equal(choice.uri, "http://installer.example");
  assert.equal(choice.protocol, "http");
  assert.equal(choice.matched, false);
  assert.match(choice.label, /^Installer · HTTP · legacy-key — http:\/\/installer\.example$/);
});

test("equally preferred services rank by protocol rather than service-list order", () => {
  const entries = [
    { id: 1, key: "vc-http", service_type: "vcenter", uris: ["http://vc.example"] },
    { id: 2, key: "esxi-https", service_type: "esxi", uris: ["https://esxi.example"] },
    { id: 3, key: "other-https", service_type: "operations", uris: ["https://ops.example"] },
  ];
  const result = choices(entries, {
    preferredServices: ["vcenter", "esxi"],
    preferredProtocols: ["https", "http"],
  });

  assert.deepEqual(Array.from(result, ({ entry }) => entry.id), [2, 1, 3]);
  assert.equal(result[0].matched, true);
  assert.equal(result[1].matched, true);
  assert.equal(result[2].matched, false);
});

test("expands multiple URI choices while preserving entry object, identifier, and URI index", () => {
  const entry = { id: 999, key: "exact-key", display_name: "Readable", username: "root", uris: ["https://first.example", "https://second.example"] };
  const result = choices([entry]);

  assert.equal(result.length, 2);
  assert.equal(result[0].entry, entry);
  assert.equal(result[1].entry, entry);
  assert.deepEqual(Array.from(result, ({ uri, uriIndex }) => [uri, uriIndex]), [
    ["https://first.example", 0], ["https://second.example", 1],
  ]);
  assert.equal(result[0].entry.id, 999);
  assert.equal(result[1].entry.id, 999);
});

test("rejects malformed, credential-bearing, hostless, and disallowed URI values", () => {
  const entry = {
    id: 1,
    key: "mixed",
    uris: ["not a URL", "https://user:secret@example.com", "https:///", "ftp://files.example", "https://valid.example"],
  };
  const result = choices([entry]);

  assert.equal(result.length, 1);
  assert.equal(result[0].uri, "https://valid.example");
  assert.equal(result[0].uriIndex, 4);
  assert.equal(result[0].protocol, "https");
});

test("does not mutate vault entries or URI arrays", () => {
  const entry = { id: 2, key: "key", service_type: "vcenter", uris: ["https://vc.example", "http://vc.example"] };
  const originalUris = [...entry.uris];
  choices([entry], { preferredServices: ["vcenter"] });

  assert.deepEqual(entry.uris, originalUris);
  assert.deepEqual(Object.keys(entry), ["id", "key", "service_type", "uris"]);
});
