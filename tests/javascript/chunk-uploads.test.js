const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");
const { webcrypto, createHash } = require("node:crypto");
const source = fs.readFileSync("atlaso/app/static/chunk-uploads.js", "utf8");

test("shared app keeps ordinary fetch working on public shells without upload assets", async () => {
  const binding = fs.readFileSync("atlaso/app/static/app.js", "utf8").split("\n").find(line => line.startsWith("const fetch ="));
  for (const management of [false, true]) {
    const calls = [];
    const context = { window: { fetch: async (url) => { calls.push("native:" + url); return "ok"; } } };
    if (management) context.window.AtlasoUploads = { fetch: async (url) => { calls.push("chunked:" + url); return "ok"; } };
    assert.equal(await vm.runInNewContext(`${binding}\nfetch('/status')`, context), "ok");
    assert.deepEqual(calls, [(management ? "chunked:" : "native:") + "/status"]);
  }
});

function harness({ lostAck = false, finalFailure = false, existing = false, confirm = false, http = false, chunkBytes = 2 } = {}) {
  const calls = [];
  const warnings = [];
  let dropped = false;
  const context = {
    URL, Headers, FormData, File, EventTarget, Event, AbortController, Uint8Array,
    crypto: http ? undefined : webcrypto, location: { href: "https://appliance/ui/management/vcf-helper", origin: "https://appliance" },
    ProgressEvent: class extends Event { constructor(name, values) { super(name); Object.assign(this, values); } },
    document: { addEventListener() {}, querySelector() { return { value: "csrf-test" }; } },
    setTimeout: (callback) => callback(),
    requestConfirmation: async (options) => { warnings.push(options); return confirm; },
    window: { fetch: async (url, options) => {
      calls.push({ url, ...options });
      if (url.endsWith("/uploads/chunks")) {
        if (existing && JSON.parse(options.body).overwrite_token !== "revision-token") {
          return { ok: false, status: 409, json: async () => ({ detail: "Already exists", code: "overwrite_required", overwrite_token: "revision-token" }) };
        }
        return { ok: true, json: async () => ({ id: "session", chunk_bytes: chunkBytes }) };
      }
      if (options.method === "PUT") {
        if (lostAck && !dropped) { dropped = true; throw new Error("lost acknowledgement"); }
        return { ok: true, json: async () => ({ offset: Number(options.headers["X-Atlaso-Upload-Offset"]) + options.body.size }) };
      }
      if (options.method === "DELETE") return { ok: true };
      if (finalFailure) throw new Error("final response lost");
      return { ok: true, status: 200, text: async () => "{}" };
    } },
  };
  vm.runInNewContext(source, context);
  return { context, calls, warnings, upload: context.window.AtlasoUploads.fetch, Request: context.window.AtlasoUploads.Request };
}

test("bounded chunks retry identical offsets and finalize text fields once", async () => {
  const { calls, upload } = harness({ lostAck: true });
  const body = new FormData();
  body.append("csrf", "csrf-test");
  body.append("choice", "first");
  body.append("choice", "second");
  body.append("iso_file", new File(["abcdef"], "installer.iso"));
  const progress = [];
  await upload("/ui/management/esxi-pxe/isos/upload", { method: "POST", body }, (loaded) => progress.push(loaded));
  const chunks = calls.filter((call) => call.method === "PUT");
  assert.deepEqual(chunks.map((call) => call.headers["X-Atlaso-Upload-Offset"]), ["0", "0", "2", "4"]);
  assert.ok(chunks.every((call) => call.body.size === 2));
  assert.equal(chunks[0].headers["X-Atlaso-Chunk-SHA256"], chunks[1].headers["X-Atlaso-Chunk-SHA256"]);
  const final = calls.find((call) => call.url.endsWith("/isos/upload"));
  assert.deepEqual(JSON.parse(final.body), { files: ["session"], fields: [["csrf", "csrf-test"], ["choice", "first"], ["choice", "second"]] });
  assert.equal(final.headers.get("X-Atlaso-Chunked"), "1");
  assert.deepEqual(progress, [0, 2, 4, 6]);
  assert.equal(calls.at(-1).method, "DELETE");
});

test("HTTP-only checksum fallback matches SHA-256 across padding and full chunk boundaries", async () => {
  for (const length of [1, 55, 56, 63, 64, 65, 8 * 1024 ** 2]) {
    const data = Uint8Array.from({ length }, (_, index) => index % 251);
    const { calls, upload } = harness({ http: true, chunkBytes: 8 * 1024 ** 2 });
    await upload("/ui/management/vcf-helper/sddc-manager/ovas/upload", {
      method: "POST", body: new File([data], "test.ova"),
    });
    assert.equal(calls.find((call) => call.method === "PUT").headers["X-Atlaso-Chunk-SHA256"],
      createHash("sha256").update(data).digest("hex"));
  }
});

test("XHR adapter ends successful, failed and aborted requests exactly once", async () => {
  for (const outcome of ["success", "failure", "abort"]) {
    const { Request } = harness({ finalFailure: outcome !== "success" });
    const request = new Request();
    const events = [];
    for (const name of ["load", "abort", "loadend"]) request.addEventListener(name, () => events.push(name));
    request.open("POST", "/ui/management/vcf-helper/sddc-manager/ovas/upload");
    if (outcome === "abort") request.abort();
    await request.send(new File(["abc"], "test.ova"));
    assert.deepEqual(events, [outcome === "abort" ? "abort" : "load", "loadend"]);
  }
});

test("canceling an overwrite sends no file bytes or finalization", async () => {
  const { calls, warnings, upload } = harness({ existing: true });
  await assert.rejects(upload("/ui/management/vcf-helper/sddc-manager/ovas/upload", {
    method: "POST", body: new File(["abcdef"], "existing.ova"),
  }), /existing file was kept/);
  assert.equal(calls.length, 1);
  assert.equal(warnings[0].title, "Overwrite existing file?");
  assert.match(warnings[0].message, /existing.ova/);
  assert.equal(warnings[0].label, "Overwrite");
});

test("explicit overwrite binds the reservation to the challenge before chunks", async () => {
  const { calls, warnings, upload } = harness({ existing: true, confirm: true });
  await upload("/ui/management/vcf-helper/sddc-manager/ovas/upload", {
    method: "POST", body: new File(["abcdef"], "existing.ova"),
  });
  assert.equal(warnings.length, 1);
  assert.equal(JSON.parse(calls[0].body).overwrite_token, undefined);
  assert.equal(JSON.parse(calls[1].body).overwrite_token, "revision-token");
  assert.equal(calls[2].method, "PUT");
});

test("finalization is never automatically replayed after an ambiguous response", async () => {
  const { calls, upload } = harness({ finalFailure: true });
  const body = new FormData();
  body.append("tool_archive_file", new File(["ab"], "vcf-download-tool-test.tar.gz"));
  await assert.rejects(upload("/ui/management/vcf-offline-depot/tool-package", { method: "POST", body }), /final response lost/);
  assert.equal(calls.filter((call) => call.url.endsWith("/tool-package")).length, 1);
  assert.equal(calls.at(-1).method, "DELETE");
});

test("ordinary requests pass through and cross-origin file uploads fail closed", async () => {
  const { calls, upload } = harness();
  await upload("/status", {});
  assert.equal(calls.length, 1);
  const body = new FormData();
  body.append("archive_file", new File(["ab"], "settings.json"));
  await assert.rejects(upload("https://elsewhere/upload", { method: "POST", body }), /this appliance/);
  assert.equal(calls.length, 1);
});


test("chunk and ordinary mutations retain the late-installed apply refresh wrapper", async () => {
  const { context, calls, upload } = harness();
  context.Request = globalThis.Request;
  context.window.location = context.location;
  context.window.AtlasoRoutes = { management: path => "/ui/management" + path };
  let refreshes = 0;
  context.window.clearTimeout = () => {};
  context.window.setTimeout = () => { refreshes += 1; return refreshes; };
  const appPrefix = fs.readFileSync("atlaso/app/static/app.js", "utf8").split("function readCookieValue")[0];
  vm.runInNewContext(appPrefix, context);
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
    const before = refreshes;
    await vm.runInNewContext(`fetch('/ui/management/settings', {method: '${method}'})`, context);
    assert.equal(refreshes, before + 1);
  }
  const beforeRead = refreshes;
  await vm.runInNewContext("fetch('/ui/management/settings')", context);
  assert.equal(refreshes, beforeRead);
  await upload("/ui/management/vcf-helper/sddc-manager/ovas/upload", {
    method: "POST", body: new File(["abc"], "test.ova"),
  });
  assert.ok(refreshes > beforeRead);
  assert.equal(calls.filter(call => call.url.endsWith('/ovas/upload')).length, 1);
});
