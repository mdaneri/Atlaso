const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const source = fs.readFileSync("atlaso/app/static/chunk-uploads.js", "utf8");

function harness({ lostAck = false, finalFailure = false } = {}) {
  const calls = [];
  let dropped = false;
  const context = {
    URL, Headers, FormData, File, EventTarget, Event, AbortController, Uint8Array,
    crypto: webcrypto, location: { href: "https://appliance/ui/management/vcf-helper", origin: "https://appliance" },
    document: { addEventListener() {}, querySelector() { return { value: "csrf-test" }; } },
    setTimeout: (callback) => callback(),
    window: { fetch: async (url, options) => {
      calls.push({ url, ...options });
      if (url.endsWith("/uploads/chunks")) return { ok: true, json: async () => ({ id: "session", chunk_bytes: 2 }) };
      if (options.method === "PUT") {
        if (lostAck && !dropped) { dropped = true; throw new Error("lost acknowledgement"); }
        return { ok: true, json: async () => ({ offset: Number(options.headers["X-Atlaso-Upload-Offset"]) + options.body.size }) };
      }
      if (options.method === "DELETE") return { ok: true };
      if (finalFailure) throw new Error("final response lost");
      return { ok: true, status: 200 };
    } },
  };
  vm.runInNewContext(source, context);
  return { calls, upload: context.window.AtlasoUploads.fetch };
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
