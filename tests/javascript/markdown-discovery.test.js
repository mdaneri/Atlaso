const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "../..");
const cli = path.join(root, "node_modules/markdownlint-cli2/markdownlint-cli2-bin.mjs");

test("Markdown discovery excludes only root task state and supports explicit opt-in", () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "atlaso-markdown-"));
  fs.copyFileSync(path.join(root, ".markdownlint-cli2.jsonc"), path.join(fixture, ".markdownlint-cli2.jsonc"));
  function write(relative, content) {
    const file = path.join(fixture, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
  }
  function lint(...args) {
    const result = spawnSync(process.execPath, [cli, ...args], {
      cwd: fixture, encoding: "utf8", timeout: 10000, maxBuffer: 128 * 1024,
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    return result;
  }
  write("README.md", "# Fixture\n");
  write(".atlaso-local/deep/invalid.md", "## Missing document heading\n");
  let result = lint();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  result = lint(".atlaso-local/deep/invalid.md");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  result = lint("--no-globs", ".atlaso-local/deep/invalid.md");
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /MD041/);
  for (const source of ["docs/invalid.md", "docs/.atlaso-local/invalid.md", "untracked.md"]) {
    write(source, "## Missing document heading\n");
    result = lint();
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stdout + result.stderr, /MD041/);
    write(source, "# Valid heading\n");
  }
});
