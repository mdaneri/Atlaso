const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "../..");

function checkParser(source) {
  // A synchronous parser loop blocks JS timers; enforce the deadline from a parent process.
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", source], {
    cwd: root,
    encoding: "utf8",
    timeout: 5000,
    killSignal: "SIGKILL",
    maxBuffer: 64 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr);
}

for (const input of ["a=[1 #", "a={b=1 #"]) {
  test(`Markdown TOML parser rejects an EOF comment: ${input}`, () => {
    checkParser(`
      import assert from "node:assert/strict";
      import parse from "markdownlint-cli2/parsers/toml";
      assert.throws(() => parse(${JSON.stringify(input)}),
        (error) => error.constructor.name === "TomlError");
    `);
  });
}

test("Markdown TOML parser preserves valid configuration and comments", () => {
  checkParser(String.raw`
    import assert from "node:assert/strict";
    import parse from "markdownlint-cli2/parsers/toml";
    assert.deepEqual(parse('default = true\nMD013 = { line_length = 120 }\n'), {
      default: true, MD013: { line_length: 120 }
    });
    assert.deepEqual(parse('a=[1 # comment\n, 2]\nb={c=3} # final comment'), {
      a: [1, 2], b: {c: 3}
    });
  `);
});
