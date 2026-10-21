const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

function check(source) {
  // A separate process enforces a deadline even when a parser blocks the event loop.
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", source], {
    cwd: path.resolve(__dirname, "../.."), encoding: "utf8", timeout: 5000,
    killSignal: "SIGKILL", maxBuffer: 64 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr);
}

test("Markdown parser bounds unclosed references, HTML, and smart quotes", () => {
  check(String.raw`
    import assert from "node:assert/strict";
    import MarkdownIt from "markdown-it";
    const md = new MarkdownIt({ html: true, typographer: true });
    md.render('[a]: /u "' + 'x\n'.repeat(200000));
    md.render('[' + 'a\n'.repeat(200000));
    for (const opener of ['<!--', '<?x', '<!A', '<![CDATA[']) {
      md.render('x ' + opener.repeat(100000));
    }
    md.render('"a '.repeat(100000) + "b' ".repeat(100000));
    md.render("'a ".repeat(100000) + 'b" '.repeat(100000));
    assert.match(md.render('[link][a]\n\n[a]: /safe\n'), /href="\/safe"/);
    assert.match(md.render('"hello"'), /“hello”/);
    assert.match(md.render('x <!-- closed -->'), /<!-- closed -->/);
  `);
});

test("TOML config parser handles large flat documents and valid settings", () => {
  check(String.raw`
    import assert from "node:assert/strict";
    import parse from "markdownlint-cli2/parsers/toml";
    const source = Array.from({length: 256000}, (_, i) => 'k' + i + ' = 1').join('\n');
    assert.equal(Object.keys(parse(source)).length, 256000);
    assert.deepEqual(JSON.parse(JSON.stringify(parse('default = true\nMD013 = { line_length = 120 }'))), {
      default: true, MD013: {line_length: 120}
    });
  `);
});

test("YAML merge budgets count empty mappings and preserve ordinary config", () => {
  check(String.raw`
    import assert from "node:assert/strict";
    import { load, YAML11_SCHEMA } from "js-yaml";
    import parse from "markdownlint-cli2/parsers/yaml";
    const source = 'arr: &arr [' + '{},'.repeat(100).slice(0, -1) + ']\n' +
      'targets:\n' + '  - <<: *arr\n'.repeat(100);
    assert.throws(() => load(source, {schema: YAML11_SCHEMA, maxTotalMergeKeys: 1000}),
      /merge/i);
    assert.deepEqual(parse('default: true\nMD013:\n  line_length: 120\n'), {
      default: true, MD013: {line_length: 120}
    });
  `);
});

test("Math extension preserves rendering and ignores inherited trust", () => {
  check(String.raw`
    import assert from "node:assert/strict";
    import { micromark } from "micromark";
    import { math, mathHtml } from "micromark-extension-math";
    const render = (source, options) => micromark(source, {
      extensions: [math()], htmlExtensions: [mathHtml(options)]
    });
    assert.match(render('$x^2$'), /katex/);
    assert.match(render('$$\nx^2\n$$'), /katex-display/);
    assert.throws(() => render('$\\notARealCommand$'), /Undefined control sequence/);
    const source = '$\\href{https://example.com/}{safe}$';
    assert.match(render(source, {trust: true}), /href="https:\/\/example.com\/"/);
    Object.prototype.trust = true;
    try {
      assert.doesNotMatch(render(source), /href=/);
      assert.doesNotMatch(render(source, {}), /href=/);
    } finally {
      delete Object.prototype.trust;
    }
  `);
});
