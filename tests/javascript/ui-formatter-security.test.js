const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf("{", start);
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

const context = vm.createContext({ String });
vm.runInContext(
  `${functionSource("escapeHtml")}\n` +
    `${functionSource("esxStoragePathFormatter")}\n` +
    `${functionSource("esxiHostKickstartFormatter")}\n` +
    "globalThis.esxStoragePathFormatter = esxStoragePathFormatter; " +
    "globalThis.esxiHostKickstartFormatter = esxiHostKickstartFormatter;",
  context,
);

function cell(value, data = {}) {
  return {
    getValue: () => value,
    getRow: () => ({ getData: () => data }),
  };
}

function assertLiteralText(rendered, hostileValue) {
  assert.equal(/<\/?[A-Za-z][^>]*>/.test(rendered), false);
  assert.equal(/<[^>]+\son\w+\s*=/.test(rendered), false);
  assert.equal(
    rendered
      .replaceAll("&lt;", "<")
      .replaceAll("&gt;", ">")
      .replaceAll("&quot;", '"')
      .replaceAll("&#39;", "'")
      .replaceAll("&amp;", "&"),
    hostileValue,
  );
}

test("ESX Storage path formatter renders persisted markup-shaped paths as literal text", () => {
  const hostilePath = '<img src=x onerror="globalThis.pathInjected=true">';
  const rendered = context.esxStoragePathFormatter(cell(hostilePath));

  assert.equal(
    rendered,
    "&lt;img src=x onerror=&quot;globalThis.pathInjected=true&quot;&gt;",
  );
  assertLiteralText(rendered, hostilePath);
  const alternatePath = "</td><svg/onload=globalThis.pathInjected=true>";
  assertLiteralText(
    context.esxStoragePathFormatter(cell(alternatePath)),
    alternatePath,
  );
  assert.match(
    appSource,
    /field: "relative_path", formatter: esxStoragePathFormatter/,
  );
});

test("Host References Kickstart formatter renders persisted markup-shaped labels as literal text", () => {
  const hostileName = '<img src=x onerror="globalThis.kickstartInjected=true">';
  const rendered = context.esxiHostKickstartFormatter(
    cell("7"),
    { 7: hostileName },
  );

  assert.equal(
    rendered,
    "&lt;img src=x onerror=&quot;globalThis.kickstartInjected=true&quot;&gt;",
  );
  assertLiteralText(rendered, hostileName);
  const alternateName = "</option><svg/onload=globalThis.kickstartInjected=true>";
  assertLiteralText(
    context.esxiHostKickstartFormatter(cell("8"), { 8: alternateName }),
    alternateName,
  );
  assert.match(
    appSource,
    /formatter: \(cell\) => esxiHostKickstartFormatter\(cell, kickstartValues\)/,
  );
});
